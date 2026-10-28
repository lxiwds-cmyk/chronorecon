"""Downloads archived and live files, deduplicates content, and resumes."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import threading
import time
import zlib
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from tqdm import tqdm

from .config import Settings
from .db import Store
from .http import HttpClient, RateLimiter, TooLarge, read_response_limited
from .models import DownloadCandidate, DownloadResult
from .sources.base import SourceContext
from .sources.wayback import WaybackSource
from .utils import (
    host_from_url,
    looks_like_archive_error,
    safe_join,
    safe_path_for_url,
    sha256_bytes,
    timestamp_in_range,
    url_extension,
)

SOURCE_PRIORITY = {
    "wayback": 0,
    "commoncrawl": 1,
    "arquivo": 2,
    "urlscan": 3,
    "virustotal": 4,
    "otx": 5,
    "ghostarchive": 6,
    "live": 99,
}

STATUS_RE = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})\b", re.IGNORECASE)


class DownloadError(RuntimeError):
    pass


@dataclass
class FetchResult:
    body: bytes
    content_type: str
    http_status: int
    final_url: str = ""


def parse_warc_record(data: bytes) -> FetchResult:
    """Extract the HTTP response body from a Common Crawl WARC record."""
    raw = data
    if raw.startswith(b"\x1f\x8b"):
        try:
            raw = gzip.decompress(raw)
        except OSError:
            decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            try:
                raw = decompressor.decompress(raw)
            except zlib.error as exc:
                raise DownloadError(f"WARC gzip decompression failed: {exc}") from exc

    warc_head, separator, rest = raw.partition(b"\r\n\r\n")
    if not separator:
        raise DownloadError("WARC record has no header separator")
    warc_headers = _parse_headers(warc_head)
    warc_type = (warc_headers.get("warc-type") or "").lower()
    if warc_type not in ("response", "resource"):
        raise DownloadError(f"unsupported WARC type: {warc_type or 'unknown'}")

    http_head, separator, body = rest.partition(b"\r\n\r\n")
    if not separator:
        raise DownloadError("WARC response has no HTTP header separator")
    lines = http_head.split(b"\r\n", 1)
    if not lines:
        raise DownloadError("WARC response has no HTTP status line")
    status_match = STATUS_RE.match(lines[0].decode("latin-1", "replace"))
    if not status_match:
        raise DownloadError("WARC response has an invalid HTTP status line")
    status = int(status_match.group(1))
    http_headers = _parse_headers(lines[1] if len(lines) > 1 else b"")
    content_type = http_headers.get("content-type", "")

    declared = http_headers.get("content-length", "")
    if declared.isdigit() and len(body) != int(declared):
        # Trailing bytes can be part of the WARC block; the body is still the
        # first Content-Length bytes.  If the body is shorter, it is truncated.
        if len(body) < int(declared):
            raise DownloadError(
                f"WARC body truncated ({len(body)} < {declared} bytes)"
            )
        body = body[: int(declared)]

    encoding = http_headers.get("content-encoding", "").lower()
    if body.startswith(b"\x1f\x8b") and "gzip" in encoding:
        try:
            body = gzip.decompress(body)
        except OSError:
            pass
    elif "deflate" in encoding and body:
        try:
            body = zlib.decompress(body)
        except zlib.error:
            pass

    if not (200 <= status <= 299):
        raise DownloadError(f"archived HTTP status {status}")
    if not body:
        raise DownloadError("archived response body is empty")
    return FetchResult(
        body=body,
        content_type=content_type,
        http_status=status,
    )


def _parse_headers(block: bytes) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for line in block.split(b"\r\n"):
        if b":" not in line:
            continue
        key, value = line.split(b":", 1)
        headers[key.decode("latin-1", "replace").strip().lower()] = (
            value.decode("latin-1", "replace").strip()
        )
    return headers


class Downloader:
    def __init__(self, settings: Settings, store: Store, logger, output_dir: Path):
        self.settings = settings
        self.store = store
        self.log = logger
        self.output_dir = output_dir
        self.files_dir = output_dir / "downloads"
        self.meta_dir = output_dir / "metadata"
        self.files_dir.mkdir(parents=True, exist_ok=True)
        self.meta_dir.mkdir(parents=True, exist_ok=True)
        self.http = HttpClient(
            timeout=settings.timeout,
            retries=settings.retries,
            user_agent=settings.user_agent,
            insecure=settings.insecure,
        )
        self.rate = RateLimiter()
        self.hashes: Dict[str, str] = store.saved_hashes()
        self._save_lock = threading.Lock()
        self._bytes_lock = threading.Lock()
        self._total_bytes = 0
        self._stop = threading.Event()
        self.wayback = WaybackSource()
        self.downloads_jsonl = self.meta_dir / "downloads.jsonl"
        self._json_lock = threading.Lock()

    def run(self) -> dict:
        counts = self.store.counts()
        total_urls = counts["urls"]
        if total_urls == 0:
            return {
                "attempted": 0,
                "saved": 0,
                "duplicates": 0,
                "failed": 0,
                "skipped": 0,
                "bytes": 0,
                "seconds": 0.0,
            }
        started = time.time()
        saved = duplicates = failed = skipped = 0
        submitted = 0
        pbar = tqdm(
            total=total_urls,
            desc="Downloading",
            unit="url",
            dynamic_ncols=True,
            disable=self.settings.quiet,
        )
        executor = ThreadPoolExecutor(max_workers=max(1, self.settings.threads))
        pending: Dict[Future, int] = {}
        try:
            for row in self.store.iter_urls():
                if self._stop.is_set():
                    break
                url_id = int(row["id"])
                url = row["url"]
                if not self._url_extension_allowed(url):
                    pbar.update(1)
                    skipped += 1
                    continue
                if self.settings.max_files and submitted >= self.settings.max_files:
                    self.log.info(
                        "downloader: stopping at max-files=%s",
                        self.settings.max_files,
                    )
                    break
                future = executor.submit(self._download_one, url_id, url)
                pending[future] = url_id
                submitted += 1
                if len(pending) >= max(2, self.settings.threads * 3):
                    done, _ = wait(pending, return_when=FIRST_COMPLETED)
                    for finished in done:
                        pending.pop(finished, None)
                        results = self._future_result(finished)
                        pbar.update(1)
                        if not results:
                            skipped += 1
                        else:
                            for result in results:
                                self._record(result)
                                if result.status == "saved":
                                    saved += 1
                                elif result.status == "duplicate":
                                    duplicates += 1
                                elif result.status == "failed":
                                    failed += 1
                                else:
                                    skipped += 1
                        if self._total_size_exceeded():
                            self._stop.set()
            while pending:
                done, _ = wait(pending, return_when=FIRST_COMPLETED)
                for finished in done:
                    pending.pop(finished, None)
                    results = self._future_result(finished)
                    pbar.update(1)
                    if not results:
                        skipped += 1
                    else:
                        for result in results:
                            self._record(result)
                            if result.status == "saved":
                                saved += 1
                            elif result.status == "duplicate":
                                duplicates += 1
                            elif result.status == "failed":
                                failed += 1
                            else:
                                skipped += 1
                    if self._total_size_exceeded():
                        self._stop.set()
        finally:
            executor.shutdown(wait=True, cancel_futures=True)
            pbar.close()
            self.http.close()
        self._write_failed_list()
        elapsed = round(time.time() - started, 2)
        return {
            "attempted": submitted,
            "saved": saved,
            "duplicates": duplicates,
            "failed": failed,
            "skipped": skipped,
            "bytes": self._total_bytes,
            "seconds": elapsed,
        }

    # ------------------------------------------------------------- scheduling

    def _future_result(self, future: Future) -> Optional[List[DownloadResult]]:
        try:
            return future.result()
        except Exception as exc:  # noqa: BLE001
            self.log.warning("downloader: worker failed: %s", exc)
            if self.settings.verbose:
                import traceback

                self.log.debug(traceback.format_exc())
            return None

    def _url_extension_allowed(self, url: str) -> bool:
        ext = url_extension(url)
        if self.settings.only_ext:
            return ext in self.settings.only_ext
        if self.settings.exclude_ext and ext in self.settings.exclude_ext:
            return False
        return True

    def _total_size_exceeded(self) -> bool:
        if not self.settings.max_total_size:
            return False
        with self._bytes_lock:
            return self._total_bytes >= self.settings.max_total_size

    # -------------------------------------------------------------- per URL

    def _download_one(
        self, url_id: int, url: str
    ) -> Optional[List[DownloadResult]]:
        snapshots = self.store.get_snapshots(url_id)
        completed: Set[Tuple[str, int]] = set()
        if self.settings.resume and not self.settings.force:
            completed = self.store.get_completed(url_id)
            if completed and not self.settings.all_versions:
                return None

        candidates = self._candidates(url, snapshots)
        if not candidates:
            return [
                self._failure(
                    url_id, url, "no downloadable snapshot and live fetch disabled"
                )
            ]
        if self.settings.all_versions:
            return self._download_versions(url_id, url, candidates, completed)

        last_error = "no download candidate succeeded"
        wayback_failed = False
        tried = 0
        for candidate in candidates:
            key = (candidate.source, candidate.snapshot_id or 0)
            if key in completed and not self.settings.force:
                continue
            if tried >= 8:
                break
            tried += 1
            try:
                return [
                    self._try_candidate(
                        url_id, url, candidate, version_tag=None
                    )
                ]
            except TooLarge as exc:
                last_error = f"too large: {exc}"
                self.log.debug("%s: %s", url, last_error)
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)
                if candidate.source == "wayback":
                    wayback_failed = True
                self.log.debug("%s [%s]: %s", url, candidate.source, exc)

        if wayback_failed and not self._stop.is_set():
            for alternate in self._wayback_alternates(url):
                try:
                    return [
                        self._try_candidate(
                            url_id, url, alternate, version_tag=None
                        )
                    ]
                except Exception as exc:  # noqa: BLE001
                    last_error = str(exc)

        return [self._failure(url_id, url, last_error)]

    def _download_versions(
        self,
        url_id: int,
        url: str,
        candidates: List[DownloadCandidate],
        completed: Set[Tuple[str, int]],
    ) -> Optional[List[DownloadResult]]:
        """Attempt every distinct capture selected by --all-versions."""
        candidates = self._limit_versions(url, candidates)
        results: List[DownloadResult] = []
        last_error = "no download candidate succeeded"
        attempted = 0
        for candidate in candidates:
            key = (candidate.source, candidate.snapshot_id or 0)
            if key in completed and not self.settings.force:
                continue
            attempted += 1
            try:
                results.append(
                    self._try_candidate(
                        url_id,
                        url,
                        candidate,
                        version_tag=self._version_tag(candidate),
                    )
                )
            except TooLarge as exc:
                last_error = f"too large: {exc}"
                self.log.debug("%s: %s", url, last_error)
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)
                self.log.debug("%s [%s]: %s", url, candidate.source, exc)
        if results:
            return results
        if attempted == 0:
            return None
        return [self._failure(url_id, url, last_error)]

    def _try_candidate(
        self,
        url_id: int,
        url: str,
        candidate: DownloadCandidate,
        version_tag: Optional[str],
    ) -> DownloadResult:
        fetched = self._fetch(candidate)
        path, digest, duplicate_of = self._write_content(
            url, fetched.body, fetched.content_type, version_tag
        )
        if not duplicate_of:
            with self._bytes_lock:
                self._total_bytes += len(fetched.body)
        return DownloadResult(
            url=url,
            source=candidate.source,
            url_id=url_id,
            snapshot_id=candidate.snapshot_id or 0,
            path=path,
            sha256=digest,
            size=len(fetched.body),
            http_status=fetched.http_status,
            content_type=fetched.content_type,
            timestamp=candidate.timestamp,
            status="duplicate" if duplicate_of else "saved",
            duplicate_of=duplicate_of,
        )

    def _failure(self, url_id: int, url: str, error: str) -> DownloadResult:
        return DownloadResult(
            url=url,
            source="failed",
            url_id=url_id,
            status="failed",
            error=error,
        )

    def _candidates(
        self, url: str, snapshots: List[DownloadCandidate]
    ) -> List[DownloadCandidate]:
        archive: List[DownloadCandidate] = []
        for snapshot in snapshots:
            if not timestamp_in_range(
                snapshot.timestamp,
                self.settings.from_date,
                self.settings.to_date,
            ):
                continue
            candidate = self._candidate_from_snapshot(url, snapshot)
            if candidate:
                archive.append(candidate)

        # Prefer successful captures and recent timestamps.
        archive.sort(
            key=lambda c: (
                0 if c.status.isdigit() and 200 <= int(c.status) <= 299 else 1,
                SOURCE_PRIORITY.get(c.source, 50),
                _negative_timestamp(c.timestamp),
            )
        )

        deduped: List[DownloadCandidate] = []
        seen = set()
        for candidate in archive:
            identity = (
                candidate.source,
                candidate.digest or candidate.response_hash or candidate.timestamp,
                candidate.warc_offset,
            )
            if identity in seen:
                continue
            seen.add(identity)
            deduped.append(candidate)

        # A live fetch has no capture date, so it cannot satisfy a historical
        # date range.
        if self.settings.allow_live and not (
            self.settings.from_date or self.settings.to_date
        ):
            deduped.append(
                DownloadCandidate(
                    url=url,
                    source="live",
                    download_url=url,
                )
            )
        return deduped

    def _candidate_from_snapshot(
        self, url: str, snapshot: DownloadCandidate
    ) -> Optional[DownloadCandidate]:
        candidate = DownloadCandidate(
            url=url,
            source=snapshot.source,
            snapshot_id=snapshot.snapshot_id,
            timestamp=snapshot.timestamp,
            status=snapshot.status,
            mime=snapshot.mime,
            digest=snapshot.digest,
            warc_filename=snapshot.warc_filename,
            warc_offset=snapshot.warc_offset,
            warc_length=snapshot.warc_length,
            response_hash=snapshot.response_hash,
            download_url=snapshot.download_url,
        )
        if snapshot.source == "wayback" and snapshot.timestamp:
            candidate.download_url = (
                f"https://web.archive.org/web/{snapshot.timestamp}id_/{url}"
            )
            return candidate
        if snapshot.source == "commoncrawl" and snapshot.warc_filename:
            return candidate
        if snapshot.source == "arquivo":
            if not candidate.download_url and snapshot.timestamp:
                candidate.download_url = (
                    f"https://arquivo.pt/noFrame/replay/"
                    f"{snapshot.timestamp}id_/{url}"
                )
            return candidate if candidate.download_url else None
        if snapshot.source == "urlscan" and snapshot.response_hash:
            candidate.download_url = (
                f"https://urlscan.io/responses/{snapshot.response_hash}/"
            )
            return candidate
        if candidate.download_url.startswith(("http://", "https://")):
            return candidate
        return None

    def _limit_versions(
        self, url: str, candidates: List[DownloadCandidate]
    ) -> List[DownloadCandidate]:
        limit = max(1, self.settings.max_versions_per_url)
        result: List[DownloadCandidate] = []
        seen_content = set()
        for candidate in candidates:
            identity = (
                candidate.digest
                or candidate.response_hash
                or candidate.timestamp
                or candidate.source
            )
            if identity in seen_content and candidate.source != "live":
                continue
            seen_content.add(identity)
            result.append(candidate)
            if len(result) >= limit:
                break
        return result

    def _version_tag(self, candidate: DownloadCandidate) -> str:
        prefix = {
            "wayback": "wb",
            "commoncrawl": "cc",
            "arquivo": "ar",
            "urlscan": "us",
            "live": "live",
        }.get(candidate.source, candidate.source[:2] or "x")
        value = candidate.timestamp or (candidate.digest or "")[:10] or "na"
        return f"{prefix}{value}"

    def _wayback_alternates(self, url: str) -> List[DownloadCandidate]:
        host = host_from_url(url) or self.settings.domains[0]
        ctx = SourceContext(
            settings=self.settings,
            domain=host,
            store=self.store,
            http=self.http,
            rate=self.rate,
            log=self.log,
        )
        try:
            snapshots = self.wayback.alternates(ctx, url, limit=3)
        except Exception as exc:
            self.log.debug("wayback alternates failed for %s: %s", url, exc)
            return []
        result = []
        for snapshot in snapshots:
            candidate = self._candidate_from_snapshot(
                url,
                DownloadCandidate(
                    url=url,
                    source="wayback",
                    timestamp=snapshot.timestamp,
                    status=snapshot.status,
                    mime=snapshot.mime,
                    digest=snapshot.digest,
                    download_url=snapshot.download_url,
                ),
            )
            if candidate:
                result.append(candidate)
        return result

    # ----------------------------------------------------------------- fetch

    def _fetch(self, candidate: DownloadCandidate) -> FetchResult:
        if candidate.source == "wayback":
            return self._fetch_http(
                candidate.download_url,
                candidate,
                allow_redirects=False,
                archive_check=True,
                interval=0.15,
            )
        if candidate.source == "commoncrawl":
            return self._fetch_warc(candidate)
        if candidate.source == "arquivo":
            return self._fetch_http(
                candidate.download_url,
                candidate,
                allow_redirects=False,
                archive_check=True,
                interval=0.02,
            )
        if candidate.source == "urlscan":
            headers = {}
            if self.settings.urlscan_key:
                headers["api-key"] = self.settings.urlscan_key
            return self._fetch_http(
                candidate.download_url,
                candidate,
                allow_redirects=True,
                archive_check=False,
                interval=0.5,
                headers=headers,
            )
        return self._fetch_http(
            candidate.download_url or candidate.url,
            candidate,
            allow_redirects=True,
            archive_check=False,
            interval=0.05,
        )

    def _fetch_http(
        self,
        url: str,
        candidate: DownloadCandidate,
        allow_redirects: bool,
        archive_check: bool,
        interval: float,
        headers: Optional[dict] = None,
    ) -> FetchResult:
        if not url:
            raise DownloadError("empty download URL")
        host = host_from_url(url) or "unknown"
        self.rate.wait(host, interval)
        self.log.debug("GET %s", url)
        try:
            response = self.http.get(
                url,
                headers=headers or None,
                stream=True,
                allow_redirects=allow_redirects,
                timeout=max(self.settings.timeout, 60),
            )
        except Exception as exc:
            raise DownloadError(f"request failed: {exc}") from exc
        with response:
            if response.status_code < 200 or response.status_code >= 300:
                raise DownloadError(f"HTTP {response.status_code}")
            try:
                body = read_response_limited(response, self.settings.max_file_size)
            except TooLarge:
                raise
            except Exception as exc:
                raise DownloadError(f"could not read response: {exc}") from exc
            if not body:
                raise DownloadError("empty response body")
            content_type = (response.headers.get("Content-Type") or "").strip()
            if archive_check:
                sample = body[:12000].decode("utf-8", "ignore")
                if looks_like_archive_error(sample):
                    raise DownloadError("archive returned an error page")
            return FetchResult(
                body=body,
                content_type=content_type or candidate.mime,
                http_status=response.status_code,
                final_url=response.url,
            )

    def _fetch_warc(self, candidate: DownloadCandidate) -> FetchResult:
        filename = candidate.warc_filename
        offset = int(candidate.warc_offset or 0)
        length = int(candidate.warc_length or 0)
        if not filename or length <= 0:
            raise DownloadError("WARC location is incomplete")
        if self.settings.max_file_size:
            max_range = max(
                self.settings.max_file_size * 2 + 1024 * 1024,
                4 * 1024 * 1024,
            )
            if length > max_range:
                raise DownloadError(f"WARC range too large ({length} bytes)")
        url = "https://data.commoncrawl.org/" + filename.lstrip("/")
        self.rate.wait("data.commoncrawl.org", 0.02)
        headers = {"Range": f"bytes={offset}-{offset + length - 1}"}
        try:
            response = self.http.get(
                url, headers=headers, stream=True, timeout=max(self.settings.timeout, 90)
            )
        except Exception as exc:
            raise DownloadError(f"WARC request failed: {exc}") from exc
        with response:
            if response.status_code != 206:
                raise DownloadError(
                    f"WARC range request returned HTTP {response.status_code}"
                )
            chunks = []
            total = 0
            for chunk in response.iter_content(64 * 1024):
                if not chunk:
                    continue
                total += len(chunk)
                if total > length:
                    break
                chunks.append(chunk)
            data = b"".join(chunks)
        if len(data) < length:
            raise DownloadError(f"WARC range truncated ({len(data)} < {length})")
        result = parse_warc_record(data)
        if (
            self.settings.max_file_size
            and len(result.body) > self.settings.max_file_size
        ):
            raise TooLarge(
                f"WARC body {len(result.body)} exceeds limit "
                f"{self.settings.max_file_size}"
            )
        if result.content_type and not candidate.mime:
            candidate.mime = result.content_type
        return result

    # ----------------------------------------------------------------- store

    def _write_content(
        self,
        url: str,
        body: bytes,
        content_type: str,
        version_tag: Optional[str],
    ) -> Tuple[str, str, str]:
        digest = sha256_bytes(body)
        with self._save_lock:
            existing = self.hashes.get(digest)
            restore: Optional[Tuple[str, Path]] = None
            if existing and not self.settings.force:
                try:
                    existing_path = safe_join(self.files_dir, existing)
                except ValueError:
                    self.hashes.pop(digest, None)
                else:
                    if existing_path.is_file():
                        if _hash_file(existing_path) == digest:
                            return existing, digest, existing
                        # A corrupt file must not be reported as a duplicate.
                        self.hashes.pop(digest, None)
                    else:
                        # Keep the original relative path so resumed runs
                        # restore a deleted download instead of silently
                        # recording a duplicate that does not exist.
                        restore = (existing, existing_path)
            if restore is not None:
                relative, target = restore
            else:
                relative = safe_path_for_url(url, content_type, version_tag)
                target = safe_join(self.files_dir, relative)
            if target.exists() and not self.settings.force:
                if target.is_file() and _hash_file(target) == digest:
                    self.hashes[digest] = relative
                    return relative, digest, ""
                relative = _append_hash(relative, digest)
                target = safe_join(self.files_dir, relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_name(
                target.name + f".part-{os.getpid()}-{threading.get_ident()}"
            )
            try:
                temporary.write_bytes(body)
                os.chmod(temporary, 0o644)
                os.replace(temporary, target)
            finally:
                if temporary.exists():
                    try:
                        temporary.unlink()
                    except OSError:
                        pass
            self.hashes[digest] = relative
            return relative, digest, ""

    def _record(self, result: DownloadResult) -> None:
        try:
            self.store.record_download(result)
            self.store.commit()
        except Exception as exc:  # noqa: BLE001
            self.log.warning("could not record download %s: %s", result.url, exc)
        record = {
            "url": result.url,
            "source": result.source,
            "path": result.path,
            "sha256": result.sha256,
            "size": result.size,
            "http_status": result.http_status,
            "content_type": result.content_type,
            "timestamp": result.timestamp,
            "status": result.status,
            "duplicate_of": result.duplicate_of,
            "error": result.error,
        }
        with self._json_lock:
            with open(self.downloads_jsonl, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    def _write_failed_list(self) -> None:
        path = self.meta_dir / "failed.txt"
        try:
            with open(path, "w", encoding="utf-8") as handle:
                for url, error in self.store.failed_urls():
                    handle.write(f"{url}\t{error}\n")
        except OSError as exc:
            self.log.debug("could not write failed list: %s", exc)


def _negative_timestamp(timestamp: str) -> str:
    # Sorting strings in reverse order is not directly possible with a key;
    # invert the digits so the newest timestamp sorts first.
    if not timestamp:
        return "99999999999999"
    return "".join(str(9 - int(char)) if char.isdigit() else char for char in timestamp)


def _append_hash(relative: str, digest: str) -> str:
    path = Path(relative)
    return str(path.with_name(f"{path.stem}__{digest[:10]}{path.suffix}"))


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
