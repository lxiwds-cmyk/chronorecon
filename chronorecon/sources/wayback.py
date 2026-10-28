"""Internet Archive Wayback Machine CDX source."""

from __future__ import annotations

import json
import time
from typing import List, Optional, Tuple

from ..models import Snapshot, UrlHit
from ..utils import compact_timestamp
from .base import BaseSource, SourceContext, SourceError, SourceUnavailable

CDX_ENDPOINT = "https://web.archive.org/cdx/search/cdx"
AVAILABILITY_ENDPOINT = "https://archive.org/wayback/available"
CDX_FIELDS = "timestamp,original,statuscode,mimetype,digest,length"
KNOWN_HEADERS = {"timestamp", "original", "urlkey", "statuscode", "mimetype", "digest", "length"}


def parse_cdx_json(text: str) -> Tuple[List[dict], Optional[str]]:
    """Parse the JSON array returned by the Wayback CDX server.

    The CDX server appends a resumption key as ``[], ["key"]`` when
    ``showResumeKey=true`` is used.  The key is not a CDX record.
    """
    try:
        data = json.loads(text)
    except ValueError as exc:
        snippet = (text or "")[:200].replace("\n", " ")
        raise SourceError(f"CDX returned non-JSON data: {snippet!r}") from exc
    if not isinstance(data, list):
        raise SourceError("CDX returned an unexpected JSON shape")
    if not data:
        return [], None

    header = None
    rows = data
    first = data[0]
    if (
        isinstance(first, list)
        and first
        and isinstance(first[0], str)
        and first[0] in KNOWN_HEADERS
    ):
        header = [str(column) for column in first]
        rows = data[1:]

    resume_key = None
    if (
        len(rows) >= 2
        and isinstance(rows[-2], list)
        and len(rows[-2]) == 0
        and isinstance(rows[-1], list)
        and len(rows[-1]) == 1
    ):
        resume_key = str(rows[-1][0])
        rows = rows[:-2]
    elif rows and isinstance(rows[-1], list) and len(rows[-1]) == 0:
        rows = rows[:-1]

    if header is None:
        header = ["timestamp", "original", "statuscode", "mimetype", "digest", "length"]

    records: List[dict] = []
    for row in rows:
        if not isinstance(row, list) or not row:
            continue
        # A resumption key can occasionally appear as a one-item row.
        if len(row) == 1 and header and header[0] != "urlkey":
            continue
        values = list(row) + [""] * max(0, len(header) - len(row))
        record = {header[i]: values[i] for i in range(len(header))}
        if record.get("original") or record.get("url"):
            records.append(record)
    return records, resume_key


def _record_to_hit(record: dict) -> Optional[UrlHit]:
    url = (record.get("original") or record.get("url") or "").strip()
    if not url:
        return None
    timestamp = compact_timestamp(record.get("timestamp"))
    status = str(record.get("statuscode") or record.get("status") or "")
    mime = str(record.get("mimetype") or record.get("mime") or "")
    digest = str(record.get("digest") or "")
    try:
        length = int(record.get("length") or 0)
    except (TypeError, ValueError):
        length = 0
    snapshot = Snapshot(
        source="wayback",
        timestamp=timestamp,
        status=status,
        mime=mime,
        digest=digest,
        length=length,
    )
    return UrlHit(
        url=url,
        source="wayback",
        timestamp=timestamp,
        status=status,
        mime=mime,
        digest=digest,
        length=length,
        snapshot=snapshot,
    )


class WaybackSource(BaseSource):
    name = "wayback"
    kind = "url"
    description = "Internet Archive Wayback Machine CDX"

    def collect(self, ctx: SourceContext):
        page_limit = 20000
        if ctx.settings.max_urls_per_source:
            page_limit = min(page_limit, max(1, ctx.settings.max_urls_per_source))
        if ctx.settings.all_versions and ctx.settings.max_captures:
            page_limit = min(page_limit, max(1, ctx.settings.max_captures))
        base = {
            "url": ctx.domain,
            "matchType": "domain",
            "output": "json",
            "fl": CDX_FIELDS,
            "showResumeKey": "true",
            "limit": str(page_limit),
        }
        if not ctx.settings.all_versions:
            base["collapse"] = "urlkey"
        if ctx.settings.from_date:
            base["from"] = ctx.settings.from_date
        if ctx.settings.to_date:
            base["to"] = ctx.settings.to_date

        resume_key: Optional[str] = None
        seen_keys = set()
        pages = 0
        emitted = 0
        while True:
            params = dict(base)
            if resume_key:
                params["resumeKey"] = resume_key
            ctx.log.info(
                "wayback: requesting CDX page %s%s (the archive can be slow)",
                pages + 1,
                " (resume key)" if resume_key else "",
            )
            try:
                text = self._fetch(
                    ctx,
                    params,
                    attempts=1 if "collapse" in params else 2,
                    timeout=60 if "collapse" in params else 90,
                )
            except SourceUnavailable as exc:
                # Collapsed domain queries are much more likely to hit the
                # CDX gateway timeout.  On the first page, retry without
                # collapsing; the database still deduplicates URLs, and the
                # downloader can choose the newest capture.
                if "collapse" not in params or pages or resume_key:
                    raise
                ctx.log.warning(
                    "wayback: collapsed query failed (%s); retrying without collapse",
                    exc,
                )
                base.pop("collapse", None)
                params.pop("collapse", None)
                text = self._fetch(ctx, params, attempts=2, timeout=90)
            records, next_key = parse_cdx_json(text)
            pages += 1
            for record in records:
                hit = _record_to_hit(record)
                if hit is None:
                    continue
                yield hit
                emitted += 1
                if ctx.settings.max_urls_per_source and emitted >= ctx.settings.max_urls_per_source:
                    ctx.log.warning(
                        "wayback: stopped at max-urls-per-source=%s",
                        ctx.settings.max_urls_per_source,
                    )
                    return
                if (
                    ctx.settings.all_versions
                    and ctx.settings.max_captures
                    and emitted >= ctx.settings.max_captures
                ):
                    ctx.log.warning(
                        "wayback: stopped at max-captures=%s",
                        ctx.settings.max_captures,
                    )
                    return
            ctx.log.debug(
                "wayback: page %s returned %s records (resume=%s)",
                pages,
                len(records),
                bool(next_key),
            )
            if not next_key:
                break
            if next_key in seen_keys:
                ctx.log.warning("wayback: repeated resumption key, stopping")
                break
            seen_keys.add(next_key)
            resume_key = next_key
            time.sleep(1.5)
        ctx.log.info("wayback: %s capture rows from %s page(s)", emitted, pages)

    def _fetch(
        self,
        ctx: SourceContext,
        params: dict,
        attempts: int = 2,
        timeout: int = 90,
    ) -> str:
        last_error = "unknown error"
        attempts = max(1, int(attempts))
        # CDX requests can legitimately take a minute on the public server.
        # Use a no-retry session and manually bound the number of attempts so
        # a heavily loaded archive cannot hold up the whole run for many
        # minutes through nested automatic retries.
        request_timeout = max(ctx.settings.timeout, int(timeout))
        for attempt in range(attempts):
            try:
                response = ctx.http.get(
                    CDX_ENDPOINT,
                    params=params,
                    timeout=request_timeout,
                    once=True,
                )
            except Exception as exc:  # network errors / read timeouts
                last_error = str(exc)
                ctx.log.warning(
                    "wayback: request %s/%s failed: %s", attempt + 1, attempts, exc
                )
                if attempt + 1 < attempts:
                    time.sleep(4 + attempt * 4)
                continue

            text = response.text or ""
            if response.status_code == 200 and text.lstrip().startswith("["):
                return text
            snippet = text[:300].replace("\n", " ")
            last_error = f"HTTP {response.status_code}: {snippet}"
            offline = (
                response.status_code in (429, 503)
                or "temporarily offline" in text[:4000].lower()
                or "too many requests" in text[:4000].lower()
            )
            if offline or response.status_code >= 500:
                ctx.log.warning(
                    "wayback: request %s/%s returned HTTP %s",
                    attempt + 1,
                    attempts,
                    response.status_code,
                )
                if attempt + 1 < attempts:
                    time.sleep(6 + attempt * 6)
                continue
            raise SourceUnavailable(f"Wayback CDX unavailable: {last_error}")
        raise SourceUnavailable(f"Wayback CDX unavailable after retries: {last_error}")

    def alternates(self, ctx: SourceContext, url: str, limit: int = 5) -> List[Snapshot]:
        """Fetch the latest successful captures of one URL for download retries."""
        params = {
            "url": url,
            "output": "json",
            "fl": CDX_FIELDS,
            "filter": "statuscode:200",
            "limit": f"-{max(1, limit)}",
            "fastLatest": "true",
        }
        snapshots: List[Snapshot] = []
        try:
            response = ctx.http.get(CDX_ENDPOINT, params=params, timeout=ctx.settings.timeout)
            if response.status_code == 200 and response.text.lstrip().startswith("["):
                records, _ = parse_cdx_json(response.text)
                for record in records:
                    hit = _record_to_hit(record)
                    if hit and hit.snapshot:
                        snapshots.append(hit.snapshot)
        except Exception as exc:
            ctx.log.debug("wayback alternates failed for %s: %s", url, exc)

        if not snapshots:
            try:
                response = ctx.http.get(
                    AVAILABILITY_ENDPOINT,
                    params={"url": url},
                    timeout=ctx.settings.timeout,
                )
                payload = response.json()
                closest = (payload.get("archived_snapshots") or {}).get("closest") or {}
                if closest.get("available") and closest.get("timestamp"):
                    timestamp = compact_timestamp(closest.get("timestamp"))
                    snapshots.append(
                        Snapshot(
                            source="wayback",
                            timestamp=timestamp,
                            status=str(closest.get("status") or "200"),
                            download_url=str(closest.get("url") or ""),
                        )
                    )
            except Exception as exc:
                ctx.log.debug("wayback availability failed for %s: %s", url, exc)

        # Deduplicate by timestamp.
        unique = {}
        for snapshot in snapshots:
            unique[snapshot.timestamp] = snapshot
        return list(unique.values())
