"""SQLite storage for URLs, snapshots, subdomains and download state."""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple

from .models import DownloadCandidate, DownloadResult, Snapshot, UrlHit
from .utils import now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    host TEXT NOT NULL,
    first_seen TEXT,
    last_seen TEXT,
    status TEXT,
    mime TEXT,
    digest TEXT,
    length INTEGER,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_urls_host ON urls(host);

CREATE TABLE IF NOT EXISTS url_sources (
    url_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    PRIMARY KEY (url_id, source),
    FOREIGN KEY (url_id) REFERENCES urls(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT '',
    mime TEXT NOT NULL DEFAULT '',
    digest TEXT NOT NULL DEFAULT '',
    length INTEGER NOT NULL DEFAULT 0,
    warc_filename TEXT NOT NULL DEFAULT '',
    warc_offset INTEGER NOT NULL DEFAULT 0,
    warc_length INTEGER NOT NULL DEFAULT 0,
    response_hash TEXT NOT NULL DEFAULT '',
    download_url TEXT NOT NULL DEFAULT '',
    extra TEXT NOT NULL DEFAULT '{}',
    UNIQUE (url_id, source, timestamp, digest, response_hash, warc_filename, warc_offset),
    FOREIGN KEY (url_id) REFERENCES urls(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_snapshots_url ON snapshots(url_id);

CREATE TABLE IF NOT EXISTS subdomains (
    host TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subdomain_sources (
    host TEXT NOT NULL,
    source TEXT NOT NULL,
    PRIMARY KEY (host, source),
    FOREIGN KEY (host) REFERENCES subdomains(host) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS downloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_id INTEGER NOT NULL,
    snapshot_id INTEGER NOT NULL DEFAULT 0,
    url TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    sha256 TEXT NOT NULL DEFAULT '',
    size INTEGER NOT NULL DEFAULT 0,
    http_status INTEGER NOT NULL DEFAULT 0,
    content_type TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    duplicate_of TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE (url_id, source, snapshot_id, path)
);
CREATE INDEX IF NOT EXISTS idx_downloads_url ON downloads(url_id);

CREATE TABLE IF NOT EXISTS source_runs (
    source TEXT PRIMARY KEY,
    urls INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    seconds REAL NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL DEFAULT ''
);
"""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(
            str(path), timeout=60, check_same_thread=False
        )
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        with self._lock:
            try:
                self.conn.commit()
            finally:
                self.conn.close()

    def commit(self) -> None:
        with self._lock:
            self.conn.commit()

    # ------------------------------------------------------------------ urls

    def _merge_url_row(
        self,
        row: sqlite3.Row,
        timestamp: str,
        status: str,
        mime: str,
        digest: str,
        length: int,
    ) -> Tuple:
        first_seen = row["first_seen"] or ""
        last_seen = row["last_seen"] or ""
        if timestamp:
            if not first_seen or timestamp < first_seen:
                first_seen = timestamp
            if not last_seen or timestamp > last_seen:
                last_seen = timestamp

        old_status = (row["status"] or "").strip()
        new_status = (status or "").strip()
        if not old_status:
            merged_status = new_status
        elif new_status.isdigit() and 200 <= int(new_status) <= 299:
            if not (old_status.isdigit() and 200 <= int(old_status) <= 299):
                merged_status = new_status
            else:
                merged_status = old_status
        else:
            merged_status = old_status

        old_mime = (row["mime"] or "").strip()
        merged_mime = old_mime
        if (not old_mime or old_mime.lower() in ("unk", "unknown", "application/octet-stream")) and mime:
            merged_mime = mime

        merged_digest = (row["digest"] or "").strip() or (digest or "").strip()
        old_length = row["length"] or 0
        merged_length = old_length if old_length else (length or 0)
        return (
            first_seen or None,
            last_seen or None,
            merged_status or None,
            merged_mime or None,
            merged_digest or None,
            merged_length or None,
        )

    def add_hit(self, hit: UrlHit) -> Tuple[bool, bool]:
        """Insert a URL hit.  Returns ``(new_url, new_snapshot)``."""
        snap = hit.snapshot
        timestamp = hit.timestamp or (snap.timestamp if snap else "")
        status = hit.status or (snap.status if snap else "")
        mime = hit.mime or (snap.mime if snap else "")
        digest = hit.digest or (snap.digest if snap else "")
        length = hit.length or (snap.length if snap else 0)
        created = now_iso()

        with self._lock:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO urls(url, host, created_at) VALUES (?, ?, ?)",
                (hit.url, hit_url_host(hit.url), created),
            )
            new_url = cur.rowcount > 0
            row = self.conn.execute(
                "SELECT id, first_seen, last_seen, status, mime, digest, length "
                "FROM urls WHERE url = ?",
                (hit.url,),
            ).fetchone()
            if row is None:
                return False, False
            url_id = int(row["id"])
            merged = self._merge_url_row(row, timestamp, status, mime, digest, length)
            self.conn.execute(
                "UPDATE urls SET first_seen=?, last_seen=?, status=?, mime=?, digest=?, length=? "
                "WHERE id=?",
                (*merged, url_id),
            )
            self.conn.execute(
                "INSERT OR IGNORE INTO url_sources(url_id, source) VALUES (?, ?)",
                (url_id, hit.source),
            )

            new_snapshot = False
            if snap is None:
                snap = Snapshot(
                    source=hit.source,
                    timestamp=timestamp,
                    status=status,
                    mime=mime,
                    digest=digest,
                    length=length,
                )
            # Only store a snapshot when it contains capture-level data.
            if snap.timestamp or snap.download_url or snap.warc_filename or snap.response_hash:
                cur = self.conn.execute(
                    "INSERT OR IGNORE INTO snapshots("
                    "url_id, source, timestamp, status, mime, digest, length, "
                    "warc_filename, warc_offset, warc_length, response_hash, download_url, extra"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        url_id,
                        snap.source or hit.source,
                        snap.timestamp or "",
                        snap.status or "",
                        snap.mime or "",
                        snap.digest or "",
                        int(snap.length or 0),
                        snap.warc_filename or "",
                        int(snap.warc_offset or 0),
                        int(snap.warc_length or 0),
                        snap.response_hash or "",
                        snap.download_url or "",
                        json.dumps(snap.extra or {}, ensure_ascii=False),
                    ),
                )
                new_snapshot = cur.rowcount > 0
            return new_url, new_snapshot

    def add_subdomain(self, host: str, source: str) -> bool:
        host = (host or "").rstrip(".").lower()
        if not host:
            return False
        with self._lock:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO subdomains(host, created_at) VALUES (?, ?)",
                (host, now_iso()),
            )
            self.conn.execute(
                "INSERT OR IGNORE INTO subdomain_sources(host, source) VALUES (?, ?)",
                (host, source),
            )
            return cur.rowcount > 0

    def record_source_run(
        self,
        source: str,
        urls: int,
        errors: int,
        seconds: float,
        status: str,
        message: str = "",
    ) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO source_runs(source, urls, errors, seconds, status, message) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(source) DO UPDATE SET "
                "urls=excluded.urls, errors=excluded.errors, seconds=excluded.seconds, "
                "status=excluded.status, message=excluded.message",
                (source, urls, errors, seconds, status, message[:1000]),
            )
            self.conn.commit()

    # --------------------------------------------------------------- queries

    @contextmanager
    def _read_connection(self) -> Iterator[sqlite3.Connection]:
        """Open a read connection with all pending writes visible.

        Download workers write through ``self.conn`` while long-lived cursors
        are open.  A separate connection keeps those cursors stable, and the
        commit before opening it makes recent writes visible without breaking
        the caller's transaction (all writes are statement-level).
        """
        with self._lock:
            self.conn.commit()
        conn = sqlite3.connect(str(self.path), timeout=60)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def iter_urls(self) -> Iterator[sqlite3.Row]:
        """Yield URLs from a dedicated, stable read snapshot."""
        with self._read_connection() as conn:
            for row in conn.execute("SELECT id, url, host FROM urls ORDER BY url"):
                yield row

    def get_url(self, url_id: int) -> Optional[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(
                "SELECT id, url, host FROM urls WHERE id = ?", (url_id,)
            ).fetchone()

    def get_sources(self, url_id: int) -> List[str]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT source FROM url_sources WHERE url_id = ? ORDER BY source",
                (url_id,),
            ).fetchall()
        return [row["source"] for row in rows]

    def get_snapshots(self, url_id: int) -> List[DownloadCandidate]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, url_id, source, timestamp, status, mime, digest, length, "
                "warc_filename, warc_offset, warc_length, response_hash, download_url "
                "FROM snapshots WHERE url_id = ?",
                (url_id,),
            ).fetchall()
        candidates = []
        for row in rows:
            candidates.append(
                DownloadCandidate(
                    url="",
                    source=row["source"],
                    snapshot_id=int(row["id"]),
                    timestamp=row["timestamp"] or "",
                    status=row["status"] or "",
                    mime=row["mime"] or "",
                    digest=row["digest"] or "",
                    warc_filename=row["warc_filename"] or "",
                    warc_offset=int(row["warc_offset"] or 0),
                    warc_length=int(row["warc_length"] or 0),
                    response_hash=row["response_hash"] or "",
                    download_url=row["download_url"] or "",
                )
            )
        return candidates

    def get_completed(self, url_id: int) -> Set[Tuple[str, int]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT source, snapshot_id FROM downloads "
                "WHERE url_id = ? AND status IN ('saved', 'duplicate')",
                (url_id,),
            ).fetchall()
        return {(row["source"], int(row["snapshot_id"] or 0)) for row in rows}

    def record_download(self, result: DownloadResult) -> None:
        with self._lock:
            if result.status in ("saved", "duplicate"):
                # A later successful retry makes an earlier failure stale.
                self.conn.execute(
                    "DELETE FROM downloads WHERE url_id = ? AND status = 'failed'",
                    (result.url_id,),
                )
            self.conn.execute(
                "INSERT INTO downloads("
                "url_id, snapshot_id, url, source, path, sha256, size, http_status, "
                "content_type, timestamp, status, duplicate_of, error, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(url_id, source, snapshot_id, path) DO UPDATE SET "
                "sha256=excluded.sha256, size=excluded.size, http_status=excluded.http_status, "
                "content_type=excluded.content_type, timestamp=excluded.timestamp, "
                "status=excluded.status, duplicate_of=excluded.duplicate_of, "
                "error=excluded.error, created_at=excluded.created_at",
                (
                    result.url_id,
                    result.snapshot_id,
                    result.url,
                    result.source,
                    result.path,
                    result.sha256,
                    result.size,
                    result.http_status,
                    result.content_type,
                    result.timestamp,
                    result.status,
                    result.duplicate_of,
                    result.error[:2000],
                    now_iso(),
                ),
            )

    # -------------------------------------------------------------- reporting

    def counts(self) -> Dict[str, int]:
        with self._lock:
            urls = self.conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
            hosts = self.conn.execute("SELECT COUNT(*) FROM subdomains").fetchone()[0]
            snapshots = self.conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
            saved = self.conn.execute(
                "SELECT COUNT(*) FROM downloads WHERE status = 'saved'"
            ).fetchone()[0]
            duplicates = self.conn.execute(
                "SELECT COUNT(*) FROM downloads WHERE status = 'duplicate'"
            ).fetchone()[0]
            failed = self.conn.execute(
                "SELECT COUNT(*) FROM downloads WHERE status = 'failed'"
            ).fetchone()[0]
            skipped = self.conn.execute(
                "SELECT COUNT(*) FROM downloads WHERE status = 'skipped'"
            ).fetchone()[0]
            saved_bytes = self.conn.execute(
                "SELECT COALESCE(SUM(size), 0) FROM downloads WHERE status = 'saved'"
            ).fetchone()[0]
            failed_bytes = self.conn.execute(
                "SELECT COALESCE(SUM(size), 0) FROM downloads WHERE status = 'failed'"
            ).fetchone()[0]
        return {
            "urls": int(urls),
            "hosts": int(hosts),
            "snapshots": int(snapshots),
            "saved": int(saved),
            "duplicates": int(duplicates),
            "failed": int(failed),
            "skipped": int(skipped),
            "saved_bytes": int(saved_bytes),
            "failed_bytes": int(failed_bytes),
        }

    def iter_report_rows(self) -> Iterator[Dict]:
        """Yield every URL with its merged metadata and source list."""
        with self._read_connection() as conn:
            cursor = conn.execute(
                "SELECT u.id, u.url, u.host, u.first_seen, u.last_seen, u.status, "
                "u.mime, u.digest, u.length, "
                "GROUP_CONCAT(us.source, ',') AS sources "
                "FROM urls u LEFT JOIN url_sources us ON us.url_id = u.id "
                "GROUP BY u.id ORDER BY u.url"
            )
            for row in cursor:
                sources = (row["sources"] or "").split(",")
                yield {
                    "id": int(row["id"]),
                    "url": row["url"],
                    "host": row["host"] or "",
                    "first_seen": row["first_seen"] or "",
                    "last_seen": row["last_seen"] or "",
                    "status": row["status"] or "",
                    "mime": row["mime"] or "",
                    "digest": row["digest"] or "",
                    "length": int(row["length"] or 0),
                    "sources": sorted({source for source in sources if source}),
                }

    def url_hosts(self) -> List[str]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT DISTINCT host FROM urls WHERE host != '' ORDER BY host"
            ).fetchall()
        return [row["host"] for row in rows]

    def download_rows(self, successful_only: bool = True) -> List[Dict]:
        query = (
            "SELECT url_id, url, source, path, sha256, size, http_status, "
            "content_type, timestamp, status, duplicate_of, error, created_at "
            "FROM downloads "
        )
        if successful_only:
            query += "WHERE status IN ('saved', 'duplicate') "
        query += "ORDER BY url_id, path"
        with self._lock:
            rows = self.conn.execute(query).fetchall()
        return [dict(row) for row in rows]

    def source_url_counts(self) -> Dict[str, int]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT source, COUNT(*) AS n FROM url_sources GROUP BY source ORDER BY source"
            ).fetchall()
        return {row["source"]: int(row["n"]) for row in rows}

    def source_runs(self) -> List[Dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT source, urls, errors, seconds, status, message "
                "FROM source_runs ORDER BY source"
            ).fetchall()
        return [dict(row) for row in rows]

    def subdomains(self) -> List[str]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT host FROM subdomains ORDER BY host"
            ).fetchall()
        return [row["host"] for row in rows]

    def host_sources(self) -> Dict[str, List[str]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT host, source FROM subdomain_sources ORDER BY host, source"
            ).fetchall()
        result: Dict[str, List[str]] = {}
        for row in rows:
            result.setdefault(row["host"], []).append(row["source"])
        return result

    def failed_urls(self) -> List[Tuple[str, str]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT url, error FROM downloads WHERE status = 'failed' "
                "ORDER BY created_at DESC"
            ).fetchall()
        return [(row["url"], row["error"]) for row in rows]

    def downloaded_url_ids(self) -> Set[int]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT DISTINCT url_id FROM downloads WHERE status IN ('saved', 'duplicate')"
            ).fetchall()
        return {int(row["url_id"]) for row in rows}

    def saved_hashes(self) -> Dict[str, str]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT sha256, path FROM downloads "
                "WHERE status IN ('saved', 'duplicate') AND sha256 != '' "
                "ORDER BY CASE status WHEN 'saved' THEN 0 ELSE 1 END, id"
            ).fetchall()
        result: Dict[str, str] = {}
        for row in rows:
            result[row["sha256"]] = row["path"]
        return result


def hit_url_host(url: str) -> str:
    from .utils import host_from_url

    return host_from_url(url)
