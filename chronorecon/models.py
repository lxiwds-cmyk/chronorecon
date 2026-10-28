"""Small data objects shared by collectors, the store and the downloader."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class Snapshot:
    """One archived (or live) observation of a URL."""

    source: str
    timestamp: str = ""
    status: str = ""
    mime: str = ""
    digest: str = ""
    length: int = 0
    warc_filename: str = ""
    warc_offset: int = 0
    warc_length: int = 0
    response_hash: str = ""
    download_url: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def identity(self):
        return (
            self.source,
            self.timestamp,
            self.digest,
            self.response_hash,
            self.warc_filename,
            self.warc_offset,
        )


@dataclass
class UrlHit:
    """A URL discovered by one source, with optional capture metadata."""

    url: str
    source: str
    timestamp: str = ""
    status: str = ""
    mime: str = ""
    digest: str = ""
    length: int = 0
    snapshot: Optional[Snapshot] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DownloadCandidate:
    """A concrete thing the downloader can attempt."""

    url: str
    source: str
    snapshot_id: Optional[int] = None
    timestamp: str = ""
    status: str = ""
    mime: str = ""
    digest: str = ""
    warc_filename: str = ""
    warc_offset: int = 0
    warc_length: int = 0
    response_hash: str = ""
    download_url: str = ""


@dataclass
class DownloadResult:
    url: str
    source: str
    url_id: int = 0
    snapshot_id: int = 0
    path: str = ""
    sha256: str = ""
    size: int = 0
    http_status: int = 0
    content_type: str = ""
    timestamp: str = ""
    status: str = "failed"
    duplicate_of: str = ""
    error: str = ""
