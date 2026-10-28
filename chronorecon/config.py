"""Configuration defaults and source catalogue."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

VERSION = "1.0.0"

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 ChronoRecon/1.0"
)

DEFAULT_URL_SOURCES = [
    "wayback",
    "commoncrawl",
    "otx",
    "urlscan",
    "arquivo",
    "ghostarchive",
]

DEFAULT_PASSIVE_SOURCES = [
    "crtsh",
    "certspotter",
    "hackertarget",
    "rapiddns",
]

# Sources that need an API key.  They are skipped automatically when the key
# is missing and enabled automatically when it is present.
KEYED_SOURCES = {"virustotal"}

SOURCE_DESCRIPTIONS: Dict[str, str] = {
    "wayback": "Internet Archive Wayback CDX (all captures, resume-key pagination)",
    "commoncrawl": "Common Crawl URL index (multiple crawls) + direct WARC body recovery",
    "otx": "AlienVault OTX domain URL list",
    "urlscan": "urlscan.io historical scans (+ response-body hashes with an API key)",
    "arquivo": "Arquivo.pt CDX archive (Portuguese web archive)",
    "ghostarchive": "GhostArchive search index",
    "virustotal": "VirusTotal domain URLs (requires VT_API_KEY)",
    "crtsh": "crt.sh certificate transparency logs (passive subdomains)",
    "certspotter": "Cert Spotter certificate transparency API (passive subdomains)",
    "otx_passive": "AlienVault OTX passive DNS (passive subdomains)",
    "hackertarget": "HackerTarget host search (passive subdomains)",
    "rapiddns": "RapidDNS subdomain index (passive subdomains)",
    "import": "URLs imported with --from-file",
}

URL_SOURCES = {
    "wayback",
    "commoncrawl",
    "otx",
    "urlscan",
    "arquivo",
    "ghostarchive",
    "virustotal",
}

PASSIVE_SOURCES = {
    "crtsh",
    "certspotter",
    "otx_passive",
    "hackertarget",
    "rapiddns",
}

ALL_SOURCES = URL_SOURCES | PASSIVE_SOURCES


@dataclass
class Settings:
    domains: List[str]
    output_root: Path
    include_subdomains: bool = True
    download: bool = True

    # Source selection.
    url_sources: List[str] = field(default_factory=lambda: list(DEFAULT_URL_SOURCES))
    passive_sources: List[str] = field(default_factory=lambda: list(DEFAULT_PASSIVE_SOURCES))

    # Network.
    timeout: int = 45
    retries: int = 4
    threads: int = 6
    insecure: bool = False
    user_agent: str = DEFAULT_USER_AGENT

    # Limits.  0 means unlimited.
    max_urls_per_source: int = 0
    max_captures: int = 0
    max_files: int = 0
    max_file_size: int = 50 * 1024 * 1024
    max_total_size: int = 0
    max_versions_per_url: int = 10

    # Source-specific knobs.
    cc_indexes: int = 3
    cc_all: bool = False
    otx_pages: int = 10
    urlscan_pages: int = 3
    urlscan_details: int = 50
    vt_limit: int = 80
    vt_delay: float = 15.0
    ghost_pages: int = 3
    rapiddns_pages: int = 1

    # Extra URL lists (gau, waymore, waybackurls, manual notes, ...).
    import_files: List[str] = field(default_factory=list)

    # Download behaviour.
    all_versions: bool = False
    resume: bool = True
    force: bool = False
    allow_live: bool = True
    only_ext: Set[str] = field(default_factory=set)
    exclude_ext: Set[str] = field(default_factory=set)
    include_regex: Optional[str] = None
    exclude_regex: Optional[str] = None

    # Dates (YYYY, YYYYMM, YYYYMMDD or full 14 digit).
    from_date: str = ""
    to_date: str = ""

    # API keys.
    urlscan_key: Optional[str] = None
    vt_key: Optional[str] = None
    otx_key: Optional[str] = None

    # Output/debug.
    quiet: bool = False
    verbose: bool = False

    def downloads_enabled(self) -> bool:
        return bool(self.download)

    def effective_max_urls(self) -> int:
        return self.max_urls_per_source

    def all_source_names(self) -> List[str]:
        return self.url_sources + self.passive_sources
