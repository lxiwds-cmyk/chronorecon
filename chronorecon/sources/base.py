"""Source interfaces and shared context."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, Iterator, Optional, Set

from ..config import Settings
from ..db import Store
from ..http import HttpClient, RateLimiter
from ..models import UrlHit
from ..utils import host_in_scope, normalize_domain


class SourceError(RuntimeError):
    pass


class SourceUnavailable(SourceError):
    pass


@dataclass
class SourceContext:
    settings: Settings
    domain: str
    store: Store
    http: HttpClient
    rate: RateLimiter
    log: logging.Logger
    subdomains: Set[str] = field(default_factory=set)
    stats: Dict[str, Dict[str, int]] = field(default_factory=dict)

    def add_subdomain(self, host: str, source: str) -> bool:
        host = (host or "").strip().lower()
        if host.startswith("*."):
            host = host[2:]
        if not host or "://" in host or "/" in host:
            try:
                host = normalize_domain(host)
            except ValueError:
                return False
        host = host.rstrip(".").lower()
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            pass
        if not host_in_scope(
            host, self.domain, self.settings.include_subdomains
        ):
            return False
        self.subdomains.add(host)
        added = self.store.add_subdomain(host, source)
        if added:
            self.bump(source, "hosts")
        return added

    def bump(self, source: str, key: str, amount: int = 1) -> None:
        bucket = self.stats.setdefault(source, {})
        bucket[key] = bucket.get(key, 0) + amount


class BaseSource:
    name = "base"
    kind = "url"  # "url" or "passive"
    description = ""
    requires_key: Optional[str] = None

    def is_available(self, settings: Settings) -> bool:
        if self.requires_key == "urlscan":
            return True  # search works without a key
        if self.requires_key == "virustotal":
            return bool(settings.vt_key)
        if self.requires_key == "otx":
            return bool(getattr(settings, "otx_key", None))
        return True

    def unavailable_reason(self, settings: Settings) -> str:
        if self.requires_key == "virustotal" and not settings.vt_key:
            return "set VT_API_KEY or --vt-key"
        if self.requires_key == "otx" and not getattr(settings, "otx_key", None):
            return "set OTX_API_KEY or --otx-key"
        return "source unavailable"

    def collect(self, ctx: SourceContext) -> Iterator[UrlHit]:
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.name}>"
