"""Source registry."""

from __future__ import annotations

from typing import Dict, List, Type

from .arquivo import ArquivoSource
from .base import BaseSource, SourceContext, SourceError, SourceUnavailable
from .commoncrawl import CommonCrawlSource
from .ghostarchive import GhostArchiveSource
from .otx import OTXPassiveSource, OTXUrlsSource
from .passive import (
    CertSpotterSource,
    CrtShSource,
    HackerTargetSource,
    RapidDnsSource,
)
from .urlscan import URLScanSource
from .virustotal import VirusTotalSource
from .wayback import WaybackSource

SOURCE_CLASSES: Dict[str, Type[BaseSource]] = {
    "wayback": WaybackSource,
    "commoncrawl": CommonCrawlSource,
    "otx": OTXUrlsSource,
    "urlscan": URLScanSource,
    "arquivo": ArquivoSource,
    "ghostarchive": GhostArchiveSource,
    "virustotal": VirusTotalSource,
    "crtsh": CrtShSource,
    "certspotter": CertSpotterSource,
    "otx_passive": OTXPassiveSource,
    "hackertarget": HackerTargetSource,
    "rapiddns": RapidDnsSource,
}


def build_source(name: str) -> BaseSource:
    try:
        return SOURCE_CLASSES[name]()
    except KeyError as exc:
        raise ValueError(f"unknown source: {name}") from exc


def source_names() -> List[str]:
    return sorted(SOURCE_CLASSES)


__all__ = [
    "BaseSource",
    "SourceContext",
    "SourceError",
    "SourceUnavailable",
    "SOURCE_CLASSES",
    "build_source",
    "source_names",
]
