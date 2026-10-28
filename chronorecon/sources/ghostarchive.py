"""GhostArchive search source.

GhostArchive is a separate public web archive.  Its search results are plain
HTML; we extract the original URL shown for each archived item.  This source is
intentionally best-effort and never required for a successful run.
"""

from __future__ import annotations

import html as html_lib
import re
import time
from typing import Iterator

from ..models import UrlHit
from ..utils import extract_original_url, host_from_url
from .base import BaseSource, SourceContext, SourceUnavailable

SEARCH_ENDPOINT = "https://ghostarchive.org/search"
ANCHOR_RE = re.compile(
    r'href="/archive/([A-Za-z0-9_-]+)"[^>]*>\s*(https?://[^<\s"]+)',
    re.IGNORECASE,
)
ORIG_RE = re.compile(r"\(Orig site:\s*(https?://[^)]+)\)", re.IGNORECASE)
NEXT_RE = re.compile(r'href="[^"]*[?&]page=(\d+)[^"]*"', re.IGNORECASE)


class GhostArchiveSource(BaseSource):
    name = "ghostarchive"
    kind = "url"
    description = "GhostArchive search index"

    def collect(self, ctx: SourceContext) -> Iterator[UrlHit]:
        seen = set()
        total = 0
        pages = max(1, ctx.settings.ghost_pages)
        for page in range(1, pages + 1):
            params = {"term": ctx.domain}
            if page > 1:
                params["page"] = str(page)
            try:
                response = ctx.http.get(
                    SEARCH_ENDPOINT,
                    params=params,
                    timeout=max(ctx.settings.timeout, 60),
                )
            except Exception as exc:
                if page == 1:
                    raise SourceUnavailable(f"GhostArchive unavailable: {exc}")
                ctx.log.warning("ghostarchive: page %s failed: %s", page, exc)
                break
            if response.status_code in (403, 429):
                if page == 1:
                    raise SourceUnavailable(
                        f"GhostArchive blocked the request (HTTP {response.status_code})"
                    )
                break
            if response.status_code >= 400:
                if page == 1:
                    raise SourceUnavailable(
                        f"GhostArchive HTTP {response.status_code}"
                    )
                break
            body = response.text or ""
            matches = list(ANCHOR_RE.finditer(body))
            if not matches:
                break
            for match in matches:
                display = html_lib.unescape(match.group(2)).strip()
                original = extract_original_url(display)
                if not host_from_url(original):
                    continue
                # If the displayed item is an archive wrapper, try the explicit
                # "Orig site" value in the surrounding table cell.
                tail = body[match.end() : match.end() + 500]
                orig_match = ORIG_RE.search(tail)
                if orig_match:
                    maybe = extract_original_url(
                        html_lib.unescape(orig_match.group(1)).strip()
                    )
                    if maybe:
                        original = maybe
                if original in seen:
                    continue
                seen.add(original)
                yield UrlHit(url=original, source="ghostarchive")
                total += 1
                if (
                    ctx.settings.max_urls_per_source
                    and total >= ctx.settings.max_urls_per_source
                ):
                    ctx.log.warning(
                        "ghostarchive: stopped at max-urls-per-source=%s",
                        ctx.settings.max_urls_per_source,
                    )
                    return
            page_numbers = [int(value) for value in NEXT_RE.findall(body)]
            if page_numbers and max(page_numbers) <= page:
                break
            time.sleep(1.0)
        ctx.log.info("ghostarchive: %s URL rows", total)
