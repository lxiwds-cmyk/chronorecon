"""VirusTotal domain URL source (optional API key)."""

from __future__ import annotations

import time
from typing import Iterator

from ..models import Snapshot, UrlHit
from ..utils import compact_timestamp, host_from_url
from .base import BaseSource, SourceContext, SourceUnavailable


class VirusTotalSource(BaseSource):
    name = "virustotal"
    kind = "url"
    description = "VirusTotal domain URLs"
    requires_key = "virustotal"

    def collect(self, ctx: SourceContext) -> Iterator[UrlHit]:
        if not ctx.settings.vt_key:
            raise SourceUnavailable("VirusTotal requires VT_API_KEY or --vt-key")
        headers = {"x-apikey": ctx.settings.vt_key}
        url = f"https://www.virustotal.com/api/v3/domains/{ctx.domain}/urls?limit=40"
        emitted = 0
        pages = 0
        while url and emitted < max(1, ctx.settings.vt_limit):
            pages += 1
            try:
                payload = ctx.http.get_json(url, headers=headers, timeout=90)
            except Exception as exc:
                if pages == 1:
                    raise SourceUnavailable(f"VirusTotal unavailable: {exc}")
                ctx.log.warning("virustotal: page %s failed: %s", pages, exc)
                break
            for item in payload.get("data") or []:
                if not isinstance(item, dict):
                    continue
                attributes = item.get("attributes") or {}
                candidate = (attributes.get("url") or "").strip()
                if not candidate:
                    continue
                timestamp = compact_timestamp(
                    attributes.get("last_analysis_date")
                    or attributes.get("first_submission_date")
                )
                status = str(attributes.get("last_http_response_status_code") or "")
                headers_map = attributes.get("last_http_response_headers") or {}
                mime = ""
                if isinstance(headers_map, dict):
                    for key, value in headers_map.items():
                        if str(key).lower() == "content-type":
                            mime = str(value)
                            break
                digest = str(
                    attributes.get("last_http_response_content_sha256") or ""
                )
                host = host_from_url(candidate)
                if host:
                    ctx.add_subdomain(host, "virustotal")
                snapshot = Snapshot(
                    source="virustotal",
                    timestamp=timestamp,
                    status=status,
                    mime=mime,
                    digest=digest,
                )
                yield UrlHit(
                    url=candidate,
                    source="virustotal",
                    timestamp=timestamp,
                    status=status,
                    mime=mime,
                    digest=digest,
                    snapshot=snapshot,
                )
                emitted += 1
                if emitted >= ctx.settings.vt_limit:
                    break
            next_url = (payload.get("links") or {}).get("next")
            if not next_url or emitted >= ctx.settings.vt_limit:
                break
            url = next_url
            if ctx.settings.vt_delay > 0:
                time.sleep(ctx.settings.vt_delay)
        ctx.log.info("virustotal: %s URL rows across %s page(s)", emitted, pages)
