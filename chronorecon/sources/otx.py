"""AlienVault OTX URL and passive-DNS sources."""

from __future__ import annotations

import time

from ..models import Snapshot, UrlHit
from ..utils import compact_timestamp, host_from_url
from .base import BaseSource, SourceContext, SourceUnavailable

OTX_BASE = "https://otx.alienvault.com/api/v1/indicators/domain"


class OTXUrlsSource(BaseSource):
    name = "otx"
    kind = "url"
    description = "AlienVault OTX domain URL list"

    def collect(self, ctx: SourceContext):
        endpoint = f"{OTX_BASE}/{ctx.domain}/url_list"
        page = 1
        emitted = 0
        total_size = 0
        while page <= max(1, ctx.settings.otx_pages):
            params = {"limit": 500, "page": page}
            try:
                payload = ctx.http.get_json(
                    endpoint, params=params, timeout=max(ctx.settings.timeout, 90)
                )
            except Exception as exc:
                if page == 1:
                    raise SourceUnavailable(f"OTX URL list unavailable: {exc}")
                ctx.log.warning("otx: page %s failed: %s", page, exc)
                break
            items = payload.get("url_list") or []
            total_size = int(payload.get("full_size") or total_size or 0)
            if page == 1 and total_size:
                ctx.log.info("otx: %s URLs known for %s", total_size, ctx.domain)
            for item in items:
                if not isinstance(item, dict):
                    continue
                url = (item.get("url") or "").strip()
                if not url:
                    continue
                timestamp = compact_timestamp(item.get("date"))
                status = str(item.get("httpcode") or "")
                if not status:
                    status = str(
                        ((item.get("result") or {}).get("urlworker") or {}).get(
                            "http_code"
                        )
                        or ""
                    )
                hostname = item.get("hostname") or host_from_url(url)
                if hostname:
                    ctx.add_subdomain(hostname, "otx")
                snapshot = Snapshot(
                    source="otx",
                    timestamp=timestamp,
                    status=status,
                )
                yield UrlHit(
                    url=url,
                    source="otx",
                    timestamp=timestamp,
                    status=status,
                    snapshot=snapshot,
                )
                emitted += 1
                if (
                    ctx.settings.max_urls_per_source
                    and emitted >= ctx.settings.max_urls_per_source
                ):
                    ctx.log.warning(
                        "otx: stopped at max-urls-per-source=%s",
                        ctx.settings.max_urls_per_source,
                    )
                    return
            if not payload.get("has_next") or not items:
                break
            page += 1
            time.sleep(1.5)
        ctx.log.info("otx: %s URL rows", emitted)


class OTXPassiveSource(BaseSource):
    name = "otx_passive"
    kind = "passive"
    description = "AlienVault OTX passive DNS"
    requires_key = "otx"

    def collect(self, ctx: SourceContext):
        endpoint = f"{OTX_BASE}/{ctx.domain}/passive_dns"
        headers = {}
        if getattr(ctx.settings, "otx_key", None):
            headers["X-OTX-API-KEY"] = ctx.settings.otx_key
        try:
            response = ctx.http.get(
                endpoint,
                headers=headers,
                timeout=max(ctx.settings.timeout, 90),
            )
        except Exception as exc:
            raise SourceUnavailable(f"OTX passive DNS unavailable: {exc}")
        if response.status_code in (401, 403):
            raise SourceUnavailable(
                "OTX passive DNS requires an API key (set OTX_API_KEY or --otx-key)"
            )
        if response.status_code >= 400:
            raise SourceUnavailable(
                f"OTX passive DNS HTTP {response.status_code}"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise SourceUnavailable("OTX passive DNS returned invalid JSON") from exc
        count = 0
        for item in payload.get("passive_dns") or []:
            if not isinstance(item, dict):
                continue
            hostname = item.get("hostname") or item.get("host") or ""
            if hostname:
                ctx.add_subdomain(hostname, "otx_passive")
                count += 1
        ctx.log.info("otx_passive: %s host rows", count)
        yield from ()
