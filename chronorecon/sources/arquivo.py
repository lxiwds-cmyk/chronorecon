"""Arquivo.pt CDX source."""

from __future__ import annotations

import json

from ..models import Snapshot, UrlHit
from ..utils import compact_timestamp, host_from_url
from .base import BaseSource, SourceContext, SourceUnavailable

CDX_ENDPOINT = "https://arquivo.pt/wayback/cdx"
REPLAY_ENDPOINT = "https://arquivo.pt/noFrame/replay/{timestamp}id_/{url}"


class ArquivoSource(BaseSource):
    name = "arquivo"
    kind = "url"
    description = "Arquivo.pt web archive"

    def collect(self, ctx: SourceContext):
        limit = 100000
        if ctx.settings.max_urls_per_source:
            limit = min(limit, max(1, ctx.settings.max_urls_per_source))
        params = {
            "url": ctx.domain,
            "matchType": "domain",
            "output": "json",
            "fields": "url,timestamp,status,mime,digest,length,offset,filename",
            "limit": str(limit),
        }
        if not ctx.settings.all_versions:
            params["collapseTime"] = "8"
        try:
            response = ctx.http.get(
                CDX_ENDPOINT,
                params=params,
                timeout=max(ctx.settings.timeout, 90),
                stream=True,
            )
        except Exception as exc:
            raise SourceUnavailable(f"Arquivo.pt unavailable: {exc}")
        if response.status_code >= 400:
            snippet = response.text[:200].replace("\n", " ")
            response.close()
            raise SourceUnavailable(
                f"Arquivo.pt HTTP {response.status_code}: {snippet}"
            )
        count = 0
        with response:
            for raw in response.iter_lines(decode_unicode=True):
                if not raw:
                    continue
                if raw.lstrip().startswith("<"):
                    raise SourceUnavailable("Arquivo.pt returned HTML instead of JSON")
                try:
                    item = json.loads(raw)
                except ValueError:
                    continue
                if not isinstance(item, dict):
                    continue
                url = (item.get("url") or "").strip()
                if not url:
                    continue
                timestamp = compact_timestamp(item.get("timestamp"))
                status = str(item.get("status") or "")
                mime = str(item.get("mime") or "")
                digest = str(item.get("digest") or "")
                try:
                    length = int(item.get("length") or 0)
                except (TypeError, ValueError):
                    length = 0
                if item.get("mime") == "warc/revisit":
                    # Revisit records have no distinct payload; the original
                    # capture is a better download candidate.
                    continue
                snapshot = Snapshot(
                    source="arquivo",
                    timestamp=timestamp,
                    status=status,
                    mime=mime,
                    digest=digest,
                    length=length,
                    download_url=REPLAY_ENDPOINT.format(timestamp=timestamp, url=url),
                )
                host = host_from_url(url)
                if host:
                    ctx.add_subdomain(host, "arquivo")
                yield UrlHit(
                    url=url,
                    source="arquivo",
                    timestamp=timestamp,
                    status=status,
                    mime=mime,
                    digest=digest,
                    length=length,
                    snapshot=snapshot,
                )
                count += 1
                if ctx.settings.max_urls_per_source and count >= ctx.settings.max_urls_per_source:
                    ctx.log.warning(
                        "arquivo: stopped at max-urls-per-source=%s",
                        ctx.settings.max_urls_per_source,
                    )
                    break
        ctx.log.info("arquivo: %s capture rows", count)
