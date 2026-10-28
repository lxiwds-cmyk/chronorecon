"""Common Crawl index source with pagination."""

from __future__ import annotations

import json
import time
from typing import Iterator, List

from ..models import Snapshot, UrlHit
from ..utils import compact_timestamp
from .base import BaseSource, SourceContext, SourceUnavailable

COLLINFO = "https://index.commoncrawl.org/collinfo.json"
CC_FIELDS = "url,timestamp,status,mime,digest,length,offset,filename"


class CommonCrawlSource(BaseSource):
    name = "commoncrawl"
    kind = "url"
    description = "Common Crawl URL index and WARC records"

    def collect(self, ctx: SourceContext):
        indexes = self._indexes(ctx)
        total = 0
        for index in indexes:
            for hit in self._collect_index(ctx, index):
                yield hit
                total += 1
                if (
                    ctx.settings.max_urls_per_source
                    and total >= ctx.settings.max_urls_per_source
                ):
                    ctx.log.warning(
                        "commoncrawl: stopped at max-urls-per-source=%s",
                        ctx.settings.max_urls_per_source,
                    )
                    return
            ctx.log.info(
                "commoncrawl: %s -> %s rows so far", index.get("id"), total
            )
            time.sleep(0.6)
        ctx.log.info(
            "commoncrawl: %s rows across %s crawl(s)", total, len(indexes)
        )

    def _indexes(self, ctx: SourceContext) -> List[dict]:
        try:
            infos = ctx.http.get_json(COLLINFO, timeout=ctx.settings.timeout)
        except Exception as exc:
            raise SourceUnavailable(
                f"could not fetch Common Crawl collection list: {exc}"
            )
        if not isinstance(infos, list) or not infos:
            raise SourceUnavailable("Common Crawl returned an empty collection list")
        if ctx.settings.cc_all:
            selected = infos
        else:
            selected = infos[: max(1, ctx.settings.cc_indexes)]
        return [item for item in selected if item.get("cdx-api")]

    def _collect_index(self, ctx: SourceContext, index: dict) -> Iterator[UrlHit]:
        api = index["cdx-api"]
        params = {
            "url": ctx.domain,
            "matchType": "domain",
            "output": "json",
            "fl": CC_FIELDS,
        }
        if ctx.settings.from_date:
            params["from"] = ctx.settings.from_date
        if ctx.settings.to_date:
            params["to"] = ctx.settings.to_date

        pages = self._page_count(ctx, api, params)
        if pages and pages > 1:
            page_size = 5
            for page in range(pages):
                page_params = dict(params)
                page_params["page"] = str(page)
                page_params["pageSize"] = str(page_size)
                yield from self._consume(ctx, api, page_params)
                time.sleep(0.5)
            return
        yield from self._consume(ctx, api, params)

    def _page_count(self, ctx: SourceContext, api: str, params: dict) -> int:
        probe = dict(params)
        probe["showNumPages"] = "true"
        probe["pageSize"] = "5"
        try:
            response = ctx.http.get(api, params=probe, timeout=ctx.settings.timeout)
            payload = response.json()
            if isinstance(payload, dict) and isinstance(payload.get("pages"), int):
                return max(0, payload["pages"])
        except Exception as exc:
            ctx.log.debug("commoncrawl: pagination probe failed for %s: %s", api, exc)
        return 0

    def _consume(
        self,
        ctx: SourceContext,
        api: str,
        params: dict,
    ) -> Iterator[UrlHit]:
        try:
            response = ctx.http.get(
                api,
                params=params,
                timeout=max(ctx.settings.timeout, 90),
                stream=True,
            )
        except Exception as exc:
            raise SourceUnavailable(f"Common Crawl index request failed: {exc}")
        if response.status_code >= 400:
            snippet = response.text[:200].replace("\n", " ")
            response.close()
            raise SourceUnavailable(
                f"Common Crawl index HTTP {response.status_code}: {snippet}"
            )
        with response:
            for raw in response.iter_lines(decode_unicode=True):
                if not raw:
                    continue
                if raw.lstrip().startswith("<"):
                    raise SourceUnavailable(
                        "Common Crawl returned HTML instead of JSON"
                    )
                try:
                    item = json.loads(raw)
                except ValueError:
                    continue
                if not isinstance(item, dict) or item.get("error"):
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
                    offset = int(item.get("offset") or 0)
                except (TypeError, ValueError):
                    length = 0
                    offset = 0
                filename = str(item.get("filename") or "")
                snapshot = Snapshot(
                    source="commoncrawl",
                    timestamp=timestamp,
                    status=status,
                    mime=mime,
                    digest=digest,
                    length=length,
                    warc_filename=filename,
                    warc_offset=offset,
                    warc_length=length,
                )
                yield UrlHit(
                    url=url,
                    source="commoncrawl",
                    timestamp=timestamp,
                    status=status,
                    mime=mime,
                    digest=digest,
                    length=length,
                    snapshot=snapshot,
                )
