"""urlscan.io search and scan-detail source."""

from __future__ import annotations

import time
from typing import List, Optional

from ..models import Snapshot, UrlHit
from ..utils import compact_timestamp
from .base import BaseSource, SourceContext, SourceUnavailable

SEARCH_ENDPOINT = "https://urlscan.io/api/v1/search/"
RESULT_ENDPOINT = "https://urlscan.io/api/v1/result/{scan_id}/"
RESPONSE_ENDPOINT = "https://urlscan.io/responses/{hash}/"


class URLScanSource(BaseSource):
    name = "urlscan"
    kind = "url"
    description = "urlscan.io historical scans"

    def collect(self, ctx: SourceContext):
        headers = self._headers(ctx)
        scan_ids: List[str] = []
        seen_urls = set()
        seen_scans = set()
        search_after: Optional[str] = None
        total = 0
        pages = max(1, ctx.settings.urlscan_pages)
        for page in range(pages):
            params = {"q": f"domain:{ctx.domain}", "size": 1000}
            if search_after:
                params["search_after"] = search_after
            try:
                response = ctx.http.get(
                    SEARCH_ENDPOINT,
                    params=params,
                    headers=headers,
                    timeout=max(ctx.settings.timeout, 60),
                )
            except Exception as exc:
                if page == 0:
                    raise SourceUnavailable(f"urlscan search unavailable: {exc}")
                ctx.log.warning("urlscan: search page %s failed: %s", page + 1, exc)
                break
            if response.status_code == 429:
                raise SourceUnavailable("urlscan rate limit reached (add an API key)")
            if response.status_code >= 400:
                raise SourceUnavailable(
                    f"urlscan search HTTP {response.status_code}: "
                    f"{response.text[:200]}"
                )
            try:
                payload = response.json()
            except ValueError as exc:
                raise SourceUnavailable("urlscan returned invalid JSON") from exc

            limit_days = payload.get("search_date_limit_days")
            if page == 0 and limit_days:
                ctx.log.warning(
                    "urlscan: anonymous/free search is limited to the last %s days",
                    limit_days,
                )
            results = payload.get("results") or []
            if not results:
                break
            for result in results:
                page_info = result.get("page") or {}
                task_info = result.get("task") or {}
                for field in (page_info, task_info):
                    host = field.get("domain") or ""
                    if host:
                        ctx.add_subdomain(host, "urlscan")
                scan_id = result.get("_id")
                if scan_id and str(scan_id) not in seen_scans:
                    seen_scans.add(str(scan_id))
                    scan_ids.append(str(scan_id))

                timestamp = compact_timestamp(task_info.get("time"))
                status = str(page_info.get("status") or "")
                mime = str(page_info.get("mimeType") or "")
                for candidate in (page_info.get("url"), task_info.get("url")):
                    if not candidate:
                        continue
                    candidate = str(candidate).strip()
                    if not candidate or candidate in seen_urls:
                        continue
                    seen_urls.add(candidate)
                    snapshot = Snapshot(
                        source="urlscan",
                        timestamp=timestamp,
                        status=status,
                        mime=mime,
                    )
                    yield UrlHit(
                        url=candidate,
                        source="urlscan",
                        timestamp=timestamp,
                        status=status,
                        mime=mime,
                        snapshot=snapshot,
                    )
                    total += 1
                    if (
                        ctx.settings.max_urls_per_source
                        and total >= ctx.settings.max_urls_per_source
                    ):
                        ctx.log.warning(
                            "urlscan: stopped at max-urls-per-source=%s",
                            ctx.settings.max_urls_per_source,
                        )
                        return

            ctx.log.info(
                "urlscan: search page %s -> %s scan results", page + 1, len(results)
            )
            if not payload.get("has_more"):
                break
            last_sort = results[-1].get("sort")
            if not last_sort:
                break
            if isinstance(last_sort, (list, tuple)):
                next_after = ",".join(str(part) for part in last_sort)
            else:
                next_after = str(last_sort)
            if next_after == search_after:
                break
            search_after = next_after
            time.sleep(1.5)

        details = max(0, ctx.settings.urlscan_details)
        if ctx.settings.urlscan_key and details and scan_ids:
            ctx.log.info(
                "urlscan: fetching resource details for %s scan(s)",
                min(details, len(scan_ids)),
            )
            yielded = self._collect_details(ctx, headers, scan_ids[:details])
            for hit in yielded:
                yield hit
                total += 1
                if (
                    ctx.settings.max_urls_per_source
                    and total >= ctx.settings.max_urls_per_source
                ):
                    ctx.log.warning(
                        "urlscan: stopped at max-urls-per-source=%s",
                        ctx.settings.max_urls_per_source,
                    )
                    return

    def _headers(self, ctx: SourceContext) -> dict:
        headers = {}
        if ctx.settings.urlscan_key:
            headers["api-key"] = ctx.settings.urlscan_key
        return headers

    def _collect_details(self, ctx: SourceContext, headers: dict, scan_ids: List[str]):
        seen = set()
        for scan_id in scan_ids:
            time.sleep(1.0)
            try:
                response = ctx.http.get(
                    RESULT_ENDPOINT.format(scan_id=scan_id),
                    headers=headers,
                    timeout=max(ctx.settings.timeout, 60),
                )
            except Exception as exc:
                ctx.log.debug("urlscan: result %s failed: %s", scan_id, exc)
                continue
            if response.status_code in (401, 403):
                ctx.log.warning(
                    "urlscan: result API rejected the request; add URLSCAN_API_KEY"
                )
                return
            if response.status_code == 429:
                ctx.log.warning("urlscan: result API rate limited; stopping details")
                return
            if response.status_code >= 400:
                continue
            try:
                payload = response.json()
            except ValueError:
                continue
            data = payload.get("data") or {}
            if not data:
                continue

            requests = data.get("requests") or []
            for transaction in requests:
                if not isinstance(transaction, dict):
                    continue
                request = transaction.get("request") or {}
                request_inner = request.get("request") or request
                url = request_inner.get("url") or request.get("url") or ""
                if not url:
                    continue
                response_info = transaction.get("response") or {}
                response_inner = response_info.get("response") or response_info
                status = str(
                    response_inner.get("status")
                    or response_info.get("status")
                    or ""
                )
                mime = str(
                    response_inner.get("mimeType")
                    or response_info.get("mimeType")
                    or ""
                )
                resp_hash = (
                    response_inner.get("hash")
                    or response_info.get("hash")
                    or ""
                )
                if not resp_hash:
                    # Older exports nested it one level deeper.
                    nested = response_info.get("response") or {}
                    resp_hash = nested.get("hash") or ""
                key = (url, resp_hash)
                if key in seen:
                    continue
                seen.add(key)
                snapshot = None
                if resp_hash:
                    snapshot = Snapshot(
                        source="urlscan",
                        status=status,
                        mime=mime,
                        response_hash=str(resp_hash),
                        download_url=RESPONSE_ENDPOINT.format(hash=resp_hash),
                    )
                yield UrlHit(
                    url=url,
                    source="urlscan",
                    status=status,
                    mime=mime,
                    snapshot=snapshot,
                )

            for url in data.get("lists", {}).get("urls", []) or []:
                if isinstance(url, str) and url and (url, "") not in seen:
                    seen.add((url, ""))
                    yield UrlHit(url=url, source="urlscan")

            for link in data.get("links", []) or []:
                if isinstance(link, str):
                    url = link
                elif isinstance(link, dict):
                    url = link.get("href") or link.get("url") or ""
                else:
                    continue
                if url and (url, "") not in seen:
                    seen.add((url, ""))
                    yield UrlHit(url=url, source="urlscan")

            for host in data.get("lists", {}).get("domains", []) or []:
                if isinstance(host, str):
                    ctx.add_subdomain(host, "urlscan")

        ctx.log.info("urlscan: detail extraction complete")
