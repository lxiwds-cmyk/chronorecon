"""Passive subdomain sources that feed the historical URL search."""

from __future__ import annotations

import html as html_lib
import re
import time
from typing import Iterator

from ..utils import host_in_scope
from .base import BaseSource, SourceContext, SourceUnavailable

CRTSH = "https://crt.sh/"
CERTSPOTTER = "https://api.certspotter.com/v1/issuances"
HACKERTARGET = "https://api.hackertarget.com/hostsearch/"
RAPIDDNS = "https://rapiddns.io/subdomain/{domain}"

HOST_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")
TD_RE = re.compile(r"<td[^>]*>\s*([^<]+?)\s*</td>", re.IGNORECASE)


class CrtShSource(BaseSource):
    name = "crtsh"
    kind = "passive"
    description = "crt.sh certificate transparency logs"

    def collect(self, ctx: SourceContext) -> Iterator:
        try:
            response = ctx.http.get(
                CRTSH,
                params={"q": f"%.{ctx.domain}", "output": "json"},
                timeout=max(ctx.settings.timeout, 90),
            )
        except Exception as exc:
            raise SourceUnavailable(f"crt.sh unavailable: {exc}")
        if response.status_code >= 400:
            raise SourceUnavailable(f"crt.sh HTTP {response.status_code}")
        try:
            entries = response.json()
        except ValueError as exc:
            raise SourceUnavailable("crt.sh returned invalid JSON") from exc
        count = 0
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict):
                continue
            names = []
            names.extend(str(entry.get("name_value") or "").splitlines())
            names.append(str(entry.get("common_name") or ""))
            for name in names:
                name = name.strip().lower().lstrip("*.")
                if not name or not HOST_RE.match(name):
                    continue
                if ctx.add_subdomain(name, "crtsh"):
                    count += 1
        ctx.log.info("crtsh: %s new host(s)", count)
        yield from ()


class CertSpotterSource(BaseSource):
    name = "certspotter"
    kind = "passive"
    description = "Cert Spotter certificate transparency API"

    def collect(self, ctx: SourceContext) -> Iterator:
        try:
            response = ctx.http.get(
                CERTSPOTTER,
                params={
                    "domain": ctx.domain,
                    "include_subdomains": "true",
                    "expand": "dns_names",
                },
                timeout=max(ctx.settings.timeout, 90),
            )
        except Exception as exc:
            raise SourceUnavailable(f"Cert Spotter unavailable: {exc}")
        if response.status_code == 429:
            raise SourceUnavailable("Cert Spotter rate limited the request")
        if response.status_code >= 400:
            raise SourceUnavailable(f"Cert Spotter HTTP {response.status_code}")
        try:
            entries = response.json()
        except ValueError as exc:
            raise SourceUnavailable("Cert Spotter returned invalid JSON") from exc
        count = 0
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict):
                continue
            for name in entry.get("dns_names") or []:
                name = str(name).strip().lower().lstrip("*.")
                if name and HOST_RE.match(name):
                    if ctx.add_subdomain(name, "certspotter"):
                        count += 1
        ctx.log.info("certspotter: %s new host(s)", count)
        yield from ()


class HackerTargetSource(BaseSource):
    name = "hackertarget"
    kind = "passive"
    description = "HackerTarget host search"

    def collect(self, ctx: SourceContext) -> Iterator:
        try:
            response = ctx.http.get(
                HACKERTARGET,
                params={"q": ctx.domain},
                timeout=max(ctx.settings.timeout, 60),
            )
        except Exception as exc:
            raise SourceUnavailable(f"HackerTarget unavailable: {exc}")
        if response.status_code >= 400:
            raise SourceUnavailable(f"HackerTarget HTTP {response.status_code}")
        text = (response.text or "").strip()
        lower = text.lower()
        if "no records" in lower or not text:
            ctx.log.info("hackertarget: no host records")
            yield from ()
            return
        if "error" in lower or "api count exceeded" in lower:
            raise SourceUnavailable(f"HackerTarget: {text[:200]}")
        count = 0
        for line in text.splitlines():
            host = line.split(",", 1)[0].strip().lower()
            if host and HOST_RE.match(host):
                if ctx.add_subdomain(host, "hackertarget"):
                    count += 1
        ctx.log.info("hackertarget: %s new host(s)", count)
        yield from ()


class RapidDnsSource(BaseSource):
    name = "rapiddns"
    kind = "passive"
    description = "RapidDNS subdomain index"

    def collect(self, ctx: SourceContext) -> Iterator:
        count = 0
        pages = max(1, ctx.settings.rapiddns_pages)
        for page in range(1, pages + 1):
            params = {"full": "1"}
            if page > 1:
                params["page"] = str(page)
            try:
                response = ctx.http.get(
                    RAPIDDNS.format(domain=ctx.domain),
                    params=params,
                    timeout=max(ctx.settings.timeout, 60),
                )
            except Exception as exc:
                if page == 1:
                    raise SourceUnavailable(f"RapidDNS unavailable: {exc}")
                break
            if response.status_code >= 400:
                if page == 1:
                    raise SourceUnavailable(f"RapidDNS HTTP {response.status_code}")
                break
            body = response.text or ""
            if "just a moment" in body[:4000].lower():
                raise SourceUnavailable("RapidDNS returned a Cloudflare challenge")
            found = 0
            for raw in TD_RE.findall(body):
                value = html_lib.unescape(raw).strip().lower()
                if not value or not HOST_RE.match(value):
                    continue
                if not host_in_scope(value, ctx.domain, True):
                    continue
                if ctx.add_subdomain(value, "rapiddns"):
                    count += 1
                    found += 1
            if not found:
                break
            time.sleep(1.0)
        ctx.log.info("rapiddns: %s new host(s)", count)
        yield from ()
