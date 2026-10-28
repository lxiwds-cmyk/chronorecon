"""Runs passive and URL sources, normalizes results, and stores them."""

from __future__ import annotations

import re
import sys
import time
import traceback
from pathlib import Path
from typing import TextIO

from .config import Settings
from .db import Store
from .http import HttpClient, RateLimiter
from .models import UrlHit
from .sources import SourceContext, SourceError, SourceUnavailable, build_source
from .utils import host_from_url, is_in_scope, normalize_url, timestamp_in_range

BATCH_COMMIT = 500


class Collector:
    def __init__(self, settings: Settings, store: Store, logger):
        self.settings = settings
        self.store = store
        self.log = logger
        self.http = HttpClient(
            timeout=settings.timeout,
            retries=settings.retries,
            user_agent=settings.user_agent,
            insecure=settings.insecure,
        )
        self.rate = RateLimiter()
        self.include_re = (
            re.compile(settings.include_regex, re.IGNORECASE)
            if settings.include_regex
            else None
        )
        self.exclude_re = (
            re.compile(settings.exclude_regex, re.IGNORECASE)
            if settings.exclude_regex
            else None
        )
        self.import_files = getattr(settings, "import_files", []) or []

    def run(self, domain: str) -> dict:
        ctx = SourceContext(
            settings=self.settings,
            domain=domain,
            store=self.store,
            http=self.http,
            rate=self.rate,
            log=self.log,
        )
        ctx.subdomains.add(domain)
        started = time.time()
        try:
            for name in self.settings.passive_sources:
                self._run_passive(name, ctx)
            for name in self.settings.url_sources:
                self._run_url(name, ctx)
            if self.import_files:
                self._run_imports(ctx)
        finally:
            self.store.commit()
            self.http.close()
        counts = self.store.counts()
        counts["seconds"] = round(time.time() - started, 2)
        return counts

    # ------------------------------------------------------------- run modes

    def _run_passive(self, name: str, ctx: SourceContext) -> None:
        source = build_source(name)
        if not source.is_available(self.settings):
            reason = source.unavailable_reason(self.settings)
            self.log.warning("%s: skipped (%s)", name, reason)
            self.store.record_source_run(name, 0, 0, 0, "skipped", reason)
            return
        started = time.time()
        errors = 0
        status = "ok"
        message = ""
        self.log.info("[passive] %s: %s", name, source.description)
        try:
            for _ in source.collect(ctx):
                # Passive sources only contribute hosts; if one yields a URL,
                # store it so custom sources remain useful.
                pass
        except SourceUnavailable as exc:
            status, message = "error", str(exc)
            errors += 1
            self.log.warning("%s: %s", name, exc)
        except SourceError as exc:
            status, message = "error", str(exc)
            errors += 1
            self.log.warning("%s: %s", name, exc)
        except Exception as exc:  # noqa: BLE001
            status, message = "error", f"{type(exc).__name__}: {exc}"
            errors += 1
            self.log.warning("%s failed: %s", name, exc)
            if self.settings.verbose:
                self.log.debug(traceback.format_exc())
        seconds = round(time.time() - started, 2)
        hosts = ctx.stats.get(name, {}).get("hosts", 0)
        message = message or f"{hosts} new host(s)"
        self.store.record_source_run(name, 0, errors, seconds, status, message)
        self.store.commit()
        self.log.info("%s: %s host(s), %.1fs", name, hosts, seconds)

    def _run_url(self, name: str, ctx: SourceContext) -> None:
        source = build_source(name)
        if not source.is_available(self.settings):
            reason = source.unavailable_reason(self.settings)
            self.log.warning("%s: skipped (%s)", name, reason)
            self.store.record_source_run(name, 0, 0, 0, "skipped", reason)
            return
        started = time.time()
        hits = 0
        added = 0
        errors = 0
        status = "ok"
        message = ""
        self.log.info("[url] %s: %s", name, source.description)
        try:
            for hit in source.collect(ctx):
                if not self._accept_hit(hit, ctx.domain):
                    continue
                host = host_from_url(hit.url)
                if host:
                    ctx.add_subdomain(host, name)
                new_url, _ = self.store.add_hit(hit)
                hits += 1
                added += int(bool(new_url))
                if hits % BATCH_COMMIT == 0:
                    self.store.commit()
                    self.log.debug("%s: %s hits (%s new)", name, hits, added)
        except SourceUnavailable as exc:
            status, message = "error", str(exc)
            errors += 1
            self.log.warning("%s: %s", name, exc)
        except SourceError as exc:
            status, message = "error", str(exc)
            errors += 1
            self.log.warning("%s: %s", name, exc)
        except Exception as exc:  # noqa: BLE001
            status, message = "error", f"{type(exc).__name__}: {exc}"
            errors += 1
            self.log.warning("%s failed: %s", name, exc)
            if self.settings.verbose:
                self.log.debug(traceback.format_exc())
        finally:
            self.store.commit()
        seconds = round(time.time() - started, 2)
        if errors and hits:
            status = "partial"
        self.store.record_source_run(name, hits, errors, seconds, status, message)
        self.store.commit()
        self.log.info(
            "%s: %s scoped hit(s), %s new URL(s), %.1fs",
            name,
            hits,
            added,
            seconds,
        )

    # ------------------------------------------------------------- filtering

    def _accept_hit(self, hit: UrlHit, domain: str) -> bool:
        if not hit or not hit.url:
            return False
        normalized = normalize_url(hit.url)
        if not normalized:
            return False
        if not is_in_scope(
            normalized, domain, self.settings.include_subdomains
        ):
            return False
        if self.include_re and not self.include_re.search(normalized):
            return False
        if self.exclude_re and self.exclude_re.search(normalized):
            return False
        if not timestamp_in_range(
            hit.timestamp,
            self.settings.from_date,
            self.settings.to_date,
        ):
            return False
        hit.url = normalized
        return True

    # --------------------------------------------------------------- imports

    def _run_imports(self, ctx: SourceContext) -> None:
        started = time.time()
        hits = 0
        added = 0
        errors = 0
        for path in self.import_files:
            self.log.info("[import] reading %s", path)
            try:
                if str(path) == "-":
                    stream: TextIO = sys.stdin
                    close = False
                else:
                    stream = open(Path(path), "r", encoding="utf-8", errors="replace")
                    close = True
                try:
                    for line in stream:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "://" not in line:
                            lower = line.lower()
                            if re.match(
                                r"^(?:mailto|tel|data|javascript|ftp|ftps|ws|wss|"
                                r"file|blob|about):",
                                lower,
                            ):
                                continue
                            line = "https://" + line
                        hit = UrlHit(url=line, source="import")
                        if not self._accept_hit(hit, ctx.domain):
                            continue
                        host = host_from_url(hit.url)
                        if host:
                            ctx.add_subdomain(host, "import")
                        new_url, _ = self.store.add_hit(hit)
                        hits += 1
                        added += int(bool(new_url))
                        if hits % BATCH_COMMIT == 0:
                            self.store.commit()
                finally:
                    if close:
                        stream.close()
            except OSError as exc:
                errors += 1
                self.log.warning("import %s failed: %s", path, exc)
        self.store.commit()
        seconds = round(time.time() - started, 2)
        self.store.record_source_run(
            "import",
            hits,
            errors,
            seconds,
            "ok" if not errors else "partial",
            f"{added} new URL(s)",
        )
        self.log.info("import: %s scoped URL(s), %s new", hits, added)
