"""Command-line interface for ChronoRecon."""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
import tempfile
import time
import traceback
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .collector import Collector
from .config import (
    ALL_SOURCES,
    DEFAULT_PASSIVE_SOURCES,
    DEFAULT_URL_SOURCES,
    KEYED_SOURCES,
    PASSIVE_SOURCES,
    SOURCE_DESCRIPTIONS,
    URL_SOURCES,
    VERSION,
)
from .db import Store
from .downloader import Downloader
from .report import generate_reports
from .utils import (
    human_bytes,
    normalize_cdx_date,
    normalize_domain,
    parse_ext_set,
    parse_size,
)

LOGGER_NAME = "chronorecon"


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not an integer: {value!r}") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return number


def _non_negative_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not an integer: {value!r}") from exc
    if number < 0:
        raise argparse.ArgumentTypeError("value cannot be negative")
    return number


def _size_value(value: str) -> int:
    try:
        return parse_size(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _split_names(value: str) -> List[str]:
    return [part.strip().lower() for part in value.split(",") if part.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chronorecon",
        description=(
            "Collect historical URLs from multiple independent archives, save "
            "them to urls.txt, and recover the archived response bodies."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  chronorecon example.com\n"
            "  chronorecon example.com -o /tmp/recon --threads 12 --all-versions\n"
            "  chronorecon example.com --sources wayback,commoncrawl,arquivo "
            "--no-passive\n"
            "  chronorecon example.com --from-file gau.txt --from-file waymore.txt\n"
            "  chronorecon example.com --no-download --max-urls-per-source 5000\n"
            "\n"
            "sources:\n"
            "  URL sources     : wayback, commoncrawl, otx, urlscan, arquivo,\n"
            "                    ghostarchive, virustotal (key required)\n"
            "  Passive sources : crtsh, certspotter, hackertarget, rapiddns,\n"
            "                    otx_passive (key required)\n"
            "\n"
            "API keys are read from URLSCAN_API_KEY, VT_API_KEY and OTX_API_KEY.\n"
            "Only test systems you are authorized to assess.\n"
        ),
    )
    parser.add_argument("targets", nargs="*", help="target domain(s), e.g. example.com")
    parser.add_argument(
        "-o",
        "--output",
        default=".",
        help="parent directory for target folders (default: current directory)",
    )
    parser.add_argument(
        "--version", action="version", version=f"ChronoRecon {VERSION}"
    )

    source_group = parser.add_argument_group("source selection")
    source_group.add_argument(
        "--sources",
        metavar="LIST",
        help=(
            "comma-separated URL sources, 'all', or 'none' "
            f"(default: {','.join(DEFAULT_URL_SOURCES)})"
        ),
    )
    source_group.add_argument(
        "--passive-sources",
        metavar="LIST",
        help=(
            "comma-separated passive sources, 'all', or 'none' "
            f"(default: {','.join(DEFAULT_PASSIVE_SOURCES)})"
        ),
    )
    source_group.add_argument(
        "--all-sources",
        action="store_true",
        help="enable every URL and passive source (keyed sources still need keys)",
    )
    source_group.add_argument(
        "--no-passive",
        action="store_true",
        help="disable passive subdomain discovery",
    )
    source_group.add_argument(
        "--skip",
        action="append",
        default=[],
        metavar="LIST",
        help="comma-separated source names to disable (repeatable)",
    )
    source_group.add_argument(
        "--list-sources", action="store_true", help="list sources and exit"
    )
    source_group.add_argument(
        "--from-file",
        action="append",
        default=[],
        metavar="PATH",
        help="import URLs from a file, one per line ('-' reads stdin; repeatable)",
    )

    limit_group = parser.add_argument_group("limits and filtering")
    limit_group.add_argument(
        "--max-urls-per-source",
        type=_non_negative_int,
        default=0,
        metavar="N",
        help="stop each URL source after N rows (0 = unlimited)",
    )
    limit_group.add_argument(
        "--max-captures",
        type=_non_negative_int,
        default=0,
        metavar="N",
        help="stop Wayback after N capture rows when --all-versions is used",
    )
    limit_group.add_argument(
        "--max-files",
        type=_non_negative_int,
        default=0,
        metavar="N",
        help="stop after submitting N URLs to the downloader (0 = unlimited)",
    )
    limit_group.add_argument(
        "--max-file-size",
        type=_size_value,
        default=50 * 1024 * 1024,
        metavar="SIZE",
        help="maximum size of one downloaded file (default: 50M, 0 = unlimited)",
    )
    limit_group.add_argument(
        "--max-total-size",
        type=_size_value,
        default=0,
        metavar="SIZE",
        help="stop downloading after this many bytes (default: unlimited)",
    )
    limit_group.add_argument(
        "--max-versions-per-url",
        type=_positive_int,
        default=10,
        metavar="N",
        help="captures per URL with --all-versions (default: 10)",
    )
    limit_group.add_argument(
        "--only-ext",
        action="append",
        default=[],
        metavar="EXT",
        help="download only these extensions, e.g. js,html,css (repeatable)",
    )
    limit_group.add_argument(
        "--exclude-ext",
        action="append",
        default=[],
        metavar="EXT",
        help="never download these extensions (repeatable)",
    )
    limit_group.add_argument(
        "--include-regex", metavar="REGEX", help="only keep matching URLs"
    )
    limit_group.add_argument(
        "--exclude-regex", metavar="REGEX", help="drop matching URLs"
    )
    limit_group.add_argument("--from-date", metavar="DATE", default="", help="earliest capture date")
    limit_group.add_argument("--to-date", metavar="DATE", default="", help="latest capture date")

    source_opts = parser.add_argument_group("source options")
    source_opts.add_argument(
        "--cc-indexes",
        type=_positive_int,
        default=3,
        metavar="N",
        help="number of recent Common Crawl indexes (default: 3)",
    )
    source_opts.add_argument(
        "--cc-all", action="store_true", help="query every Common Crawl index"
    )
    source_opts.add_argument(
        "--otx-pages",
        type=_positive_int,
        default=10,
        metavar="N",
        help="maximum OTX URL pages of 500 (default: 10)",
    )
    source_opts.add_argument(
        "--urlscan-pages",
        type=_positive_int,
        default=3,
        metavar="N",
        help="maximum urlscan search pages (default: 3)",
    )
    source_opts.add_argument(
        "--urlscan-details",
        type=_non_negative_int,
        default=50,
        metavar="N",
        help="urlscan result pages to expand when a key is present (default: 50)",
    )
    source_opts.add_argument(
        "--ghost-pages",
        type=_positive_int,
        default=3,
        metavar="N",
        help="GhostArchive search pages (default: 3)",
    )
    source_opts.add_argument(
        "--rapiddns-pages",
        type=_positive_int,
        default=1,
        metavar="N",
        help="RapidDNS pages (default: 1)",
    )
    source_opts.add_argument(
        "--vt-limit",
        type=_positive_int,
        default=80,
        metavar="N",
        help="maximum VirusTotal URL results (default: 80)",
    )
    source_opts.add_argument(
        "--urlscan-key", default=os.environ.get("URLSCAN_API_KEY", ""), help=argparse.SUPPRESS
    )
    source_opts.add_argument(
        "--vt-key", default=os.environ.get("VT_API_KEY", ""), help=argparse.SUPPRESS
    )
    source_opts.add_argument(
        "--otx-key", default=os.environ.get("OTX_API_KEY", ""), help=argparse.SUPPRESS
    )

    download_group = parser.add_argument_group("download behaviour")
    download_group.add_argument(
        "--no-download",
        action="store_true",
        help="enumerate URLs only; do not recover response bodies",
    )
    download_group.add_argument(
        "--all-versions",
        action="store_true",
        help="keep distinct captures of each URL, not just the newest usable one",
    )
    download_group.add_argument(
        "--no-live",
        action="store_true",
        help="never fetch the current live URL as a fallback",
    )
    download_group.add_argument(
        "--no-resume",
        action="store_true",
        help="do not skip URLs already saved in the database",
    )
    download_group.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing files and re-download completed URLs",
    )
    download_group.add_argument(
        "--threads",
        type=_positive_int,
        default=6,
        metavar="N",
        help="download worker threads (default: 6)",
    )
    download_group.add_argument(
        "--timeout",
        type=_positive_int,
        default=45,
        metavar="SECONDS",
        help="HTTP timeout (default: 45)",
    )
    download_group.add_argument(
        "--retries",
        type=_non_negative_int,
        default=4,
        metavar="N",
        help="HTTP retries for transient failures (default: 4)",
    )

    misc = parser.add_argument_group("other")
    misc.add_argument(
        "--no-subdomains",
        action="store_true",
        help="keep only the exact target host, excluding subdomains",
    )
    misc.add_argument(
        "--insecure", action="store_true", help="disable TLS certificate verification"
    )
    verbosity = misc.add_mutually_exclusive_group()
    verbosity.add_argument("-q", "--quiet", action="store_true", help="errors only")
    verbosity.add_argument(
        "-v", "--verbose", action="store_true", help="debug logging"
    )
    return parser


def _configure_logging(quiet: bool, verbose: bool) -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    console = logging.StreamHandler()
    console.setLevel(
        logging.WARNING if quiet else (logging.DEBUG if verbose else logging.INFO)
    )
    console.setFormatter(logging.Formatter("%(levelname)-7s %(message)s"))
    logger.addHandler(console)
    return logger


def _add_file_handler(logger: logging.Logger, path: Path) -> logging.Handler:
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(path, mode="a", encoding="utf-8")
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-7s %(message)s")
    )
    logger.addHandler(handler)
    return handler


def _resolve_sources(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> Tuple[List[str], List[str]]:
    skip = set()
    for value in args.skip:
        skip.update(_split_names(value))

    if args.all_sources:
        url_sources = sorted(URL_SOURCES)
        passive_sources = sorted(PASSIVE_SOURCES)
    else:
        if args.sources is None:
            url_sources = list(DEFAULT_URL_SOURCES)
            if args.vt_key and "virustotal" not in url_sources:
                url_sources.append("virustotal")
        else:
            requested = _split_names(args.sources)
            if requested == ["all"]:
                url_sources = sorted(URL_SOURCES)
            elif requested == ["none"]:
                url_sources = []
            else:
                url_sources = requested
        if args.no_passive:
            passive_sources = []
        elif args.passive_sources is None:
            passive_sources = list(DEFAULT_PASSIVE_SOURCES)
            if args.otx_key and "otx_passive" not in passive_sources:
                passive_sources.append("otx_passive")
        else:
            requested = _split_names(args.passive_sources)
            if requested == ["all"]:
                passive_sources = sorted(PASSIVE_SOURCES)
            elif requested == ["none"]:
                passive_sources = []
            else:
                passive_sources = requested

    for name in url_sources:
        if name not in ALL_SOURCES:
            parser.error(f"unknown URL source: {name!r} (try --list-sources)")
        if name not in URL_SOURCES:
            parser.error(
                f"{name!r} is a passive source; use --passive-sources instead"
            )
    for name in passive_sources:
        if name not in ALL_SOURCES:
            parser.error(f"unknown passive source: {name!r} (try --list-sources)")
        if name not in PASSIVE_SOURCES:
            parser.error(
                f"{name!r} is a URL source; use --sources instead"
            )

    if args.no_passive:
        passive_sources = []
    url_sources = [name for name in url_sources if name not in skip]
    passive_sources = [name for name in passive_sources if name not in skip]
    unknown_skips = skip - ALL_SOURCES
    if unknown_skips:
        parser.error(
            "unknown source(s) in --skip: " + ", ".join(sorted(unknown_skips))
        )
    return list(dict.fromkeys(url_sources)), list(dict.fromkeys(passive_sources))


def _list_sources() -> None:
    print("ChronoRecon sources\n")
    print("URL sources (historical endpoints and captures):")
    for name in sorted(URL_SOURCES):
        marker = " *key" if name in KEYED_SOURCES else ""
        print(f"  {name:<14} {SOURCE_DESCRIPTIONS.get(name, '')}{marker}")
    print("\nPassive sources (subdomain discovery):")
    for name in sorted(PASSIVE_SOURCES):
        marker = " *key" if name == "otx_passive" else ""
        print(f"  {name:<14} {SOURCE_DESCRIPTIONS.get(name, '')}{marker}")
    print(
        "\nThe tool never queries the same database through two names; gau/"
        "waymore output can be added with --from-file.\n"
        "Keys: URLSCAN_API_KEY, VT_API_KEY, OTX_API_KEY"
    )


def _normalize_targets(
    values: List[str], parser: argparse.ArgumentParser
) -> List[str]:
    targets: List[str] = []
    for value in values:
        text = value.strip()
        if text.startswith("*."):
            text = text[2:]
        try:
            host = normalize_domain(text)
        except ValueError as exc:
            parser.error(str(exc))
        if not host:
            parser.error(f"could not parse target: {value!r}")
        if host not in targets:
            targets.append(host)
    return targets


def _materialize_stdin(paths: List[str]) -> Tuple[List[str], Optional[Path]]:
    if "-" not in paths:
        return paths, None
    data = sys.stdin.read()
    descriptor, name = tempfile.mkstemp(prefix="chronorecon-stdin-", suffix=".txt")
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(data)
        if data and not data.endswith("\n"):
            handle.write("\n")
    temporary = Path(name)
    return [str(temporary) if path == "-" else path for path in paths], temporary


def run_target(
    domain: str,
    settings,
    logger: logging.Logger,
) -> Dict:
    """Run collection, download and reporting for one target host."""
    started = time.time()
    target_dir = (Path(settings.output_root) / domain).resolve()
    meta_dir = target_dir / "metadata"
    meta_dir.mkdir(parents=True, exist_ok=True)
    log_path = meta_dir / "run.log"
    handler = _add_file_handler(logger, log_path)
    store: Optional[Store] = None
    summary: Dict = {}
    error: Optional[BaseException] = None
    download_stats: Dict = {}
    try:
        logger.info("=" * 68)
        logger.info("ChronoRecon %s - target %s", VERSION, domain)
        logger.info("Output folder: %s", target_dir)
        logger.info(
            "URL sources: %s",
            ", ".join(settings.url_sources) if settings.url_sources else "(none)",
        )
        logger.info(
            "Passive sources: %s",
            ", ".join(settings.passive_sources) if settings.passive_sources else "(none)",
        )
        store = Store(meta_dir / "chronorecon.db")
        collector = Collector(settings, store, logger)
        collector.run(domain)
        if settings.download:
            downloader = Downloader(settings, store, logger, target_dir)
            download_stats = downloader.run()
            logger.info(
                "download: %s saved, %s duplicate, %s failed, %s skipped (%s)",
                download_stats.get("saved", 0),
                download_stats.get("duplicates", 0),
                download_stats.get("failed", 0),
                download_stats.get("skipped", 0),
                human_bytes(int(download_stats.get("bytes", 0))),
            )
        summary = generate_reports(
            store,
            target_dir,
            domain,
            logger,
            download_stats=download_stats,
            elapsed_seconds=time.time() - started,
        )
    except KeyboardInterrupt:
        raise
    except BaseException as exc:  # noqa: BLE001
        error = exc
        logger.error("target %s failed: %s", domain, exc)
        if settings.verbose:
            logger.debug(traceback.format_exc())
    finally:
        if store is not None:
            try:
                store.close()
            except Exception:  # noqa: BLE001
                pass
        logger.removeHandler(handler)
        handler.close()
    return {
        "domain": domain,
        "target_dir": target_dir,
        "summary": summary,
        "error": error,
        "download_stats": download_stats,
    }


def _print_summary(result: Dict) -> None:
    domain = result["domain"]
    target_dir = result["target_dir"]
    summary = result.get("summary") or {}
    counts = summary.get("counts") or {}
    print()
    print(f"== {domain} ==")
    if result.get("error") is not None:
        print(f"  FAILED      : {result['error']}")
        print(f"  Partial data: {target_dir}")
        return
    print(f"  Folder      : {target_dir}")
    print(f"  URLs        : {counts.get('urls', 0)}")
    print(f"  Subdomains  : {counts.get('subdomains', 0)}")
    print(
        "  By type     : {} JS, {} HTML, {} CSS".format(
            counts.get("javascript_files", 0),
            counts.get("html_files", 0),
            counts.get("css_files", 0),
        )
    )
    print(
        "  Downloads   : {} saved, {} duplicate, {} failed ({})".format(
            counts.get("downloads_saved", 0),
            counts.get("downloads_duplicate", 0),
            counts.get("downloads_failed", 0),
            human_bytes(int(counts.get("download_bytes", 0))),
        )
    )
    print(f"  URLs file   : {target_dir / 'urls.txt'}")
    print(f"  Downloads   : {target_dir / 'downloads'}")
    print(f"  Summary     : {target_dir / 'metadata' / 'summary.json'}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_sources:
        _list_sources()
        return 0
    if not args.targets:
        parser.error("a target domain is required (or use --list-sources)")

    logger = _configure_logging(args.quiet, args.verbose)
    url_sources, passive_sources = _resolve_sources(args, parser)
    targets = _normalize_targets(args.targets, parser)

    try:
        from_date = normalize_cdx_date(args.from_date)
        to_date = normalize_cdx_date(args.to_date)
    except ValueError as exc:
        parser.error(str(exc))

    for pattern_name in ("include_regex", "exclude_regex"):
        value = getattr(args, pattern_name)
        if value:
            try:
                re.compile(value)
            except re.error as exc:
                parser.error(f"--{pattern_name.replace('_', '-')}: {exc}")

    import_files, temporary_import = _materialize_stdin(list(args.from_file))
    for path in import_files:
        if path and not Path(path).is_file():
            cleanup = [str(temporary_import)] if temporary_import else []
            for item in cleanup:
                try:
                    Path(item).unlink()
                except OSError:
                    pass
            parser.error(f"--from-file does not exist: {path}")

    output_root = Path(args.output).expanduser().resolve()
    try:
        output_root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        parser.error(f"cannot create output directory {output_root}: {exc}")

    only_ext = parse_ext_set(args.only_ext)
    exclude_ext = parse_ext_set(args.exclude_ext)
    for name in only_ext & exclude_ext:
        logger.warning("extension %s is both included and excluded; excluding it", name)
    exclude_ext |= only_ext & exclude_ext

    results: List[Dict] = []
    interrupted = False
    try:
        for domain in targets:
            settings = _base_settings(
                args,
                output_root=output_root,
                target=domain,
                url_sources=url_sources,
                passive_sources=passive_sources,
                import_files=import_files,
                only_ext=only_ext,
                exclude_ext=exclude_ext,
                from_date=from_date,
                to_date=to_date,
            )
            result = run_target(domain, settings, logger)
            results.append(result)
            if not args.quiet:
                _print_summary(result)
    except KeyboardInterrupt:
        interrupted = True
        logger.warning("interrupted - rerun the same command to resume")
    finally:
        if temporary_import is not None:
            try:
                temporary_import.unlink()
            except OSError:
                pass

    if interrupted:
        return 130
    failures = [item for item in results if item.get("error") is not None]
    total_urls = sum(
        ((item.get("summary") or {}).get("counts") or {}).get("urls", 0)
        for item in results
    )
    if len(results) > 1:
        print()
        print(
            "Total: {} target(s), {} unique URL(s), {} failure(s)".format(
                len(results), total_urls, len(failures)
            )
        )
    if failures:
        logger.error("%s target(s) failed", len(failures))
        return 1
    if not total_urls:
        logger.warning("no URLs were discovered for any target")
        return 2
    return 0


def _base_settings(
    args: argparse.Namespace,
    output_root: Path,
    target: str,
    url_sources: List[str],
    passive_sources: List[str],
    import_files: List[str],
    only_ext,
    exclude_ext,
    from_date: str,
    to_date: str,
):
    from .config import Settings

    return Settings(
        domains=[target],
        output_root=output_root,
        include_subdomains=not args.no_subdomains,
        download=not args.no_download,
        url_sources=list(url_sources),
        passive_sources=list(passive_sources),
        timeout=args.timeout,
        retries=args.retries,
        threads=args.threads,
        insecure=args.insecure,
        max_urls_per_source=args.max_urls_per_source,
        max_captures=args.max_captures,
        max_files=args.max_files,
        max_file_size=args.max_file_size,
        max_total_size=args.max_total_size,
        max_versions_per_url=args.max_versions_per_url,
        cc_indexes=args.cc_indexes,
        cc_all=args.cc_all,
        otx_pages=args.otx_pages,
        urlscan_pages=args.urlscan_pages,
        urlscan_details=args.urlscan_details,
        vt_limit=args.vt_limit,
        ghost_pages=args.ghost_pages,
        rapiddns_pages=args.rapiddns_pages,
        import_files=list(import_files),
        all_versions=args.all_versions,
        resume=not args.no_resume,
        force=args.force,
        allow_live=not args.no_live,
        only_ext=set(only_ext),
        exclude_ext=set(exclude_ext),
        include_regex=args.include_regex or None,
        exclude_regex=args.exclude_regex or None,
        from_date=from_date,
        to_date=to_date,
        urlscan_key=args.urlscan_key or None,
        vt_key=args.vt_key or None,
        otx_key=args.otx_key or None,
        quiet=args.quiet,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    raise SystemExit(main())
