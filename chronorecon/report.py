"""Generate the human- and machine-readable result files for one target."""

from __future__ import annotations

import json
import re
from collections import Counter
from contextlib import ExitStack
from pathlib import Path
from typing import Dict, List, Optional

from .config import VERSION
from .db import Store
from .utils import (
    content_type_to_ext,
    human_bytes,
    now_iso,
    url_extension,
)

HTML_EXTENSIONS = {
    ".html",
    ".htm",
    ".xhtml",
    ".shtml",
    ".php",
    ".asp",
    ".aspx",
    ".jsp",
    ".jspx",
    ".cfm",
    ".do",
    ".action",
}
JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx"}
CSS_EXTENSIONS = {".css"}

SOURCE_FILE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _mime_family(mime: str) -> str:
    mime = (mime or "").split(";", 1)[0].strip().lower()
    if mime in ("text/html", "application/xhtml+xml"):
        return "html"
    if "javascript" in mime or "ecmascript" in mime:
        return "js"
    if mime == "text/css":
        return "css"
    return ""


def _category(url: str, mime: str) -> str:
    extension = url_extension(url)
    family = _mime_family(mime)
    if extension in JS_EXTENSIONS or family == "js":
        return "js"
    if extension in CSS_EXTENSIONS or family == "css":
        return "css"
    if extension in HTML_EXTENSIONS or family == "html" or not extension:
        return "html"
    return "other"


def _format_sources(runs: List[Dict], url_counts: Dict[str, int]) -> List[str]:
    lines = []
    known = {run["source"] for run in runs}
    for run in runs:
        lines.append(
            "  {source:<14} {status:<8} {urls:>8} URL(s)  {seconds:>7.1f}s  {message}".format(
                source=run["source"],
                status=run.get("status") or "",
                urls=url_counts.get(run["source"], run.get("urls") or 0),
                seconds=float(run.get("seconds") or 0),
                message=(run.get("message") or "").strip(),
            ).rstrip()
        )
    for source in sorted(set(url_counts) - known):
        lines.append(
            "  {:<14} {:<8} {:>8} URL(s)".format(
                source, "ok", url_counts[source]
            )
        )
    return lines


def generate_reports(
    store: Store,
    output_dir: Path,
    domain: str,
    logger,
    download_stats: Optional[Dict] = None,
    elapsed_seconds: float = 0.0,
) -> Dict:
    """Write urls.txt, per-source lists, metadata and summary.json."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    meta_dir = output_dir / "metadata"
    meta_dir.mkdir(parents=True, exist_ok=True)
    by_source_dir = output_dir / "urls_by_source"
    by_source_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "downloads").mkdir(parents=True, exist_ok=True)

    urls_path = output_dir / "urls.txt"
    js_path = output_dir / "urls_js.txt"
    html_path = output_dir / "urls_html.txt"
    css_path = output_dir / "urls_css.txt"
    jsonl_path = meta_dir / "urls.jsonl"
    files_jsonl_path = meta_dir / "files.jsonl"

    source_handles: Dict[str, object] = {}
    source_counts: Counter = Counter()
    extension_counter: Counter = Counter()
    category_counter: Counter = Counter()
    url_hosts = set()
    total_urls = 0

    try:
        with ExitStack() as stack:
            urls_handle = stack.enter_context(open(urls_path, "w", encoding="utf-8"))
            js_handle = stack.enter_context(open(js_path, "w", encoding="utf-8"))
            html_handle = stack.enter_context(open(html_path, "w", encoding="utf-8"))
            css_handle = stack.enter_context(open(css_path, "w", encoding="utf-8"))
            jsonl_handle = stack.enter_context(open(jsonl_path, "w", encoding="utf-8"))
            for row in store.iter_report_rows():
                url = row["url"]
                total_urls += 1
                urls_handle.write(url + "\n")
                jsonl_handle.write(json.dumps(row, ensure_ascii=False) + "\n")

                host = row["host"]
                if host:
                    url_hosts.add(host)
                category = _category(url, row["mime"])
                category_counter[category] += 1
                if category == "js":
                    js_handle.write(url + "\n")
                elif category == "css":
                    css_handle.write(url + "\n")
                elif category == "html":
                    html_handle.write(url + "\n")

                extension = url_extension(url) or content_type_to_ext(row["mime"])
                extension_counter[extension or "(none)"] += 1

                for source in row["sources"]:
                    safe = SOURCE_FILE_RE.sub("_", source) or "unknown"
                    handle = source_handles.get(safe)
                    if handle is None:
                        handle = open(
                            by_source_dir / f"{safe}.txt", "w", encoding="utf-8"
                        )
                        source_handles[safe] = handle
                    handle.write(url + "\n")
                    source_counts[source] += 1
    finally:
        for handle in source_handles.values():
            try:
                handle.close()
            except OSError:
                pass

    # Make sure a file exists even for a source that produced zero URLs.
    for run in store.source_runs():
        safe = SOURCE_FILE_RE.sub("_", run["source"]) or "unknown"
        path = by_source_dir / f"{safe}.txt"
        if not path.exists():
            path.write_text("", encoding="utf-8")

    discovered = set(store.subdomains())
    discovered.update(url_hosts)
    discovered.add(domain)
    subdomains = sorted(host for host in discovered if host)
    (output_dir / "subdomains.txt").write_text(
        "\n".join(subdomains) + ("\n" if subdomains else ""), encoding="utf-8"
    )
    (output_dir / "hosts.txt").write_text(
        "\n".join(sorted(url_hosts)) + ("\n" if url_hosts else ""),
        encoding="utf-8",
    )

    successful = store.download_rows(successful_only=True)
    with open(files_jsonl_path, "w", encoding="utf-8") as handle:
        for row in successful:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    counts = store.counts()
    source_runs = store.source_runs()
    summary = {
        "tool": "ChronoRecon",
        "version": VERSION,
        "target": domain,
        "generated_at": now_iso(),
        "elapsed_seconds": round(float(elapsed_seconds), 2),
        "counts": {
            "urls": total_urls,
            "subdomains": len(subdomains),
            "url_hosts": len(url_hosts),
            "javascript_files": category_counter.get("js", 0),
            "html_files": category_counter.get("html", 0),
            "css_files": category_counter.get("css", 0),
            "other_files": category_counter.get("other", 0),
            "urls_by_category": dict(category_counter),
            "snapshots": counts["snapshots"],
            "downloads_saved": counts["saved"],
            "downloads_duplicate": counts["duplicates"],
            "downloads_failed": counts["failed"],
            "downloads_skipped": counts["skipped"],
            "download_bytes": counts["saved_bytes"],
        },
        "download_run": download_stats or {},
        "urls_by_source": dict(sorted(source_counts.items())),
        "top_extensions": dict(extension_counter.most_common(30)),
        "sources": source_runs,
        "outputs": {
            "urls": str(urls_path.relative_to(output_dir)),
            "javascript": str(js_path.relative_to(output_dir)),
            "html": str(html_path.relative_to(output_dir)),
            "css": str(css_path.relative_to(output_dir)),
            "subdomains": "subdomains.txt",
            "hosts": "hosts.txt",
            "downloads": "downloads/",
            "url_metadata": str(jsonl_path.relative_to(output_dir)),
            "files_metadata": str(files_jsonl_path.relative_to(output_dir)),
        },
    }
    (meta_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    readme_lines = [
        f"ChronoRecon v{VERSION} results for {domain}",
        "=" * (28 + len(domain)),
        f"Generated: {summary['generated_at']}",
        "",
        f"Unique historical URLs : {total_urls}",
        f"Hosts seen in URLs     : {len(url_hosts)}",
        f"Subdomains discovered  : {len(subdomains)}",
        f"JavaScript URLs        : {category_counter.get('js', 0)}",
        f"HTML URLs              : {category_counter.get('html', 0)}",
        f"CSS URLs               : {category_counter.get('css', 0)}",
        f"Files saved            : {counts['saved']} ({human_bytes(counts['saved_bytes'])})",
        f"Duplicate files        : {counts['duplicates']}",
        f"Download failures      : {counts['failed']}",
        "",
        "Output files",
        "------------",
        "  urls.txt                 All unique URLs (sorted).",
        "  urls_js.txt              JavaScript URLs.",
        "  urls_html.txt            HTML / server-page URLs.",
        "  urls_css.txt             CSS URLs.",
        "  subdomains.txt           Hosts found by passive and URL sources.",
        "  hosts.txt                Hosts taken from discovered URLs.",
        "  urls_by_source/          One URL list per source.",
        "  downloads/               Recovered archived/live response bodies.",
        "  metadata/urls.jsonl      Full per-URL metadata.",
        "  metadata/files.jsonl     Index of saved files.",
        "  metadata/downloads.jsonl Every download attempt.",
        "  metadata/failed.txt      Download failures as URL<TAB>error.",
        "  metadata/summary.json    Machine-readable run summary.",
        "  metadata/run.log         Full run log.",
        "",
        "Sources",
        "-------",
    ]
    readme_lines.extend(_format_sources(source_runs, dict(source_counts)))
    readme_lines.extend(
        [
            "",
            "Notes",
            "-----",
            "  * Files are content-deduplicated by SHA-256.  Metadata records when",
            "    two archived URLs returned identical bytes.",
            "  * The default download keeps the newest usable capture per URL.",
            "    Re-run with --all-versions to keep distinct captures of each URL.",
            "  * Re-running the same command resumes from metadata/chronorecon.db.",
            "  * Historical archives can be incomplete; use --from-file to add",
            "    URLs produced by gau, waymore, waybackurls or other tools.",
            "",
            "Only use ChronoRecon against systems you are authorized to test.",
            "",
        ]
    )
    (output_dir / "README.txt").write_text(
        "\n".join(readme_lines), encoding="utf-8"
    )

    logger.info(
        "report: %s URLs, %s JS, %s HTML, %s CSS -> %s",
        total_urls,
        category_counter.get("js", 0),
        category_counter.get("html", 0),
        category_counter.get("css", 0),
        output_dir,
    )
    return summary
