import json
import logging

from chronorecon.db import Store
from chronorecon.models import DownloadResult, Snapshot, UrlHit
from chronorecon.report import generate_reports


def test_reports_end_to_end(tmp_path):
    store = Store(tmp_path / "metadata" / "chronorecon.db")
    logger = logging.getLogger("test.report")
    logger.addHandler(logging.NullHandler())
    try:
        store.add_hit(
            UrlHit(
                url="https://example.com/",
                source="wayback",
                timestamp="20200101000000",
                status="200",
                mime="text/html",
                snapshot=Snapshot(
                    source="wayback",
                    timestamp="20200101000000",
                    status="200",
                    mime="text/html",
                ),
            )
        )
        store.add_hit(
            UrlHit(
                url="https://example.com/app.js",
                source="commoncrawl",
                mime="application/javascript",
                snapshot=Snapshot(
                    source="commoncrawl",
                    mime="application/javascript",
                ),
            )
        )
        store.add_hit(
            UrlHit(
                url="https://sub.example.com/style.css",
                source="urlscan",
                mime="text/css",
            )
        )
        store.add_subdomain("sub.example.com", "crtsh")
        url_id = next(store.iter_urls())["id"]
        store.record_download(
            DownloadResult(
                url="https://example.com/",
                source="wayback",
                url_id=url_id,
                snapshot_id=1,
                path="example.com/index.html",
                sha256="deadbeef",
                size=12,
                http_status=200,
                content_type="text/html",
                status="saved",
            )
        )
        store.commit()

        out = tmp_path / "example.com"
        summary = generate_reports(store, out, "example.com", logger)

        assert (out / "urls.txt").read_text().splitlines() == [
            "https://example.com/",
            "https://example.com/app.js",
            "https://sub.example.com/style.css",
        ]
        assert (out / "urls_js.txt").read_text().strip() == (
            "https://example.com/app.js"
        )
        assert (out / "urls_css.txt").read_text().strip() == (
            "https://sub.example.com/style.css"
        )
        assert "https://example.com/" in (out / "urls_html.txt").read_text()
        assert (out / "subdomains.txt").read_text().splitlines() == [
            "example.com",
            "sub.example.com",
        ]
        assert (out / "urls_by_source" / "wayback.txt").read_text().strip() == (
            "https://example.com/"
        )
        assert summary["counts"]["urls"] == 3
        assert summary["counts"]["downloads_saved"] == 1
        assert summary["counts"]["javascript_files"] == 1
        assert summary["counts"]["css_files"] == 1

        stored = json.loads((out / "metadata" / "summary.json").read_text())
        assert stored["target"] == "example.com"
        assert stored["counts"]["urls"] == 3
        lines = (out / "metadata" / "urls.jsonl").read_text().splitlines()
        assert len(lines) == 3
        assert json.loads(lines[0])["sources"] == ["wayback"]
        assert "ChronoRecon" in (out / "README.txt").read_text()
        assert (out / "downloads").is_dir()
    finally:
        store.close()
