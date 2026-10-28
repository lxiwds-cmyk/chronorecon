import logging

from chronorecon.collector import Collector
from chronorecon.config import Settings
from chronorecon.db import Store


def test_imports_are_scoped_and_stored(tmp_path):
    source = tmp_path / "urls.txt"
    source.write_text(
        "\n".join(
            [
                "# comment",
                "https://example.com/a.js",
                "example.com/b",
                "https://sub.example.com/c",
                "https://other.com/d",
                "mailto:test@example.com",
                "",
            ]
        )
    )
    settings = Settings(
        domains=["example.com"],
        output_root=tmp_path,
        url_sources=[],
        passive_sources=[],
        import_files=[str(source)],
        download=False,
    )
    store = Store(tmp_path / "metadata" / "test.db")
    logger = logging.getLogger("test.collector")
    logger.addHandler(logging.NullHandler())
    try:
        collector = Collector(settings, store, logger)
        counts = collector.run("example.com")
        assert counts["urls"] == 3
        urls = [row["url"] for row in store.iter_report_rows()]
        assert urls == [
            "https://example.com/a.js",
            "https://example.com/b",
            "https://sub.example.com/c",
        ]
        assert store.subdomains() == [
            "example.com",
            "sub.example.com",
        ]
        run = {item["source"]: item for item in store.source_runs()}["import"]
        assert run["status"] == "ok"
        assert run["urls"] == 3
    finally:
        store.close()


def test_import_regex_filter(tmp_path):
    source = tmp_path / "urls.txt"
    source.write_text("https://example.com/keep.js\nhttps://example.com/drop.png\n")
    settings = Settings(
        domains=["example.com"],
        output_root=tmp_path,
        url_sources=[],
        passive_sources=[],
        import_files=[str(source)],
        include_regex=r"\.js$",
        download=False,
    )
    store = Store(tmp_path / "metadata" / "test.db")
    logger = logging.getLogger("test.collector")
    logger.addHandler(logging.NullHandler())
    try:
        Collector(settings, store, logger).run("example.com")
        assert [row["url"] for row in store.iter_report_rows()] == [
            "https://example.com/keep.js"
        ]
    finally:
        store.close()
