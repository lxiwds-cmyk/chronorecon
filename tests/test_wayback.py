import json
import logging
from types import SimpleNamespace

import pytest

from chronorecon.config import Settings
from chronorecon.sources.base import SourceError, SourceUnavailable
from chronorecon.sources.wayback import WaybackSource, parse_cdx_json


def test_parse_cdx_with_header():
    payload = [
        ["timestamp", "original", "statuscode"],
        ["20200101000000", "https://example.com/a", "200"],
        ["20210101000000", "https://example.com/b", "404"],
    ]
    records, resume = parse_cdx_json(json.dumps(payload))
    assert resume is None
    assert len(records) == 2
    assert records[0]["original"] == "https://example.com/a"
    assert records[1]["statuscode"] == "404"


def test_parse_cdx_with_resume_key():
    payload = [
        ["timestamp", "original"],
        ["20200101000000", "https://example.com/a"],
        [],
        ["resume-token-123"],
    ]
    records, resume = parse_cdx_json(json.dumps(payload))
    assert len(records) == 1
    assert resume == "resume-token-123"


def test_parse_cdx_without_header():
    payload = [["20200101000000", "https://example.com/a", "200", "text/html", "d", "1"]]
    records, resume = parse_cdx_json(json.dumps(payload))
    assert resume is None
    assert records[0]["timestamp"] == "20200101000000"


def test_parse_cdx_rejects_html():
    with pytest.raises(SourceError):
        parse_cdx_json("<html>temporarily offline</html>")


def test_parse_cdx_handles_empty():
    assert parse_cdx_json("[]") == ([], None)


def test_wayback_retries_without_collapse(monkeypatch, tmp_path):
    source = WaybackSource()
    calls = []
    payload = json.dumps(
        [
            ["timestamp", "original", "statuscode", "mimetype", "digest", "length"],
            [
                "20200101000000",
                "https://example.com/a",
                "200",
                "text/html",
                "digest",
                "1",
            ],
        ]
    )

    def fake_fetch(ctx, params, attempts=2, timeout=90):
        calls.append((dict(params), attempts, timeout))
        if params.get("collapse"):
            raise SourceUnavailable("HTTP 504")
        return payload

    monkeypatch.setattr(source, "_fetch", fake_fetch)
    settings = Settings(
        domains=["example.com"],
        output_root=tmp_path,
        url_sources=["wayback"],
        passive_sources=[],
        download=False,
    )
    ctx = SimpleNamespace(
        domain="example.com",
        settings=settings,
        log=logging.getLogger("test.wayback"),
    )
    hits = list(source.collect(ctx))

    assert len(hits) == 1
    assert hits[0].url == "https://example.com/a"
    assert calls[0][0]["collapse"] == "urlkey"
    assert calls[0][1:] == (1, 60)
    assert "collapse" not in calls[1][0]
    assert calls[1][1:] == (2, 90)
