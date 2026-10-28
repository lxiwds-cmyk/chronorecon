import json

import pytest

from chronorecon.sources.base import SourceError
from chronorecon.sources.wayback import parse_cdx_json


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
