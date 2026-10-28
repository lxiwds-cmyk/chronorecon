import gzip
import logging

import pytest

from chronorecon.config import Settings
from chronorecon.db import Store
from chronorecon.downloader import (
    DownloadError,
    Downloader,
    FetchResult,
    parse_warc_record,
)
from chronorecon.models import DownloadCandidate, Snapshot, UrlHit


def make_warc(body: bytes, content_type: str = "text/html", status: str = "200 OK") -> bytes:
    http = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode("latin-1")
    http += body
    return (
        b"WARC/1.0\r\n"
        b"WARC-Type: response\r\n"
        b"Content-Type: application/http; msgtype=response\r\n"
        + f"Content-Length: {len(http)}\r\n\r\n".encode("ascii")
        + http
    )


def test_parse_warc_plain():
    record = make_warc(b"<html>hello</html>")
    result = parse_warc_record(record)
    assert result.http_status == 200
    assert result.content_type == "text/html"
    assert result.body == b"<html>hello</html>"


def test_parse_warc_gzip_member():
    record = gzip.compress(make_warc(b"hello world"))
    result = parse_warc_record(record)
    assert result.body == b"hello world"


def test_parse_warc_content_encoding_gzip():
    body = gzip.compress(b"compressed body")
    http = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Encoding: gzip\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode("latin-1") + body
    record = (
        b"WARC/1.0\r\nWARC-Type: response\r\n"
        + f"Content-Length: {len(http)}\r\n\r\n".encode("ascii")
        + http
    )
    result = parse_warc_record(record)
    assert result.body == b"compressed body"


def test_parse_warc_rejects_error_status():
    with pytest.raises(DownloadError):
        parse_warc_record(make_warc(b"not found", status="404 Not Found"))


def test_parse_warc_rejects_truncated():
    record = make_warc(b"hello world")[:-3]
    with pytest.raises(DownloadError):
        parse_warc_record(record)


@pytest.fixture
def downloader(tmp_path):
    settings = Settings(
        domains=["example.com"],
        output_root=tmp_path,
        download=True,
        threads=2,
        timeout=5,
        retries=0,
    )
    store = Store(tmp_path / "meta" / "test.db")
    logger = logging.getLogger("test.downloader")
    logger.addHandler(logging.NullHandler())
    instance = Downloader(settings, store, logger, tmp_path / "example.com")
    yield instance
    store.close()


def test_candidate_generation(downloader):
    wayback = DownloadCandidate(
        url="https://example.com/a",
        source="wayback",
        snapshot_id=1,
        timestamp="20200101000000",
        status="200",
    )
    candidate = downloader._candidate_from_snapshot("https://example.com/a", wayback)
    assert candidate.download_url == (
        "https://web.archive.org/web/20200101000000id_/https://example.com/a"
    )

    cc = DownloadCandidate(
        url="https://example.com/a",
        source="commoncrawl",
        warc_filename="crawl-data/x.warc.gz",
        warc_offset=10,
        warc_length=20,
    )
    candidate = downloader._candidate_from_snapshot("https://example.com/a", cc)
    assert candidate.warc_offset == 10

    urlscan = DownloadCandidate(
        url="https://example.com/a",
        source="urlscan",
        response_hash="abc123",
    )
    candidate = downloader._candidate_from_snapshot("https://example.com/a", urlscan)
    assert candidate.download_url == "https://urlscan.io/responses/abc123/"

    unsupported = DownloadCandidate(
        url="https://example.com/a", source="otx", timestamp="20200101"
    )
    assert downloader._candidate_from_snapshot("https://example.com/a", unsupported) is None


def test_write_content_deduplicates(downloader):
    path, digest, duplicate = downloader._write_content(
        "https://example.com/a", b"same bytes", "text/html", None
    )
    assert path.endswith("a.html")
    assert duplicate == ""
    assert (downloader.files_dir / path).read_bytes() == b"same bytes"

    second, second_digest, duplicate = downloader._write_content(
        "https://example.com/b", b"same bytes", "text/html", None
    )
    assert second == path
    assert second_digest == digest
    assert duplicate == path
    assert not (downloader.files_dir / "example.com" / "b.html").exists()


def test_write_content_restores_deleted_file(downloader):
    path, _, _ = downloader._write_content(
        "https://example.com/a", b"same bytes", "text/html", None
    )
    target = downloader.files_dir / path
    target.unlink()

    restored, digest, duplicate = downloader._write_content(
        "https://example.com/a", b"same bytes", "text/html", None
    )
    assert restored == path
    assert duplicate == ""
    assert digest
    assert target.read_bytes() == b"same bytes"


def test_candidates_filter_dates_and_disable_live(downloader):
    downloader.settings.from_date = "2020"
    downloader.settings.to_date = "2020"
    snapshots = [
        DownloadCandidate(
            url="u", source="wayback", timestamp="20190101000000", status="200"
        ),
        DownloadCandidate(
            url="u", source="wayback", timestamp="20200101000000", status="200"
        ),
        DownloadCandidate(
            url="u", source="wayback", timestamp="20210101000000", status="200"
        ),
    ]
    candidates = downloader._candidates("https://example.com/a", snapshots)
    assert [item.timestamp for item in candidates] == ["20200101000000"]
    assert all(item.source != "live" for item in candidates)


def test_limit_versions(downloader):
    candidates = [
        DownloadCandidate(url="u", source="wayback", timestamp="2020", digest="a"),
        DownloadCandidate(url="u", source="wayback", timestamp="2021", digest="a"),
        DownloadCandidate(url="u", source="wayback", timestamp="2022", digest="b"),
        DownloadCandidate(url="u", source="live"),
    ]
    limited = downloader._limit_versions("u", candidates)
    assert len(limited) == 3
    assert [item.digest for item in limited] == ["a", "b", ""]


def test_all_versions_downloads_each_capture(downloader):
    downloader.settings.all_versions = True
    downloader.settings.allow_live = False
    for timestamp, digest in (
        ("20200101000000", "digest-one"),
        ("20210101000000", "digest-two"),
    ):
        downloader.store.add_hit(
            UrlHit(
                url="https://example.com/a",
                source="wayback",
                timestamp=timestamp,
                status="200",
                snapshot=Snapshot(
                    source="wayback",
                    timestamp=timestamp,
                    status="200",
                    mime="text/html",
                    digest=digest,
                ),
            )
        )
    downloader.store.commit()
    url_id = next(downloader.store.iter_urls())["id"]

    def fake_fetch(candidate):
        return FetchResult(
            body=f"body-{candidate.timestamp}".encode(),
            content_type="text/html",
            http_status=200,
        )

    downloader._fetch = fake_fetch
    results = downloader._download_one(url_id, "https://example.com/a")
    assert results is not None
    assert len(results) == 2
    assert all(item.status == "saved" for item in results)
    assert len({item.path for item in results}) == 2
    for item in results:
        assert (downloader.files_dir / item.path).is_file()

    # A resumed run sees both captures as completed and skips the URL.
    for item in results:
        downloader.store.record_download(item)
    downloader.store.commit()
    assert downloader._download_one(url_id, "https://example.com/a") is None
