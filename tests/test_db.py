from chronorecon.db import Store
from chronorecon.models import DownloadResult, Snapshot, UrlHit


def make_store(tmp_path):
    return Store(tmp_path / "metadata" / "chronorecon.db")


def test_add_hit_and_merge(tmp_path):
    store = make_store(tmp_path)
    try:
        hit = UrlHit(
            url="https://example.com/a",
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
        assert store.add_hit(hit) == (True, True)
        assert store.add_hit(hit) == (False, False)

        later = UrlHit(
            url="https://example.com/a",
            source="commoncrawl",
            timestamp="20210101000000",
            status="200",
            mime="text/html",
            snapshot=Snapshot(
                source="commoncrawl",
                timestamp="20210101000000",
                status="200",
                mime="text/html",
            ),
        )
        assert store.add_hit(later) == (False, True)
        rows = list(store.iter_report_rows())
        assert len(rows) == 1
        assert rows[0]["first_seen"] == "20200101000000"
        assert rows[0]["last_seen"] == "20210101000000"
        assert rows[0]["sources"] == ["commoncrawl", "wayback"]
        assert store.get_sources(rows[0]["id"]) == ["commoncrawl", "wayback"]
    finally:
        store.close()


def test_subdomains_and_counts(tmp_path):
    store = make_store(tmp_path)
    try:
        assert store.add_subdomain("WWW.Example.com.", "crtsh") is True
        assert store.add_subdomain("www.example.com", "certspotter") is False
        assert store.subdomains() == ["www.example.com"]
        assert store.host_sources()["www.example.com"] == ["certspotter", "crtsh"]
    finally:
        store.close()


def test_downloads_and_resume(tmp_path):
    store = make_store(tmp_path)
    try:
        store.add_hit(UrlHit(url="https://example.com/a", source="wayback"))
        url_id = next(store.iter_urls())["id"]
        result = DownloadResult(
            url="https://example.com/a",
            source="wayback",
            url_id=url_id,
            snapshot_id=1,
            path="example.com/a.html",
            sha256="abc",
            size=10,
            http_status=200,
            content_type="text/html",
            timestamp="20200101000000",
            status="saved",
        )
        store.record_download(result)
        store.commit()
        assert (store.get_completed(url_id)) == {("wayback", 1)}
        assert store.downloaded_url_ids() == {url_id}
        assert store.counts()["saved"] == 1
        assert store.counts()["saved_bytes"] == 10
        assert store.saved_hashes() == {"abc": "example.com/a.html"}
        files = store.download_rows()
        assert len(files) == 1
        assert files[0]["url"] == "https://example.com/a"
    finally:
        store.close()
