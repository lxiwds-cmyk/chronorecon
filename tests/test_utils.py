import pytest

from chronorecon.utils import (
    compact_timestamp,
    extract_original_url,
    host_in_scope,
    is_in_scope,
    normalize_cdx_date,
    normalize_domain,
    normalize_url,
    parse_ext_set,
    parse_size,
    safe_join,
    safe_path_for_url,
    timestamp_in_range,
)


def test_normalize_url_basics():
    assert normalize_url("HTTPS://Example.COM:443/a b?x=hello world#frag") == (
        "https://example.com/a%20b?x=hello%20world"
    )
    assert normalize_url("http://example.com") == "http://example.com/"
    assert normalize_url("http://example.com:8080/x") == "http://example.com:8080/x"
    assert normalize_url("http://example.com:80/x") == "http://example.com/x"
    assert normalize_url("https://example.com:443") == "https://example.com/"


def test_normalize_url_rejects_non_http():
    for value in (
        "javascript:alert(1)",
        "mailto:test@example.com",
        "data:text/plain,hello",
        "ftp://example.com/file",
        "",
    ):
        assert normalize_url(value) is None


def test_normalize_url_keeps_escapes():
    assert normalize_url("https://example.com/a%2Fb?q=%20") == (
        "https://example.com/a%2Fb?q=%20"
    )


def test_normalize_domain_and_scope():
    assert normalize_domain("https://www.Example.com/path") == "www.example.com"
    assert normalize_domain("example.com") == "example.com"
    assert host_in_scope("a.example.com", "example.com", True)
    assert host_in_scope("example.com", "example.com", True)
    assert not host_in_scope("example.com.evil.test", "example.com", True)
    assert not host_in_scope("a.example.com", "example.com", False)
    assert is_in_scope("https://a.example.com/x", "example.com", True)
    assert not is_in_scope("https://other.com/x", "example.com", True)


@pytest.mark.parametrize("value", ["../evil", ".example.com", "a..b", "bad host"])
def test_normalize_domain_rejects_bad_hosts(value):
    with pytest.raises(ValueError):
        normalize_domain(value)


def test_safe_paths_and_queries():
    path = safe_path_for_url("https://example.com/a/b.js?x=1", "application/javascript")
    assert path.startswith("example.com/a/")
    assert path.endswith(".js")
    assert "__q_" in path

    other = safe_path_for_url("https://example.com/a/b.js?x=2", "application/javascript")
    assert path != other
    assert safe_path_for_url("https://example.com/", "text/html") == "example.com/index.html"
    assert safe_path_for_url("https://example.com/a", "text/css") == "example.com/a.css"
    assert "__v_" in safe_path_for_url("https://example.com/a", "", "wayback-2020")


def test_safe_join_blocks_traversal(tmp_path):
    with pytest.raises(ValueError):
        safe_join(tmp_path, "../outside.txt")
    with pytest.raises(ValueError):
        safe_join(tmp_path, "a/../../outside.txt")
    assert safe_join(tmp_path, "a/b.txt").name == "b.txt"


def test_size_and_date_parsing():
    assert parse_size("0") == 0
    assert parse_size("10") == 10
    assert parse_size("1K") == 1024
    assert parse_size("1.5M") == 1572864
    assert parse_size("2 GB") == 2 * 1024**3
    with pytest.raises(ValueError):
        parse_size("nope")

    assert normalize_cdx_date("") == ""
    assert normalize_cdx_date("2020") == "2020"
    assert normalize_cdx_date("2020-01-02") == "20200102"
    assert normalize_cdx_date("20200102030405") == "20200102030405"
    with pytest.raises(ValueError):
        normalize_cdx_date("20-1")


def test_timestamp_in_range():
    assert timestamp_in_range("20200102030405", "2020", "2020")
    assert timestamp_in_range("20191231235959", "2020", "2020") is False
    assert timestamp_in_range("20210101000000", "2020", "2020") is False
    assert timestamp_in_range("20200102030405", "20200102", "20200102")
    assert timestamp_in_range("20200103000000", "20200102", "20200102") is False
    # Epoch strings are converted rather than compared as digits.
    assert timestamp_in_range("1577934245", "2020", "2020")
    # Unknown timestamps cannot be filtered.
    assert timestamp_in_range("", "2020", "2020")


def test_extensions_and_timestamps():
    assert parse_ext_set([".JS,html", "css"]) == {".js", ".html", ".css"}
    assert compact_timestamp("2020-01-02T03:04:05Z") == "20200102030405"
    assert compact_timestamp(1577934245) == "20200102030405"
    assert extract_original_url(
        "https://web.archive.org/web/20200101000000id_/https://example.com/a"
    ) == "https://example.com/a"
    assert extract_original_url("https://example.com/a") == "https://example.com/a"
