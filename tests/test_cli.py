import pytest

from chronorecon.cli import _resolve_sources, build_parser, main


def test_cli_import_only(tmp_path):
    source = tmp_path / "urls.txt"
    source.write_text(
        "https://example.com/\nhttps://example.com/app.js\n"
        "https://example.com/style.css\n"
    )
    out = tmp_path / "out"
    code = main(
        [
            "example.com",
            "-o",
            str(out),
            "--sources",
            "none",
            "--no-passive",
            "--from-file",
            str(source),
            "--no-download",
            "-q",
        ]
    )
    assert code == 0
    target = out / "example.com"
    assert (target / "urls.txt").is_file()
    assert (target / "downloads").is_dir()
    assert (target / "metadata" / "summary.json").is_file()
    assert len((target / "urls.txt").read_text().splitlines()) == 3
    assert (target / "urls_js.txt").read_text().strip() == "https://example.com/app.js"


def test_no_passive_overrides_all_sources():
    parser = build_parser()
    args = parser.parse_args(["example.com", "--all-sources", "--no-passive"])
    url_sources, passive_sources = _resolve_sources(args, parser)
    assert "wayback" in url_sources
    assert passive_sources == []


def test_cli_list_sources(capsys):
    assert main(["--list-sources"]) == 0
    output = capsys.readouterr().out
    assert "wayback" in output
    assert "commoncrawl" in output
    assert "arquivo" in output


def test_cli_requires_target():
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_cli_rejects_unknown_source(tmp_path):
    with pytest.raises(SystemExit) as exc:
        main(["example.com", "-o", str(tmp_path), "--sources", "not-real"])
    assert exc.value.code == 2


def test_cli_rejects_bad_date(tmp_path):
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "example.com",
                "-o",
                str(tmp_path),
                "--sources",
                "none",
                "--from-date",
                "20-1",
            ]
        )
    assert exc.value.code == 2


def test_cli_no_urls_returns_two(tmp_path):
    source = tmp_path / "empty.txt"
    source.write_text("https://other.com/x\n")
    code = main(
        [
            "example.com",
            "-o",
            str(tmp_path),
            "--sources",
            "none",
            "--no-passive",
            "--from-file",
            str(source),
            "--no-download",
            "-q",
        ]
    )
    assert code == 2
