# ChronoRecon

**Historical URL reconnaissance and archived-file recovery for authorized security testing.**

ChronoRecon gives one domain, queries many **independent** historical sources, writes every unique URL to
`target.com/urls.txt`, downloads the archived response bodies into `target.com/downloads/`, and produces
ready-to-grep lists for JavaScript, HTML and CSS.

Unlike wrappers that call gau, waymore and waybackurls at the same time — all of which mostly read the same
Wayback/Common Crawl indexes — ChronoRecon talks to the underlying archives and APIs directly and adds
independent archives such as Arquivo.pt and GhostArchive. gau/waymore output can still be merged with
`--from-file` without duplicating queries.

---

## Features

- **7 URL sources** and **5 passive sources**; urlscan, VirusTotal and OTX passive DNS can use API keys.
- **Wayback CDX** with resumable pagination and capture metadata; `--all-versions` keeps multiple captures, and raw replay uses `id_` downloads.
- **Common Crawl** across multiple crawl indexes with direct WARC `Range` body recovery.
- **Arquivo.pt** (Portuguese web archive) URL index and raw replay.
- **GhostArchive** search index.
- **AlienVault OTX**, **urlscan.io**, optional **VirusTotal**.
- **Passive discovery** with crt.sh, Cert Spotter, HackerTarget, RapidDNS and optional OTX passive DNS.
- **SQLite-backed** state: resume a huge run, never re-download completed URLs.
- **SHA-256 content deduplication** across URLs and sources.
- Separate lists for JS, HTML and CSS, plus per-source lists and JSONL metadata.
- Retries, polite per-host rate limits, configurable timeouts and size limits.
- Import existing URL lists from `gau`, `waymore`, `waybackurls`, Burp, or notes.

## Data sources

| Source | Kind | What it provides | Key |
|---|---|---|---|
| `wayback` | URL | Internet Archive CDX captures; raw replay bodies | — |
| `commoncrawl` | URL | Multiple Common Crawl indexes; WARC response bodies | — |
| `otx` | URL | AlienVault OTX domain URL history | — |
| `urlscan` | URL | urlscan.io historical scans; response bodies (detail API) | optional |
| `arquivo` | URL | Arquivo.pt CDX and raw replay | — |
| `ghostarchive` | URL | GhostArchive search results | — |
| `virustotal` | URL | VirusTotal domain URL list | required |
| `crtsh` | Passive | Certificate Transparency hostnames | — |
| `certspotter` | Passive | Certificate Transparency hostnames | — |
| `hackertarget` | Passive | Host search | — |
| `rapiddns` | Passive | Subdomain index | — |
| `otx_passive` | Passive | OTX passive DNS hostnames | required |

Each archive above is a separate collection. Common Crawl is not the Wayback Machine; Arquivo.pt and
GhostArchive are independent crawls. `--sources all` enables every URL source; keyed sources are skipped with a
clear message when their key is absent.

Anonymous urlscan search is limited by urlscan to recent scans. Adding `URLSCAN_API_KEY` enables the result API
and response-body recovery. VirusTotal requires `VT_API_KEY`; OTX passive DNS requires `OTX_API_KEY`.

## Quick start

Requirements: **Python 3.9+** and normal internet access.

```bash
git clone https://github.com/lxiwds-cmyk/chronorecon.git
cd chronorecon

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# or: pip install -e .

python -m chronorecon example.com
```

After a `pip install`, the shorter command works:

```bash
chronorecon example.com
```

The target folder is created in the current directory unless `-o/--output` is given:

```text
example.com/
├── urls.txt                 # every unique historical URL, sorted
├── urls_js.txt
├── urls_html.txt
├── urls_css.txt
├── urls_by_source/
│   ├── arquivo.txt
│   ├── commoncrawl.txt
│   ├── ghostarchive.txt
│   ├── otx.txt
│   ├── urlscan.txt
│   └── wayback.txt
├── subdomains.txt
├── hosts.txt
├── downloads/               # recovered archived/live files
│   └── example.com/...
├── README.txt               # generated run summary
└── metadata/
    ├── chronorecon.db       # resumable state
    ├── urls.jsonl           # per-URL metadata
    ├── files.jsonl          # index of saved files
    ├── downloads.jsonl      # every download attempt
    ├── summary.json
    ├── failed.txt
    └── run.log
```

## Common usage

```bash
# Full default run: all archive sources + passive discovery + downloads
chronorecon example.com

# Put results in /tmp/recon, use 12 download threads
chronorecon example.com -o /tmp/recon --threads 12

# Enumerate only, no downloads
chronorecon example.com --no-download

# Keep up to 10 distinct captures of every URL
chronorecon example.com --all-versions --max-versions-per-url 10

# Only JavaScript, HTML and CSS
chronorecon example.com --only-ext js,html,css

# Exclude images and fonts from downloads
chronorecon example.com --exclude-ext png,jpg,jpeg,gif,svg,woff,woff2,ttf,ico

# Search one specific archive only
chronorecon example.com --sources wayback --no-passive

# Add output from other tools (no duplicate archive queries)
gau example.com > gau.txt
waymore -i example.com -oU waymore.txt
chronorecon example.com --from-file gau.txt --from-file waymore.txt

# Repeatable target batch
chronorecon example.com example.org -o /tmp/recon

# Discover source names / requirements
chronorecon --list-sources
```

### Optional API keys

```bash
export URLSCAN_API_KEY="..."
export VT_API_KEY="..."
export OTX_API_KEY="..."

chronorecon example.com --sources all --passive-sources all
```

Keys can also be passed with `--urlscan-key`, `--vt-key` and `--otx-key`. Keyed sources are never required
for a successful run; missing keys are reported as `skipped`.

## How downloading works

For each unique URL, ChronoRecon builds download candidates from stored capture metadata and tries them in
priority order:

1. **Wayback** raw replay: `https://web.archive.org/web/{timestamp}id_/{url}`
2. **Common Crawl** WARC: HTTP `Range` request to `data.commoncrawl.org` and WARC record parsing
3. **Arquivo.pt** raw replay: `https://arquivo.pt/noFrame/replay/{timestamp}id_/{url}`
4. **urlscan.io** response body by SHA-256 (with an API key)
5. **Live URL** as a last-resort fallback (`--no-live` disables it)

Successful responses are stored under `downloads/<host>/<path>`. Query strings get a short deterministic
suffix so different parameters cannot overwrite each other. Content is deduplicated by SHA-256: identical
bytes are saved once, and the metadata records which URL shares the file.

Defaults are intentionally safe: one usable capture per URL (the newest among collected candidates), 50 MiB
per file, no total cap. Use `--all-versions`, `--max-file-size`, `--max-total-size` and `--max-files` to
change this. Re-running the same command reuses the SQLite download state, so completed URLs are not fetched
again; source queries are repeated to pick up new captures. `--force` re-downloads and overwrites.

## Options worth knowing

| Option | Purpose |
|---|---|
| `--sources LIST` | URL sources (`all`, `none`, or comma-separated names) |
| `--passive-sources LIST` | Passive sources (`all`, `none`, or names) |
| `--all-sources` | Enable every source; keyed ones still require keys |
| `--from-file PATH` | Import extra URL lists; `-` reads stdin |
| `--max-urls-per-source N` | Cap rows per source |
| `--max-captures N` | Cap Wayback capture rows with `--all-versions` |
| `--max-file-size SIZE` | Per-file limit, e.g. `50M`, `1G`, `0` for unlimited |
| `--max-total-size SIZE` | Stop downloading after this many bytes |
| `--only-ext` / `--exclude-ext` | Extension allow/deny lists |
| `--include-regex` / `--exclude-regex` | URL filtering |
| `--from-date` / `--to-date` | Capture date bounds (`YYYY`, `YYYYMMDD`, or 14 digits); live fallback is disabled when set |
| `--all-versions` | Keep distinct captures of each URL |
| `--no-live` | Never fetch the current live URL |
| `--no-subdomains` | Restrict scope to the exact target host |
| `--cc-all` | Query every Common Crawl index instead of the newest 3 |
| `-q` / `-v` | Quiet / debug logging |

Run `chronorecon --help` for the complete list.

## Installation alternatives

### install.sh

```bash
chmod +x install.sh
./install.sh
```

The script creates `.venv`, installs dependencies and a `chronorecon` launcher in `.venv/bin`.

### Docker

```bash
docker build -t chronorecon .
docker run --rm -it -v "$PWD/results:/data" chronorecon example.com -o /data
```

### Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

## Design notes and limits

- The SQLite database makes each target resumable. A killed run can be restarted with the same command.
- Archived responses can be missing, truncated, or return archive error pages; the downloader validates
  status codes and obvious error markers, then falls back to another source or the live URL.
- Public archives are rate-limited and occasionally offline. Wayback CDX in particular can be slow; the
  tool retries with backoff and logs each attempt. Do not run many large targets in parallel.
- Common Crawl ranges are fetched only for the WARC record, not whole WARC files.
- URLScan's anonymous search window is limited; a free API key improves coverage and enables bodies.
- Historical data can contain secrets, but access must still be authorized. This tool performs only GET
  requests to public archives and, optionally, the live target.
- Some archives wrap responses with their own HTML. The raw replay endpoints (`id_`) are used where
  available to avoid archive banners.
- URLs are normalized (scheme/host casing, default ports, fragments, unsafe characters) before storage.
  Query strings are preserved and hashed only for filesystem naming.

## Legal and ethical use

ChronoRecon is for **authorized** security research, bug bounty programs that permit passive/historical
reconnaissance, and defensive asset inventory. You are responsible for complying with the target's scope,
program rules, terms of service, and applicable law. Do not use it to access systems you do not own or have
permission to test. The authors provide no warranty.

## Publishing to GitHub

From this repository:

```bash
git init
git add .
git commit -m "ChronoRecon 1.0.0: multi-source historical URL recon"
git branch -M main

# with GitHub CLI authenticated:
gh repo create chronorecon --public --source=. --remote=origin --push

# or create the repository in the web UI, then:
git remote add origin https://github.com/lxiwds-cmyk/chronorecon.git
git push -u origin main
```

## License

MIT — see [LICENSE](LICENSE).
