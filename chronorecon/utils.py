"""URL, scope, path and timestamp helpers."""

from __future__ import annotations

import datetime as _dt
import hashlib
import os
import re
import unicodedata
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set
from urllib.parse import quote, unquote, urlsplit, urlunsplit

DEFAULT_PORTS = {"http": 80, "https": 443}
REJECTED_SCHEMES = {
    "javascript",
    "mailto",
    "data",
    "tel",
    "blob",
    "about",
    "file",
    "ftp",
    "ftps",
    "ws",
    "wss",
}
RESERVED_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}
MIME_EXTENSIONS = {
    "text/html": ".html",
    "application/xhtml+xml": ".html",
    "text/css": ".css",
    "application/javascript": ".js",
    "application/x-javascript": ".js",
    "text/javascript": ".js",
    "application/ecmascript": ".js",
    "text/ecmascript": ".js",
    "application/json": ".json",
    "application/ld+json": ".json",
    "text/json": ".json",
    "application/xml": ".xml",
    "text/xml": ".xml",
    "text/plain": ".txt",
    "text/csv": ".csv",
    "text/markdown": ".md",
    "application/pdf": ".pdf",
    "application/zip": ".zip",
    "application/gzip": ".gz",
    "application/x-gzip": ".gz",
    "application/x-tar": ".tar",
    "application/wasm": ".wasm",
    "application/x-httpd-php": ".php",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/svg+xml": ".svg",
    "image/x-icon": ".ico",
    "image/vnd.microsoft.icon": ".ico",
    "font/woff": ".woff",
    "font/woff2": ".woff2",
    "font/ttf": ".ttf",
    "font/otf": ".otf",
    "application/vnd.ms-fontobject": ".eot",
    "video/mp4": ".mp4",
    "video/webm": ".webm",
    "audio/mpeg": ".mp3",
    "audio/ogg": ".ogg",
}


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def sha1_hex(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8", "replace")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def normalize_domain(value: str) -> str:
    """Turn a domain or URL into a lowercase IDNA hostname.

    ``https://www.Example.com/path`` -> ``www.example.com``.
    The caller decides whether to use the apex or the literal host.
    """
    value = (value or "").strip()
    if not value:
        raise ValueError("empty domain")
    if "://" not in value:
        value = "https://" + value
    parsed = urlsplit(value)
    host = parsed.hostname
    if not host:
        raise ValueError(f"could not parse a hostname from {value!r}")
    host = host.rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    if not host or len(host) > 253:
        raise ValueError(f"invalid hostname: {value!r}")
    if ":" not in host:  # IPv6 literals are handled leniently.
        if not re.fullmatch(r"[a-z0-9_](?:[a-z0-9._-]*[a-z0-9_])?", host):
            raise ValueError(f"invalid hostname: {value!r}")
        if any(not label for label in host.split(".")):
            raise ValueError(f"invalid hostname: {value!r}")
    return host


def host_from_url(url: str) -> str:
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return ""
    return host.rstrip(".").lower()


def normalize_url(url: str) -> Optional[str]:
    """Normalize an HTTP(S) URL for deduplication and downloading.

    Returns ``None`` for non-HTTP schemes and malformed values.  Fragments are
    removed because they are never sent to a server and cannot identify a
    stored file.  Credentials and default ports are removed.
    """
    if not url:
        return None
    url = url.strip().replace("\x00", "")
    if not url or len(url) > 16384:
        return None
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme in REJECTED_SCHEMES or scheme not in ("http", "https"):
        return None
    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if not host:
        return None
    host = host.rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass

    netloc = host
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]"
    if port and DEFAULT_PORTS.get(scheme) != port:
        netloc = f"{netloc}:{port}"

    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    # Percent-encode unsafe characters (spaces, angle brackets, non-ASCII)
    # while leaving existing escapes such as %2F intact.
    path = quote(path, safe="/%:@!$&'()*+,;=-._~")
    query = quote(parsed.query, safe="/%?:@!$&'()*+,;=-._~")
    return urlunsplit((scheme, netloc, path, query, ""))


def host_in_scope(host: str, root: str, include_subdomains: bool = True) -> bool:
    host = (host or "").rstrip(".").lower()
    root = (root or "").rstrip(".").lower()
    if not host or not root:
        return False
    if host == root:
        return True
    return bool(include_subdomains and host.endswith("." + root))


def is_in_scope(url: str, root: str, include_subdomains: bool = True) -> bool:
    host = host_from_url(url)
    return host_in_scope(host, root, include_subdomains)


def url_extension(url: str) -> str:
    try:
        path = urlsplit(url).path
    except ValueError:
        return ""
    name = unquote(path.rsplit("/", 1)[-1])
    ext = os.path.splitext(name)[1].lower()
    return ext if re.fullmatch(r"\.[a-z0-9]{1,12}", ext or "") else ""


def content_type_to_ext(content_type: str) -> str:
    mime = (content_type or "").split(";", 1)[0].strip().lower()
    if not mime:
        return ""
    if mime in MIME_EXTENSIONS:
        return MIME_EXTENSIONS[mime]
    if mime.startswith("text/"):
        return ".txt"
    if mime.startswith("image/"):
        return ".img"
    if mime.startswith("font/"):
        return ".font"
    if mime.startswith("audio/"):
        return ".audio"
    if mime.startswith("video/"):
        return ".video"
    return ""


def _safe_segment(segment: str) -> str:
    segment = unquote(segment)
    segment = unicodedata.normalize("NFKC", segment)
    segment = segment.replace("\\", "_").replace("/", "_")
    segment = re.sub(r"[^A-Za-z0-9._~@+-]", "_", segment)
    segment = segment.strip(" .")
    if not segment or segment in (".", ".."):
        segment = "_"
    if segment.upper().split(".", 1)[0] in RESERVED_NAMES:
        segment = "_" + segment
    if len(segment) > 120:
        segment = segment[:90] + "__" + sha1_hex(segment)[:10]
    return segment


def _safe_host_dir(url: str) -> str:
    parsed = urlsplit(url)
    host = (parsed.hostname or "unknown").rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    host = re.sub(r"[^A-Za-z0-9._-]", "_", host) or "unknown"
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port and port not in (80, 443):
        host = f"{host}_{port}"
    return host


def safe_path_for_url(
    url: str,
    content_type: str = "",
    version_tag: Optional[str] = None,
) -> str:
    """Return a safe relative path for a downloaded URL.

    The host becomes the first directory.  Query strings are represented by a
    short hash so that ``?v=1`` and ``?v=2`` cannot overwrite each other.
    """
    parsed = urlsplit(url)
    path = unquote(parsed.path or "/")
    if path.endswith("/"):
        path += "index.html"
    segments: List[str] = [s for s in path.split("/") if s]
    if not segments:
        segments = ["index.html"]

    # Keep a sane directory depth.  Deep URLs get a deterministic prefix.
    if len(segments) > 24:
        digest = sha1_hex(path)[:10]
        segments = ["_deep_" + digest] + segments[-23:]

    segments = [_safe_segment(seg) for seg in segments]
    last = segments[-1]
    stem, ext = os.path.splitext(last)
    if not ext:
        ext = content_type_to_ext(content_type)

    suffixes = ""
    if parsed.query:
        suffixes += "__q_" + sha1_hex(parsed.query)[:10]
    if version_tag:
        tag = re.sub(r"[^A-Za-z0-9._-]", "_", str(version_tag))[:48].strip("._-")
        if tag:
            suffixes += "__v_" + tag
    if len(stem) > 120:
        stem = stem[:90] + "__" + sha1_hex(stem)[:10]
    segments[-1] = stem + suffixes + ext

    host_dir = _safe_host_dir(url)
    rel = "/".join([host_dir] + segments)
    if len(rel) > 900:
        rel = host_dir + "/" + sha1_hex(url)[:20] + (ext or ".bin")
    return rel


def safe_join(base: Path, relative: str) -> Path:
    """Join ``relative`` under ``base`` and refuse path traversal."""
    base = Path(base).resolve()
    target = (base / relative).resolve()
    try:
        target.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"unsafe path outside output directory: {relative}") from exc
    return target


def compact_timestamp(value) -> str:
    """Convert common date formats to a 4-14 digit sortable timestamp."""
    if value is None or value == "":
        return ""
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 10_000_000_000:  # milliseconds
            number /= 1000.0
        try:
            return _dt.datetime.fromtimestamp(
                number, _dt.timezone.utc
            ).strftime("%Y%m%d%H%M%S")
        except (OSError, OverflowError, ValueError):
            return ""
    text = str(value).strip()
    digits = re.sub(r"\D", "", text)
    if len(digits) >= 8:
        return digits[:14]
    if len(digits) >= 4:
        return digits[:4]
    return ""


def parse_size(value: str, default: int = 0) -> int:
    """Parse ``50M``, ``1.5GB`` or a plain byte count into bytes.

    ``0`` and an empty value mean unlimited.  Negative values are invalid.
    """
    if value is None:
        return default
    text = str(value).strip().lower().replace("_", "").replace(" ", "")
    if not text:
        return default
    match = re.fullmatch(r"(\d+(?:\.\d+)?)([kmgt]?)(?:i?b)?", text)
    if not match:
        raise ValueError(f"invalid size: {value!r}")
    number = float(match.group(1))
    unit = match.group(2)
    factors = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}
    return int(number * factors[unit])


def normalize_cdx_date(value: str) -> str:
    """Validate a Wayback/Common Crawl date and return its digit form."""
    if value is None or str(value).strip() == "":
        return ""
    digits = re.sub(r"\D", "", str(value))
    if len(digits) not in (4, 6, 8, 10, 12, 14):
        raise ValueError(
            f"invalid date {value!r}; use YYYY, YYYYMM, YYYYMMDD or 14 digits"
        )
    return digits


def date_bound(value: str, end: bool = False) -> str:
    """Expand a validated date to a 14-digit lower or upper bound."""
    digits = re.sub(r"\D", "", str(value or ""))[:14]
    if not digits:
        return ""
    return digits + ("9" if end else "0") * (14 - len(digits))


def timestamp_in_range(
    timestamp: str, from_date: str = "", to_date: str = ""
) -> bool:
    """Return whether a capture timestamp falls inside inclusive date bounds.

    Sources without a timestamp are left to the caller's judgment; this helper
    returns ``True`` for them because there is nothing to compare.
    """
    if not timestamp:
        return True
    digits = re.sub(r"\D", "", str(timestamp))
    if not digits:
        return True
    # Some APIs return a Unix epoch as a string instead of a formatted date.
    if len(digits) in (10, 13) and not digits.startswith(("19", "20")):
        converted = compact_timestamp(int(digits))
        if converted:
            digits = converted
    value = (digits + "0" * 14)[:14]
    lower = date_bound(from_date)
    upper = date_bound(to_date, end=True)
    if lower and value < lower:
        return False
    if upper and value > upper:
        return False
    return True


def parse_ext_set(values: Iterable[str]) -> Set[str]:
    result: Set[str] = set()
    for value in values or []:
        for item in str(value).split(","):
            item = item.strip().lower()
            if not item:
                continue
            item = item.replace("*", "").lstrip(".")
            if item:
                result.add("." + item)
    return result


def extension_from_content_type(content_type: str) -> str:
    return content_type_to_ext(content_type)


def looks_like_archive_error(text: str) -> bool:
    if not text:
        return False
    sample = text[:6000].lower()
    markers = (
        "internet archive: temporarily offline",
        "the wayback machine is temporarily unavailable",
        "wayback machine has not archived that url",
        "this url has been excluded from the wayback machine",
        "not archived",
        "too many requests",
        "rate limit exceeded",
        "request rate exceeded",
    )
    return any(marker in sample for marker in markers)


def extract_original_url(value: str) -> str:
    """Unwrap a Wayback/Arquivo replay URL into the original URL when possible."""
    value = (value or "").strip()
    match = re.match(
        r"^https?://web\.archive\.org/web/\d{4,14}(?:[a-z_]+)?/(.+)$",
        value,
        re.IGNORECASE,
    )
    if match:
        return match.group(1)
    match = re.match(
        r"^https?://arquivo\.pt/(?:noFrame/)?replay/\d{4,14}(?:[a-z_]+)?/(.+)$",
        value,
        re.IGNORECASE,
    )
    if match:
        return match.group(1)
    return value


def human_bytes(size: int) -> str:
    number = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if number < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(number)} {unit}"
            return f"{number:.1f} {unit}"
        number /= 1024.0
    return f"{number:.1f} TB"


def chunked(items: Sequence, size: int):
    for start in range(0, len(items), size):
        yield items[start : start + size]


def unique_preserving_order(values: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    result: List[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result
