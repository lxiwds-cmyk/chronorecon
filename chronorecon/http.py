"""HTTP helpers with thread-local sessions, retries and polite rate limits."""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class HttpError(RuntimeError):
    def __init__(self, message: str, status: Optional[int] = None, url: str = ""):
        super().__init__(message)
        self.status = status
        self.url = url


class RateLimiter:
    """Per-host minimum interval limiter shared by all downloader threads."""

    def __init__(self):
        self._guard = threading.Lock()
        self._locks: Dict[str, threading.Lock] = {}
        self._last: Dict[str, float] = {}

    def _lock_for(self, key: str) -> threading.Lock:
        with self._guard:
            lock = self._locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._locks[key] = lock
            return lock

    def wait(self, key: str, min_interval: float) -> None:
        if min_interval <= 0:
            return
        lock = self._lock_for(key)
        with lock:
            now = time.monotonic()
            last = self._last.get(key, 0.0)
            delay = (last + min_interval) - now
            if delay > 0:
                time.sleep(delay)
            self._last[key] = time.monotonic()


class HttpClient:
    """A requests wrapper safe to share between threads.

    Each thread gets its own ``requests.Session`` because Session objects are
    not thread-safe.  Retries are configured for transient archive/API errors.
    """

    def __init__(
        self,
        timeout: int = 45,
        retries: int = 4,
        user_agent: str = "ChronoRecon/1.0",
        insecure: bool = False,
    ):
        self.timeout = timeout
        self.retries = retries
        self.user_agent = user_agent
        self.insecure = insecure
        self._local = threading.local()

    def _make_session(self, retries: Optional[int] = None) -> requests.Session:
        session = requests.Session()
        session.headers.update(
            {
                "User-Agent": self.user_agent,
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "keep-alive",
            }
        )
        count = max(0, self.retries if retries is None else int(retries))
        retry = Retry(
            total=count,
            connect=count,
            read=count,
            status=count,
            backoff_factor=1.5,
            status_forcelist=(429, 500, 502, 503, 504, 520, 522, 524),
            allowed_methods=frozenset({"GET", "HEAD"}),
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=32,
            pool_maxsize=32,
            pool_block=False,
        )
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    @property
    def session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = self._make_session()
            self._local.session = session
        return session

    @property
    def once_session(self) -> requests.Session:
        """A session with no automatic retries, for endpoints we retry manually."""
        session = getattr(self._local, "once_session", None)
        if session is None:
            session = self._make_session(retries=0)
            self._local.once_session = session
        return session

    def get(self, url: str, once: bool = False, **kwargs: Any) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", not self.insecure)
        session = self.once_session if once else self.session
        return session.get(url, **kwargs)

    def get_json(self, url: str, **kwargs: Any) -> Any:
        response = self.get(url, **kwargs)
        if response.status_code >= 400:
            raise HttpError(
                f"HTTP {response.status_code} for {url}",
                status=response.status_code,
                url=url,
            )
        try:
            return response.json()
        except ValueError as exc:
            snippet = response.text[:300].replace("\n", " ")
            raise HttpError(f"invalid JSON from {url}: {snippet!r}") from exc

    def close(self) -> None:
        for attribute in ("session", "once_session"):
            session = getattr(self._local, attribute, None)
            if session is not None:
                session.close()
                setattr(self._local, attribute, None)


class TooLarge(Exception):
    pass


def read_response_limited(response: requests.Response, max_bytes: int) -> bytes:
    """Read a streaming response, enforcing a decoded-size limit."""
    if max_bytes > 0:
        declared = response.headers.get("Content-Length")
        if declared and declared.isdigit() and int(declared) > max_bytes:
            raise TooLarge(
                f"Content-Length {int(declared)} exceeds limit {max_bytes}"
            )
    chunks = []
    total = 0
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        total += len(chunk)
        if max_bytes > 0 and total > max_bytes:
            raise TooLarge(f"response exceeds limit {max_bytes}")
        chunks.append(chunk)
    return b"".join(chunks)
