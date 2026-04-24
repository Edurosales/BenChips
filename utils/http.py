"""
utils/http.py — Cliente HTTP async con rate limiting, retry, baseline y detección de soft-404.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import ssl
import time
from typing import Optional
from urllib.parse import urlparse
from uuid import uuid4

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

from config import UA


class Baseline:
    """Fingerprint de respuesta para detectar soft-404."""

    def __init__(self, status: int, body: bytes):
        self.status     = status
        self.body_len   = len(body)
        self.body_hash  = hashlib.md5(body[:8192]).hexdigest()
        self.title      = self._extract_title(body)

    @staticmethod
    def _extract_title(body: bytes) -> str:
        text = body[:2048].decode("utf-8", errors="ignore").lower()
        m = re.search(r"<title[^>]*>(.*?)</title>", text)
        return m.group(1).strip()[:80] if m else ""

    def is_soft_404(self, status: int, body: bytes) -> bool:
        """True si la respuesta parece ser una soft-404."""
        if self.status != 200 or status != 200:
            return False
        if hashlib.md5(body[:8192]).hexdigest() == self.body_hash:
            return True
        if self.body_len > 200 and len(body) > 100:
            ratio = len(body) / self.body_len
            if 0.92 <= ratio <= 1.08:
                return True
        title = Baseline._extract_title(body)
        if title and self.title and title == self.title:
            return True
        return False


class Response:
    def __init__(self, status: int, headers: dict, body: bytes, url: str = ""):
        self.status  = status
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.body    = body
        self.url     = url
        self.text    = body.decode("utf-8", errors="ignore")

    def get_header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


class AsyncHTTPClient:
    """
    Cliente aiohttp con:
    - Rate limiting por semáforo
    - Retry con backoff exponencial
    - Baseline soft-404 por hostname
    - SSL lax opcional
    """

    def __init__(
        self,
        session: "aiohttp.ClientSession",
        rate_limit:   int = 25,
        timeout:      int = 8,
        max_retries:  int = 2,
    ):
        self.session     = session
        self.semaphore   = asyncio.Semaphore(rate_limit)
        self.timeout     = aiohttp.ClientTimeout(total=timeout, connect=5)
        self.max_retries = max_retries
        self.baselines:  dict[str, Baseline] = {}
        self._headers = {
            "User-Agent": UA,
            "Accept":     "text/html,application/json,*/*;q=0.8",
        }

    async def request(
        self,
        method:        str,
        url:           str,
        follow:        bool = True,
        lax_ssl:       bool = True,
        extra_headers: Optional[dict] = None,
        body_limit:    int  = 65536,
    ) -> Optional[Response]:
        ssl_ctx = False if lax_ssl else None
        hdrs    = dict(self._headers)
        if extra_headers:
            hdrs.update(extra_headers)

        max_redirects = 10 if follow else 0

        for attempt in range(self.max_retries + 1):
            async with self.semaphore:
                try:
                    async with self.session.request(
                        method, url,
                        headers        = hdrs,
                        ssl            = ssl_ctx,
                        allow_redirects= follow,
                        max_redirects  = max_redirects,
                        timeout        = self.timeout,
                    ) as r:
                        body = await r.read()
                        body = body[:body_limit]
                        return Response(r.status, dict(r.headers), body, str(r.url))

                except asyncio.TimeoutError:
                    pass
                except Exception:
                    pass

                if attempt < self.max_retries:
                    await asyncio.sleep(2 ** attempt * 0.5)

        return None

    async def get(self, url: str, **kwargs) -> Optional[Response]:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs) -> Optional[Response]:
        return await self.request("HEAD", url, **kwargs)

    async def options_req(self, url: str, **kwargs) -> Optional[Response]:
        return await self.request("OPTIONS", url, **kwargs)

    async def method_req(self, method: str, url: str, **kwargs) -> Optional[Response]:
        return await self.request(method, url, **kwargs)

    async def establish_baseline(self, base_url: str) -> None:
        """Hace 2 peticiones a rutas aleatorias para fingerprint el comportamiento 404."""
        hostname = urlparse(base_url).hostname or base_url
        samples  = []

        for _ in range(2):
            rand_path = f"/{uuid4().hex}/{uuid4().hex}.html"
            resp = await self.get(
                base_url.rstrip("/") + rand_path,
                follow=True, lax_ssl=True
            )
            if resp:
                samples.append(resp)
            await asyncio.sleep(0.1)

        if samples:
            best = max(samples, key=lambda r: len(r.body))
            self.baselines[hostname] = Baseline(best.status, best.body)

    def is_soft_404(self, hostname: str, status: int, body: bytes) -> bool:
        bl = self.baselines.get(hostname)
        if bl is None:
            return False
        return bl.is_soft_404(status, body)


def create_session() -> "aiohttp.ClientSession":
    """Crea una sesión aiohttp con connector optimizado."""
    connector = aiohttp.TCPConnector(
        limit           = 100,
        limit_per_host  = 30,
        ssl             = False,
        force_close     = False,
        enable_cleanup_closed = True,
    )
    return aiohttp.ClientSession(connector=connector)
