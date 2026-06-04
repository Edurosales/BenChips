"""
utils/crawler.py — Crawler ligero para descubrir endpoints en el mismo dominio.

Extrae links de HTML (href, action, src) y de JS (fetch/axios calls).
Solo sigue URLs del mismo hostname — scope control automático.
Retorna lista ordenada de URLs únicas para alimentar el escáner activo.
"""
from __future__ import annotations

import asyncio
import re
from collections import deque
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin, urlparse, urlunparse

from utils.http import AsyncHTTPClient


class _HTMLLinkParser(HTMLParser):
    """Extrae URLs de href/action/src en HTML."""

    _LINK_ATTRS = {
        "a": "href", "link": "href", "area": "href",
        "form": "action",
        "script": "src", "iframe": "src", "frame": "src", "embed": "src",
        "img": "src",
    }

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        attr = dict(attrs)
        key = self._LINK_ATTRS.get(tag.lower())
        if key and attr.get(key):
            raw = attr[key].strip()
            # Ignorar anchors puros, mailto, tel, javascript:
            if raw and not raw.startswith(("#", "mailto:", "tel:", "javascript:")):
                self.links.append(urljoin(self.base_url, raw))


_JS_URL_PATTERNS = [
    re.compile(r"""fetch\s*\(\s*['"`]([^'"`\s]{4,200})['"`]""", re.I),
    re.compile(r"""axios\s*\.\s*\w+\s*\(\s*['"`]([^'"`\s]{4,200})['"`]""", re.I),
    re.compile(r"""(?:url|endpoint|api_?url|base_?url|path)\s*[:=]\s*['"`]([/][^'"`\s]{2,150})['"`]""", re.I),
    re.compile(r"""['"`](/api/[^'"`\s]{2,100})['"`]""", re.I),
    re.compile(r"""['"`](/v\d+/[^'"`\s]{2,100})['"`]""", re.I),
]


def _extract_js_urls(body: str, base_url: str) -> list[str]:
    urls = []
    for pat in _JS_URL_PATTERNS:
        for m in pat.finditer(body):
            candidate = m.group(1)
            full = urljoin(base_url, candidate)
            urls.append(full)
    return urls


def _normalize(url: str) -> str:
    """Elimina fragmentos, normaliza trailing slash."""
    p = urlparse(url)
    clean = urlunparse(p._replace(fragment=""))
    return clean.rstrip("/") or clean


def _same_scope(url: str, base_hostname: str) -> bool:
    h = (urlparse(url).hostname or "").lower()
    b = base_hostname.lower()
    return h == b or h.endswith("." + b)


def _is_static(url: str) -> bool:
    """Descarta assets estáticos que no tienen superficie de ataque."""
    ext = urlparse(url).path.rsplit(".", 1)[-1].lower()
    return ext in (
        "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp", "tiff",
        "css", "woff", "woff2", "ttf", "eot", "otf",
        "mp4", "mp3", "wav", "avi", "mov", "pdf",
        "zip", "tar", "gz", "rar",
    )


async def crawl(
    client: AsyncHTTPClient,
    start_url: str,
    max_pages: int = 80,
    max_depth: int = 2,
    concurrency: int = 8,
) -> list[str]:
    """
    Crawlea el sitio desde start_url, respetando el scope (mismo hostname).

    Args:
        client:      AsyncHTTPClient ya configurado (con auth si aplica).
        start_url:   URL raíz del objetivo.
        max_pages:   Máximo de páginas a visitar.
        max_depth:   Profundidad máxima de crawling.
        concurrency: Requests simultáneos del crawler.

    Returns:
        Lista de URLs únicas del mismo dominio, en orden de descubrimiento.
        Incluye paths de HTML, formularios, scripts y llamadas JS.
    """
    base_hostname = urlparse(start_url).hostname or ""
    visited: set[str] = set()
    discovered: list[str] = []           # orden de descubrimiento
    queue: asyncio.Queue = asyncio.Queue()
    await queue.put((start_url, 0))

    sem = asyncio.Semaphore(concurrency)

    async def process(url: str, depth: int):
        norm = _normalize(url)
        if norm in visited:
            return
        if not _same_scope(url, base_hostname):
            return
        if _is_static(url):
            return

        visited.add(norm)
        discovered.append(url)

        if depth >= max_depth:
            return

        async with sem:
            resp = await client.get(url, follow=True, lax_ssl=True, body_limit=131072)
        if not resp:
            return

        content_type = resp.headers.get("content-type", "").lower()
        new_links: list[str] = []

        # HTML: extraer href/action/src
        if "text/html" in content_type:
            parser = _HTMLLinkParser(url)
            try:
                parser.feed(resp.text)
            except Exception:
                pass
            new_links.extend(parser.links)

        # JS: extraer patrones de fetch/axios/url=
        if "javascript" in content_type or url.rstrip("/").endswith(".js"):
            new_links.extend(_extract_js_urls(resp.text, url))

        # También buscar JS inline en páginas HTML
        if "text/html" in content_type:
            new_links.extend(_extract_js_urls(resp.text, url))

        for link in new_links:
            n = _normalize(link)
            if n not in visited and _same_scope(link, base_hostname) and not _is_static(link):
                await queue.put((link, depth + 1))

    while not queue.empty() and len(visited) < max_pages:
        batch = []
        while not queue.empty() and len(batch) < concurrency:
            try:
                item = queue.get_nowait()
                batch.append(item)
            except asyncio.QueueEmpty:
                break

        if not batch:
            break

        await asyncio.gather(*[process(u, d) for u, d in batch])

    # Eliminar duplicados preservando orden
    seen: set[str] = set()
    unique: list[str] = []
    for u in discovered:
        n = _normalize(u)
        if n not in seen:
            seen.add(n)
            unique.append(u)

    return unique
