"""
utils/crawler.py — Crawler dual: HTTP ligero + Playwright SPA.

- crawl()     : HTTP async, extrae href/action/src + inline JS patterns. Siempre disponible.
- crawl_spa() : Playwright headless, captura XHR/fetch en runtime + SPA routes vía navegación.
                Requiere: pip install playwright && playwright install chromium
                Retorna URLs adicionales que el HTTP crawler no ve (SPAs, lazy routes).
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


# ─── SPA Crawler (Playwright) ─────────────────────────────────────────────────

async def crawl_spa(
    start_url:    str,
    max_pages:    int = 25,
    timeout_ms:   int = 12_000,
    stealth:      bool = False,
) -> list[str]:
    """
    Crawl de SPA con Playwright headless — captura rutas JS y llamadas XHR/fetch
    que el crawler HTTP no puede ver.

    Requiere: pip install playwright && playwright install chromium

    Returns:
        Lista de URLs únicas descubiertas (mismo hostname), vacía si Playwright no disponible.
    """
    try:
        from playwright.async_api import async_playwright, TimeoutError as PWTimeout
    except ImportError:
        return []

    base_hostname = urlparse(start_url).hostname or ""
    discovered:   set[str] = set()
    api_captured: set[str] = set()

    _UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox"],
            )
            ctx = await browser.new_context(
                user_agent            = _UA,
                ignore_https_errors   = True,
                java_script_enabled   = True,
                bypass_csp            = True,   # necesario para ver contenido detrás de strict CSP
                viewport              = {"width": 1280, "height": 800},
            )

            # Interceptar TODAS las peticiones de red para capturar endpoints de API
            def on_request(req):
                u = req.url
                if _same_scope(u, base_hostname) and not _is_static(u):
                    api_captured.add(_normalize(u))

            ctx.on("request", on_request)

            page = await ctx.new_page()

            to_visit: list[str] = [start_url]
            visited_spa: set[str] = set()

            for target_url in to_visit:
                if len(visited_spa) >= max_pages:
                    break
                norm = _normalize(target_url)
                if norm in visited_spa:
                    continue
                visited_spa.add(norm)

                try:
                    await page.goto(
                        target_url,
                        wait_until = "networkidle",
                        timeout    = timeout_ms,
                    )
                    # Extra wait para renders lentos
                    await page.wait_for_timeout(800)
                except PWTimeout:
                    # networkidle timeout — seguimos con lo que haya cargado
                    try:
                        await page.wait_for_load_state("domcontentloaded", timeout=3000)
                    except Exception:
                        pass
                except Exception:
                    continue

                # URL actual tras SPA routing (puede diferir de target_url)
                current = page.url
                if current and _same_scope(current, base_hostname):
                    discovered.add(current)
                    visited_spa.add(_normalize(current))

                # ── Extraer links del DOM renderizado ──────────────────────
                try:
                    links = await page.evaluate("""
                        () => {
                            const urls = new Set();
                            document.querySelectorAll('a[href], area[href]').forEach(el => {
                                if (el.href) urls.add(el.href);
                            });
                            document.querySelectorAll('[data-href],[data-url],[data-link]').forEach(el => {
                                const v = el.dataset.href || el.dataset.url || el.dataset.link;
                                if (v) urls.add(new URL(v, location.href).href);
                            });
                            // React Router / Angular RouterLink style hrefs
                            document.querySelectorAll('[routerlink],[ng-href]').forEach(el => {
                                const v = el.getAttribute('routerlink') || el.getAttribute('ng-href');
                                if (v) urls.add(new URL(v, location.href).href);
                            });
                            return [...urls];
                        }
                    """)
                    for link in (links or []):
                        if _same_scope(link, base_hostname) and not _is_static(link):
                            norm_link = _normalize(link)
                            if norm_link not in visited_spa:
                                to_visit.append(link)
                                discovered.add(link)
                except Exception:
                    pass

                # ── Clicar nav links para activar rutas SPA ────────────────
                try:
                    nav_els = await page.query_selector_all(
                        "nav a, [role='navigation'] a, header a, .navbar a, .menu a, "
                        ".sidebar a, [class*='nav'] a, [class*='menu'] a"
                    )
                    for el in nav_els[:12]:
                        try:
                            href = await el.get_attribute("href")
                            if href and not href.startswith(("#", "javascript:", "mailto:")):
                                full = urljoin(current, href)
                                if _same_scope(full, base_hostname):
                                    norm_nav = _normalize(full)
                                    if norm_nav not in visited_spa:
                                        to_visit.append(full)
                        except Exception:
                            continue
                except Exception:
                    pass

            await browser.close()

    except Exception:
        return []

    # Unir URLs de navegación + endpoints de API capturados vía red
    all_found = discovered | api_captured
    unique: list[str] = []
    seen: set[str] = set()
    for u in all_found:
        n = _normalize(u)
        if n not in seen and _same_scope(u, base_hostname) and not _is_static(u):
            seen.add(n)
            unique.append(u)

    return unique
