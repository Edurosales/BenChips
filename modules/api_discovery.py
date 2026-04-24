"""
modules/api_discovery.py — Descubrimiento de endpoints, APIs y URLs internas.
Analiza JS, HTML, fetch/axios calls, hrefs y atributos data-.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse, urljoin

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


# ─── Patrones de extracción ────────────────────────────────────────────────────

# URLs en fetch()/axios/XMLHttpRequest/jQuery.ajax
FETCH_PATTERNS = [
    r"""fetch\s*\(\s*['"`]([^'"`\s]{3,200})['"`]""",
    r"""axios\.\w+\s*\(\s*['"`]([^'"`\s]{3,200})['"`]""",
    r"""XMLHttpRequest[^;]*open\s*\([^,]+,\s*['"`]([^'"`\s]{3,200})['"`]""",
    r"""\$\.(?:get|post|ajax|getJSON)\s*\(\s*['"`]([^'"`\s]{3,200})['"`]""",
    r"""url\s*:\s*['"`]([^'"`\s]{3,200})['"`]""",
    r"""['"`](/(?:api|v\d|graphql|rest|rpc|service|ws|socket)[^'"`\s]{0,150})['"`]""",
]

# Atributos HTML con URLs
HTML_ATTR_PATTERNS = [
    r"""<a[^>]+href=['"]([^'"#\s]{3,200})['"]""",
    r"""<form[^>]+action=['"]([^'"#\s]{3,200})['"]""",
    r"""<script[^>]+src=['"]([^'"#\s]{3,200})['"]""",
    r"""<link[^>]+href=['"]([^'"#\s]{3,200})['"]""",
    r"""data-url=['"]([^'"#\s]{3,200})['"]""",
    r"""data-api=['"]([^'"#\s]{3,200})['"]""",
    r"""data-endpoint=['"]([^'"#\s]{3,200})['"]""",
    r"""data-src=['"]([^'"#\s]{3,200})['"]""",
]

# Rutas que sugieren API
API_INDICATORS = [
    "/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql",
    "/rpc/", "/service/", "/ws/", "/socket/", "/endpoint",
    ".json", ".xml", "/auth/", "/oauth/", "/token",
]


def _is_interesting(url_str: str, base_hostname: str) -> bool:
    """Filtra URLs útiles (no imágenes, fonts, etc.)."""
    LOW_VALUE = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff",
                 ".woff2", ".ttf", ".eot", ".svg", ".css", ".map")
    if any(url_str.lower().endswith(e) for e in LOW_VALUE):
        return False
    if url_str.startswith(("data:", "javascript:", "mailto:", "tel:", "#")):
        return False
    return True


def _normalize_url(href: str, base_url: str, base_hostname: str) -> str | None:
    """Convierte hrefs relativos a absolutos y filtra externos si no son API."""
    try:
        full = urljoin(base_url, href)
        parsed = urlparse(full)
        # Incluir: misma hostname o APIs externas conocidas
        if parsed.hostname == base_hostname:
            return full
        # APIs externas interesantes
        if any(ind in full for ind in API_INDICATORS):
            return full
        return None
    except Exception:
        return None


async def run(
    client:    AsyncHTTPClient,
    url:       str,
    body:      str | None = None,
    max_js:    int = 5,
) -> tuple[list[Vuln], list[dict]]:
    """
    Extrae endpoints/APIs del HTML y scripts JS principales.
    Retorna (vulns, endpoints_list).
    """
    vulns:     list[Vuln]  = []
    endpoints: list[dict]  = []
    seen:      set[str]    = set()

    parsed        = urlparse(url)
    base_hostname = parsed.hostname or ""
    base_url      = f"{parsed.scheme}://{parsed.netloc}"

    def extract_urls(text: str, source: str) -> list[dict]:
        found = []
        # Fetch/API call patterns
        for pat in FETCH_PATTERNS:
            for m in re.finditer(pat, text, re.IGNORECASE):
                href = m.group(1).strip()
                if not _is_interesting(href, base_hostname):
                    continue
                norm = _normalize_url(href, url, base_hostname)
                if norm and norm not in seen:
                    seen.add(norm)
                    is_api = any(ind in norm for ind in API_INDICATORS)
                    found.append({"url": norm, "source": source, "type": "api" if is_api else "fetch"})
        # HTML attributes
        for pat in HTML_ATTR_PATTERNS:
            for m in re.finditer(pat, text, re.IGNORECASE):
                href = m.group(1).strip()
                if not _is_interesting(href, base_hostname):
                    continue
                norm = _normalize_url(href, url, base_hostname)
                if norm and norm not in seen:
                    seen.add(norm)
                    is_api = any(ind in norm for ind in API_INDICATORS)
                    found.append({"url": norm, "source": source, "type": "api" if is_api else "link"})
        return found

    # ── Analizar HTML principal ────────────────────────────────────────────────
    if body is None:
        resp = await client.get(url, follow=True, lax_ssl=True, body_limit=524288)
        body = resp.text if resp else ""

    html_endpoints = extract_urls(body, "HTML principal")
    endpoints.extend(html_endpoints)

    # ── Encontrar scripts JS referenciados y analizarlos ─────────────────────
    js_srcs = re.findall(r'<script[^>]+src=[\'"]([^\'"]{3,200})[\'"]', body, re.IGNORECASE)
    js_srcs = [s for s in js_srcs if not s.endswith(".map")]

    async def fetch_js(src: str):
        js_url = urljoin(url, src)
        if urlparse(js_url).hostname != base_hostname:
            return  # Solo JS propio
        resp = await client.get(js_url, follow=True, lax_ssl=True, body_limit=524288)
        if resp and resp.text:
            js_found = extract_urls(resp.text, f"JS: {src[:50]}")
            endpoints.extend(js_found)

    await asyncio.gather(*[fetch_js(s) for s in js_srcs[:max_js]])

    # ── Generar vulns si hay endpoints sensibles expuestos ────────────────────
    api_endpoints = [e for e in endpoints if e["type"] == "api"]
    if api_endpoints:
        sample = "\n".join(f"  • {e['url']}" for e in api_endpoints[:10])
        vulns.append(make_vuln(
            title       = f"Endpoints de API expuestos/detectados ({len(api_endpoints)})",
            severity    = "INFO",
            cvss        = 0.0,
            category    = "API Discovery",
            description = "Se detectaron endpoints de API en el código JS/HTML. Verificar que no expongan datos sin autenticación.",
            evidence    = sample,
            fix         = "Asegurar autenticación en todos los endpoints. Implementar rate limiting y revisar si alguno expone datos sensibles.",
            ref         = "https://owasp.org/www-project-api-security/",
            module      = "api_discovery",
        ))

    # Deduplicar y ordenar
    seen_urls = set()
    unique = []
    for e in endpoints:
        if e["url"] not in seen_urls:
            seen_urls.add(e["url"])
            unique.append(e)
    unique.sort(key=lambda x: (x["type"] != "api", x["url"]))

    return vulns, unique
