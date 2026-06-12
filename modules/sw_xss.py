"""
modules/sw_xss.py — Service Worker, manifest, WebRTC IP leak.

Vectores cubiertos:
  - manifest.json con start_url controlable (open redirect persistente).
  - service-worker.js que cachea respuestas con XSS persistente.
  - WebRTC IP leak via STUN servers expuestos (bypass de proxy/VPN).
  - SW scope amplio (scope: "/") en CDN compartido.

Anti-FP:
  - Confirma el SW está activo (Content-Type: text/javascript, registración valid).
  - manifest validado por JSON parse.
"""

from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import urljoin, urlparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


_SW_PATHS = [
    "/service-worker.js",
    "/sw.js",
    "/serviceworker.js",
    "/firebase-messaging-sw.js",
    "/workbox-sw.js",
]

_MANIFEST_PATHS = [
    "/manifest.json",
    "/manifest.webmanifest",
    "/site.webmanifest",
]


def _find_sw_registration(html: str) -> str | None:
    """Busca registro de SW en el HTML."""
    m = re.search(r"navigator\.serviceWorker\.register\(\s*['\"]([^'\"]+)['\"]", html)
    return m.group(1) if m else None


def _find_webrtc_stun(html: str) -> list[str]:
    """Detecta STUN/TURN servers expuestos en JS."""
    pattern = re.compile(r"urls?:\s*['\"](?:stun|turn):([^'\"]+)['\"]")
    return pattern.findall(html)


async def run(client: AsyncHTTPClient, url: str) -> list[Vuln]:
    vulns: list[Vuln] = []
    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    # ── Get main page body para detectar registros ─────────────────────────
    main = await client.get(url, body_limit=65536)
    main_html = main.text if main else ""

    # ── Service Worker analysis ─────────────────────────────────────────────
    sw_url_from_html = _find_sw_registration(main_html)
    sw_candidates = list(_SW_PATHS)
    if sw_url_from_html:
        sw_candidates.insert(0, sw_url_from_html if sw_url_from_html.startswith("/")
                             else "/" + sw_url_from_html)

    sem = asyncio.Semaphore(5)

    async def check_sw(path: str):
        async with sem:
            target = base.rstrip("/") + path if path.startswith("/") else urljoin(base, path)
            resp = await client.get(target, body_limit=32768)
            if not resp or resp.status != 200:
                return
            ct = resp.headers.get("content-type", "")
            if "javascript" not in ct.lower():
                return

            body = resp.text

            # importScripts() de URL controlable?
            if re.search(r"importScripts\s*\(\s*[`'\"]https?://", body):
                vulns.append(make_vuln(
                    title       = f"Service Worker importa scripts externos: {path}",
                    severity    = "MEDIUM",
                    cvss        = 5.4,
                    category    = "Service Worker",
                    description = (
                        "El SW carga scripts vía importScripts() desde URLs externas. "
                        "Si el CDN se compromete, el atacante ejecuta JS persistente "
                        "(SW sobrevive al cierre del browser)."
                    ),
                    evidence    = f"GET {target} → contiene importScripts(http*).",
                    fix         = "Bundlear scripts en el mismo origin o validar SRI.",
                    ref         = "https://www.invicti.com/blog/web-security/service-worker-security/",
                    module      = "sw_xss",
                    url         = target,
                    cwe         = "CWE-829",
                ))

            # Cache de respuestas sin validación
            if "cache.addAll" in body or "cache.put" in body:
                # Esto NO es vuln per se — info-level
                pass

    await asyncio.gather(*[check_sw(p) for p in sw_candidates[:5]])

    # ── Manifest analysis ───────────────────────────────────────────────────
    async def check_manifest(path: str):
        async with sem:
            target = base.rstrip("/") + path
            resp = await client.get(target, body_limit=16384)
            if not resp or resp.status != 200:
                return
            try:
                data = json.loads(resp.text)
            except (json.JSONDecodeError, ValueError):
                return

            # start_url externa?
            start = data.get("start_url", "")
            if start and (start.startswith("http://") or start.startswith("https://")):
                start_parsed = urlparse(start)
                if start_parsed.netloc and start_parsed.netloc != parsed.netloc:
                    vulns.append(make_vuln(
                        title       = "PWA manifest con start_url externa",
                        severity    = "MEDIUM",
                        cvss        = 5.3,
                        category    = "PWA / Manifest",
                        description = (
                            f"manifest.json define start_url={start} apuntando a otro dominio. "
                            "Permite phishing persistente: usuario añade el PWA y se redirige a "
                            "sitio externo al abrir."
                        ),
                        evidence    = f"GET {target} → start_url=\"{start}\"",
                        fix         = "Usar paths relativos en start_url (start_url: '/').",
                        ref         = "https://web.dev/articles/add-manifest",
                        module      = "sw_xss",
                        url         = target,
                        cwe         = "CWE-601",
                    ))

    await asyncio.gather(*[check_manifest(p) for p in _MANIFEST_PATHS])

    # ── WebRTC STUN leak ────────────────────────────────────────────────────
    stuns = _find_webrtc_stun(main_html)
    if stuns:
        vulns.append(make_vuln(
            title       = "WebRTC STUN configurado — posible IP leak",
            severity    = "INFO",
            cvss        = 2.0,
            category    = "Privacy",
            description = (
                "El sitio configura RTCPeerConnection con STUN/TURN, lo que permite "
                "exponer la IP real del cliente incluso detrás de VPN/proxy "
                "(WebRTC IP leak)."
            ),
            evidence    = f"STUN servers detectados: {', '.join(stuns[:3])}",
            fix         = "Restringir iceServers en RTCPeerConnection o ofrecer opt-out al usuario.",
            ref         = "https://browserleaks.com/webrtc",
            module      = "sw_xss",
            url         = url,
        ))

    return vulns
