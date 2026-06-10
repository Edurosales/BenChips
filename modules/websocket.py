"""
modules/websocket.py — WebSocket security testing (CSWSH).

Detecta WebSockets accesibles desde cualquier Origin (Cross-Site WebSocket
Hijacking — CSWSH).

Estrategia:
  1. Parsear HTML buscando new WebSocket(...) o socket.io connect string
  2. Conectar al WS endpoint con Origin: https://evil.com
  3. Si conecta exitosamente → falta origin check.
"""

from __future__ import annotations

import asyncio
import re
import secrets
from urllib.parse import urlparse, urljoin

import aiohttp

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


_WS_PATTERNS = [
    re.compile(r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'io\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),  # socket.io
    re.compile(r'ws://([^"\'\s]+)', re.IGNORECASE),
    re.compile(r'wss://([^"\'\s]+)', re.IGNORECASE),
]

# Endpoints típicos
_DEFAULT_WS_PATHS = [
    "/ws", "/websocket", "/socket.io/", "/api/ws", "/notifications",
    "/api/socket", "/echo",
]


def _to_ws(url: str) -> str:
    """http → ws, https → wss"""
    if url.startswith("https://"):
        return "wss://" + url[8:]
    if url.startswith("http://"):
        return "ws://" + url[7:]
    return url


async def run(client: AsyncHTTPClient, url: str) -> list[Vuln]:
    vulns: list[Vuln] = []

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    # ── 1) Localizar WS endpoints en HTML ────────────────────────────────────
    page = await client.get(url, body_limit=131072)
    if not page:
        return vulns

    found_ws: set[str] = set()
    for pat in _WS_PATTERNS:
        for m in pat.finditer(page.text):
            ws_url = m.group(1) if "://" in m.group(0) else m.group(0)
            if not ws_url.startswith(("ws://", "wss://", "http://", "https://", "/")):
                continue
            if ws_url.startswith("/"):
                ws_url = base + ws_url
            ws_url = _to_ws(ws_url)
            found_ws.add(ws_url.split("?")[0])

    # Si no encontramos nada en HTML, probar paths default
    if not found_ws:
        for p in _DEFAULT_WS_PATHS:
            found_ws.add(_to_ws(base.rstrip("/") + p))

    session = client.session
    if not session:
        return vulns

    sem = asyncio.Semaphore(2)
    tested: set[str] = set()

    async def test_ws(ws_url: str):
        async with sem:
            if ws_url in tested:
                return
            tested.add(ws_url)

            evil_origin = f"https://evil-{secrets.token_hex(4)}.attacker-test.com"
            try:
                async with session.ws_connect(
                    ws_url,
                    headers={"Origin": evil_origin},
                    ssl=False,
                    timeout=aiohttp.ClientWSTimeout(ws_close=5.0),
                    autoping=False,
                ) as ws:
                    # Conexión exitosa con Origin evil → CSWSH
                    vulns.append(make_vuln(
                        title       = f"CSWSH: WebSocket sin origin check ({ws_url})",
                        severity    = "HIGH",
                        cvss        = 8.1,
                        category    = "Cross-Site WebSocket Hijacking",
                        description = (
                            "El servidor WebSocket aceptó conexión desde origen arbitrario "
                            "sin validación. Un sitio malicioso puede establecer un WS desde "
                            "el navegador de la víctima (con sus cookies) y enviar/recibir "
                            "mensajes en su nombre."
                        ),
                        evidence    = (
                            f"WS URL: {ws_url}\n"
                            f"Origin enviado: {evil_origin}\n"
                            f"Conexión: ESTABLECIDA (handshake exitoso)"
                        ),
                        fix         = (
                            "Validar el header Origin contra whitelist en el WS handshake. "
                            "En Node socket.io: io.use((s,n) => check s.handshake.headers.origin). "
                            "En Flask-SocketIO: cors_allowed_origins=whitelist. "
                            "Adicionalmente: implementar CSRF token en mensajes WS."
                        ),
                        ref         = "https://christian-schneider.net/CrossSiteWebSocketHijacking.html",
                        module      = "websocket",
                        url         = ws_url,
                        cwe         = "CWE-352",
                    ))
                    await ws.close()
            except Exception:
                # Fallo en handshake → o servidor correcto, o WS no responde aquí
                pass

    await asyncio.gather(*[test_ws(u) for u in list(found_ws)[:5]])
    return vulns
