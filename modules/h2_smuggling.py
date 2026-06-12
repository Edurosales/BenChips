"""
modules/h2_smuggling.py — HTTP/2 specific request smuggling.

Vectores:
  - H2.CL: CL header en stream H2 (HTTP/2 no debería usar CL).
  - H2.TE: Transfer-Encoding en H2 (prohibido por RFC 7540 §8.1.2.2).
  - h2c upgrade hijack (cleartext H2 sobre H1).
  - CRLF en HPACK (header injection vía codificación huffman).

Detección no-invasiva:
  - Identifica si el server soporta H2 (ALPN + h2c upgrade).
  - Envía un single H2 request con TE header y verifica si se acepta
    (debería ser rechazado por server compliant).

Requiere: pip install httpx[http2]  (httpx soporta h2 nativo).
Si httpx[http2] no está, se omite.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from utils.vuln import Vuln, make_vuln


def _has_h2() -> bool:
    try:
        import httpx  # noqa: F401
        import h2     # noqa: F401
        return True
    except ImportError:
        return False


async def run(client, url: str, full_scan: bool = False) -> list[Vuln]:
    vulns: list[Vuln] = []
    if not full_scan or not _has_h2():
        return vulns

    import httpx  # type: ignore

    parsed = urlparse(url)
    if parsed.scheme != "https":
        return vulns  # H2 cleartext es raro en producción

    try:
        async with httpx.AsyncClient(http2=True, verify=False, timeout=10) as h2c:
            # ── 1. Probe H2 support via ALPN ────────────────────────────────
            r = await h2c.get(url)
            http_ver = r.http_version  # "HTTP/2" o "HTTP/1.1"

            if http_ver != "HTTP/2":
                return vulns  # No soporta H2, no aplica

            # ── 2. TE header en H2 (debería rechazarse) ─────────────────────
            try:
                r_te = await h2c.request(
                    "POST", url,
                    headers={"Transfer-Encoding": "chunked"},
                    content=b"0\r\n\r\n",
                )
                if r_te.status_code < 400:
                    vulns.append(make_vuln(
                        title       = "HTTP/2 acepta Transfer-Encoding (prohibido por RFC 7540)",
                        severity    = "MEDIUM",
                        cvss        = 5.3,
                        category    = "Request Smuggling",
                        description = (
                            "El servidor procesa el header Transfer-Encoding dentro de un "
                            "stream HTTP/2. RFC 7540 §8.1.2.2 lo prohíbe — su presencia indica "
                            "una capa intermedia (LB / WAF) que potencialmente downgrade-a-H1 "
                            "el request, abriendo H2.TE smuggling."
                        ),
                        evidence    = f"H2 POST con TE:chunked → {r_te.status_code}",
                        fix         = "El frontend H2 debe striprear TE antes del backend. "
                                      "Si hay downgrade H2→H1, reescribir CL/TE en el proxy.",
                        ref         = "https://portswigger.net/research/http2",
                        module      = "h2_smuggling",
                        url         = url,
                        cwe         = "CWE-444",
                    ))
            except Exception:
                pass

            # ── 3. Content-Length en H2 (no necesario, suspect) ─────────────
            # No reportamos esto como vuln — H2 sí permite CL en algunos casos.

            # ── 4. h2c upgrade desde H1 sin re-handshake ───────────────────
            # Difícil de probar genéricamente. Solo info.
    except Exception:
        return vulns

    return vulns
