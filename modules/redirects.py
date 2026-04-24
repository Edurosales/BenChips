"""
modules/redirects.py — Detección de open redirect en parámetros URL.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse, quote

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln
from config import REDIRECT_PARAMS


PAYLOAD = "https://evil.attacker.com"
# Variantes de encoding para bypassear filtros básicos
PAYLOAD_VARIANTS = [
    "https://evil.attacker.com",
    "//evil.attacker.com",
    "https:/%09/evil.attacker.com",
    "https://evil.attacker.com%2F",
    "https://evil.attacker.com%23",
]


async def run(client: AsyncHTTPClient, url: str) -> list[Vuln]:
    """
    Prueba parámetros GET comunes para open redirect.
    """
    vulns: list[Vuln] = []
    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    found_params: set[str] = set()

    async def test_param(param: str):
        for payload in PAYLOAD_VARIANTS:
            if param in found_params:
                return
            test_url = f"{base}/?{param}={quote(payload, safe=':/')}"
            resp = await client.get(test_url, follow=False, lax_ssl=True)

            if not resp:
                continue

            loc = resp.headers.get("location", "")

            if resp.status in (301, 302, 307, 308) and (
                "evil.attacker.com" in loc or payload in loc
            ):
                found_params.add(param)
                vulns.append(make_vuln(
                    title       = f"Open Redirect en parámetro '{param}'",
                    severity    = "HIGH",
                    cvss        = 7.4,
                    category    = "Open Redirect",
                    description = (
                        "El servidor redirige a cualquier URL externa sin validación. "
                        "Útil para phishing: la URL del sitio real es visible en el enlace malicioso."
                    ),
                    evidence    = f"GET /?{param}={payload} → {resp.status} Location: {loc[:100]}",
                    fix         = (
                        f"Validar que '{param}' solo redirige a URLs de tu propio dominio (lista blanca). "
                        "Nunca redirigir a URLs arbitrarias de entrada del usuario."
                    ),
                    ref         = "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                    module      = "redirects",
                ))
                return

    await asyncio.gather(*[test_param(p) for p in REDIRECT_PARAMS])

    return vulns
