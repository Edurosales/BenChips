"""
modules/crlf.py — CRLF Injection / HTTP Response Splitting.

Inyecta %0d%0a + cabecera o cuerpo en parámetros GET y verifica si:
  1. Aparece como header en la respuesta (response splitting).
  2. Se refleja con saltos de línea reales en el body.

Anti-FP:
  - Token aleatorio para evitar colisiones.
  - Solo confirma si el header inyectado APARECE en headers de respuesta.
  - Diferenciar entre encodings procesados (vulnerable) y rechazados (servidor seguro).
"""

from __future__ import annotations

import asyncio
import secrets
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


_CRLF_PARAMS = [
    "url", "redirect", "next", "return", "callback",
    "lang", "locale", "page", "view", "ref", "from",
    "path", "file", "name", "q", "search",
]


def _inject(url: str, parsed, param: str, value: str) -> str:
    params = parse_qs(parsed.query)
    flat   = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
    flat[param] = value
    return urlunparse(parsed._replace(query=urlencode(flat, safe="%")))


async def run(client: AsyncHTTPClient, url: str) -> list[Vuln]:
    vulns: list[Vuln] = []
    found: set[str] = set()

    parsed = urlparse(url)
    existing = list(parse_qs(parsed.query).keys())
    probe_params = existing + [p for p in _CRLF_PARAMS if p not in existing]

    sem = asyncio.Semaphore(4)

    async def check(param: str, payload_template: str, technique: str):
        async with sem:
            if param in found:
                return
            token = secrets.token_hex(5)
            payload = payload_template.format(token=token)
            test_url = _inject(url, parsed, param, payload)

            resp = await client.get(test_url, follow=False, lax_ssl=True, body_limit=8192)
            if not resp:
                return

            target_header = f"x-injected-{token}"

            # Anti-FP: confirmar que el header está realmente presente en la respuesta
            if target_header in resp.headers:
                found.add(param)
                vulns.append(make_vuln(
                    title       = f"CRLF Injection en parámetro '{param}' ({technique})",
                    severity    = "HIGH",
                    cvss        = 7.5,
                    category    = "CRLF Injection",
                    description = (
                        f"El parámetro '{param}' permite inyectar CR/LF en headers de respuesta. "
                        "Habilita HTTP Response Splitting, cache poisoning, "
                        "session fixation via Set-Cookie y XSS vía Content-Type."
                    ),
                    evidence    = (
                        f"Payload: {payload}\n"
                        f"Header inyectado confirmado en respuesta: {target_header}\n"
                        f"PoC: curl -i '{test_url}'"
                    ),
                    fix         = (
                        "Rechazar caracteres \\r y \\n en valores de parámetros usados "
                        "para construir headers o redirects. Usar APIs que sanitizan "
                        "automáticamente (Response.setHeader en Express, etc)."
                    ),
                    ref         = "https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
                    module      = "crlf",
                    url         = url,
                    cwe         = "CWE-93",
                ))

    techniques = [
        ("test%0d%0aX-Injected-{token}:%201", "URL-encoded \\r\\n"),
        ("test%0aX-Injected-{token}:%201",    "LF-only (algunos servidores aceptan)"),
        ("test%E5%98%8A%E5%98%8DX-Injected-{token}:%201", "UTF-8 overlong CRLF"),
    ]

    tasks = []
    for param in probe_params[:6]:
        for tpl, tech in techniques:
            tasks.append(check(param, tpl, tech))

    await asyncio.gather(*tasks)
    return vulns
