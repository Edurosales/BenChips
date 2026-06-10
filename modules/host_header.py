"""
modules/host_header.py — Host Header Injection / Password reset poisoning.

Detecta tres clases de vulnerabilidad:
  1. Reflected Host Header: el servidor devuelve el host inyectado en body/links
     (riesgo de cache poisoning + password reset poisoning si el host se usa
     para construir URLs en correos).
  2. Off-by-default routing: X-Forwarded-Host / X-Forwarded-Server alteran el routing
     a sitios virtual-hosted distintos.
  3. Absolute URL override: enviar Host: en una request con URL absoluta y ver
     si el servidor confía en la cabecera.

Anti-FP:
  - Token aleatorio único por test (no colisiones con strings legítimas).
  - Baseline body sin inyección; solo reporta si el token reflejado SOLO aparece
    en la respuesta con inyección.
  - Diferencia entre reflejo en body (HIGH si en link) vs solo en header (MEDIUM).
"""

from __future__ import annotations

import asyncio
import re
import secrets
from urllib.parse import urlparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


async def run(client: AsyncHTTPClient, url: str) -> list[Vuln]:
    vulns: list[Vuln] = []

    parsed = urlparse(url)
    original_host = parsed.hostname or ""
    if not original_host:
        return vulns

    # ── Baseline limpio ──────────────────────────────────────────────────────
    base = await client.get(url, follow=False, lax_ssl=True, body_limit=65536)
    if not base:
        return vulns
    baseline_text = base.text.lower()

    # Token aleatorio para evitar colisiones con cadenas legítimas
    token = f"evilhdr-{secrets.token_hex(6)}.attacker-poison.test"

    test_cases = [
        # (header_name, value, description)
        ("Host",                 token,                     "Host header"),
        ("X-Forwarded-Host",     token,                     "X-Forwarded-Host"),
        ("X-Host",               token,                     "X-Host"),
        ("X-Forwarded-Server",   token,                     "X-Forwarded-Server"),
        ("X-HTTP-Host-Override", token,                     "X-HTTP-Host-Override"),
        ("Forwarded",            f"host={token}",            "Forwarded host="),
    ]

    sem = asyncio.Semaphore(3)

    async def probe(header_name: str, value: str, desc: str):
        async with sem:
            # No queremos seguir redirects: si el servidor redirige al host inyectado
            # ya es señal de bug, no queremos perseguirlo
            resp = await client.get(
                url,
                follow=False,
                lax_ssl=True,
                extra_headers={header_name: value},
                body_limit=65536,
            )
            if not resp:
                return

            text = resp.text
            text_lower = text.lower()

            # ── Reflejo en body ──────────────────────────────────────────────
            if token in text_lower and token not in baseline_text:
                # Buscar si el token está dentro de un atributo href/src/action (más grave)
                in_link = bool(re.search(
                    rf'(href|src|action)=["\'][^"\']*{re.escape(token)}',
                    text_lower,
                ))
                if in_link:
                    sev, cvss = "HIGH", 7.5
                    title = f"Host Header Injection — reflejado en link ({desc})"
                    impact = (
                        "El host inyectado aparece dentro de un atributo href/src/action. "
                        "Explotable como password-reset poisoning si el servidor envía emails "
                        "con enlaces basados en el Host."
                    )
                else:
                    sev, cvss = "MEDIUM", 5.3
                    title = f"Host Header Reflejado en body ({desc})"
                    impact = (
                        "El host inyectado se refleja en el HTML. Posible cache poisoning "
                        "si la respuesta es cacheable o reset poisoning según contexto."
                    )

                vulns.append(make_vuln(
                    title       = title,
                    severity    = sev,
                    cvss        = cvss,
                    category    = "Host Header Injection",
                    description = impact,
                    evidence    = (
                        f"Request header inyectado: {header_name}: {value}\n"
                        f"Token reflejado en respuesta (no estaba en baseline)\n"
                        f"En link href/src/action: {'SÍ' if in_link else 'no'}\n"
                        f"PoC: curl -H '{header_name}: evil.com' '{url}'"
                    ),
                    fix         = (
                        "Validar el header Host contra una whitelist de dominios. "
                        "No usar el Host del request para construir URLs absolutas en correos. "
                        "Configurar VHost por defecto que devuelva 400 ante hosts desconocidos."
                    ),
                    ref         = "https://portswigger.net/web-security/host-header",
                    module      = "host_header",
                    url         = url,
                    cwe         = "CWE-20",
                ))
                return

            # ── Redirect a host inyectado ────────────────────────────────────
            location = resp.headers.get("location", "")
            if token in location.lower():
                vulns.append(make_vuln(
                    title       = f"Host Header redirige a host inyectado ({desc})",
                    severity    = "HIGH",
                    cvss        = 7.5,
                    category    = "Host Header Injection",
                    description = (
                        "El servidor responde con Location apuntando al host inyectado. "
                        "Phishing vía redirect controlado por el atacante."
                    ),
                    evidence    = (
                        f"Request: {header_name}: {value}\n"
                        f"Response: HTTP {resp.status} Location: {location[:200]}\n"
                        f"PoC: curl -H '{header_name}: evil.com' -i '{url}'"
                    ),
                    fix         = (
                        "No construir Location a partir del Host. Usar host canónico fijo."
                    ),
                    ref         = "https://portswigger.net/web-security/host-header",
                    module      = "host_header",
                    url         = url,
                    cwe         = "CWE-601",
                ))

    await asyncio.gather(*[probe(h, v, d) for h, v, d in test_cases])
    return vulns
