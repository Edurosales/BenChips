"""
modules/cache_poisoning.py — Web Cache Poisoning (PortSwigger style).

Detecta unkeyed headers reflected in cached responses:
  1. Identifica si la respuesta es cacheable (Cache-Control public, max-age, Age).
  2. Inyecta payload único en headers candidatos (X-Forwarded-Host, X-Original-URL,
     X-Forwarded-Scheme, etc).
  3. Re-fetch SIN el header inyectado → si el payload aparece, el cache lo guardó.

Esto es la técnica de James Kettle (PortSwigger) https://portswigger.net/research/practical-web-cache-poisoning

Anti-FP:
  - Solo testea endpoints cacheables.
  - Token aleatorio por test.
  - Confirma con segunda petición limpia que el payload está en cache.
"""

from __future__ import annotations

import asyncio
import secrets

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


_UNKEYED_HEADERS = [
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Forwarded-For",
    "X-Host",
    "X-Forwarded-Server",
    "Forwarded",
]


def _is_cacheable(resp) -> tuple[bool, str]:
    """True si la respuesta indica que está siendo cacheada."""
    cc  = resp.headers.get("cache-control", "").lower()
    age = resp.headers.get("age", "")
    x_cache = resp.headers.get("x-cache", "").lower()
    via = resp.headers.get("via", "").lower()

    reasons = []
    if "public" in cc:
        reasons.append("Cache-Control: public")
    if "max-age" in cc and "max-age=0" not in cc:
        reasons.append(cc)
    if age:
        reasons.append(f"Age: {age}")
    if "hit" in x_cache:
        reasons.append(f"X-Cache: {x_cache}")
    if any(x in via for x in ("varnish", "squid", "cloudfront", "fastly")):
        reasons.append(f"Via: {via[:60]}")

    is_cache = len(reasons) > 0 and "no-store" not in cc and "private" not in cc
    return is_cache, " | ".join(reasons)


async def run(client: AsyncHTTPClient, url: str) -> list[Vuln]:
    vulns: list[Vuln] = []

    base = await client.get(url, follow=False, lax_ssl=True, body_limit=65536)
    if not base:
        return vulns

    cacheable, cache_reason = _is_cacheable(base)
    if not cacheable:
        return vulns  # No cacheable → no hay riesgo de poisoning

    sem = asyncio.Semaphore(3)

    async def probe(header: str):
        async with sem:
            token = f"poison-{secrets.token_hex(5)}.evil.test"

            # Inyectar el header con payload
            poisoned = await client.get(
                url,
                follow=False,
                lax_ssl=True,
                extra_headers={header: token},
                body_limit=65536,
            )
            if not poisoned:
                return

            # Si el token aparece en el body de la petición envenenada → primer indicio
            if token not in poisoned.text.lower():
                return

            # Esperar brevemente y refetch SIN el header
            await asyncio.sleep(0.5)
            clean = await client.get(url, follow=False, lax_ssl=True, body_limit=65536)
            if not clean:
                return

            # Si el token persiste en la respuesta limpia, el cache lo guardó
            if token in clean.text.lower():
                vulns.append(make_vuln(
                    title       = f"Cache Poisoning vía header '{header}'",
                    severity    = "HIGH",
                    cvss        = 8.6,
                    category    = "Web Cache Poisoning",
                    description = (
                        f"El header '{header}' es un input no-keyed que el servidor "
                        "refleja en respuestas cacheables. Un atacante puede envenenar "
                        "el cache global con contenido controlado, afectando a todos los "
                        "usuarios que reciban la respuesta cacheada."
                    ),
                    evidence    = (
                        f"Indicios de cache: {cache_reason}\n"
                        f"Header inyectado: {header}: {token}\n"
                        f"Token reflejado en respuesta envenenada: SÍ\n"
                        f"Token persiste en respuesta limpia (refetch sin header): SÍ\n"
                        f"PoC: curl -H '{header}: evil.com' '{url}' ; curl '{url}'"
                    ),
                    fix         = (
                        f"1) Excluir '{header}' del request. "
                        "2) Incluirlo en la cache key si necesario. "
                        "3) Sanitizar el valor antes de usarlo en la respuesta. "
                        "4) Marcar respuestas con datos derivados de headers como private."
                    ),
                    ref         = "https://portswigger.net/research/practical-web-cache-poisoning",
                    module      = "cache_poisoning",
                    url         = url,
                    cwe         = "CWE-444",
                ))

    await asyncio.gather(*[probe(h) for h in _UNKEYED_HEADERS])
    return vulns
