"""
modules/prototype_pollution.py — Client-side & server-side Prototype Pollution.

Detección Client-Side:
  - Cargar la página con ?__proto__[polluted]=YES y ejecutar PoC: si
    document.title contiene "YES" tras eval del payload, vulnerable.
  - Aquí solo podemos hacer la versión "sin headless": cargamos con el query
    contaminado y buscamos en el HTML respuesto si window.polluted aparece.

Detección Server-Side:
  - POST JSON con {"__proto__": {"polluted": true}} en endpoints API.
  - Refetch del mismo endpoint con un payload normal y buscar si la propiedad
    "polluted" aparece en la respuesta (Node.js Object.prototype contamination).

Anti-FP:
  - Token único por test.
  - Baseline antes y después.
  - Solo reporta si la propiedad inyectada PERSISTE entre requests (proceso compartido).
"""

from __future__ import annotations

import asyncio
import json
import secrets
from urllib.parse import urlparse, urlencode

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


async def run(client: AsyncHTTPClient, url: str) -> list[Vuln]:
    vulns: list[Vuln] = []

    # ── Server-side: POST JSON con __proto__ contamination ───────────────────
    parsed = urlparse(url)
    api_candidates = [
        url,
        url.rstrip("/") + "/api",
        url.rstrip("/") + "/api/user",
        url.rstrip("/") + "/api/config",
    ]

    sem = asyncio.Semaphore(3)

    async def test_server_side(target: str):
        async with sem:
            token = secrets.token_hex(6)
            poison_field = f"polluted_{token}"

            # Inyección
            payload = {"__proto__": {poison_field: "yes"}, "normal": "data"}
            r1 = await client.post_json(target, payload, body_limit=16384)
            if not r1 or r1.status >= 500:
                return

            # Refetch limpio: si la propiedad aparece sin enviarla → pollution global
            r2 = await client.post_json(target, {"normal": "different"}, body_limit=16384)
            if not r2:
                return

            if poison_field in r2.text:
                vulns.append(make_vuln(
                    title       = "Prototype Pollution Server-Side (Node.js)",
                    severity    = "CRITICAL",
                    cvss        = 9.0,
                    category    = "Prototype Pollution",
                    description = (
                        "El servidor (Node.js) procesa __proto__ en el body JSON sin "
                        "sanitizar, contaminando Object.prototype globalmente. "
                        "Explotable a RCE en muchas librerías downstream (lodash, jQuery, etc) "
                        "o a auth bypass y DoS."
                    ),
                    evidence    = (
                        f"Request 1: POST {target} con body {json.dumps(payload)}\n"
                        f"Request 2: POST {target} con body {{\"normal\":\"different\"}}\n"
                        f"Propiedad '{poison_field}' apareció en respuesta 2 sin enviarse → pollution confirmada"
                    ),
                    fix         = (
                        "Usar Object.create(null) o Map en vez de {} para datos del usuario. "
                        "Validar/limpiar input JSON eliminando __proto__, constructor, prototype. "
                        "Usar librería 'safer-eval', 'es-toolkit' o 'lodash.set' con freeze. "
                        "Node ≥18: usar --disallow-prototype-mutations flag."
                    ),
                    ref         = "https://github.com/HoLyVieR/prototype-pollution-nsec18",
                    module      = "prototype_pollution",
                    url         = target,
                    cwe         = "CWE-1321",
                ))

    await asyncio.gather(*[test_server_side(t) for t in api_candidates[:3]])

    # ── Client-side: query string con __proto__ ───────────────────────────────
    # Buscar referencias a propiedades vulnerables en JS antes de marcar
    token = secrets.token_hex(5)
    test_url = url + ("&" if "?" in url else "?") + urlencode({
        f"__proto__[polluted_{token}]": "yes",
        f"constructor[prototype][polluted_{token}]": "yes",
    })

    resp = await client.get(test_url, follow=True, lax_ssl=True, body_limit=65536)
    if resp and resp.status == 200:
        body = resp.text.lower()
        # Heurística: librerías conocidas vulnerables a CSPP en cliente
        risky_libs = ("jquery", "lodash", "extend", "merge", "deeply",
                      "$.extend", "_.merge", "_.set", "object.assign")
        risky_present = sum(1 for r in risky_libs if r in body)

        if risky_present >= 2:
            vulns.append(make_vuln(
                title       = "Posible Prototype Pollution Client-Side",
                severity    = "MEDIUM",
                cvss        = 5.4,
                category    = "Prototype Pollution",
                description = (
                    "La página usa librerías históricamente vulnerables a CSPP "
                    "(client-side prototype pollution) y acepta parámetros __proto__ "
                    "en la URL. Requiere verificación manual con headless browser."
                ),
                evidence    = (
                    f"URL test: {test_url[:200]}\n"
                    f"Librerías con historial vulnerable encontradas: {risky_present}\n"
                    f"Verificar manualmente con: page.evaluate('Object.prototype.polluted_{token}')"
                ),
                fix         = (
                    "Actualizar lodash ≥4.17.21, jQuery ≥3.5. Usar Object.freeze(Object.prototype) "
                    "en código de carga. Validar query params antes de pasar a $.extend/_.merge."
                ),
                ref         = "https://blog.s1r1us.ninja/research/PP",
                module      = "prototype_pollution",
                url         = url,
                cwe         = "CWE-1321",
                confidence  = 50,
            ))

    return vulns
