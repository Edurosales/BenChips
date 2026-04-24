"""
modules/http_methods.py — Detección de métodos HTTP peligrosos habilitados.
"""

from __future__ import annotations

import asyncio

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln
from config import DANGEROUS_METHODS


async def run(client: AsyncHTTPClient, url: str) -> list[Vuln]:
    """
    Prueba métodos HTTP peligrosos y verifica cuáles están habilitados.
    """
    vulns: list[Vuln] = []

    # ── OPTIONS primero — nos da la lista completa ─────────────────────────────
    allowed_header_methods: set[str] = set()
    resp_options = await client.request("OPTIONS", url, follow=False, lax_ssl=True)
    if resp_options and resp_options.status < 405:
        allow = resp_options.headers.get("allow", "")
        allowed_header_methods = {m.strip().upper() for m in allow.split(",")}

    # ── Probar cada método peligroso ───────────────────────────────────────────
    async def check_method(method: str, sev: str, cvss: float, desc: str):
        resp = await client.request(method, url, follow=False, lax_ssl=True)
        if resp is None:
            return None

        # ── Confirmar que el método está REALMENTE habilitado ──────────────────
        # 400 = bad request / method not understood  → NO habilitado
        # 401/403 = requiere auth pero existe        → habilitado (potencial)
        # 404 = recurso no existe pero método ok     → habilitado (potencial)
        # 405 = Method Not Allowed                   → NO habilitado
        # 501 = Not Implemented                      → NO habilitado
        REJECTED = {400, 405, 501, 505}
        if resp.status in REJECTED:
            # Aun puede estar en el Allow header
            if method in allowed_header_methods:
                return make_vuln(
                    title       = f"Método {method} listado en Allow header",
                    severity    = "LOW" if sev == "MEDIUM" else sev,
                    cvss        = max(cvss - 2.0, 0.0),
                    category    = "HTTP Methods",
                    description = f"{desc} (aparece en Allow header aunque el servidor lo rechace devolviendo {resp.status})",
                    evidence    = f"Allow: {resp_options.headers.get('allow','?') if resp_options else '?'}",
                    fix         = f"Eliminar {method} del header Allow y deshabilitar en el servidor.",
                    module      = "http_methods",
                )
            return None

        # Método aceptado (200–399 o 401/403/404 indican que el servidor procesó el método)
        return make_vuln(
            title       = f"Método HTTP habilitado: {method}",
            severity    = sev,
            cvss        = cvss,
            category    = "HTTP Methods",
            description = desc,
            evidence    = f"{method} {url} → HTTP {resp.status}",
            fix         = (
                f"Deshabilitar {method} si no es necesario. "
                "Apache: <Limit> | Nginx: if ($request_method !~ ^(GET|POST|HEAD)$)"
            ),
            url         = url,
            module      = "http_methods",
        )


    tasks   = [check_method(m, sev, cvss, desc) for m, sev, cvss, desc in DANGEROUS_METHODS]
    results = await asyncio.gather(*tasks)

    for r in results:
        if r:
            vulns.append(r)

    # ── TRACE especial: verificar reflejo del body ────────────────────────────
    resp_trace = await client.request(
        "TRACE", url, follow=False, lax_ssl=True,
        extra_headers={"X-Custom-Header": "VulnScannerProbe"}
    )
    if resp_trace and resp_trace.status == 200 and "VulnScannerProbe" in resp_trace.text:
        # Verificar si ya fue añadido
        already = any("TRACE" in v.title for v in vulns)
        if not already:
            vulns.append(make_vuln(
                title       = "TRACE habilitado con reflejo de headers (XST)",
                severity    = "HIGH",
                cvss        = 8.1,
                category    = "HTTP Methods",
                description = "TRACE activo y refleja los headers enviados. Permite Cross-Site Tracing (XST) para robar cookies HttpOnly vía XSS.",
                evidence    = f"TRACE {url} → 200 OK con body reflejado",
                fix         = "Deshabilitar TRACE en el servidor web.",
                ref         = "https://owasp.org/www-community/attacks/Cross_Site_Tracing",
                module      = "http_methods",
            ))

    return vulns
