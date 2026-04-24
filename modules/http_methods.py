"""
modules/http_methods.py — Detección de métodos HTTP peligrosos habilitados.

Anti-falsos-positivos:
  - Se obtiene primero el status baseline del URL con GET.
  - Si un método devuelve el mismo código que GET (ej: ambos 302 → login),
    se ignora porque IIS/ASP.NET redirige todo indiscriminadamente.
  - Solo se reporta si el método produce una respuesta distinta al baseline,
    O si aparece explícitamente en el header Allow de OPTIONS.
  - Para TRACE: solo HIGH si el body refleja los headers enviados.
"""

from __future__ import annotations

import asyncio

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln
from config import DANGEROUS_METHODS

# Códigos que significan "no implementado/no permitido" — nunca reportar
_REJECTED = {400, 405, 501, 505}

# Códigos que son definitivamente una acción real del servidor (no redirect genérico)
_REAL_ACTION = {200, 201, 202, 204, 207}


async def run(client: AsyncHTTPClient, url: str) -> list[Vuln]:
    """
    Prueba métodos HTTP peligrosos verificando que están REALMENTE habilitados.
    Usa un GET baseline para evitar falsos positivos por redirects genéricos de IIS.
    """
    vulns: list[Vuln] = []

    # ── 0. Baseline GET — qué responde el servidor normalmente ─────────────────
    baseline_resp = await client.request("GET", url, follow=False, lax_ssl=True)
    baseline_status = baseline_resp.status if baseline_resp else None

    # ── 1. OPTIONS — obtener el Allow header oficial ────────────────────────────
    allowed_methods: set[str] = set()
    resp_options = await client.request("OPTIONS", url, follow=False, lax_ssl=True)
    if resp_options and resp_options.status not in _REJECTED:
        allow_hdr = resp_options.headers.get("allow", "")
        if allow_hdr:
            allowed_methods = {m.strip().upper() for m in allow_hdr.split(",")}

    # ── 2. Probar cada método peligroso ────────────────────────────────────────
    async def check_method(method: str, sev: str, cvss: float, desc: str):
        resp = await client.request(method, url, follow=False, lax_ssl=True)
        if resp is None:
            return None

        status = resp.status

        # Definitivamente rechazado por el servidor
        if status in _REJECTED:
            # Aún puede aparecer en el Allow header
            if method in allowed_methods:
                return make_vuln(
                    title       = f"Método {method} en Allow header",
                    severity    = "LOW",
                    cvss        = max(cvss - 3.0, 0.0),
                    category    = "HTTP Methods",
                    description = (
                        f"{desc} (listado en Allow header aunque devuelve {status}; "
                        "puede ser un WAF o config parcial)"
                    ),
                    evidence    = f"Allow: {allow_hdr} | {method} → HTTP {status}",
                    fix         = f"Eliminar {method} del header Allow.",
                    module      = "http_methods",
                )
            return None

        # El servidor devuelve el mismo código que para GET:
        # IIS/ASP.NET hace redirect (302) a login para CUALQUIER método no reconocido.
        # → Esto NO es evidencia de que el método esté habilitado.
        if baseline_status is not None and status == baseline_status and status >= 300:
            # Excepción: si además aparece en el Allow header, sí reportar con severidad reducida
            if method in allowed_methods:
                return make_vuln(
                    title       = f"Método {method} posiblemente habilitado (Allow header)",
                    severity    = "LOW" if sev in ("HIGH", "MEDIUM") else sev,
                    cvss        = max(cvss - 2.5, 0.0),
                    category    = "HTTP Methods",
                    description = (
                        f"{desc}. El servidor redirige con {status} (igual que GET), "
                        "pero el método aparece en el header Allow."
                    ),
                    evidence    = f"Allow: {allow_hdr} | {method} → HTTP {status} (mismo que GET)",
                    fix         = (
                        f"Deshabilitar {method} en la configuración del servidor. "
                        "IIS: requestFiltering | Apache: <Limit> | Nginx: limit_except"
                    ),
                    module      = "http_methods",
                )
            # Redirect idéntico a GET pero sin Allow → falso positivo, ignorar
            return None

        # Respuesta real (200/201/204) → método definitivamente activo
        if status in _REAL_ACTION:
            return make_vuln(
                title       = f"Método HTTP habilitado: {method}",
                severity    = sev,
                cvss        = cvss,
                category    = "HTTP Methods",
                description = desc,
                evidence    = f"{method} {url} → HTTP {status} (respuesta real, no redirect)",
                fix         = (
                    f"Deshabilitar {method} si no es necesario. "
                    "IIS: requestFiltering/verb | Apache: <Limit> | Nginx: limit_except"
                ),
                url         = url,
                module      = "http_methods",
            )

        # 401/403 — existe pero requiere autenticación; reportar si aparece en Allow
        if status in {401, 403} and method in allowed_methods:
            return make_vuln(
                title       = f"Método HTTP habilitado: {method} (requiere auth)",
                severity    = "MEDIUM" if sev == "HIGH" else sev,
                cvss        = max(cvss - 1.5, 0.0),
                category    = "HTTP Methods",
                description = f"{desc} (protegido por autenticación)",
                evidence    = f"{method} {url} → HTTP {status} | Allow incluye {method}",
                fix         = (
                    f"Verificar si {method} es necesario. "
                    "Si no, deshabilitar completamente."
                ),
                url         = url,
                module      = "http_methods",
            )

        # Cualquier otro código distinto al baseline y no en REJECTED → reportar
        if baseline_status is None or status != baseline_status:
            return make_vuln(
                title       = f"Método HTTP habilitado: {method}",
                severity    = sev,
                cvss        = cvss,
                category    = "HTTP Methods",
                description = desc,
                evidence    = f"{method} {url} → HTTP {status}",
                fix         = (
                    f"Deshabilitar {method} si no es necesario. "
                    "IIS: requestFiltering/verb | Apache: <Limit> | Nginx: limit_except"
                ),
                url         = url,
                module      = "http_methods",
            )

        return None

    # Ejecutar todos los métodos en paralelo (excluyendo TRACE que se trata aparte)
    non_trace = [(m, s, c, d) for m, s, c, d in DANGEROUS_METHODS if m != "TRACE"]
    tasks     = [check_method(m, s, c, d) for m, s, c, d in non_trace]
    results   = await asyncio.gather(*tasks)

    for r in results:
        if r:
            vulns.append(r)

    # ── 3. TRACE — verificación estricta: solo positivo si refleja el body ─────
    marker = "VulnScan-Probe-7f3a9c"
    resp_trace = await client.request(
        "TRACE", url, follow=False, lax_ssl=True,
        extra_headers={"X-Probe-Marker": marker}
    )
    if resp_trace:
        body_text = resp_trace.text
        if resp_trace.status == 200 and marker in body_text:
            # Confirmado: TRACE activo con reflejo de headers (XST real)
            vulns.append(make_vuln(
                title       = "TRACE habilitado con reflejo de headers (XST)",
                severity    = "HIGH",
                cvss        = 8.1,
                category    = "HTTP Methods",
                description = (
                    "TRACE activo y refleja los headers enviados. Permite "
                    "Cross-Site Tracing (XST) para robar cookies HttpOnly vía XSS."
                ),
                evidence    = f"TRACE {url} → 200 OK con body reflejado (marker encontrado)",
                fix         = "Deshabilitar TRACE en el servidor web.",
                ref         = "https://owasp.org/www-community/attacks/Cross_Site_Tracing",
                module      = "http_methods",
            ))
        elif resp_trace.status in _REAL_ACTION and resp_trace.status != baseline_status:
            # TRACE responde 200 pero sin reflejo confirmado — reportar como MEDIUM
            vulns.append(make_vuln(
                title       = "Método HTTP habilitado: TRACE (sin reflejo confirmado)",
                severity    = "MEDIUM",
                cvss        = 5.3,
                category    = "HTTP Methods",
                description = (
                    "TRACE responde con 200 pero no se confirmó reflejo de headers. "
                    "Posible riesgo XST si hay XSS presente."
                ),
                evidence    = f"TRACE {url} → HTTP {resp_trace.status}",
                fix         = "Deshabilitar TRACE en el servidor web.",
                ref         = "https://owasp.org/www-community/attacks/Cross_Site_Tracing",
                module      = "http_methods",
            ))

    return vulns
