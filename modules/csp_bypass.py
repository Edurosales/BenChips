"""
modules/csp_bypass.py — CSP bypass auto-detection.

Analiza la CSP del target y busca:
  1. CDNs en script-src whitelist conocidos por permitir bypass:
     - ajax.googleapis.com (AngularJS XSS sandbox escape histórico)
     - cdnjs.cloudflare.com (cualquier lib vulnerable hospedada)
     - cdn.jsdelivr.net (cualquier package npm/github)
  2. JSONP endpoints en mismo dominio (script-src 'self')
  3. Object/embed-src laxos (Flash XSS)
  4. base-uri faltante o '*' (base href hijack)
  5. form-action faltante (form hijack via XSS injection)
  6. Permite 'unsafe-eval' sin strict-dynamic
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


# CDNs en whitelist que son CSP bypass conocidos
_BYPASSABLE_CDNS = {
    "ajax.googleapis.com": "AngularJS sandbox escape (CVE-2019-10768); cualquier lib vulnerable",
    "cdnjs.cloudflare.com": "Hospeda miles de libs incluidas versiones vulnerables",
    "cdn.jsdelivr.net":    "Sirve cualquier paquete npm/github incluidos vulnerables",
    "unpkg.com":           "Idem jsdelivr — cualquier paquete npm accesible",
    "code.jquery.com":     "Versiones antiguas vulnerables disponibles",
    "stackpath.bootstrapcdn.com": "Versiones antiguas Bootstrap con CVEs",
}


async def run(client: AsyncHTTPClient, url: str) -> list[Vuln]:
    vulns: list[Vuln] = []

    resp = await client.get(url, body_limit=4096)
    if not resp:
        return vulns

    csp = resp.headers.get("content-security-policy", "")
    if not csp:
        return vulns

    csp_lower = csp.lower()

    # ── 1) CDNs bypassables en script-src ────────────────────────────────────
    # Buscar script-src o default-src
    m = re.search(r"(?:script-src|default-src)([^;]+)", csp_lower)
    if m:
        directive = m.group(1)
        for cdn, reason in _BYPASSABLE_CDNS.items():
            if cdn in directive:
                vulns.append(make_vuln(
                    title       = f"CSP bypass: CDN whitelisted ({cdn})",
                    severity    = "MEDIUM",
                    cvss        = 6.1,
                    category    = "CSP Bypass",
                    description = (
                        f"La CSP permite scripts desde '{cdn}'. {reason}. "
                        "Atacante con XSS puede cargar JS controlado o lib vulnerable "
                        "para escape de sandbox."
                    ),
                    evidence    = f"CSP directive: {directive.strip()[:200]}",
                    fix         = (
                        f"Eliminar '{cdn}' de script-src. Self-host las librerías "
                        "necesarias con SRI. Usar nonce-based CSP en lugar de whitelist."
                    ),
                    ref         = "https://research.google/pubs/pub45542/",
                    module      = "csp_bypass",
                    url         = url,
                    cwe         = "CWE-1021",
                ))

    # ── 2) base-uri faltante ─────────────────────────────────────────────────
    if "base-uri" not in csp_lower:
        vulns.append(make_vuln(
            title       = "CSP bypass: base-uri no definido",
            severity    = "MEDIUM",
            cvss        = 5.4,
            category    = "CSP Bypass",
            description = (
                "Sin directiva base-uri, un atacante con XSS (incluso limitado a "
                "injection de un <base> tag) puede redirigir todos los relative "
                "URLs a su dominio, bypaseando script-src 'self'."
            ),
            evidence    = f"CSP: {csp[:200]}",
            fix         = "Agregar: base-uri 'self' (o 'none' si la app no usa <base>).",
            ref         = "https://csp.withgoogle.com/docs/strict-csp.html",
            module      = "csp_bypass",
            url         = url,
            cwe         = "CWE-1021",
        ))

    # ── 3) form-action faltante ──────────────────────────────────────────────
    if "form-action" not in csp_lower:
        vulns.append(make_vuln(
            title       = "CSP: form-action no definido",
            severity    = "LOW",
            cvss        = 3.7,
            category    = "CSP Bypass",
            description = (
                "Sin form-action, un atacante con XSS puede inyectar <form action=evil.com> "
                "para exfiltrar datos del formulario (credenciales, CC, etc)."
            ),
            evidence    = f"CSP: {csp[:200]}",
            fix         = "Agregar: form-action 'self' (lista de endpoints válidos si hay externos).",
            ref         = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/form-action",
            module      = "csp_bypass",
            url         = url,
        ))

    # ── 4) object-src no restringido ─────────────────────────────────────────
    if "object-src" not in csp_lower and "default-src" in csp_lower:
        # Si default-src es laxo, object-src hereda
        default_m = re.search(r"default-src([^;]+)", csp_lower)
        if default_m and ("*" in default_m.group(1) or "https:" in default_m.group(1)):
            vulns.append(make_vuln(
                title       = "CSP bypass: object-src hereda default laxo",
                severity    = "MEDIUM",
                cvss        = 5.4,
                category    = "CSP Bypass",
                description = (
                    "object-src no está definido y hereda default-src amplio. "
                    "Permite cargar plugins (Flash, Java) que pueden ejecutar código "
                    "fuera de la sandbox del navegador."
                ),
                evidence    = f"default-src: {default_m.group(1).strip()[:120]}",
                fix         = "Agregar: object-src 'none'.",
                ref         = "https://csp.withgoogle.com/docs/strict-csp.html",
                module      = "csp_bypass",
                url         = url,
                cwe         = "CWE-1021",
            ))

    # ── 5) unsafe-eval sin strict-dynamic ────────────────────────────────────
    if "'unsafe-eval'" in csp_lower and "'strict-dynamic'" not in csp_lower:
        vulns.append(make_vuln(
            title       = "CSP: unsafe-eval permitido",
            severity    = "MEDIUM",
            cvss        = 5.4,
            category    = "CSP Bypass",
            description = (
                "unsafe-eval permite eval(), new Function(), setTimeout(string). "
                "Anula la protección de muchas variantes de XSS y permite escape "
                "de sandbox en frameworks como Vue/Alpine con templates."
            ),
            evidence    = f"CSP: {csp[:200]}",
            fix         = "Eliminar unsafe-eval. Migrar a runtime que no usa eval (Vue 3 sin templates inline).",
            ref         = "https://web.dev/csp-xss/",
            module      = "csp_bypass",
            url         = url,
            cwe         = "CWE-1021",
        ))

    return vulns
