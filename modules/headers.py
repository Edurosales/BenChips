"""
modules/headers.py — Análisis de security headers, CORS, cookies y CSP.
"""

from __future__ import annotations

import re
from typing import Optional

from utils.http import AsyncHTTPClient, Response
from utils.vuln import Vuln, make_vuln
from config import SECURITY_HEADERS, CSP_INSECURE, EOL_SIGNATURES


async def run(client: AsyncHTTPClient, url: str) -> tuple[list[Vuln], Response | None]:
    """
    Analiza headers de seguridad, CORS, cookies, CSP y fingerprint del servidor.
    Retorna (vulns, response).
    """
    vulns: list[Vuln] = []

    resp = await client.get(url, follow=True, lax_ssl=True, body_limit=65536)
    if not resp:
        return [make_vuln(
            "Sin respuesta HTTP", "INFO", 0.0, "Connectivity",
            "No se pudo conectar al servidor.", "Request failed",
            "Verificar URL y disponibilidad.", module="headers",
        )], None

    h = resp.headers  # ya en minúsculas

    # ── Security Headers faltantes ─────────────────────────────────────────────
    for header, meta in SECURITY_HEADERS.items():
        if header.lower() not in h:
            vulns.append(make_vuln(
                title       = f"Header faltante: {header}",
                severity    = meta["severity"],
                cvss        = meta["cvss"],
                category    = "Security Headers",
                description = meta["description"],
                evidence    = f"Header '{header}' ausente en la respuesta HTTP",
                fix         = f"Agregar → {header}: {meta['fix']}",
                ref         = meta["ref"],
                module      = "headers",
            ))

    # ── CSP existente pero insegura ────────────────────────────────────────────
    csp = h.get("content-security-policy", "")
    if csp:
        for directive, sev, cvss, desc in CSP_INSECURE:
            if directive in csp:
                vulns.append(make_vuln(
                    title       = f"CSP insegura: '{directive}'",
                    severity    = sev,
                    cvss        = cvss,
                    category    = "Content-Security-Policy",
                    description = desc,
                    evidence    = f"CSP: {csp[:150]}",
                    fix         = f"Eliminar '{directive}' de la directiva CSP.",
                    ref         = "https://csp-evaluator.withgoogle.com/",
                    module      = "headers",
                ))

    # ── HSTS análisis profundo ─────────────────────────────────────────────────
    hsts = h.get("strict-transport-security", "")
    if hsts:
        if "includesubdomains" not in hsts.lower():
            vulns.append(make_vuln(
                "HSTS sin includeSubDomains", "LOW", 3.1, "Security Headers",
                "Los subdominios no están cubiertos por HSTS — posible downgrade en ellos.",
                f"Strict-Transport-Security: {hsts}",
                "Agregar includeSubDomains al header HSTS.",
                module="headers",
            ))
        age_m = re.search(r"max-age=(\d+)", hsts)
        if age_m and int(age_m.group(1)) < 15552000:
            days = int(age_m.group(1)) // 86400
            vulns.append(make_vuln(
                f"HSTS max-age muy corto ({days} días)", "LOW", 3.1, "Security Headers",
                "max-age recomendado mínimo 180 días (15552000), ideal 1 año.",
                f"Strict-Transport-Security: {hsts}",
                "Cambiar a: max-age=31536000; includeSubDomains; preload",
                module="headers",
            ))

    # ── Cookies ───────────────────────────────────────────────────────────────
    raw_hdrs = resp.headers
    cookies_raw = []
    for k, v in raw_hdrs.items():
        if k.lower() == "set-cookie":
            cookies_raw.append(v)

    for cookie in cookies_raw:
        cl = cookie.lower()
        if "httponly" not in cl:
            vulns.append(make_vuln(
                "Cookie sin flag HttpOnly", "MEDIUM", 6.1, "Cookie Security",
                "La cookie es accesible desde JavaScript. Si hay XSS, el atacante roba la sesión.",
                f"Set-Cookie: {cookie[:100]}",
                "Agregar ; HttpOnly a todas las cookies de sesión.",
                ref="https://developer.mozilla.org/es/docs/Web/HTTP/Cookies",
                module="headers",
            ))
        if "secure" not in cl:
            vulns.append(make_vuln(
                "Cookie sin flag Secure", "MEDIUM", 5.9, "Cookie Security",
                "La cookie se envía también por HTTP plano, expuesta a interceptación.",
                f"Set-Cookie: {cookie[:100]}",
                "Agregar ; Secure a todas las cookies.",
                module="headers",
            ))
        if "samesite" not in cl:
            vulns.append(make_vuln(
                "Cookie sin atributo SameSite", "LOW", 4.3, "Cookie Security",
                "Sin SameSite la cookie se envía en peticiones cross-site (riesgo CSRF).",
                f"Set-Cookie: {cookie[:100]}",
                "Agregar ; SameSite=Strict o SameSite=Lax.",
                ref="https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
                module="headers",
            ))

    # ── CORS ──────────────────────────────────────────────────────────────────
    cors = h.get("access-control-allow-origin", "")
    if cors == "*":
        vulns.append(make_vuln(
            "CORS abierto: Access-Control-Allow-Origin: *",
            "HIGH", 7.5, "CORS Misconfiguration",
            "Cualquier dominio puede hacer peticiones cross-origin a esta API.",
            "Access-Control-Allow-Origin: *",
            "Especificar dominios explícitos: Access-Control-Allow-Origin: https://tudominio.com",
            ref="https://portswigger.net/web-security/cors",
            module="headers",
        ))
    elif cors and cors not in ("null", ""):
        resp2 = await client.get(
            url, extra_headers={"Origin": "https://evil.attacker.com"}, lax_ssl=True
        )
        if resp2:
            cors2 = resp2.headers.get("access-control-allow-origin", "")
            cred2 = resp2.headers.get("access-control-allow-credentials", "")
            if "evil.attacker.com" in cors2:
                sev  = "CRITICAL" if "true" in cred2.lower() else "HIGH"
                cvss = 9.1 if "true" in cred2.lower() else 7.5
                vulns.append(make_vuln(
                    "CORS refleja origen arbitrario" + (" + credenciales" if "true" in cred2.lower() else ""),
                    sev, cvss, "CORS Misconfiguration",
                    "El servidor refleja cualquier origen. "
                    + ("Con Allow-Credentials:true un atacante puede leer respuestas autenticadas." if "true" in cred2.lower() else ""),
                    f"Origin: evil.attacker.com → ACAO: {cors2}, ACAC: {cred2}",
                    "Validar lista blanca estricta de orígenes permitidos. Nunca usar reflection.",
                    ref="https://portswigger.net/web-security/cors",
                    module="headers",
                ))

    # ── Fingerprint del servidor ───────────────────────────────────────────────
    server  = h.get("server", "")
    powered = h.get("x-powered-by", "")
    all_fp  = f"{server} {powered}".strip()

    for sig, (sev, cvss, desc) in EOL_SIGNATURES.items():
        if sig.lower() in all_fp.lower():
            vulns.append(make_vuln(
                f"Software EOL: {sig}", sev, cvss, "Version Disclosure",
                f"{desc}. Software sin soporte de seguridad activo.",
                f"Server: {server} | X-Powered-By: {powered}",
                "Actualizar urgentemente a la versión actual con soporte.",
                ref="https://endoflife.date",
                module="headers",
            ))

    if server and server.lower() not in ("cloudflare", "", "nginx", "apache"):
        vulns.append(make_vuln(
            "Versión exacta del servidor expuesta", "MEDIUM", 5.3, "Information Disclosure",
            "Revelar la versión exacta permite buscar CVEs específicos.",
            f"Server: {server}",
            "ServerTokens Prod (Apache) / server_tokens off (Nginx) / suppress en IIS.",
            ref="https://owasp.org/www-project-secure-headers/",
            module="headers",
        ))

    if powered:
        vulns.append(make_vuln(
            f"Framework expuesto: {powered}", "LOW", 3.1, "Information Disclosure",
            "X-Powered-By revela el stack tecnológico del backend.",
            f"X-Powered-By: {powered}",
            "PHP: expose_php=Off | Express: app.disable('x-powered-by') | ASP.NET: removeServerHeader",
            module="headers",
        ))

    return vulns, resp
