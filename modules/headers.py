"""
modules/headers.py — Análisis de security headers, CORS, cookies y CSP.

Anti-falsos-positivos:
  - Context-aware: headers HTML-only (CSP, X-Frame-Options, Referrer-Policy) se omiten
    para endpoints JSON/XML — no son aplicables a APIs sin respuesta HTML.
  - CORS *: solo HIGH si hay Allow-Credentials:true. Sin credentials es MEDIUM (intencional
    en APIs públicas). Solo CRITICAL cuando refleja origen arbitrario + credentials.
  - Cookies: se omiten cookies de tracking/analytics (_ga, _gid, etc.) — no son sesión.
  - CSP wildcard '*': solo reporta si aparece como valor standalone, no en *.example.com.
  - EOL + versión exacta: sin duplicar si ya hay un vuln EOL para el mismo server string.
"""

from __future__ import annotations

import re
from typing import Optional

from utils.http import AsyncHTTPClient, Response
from utils.vuln import Vuln, make_vuln
from config import SECURITY_HEADERS, CSP_INSECURE, EOL_SIGNATURES

# Headers que solo tienen sentido en respuestas HTML (no en APIs JSON/XML)
_HTML_ONLY_HEADERS = frozenset([
    "content-security-policy",
    "x-frame-options",
    "referrer-policy",
])

# Prefijos de cookies de tracking/analytics — no son cookies de sesión
_TRACKING_PREFIXES = (
    "_ga", "_gid", "_gat", "_fbp", "_fbc", "_gcl",
    "__utm", "ajs_", "mp_", "_hjid", "_ym_", "intercom-",
)

def _is_tracking_cookie(raw_cookie: str) -> bool:
    name = raw_cookie.split("=")[0].strip().lower()
    return name.startswith(_TRACKING_PREFIXES)


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

    # Detectar si este endpoint es una API (JSON/XML) o retorna HTML
    content_type = h.get("content-type", "").lower()
    is_api = (
        "application/json" in content_type
        or "application/xml" in content_type
        or "text/xml" in content_type
        or "application/graphql" in content_type
    )

    # ── Security Headers faltantes ─────────────────────────────────────────────
    for header, meta in SECURITY_HEADERS.items():
        # Headers HTML-only no aplican a endpoints que devuelven JSON/XML puro
        if is_api and header.lower() in _HTML_ONLY_HEADERS:
            continue
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
    # Anti-FP:
    #   - 'unsafe-inline' es válido cuando hay 'nonce-XXX' o 'strict-dynamic'
    #     (CSP 3: el navegador moderno ignora unsafe-inline si encuentra nonce/hash).
    #   - 'unsafe-eval' es decisión de diseño en apps con Vue/Alpine inline templates.
    #   - '*' standalone se reporta; '*' solo en img-src/media-src baja a LOW.
    csp = h.get("content-security-policy", "")
    if csp:
        csp_lower = csp.lower()
        has_nonce          = "'nonce-" in csp_lower
        has_strict_dynamic = "'strict-dynamic'" in csp_lower
        # Si hay nonce o strict-dynamic, 'unsafe-inline' es legítimo (fallback browser-compat)
        unsafe_inline_legit = has_nonce or has_strict_dynamic

        for directive, sev, cvss, desc in CSP_INSECURE:
            if directive == "*":
                if not re.search(r"(?:^|[\s])\*(?=[\s;]|$)", csp):
                    continue
                # Si el '*' está solo en img-src/media-src/font-src → LOW
                if re.search(r"(img-src|media-src|font-src)[^;]*\*", csp_lower):
                    sev, cvss = "LOW", 3.1
                    desc = "Wildcard en img-src/media-src/font-src (riesgo bajo, no permite scripts)"
            elif directive == "unsafe-inline":
                if "'unsafe-inline'" not in csp_lower:
                    continue
                if unsafe_inline_legit:
                    continue  # Browser moderno ignora unsafe-inline si hay nonce/strict-dynamic
            elif directive == "unsafe-eval":
                if "'unsafe-eval'" not in csp_lower:
                    continue
            else:
                if directive not in csp_lower:
                    continue

            vulns.append(make_vuln(
                title       = f"CSP insegura: '{directive}'",
                severity    = sev,
                cvss        = cvss,
                category    = "Content-Security-Policy",
                description = desc + (
                    " (Nota: la CSP usa nonce/strict-dynamic, lo cual mitiga parcialmente)."
                    if unsafe_inline_legit and directive != "unsafe-inline" else ""
                ),
                evidence    = f"CSP: {csp[:200]}",
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
        # Omitir cookies de tracking/analytics — no son cookies de sesión y
        # reportarlas como MEDIUM genera ruido que desacredita el informe
        if _is_tracking_cookie(cookie):
            continue

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
        creds = h.get("access-control-allow-credentials", "")
        if "true" in creds.lower():
            # CORS * + credentials = configuración imposible según spec, pero algunos
            # servidores mal configurados la aceptan — muy peligroso
            vulns.append(make_vuln(
                "CORS * con Allow-Credentials: true",
                "CRITICAL", 9.1, "CORS Misconfiguration",
                "CORS wildcard con credenciales permitidas permite a cualquier sitio leer "
                "respuestas autenticadas del usuario (cookies, tokens).",
                f"Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: {creds}",
                "Nunca combinar ACAO:* con ACAC:true. Usar lista blanca explícita de orígenes.",
                ref="https://portswigger.net/web-security/cors",
                module="headers",
            ))
        else:
            # Sin credentials, CORS * es intencional en APIs públicas — MEDIUM, no HIGH
            vulns.append(make_vuln(
                "CORS permisivo: Access-Control-Allow-Origin: *",
                "MEDIUM", 5.3, "CORS Misconfiguration",
                "Cualquier origen puede leer respuestas de esta API. "
                "Impacto real depende de si los endpoints retornan datos sensibles sin autenticación. "
                "Verificar si la API sirve datos autenticados antes de reportar.",
                "Access-Control-Allow-Origin: *",
                "Limitar a orígenes específicos si la API maneja datos de usuario. "
                "Para APIs públicas de solo lectura, CORS:* puede ser intencional.",
                ref="https://portswigger.net/web-security/cors",
                module="headers",
            ))
    elif cors and cors not in ("null", ""):
        # Anti-FP: probar con 2 orígenes distintos. Solo reportar si AMBOS se reflejan.
        # Esto descarta servidores que devuelven un Origin fijo o eco por debug.
        import secrets
        evil1 = f"https://evil-{secrets.token_hex(4)}.attacker-test.com"
        evil2 = f"https://malicious-{secrets.token_hex(4)}.bad-actor.example"

        resp_a = await client.get(url, extra_headers={"Origin": evil1}, lax_ssl=True)
        resp_b = await client.get(url, extra_headers={"Origin": evil2}, lax_ssl=True)

        if resp_a and resp_b:
            cors_a = resp_a.headers.get("access-control-allow-origin", "")
            cors_b = resp_b.headers.get("access-control-allow-origin", "")
            cred_a = resp_a.headers.get("access-control-allow-credentials", "")
            cred_b = resp_b.headers.get("access-control-allow-credentials", "")

            both_reflected = (evil1 in cors_a) and (evil2 in cors_b)

            if both_reflected:
                with_creds = "true" in cred_a.lower() or "true" in cred_b.lower()
                sev  = "CRITICAL" if with_creds else "HIGH"
                cvss = 9.1 if with_creds else 7.5
                vulns.append(make_vuln(
                    "CORS refleja origen arbitrario" + (" + credenciales" if with_creds else ""),
                    sev, cvss, "CORS Misconfiguration",
                    "El servidor refleja cualquier origen entrante (confirmado con 2 orígenes distintos). "
                    + ("Con Allow-Credentials:true un atacante puede leer respuestas autenticadas." if with_creds else ""),
                    (f"Test #1 Origin: {evil1} → ACAO: {cors_a}\n"
                     f"Test #2 Origin: {evil2} → ACAO: {cors_b}\n"
                     f"ACAC: {cred_a or 'no'}"),
                    "Validar lista blanca estricta de orígenes permitidos. Nunca usar reflection.",
                    ref="https://portswigger.net/web-security/cors",
                    module="headers",
                ))

    # ── Fingerprint del servidor ───────────────────────────────────────────────
    server  = h.get("server", "")
    powered = h.get("x-powered-by", "")
    all_fp  = f"{server} {powered}".strip()

    eol_found = False
    for sig, (sev, cvss, desc) in EOL_SIGNATURES.items():
        if sig.lower() in all_fp.lower():
            eol_found = True
            vulns.append(make_vuln(
                f"Software EOL: {sig}", sev, cvss, "Version Disclosure",
                f"{desc}. Software sin soporte de seguridad activo.",
                f"Server: {server} | X-Powered-By: {powered}",
                "Actualizar urgentemente a la versión actual con soporte.",
                ref="https://endoflife.date",
                module="headers",
            ))

    # Solo reportar 'versión exacta expuesta' si NO hay un vuln EOL ya (evita duplicado)
    if not eol_found and server and server.lower() not in ("cloudflare", "", "nginx", "apache"):
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

    # ── SRI (Subresource Integrity) en scripts de CDN externos ────────────────
    body_text = resp.text or ""
    if body_text and "<script" in body_text.lower():
        cdn_scripts_without_sri = _check_sri(body_text)
        if cdn_scripts_without_sri:
            vulns.append(make_vuln(
                "Scripts de CDN sin Subresource Integrity (SRI)",
                "LOW", 3.7, "Subresource Integrity",
                "Los scripts cargados desde CDN externo no incluyen el atributo "
                "integrity. Si el CDN es comprometido, se puede inyectar código "
                "malicioso sin que el navegador lo detecte.",
                "Ejemplos sin SRI:\n" + "\n".join(cdn_scripts_without_sri[:3]),
                "Agregar atributo integrity=\"sha384-...\" y crossorigin=\"anonymous\" "
                "a cada <script src> y <link rel=stylesheet> de CDN externo.",
                ref="https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
                module="headers",
            ))

    # ── Mixed content: recursos http:// en página https:// ────────────────────
    if url.startswith("https://") and body_text:
        mixed = _check_mixed_content(body_text)
        if mixed:
            vulns.append(make_vuln(
                "Mixed Content: recursos HTTP en página HTTPS",
                "MEDIUM", 5.3, "Mixed Content",
                "La página HTTPS carga recursos vía HTTP plano. El navegador los "
                "bloquea o avisa al usuario. Un atacante en la red puede modificarlos.",
                "Recursos mixed:\n" + "\n".join(mixed[:5]),
                "Migrar todos los recursos a HTTPS. Agregar header "
                "Content-Security-Policy: upgrade-insecure-requests.",
                ref="https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
                module="headers",
            ))

    return vulns, resp


def _check_sri(html: str) -> list[str]:
    """Encuentra <script src> de CDN externo sin atributo integrity."""
    import re as _re
    pattern = _re.compile(
        r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>',
        _re.IGNORECASE,
    )
    cdn_hosts = (
        "ajax.googleapis.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net",
        "code.jquery.com", "unpkg.com", "stackpath.bootstrapcdn.com",
        "maxcdn.bootstrapcdn.com", "use.fontawesome.com",
    )
    bad = []
    for m in pattern.finditer(html):
        tag = m.group(0)
        src = m.group(1)
        if any(cdn in src for cdn in cdn_hosts) and "integrity=" not in tag.lower():
            bad.append(src[:120])
    return bad


def _check_mixed_content(html: str) -> list[str]:
    """Busca recursos http:// dentro de la página."""
    import re as _re
    pattern = _re.compile(
        r'(?:src|href)=["\'](http://[^"\']+)["\']',
        _re.IGNORECASE,
    )
    found = []
    for m in pattern.finditer(html):
        url_found = m.group(1)
        # Ignorar links a recursos que claramente son enlaces externos en <a>
        # (solo nos importan src/href de scripts, links, imgs, iframes)
        if "://localhost" in url_found or "://127.0.0.1" in url_found:
            continue
        found.append(url_found[:120])
    # Dedup
    return list(dict.fromkeys(found))
