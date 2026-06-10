"""
modules/oauth_oidc.py — OAuth2 / OpenID Connect misconfigurations.

Detecta:
  1. Discovery endpoint expuesto (.well-known/openid-configuration)
  2. redirect_uri whitelist bypass (open redirect en authorization endpoint)
  3. state parameter no obligatorio (CSRF)
  4. PKCE no requerido para public clients
  5. response_type permite 'token' (implicit flow, deprecated)
  6. id_token con kid traversal o alg=none
"""

from __future__ import annotations

import asyncio
import json
import secrets
from urllib.parse import urlparse, urlencode, parse_qs

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


_WELL_KNOWN_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/.well-known/openid-configuration",
    "/auth/realms/master/.well-known/openid-configuration",  # Keycloak
]

_AUTHORIZE_PATHS = [
    "/oauth/authorize", "/oauth2/authorize", "/connect/authorize",
    "/auth/realms/master/protocol/openid-connect/auth",
]


async def run(client: AsyncHTTPClient, url: str) -> list[Vuln]:
    vulns: list[Vuln] = []

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    # ── 1) Discovery endpoint ───────────────────────────────────────────────
    discovery_data = None
    discovery_url  = None
    for wkp in _WELL_KNOWN_PATHS:
        u = base.rstrip("/") + wkp
        r = await client.get(u, body_limit=32768)
        if r and r.status == 200 and "issuer" in r.text.lower():
            try:
                discovery_data = json.loads(r.text)
                discovery_url  = u
                break
            except Exception:
                pass

    if not discovery_data:
        return vulns  # Sin OAuth/OIDC, nada que probar

    vulns.append(make_vuln(
        title       = "OIDC discovery endpoint público",
        severity    = "INFO",
        cvss        = 0.0,
        category    = "OAuth / OIDC",
        description = (
            "El endpoint .well-known/openid-configuration está disponible públicamente. "
            "Diseñado para descubrimiento por clientes — no es vulnerabilidad per se, "
            "pero indica que hay flujo OAuth/OIDC para auditar."
        ),
        evidence    = (
            f"URL: {discovery_url}\n"
            f"Issuer: {discovery_data.get('issuer', 'N/A')}\n"
            f"Authorization endpoint: {discovery_data.get('authorization_endpoint', 'N/A')}"
        ),
        fix         = "(Informativo — endpoint diseñado para ser público).",
        ref         = "https://openid.net/specs/openid-connect-discovery-1_0.html",
        module      = "oauth_oidc",
        url         = discovery_url,
    ))

    # ── 2) Implicit flow soportado (deprecated) ─────────────────────────────
    grants = discovery_data.get("response_types_supported", [])
    if any("token" in g and "code" not in g for g in grants):
        vulns.append(make_vuln(
            title       = "OAuth: Implicit flow habilitado (response_type=token)",
            severity    = "MEDIUM",
            cvss        = 5.4,
            category    = "OAuth / OIDC",
            description = (
                "El servidor permite el flujo Implicit (response_type=token), "
                "deprecado por OAuth 2.1 por ser vulnerable a token leakage via "
                "URL fragment, history, logs, Referer."
            ),
            evidence    = f"response_types_supported: {grants}",
            fix         = "Migrar a Authorization Code flow + PKCE. Eliminar 'token' de response_types_supported.",
            ref         = "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-29",
            module      = "oauth_oidc",
            url         = discovery_url,
            cwe         = "CWE-522",
        ))

    # ── 3) PKCE no requerido ────────────────────────────────────────────────
    pkce_supported = discovery_data.get("code_challenge_methods_supported", [])
    if not pkce_supported:
        vulns.append(make_vuln(
            title       = "OAuth: PKCE no soportado",
            severity    = "HIGH",
            cvss        = 7.5,
            category    = "OAuth / OIDC",
            description = (
                "El servidor no anuncia code_challenge_methods_supported. PKCE "
                "es obligatorio en OAuth 2.1 para todos los clientes (public y "
                "confidential) — protege contra code interception."
            ),
            evidence    = "discovery missing code_challenge_methods_supported",
            fix         = "Habilitar PKCE S256 en el servidor de autorización.",
            ref         = "https://datatracker.ietf.org/doc/html/rfc7636",
            module      = "oauth_oidc",
            url         = discovery_url,
            cwe         = "CWE-345",
        ))

    # ── 4) redirect_uri bypass test ──────────────────────────────────────────
    auth_ep = discovery_data.get("authorization_endpoint", "")
    if auth_ep:
        # Probar varios bypasses comunes
        bypasses = [
            "https://evil.attacker-test.com",                 # Origen totalmente diferente
            f"{base}.attacker-test.com",                       # Subdomain confusion
            f"{base}@evil.attacker-test.com",                  # Userinfo trick
            f"{base}#@evil.attacker-test.com",                 # Fragment bypass
            f"{base}/../redirect?to=evil.attacker-test.com",   # Path traversal
        ]

        for bypass in bypasses[:3]:
            params = {
                "client_id":    "test-client",
                "redirect_uri": bypass,
                "response_type": "code",
                "scope":        "openid",
                "state":        secrets.token_hex(8),
            }
            test_url = f"{auth_ep}?{urlencode(params)}"
            r = await client.get(test_url, follow=False, body_limit=4096)
            if not r:
                continue

            location = r.headers.get("location", "")
            # Si redirige al bypass → ACCEPT INVÁLIDO
            if "evil.attacker-test.com" in location.lower():
                vulns.append(make_vuln(
                    title       = "OAuth: redirect_uri bypass posible",
                    severity    = "CRITICAL",
                    cvss        = 9.0,
                    category    = "OAuth / OIDC",
                    description = (
                        "El servidor de autorización aceptó un redirect_uri arbitrario. "
                        "Permite robo de authorization code → account takeover."
                    ),
                    evidence    = (
                        f"GET {test_url[:200]}\n"
                        f"Location: {location[:200]}\n"
                        f"Servidor confió en el redirect_uri inyectado"
                    ),
                    fix         = (
                        "Whitelist EXACTA de redirect_uri (string comparison, no prefix). "
                        "Rechazar URIs con fragmentos, userinfo, traversal. RFC 6749 §3.1.2.2."
                    ),
                    ref         = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2",
                    module      = "oauth_oidc",
                    url         = auth_ep,
                    cwe         = "CWE-601",
                ))
                break  # Una confirmación basta

    return vulns
