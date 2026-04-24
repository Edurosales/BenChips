"""
modules/jwt_scan.py — Detección y análisis de JSON Web Tokens (JWT).

Busca tokens en cabeceras Set-Cookie o cuerpos de respuesta y evalúa:
  - Firma ausente (alg: none)
  - Secretos débiles (fuerza bruta sigilosa contra JWT_WEAK_SECRETS)

Anti-falsos-positivos:
  - Solo procesa strings que realmente parezcan JWTs válidos (3 partes base64).
  - La fuerza bruta es offline, no genera tráfico.
"""

from __future__ import annotations

import base64
import hmac
import hashlib
import json
import re

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln
from config import JWT_WEAK_SECRETS


# Regex para identificar un JWT (header.payload.signature) en base64url
_JWT_PATTERN = re.compile(r'(eyJ[A-Za-z0-9_-]+)\.(eyJ[A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)')


def _base64url_decode(data: str) -> bytes:
    rem = len(data) % 4
    if rem > 0:
        data += '=' * (4 - rem)
    return base64.urlsafe_b64decode(data.replace('-', '+').replace('_', '/'))


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


async def run(
    client:    AsyncHTTPClient,
    url:       str,
    body_text: str | None = None,
    headers:   dict | None = None,
) -> list[Vuln]:
    """
    Busca JWTs en el texto base y analiza su seguridad (offline).
    """
    vulns: list[Vuln] = []
    found_jwts: set[str] = set()

    # Combinar texto donde buscar JWTs
    search_text = body_text or ""
    if headers:
        for k, v in headers.items():
            search_text += f" {v}"

    matches = _JWT_PATTERN.findall(search_text)
    
    # Solo procesamos tokens únicos para no repetir
    unique_tokens = set()
    for m in matches:
        token = f"{m[0]}.{m[1]}.{m[2]}"
        if token not in found_jwts:
            unique_tokens.add(token)
            found_jwts.add(token)

    for token in unique_tokens:
        parts = token.split('.')
        if len(parts) != 3:
            continue
            
        header_b64, payload_b64, signature_b64 = parts

        try:
            header_json = json.loads(_base64url_decode(header_b64))
            payload_json = json.loads(_base64url_decode(payload_b64))
        except Exception:
            continue  # No era JSON válido

        alg = header_json.get("alg", "").upper()
        
        # ── 1. Vulnerabilidad alg: none ────────────────────────────────────────
        if alg == "NONE":
            vulns.append(make_vuln(
                title       = "JWT Vulnerable a bypass 'alg: none'",
                severity    = "CRITICAL",
                cvss        = 9.1,
                category    = "Broken Authentication",
                description = (
                    "Se encontró un JWT que especifica 'alg: none'. "
                    "Un atacante podría forjar tokens válidos con cualquier privilegio "
                    "sin necesitar la clave criptográfica."
                ),
                evidence    = f"Header JWT: {json.dumps(header_json)}\nPayload: {json.dumps(payload_json)}",
                fix         = "Rechazar tokens con algoritmo 'none' en el backend. Exigir firmas fuertes (HS256, RS256).",
                ref         = "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                module      = "jwt_scan",
            ))

        # ── 2. Fuerza bruta de firma (solo para HS256) ─────────────────────────
        if alg == "HS256":
            msg = f"{header_b64}.{payload_b64}".encode('utf-8')
            target_sig = _base64url_decode(signature_b64)

            cracked_secret = None
            for secret in JWT_WEAK_SECRETS:
                computed = hmac.new(secret.encode('utf-8'), msg, hashlib.sha256).digest()
                if computed == target_sig:
                    cracked_secret = secret
                    break

            if cracked_secret:
                vulns.append(make_vuln(
                    title       = "JWT con Secreto Débil (Cracked)",
                    severity    = "CRITICAL",
                    cvss        = 9.8,
                    category    = "Broken Authentication",
                    description = (
                        "El JWT está firmado con un secreto extremadamente débil y conocido. "
                        "Un atacante puede crear tokens válidos (ej. escalar a admin)."
                    ),
                    evidence    = (
                        f"El token fue crackeado exitosamente.\n"
                        f"Secreto: '{cracked_secret}'\n"
                        f"Algoritmo: HS256\n"
                        f"Payload extraído: {json.dumps(payload_json)}"
                    ),
                    fix         = (
                        "Generar un secreto criptográficamente seguro (mínimo 256 bits / 32 caracteres) "
                        "usando un generador de números aleatorios seguro."
                    ),
                    ref         = "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
                    module      = "jwt_scan",
                ))

    return vulns
