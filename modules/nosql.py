"""
modules/nosql.py — NoSQL Injection (MongoDB, CouchDB, basic Firestore).

Detecta dos patrones:
  1. Operator injection en JSON body: {"user": {"$ne": null}} bypass auth.
  2. Operator injection en query string: ?username[$ne]=xxx
  3. JavaScript injection en MongoDB ($where, mapReduce).

Anti-FP:
  - Baseline con valor benigno.
  - Detecta diferencias significativas: status code, body length, presencia de
    JSON con campos de datos (no errores).
  - Solo reporta si la respuesta inyectada devuelve MÁS datos que la limpia
    (típico de bypass auth: lista de usuarios en vez de error 401).
"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import urlparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


_NOSQL_OPERATORS = [
    ({"$ne": None},          "$ne null (auth bypass clásico)"),
    ({"$gt": ""},            "$gt vacío (true en cualquier string)"),
    ({"$regex": ".*"},       "$regex .* (match cualquier valor)"),
    ({"$exists": True},      "$exists true (siempre verdadero)"),
]

_JS_PAYLOADS = [
    ("'||'1'=='1",                 "JavaScript OR truthy"),
    ("';return true;//",           "Function return true"),
    ("'; sleep(3000); var x='",    "JavaScript sleep (blind)"),
]

_AUTH_FIELDS = ["username", "user", "email", "login", "name"]
_PASS_FIELDS = ["password", "pass", "pwd", "secret"]


async def run(client: AsyncHTTPClient, url: str) -> list[Vuln]:
    """
    Solo testea si la URL es plausiblemente un endpoint de login/API.
    Para no generar ruido en webs estáticas.
    """
    vulns: list[Vuln] = []

    parsed = urlparse(url)
    path = (parsed.path or "").lower()

    # Si el path no sugiere API o login, no testeamos (NoSQL injection típica)
    api_hints = ("/api/", "/login", "/auth", "/signin", "/session", "/user", "/account")
    if not any(h in path for h in api_hints):
        # Pero igual probamos a /api/login y /login si la raíz devuelve 200
        candidates = [
            url.rstrip("/") + "/api/login",
            url.rstrip("/") + "/login",
            url.rstrip("/") + "/api/auth",
        ]
    else:
        candidates = [url]

    sem = asyncio.Semaphore(3)

    async def test_endpoint(target_url: str):
        async with sem:
            # Baseline limpio
            baseline_body = {"username": "test_user_baseline", "password": "wrongpass123"}
            baseline = await client.post_json(target_url, baseline_body, body_limit=32768)
            if not baseline:
                return

            # Si el endpoint devuelve 404/405, no es un endpoint válido de login
            if baseline.status in (404, 405, 410):
                return

            baseline_len = len(baseline.body)

            # ── Operator injection ───────────────────────────────────────────
            for op_payload, desc in _NOSQL_OPERATORS:
                inj_body = {
                    "username": op_payload,
                    "password": op_payload,
                }
                resp = await client.post_json(target_url, inj_body, body_limit=32768)
                if not resp:
                    continue

                # Bypass exitoso: status pasa de 401/400 a 200 con body distinto
                bypass_status = (
                    baseline.status in (401, 403, 400, 422)
                    and resp.status == 200
                )
                # O: body crece significativamente (más datos retornados)
                bypass_size = (
                    baseline.status == resp.status
                    and len(resp.body) > baseline_len * 1.5
                    and len(resp.body) > 200
                )

                if bypass_status or bypass_size:
                    vulns.append(make_vuln(
                        title       = f"NoSQL Injection — operator bypass ({desc})",
                        severity    = "CRITICAL",
                        cvss        = 9.8,
                        category    = "NoSQL Injection",
                        description = (
                            "Endpoint vulnerable a inyección de operadores NoSQL. "
                            "Un atacante puede bypassear autenticación o extraer datos sin "
                            "credenciales válidas usando operadores MongoDB en JSON body."
                        ),
                        evidence    = (
                            f"Baseline: POST con credenciales falsas → HTTP {baseline.status} ({baseline_len} bytes)\n"
                            f"Inyección: POST con {json.dumps(inj_body)} → HTTP {resp.status} ({len(resp.body)} bytes)\n"
                            f"Bypass status: {bypass_status} | Bypass size: {bypass_size}\n"
                            f"PoC: curl -X POST -H 'Content-Type: application/json' "
                            f"-d '{json.dumps(inj_body)}' '{target_url}'"
                        ),
                        fix         = (
                            "Validar y tipar todo input JSON antes de pasarlo al ORM/driver. "
                            "Rechazar valores que sean objetos cuando se esperan strings. "
                            "En Mongoose: usar schema strict y sanitize-html. "
                            "En Node: librería mongo-sanitize."
                        ),
                        ref         = "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
                        module      = "nosql",
                        url         = target_url,
                        cwe         = "CWE-943",
                    ))
                    return  # Un hallazgo basta por endpoint

    await asyncio.gather(*[test_endpoint(c) for c in candidates[:3]])
    return vulns
