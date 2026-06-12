"""
modules/graphql_idor.py — IDOR en GraphQL (acceso a objetos de otros usuarios).

GraphQL IDOR difiere del REST IDOR: usa IDs opacos (base64 "Type:123") o
UUIDs en queries como node(id: X) o user(id: X).

Detecta:
  1. node(id) query — Relay spec (base64 "Type:N")
  2. Queries directas a tipos con campo ID (user/account/order/profile)
  3. Acceso a datos de usuario N+1 cuando autenticado como N
  4. Campos PII en respuesta (email, phone, SSN, credit_card, address)

Anti-FP:
  - Solo reporta si la respuesta contiene PII real (regex específicos).
  - Compara respuesta con id propio vs id+1 — si hay datos diferentes, posible IDOR.
  - No reporta en errores/null (el servidor rechazó la query).
"""
from __future__ import annotations

import asyncio
import base64
import json as _json
import re
from urllib.parse import urlparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln

# Patrones PII para detectar datos de otro usuario
_PII_PATTERNS = [
    (re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'), "email"),
    (re.compile(r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b'),                 "phone"),
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),                              "SSN"),
    (re.compile(r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14})\b'),            "credit_card"),
    (re.compile(r'"(?:address|street)["\s]*:["\s]*"[^"]{10,}'),         "address"),
    (re.compile(r'"(?:phone|mobile|telephone)["\s]*:["\s]*"[^"]{7,}'),  "phone_field"),
    (re.compile(r'"(?:ssn|social_security)["\s]*:["\s]*"[^"]{4,}'),     "ssn_field"),
    (re.compile(r'"(?:password_hash|password_digest|hashed_password)["\s]*:["\s]*"[^"]{10,}'), "password_hash"),
]

_GQL_ENDPOINTS = ["/graphql", "/api/graphql", "/gql", "/query", "/api/query"]

# Tipos comunes en GraphQL que contienen datos de usuario
_USER_TYPES = ["User", "Account", "Profile", "Customer", "Member", "Viewer"]

# Queries de IDOR para probar
def _node_query(node_id: str) -> str:
    return _json.dumps({
        "query": f"""query {{ node(id: "{node_id}") {{ id ... on User {{ id email name phone address }} ... on Account {{ id email username balance }} ... on Profile {{ id email name }} }} }}"""
    })


def _type_query(type_name: str, field_id: int) -> str:
    tl = type_name.lower()
    return _json.dumps({
        "query": f"""query {{ {tl}(id: {field_id}) {{ id email name phone username address balance role isAdmin }} }}"""
    })


def _relay_id(type_name: str, numeric_id: int) -> str:
    return base64.b64encode(f"{type_name}:{numeric_id}".encode()).decode()


def _has_pii(text: str) -> list[str]:
    found = []
    for pattern, name in _PII_PATTERNS:
        if pattern.search(text):
            found.append(name)
    return found


async def run(
    client:    AsyncHTTPClient,
    url:       str,
    full_scan: bool = False,
) -> list[Vuln]:
    vulns: list[Vuln] = []
    found: set[str]   = set()
    sem = asyncio.Semaphore(4)

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    # Localizar endpoint GraphQL
    gql_endpoint: str | None = None
    for path in _GQL_ENDPOINTS:
        ep = f"{base}{path}"
        try:
            probe = await client.post_json(ep, {"query": "{__typename}"}, body_limit=4096)
            if probe and probe.status in range(200, 300) and "data" in (probe.text or ""):
                gql_endpoint = ep
                break
        except Exception:
            continue

    if not gql_endpoint:
        return vulns

    # ── 1. Introspection para descubrir tipos con ID ───────────────────────
    intro_query = _json.dumps({
        "query": """
        {
          __schema {
            types {
              name
              fields { name type { name kind ofType { name } } }
            }
          }
        }
        """
    })
    schema_types: list[str] = list(_USER_TYPES)
    try:
        async with sem:
            r = await client.post_json(gql_endpoint, _json.loads(intro_query), body_limit=131072)
        if r and r.status == 200:
            data = _json.loads(r.text or "{}")
            types_ = data.get("data", {}).get("__schema", {}).get("types", [])
            for t in types_:
                name = t.get("name", "")
                if not name or name.startswith("_"):
                    continue
                fields = [f["name"] for f in (t.get("fields") or [])]
                # Tipo con campo id + algún campo PII → candidato
                if "id" in fields and any(f in fields for f in ("email", "phone", "name", "username", "address", "balance")):
                    if name not in schema_types:
                        schema_types.append(name)
    except Exception:
        pass

    # ── 2. Obtener baseline con ID=1 ──────────────────────────────────────
    async def probe_id(type_name: str, id1: int, id2: int) -> Vuln | None:
        q1 = _type_query(type_name, id1)
        q2 = _type_query(type_name, id2)

        async with sem:
            r1 = await client.post_json(gql_endpoint, _json.loads(q1), body_limit=32768)
        if not r1 or r1.status not in range(200, 300):
            return None
        body1 = r1.text or ""
        if '"errors"' in body1 and '"data":null' in body1:
            return None  # Query inválida

        async with sem:
            r2 = await client.post_json(gql_endpoint, _json.loads(q2), body_limit=32768)
        if not r2 or r2.status not in range(200, 300):
            return None
        body2 = r2.text or ""
        if '"errors"' in body2 and '"data":null' in body2:
            return None

        # Ambos devolvieron datos — comparar PII
        pii1 = _has_pii(body1)
        pii2 = _has_pii(body2)

        if not pii1 and not pii2:
            return None  # sin datos sensibles en ninguno

        # Si ambos tienen datos PII diferentes → IDOR probable
        if pii2 and body1[:50] != body2[:50]:
            key = f"idor:{type_name}:{id2}"
            if key not in found:
                found.add(key)
                return make_vuln(
                    title       = f"GraphQL IDOR — Acceso a {type_name} ID={id2} (PII expuesto)",
                    severity    = "HIGH",
                    cvss        = 8.1,
                    category    = "IDOR",
                    description = (
                        f"La query GraphQL para '{type_name}' permite acceder a datos "
                        f"de objetos arbitrarios (ID={id2}) sin autorización. "
                        f"Datos sensibles expuestos: {', '.join(pii2)}. "
                        "Un atacante puede enumerar todos los usuarios/cuentas del sistema."
                    ),
                    evidence    = (
                        f"Endpoint: {gql_endpoint}\n"
                        f"Query: {type_name.lower()}(id: {id2}) {{ id email name phone ... }}\n"
                        f"Tipos PII encontrados: {', '.join(pii2)}\n"
                        f"Fragmento respuesta: {body2[:300]}\n"
                        f"PoC:\ncurl -X POST {gql_endpoint} "
                        f"-H 'Content-Type: application/json' "
                        f"-d '{_type_query(type_name, id2)}'"
                    ),
                    fix         = (
                        "Implementar autorización a nivel de objeto (object-level authorization). "
                        "Verificar que el usuario autenticado tiene acceso al ID solicitado. "
                        "Usar IDs opacos/UUIDs no predecibles. "
                        "Implementar field-level authorization en el resolver de GraphQL."
                    ),
                    ref         = "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                    module      = "graphql_idor",
                    url         = gql_endpoint,
                    cwe         = "CWE-639",
                    owasp       = "API1:2023",
                )
        return None

    # ── 3. Relay node(id) IDOR ────────────────────────────────────────────
    async def probe_node(type_name: str, numeric_id: int) -> Vuln | None:
        relay_id = _relay_id(type_name, numeric_id)
        q = {"query": f'{{ node(id: "{relay_id}") {{ id ... on {type_name} {{ id email name phone username }} }} }}'}
        async with sem:
            r = await client.post_json(gql_endpoint, q, body_limit=16384)
        if not r or r.status not in range(200, 300):
            return None
        body = r.text or ""
        if '"data":null' in body or '"errors"' in body:
            return None

        pii = _has_pii(body)
        if pii:
            key = f"node:{type_name}:{numeric_id}"
            if key not in found:
                found.add(key)
                return make_vuln(
                    title       = f"GraphQL IDOR via node(id) — {type_name} ID={numeric_id}",
                    severity    = "HIGH",
                    cvss        = 8.1,
                    category    = "IDOR",
                    description = (
                        f"La interface Relay 'node(id)' de GraphQL expone datos de '{type_name}' "
                        f"sin control de acceso. IDs Relay son predecibles (base64 'Type:N'). "
                        f"PII expuesto: {', '.join(pii)}."
                    ),
                    evidence    = (
                        f"Endpoint: {gql_endpoint}\n"
                        f"Relay ID: {relay_id} (= base64('{type_name}:{numeric_id}'))\n"
                        f"PII encontrado: {', '.join(pii)}\n"
                        f"Fragmento: {body[:250]}"
                    ),
                    fix         = (
                        "Validar autorización en el resolver de 'node'. "
                        "Usar UUIDs aleatorios en vez de IDs numéricos secuenciales. "
                        "No exponer el tipo del objeto en el ID codificado."
                    ),
                    ref         = "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                    module      = "graphql_idor",
                    url         = gql_endpoint,
                    cwe         = "CWE-639",
                    owasp       = "API1:2023",
                )
        return None

    # Lanzar pruebas: IDs 1, 2 y 3 para cada tipo
    tasks = []
    for t in schema_types[:8]:
        for probe_id_val in [1, 2, 3]:
            tasks.append(probe_id(t, 1, probe_id_val + 1))
            tasks.append(probe_node(t, probe_id_val))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, Vuln):
            vulns.append(r)

    return vulns
