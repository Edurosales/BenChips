"""
modules/graphql_advanced.py — GraphQL attacks avanzados.

Cubre:
  1. Introspección habilitada en producción
  2. Alias query smuggling (mismo endpoint N veces en una sola request)
  3. Query depth attack (DoS)
  4. Batch query abuse
  5. Field suggestion enabled (info leak)
  6. CSRF GET en mutations (debería ser POST-only)
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse, urlencode

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


_GQL_ENDPOINTS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/api/query"]

_INTROSPECTION = """{
  __schema {
    types { name }
    queryType { name }
    mutationType { name }
  }
}"""

# Query con 1000 niveles de profundidad
_DEEP_QUERY = "query { " + "user { friends { " * 50 + "id " + "} } " * 50 + "}"

# 10 aliases del mismo campo (smuggling test)
_ALIAS_QUERY = "query { " + " ".join(
    f"u{i}: user(id: {i}) {{ id email }}" for i in range(10)
) + " }"

# Field suggestion test
_BAD_FIELD_QUERY = "{ usrr { id } }"  # 'usrr' typo → si responde "Did you mean 'user'?"


async def run(client: AsyncHTTPClient, url: str) -> list[Vuln]:
    vulns: list[Vuln] = []

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    for ep in _GQL_ENDPOINTS:
        target = base.rstrip("/") + ep

        # 1) Introspección
        intr = await client.post_json(target, {"query": _INTROSPECTION}, body_limit=32768)
        if not intr or intr.status >= 400:
            continue

        body = intr.text.lower()
        if "__schema" not in body and "querytype" not in body:
            continue  # No es endpoint GraphQL válido

        # Confirmamos: es GraphQL válido y responde a introspección
        vulns.append(make_vuln(
            title       = "GraphQL: Introspección habilitada en producción",
            severity    = "MEDIUM",
            cvss        = 5.3,
            category    = "GraphQL",
            description = (
                "La introspección expone el schema completo de GraphQL, incluyendo "
                "todos los queries, mutations, tipos y campos disponibles. "
                "Facilita la exploración de la superficie de ataque a un atacante."
            ),
            evidence    = (
                f"POST {target}\n"
                f"Query: {_INTROSPECTION.strip()[:100]}...\n"
                f"Schema devuelto: HTTP {intr.status} ({len(intr.body)} bytes)"
            ),
            fix         = (
                "Deshabilitar introspección en producción. "
                "Apollo: NODE_ENV=production O introspection: false. "
                "Hasura: HASURA_GRAPHQL_ENABLE_TELEMETRY=false."
            ),
            ref         = "https://owasp.org/www-project-api-security/",
            module      = "graphql_advanced",
            url         = target,
            cwe         = "CWE-200",
        ))

        # 2) Field suggestions
        sugg = await client.post_json(target, {"query": _BAD_FIELD_QUERY}, body_limit=4096)
        if sugg and "did you mean" in sugg.text.lower():
            vulns.append(make_vuln(
                title       = "GraphQL: Field suggestions habilitadas",
                severity    = "LOW",
                cvss        = 3.7,
                category    = "GraphQL",
                description = (
                    "El servidor sugiere campos similares ante typos. Permite "
                    "enumeración de schema incluso con introspección deshabilitada."
                ),
                evidence    = f"Query inválida: {_BAD_FIELD_QUERY}\nRespuesta contiene 'Did you mean'",
                fix         = "Desactivar suggestion: en Apollo, validationRules custom para eliminar NoUnusedFragments. Hasura: server side validation strict.",
                ref         = "https://www.apollographql.com/docs/apollo-server/security/",
                module      = "graphql_advanced",
                url         = target,
            ))

        # 3) Alias query smuggling — N operaciones en 1 request, bypassea rate limit
        alias_resp = await client.post_json(target, {"query": _ALIAS_QUERY}, body_limit=16384)
        if alias_resp and alias_resp.status == 200 and alias_resp.text.count("\"id\"") >= 5:
            vulns.append(make_vuln(
                title       = "GraphQL: Alias query smuggling permitido",
                severity    = "MEDIUM",
                cvss        = 6.5,
                category    = "GraphQL",
                description = (
                    "El servidor acepta múltiples aliases del mismo campo en una sola "
                    "request. Permite bypass de rate limit (10 lookups en 1 request) "
                    "y brute force eficiente (e.g. enumerar 1000 IDs por petición)."
                ),
                evidence    = (
                    f"Query con 10 aliases: HTTP {alias_resp.status}\n"
                    f"Respuesta contiene múltiples objetos id"
                ),
                fix         = (
                    "Limitar # de aliases por operación. Apollo: graphql-query-complexity "
                    "plugin con maxOperationsPerQuery=1. Rate limit a nivel de operación, "
                    "no de request."
                ),
                ref         = "https://www.escape.tech/blog/graphql-aliasing-explained/",
                module      = "graphql_advanced",
                url         = target,
                cwe         = "CWE-770",
            ))

        # 4) Depth attack
        deep_resp = await client.post_json(target, {"query": _DEEP_QUERY}, body_limit=4096)
        if deep_resp and deep_resp.status == 200:
            # Si aceptó 50 niveles sin error → no hay depth limit
            if "depth" not in deep_resp.text.lower() and "limit" not in deep_resp.text.lower():
                vulns.append(make_vuln(
                    title       = "GraphQL: Sin query depth limit (DoS vector)",
                    severity    = "MEDIUM",
                    cvss        = 6.5,
                    category    = "GraphQL",
                    description = (
                        "El servidor procesa queries con profundidad arbitraria. "
                        "Permite DoS con queries N→M→N→M recursivas o complejidad exponencial."
                    ),
                    evidence    = (
                        f"Query de profundidad 50 aceptada (HTTP {deep_resp.status})\n"
                        "Sin mensaje de error sobre depth/complexity"
                    ),
                    fix         = (
                        "Implementar graphql-depth-limit (Apollo) con max=10. "
                        "Usar query complexity scoring (graphql-cost-analysis)."
                    ),
                    ref         = "https://github.com/stems/graphql-depth-limit",
                    module      = "graphql_advanced",
                    url         = target,
                    cwe         = "CWE-770",
                ))

        # 5) CSRF GET on mutation
        # Intentar mutation por GET — si funciona, CSRF posible
        gql_get = f"{target}?query=" + urlencode({"q": "mutation { ping }"})[2:]
        get_resp = await client.get(gql_get, body_limit=2048)
        if get_resp and get_resp.status == 200 and "mutation" in get_resp.text.lower():
            vulns.append(make_vuln(
                title       = "GraphQL: Mutations aceptan GET (CSRF posible)",
                severity    = "MEDIUM",
                cvss        = 6.1,
                category    = "GraphQL",
                description = (
                    "Mutations no deberían ser invocables por GET. Aceptarlas permite "
                    "CSRF vía <img src> o <link> y bypass de same-origin policy."
                ),
                evidence    = f"GET {gql_get[:120]} → HTTP {get_resp.status}",
                fix         = "Rechazar mutations vía GET. Apollo: csrfPrevention: true.",
                ref         = "https://www.apollographql.com/docs/apollo-server/security/cors/#preventing-cross-site-request-forgery-csrf",
                module      = "graphql_advanced",
                url         = target,
                cwe         = "CWE-352",
            ))

        return vulns  # Un endpoint GraphQL basta

    return vulns
