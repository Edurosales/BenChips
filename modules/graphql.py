"""
modules/graphql.py — Detección y análisis de endpoints GraphQL.

Busca endpoints comunes y lanza una Introspection Query.
Si el servidor devuelve el esquema (__schema), se considera vulnerable
a Information Disclosure severo.
"""

from __future__ import annotations

import asyncio
import json

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/graphql/v1",
    "/query"
]

INTROSPECTION_QUERY = {
    "query": "\n    query IntrospectionQuery {\n      __schema {\n        queryType { name }\n        mutationType { name }\n        subscriptionType { name }\n        types {\n          ...FullType\n        }\n        directives {\n          name\n          description\n          locations\n          args {\n            ...InputValue\n          }\n        }\n      }\n    }\n\n    fragment FullType on __Type {\n      kind\n      name\n      description\n      fields(includeDeprecated: true) {\n        name\n        description\n        args {\n          ...InputValue\n        }\n        type {\n          ...TypeRef\n        }\n        isDeprecated\n        deprecationReason\n      }\n      inputFields {\n        ...InputValue\n      }\n      interfaces {\n        ...TypeRef\n      }\n      enumValues(includeDeprecated: true) {\n        name\n        description\n        isDeprecated\n        deprecationReason\n      }\n      possibleTypes {\n        ...TypeRef\n      }\n    }\n\n    fragment InputValue on __InputValue {\n      name\n      description\n      type { ...TypeRef }\n      defaultValue\n    }\n\n    fragment TypeRef on __Type {\n      kind\n      name\n      ofType {\n        kind\n        name\n        ofType {\n          kind\n          name\n          ofType {\n            kind\n            name\n            ofType {\n              kind\n              name\n              ofType {\n                kind\n                name\n                ofType {\n                  kind\n                  name\n                  ofType {\n                    kind\n                    name\n                  }\n                }\n              }\n            }\n          }\n        }\n      }\n    }\n  "
}


async def run(
    client:    AsyncHTTPClient,
    base_url:  str,
) -> list[Vuln]:
    vulns: list[Vuln] = []
    sem = asyncio.Semaphore(3)

    # Limpiar trailing slash
    base_url = base_url.rstrip("/")

    async def check(path: str):
        target = f"{base_url}{path}"
        async with sem:
            # Petición GET básica primero para ver si acepta json/graphql
            resp = await client.session.post(
                target,
                json=INTROSPECTION_QUERY,
                headers=client._build_headers({"Content-Type": "application/json"}),
                allow_redirects=True,
                ssl=False
            )
            try:
                body = await resp.text()
                if resp.status in (200, 400):  # A veces devuelve 400 pero incluye el schema si hubo un error parcial
                    data = json.loads(body)
                    
                    # Verificar si __schema está en la respuesta
                    if "data" in data and "__schema" in data["data"]:
                        vulns.append(make_vuln(
                            title       = "GraphQL Introspection Abierta",
                            severity    = "HIGH",
                            cvss        = 7.5,
                            category    = "Information Disclosure",
                            description = (
                                f"El endpoint GraphQL en '{path}' permite Introspection Queries. "
                                "Esto expone el esquema completo de la API (tipos, queries, mutaciones), "
                                "facilitando enormemente descubrir fallos lógicos y endpoints ocultos."
                            ),
                            evidence    = f"Endpoint: {target}\nRespuesta contiene '__schema' validado.",
                            fix         = "Deshabilitar Introspection Query en entornos de producción.",
                            ref         = "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                            module      = "graphql",
                            url         = target,
                        ))
            except Exception:
                pass

    tasks = [check(p) for p in GRAPHQL_PATHS]
    if tasks:
        await asyncio.gather(*tasks)

    return vulns
