"""
modules/business_logic.py — Pruebas de lógica de negocio.

Detecta:
  - Precios / cantidades negativas o cero en APIs de compra/carrito
  - Desbordamiento de entero en cantidades (int32 max → negativo en DB)
  - Coupon/descuento aplicado múltiples veces
  - Transferencia de 0 o cantidad negativa (double-spend)
  - Free item bypass (precio 0 en checkout)

Anti-FP:
  - Solo reporta si la respuesta indica éxito (2xx) Y hay indicadores de valor anómalo reflejado.
  - No reporta en errores 4xx (el servidor los rechazó correctamente).
"""
from __future__ import annotations

import asyncio
import json as _json
from urllib.parse import urlparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln

# Endpoints típicos de lógica de negocio
_COMMERCE_PATHS = [
    "/api/cart", "/api/cart/add", "/api/order", "/api/checkout",
    "/api/purchase", "/api/payment", "/api/transfer", "/api/buy",
    "/api/coupon", "/api/discount", "/api/promo", "/api/redeem",
    "/api/v1/cart", "/api/v1/order", "/api/v1/checkout",
    "/cart", "/order", "/checkout", "/purchase",
    "/api/wallet/transfer", "/api/balance/transfer",
]

# Campos y valores anómalos para testear
_PRICE_PROBES = [
    ("price",    -1),
    ("amount",   -1),
    ("quantity", -1),
    ("total",    -1),
    ("price",    0),
    ("amount",   0),
    ("quantity", 0),
    ("quantity", 2147483647),   # INT32_MAX — overflow en muchas DBs
    ("quantity", 9999999999),   # overflow 64-bit
    ("price",    0.001),        # precio casi cero (float truncado)
    ("discount", 101),          # descuento > 100%
    ("discount", -1),           # descuento negativo → precio mayor (o error)
]

_COUPON_PROBES = [
    {"code": "DISCOUNT10", "times": 5},   # reuso de cupón
    {"promo_code": "FREE100"},
    {"coupon": "ADMIN"},
    {"voucher": "0"},
]

# Indicadores de éxito en la respuesta (el servidor procesó el valor anómalo)
_SUCCESS_INDICATORS = [
    '"success":true', '"status":"ok"', '"status":"success"',
    '"result":"ok"', '"completed":true', '"processed":true',
    '"order_id":', '"transaction_id":', '"payment_id":',
    '"charged":0', '"total":0', '"amount":0',
    '"total":-', '"amount":-', '"price":-',
]


async def run(
    client:     AsyncHTTPClient,
    url:        str,
    full_scan:  bool = False,
    extra_urls: list[str] | None = None,
) -> list[Vuln]:
    vulns: list[Vuln] = []
    found: set[str]   = set()
    sem = asyncio.Semaphore(4)

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    # Candidatos: paths conocidos + URLs del crawler con keywords de comercio
    candidates: list[str] = []
    for path in _COMMERCE_PATHS:
        candidates.append(f"{base}{path}")
    if extra_urls:
        for u in extra_urls:
            low = u.lower()
            if any(kw in low for kw in ("cart", "order", "checkout", "pay", "buy", "purchase",
                                         "transfer", "coupon", "discount", "promo", "redeem")):
                candidates.append(u)

    async def probe_price(endpoint: str, field: str, value: object):
        body = {"item_id": 1, "product_id": 1, field: value, "quantity": abs(value) if isinstance(value, (int, float)) else 1}
        async with sem:
            resp = await client.post_json(endpoint, body, body_limit=8192)
        if not resp or resp.status not in range(200, 300):
            return  # 4xx = servidor rechazó — no hay vuln
        resp_body = (resp.text or "").lower()
        for ind in _SUCCESS_INDICATORS:
            if ind in resp_body:
                key = f"{field}:{value}:{endpoint}"
                if key not in found:
                    found.add(key)
                    sev = "HIGH" if value in (-1, 0) or (isinstance(value, int) and value > 2_000_000_000) else "MEDIUM"
                    cvss = 8.1 if sev == "HIGH" else 6.5
                    desc_detail = {
                        -1:          "Un precio o cantidad negativa fue aceptado — podría generar crédito al atacante en vez de cobrarle.",
                        0:           "Un precio/cantidad de cero fue aceptado — el atacante obtiene el item gratis.",
                        2147483647:  "Desbordamiento INT32 (2^31-1) aceptado — en muchas DBs wrappea a valor negativo.",
                        9999999999:  "Cantidad enormemente grande aceptada — overflow o abuso de límite.",
                    }.get(value, f"Valor anómalo '{value}' aceptado.")
                    vulns.append(make_vuln(
                        title       = f"Business Logic — {field}={value} aceptado en '{endpoint}'",
                        severity    = sev,
                        cvss        = cvss,
                        category    = "Business Logic",
                        description = (
                            f"El endpoint '{endpoint}' aceptó {field}={value} y devolvió éxito. "
                            f"{desc_detail}"
                        ),
                        evidence    = (
                            f"Endpoint: {endpoint}\n"
                            f"Payload: {_json.dumps(body)}\n"
                            f"Status: HTTP {resp.status}\n"
                            f"Indicador de éxito: '{ind}' en respuesta\n"
                            f"PoC: curl -X POST {endpoint} -H 'Content-Type: application/json' "
                            f"-d '{_json.dumps(body)}'"
                        ),
                        fix         = (
                            "Validar en el servidor: precio > 0, cantidad > 0 y < límite razonable. "
                            "Nunca confiar en el precio enviado por el cliente — calcularlo desde DB. "
                            "Implementar transacciones atómicas para prevenir race conditions. "
                            "Usar tipos unsigned o validar rangos antes de insertar en DB."
                        ),
                        ref         = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
                        module      = "business_logic",
                        url         = endpoint,
                        cwe         = "CWE-840",
                        owasp       = "A04:2021",
                    ))
                break

    async def probe_coupon_reuse(endpoint: str, coupon_body: dict):
        """Intenta aplicar el mismo cupón dos veces en el mismo 'session'."""
        async with sem:
            r1 = await client.post_json(endpoint, coupon_body, body_limit=8192)
        if not r1 or r1.status not in range(200, 300):
            return
        async with sem:
            r2 = await client.post_json(endpoint, coupon_body, body_limit=8192)
        if not r2 or r2.status not in range(200, 300):
            return  # segundo uso rechazado — correcto

        key = f"coupon:{endpoint}"
        if key not in found:
            found.add(key)
            vulns.append(make_vuln(
                title       = f"Business Logic — Cupón/Promo Reutilizable sin límite: '{endpoint}'",
                severity    = "MEDIUM",
                cvss        = 6.5,
                category    = "Business Logic",
                description = (
                    f"El endpoint '{endpoint}' permite aplicar el mismo código de descuento "
                    "múltiples veces. Un atacante puede acumular descuentos ilimitados."
                ),
                evidence    = (
                    f"Endpoint: {endpoint}\n"
                    f"Payload: {_json.dumps(coupon_body)}\n"
                    f"1ra aplicación: HTTP {r1.status} (éxito)\n"
                    f"2da aplicación: HTTP {r2.status} (también éxito — debería ser 4xx)"
                ),
                fix         = (
                    "Marcar el cupón como usado tras la primera aplicación (en DB, atómicamente). "
                    "Vincular el cupón a user_id para prevenir reutilización cross-account. "
                    "Implementar rate limiting en endpoints de cupones."
                ),
                ref         = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
                module      = "business_logic",
                url         = endpoint,
                cwe         = "CWE-841",
                owasp       = "A04:2021",
            ))

    # Lanzar todas las pruebas
    tasks = []
    for ep in candidates[:15]:
        for field, val in _PRICE_PROBES:
            tasks.append(probe_price(ep, field, val))

    coupon_eps = [ep for ep in candidates if any(kw in ep.lower() for kw in ("coupon", "promo", "discount", "redeem", "voucher"))]
    for ep in coupon_eps[:5]:
        for cb in _COUPON_PROBES:
            tasks.append(probe_coupon_reuse(ep, cb))

    await asyncio.gather(*tasks)
    return vulns
