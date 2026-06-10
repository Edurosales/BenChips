"""
modules/race_condition.py — Race condition / TOCTOU testing.

Detecta endpoints sin locking adecuado enviando N requests paralelos al mismo
endpoint con la misma carga. Mide cuántos devolvieron 200 OK (esperado: 1 si
hay locking, N si no).

Casos típicos:
  - Coupon redemption (mismo cupón aplicado N veces)
  - Fund transfer (overdraft mediante doble débito)
  - Account creation (mismo username/email)
  - Like/Vote (contar más allá del 1 esperado)

Limitaciones:
  - Solo detecta endpoints POST/PUT autenticados o con state.
  - Requiere conocer el endpoint vulnerable (usuario lo provee, o se usa
    una lista heurística común).

Anti-FP:
  - Comparación con baseline secuencial (mismo endpoint llamado N veces NO
    en paralelo, contar 200s).
  - Si paralelo y secuencial dan el mismo número de 200s → no hay race.
  - Solo reporta si paralelo > secuencial * 1.5.
"""

from __future__ import annotations

import asyncio
import time
from urllib.parse import urlparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


# Endpoints heurísticos donde típicamente hay races
_RACE_CANDIDATES = [
    ("/api/coupon/redeem", {"code": "TEST"}),
    ("/api/vote",          {"item_id": 1}),
    ("/api/like",          {"post_id": 1}),
    ("/api/follow",        {"user_id": 1}),
    ("/api/cart/add",      {"product_id": 1, "qty": 1}),
    ("/api/withdraw",      {"amount": 1}),
    ("/api/transfer",      {"to": "x", "amount": 1}),
]


async def run(client: AsyncHTTPClient, url: str, full_scan: bool = False) -> list[Vuln]:
    """
    Solo se ejecuta en full_scan (es invasivo: dispara 20 requests por endpoint).
    """
    vulns: list[Vuln] = []
    if not full_scan:
        return vulns

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    sem = asyncio.Semaphore(2)  # solo 2 endpoints simultáneos

    async def test_endpoint(path: str, body: dict):
        async with sem:
            target = base.rstrip("/") + path

            # Probe: existe el endpoint?
            probe = await client.post_json(target, body, body_limit=8192)
            if not probe or probe.status in (404, 405, 410):
                return

            # No probar si la primera no fue exitosa o pseudo-exitosa
            if probe.status >= 500:
                return

            n = 20

            # ── Secuencial (baseline) ────────────────────────────────────────
            seq_ok = 0
            for _ in range(n):
                r = await client.post_json(target, body, body_limit=2048)
                if r and 200 <= r.status < 300:
                    seq_ok += 1

            # ── Paralelo ─────────────────────────────────────────────────────
            await asyncio.sleep(0.5)
            tasks = [client.post_json(target, body, body_limit=2048) for _ in range(n)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            par_ok = sum(
                1 for r in results
                if not isinstance(r, Exception) and r and 200 <= r.status < 300
            )

            # ── Análisis ─────────────────────────────────────────────────────
            # Race si paralelo aprueba MÁS veces que secuencial (sugiere no-locking)
            # Y secuencial limita correctamente (típicamente 1)
            if seq_ok <= 2 and par_ok >= 5 and par_ok > seq_ok * 2:
                vulns.append(make_vuln(
                    title       = f"Race Condition (TOCTOU) en {path}",
                    severity    = "HIGH",
                    cvss        = 7.5,
                    category    = "Race Condition",
                    description = (
                        f"El endpoint {path} permite múltiples ejecuciones simultáneas "
                        "exitosas para la misma operación, indicando falta de locking. "
                        "Explotable como double-spend (cupón aplicado N veces, withdrawal "
                        "duplicado, like/vote inflation, etc)."
                    ),
                    evidence    = (
                        f"Endpoint: POST {target}\n"
                        f"N requests: {n}\n"
                        f"Secuencial (1 a la vez): {seq_ok} exitosos\n"
                        f"Paralelo (todos a la vez): {par_ok} exitosos\n"
                        f"Ratio: {par_ok/max(seq_ok,1):.1f}x más respuestas exitosas en paralelo"
                    ),
                    fix         = (
                        "Implementar locking pesimista (SELECT FOR UPDATE) o optimista "
                        "(version column + CAS). Usar transacciones DB para operaciones críticas. "
                        "Considerar rate limit + idempotency keys en API gateway."
                    ),
                    ref         = "https://portswigger.net/research/smashing-the-state-machine",
                    module      = "race_condition",
                    url         = target,
                    cwe         = "CWE-362",
                    confidence  = 80,
                ))

    await asyncio.gather(*[test_endpoint(p, b) for p, b in _RACE_CANDIDATES])
    return vulns
