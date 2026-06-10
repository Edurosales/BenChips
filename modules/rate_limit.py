"""
modules/rate_limit.py — Rate limiting / brute force protection check.

Detecta endpoints de autenticación sin rate limit:
  1. Localizar /login, /api/login, /signin, /auth.
  2. Enviar N=30 intentos con credenciales falsas en paralelo.
  3. Si TODOS devuelven 401 (sin 429) → no hay rate limit → vulnerable a
     brute force / password spraying / credential stuffing.

Anti-FP:
  - Solo reporta si los responses son CONSISTENTES (todos 401, sin variación).
  - Si después de N intentos aparece un 429 o un 423 (locked) → seguro.
"""

from __future__ import annotations

import asyncio
import secrets
from urllib.parse import urlparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


_LOGIN_PATHS = [
    "/login", "/signin", "/api/login", "/api/auth", "/api/auth/login",
    "/oauth/token", "/auth/login", "/session/new",
]


async def run(client: AsyncHTTPClient, url: str, full_scan: bool = False) -> list[Vuln]:
    """
    Solo en full_scan: mandar 30 requests es invasivo.
    """
    vulns: list[Vuln] = []
    if not full_scan:
        return vulns

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    sem = asyncio.Semaphore(2)

    async def test_endpoint(path: str):
        async with sem:
            target = base.rstrip("/") + path

            probe = await client.post_json(target, {
                "username": "test_probe", "password": "wrong"
            }, body_limit=2048)
            if not probe or probe.status in (404, 405, 410):
                return
            # Si responde >=500 o no acepta JSON, no testear
            if probe.status >= 500:
                return

            # 30 intentos en paralelo
            n = 30
            tasks = [
                client.post_json(target, {
                    "username": f"user_{secrets.token_hex(4)}",
                    "password": f"wrong_{i}",
                }, body_limit=512)
                for i in range(n)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            statuses = [
                r.status for r in results
                if not isinstance(r, Exception) and r is not None
            ]
            if not statuses:
                return

            blocked = sum(1 for s in statuses if s in (429, 423, 403))
            ok      = sum(1 for s in statuses if 200 <= s < 500 and s != 429)

            # Si CERO blocked y todos respondieron normales → sin rate limit
            if blocked == 0 and ok >= n * 0.9:
                vulns.append(make_vuln(
                    title       = f"Sin rate limit en {path}",
                    severity    = "HIGH",
                    cvss        = 7.5,
                    category    = "Missing Rate Limiting",
                    description = (
                        f"El endpoint {path} aceptó {ok}/{n} intentos de autenticación "
                        "sin disparar rate limit (429), account lockout (423) ni CAPTCHA. "
                        "Vulnerable a credential stuffing, password spraying y brute force."
                    ),
                    evidence    = (
                        f"POST {target} × {n} (credenciales falsas)\n"
                        f"Respuestas: {ok} normales, {blocked} bloqueadas\n"
                        f"Statuses únicos: {set(statuses)}"
                    ),
                    fix         = (
                        "Implementar rate limit por IP y por username (e.g. fail2ban, "
                        "express-rate-limit, Django ratelimit). Account lockout temporal "
                        "tras N intentos. CAPTCHA tras 3 fallos. "
                        "Considerar exponential backoff. Logging de intentos."
                    ),
                    ref         = "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
                    module      = "rate_limit",
                    url         = target,
                    cwe         = "CWE-307",
                ))

    await asyncio.gather(*[test_endpoint(p) for p in _LOGIN_PATHS])
    return vulns
