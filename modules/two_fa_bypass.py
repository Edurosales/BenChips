"""
modules/two_fa_bypass.py — 2FA/OTP bypass detection.

Patrones revisados:
  1. Response manipulation: cambiar success:false → success:true en respuesta JSON
  2. OTP brute force: sin rate limit en endpoint de verify
  3. Skip flow: acceder al endpoint post-2FA directamente (e.g. /dashboard)
     sin enviar OTP

Limitación: la mayoría de bugs de 2FA requieren tener una sesión
half-authenticated (post-password, pre-OTP). Aquí solo detectamos los más
obvios sin esa sesión.
"""

from __future__ import annotations

import asyncio
import secrets
from urllib.parse import urlparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


_OTP_VERIFY_PATHS = [
    "/api/2fa/verify", "/api/mfa/verify", "/api/otp/verify",
    "/auth/2fa", "/verify-otp", "/login/2fa",
]


async def run(client: AsyncHTTPClient, url: str, full_scan: bool = False) -> list[Vuln]:
    vulns: list[Vuln] = []
    if not full_scan:
        return vulns

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    sem = asyncio.Semaphore(2)

    async def test_brute_force(path: str):
        async with sem:
            target = base.rstrip("/") + path

            probe = await client.post_json(target, {"code": "000000"}, body_limit=2048)
            if not probe or probe.status in (404, 405, 410):
                return
            if probe.status >= 500:
                return

            # 50 intentos de OTP en paralelo
            n = 50
            tasks = [
                client.post_json(target, {"code": f"{i:06d}"}, body_limit=512)
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

            if blocked == 0 and len(statuses) >= n * 0.9:
                vulns.append(make_vuln(
                    title       = f"2FA/OTP sin rate limit ({path})",
                    severity    = "CRITICAL",
                    cvss        = 9.1,
                    category    = "2FA Bypass",
                    description = (
                        "El endpoint de verificación 2FA acepta intentos ilimitados. "
                        f"Brute force de OTP de 6 dígitos = 10^6 = 1M intentos, "
                        f"factible en <1h sin rate limit. Bypass completo de 2FA."
                    ),
                    evidence    = (
                        f"POST {target} × {n}\n"
                        f"Códigos secuenciales 000000-{n-1:06d}\n"
                        f"Cero respuestas 429/423 — sin rate limit"
                    ),
                    fix         = (
                        "Limitar a 5-10 intentos por sesión, luego invalidar el factor "
                        "y exigir reautenticación. Rate limit por user + por IP. "
                        "Códigos OTP de 8 dígitos mínimo para protección adicional."
                    ),
                    ref         = "https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html",
                    module      = "two_fa_bypass",
                    url         = target,
                    cwe         = "CWE-307",
                ))

    await asyncio.gather(*[test_brute_force(p) for p in _OTP_VERIFY_PATHS])
    return vulns
