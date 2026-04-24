"""
modules/waf.py — Detección de WAF/CDN y técnicas de bypass para encontrar IP real.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Optional

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln
from config import WAF_SIGNATURES


async def run(client: AsyncHTTPClient, url: str, hostname: str) -> tuple[list[Vuln], dict]:
    """
    Detecta WAF/CDN por headers y comportamiento.
    Retorna (vulns, info_dict).
    """
    vulns: list[Vuln] = []
    info  = {"waf": None, "cdn": None, "real_ip_hints": []}

    resp = await client.get(url, lax_ssl=True)
    if not resp:
        return vulns, info

    hdrs_str = " ".join(f"{k}:{v}" for k, v in resp.headers.items()).lower()

    for waf_name, sigs in WAF_SIGNATURES.items():
        if any(sig in hdrs_str for sig in sigs):
            info["waf"] = waf_name
            break

    # ── Detectar si WAF puede estar ocultando IP real ──────────────────────────
    if info["waf"] in ("Cloudflare", "Fastly", "Akamai", "AWS WAF"):
        real_ips = await _find_real_ip(hostname)
        if real_ips:
            info["real_ip_hints"] = real_ips
            vulns.append(make_vuln(
                title       = f"WAF detectado: {info['waf']} — posible IP real expuesta",
                severity    = "MEDIUM",
                cvss        = 5.3,
                category    = "WAF/CDN",
                description = (
                    f"El sitio usa {info['waf']} pero pistas de IP directa fueron encontradas. "
                    "Si la IP real es accesible, el WAF puede bypassearse completamente."
                ),
                evidence    = f"Posibles IPs directas: {', '.join(real_ips[:3])}",
                fix         = (
                    "Asegurar que el servidor origen solo acepte conexiones desde IPs del WAF/CDN. "
                    "Agregar regla de firewall para bloquear acceso directo."
                ),
                ref         = "https://blog.detectify.com/2019/07/31/bypassing-cloudflare-waf/",
                module      = "waf",
            ))

    # ── WAF no detectado — posible exposición directa ─────────────────────────
    if not info["waf"]:
        vulns.append(make_vuln(
            title       = "Sin WAF/CDN detectado",
            severity    = "INFO",
            cvss        = 0.0,
            category    = "WAF/CDN",
            description = "No se detectó ningún WAF o CDN. El servidor está expuesto directamente a internet.",
            evidence    = "Ninguna firma de WAF encontrada en headers HTTP",
            fix         = "Considerar Cloudflare, AWS WAF, o similar para protección adicional.",
            ref         = "https://owasp.org/www-project-web-application-firewall/",
            module      = "waf",
        ))

    return vulns, info


async def _find_real_ip(hostname: str) -> list[str]:
    """
    Intenta encontrar la IP real detrás de un CDN vía subdominios comunes
    que podrían no estar protegidos.
    """
    candidates = []
    subdomains  = ["direct", "origin", "backend", "mail", "ftp", "cpanel"]

    loop = asyncio.get_event_loop()

    async def resolve(sub: str):
        fqdn = f"{sub}.{hostname}"
        try:
            result = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(fqdn, None, socket.AF_INET)
            )
            ips = list({r[4][0] for r in result})
            return ips
        except Exception:
            return []

    results = await asyncio.gather(*[resolve(s) for s in subdomains], return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            candidates.extend(r)

    return list(dict.fromkeys(candidates))
