"""
modules/paths.py — Escaneo de rutas sensibles con detección de soft-404.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln
from config import SENSITIVE_PATHS


async def run(
    client:      AsyncHTTPClient,
    url:         str,
    concurrency: int = 15,
) -> tuple[list[Vuln], list[dict]]:
    """
    Escanea rutas sensibles con detección de soft-404.
    Retorna (vulns, found_paths_list).
    """
    vulns:       list[Vuln] = []
    found_paths: list[dict] = []

    parsed   = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    hostname = parsed.hostname or ""

    # Establecer baseline soft-404
    await client.establish_baseline(base_url)

    sem = asyncio.Semaphore(concurrency)

    async def check_path(path: str, sev: str, cvss: float, desc: str):
        async with sem:
            target = base_url.rstrip("/") + path
            resp   = await client.get(target, follow=False, lax_ssl=True, body_limit=32768)

            if not resp:
                return

            # Ignorar 4xx (excepto 401/403) y 5xx
            if resp.status in (400, 404, 405, 410, 500, 503):
                return

            # Si es redirect (301, 302, 303, 307), la mayoría de las veces el archivo
            # NO está expuesto, sino que te envía al index o al login.
            # IGNORAMOS redirects por ser la principal causa de falsos positivos en paths.
            if resp.status in (301, 302, 303, 307, 308):
                return

            # Soft-404 detection
            if client.is_soft_404(hostname, resp.status, resp.body):
                return

            # Si la respuesta es 200 pero súper vacía (ej. 0 bytes), probablemente sea descartada
            if resp.status == 200 and len(resp.body) < 5:
                return

            # 200, 401, 403 — el path existe o está estrictamente denegado
            found_paths.append({
                "path":   path,
                "status": resp.status,
                "sev":    sev,
                "cvss":   cvss,
                "desc":   desc,
                "size":   len(resp.body),
            })

            # 401/403 — existe pero protegido (menor severidad)
            if resp.status in (401, 403):
                sev_adj  = "LOW"   if sev in ("CRITICAL", "HIGH") else sev
                cvss_adj = min(cvss, 3.1)
                title    = f"Ruta protegida encontrada: {path}"
                desc_adj = f"{desc} — Protegida (HTTP {resp.status}) pero confirmada su existencia."
            else:
                sev_adj  = sev
                cvss_adj = cvss
                title    = f"Ruta sensible expuesta: {path}"
                desc_adj = desc

            vulns.append(make_vuln(
                title       = title,
                severity    = sev_adj,
                cvss        = cvss_adj,
                category    = "Sensitive Paths",
                description = desc_adj,
                evidence    = f"GET {path} → HTTP {resp.status} ({len(resp.body)} bytes)",
                fix         = (
                    f"Restringir acceso a {path} con autenticación o eliminarlo si no es necesario. "
                    "Verificar que no exponga datos sensibles."
                ),
                ref         = "https://owasp.org/www-project-web-security-testing-guide/",
                module      = "paths",
            ))

    tasks = [check_path(p, s, c, d) for p, s, c, d in SENSITIVE_PATHS]
    await asyncio.gather(*tasks)

    found_paths.sort(key=lambda x: x["path"])
    return vulns, found_paths
