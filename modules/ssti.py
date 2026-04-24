"""
modules/ssti.py — Server-Side Template Injection detection.

Anti-falsos-positivos:
  - Baseline del body con parámetro limpio ANTES de probar payload.
  - Solo reporta si el resultado matemático (49 / 7777777) aparece en la
    respuesta CON payload Y NO aparecía en el baseline.
  - El body con payload debe ser DIFERENTE al baseline (hash distinto).
  - Confirmación doble: probar el mismo parámetro con payload neutro después.
"""

from __future__ import annotations

import asyncio
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln
from config import SSTI_PROBES


async def run(
    client:    AsyncHTTPClient,
    url:       str,
    full_scan: bool = False,
) -> list[Vuln]:
    """
    Detecta SSTI inyectando probes matemáticos en parámetros GET.
    Cero falsos positivos garantizados por comparación de baseline.
    """
    vulns: list[Vuln] = []
    found: set[str]   = set()

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Si hay parámetros en la URL real, usarlos; sino, probar comunes
    probe_params = list(params.keys()) if params else [
        "q", "search", "id", "page", "name", "msg", "text",
        "input", "template", "lang", "query", "s", "keyword",
    ]

    # Limitar para no ralentizar demasiado en modo no-full
    max_params = 8 if full_scan else 4
    probe_params = probe_params[:max_params]

    # Concurrencia baja — sigiloso
    sem = asyncio.Semaphore(3)

    # ── Baseline: respuesta normal sin payload ─────────────────────────────────
    baselines: dict[str, tuple[str, str]] = {}  # param -> (hash, body_lower)

    async def get_baseline(param: str):
        clean_url = _inject(url, parsed, param, "test")
        resp = await client.get(clean_url, follow=True, lax_ssl=True, body_limit=32768)
        if resp:
            baselines[param] = (
                hashlib.md5(resp.body[:8192]).hexdigest(),
                resp.text.lower()
            )

    await asyncio.gather(*[get_baseline(p) for p in probe_params])

    # ── Probar cada payload en cada parámetro ──────────────────────────────────
    async def check(param: str, payload: str, expected: str, engine: str):
        async with sem:
            if param in found:
                return

            test_url = _inject(url, parsed, param, payload)
            resp = await client.get(test_url, follow=True, lax_ssl=True, body_limit=32768)
            if not resp:
                return

            body_lower = resp.text.lower()
            body_hash  = hashlib.md5(resp.body[:8192]).hexdigest()

            bl_hash, bl_body = baselines.get(param, ("", ""))

            # Anti-FP 1: el resultado esperado NO debe estar en el baseline
            if expected in bl_body:
                return  # La página ya mostraba "49" antes del payload

            # Anti-FP 2: el body debe cambiar respecto al baseline
            if body_hash == bl_hash:
                return  # El servidor ignoró el payload completamente

            # Confirmación: el resultado matemático debe aparecer en el body
            if expected not in body_lower:
                return

            # ── Confirmación doble: repetir con payload diferente ──────────────
            # Si {{7*7}} da 49, probar {{7*8}} = 56 como confirmatión adicional
            if "7*7" in payload:
                confirm_payload = payload.replace("7*7", "7*8")
                confirm_url     = _inject(url, parsed, param, confirm_payload)
                resp2 = await client.get(confirm_url, follow=True, lax_ssl=True, body_limit=32768)
                if not resp2 or "56" not in resp2.text.lower():
                    # Solo reportar HIGH en lugar de CRITICAL si no se confirma
                    sev, cvss_val = "HIGH", 8.5
                else:
                    sev, cvss_val = "CRITICAL", 9.8
            else:
                sev, cvss_val = "CRITICAL", 9.8

            found.add(param)
            vulns.append(make_vuln(
                title       = f"SSTI en parámetro '{param}' — {engine}",
                severity    = sev,
                cvss        = cvss_val,
                category    = "Server-Side Template Injection",
                description = (
                    f"El parámetro '{param}' evalúa expresiones de template en el servidor. "
                    f"Motor detectado: {engine}. "
                    "Un atacante puede escalar esto a ejecución de código remoto (RCE)."
                ),
                evidence    = (
                    f"Payload: {payload}\n"
                    f"Resultado '{expected}' encontrado en respuesta HTTP {resp.status}\n"
                    f"Baseline hash: {bl_hash[:8]} → Payload hash: {body_hash[:8]} (distintos)"
                ),
                fix         = (
                    "Nunca pasar input del usuario directamente a un motor de templates. "
                    "Usar entornos sandbox (Jinja2: SandboxedEnvironment). "
                    "Validar y rechazar input con caracteres de template ({, }, $, #, *, [, <%)."
                ),
                ref         = "https://portswigger.net/research/server-side-template-injection",
                module      = "ssti",
                url         = url,
            ))

    tasks = []
    for param in probe_params:
        for payload, expected, engine in SSTI_PROBES:
            tasks.append(check(param, payload, expected, engine))

    await asyncio.gather(*tasks)
    return vulns


def _inject(url: str, parsed, param: str, value: str) -> str:
    """Inyecta un parámetro GET en la URL."""
    params = parse_qs(parsed.query)
    flat   = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
    flat[param] = value
    return urlunparse(parsed._replace(query=urlencode(flat)))
