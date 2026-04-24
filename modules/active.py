"""
modules/active.py — Pruebas activas: SQLi, XSS reflejado, Path Traversal, SSRF.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln
from config import (
    SQLI_PAYLOADS, SQLI_ERROR_PATTERNS,
    SQLI_BLIND_PAYLOADS, SQLI_BLIND_SLEEP, SQLI_BLIND_MARGIN,
    XSS_PAYLOADS, TRAVERSAL_PAYLOADS,
)

# ─── SSRF payloads ────────────────────────────────────────────────────────────
SSRF_PARAMS = ["url", "path", "dest", "redirect", "uri", "src", "image", "load", "fetch", "api"]
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",   # AWS metadata
    "http://metadata.google.internal/",            # GCP metadata
    "http://127.0.0.1/",                           # localhost
    "http://[::1]/",                               # IPv6 localhost
    "file:///etc/passwd",                          # LFI via SSRF
]
SSRF_INDICATORS = [
    "ami-id", "instance-id", "meta-data",          # AWS
    "computeMetadata", "project-id",               # GCP
    "root:x:0:0",                                  # /etc/passwd
    "127.0.0.1", "localhost",
]


async def run(
    client:    AsyncHTTPClient,
    url:       str,
    full_scan: bool = False,
) -> list[Vuln]:
    """
    Ejecuta pruebas activas: SQLi, XSS, Path Traversal y SSRF.
    Solo en full_scan se ejecuta la suite completa.
    Retorna lista de Vuln.
    """
    vulns: list[Vuln] = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Si no hay parámetros en la URL, intentar con parámetros comunes
    if not params:
        probe_params = ["id", "page", "q", "search", "cat", "item", "product", "user", "name"]
    else:
        probe_params = list(params.keys())

    # ── SQLi ──────────────────────────────────────────────────────────────────
    sqli_vulns = await _test_sqli(client, url, parsed, probe_params)
    vulns.extend(sqli_vulns)

    # ── SQLi Blind Time-Based ──────────────────────────────────────────────────
    already_found = {v.title for v in vulns}
    blind_vulns = await _test_sqli_blind(client, url, parsed, probe_params, already_found)
    vulns.extend(blind_vulns)

    # ── XSS Reflejado ─────────────────────────────────────────────────────────
    xss_vulns = await _test_xss(client, url, parsed, probe_params)
    vulns.extend(xss_vulns)

    # ── Path Traversal ────────────────────────────────────────────────────────
    traversal_vulns = await _test_traversal(client, url, parsed, probe_params)
    vulns.extend(traversal_vulns)

    # ── SSRF (solo en full_scan) ───────────────────────────────────────────────
    if full_scan:
        ssrf_vulns = await _test_ssrf(client, url, parsed)
        vulns.extend(ssrf_vulns)

    return vulns


# ─── SQL Injection ────────────────────────────────────────────────────────────

async def _test_sqli(
    client: AsyncHTTPClient,
    url: str,
    parsed,
    probe_params: list[str],
) -> list[Vuln]:
    vulns: list[Vuln] = []
    found: set[str]   = set()
    sem = asyncio.Semaphore(8)

    # ── Baseline: body limpio para cada parámetro (valor inocuo) ──────────────
    # Si la página ya muestra un error sin payload, ignorar ese error
    baselines: dict[str, str] = {}  # param -> md5 del body limpio

    async def _get_baseline(param: str):
        clean_url = _inject_param(url, parsed, param, "1")
        resp = await client.get(clean_url, follow=True, lax_ssl=True, body_limit=65536)
        if resp:
            baselines[param] = hashlib.md5(resp.body[:8192]).hexdigest()

    await asyncio.gather(*[_get_baseline(p) for p in probe_params[:5]])

    async def check(param: str, payload: str, error_pattern: str):
        async with sem:
            test_url = _inject_param(url, parsed, param, payload)
            resp = await client.get(test_url, follow=True, lax_ssl=True, body_limit=65536)
            if not resp:
                return

            # Si el body es idéntico al baseline, el error no fue causado por el payload
            body_hash = hashlib.md5(resp.body[:8192]).hexdigest()
            if baselines.get(param) == body_hash:
                return

            body_lower = resp.text.lower()
            for ep in SQLI_ERROR_PATTERNS:
                if re.search(ep, body_lower, re.IGNORECASE):
                    key = f"{param}:{ep[:20]}"
                    if key not in found:
                        found.add(key)
                        match = re.search(ep, body_lower, re.IGNORECASE)
                        vulns.append(make_vuln(
                            title       = f"SQL Injection en parámetro '{param}'",
                            severity    = "CRITICAL",
                            cvss        = 9.8,
                            category    = "SQL Injection",
                            description = (
                                f"El parámetro '{param}' es vulnerable a SQL Injection. "
                                "Un atacante puede leer, modificar o eliminar datos de la base de datos."
                            ),
                            evidence    = (
                                f"Payload: {payload[:80]}\n"
                                f"Error detectado: {match.group(0)[:100] if match else ep}"
                            ),
                            fix         = (
                                "Usar consultas parametrizadas (prepared statements). "
                                "Nunca concatenar input del usuario en SQL. "
                                "Implementar WAF y least-privilege DB."
                            ),
                            ref         = "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection",
                            module      = "active",
                        ))
                    break

    tasks = []
    for param in probe_params[:5]:  # limitar a 5 params
        for payload, pattern in SQLI_PAYLOADS:
            tasks.append(check(param, payload, pattern))

    await asyncio.gather(*tasks)
    return vulns


# ─── SQLi Blind Time-Based ────────────────────────────────────────────────────

async def _test_sqli_blind(
    client: AsyncHTTPClient,
    url: str,
    parsed,
    probe_params: list[str],
    already_found: set[str],
) -> list[Vuln]:
    vulns: list[Vuln] = []
    found: set[str]   = set()
    sem = asyncio.Semaphore(5)

    import time

    async def check(param: str, payload: str, db_type: str, sleep_secs: int):
        title = f"SQL Injection en parámetro '{param}'"
        if title in already_found or param in found:
            return

        async with sem:
            test_url = _inject_param(url, parsed, param, payload)
            
            t0 = time.monotonic()
            resp = await client.get(test_url, follow=True, lax_ssl=True, body_limit=4096)
            dt = time.monotonic() - t0

            if dt < SQLI_BLIND_MARGIN:
                return

            confirm_payload = payload.replace(str(sleep_secs), "0")
            confirm_url = _inject_param(url, parsed, param, confirm_payload)
            
            t0_conf = time.monotonic()
            resp_conf = await client.get(confirm_url, follow=True, lax_ssl=True, body_limit=4096)
            dt_conf = time.monotonic() - t0_conf

            if dt_conf < 2.0 and param not in found:
                found.add(param)
                vulns.append(make_vuln(
                    title       = f"SQL Injection Blind (Time-Based) en parámetro '{param}'",
                    severity    = "CRITICAL",
                    cvss        = 9.8,
                    category    = "SQL Injection",
                    description = (
                        f"El parámetro '{param}' es vulnerable a Blind SQL Injection basada en tiempo. "
                        f"Base de datos inferida: {db_type}."
                    ),
                    evidence    = (
                        f"Payload con retraso ({sleep_secs}s): {payload}\n"
                        f"  → Respuesta tardó {dt:.2f} segundos.\n"
                        f"Payload de confirmación (0s): {confirm_payload}\n"
                        f"  → Respuesta tardó {dt_conf:.2f} segundos."
                    ),
                    fix         = (
                        "Usar consultas parametrizadas (prepared statements). "
                        "Nunca concatenar input del usuario en SQL. "
                        "Implementar WAF y least-privilege DB."
                    ),
                    ref         = "https://portswigger.net/web-security/sql-injection/blind",
                    module      = "active",
                ))

    tasks = []
    for param in probe_params[:3]:
        for payload, db_type, sleep_secs in SQLI_BLIND_PAYLOADS:
            tasks.append(check(param, payload, db_type, sleep_secs))

    await asyncio.gather(*tasks)
    return vulns


# ─── XSS Reflejado ────────────────────────────────────────────────────────────

async def _test_xss(
    client: AsyncHTTPClient,
    url: str,
    parsed,
    probe_params: list[str],
) -> list[Vuln]:
    vulns: list[Vuln] = []
    found: set[str]   = set()
    sem = asyncio.Semaphore(8)

    async def check(param: str, payload: str):
        async with sem:
            test_url = _inject_param(url, parsed, param, payload)
            resp = await client.get(test_url, follow=True, lax_ssl=True, body_limit=65536)
            if not resp:
                return

            body = resp.text

            # Verificar que el payload aparece SIN HTML-escape en el body.
            # Si está como &lt;script&gt; es un falso positivo: el servidor sí lo escapó.
            escaped_payload = html.escape(payload)
            payload_lower   = payload.lower()

            # Indicadores clave del payload sin escapar
            raw_indicators = [
                "<script>alert",
                "onerror=alert",
                "onload=alert",
                "<svg/onload",
                "<svg onload",
                "javascript:alert",
            ]

            reflection_found = False
            for ind in raw_indicators:
                if ind.lower() in body.lower():
                    # Confirmar que NO está escapado (la versión escaped NO debe estar cerca)
                    if html.escape(ind).lower() not in body.lower():
                        reflection_found = True
                        break
                    # Puede que ambas formas estén: verificar que la raw también está
                    # contando ocurrencias — si la raw aparece más veces que la escaped
                    raw_count    = body.lower().count(ind.lower())
                    escaped_count = body.lower().count(html.escape(ind).lower())
                    if raw_count > escaped_count:
                        reflection_found = True
                        break

            if reflection_found and param not in found:
                found.add(param)
                vulns.append(make_vuln(
                    title       = f"XSS Reflejado en parámetro '{param}'",
                    severity    = "HIGH",
                    cvss        = 8.1,
                    category    = "Cross-Site Scripting (XSS)",
                    description = (
                        f"El parámetro '{param}' refleja el payload XSS sin escapado. "
                        "Un atacante puede inyectar scripts que se ejecutan en el navegador de la víctima."
                    ),
                    evidence    = (
                        f"Payload: {payload[:80]}\n"
                        f"Reflejado sin escape en body (HTTP {resp.status})"
                    ),
                    fix         = (
                        "Sanitizar y escapar todo output HTML (htmlspecialchars en PHP, "
                        "escapeHtml en Java, etc.). Implementar CSP estricta. "
                        "Usar frameworks que auto-escapan (React, Angular, Vue)."
                    ),
                    ref         = "https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)",
                    module      = "active",
                ))

    tasks = []
    for param in probe_params[:5]:
        for payload in XSS_PAYLOADS[:3]:  # primeros 3 payloads
            tasks.append(check(param, payload))

    await asyncio.gather(*tasks)
    return vulns


# ─── Path Traversal ───────────────────────────────────────────────────────────

async def _test_traversal(
    client: AsyncHTTPClient,
    url: str,
    parsed,
    probe_params: list[str],
) -> list[Vuln]:
    vulns: list[Vuln] = []
    found: set[str]   = set()
    sem = asyncio.Semaphore(8)

    async def check(param: str, payload: str, indicator: str):
        async with sem:
            test_url = _inject_param(url, parsed, param, payload)
            resp = await client.get(test_url, follow=True, lax_ssl=True, body_limit=65536)
            if not resp:
                return
            if re.search(indicator, resp.text, re.IGNORECASE):
                if param not in found:
                    found.add(param)
                    vulns.append(make_vuln(
                        title       = f"Path Traversal en parámetro '{param}'",
                        severity    = "CRITICAL",
                        cvss        = 9.8,
                        category    = "Path Traversal",
                        description = (
                            f"El parámetro '{param}' permite salir del directorio base "
                            "y leer archivos del sistema operativo."
                        ),
                        evidence    = (
                            f"Payload: {payload[:80]}\n"
                            f"Indicador encontrado: {indicator}"
                        ),
                        fix         = (
                            "Validar y canonicalizar rutas. "
                            "Usar listas blancas de archivos permitidos. "
                            "Ejecutar la aplicación con usuario de mínimos privilegios."
                        ),
                        ref         = "https://owasp.org/www-community/attacks/Path_Traversal",
                        module      = "active",
                    ))

    tasks = []
    for param in probe_params[:3]:
        for payload, indicator in TRAVERSAL_PAYLOADS:
            tasks.append(check(param, payload, indicator))

    await asyncio.gather(*tasks)
    return vulns


# ─── SSRF ─────────────────────────────────────────────────────────────────────

async def _test_ssrf(
    client: AsyncHTTPClient,
    url: str,
    parsed,
) -> list[Vuln]:
    vulns: list[Vuln] = []
    found: set[str]   = set()
    sem = asyncio.Semaphore(5)

    async def check(param: str, ssrf_payload: str):
        async with sem:
            test_url = _inject_param(url, parsed, param, ssrf_payload)
            resp = await client.get(test_url, follow=True, lax_ssl=True, body_limit=32768)
            if not resp:
                return
            body_lower = resp.text.lower()
            for indicator in SSRF_INDICATORS:
                if indicator.lower() in body_lower:
                    key = f"{param}:{ssrf_payload[:30]}"
                    if key not in found:
                        found.add(key)
                        vulns.append(make_vuln(
                            title       = f"SSRF en parámetro '{param}'",
                            severity    = "CRITICAL",
                            cvss        = 9.8,
                            category    = "SSRF",
                            description = (
                                f"El parámetro '{param}' permite que el servidor haga peticiones "
                                "a recursos internos. Un atacante puede acceder a metadata de cloud, "
                                "servicios internos o archivos del sistema."
                            ),
                            evidence    = (
                                f"Payload: {ssrf_payload}\n"
                                f"Indicador en respuesta: '{indicator}'"
                            ),
                            fix         = (
                                "Validar y restringir URLs de destino con lista blanca. "
                                "Bloquear peticiones a rangos IP privados (169.254.x.x, 10.x.x.x, etc.). "
                                "Usar IMDSv2 en AWS con token requerido."
                            ),
                            ref         = "https://owasp.org/www-project-top-ten/2021/A10_2021-Server-Side_Request_Forgery_(SSRF)",
                            module      = "active",
                        ))
                    break

    tasks = []
    for param in SSRF_PARAMS[:5]:
        for ssrf_payload in SSRF_PAYLOADS[:2]:
            tasks.append(check(param, ssrf_payload))

    await asyncio.gather(*tasks)
    return vulns


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _inject_param(url: str, parsed, param: str, value: str) -> str:
    """Inyecta un parámetro GET en la URL, reemplazando si existe o añadiéndolo."""
    params = parse_qs(parsed.query)

    # Convertir a simples strings
    flat_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
    flat_params[param] = value

    new_query = urlencode(flat_params)
    new_parsed = parsed._replace(query=new_query)
    return urlunparse(new_parsed)
