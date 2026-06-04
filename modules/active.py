"""
modules/active.py — Pruebas activas: SQLi, XSS reflejado, Path Traversal, SSRF, JSON injection.

SSRF usa OOB (interactsh) cuando está disponible → confirmación real sin FPs.
Sin OOB, usa indicadores de respuesta específicos (sin localhost/127.0.0.1 genéricos).
JSON injection prueba APIs REST con payloads en el body.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import json as _json
import re
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln
from config import (
    SQLI_PAYLOADS, SQLI_ERROR_PATTERNS,
    SQLI_BLIND_PAYLOADS, SQLI_BLIND_SLEEP, SQLI_BLIND_MARGIN,
    XSS_PAYLOADS, TRAVERSAL_PAYLOADS,
)

if TYPE_CHECKING:
    from utils.oob import OOBClient

# ─── SSRF payloads ────────────────────────────────────────────────────────────
SSRF_PARAMS = [
    "url", "path", "dest", "redirect", "uri", "src", "image",
    "load", "fetch", "api", "callback", "webhook", "target", "next", "return",
]
SSRF_PAYLOADS_CLOUD = [
    "http://169.254.169.254/latest/meta-data/",   # AWS IMDS
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/metadata/v1/",         # DigitalOcean
]
SSRF_PAYLOADS_BLIND = [
    "http://{oob}/ssrf",                           # OOB HTTP
    "http://{oob}/",
]
# Indicadores en respuesta para detección sin OOB (solo strings muy específicos)
SSRF_INDICATORS = [
    "ami-id", "instance-id", "local-hostname",     # AWS metadata
    "computeMetadata", "project-id",               # GCP metadata
    "root:x:0:0",                                  # /etc/passwd
    "droplet_id", "vendor_data",                   # DigitalOcean
]

# Parámetros comunes en APIs JSON para fuzzing de body
_JSON_PARAMS = [
    "id", "user_id", "userId", "uid", "account_id",
    "q", "query", "search", "filter", "name", "email",
    "token", "key", "field", "value", "data", "input",
]


async def run(
    client:    AsyncHTTPClient,
    url:       str,
    full_scan: bool = False,
    oob:       "Optional[OOBClient]" = None,
    extra_urls: Optional[list[str]] = None,
) -> list[Vuln]:
    """
    Ejecuta pruebas activas: SQLi, XSS, Path Traversal, SSRF y JSON injection.

    oob:        OOBClient inicializado (opcional). Habilita SSRF confirmado.
    extra_urls: URLs adicionales descubiertas por el crawler.
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

    # ── SSRF ─────────────────────────────────────────────────────────────────
    if full_scan:
        ssrf_vulns = await _test_ssrf(client, url, parsed, oob=oob)
        vulns.extend(ssrf_vulns)

    # ── JSON Injection (APIs REST) ────────────────────────────────────────────
    # Testar la URL principal + extras del crawler
    api_targets = [url]
    if extra_urls:
        api_targets.extend(extra_urls[:20])  # limitar para no sobrecargar

    json_vulns = await _test_json_injection(client, api_targets)
    vulns.extend(json_vulns)

    # ── Tests en URLs adicionales del crawler ─────────────────────────────────
    if extra_urls:
        for extra_url in extra_urls[:15]:
            extra_parsed = urlparse(extra_url)
            extra_params = list(parse_qs(extra_parsed.query).keys())
            if not extra_params:
                continue  # sin params GET, skip (el JSON injection ya los cubre)
            # SQLi en params GET de URLs descubiertas
            vulns.extend(await _test_sqli(client, extra_url, extra_parsed, extra_params))
            # XSS en params GET de URLs descubiertas
            vulns.extend(await _test_xss(client, extra_url, extra_parsed, extra_params))

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
                                f"Error detectado: {match.group(0)[:100] if match else ep}\n"
                                f"PoC: curl '{test_url}'"
                            ),
                            fix         = (
                                "Usar consultas parametrizadas (prepared statements). "
                                "Nunca concatenar input del usuario en SQL. "
                                "Implementar WAF y least-privilege DB."
                            ),
                            ref         = "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection",
                            module      = "active",
                            url         = url,
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
    """
    Timing-based blind SQLi con baseline estadístico.
    Los tests se ejecutan SECUENCIALMENTE por parámetro para que las mediciones
    de tiempo sean válidas — ejecutarlos en paralelo invalida el timing.
    """
    import time
    vulns: list[Vuln] = []
    found: set[str]   = set()

    async def _measure_baseline(param: str, samples: int = 3) -> float:
        """Mide el tiempo de respuesta normal (mediana de N samples) para un param."""
        times = []
        for _ in range(samples):
            clean_url = _inject_param(url, parsed, param, "1")
            t0 = time.monotonic()
            resp = await client.get(clean_url, follow=True, lax_ssl=True, body_limit=4096)
            dt = time.monotonic() - t0
            if resp:
                times.append(dt)
        if not times:
            return 1.5
        times.sort()
        return times[len(times) // 2]  # mediana

    for param in probe_params[:3]:
        title_sqli = f"SQL Injection en parámetro '{param}'"
        if title_sqli in already_found or param in found:
            continue

        baseline = await _measure_baseline(param)
        threshold = baseline + SQLI_BLIND_MARGIN  # debe superar baseline + margen

        for payload, db_type, sleep_secs in SQLI_BLIND_PAYLOADS:
            if param in found:
                break

            test_url = _inject_param(url, parsed, param, payload)
            t0 = time.monotonic()
            resp = await client.get(test_url, follow=True, lax_ssl=True, body_limit=4096)
            dt = time.monotonic() - t0

            # Requiere que la respuesta supere el baseline + margen Y el tiempo de sleep
            if dt < threshold or dt < sleep_secs * 0.75:
                continue

            # Confirmación: payload con sleep=0 debe responder rápido (< baseline + 1s)
            confirm_payload = payload.replace(str(sleep_secs), "0")
            confirm_url = _inject_param(url, parsed, param, confirm_payload)
            t0_conf = time.monotonic()
            await client.get(confirm_url, follow=True, lax_ssl=True, body_limit=4096)
            dt_conf = time.monotonic() - t0_conf

            if dt_conf < baseline + 1.5:
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
                        f"Baseline normal: {baseline:.2f}s\n"
                        f"Payload sleep({sleep_secs}s): {payload}\n"
                        f"  → Respuesta tardó {dt:.2f}s (esperado ≥{threshold:.2f}s)\n"
                        f"Confirmación sleep(0s): {confirm_payload}\n"
                        f"  → Respuesta tardó {dt_conf:.2f}s (rápido = confirmado)\n"
                        f"PoC: curl '{test_url}'"
                    ),
                    fix         = (
                        "Usar consultas parametrizadas (prepared statements). "
                        "Nunca concatenar input del usuario en SQL. "
                        "Implementar WAF y least-privilege DB."
                    ),
                    ref         = "https://portswigger.net/web-security/sql-injection/blind",
                    module      = "active",
                    url         = url,
                ))

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
                        f"Reflejado sin escape en body (HTTP {resp.status})\n"
                        f"PoC: curl '{test_url}'"
                    ),
                    fix         = (
                        "Sanitizar y escapar todo output HTML (htmlspecialchars en PHP, "
                        "escapeHtml en Java, etc.). Implementar CSP estricta. "
                        "Usar frameworks que auto-escapan (React, Angular, Vue)."
                    ),
                    ref         = "https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)",
                    module      = "active",
                    url         = url,
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
    oob: "Optional[OOBClient]" = None,
) -> list[Vuln]:
    """
    Detección SSRF con dos estrategias:
    1. OOB (interactsh o webhook.site): payload único → callback confirmado → CRITICAL.
    2. Sin OOB: indicadores específicos en respuesta (metadata cloud) → HIGH probabilístico.
    """
    vulns: list[Vuln] = []
    found: set[str]   = set()
    sem = asyncio.Semaphore(3)

    # ── Estrategia 1: OOB ────────────────────────────────────────────────────
    if oob and oob.available:
        # Mapeo uid → (param, payload_url) para correlacionar callbacks
        oob_hits: dict[str, tuple[str, str]] = {}

        for param in SSRF_PARAMS[:8]:
            payload_url = oob.new_payload(f"ssrf-{param[:4]}")
            uid = oob.last_uid
            oob_hits[uid] = (param, payload_url)

            test_url = _inject_param(url, parsed, param, payload_url)
            async with sem:
                await client.get(test_url, follow=False, lax_ssl=True, body_limit=512)

        # Ventana de 15s para que el servidor del target haga el callback
        interactions = await oob.collect_all(client.session, timeout=15.0)

        confirmed: set[str] = set()
        for inter in interactions:
            protocol = inter.get("protocol", "HTTP").upper()
            remote   = inter.get("remote-address", "?")

            for uid, (param, payload_url) in oob_hits.items():
                if oob.uid_in_interaction(uid, inter) and param not in confirmed:
                    confirmed.add(param)
                    vulns.append(make_vuln(
                        title       = f"SSRF Confirmado ({oob.backend.upper()}) en parámetro '{param}'",
                        severity    = "CRITICAL",
                        cvss        = 9.8,
                        category    = "SSRF",
                        description = (
                            f"El parámetro '{param}' fuerza al servidor a hacer peticiones "
                            f"externas arbitrarias — CONFIRMADO vía callback {oob.backend} ({protocol}). "
                            "Permite acceder a metadata de cloud, servicios internos y credenciales."
                        ),
                        evidence    = (
                            f"Backend OOB: {oob.backend} ({oob._srv})\n"
                            f"Payload: {payload_url}\n"
                            f"Callback recibido: {protocol} desde IP {remote}\n"
                            f"PoC: curl '{_inject_param(url, parsed, param, payload_url)}'"
                        ),
                        fix         = (
                            "Whitelist estricta de URLs destino permitidas. "
                            "Bloquear rangos privados: 169.254.x.x, 10.x.x.x, 172.16-31.x.x, 192.168.x.x. "
                            "AWS: habilitar IMDSv2 (requiere token). "
                            "Deshabilitar redirecciones HTTP en el cliente HTTP del servidor."
                        ),
                        ref         = "https://portswigger.net/web-security/ssrf",
                        module      = "active",
                        url         = url,
                    ))

        return vulns  # Solo confirmados — cero FPs garantizados

    # ── Estrategia 2: Indicadores en respuesta (sin OOB) ─────────────────────
    baseline_resp = await client.get(url, follow=True, lax_ssl=True, body_limit=32768)
    baseline_body = baseline_resp.text.lower() if baseline_resp else ""

    async def check_direct(param: str, ssrf_payload: str):
        async with sem:
            test_url = _inject_param(url, parsed, param, ssrf_payload)
            resp = await client.get(test_url, follow=True, lax_ssl=True, body_limit=32768)
            if not resp:
                return
            body_lower = resp.text.lower()
            for indicator in SSRF_INDICATORS:
                ind_lower = indicator.lower()
                if ind_lower in baseline_body:
                    continue  # ya estaba en baseline — no es nuevo
                if ind_lower in body_lower:
                    key = f"{param}:{ssrf_payload[:30]}"
                    if key not in found:
                        found.add(key)
                        vulns.append(make_vuln(
                            title       = f"SSRF Probable en parámetro '{param}'",
                            severity    = "HIGH",
                            cvss        = 8.6,
                            category    = "SSRF",
                            description = (
                                f"El parámetro '{param}' devuelve indicadores de metadata cloud "
                                "tras inyectar una URL interna. Verificar manualmente. "
                                "Para confirmación sin FPs: activar OOB (webhook.site o interactsh)."
                            ),
                            evidence    = (
                                f"Payload: {ssrf_payload}\n"
                                f"Indicador en respuesta: '{indicator}' (ausente en baseline)\n"
                                f"PoC: curl '{test_url}'"
                            ),
                            fix         = "Whitelist de URLs. Bloquear rangos IP privados. IMDSv2 en AWS.",
                            ref         = "https://portswigger.net/web-security/ssrf",
                            module      = "active",
                            url         = url,
                        ))
                    break

    tasks = []
    for param in SSRF_PARAMS[:6]:
        for ssrf_payload in SSRF_PAYLOADS_CLOUD:
            tasks.append(check_direct(param, ssrf_payload))
    await asyncio.gather(*tasks)
    return vulns


# ─── JSON Body Injection ──────────────────────────────────────────────────────

async def _test_json_injection(
    client: AsyncHTTPClient,
    urls: list[str],
) -> list[Vuln]:
    """
    Inyecta payloads SQLi y XSS en el body JSON de endpoints que acepten POST.
    Prueba campos comunes (_JSON_PARAMS) con baseline comparativo.
    """
    vulns: list[Vuln] = []
    found: set[str] = set()
    sem = asyncio.Semaphore(5)

    async def probe(target_url: str, param: str, payload: str, vuln_type: str):
        async with sem:
            # Baseline con valor limpio
            baseline = await client.post_json(
                target_url, {param: "test_baseline_value"}, body_limit=65536
            )
            if not baseline:
                return

            resp = await client.post_json(
                target_url, {param: payload}, body_limit=65536
            )
            if not resp:
                return

            # Si el body es idéntico al baseline, el servidor ignoró el campo
            if resp.body == baseline.body:
                return

            body_lower = resp.text.lower()
            key_base = f"json:{target_url[:60]}:{param}"

            if vuln_type == "sqli":
                for ep in SQLI_ERROR_PATTERNS:
                    if re.search(ep, body_lower, re.IGNORECASE):
                        key = f"{key_base}:sqli"
                        if key not in found:
                            found.add(key)
                            match = re.search(ep, body_lower, re.IGNORECASE)
                            vulns.append(make_vuln(
                                title       = f"SQLi en JSON body (campo '{param}')",
                                severity    = "CRITICAL",
                                cvss        = 9.8,
                                category    = "SQL Injection",
                                description = (
                                    f"El campo JSON '{param}' en POST {target_url} "
                                    "es vulnerable a SQL Injection."
                                ),
                                evidence    = (
                                    f"POST {target_url}\n"
                                    f"Body: {{{repr(param)}: {repr(payload)}}}\n"
                                    f"Error detectado: {match.group(0)[:100] if match else ep}"
                                ),
                                fix         = "Usar consultas parametrizadas. Validar y tipar el input JSON.",
                                ref         = "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection",
                                module      = "active",
                                url         = target_url,
                            ))
                        break

            elif vuln_type == "xss":
                raw_indicators = ["<script>alert", "onerror=alert", "<svg/onload", "javascript:alert"]
                for ind in raw_indicators:
                    if ind.lower() in body_lower:
                        if html.escape(ind).lower() not in body_lower:
                            key = f"{key_base}:xss"
                            if key not in found:
                                found.add(key)
                                vulns.append(make_vuln(
                                    title       = f"XSS en JSON body (campo '{param}')",
                                    severity    = "HIGH",
                                    cvss        = 8.1,
                                    category    = "Cross-Site Scripting (XSS)",
                                    description = (
                                        f"El campo JSON '{param}' se refleja sin escapar en la respuesta."
                                    ),
                                    evidence    = (
                                        f"POST {target_url}\n"
                                        f"Body: {{{repr(param)}: {repr(payload)}}}\n"
                                        f"Payload reflejado sin HTML-escape."
                                    ),
                                    fix         = "Escapar output. Implementar CSP. Validar Content-Type en requests.",
                                    ref         = "https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)",
                                    module      = "active",
                                    url         = target_url,
                                ))
                            break

    tasks = []
    sqli_payload = SQLI_PAYLOADS[0][0] if SQLI_PAYLOADS else "'"
    xss_payload  = XSS_PAYLOADS[0] if XSS_PAYLOADS else "<script>alert(1)</script>"

    for target_url in urls:
        for param in _JSON_PARAMS[:6]:
            tasks.append(probe(target_url, param, sqli_payload, "sqli"))
            tasks.append(probe(target_url, param, xss_payload, "xss"))

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
