"""
modules/http_param_pollution.py — HTTP Parameter Pollution (HPP).

Duplica parámetros GET/POST en varias formas para detectar:
  - Bypass de WAF/filtros (el WAF ve el primero, la app usa el segundo)
  - Lógica de negocio rota (la app suma, concatena o usa el último valor)
  - Discrepancias entre frameworks (PHP usa último, ASP.NET usa primero, etc.)

Anti-FP:
  - Baseline diff con valor inocuo — solo reporta si el body cambia inesperadamente.
  - Descarta cambios de timestamp/nonce aleatorio usando hash parcial de los primeros 500 chars.
"""
from __future__ import annotations

import asyncio
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


# Sufijo inyectado para detectar cuál valor procesó el servidor
_PROBE_VAL  = "vul_hpp_test"
_SAFE_VAL   = "1"
_EVIL_VAL   = "2"

# Señales de procesamiento del valor inyectado en la respuesta
_HPP_INDICATORS = [
    _PROBE_VAL,
    "vul_hpp",
    "hpp_test",
]


def _body_hash(text: str) -> str:
    return hashlib.md5(text[:1000].encode(errors="replace")).hexdigest()


async def run(
    client:    AsyncHTTPClient,
    url:       str,
    full_scan: bool = False,
) -> list[Vuln]:
    vulns: list[Vuln] = []
    found: set[str]   = set()
    sem = asyncio.Semaphore(6)

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        # Intentar params comunes si no hay en la URL
        test_params = ["id", "q", "search", "page", "cat", "user"]
        probe_p = {p: [_SAFE_VAL] for p in test_params[:3]}
    else:
        probe_p = {k: v for k, v in list(params.items())[:5]}

    async def check_param(param: str, orig_vals: list[str]):
        orig_val = orig_vals[0]

        # ── Baseline: parámetro con valor normal ──────────────────────────
        def _build_url(extra_params: dict) -> str:
            all_p = dict(params)
            all_p.update(extra_params)
            qs = "&".join(
                f"{k}={v}"
                for k, vals in all_p.items()
                for v in (vals if isinstance(vals, list) else [vals])
            )
            return urlunparse(parsed._replace(query=qs))

        baseline_url = _build_url({param: [orig_val]})
        async with sem:
            baseline = await client.get(baseline_url, lax_ssl=True, body_limit=32768)
        if not baseline:
            return
        baseline_hash = _body_hash(baseline.text or "")

        # ── Variante 1: param duplicado (?id=1&id=2) ──────────────────────
        dup_qs = "&".join(
            f"{k}={v}" for k, vals in params.items() for v in vals
        ) + f"&{param}={_EVIL_VAL}"
        dup_url = urlunparse(parsed._replace(query=dup_qs))

        async with sem:
            dup_resp = await client.get(dup_url, lax_ssl=True, body_limit=32768)
        if dup_resp:
            dup_hash = _body_hash(dup_resp.text or "")
            if dup_hash != baseline_hash:
                evil_in_resp = _EVIL_VAL in (dup_resp.text or "")
                key = f"dup:{param}"
                if key not in found:
                    found.add(key)
                    vulns.append(make_vuln(
                        title       = f"HTTP Parameter Pollution — '{param}' duplicado procesado diferente",
                        severity    = "MEDIUM",
                        cvss        = 5.3,
                        category    = "HTTP Parameter Pollution",
                        description = (
                            f"El parámetro '{param}' duplicado genera una respuesta diferente. "
                            "Posible bypass de filtros/WAF: el WAF inspecciona el primer valor "
                            "mientras la aplicación usa el segundo (o los concatena)."
                            + (" El servidor procesó el valor inyectado." if evil_in_resp else "")
                        ),
                        evidence    = (
                            f"Baseline: {baseline_url}\n"
                            f"HPP:      {dup_url}\n"
                            f"Respuesta baseline (hash): {baseline_hash[:8]}\n"
                            f"Respuesta HPP (hash):      {dup_hash[:8]} ← diferente\n"
                            f"Valor inyectado reflejado: {'SÍ' if evil_in_resp else 'no'}"
                        ),
                        fix         = (
                            "Usar solo la primera (o última) ocurrencia del parámetro de forma consistente. "
                            "Documentar la política de manejo de params duplicados. "
                            "Implementar validación estricta que rechace params duplicados."
                        ),
                        ref         = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution",
                        module      = "http_param_pollution",
                        url         = url,
                        cwe         = "CWE-235",
                        owasp       = "A01:2021",
                    ))

        # ── Variante 2: array syntax (?id[]=1&id[]=2) ─────────────────────
        arr_qs = "&".join(
            f"{k}={v}" for k, vals in params.items() for v in vals
            if k != param
        ) + f"&{param}[]={orig_val}&{param}[]={_EVIL_VAL}"
        arr_url = urlunparse(parsed._replace(query=arr_qs.lstrip("&")))

        async with sem:
            arr_resp = await client.get(arr_url, lax_ssl=True, body_limit=32768)
        if arr_resp and arr_resp.status in range(200, 300):
            arr_body = arr_resp.text or ""
            if _EVIL_VAL in arr_body and _EVIL_VAL not in (baseline.text or ""):
                key = f"arr:{param}"
                if key not in found:
                    found.add(key)
                    vulns.append(make_vuln(
                        title       = f"HTTP Parameter Pollution — Array Syntax '{param}[]' aceptado",
                        severity    = "LOW",
                        cvss        = 4.3,
                        category    = "HTTP Parameter Pollution",
                        description = (
                            f"El servidor acepta '{param}[]' como array PHP-style. "
                            "Puede causar errores de tipo en backends no-PHP o "
                            "bypass de validaciones que esperan string."
                        ),
                        evidence    = (
                            f"URL: {arr_url}\n"
                            f"Valor '{_EVIL_VAL}' reflejado en respuesta"
                        ),
                        fix         = "Validar que el tipo del parámetro sea el esperado (string, not array).",
                        ref         = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution",
                        module      = "http_param_pollution",
                        url         = url,
                        cwe         = "CWE-235",
                        owasp       = "A01:2021",
                    ))

        # ── Variante 3: probe HPP con valor especial en campo injectable ───
        # Solo en full_scan — más ruidoso
        if full_scan:
            probe_qs = "&".join(
                f"{k}={v}" for k, vals in params.items() for v in vals
            ) + f"&{param}={_PROBE_VAL}"
            probe_url = urlunparse(parsed._replace(query=probe_qs))
            async with sem:
                probe_resp = await client.get(probe_url, lax_ssl=True, body_limit=32768)
            if probe_resp:
                probe_body = probe_resp.text or ""
                for ind in _HPP_INDICATORS:
                    if ind in probe_body and ind not in (baseline.text or ""):
                        key = f"reflect:{param}"
                        if key not in found:
                            found.add(key)
                            vulns.append(make_vuln(
                                title       = f"HPP — Parámetro '{param}' reflejado sin sanitizar (posible XSS/HPP chain)",
                                severity    = "LOW",
                                cvss        = 3.7,
                                category    = "HTTP Parameter Pollution",
                                description = (
                                    f"El valor del parámetro '{param}' se refleja en la respuesta. "
                                    "En combinación con HPP puede facilitar XSS o bypass de filtros."
                                ),
                                evidence    = f"URL: {probe_url}\nValor reflejado: {ind}",
                                fix         = "Sanitizar y encodear todos los parámetros reflejados en respuesta.",
                                ref         = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution",
                                module      = "http_param_pollution",
                                url         = url,
                                cwe         = "CWE-235",
                                owasp       = "A01:2021",
                            ))
                        break

    await asyncio.gather(*[check_param(p, v) for p, v in probe_p.items()])
    return vulns
