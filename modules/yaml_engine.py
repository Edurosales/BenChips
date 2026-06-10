"""
modules/yaml_engine.py — Motor de ejecución de templates YAML (estilo Nuclei).

Soporta:
  - matchers tipo `word`, `regex`, `status`, `binary`
  - condition `and` / `or` (default and)
  - matcher-level negative: invert: true
  - matchers-condition global: and (default) / or
  - part: body | header | response | url
  - extractors regex con `group` (no se usan para chaining aún, sí en evidencia)
"""

from __future__ import annotations

import asyncio
import os
import re

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


def load_templates(templates_dir: str) -> list[dict]:
    try:
        import yaml  # lazy: si pyyaml no está instalado, motor inactivo (no falla scanner)
    except ImportError:
        return []

    templates = []
    if not os.path.isdir(templates_dir):
        return templates

    for root, _, files in os.walk(templates_dir):
        for file in files:
            if file.endswith((".yaml", ".yml")):
                path = os.path.join(root, file)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                        if data and isinstance(data, dict) and "id" in data:
                            templates.append(data)
                except Exception:
                    pass
    return templates


def _match_word(words: list[str], target: str, condition: str = "and") -> bool:
    matches = [w.lower() in target for w in words]
    return all(matches) if condition == "and" else any(matches)


def _match_regex(patterns: list[str], target: str, condition: str = "and") -> bool:
    matches = [bool(re.search(p, target, re.IGNORECASE | re.MULTILINE)) for p in patterns]
    return all(matches) if condition == "and" else any(matches)


def _match_status(statuses: list, actual: int) -> bool:
    return actual in [int(s) for s in statuses]


def _eval_matcher(m: dict, body: str, headers_str: str, status: int) -> bool:
    m_type    = m.get("type", "word")
    part      = m.get("part", "body")
    invert    = bool(m.get("negative", False))
    condition = m.get("condition", "and").lower()

    if part == "body":
        target = body
    elif part == "header":
        target = headers_str
    elif part == "response":
        target = headers_str + "\n\n" + body
    elif part == "url":
        target = ""
    else:
        target = body

    result = False
    if m_type == "word":
        result = _match_word(m.get("words", []), target, condition)
    elif m_type == "regex":
        result = _match_regex(m.get("regex", m.get("words", [])), target, condition)
    elif m_type == "status":
        result = _match_status(m.get("status", []), status)
    elif m_type == "binary":
        targets = [bytes.fromhex(b).decode("latin-1", errors="ignore")
                   for b in m.get("binary", [])]
        result = any(t in target for t in targets)
    elif m_type == "size":
        sizes = m.get("size", [])
        result = len(target) in [int(s) for s in sizes]

    return (not result) if invert else result


def _extract(extractors: list[dict], body: str, headers_str: str) -> list[str]:
    out: list[str] = []
    for e in extractors:
        e_type = e.get("type", "regex")
        part   = e.get("part", "body")
        target = body if part == "body" else headers_str
        if e_type == "regex":
            for pat in e.get("regex", []):
                m = re.search(pat, target, re.IGNORECASE | re.MULTILINE)
                if m:
                    out.append(m.group(0)[:120])
        elif e_type == "kval":
            for k in e.get("kval", []):
                m = re.search(rf"{re.escape(k)}\s*[:=]\s*([^\r\n]+)", target, re.IGNORECASE)
                if m:
                    out.append(f"{k}={m.group(1).strip()[:80]}")
    return out


async def run(client: AsyncHTTPClient, base_url: str) -> list[Vuln]:
    vulns: list[Vuln] = []

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    templates_dir = os.path.join(base_dir, "templates")

    templates = load_templates(templates_dir)
    if not templates:
        return []

    sem = asyncio.Semaphore(5)
    base_url = base_url.rstrip("/")

    async def execute_template(t: dict):
        t_id     = t.get("id", "Unknown")
        info     = t.get("info", {})
        name     = info.get("name", t_id)
        severity = info.get("severity", "MEDIUM").upper()
        cvss     = float(info.get("cvss", _default_cvss(severity)))
        requests = t.get("requests", [])

        for req in requests:
            method    = req.get("method", "GET").upper()
            paths     = req.get("path", [])
            req_hdrs  = req.get("headers", {})
            body_req  = req.get("body", "")
            matchers  = req.get("matchers", [])
            extractors = req.get("extractors", [])
            mcond     = req.get("matchers-condition", "and").lower()

            for path_tpl in paths:
                path = path_tpl.replace("{{BaseURL}}", base_url)
                if not path.startswith("http"):
                    path = f"{base_url}{path if path.startswith('/') else '/' + path}"

                async with sem:
                    if method == "POST" and body_req:
                        if isinstance(body_req, dict):
                            resp = await client.post_json(path, body_req,
                                                          extra_headers=req_hdrs)
                        else:
                            resp = await client.request(
                                method=method, url=path,
                                follow=True, lax_ssl=True,
                                extra_headers=req_hdrs,
                            )
                    else:
                        resp = await client.request(
                            method=method, url=path,
                            follow=True, lax_ssl=True,
                            extra_headers=req_hdrs,
                        )

                    if not resp:
                        continue

                    body         = resp.text.lower()
                    headers_str  = "\n".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()

                    if not matchers:
                        continue

                    matcher_results = [
                        _eval_matcher(m, body, headers_str, resp.status)
                        for m in matchers
                    ]
                    matched = (all(matcher_results) if mcond == "and"
                               else any(matcher_results))

                    if matched:
                        extracted = _extract(extractors, body, headers_str) if extractors else []
                        evidence_lines = [f"Match exitoso en {path} (HTTP {resp.status})"]
                        if extracted:
                            evidence_lines.append("Extraído:")
                            evidence_lines.extend([f"  - {e}" for e in extracted])

                        vulns.append(make_vuln(
                            title       = f"{name} ({t_id})",
                            severity    = severity,
                            cvss        = cvss,
                            category    = info.get("category", "Template Based"),
                            description = info.get("description", f"Detección basada en template {t_id}"),
                            evidence    = "\n".join(evidence_lines),
                            fix         = info.get("remediation", "Revisar configuración o actualizar componente."),
                            ref         = info.get("reference", ""),
                            module      = "yaml_engine",
                            url         = path,
                            cwe         = info.get("cwe", ""),
                            owasp       = info.get("owasp", ""),
                        ))
                        break  # un path basta por template
                # fin async with sem
            # fin for path_tpl
        # fin for req

    tasks = [execute_template(t) for t in templates]
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    return vulns


def _default_cvss(severity: str) -> float:
    return {
        "CRITICAL": 9.8, "HIGH": 7.5, "MEDIUM": 5.3, "LOW": 3.1, "INFO": 0.0
    }.get(severity.upper(), 5.0)
