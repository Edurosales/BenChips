"""
modules/yaml_engine.py — Motor de ejecución de templates YAML (estilo Nuclei).

Carga archivos .yaml desde el directorio `templates/` y ejecuta las peticiones
indicadas para descubrir vulnerabilidades, aprovechando la infraestructura async
y el modo sigiloso (stealth) del scanner.
"""

from __future__ import annotations

import asyncio
import os
import re
from typing import Any

import yaml

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


def load_templates(templates_dir: str) -> list[dict]:
    """Lee todos los archivos .yaml del directorio y los retorna como dicts."""
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


async def run(
    client: AsyncHTTPClient,
    base_url: str,
) -> list[Vuln]:
    """
    Ejecuta todos los templates YAML cargados contra la URL base.
    """
    vulns: list[Vuln] = []
    
    # Resolver path al directorio de templates
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    templates_dir = os.path.join(base_dir, "templates")
    
    templates = load_templates(templates_dir)
    if not templates:
        return []

    sem = asyncio.Semaphore(5)

    # Limpiar trailing slash
    base_url = base_url.rstrip("/")

    async def execute_template(t: dict):
        t_id     = t.get("id", "Unknown")
        info     = t.get("info", {})
        name     = info.get("name", t_id)
        severity = info.get("severity", "MEDIUM").upper()
        requests = t.get("requests", [])

        for req in requests:
            method  = req.get("method", "GET").upper()
            paths   = req.get("path", [])
            headers = req.get("headers", {})
            body    = req.get("body", "")
            matchers= req.get("matchers", [])

            for path_tpl in paths:
                # Reemplazar la variable {{BaseURL}} típica de Nuclei
                path = path_tpl.replace("{{BaseURL}}", base_url)
                
                # Si el path no empieza con http, lo concatenamos
                if not path.startswith("http"):
                    path = f"{base_url}{path if path.startswith('/') else '/' + path}"

                async with sem:
                    resp = await client.request(
                        method=method,
                        url=path,
                        follow=True,
                        lax_ssl=True,
                        extra_headers=headers
                    )
                    
                    if not resp:
                        continue

                    resp_body = resp.text.lower()
                    resp_headers = str(resp.headers).lower()

                    matched_all = True
                    for m in matchers:
                        m_type = m.get("type", "word")
                        part   = m.get("part", "body")
                        words  = m.get("words", [])

                        target = resp_body if part == "body" else resp_headers

                        # Condición OR (cualquier palabra basta)
                        if m_type == "word":
                            if not any(w.lower() in target for w in words):
                                matched_all = False
                                break
                        elif m_type == "regex":
                            if not any(re.search(w, target, re.IGNORECASE) for w in words):
                                matched_all = False
                                break

                    if matched_all and matchers:
                        vulns.append(make_vuln(
                            title       = f"YAML Match: {name} ({t_id})",
                            severity    = severity,
                            cvss        = 7.0 if severity == "HIGH" else 5.0,
                            category    = "Template Based (CVE)",
                            description = info.get("description", f"Detección basada en template {t_id}"),
                            evidence    = f"Match exitoso en {path}",
                            fix         = info.get("remediation", "Revisar configuración o actualizar componente."),
                            ref         = info.get("reference", ""),
                            module      = "yaml_engine",
                            url         = path,
                        ))
                        break # Si un path hace match, pasamos a la siguiente peticion/template

    tasks = [execute_template(t) for t in templates]
    if tasks:
        await asyncio.gather(*tasks)

    return vulns
