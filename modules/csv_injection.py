"""
modules/csv_injection.py — CSV/XLSX formula injection.

Detección:
  1. Inyectar payload =cmd|'/c calc'!A1 en un campo de usuario
  2. Triggerear export del endpoint que produce CSV/Excel
  3. Verificar si el payload aparece TAL CUAL en el output (sin escapado)

Anti-FP:
  - El payload debe estar PRECEDIDO por '=', '+', '-', '@' (caracteres trigger)
  - Solo reporta si el download es realmente CSV/XLSX (Content-Type)
  - Si el servidor antepone ' o "  → escapado correcto
"""

from __future__ import annotations

import asyncio
import secrets
from urllib.parse import urlparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


_EXPORT_PATHS = [
    "/export", "/export.csv", "/export/csv", "/download/csv",
    "/api/export", "/admin/export", "/reports/export",
    "/data.csv", "/data.xlsx", "/users.csv",
]

_FIELDS = ["name", "title", "description", "comment", "note", "subject"]

_TRIGGERS = [
    ('=HYPERLINK("https://attacker.com","click")', "Formula HYPERLINK"),
    ('=1+1', "Formula =1+1"),
    ('@SUM(1,2)', "Formula @ trigger"),
    ('+CMD()', "Formula + trigger"),
]


async def run(client: AsyncHTTPClient, url: str, post_endpoints: list[str] | None = None) -> list[Vuln]:
    vulns: list[Vuln] = []

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    # Lugares de POST candidatos
    post_candidates = post_endpoints or [
        base.rstrip("/") + p for p in
        ["/api/comments", "/api/users", "/api/items", "/comment", "/feedback"]
    ]

    sem = asyncio.Semaphore(3)

    async def test_field(post_url: str, field: str, payload: str, technique: str):
        async with sem:
            tag = secrets.token_hex(4)
            tagged_payload = f"{payload}-VUL{tag}"

            # Insertar el payload
            insert = await client.post_json(
                post_url, {field: tagged_payload, "name": "test"},
                body_limit=2048,
            )
            if not insert or insert.status >= 400:
                return

            # Buscar exports
            for ep in _EXPORT_PATHS:
                exp_url = base.rstrip("/") + ep
                r = await client.get(exp_url, body_limit=131072)
                if not r or r.status != 200:
                    continue

                ct = r.headers.get("content-type", "").lower()
                if not any(t in ct for t in ("csv", "spreadsheet", "excel", "octet-stream")):
                    continue

                text = r.text

                # Verificar: el payload aparece SIN escape (no precedido de ' o ")
                if tagged_payload not in text:
                    continue

                # Buscar la posición y verificar el caracter anterior
                idx = text.find(tagged_payload)
                if idx <= 0:
                    continue
                prev_char = text[idx - 1]

                # Escape correcto: precedido de "'" o "\""
                if prev_char in ("'", "\\"):
                    continue

                vulns.append(make_vuln(
                    title       = f"CSV Formula Injection — {technique}",
                    severity    = "MEDIUM",
                    cvss        = 6.5,
                    category    = "CSV Injection",
                    description = (
                        f"El campo '{field}' permite inyectar fórmulas que se ejecutan "
                        "al abrir el export en Excel/LibreOffice. Permite exfiltración "
                        "de datos vía HYPERLINK, DDE, o ejecución de comandos en versiones "
                        "antiguas de Excel."
                    ),
                    evidence    = (
                        f"POST {post_url} con {field}={tagged_payload}\n"
                        f"GET {exp_url} → Content-Type: {ct}\n"
                        f"Payload encontrado SIN escape (caracter previo: '{prev_char}')\n"
                    ),
                    fix         = (
                        "Antes de exportar, prefijar valores que empiezan con =, +, -, @, TAB "
                        "con apóstrofo (') o entre comillas. Librerías: "
                        "openpyxl con sanitize_for_csv() helper. "
                        "Document mode = Protected View para excels recibidos."
                    ),
                    ref         = "https://owasp.org/www-community/attacks/CSV_Injection",
                    module      = "csv_injection",
                    url         = exp_url,
                    cwe         = "CWE-1236",
                ))
                return

    tasks = []
    for post_url in post_candidates[:4]:
        for field in _FIELDS[:3]:
            for trigger, tech in _TRIGGERS[:2]:
                tasks.append(test_field(post_url, field, trigger, tech))

    await asyncio.gather(*tasks)
    return vulns
