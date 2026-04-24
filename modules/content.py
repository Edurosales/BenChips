"""
modules/content.py — Detección de filtración de contenido sensible en respuestas HTTP.
"""

from __future__ import annotations

import re
import asyncio

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln
from config import LEAKAGE_PATTERNS


async def run(
    client: AsyncHTTPClient,
    url:    str,
    resp_body: str | None = None,
) -> list[Vuln]:
    """
    Escanea el body de la respuesta principal buscando patrones de leakage:
    stack traces, errores DB, credenciales hardcodeadas, claves privadas, etc.
    Opcionalmente acepta el body ya leído para evitar doble request.
    Retorna lista de Vuln encontradas.
    """
    vulns: list[Vuln] = []

    # Si no nos pasaron body, hacemos el GET
    if resp_body is None:
        resp = await client.get(url, follow=True, lax_ssl=True, body_limit=131072)
        if not resp:
            return vulns
        body = resp.text
    else:
        body = resp_body

    body_lower = body.lower()

    # ── Patrones de leakage ────────────────────────────────────────────────────
    found_categories: set[str] = set()

    for pattern, sev, cvss, desc in LEAKAGE_PATTERNS:
        try:
            match = re.search(pattern, body, re.IGNORECASE | re.MULTILINE)
        except re.error:
            continue

        if match:
            # Extraer contexto alrededor del match
            start = max(0, match.start() - 40)
            end   = min(len(body), match.end() + 80)
            ctx   = body[start:end].replace("\n", " ").replace("\r", "").strip()

            # Deduplicar por categoría de descripción
            cat_key = desc[:30]
            if cat_key in found_categories:
                continue
            found_categories.add(cat_key)

            vulns.append(make_vuln(
                title       = f"Content Leakage: {desc[:60]}",
                severity    = sev,
                cvss        = cvss,
                category    = "Content Leakage",
                description = desc,
                evidence    = f"Patrón '{pattern[:40]}' encontrado en body: ...{ctx[:150]}...",
                fix         = (
                    "Deshabilitar debug en producción. "
                    "Configurar custom error pages. "
                    "Nunca exponer stack traces, credenciales ni claves en respuestas HTTP."
                ),
                ref         = "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                module      = "content",
            ))

    # ── Directory listing ──────────────────────────────────────────────────────
    if re.search(r"index\s+of\s+/", body, re.IGNORECASE):
        vulns.append(make_vuln(
            title       = "Directory Listing habilitado",
            severity    = "MEDIUM",
            cvss        = 5.3,
            category    = "Content Leakage",
            description = "El servidor lista el contenido del directorio. Revela archivos internos, backups y estructura.",
            evidence    = f"Detección de 'Index of /' en {url}",
            fix         = (
                "Apache: Options -Indexes | "
                "Nginx: autoindex off; | "
                "IIS: deshabilitar directory browsing."
            ),
            ref         = "https://owasp.org/www-project-web-security-testing-guide/",
            module      = "content",
        ))

    # ── Emails expuestos ──────────────────────────────────────────────────────
    emails = re.findall(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        body
    )
    # Filtrar emails de ejemplos comunes
    real_emails = [
        e for e in emails
        if not any(x in e.lower() for x in ("example", "test", "placeholder", "user@", "email@"))
    ]
    if len(real_emails) > 3:
        vulns.append(make_vuln(
            title       = f"Emails expuestos en body ({len(real_emails)} encontrados)",
            severity    = "LOW",
            cvss        = 3.1,
            category    = "Information Disclosure",
            description = "Emails reales expuestos en el HTML facilitan ataques de ingeniería social y spam.",
            evidence    = ", ".join(real_emails[:5]),
            fix         = "Ocultar emails, usar formularios de contacto o antibot encoding.",
            module      = "content",
        ))

    # ── Números de versión en body ─────────────────────────────────────────────
    version_patterns = [
        (r"jQuery\s+v?(\d+\.\d+[\.\d]*)", "jQuery"),
        (r"angular[\s/]v?(\d+\.\d+[\.\d]*)", "Angular"),
        (r"react[\s@]v?(\d+\.\d+[\.\d]*)", "React"),
        (r"bootstrap[\s/]v?(\d+\.\d+[\.\d]*)", "Bootstrap"),
    ]
    for pat, lib in version_patterns:
        m = re.search(pat, body, re.IGNORECASE)
        if m:
            vulns.append(make_vuln(
                title       = f"Versión de librería expuesta: {lib} {m.group(1)}",
                severity    = "LOW",
                cvss        = 3.1,
                category    = "Information Disclosure",
                description = f"La versión exacta de {lib} es visible. Permite buscar CVEs específicos.",
                evidence    = f"Encontrado: {m.group(0)[:60]}",
                fix         = f"Eliminar versión del nombre de archivo o de comentarios HTML de {lib}.",
                module      = "content",
            ))

    return vulns
