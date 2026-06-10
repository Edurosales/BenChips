"""
modules/paths.py — Escaneo de rutas sensibles con detección de soft-404
y validación de contenido por tipo de archivo (anti-FP).
"""

from __future__ import annotations

import asyncio
import re
from typing import Callable
from urllib.parse import urlparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln
from config import SENSITIVE_PATHS


# ─── Validadores de contenido por tipo de archivo ────────────────────────────
# Devuelven True si el body parece REAL para ese tipo, False si es un FP
# (típicamente el index.html de un SPA que devuelve 200 a cualquier ruta).

_HTML_SIGNATURES = re.compile(
    r"(<!doctype\s+html|<html[\s>]|<head[\s>]|<body[\s>]|<meta\s+charset)",
    re.IGNORECASE,
)


def _looks_like_html(body: bytes) -> bool:
    sample = body[:2048].decode("utf-8", errors="ignore")
    return bool(_HTML_SIGNATURES.search(sample))


def _validate_env(body: bytes) -> bool:
    """Un .env real tiene KEY=VALUE en cada línea, sin HTML."""
    if _looks_like_html(body):
        return False
    text = body[:4096].decode("utf-8", errors="ignore")
    # Al menos 2 líneas tipo KEY=VALUE
    matches = re.findall(r"^[A-Z][A-Z0-9_]{2,}\s*=\s*\S", text, re.MULTILINE)
    return len(matches) >= 2


def _validate_git_config(body: bytes) -> bool:
    text = body[:4096].decode("utf-8", errors="ignore")
    return ("[core]" in text or "[remote " in text) and not _looks_like_html(body)


def _validate_git_head(body: bytes) -> bool:
    text = body[:512].decode("utf-8", errors="ignore").strip()
    return text.startswith("ref:") or bool(re.match(r"^[0-9a-f]{40}$", text))


def _validate_yaml(body: bytes) -> bool:
    if _looks_like_html(body):
        return False
    text = body[:4096].decode("utf-8", errors="ignore")
    # YAML real: keys con dos puntos en columna baja
    return bool(re.search(r"^[a-zA-Z_][a-zA-Z0-9_]*:\s*\S", text, re.MULTILINE))


def _validate_php_config(body: bytes) -> bool:
    """wp-config.php / config.php: si devuelve PHP source es expuesto."""
    if _looks_like_html(body):
        return False  # WordPress rendered: no expuesto
    text = body[:2048].decode("utf-8", errors="ignore")
    return ("<?php" in text or "DB_PASSWORD" in text or "define(" in text)


def _validate_aspnet_config(body: bytes) -> bool:
    text = body[:4096].decode("utf-8", errors="ignore")
    return ("<configuration>" in text or "<connectionStrings" in text)


def _validate_json_config(body: bytes) -> bool:
    if _looks_like_html(body):
        return False
    text = body[:2048].decode("utf-8", errors="ignore").lstrip()
    return text.startswith("{") and ('":' in text or '" :' in text)


def _validate_sql_dump(body: bytes) -> bool:
    if _looks_like_html(body):
        return False
    text = body[:2048].decode("utf-8", errors="ignore").upper()
    return any(s in text for s in (
        "CREATE TABLE", "INSERT INTO", "DROP TABLE", "-- MYSQL DUMP", "PG_DUMP"
    ))


def _validate_zip(body: bytes) -> bool:
    return body[:2] == b"PK"  # ZIP magic bytes


def _validate_passwd(body: bytes) -> bool:
    text = body[:4096].decode("utf-8", errors="ignore")
    return bool(re.search(r"^[a-z_][a-z0-9_-]*:[^:]*:\d+:\d+:", text, re.MULTILINE))


def _validate_ssh_key(body: bytes) -> bool:
    text = body[:512].decode("utf-8", errors="ignore")
    return "BEGIN" in text and "PRIVATE KEY" in text


def _validate_log(body: bytes) -> bool:
    """Logs reales: timestamps, niveles, no son HTML."""
    if _looks_like_html(body):
        return False
    text = body[:2048].decode("utf-8", errors="ignore")
    return bool(re.search(
        r"(\d{4}-\d{2}-\d{2}|\[\d{2}/\w{3}/\d{4}|ERROR|WARNING|INFO|DEBUG)",
        text,
    ))


def _validate_actuator(body: bytes) -> bool:
    """Spring Boot Actuator devuelve JSON estructurado."""
    if _looks_like_html(body):
        return False
    text = body[:1024].decode("utf-8", errors="ignore")
    return any(k in text for k in ('"_links"', '"status"', '"diskSpace"', '"profiles"'))


def _validate_swagger(body: bytes) -> bool:
    text = body[:4096].decode("utf-8", errors="ignore")
    return any(k in text for k in (
        '"swagger"', '"openapi"', '"paths"', 'Swagger UI', 'swagger-ui'
    ))


def _validate_server_status(body: bytes) -> bool:
    text = body[:4096].decode("utf-8", errors="ignore")
    return ("Apache Server Status" in text or "Server uptime" in text
            or "Current Requests" in text)


# Mapeo: substring del path → validador
# El primero que matchee gana
_PATH_VALIDATORS: list[tuple[str, Callable[[bytes], bool]]] = [
    (".env",                _validate_env),
    (".git/config",         _validate_git_config),
    (".git/HEAD",           _validate_git_head),
    (".gitignore",          lambda b: not _looks_like_html(b) and b"#" in b[:512] or b"*" in b[:512]),
    (".svn/entries",        lambda b: not _looks_like_html(b)),
    (".htpasswd",           lambda b: b":" in b[:512] and not _looks_like_html(b)),
    (".bash_history",       lambda b: not _looks_like_html(b) and len(b) > 10),
    (".ssh/id_rsa",         _validate_ssh_key),
    ("/etc/passwd",         _validate_passwd),
    ("wp-config",           _validate_php_config),
    ("config.php",          _validate_php_config),
    ("configuration.php",   _validate_php_config),
    ("settings.py",         lambda b: not _looks_like_html(b) and b"SECRET_KEY" in b[:4096]),
    ("web.config",          _validate_aspnet_config),
    ("appsettings.json",    _validate_json_config),
    ("database.yml",        _validate_yaml),
    ("parameters.yml",      _validate_yaml),
    ("backup.sql",          _validate_sql_dump),
    ("db.sql",              _validate_sql_dump),
    ("dump.sql",            _validate_sql_dump),
    ("backup.zip",          _validate_zip),
    ("/actuator",           _validate_actuator),
    ("/swagger",            _validate_swagger),
    ("api-docs",            _validate_swagger),
    ("openapi.json",        _validate_swagger),
    ("server-status",       _validate_server_status),
    ("server-info",         _validate_server_status),
    (".log",                _validate_log),
    ("/logs/",              _validate_log),
]


def _validate_path_content(path: str, body: bytes) -> tuple[bool, str]:
    """
    Valida que el contenido coincida con lo esperado para ese tipo de path.
    Retorna (es_valido, razon_si_invalido).
    """
    path_lower = path.lower()
    for marker, validator in _PATH_VALIDATORS:
        if marker in path_lower:
            try:
                if validator(body):
                    return True, ""
                return False, f"contenido no coincide con tipo esperado ({marker})"
            except Exception:
                return True, ""  # En duda, no descartar
    # Sin validador específico: aceptar si NO es HTML genérico
    if _looks_like_html(body) and len(body) > 200:
        return False, "respuesta parece SPA index (HTML genérico)"
    return True, ""


async def run(
    client:      AsyncHTTPClient,
    url:         str,
    concurrency: int = 15,
) -> tuple[list[Vuln], list[dict]]:
    """
    Escanea rutas sensibles con detección de soft-404 y validación de contenido.
    Retorna (vulns, found_paths_list).
    """
    vulns:       list[Vuln] = []
    found_paths: list[dict] = []

    parsed   = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    hostname = parsed.hostname or ""

    await client.establish_baseline(base_url)

    sem = asyncio.Semaphore(concurrency)

    async def check_path(path: str, sev: str, cvss: float, desc: str):
        async with sem:
            target = base_url.rstrip("/") + path
            resp   = await client.get(target, follow=False, lax_ssl=True, body_limit=32768)

            if not resp:
                return

            if resp.status in (400, 404, 405, 410, 500, 503):
                return

            if resp.status in (301, 302, 303, 307, 308):
                return

            if client.is_soft_404(hostname, resp.status, resp.body):
                return

            if resp.status == 200 and len(resp.body) < 5:
                return

            # ── Validación de contenido por tipo (anti-FP) ───────────────────
            if resp.status == 200:
                is_valid, reason = _validate_path_content(path, resp.body)
                if not is_valid:
                    # Registramos el hallazgo a nivel INFO, pero NO como vuln
                    found_paths.append({
                        "path":   path,
                        "status": resp.status,
                        "sev":    "INFO",
                        "cvss":   0.0,
                        "desc":   f"200 OK pero {reason}",
                        "size":   len(resp.body),
                    })
                    return

            found_paths.append({
                "path":   path,
                "status": resp.status,
                "sev":    sev,
                "cvss":   cvss,
                "desc":   desc,
                "size":   len(resp.body),
            })

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
                evidence    = (
                    f"GET {path} → HTTP {resp.status} ({len(resp.body)} bytes)\n"
                    f"Contenido validado: SÍ (no es SPA index)\n"
                    f"PoC: curl -i '{target}'"
                ),
                fix         = (
                    f"Restringir acceso a {path} con autenticación o eliminarlo si no es necesario. "
                    "Verificar que no exponga datos sensibles."
                ),
                ref         = "https://owasp.org/www-project-web-security-testing-guide/",
                module      = "paths",
                url         = target,
            ))

    tasks = [check_path(p, s, c, d) for p, s, c, d in SENSITIVE_PATHS]
    await asyncio.gather(*tasks)

    found_paths.sort(key=lambda x: x["path"])
    return vulns, found_paths
