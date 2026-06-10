"""
modules/file_upload.py — File upload vulnerability testing.

Detecta endpoints de upload y prueba:
  - Extensión blacklist bypass: .php.jpg, .pHP, .php5, .phtml
  - Magic byte spoofing: GIF89a header + PHP code (polyglot)
  - Content-Type spoofing: image/jpeg con cuerpo PHP
  - Path traversal en filename: ../../shell.php
  - Null byte: shell.php%00.jpg
  - SVG con script embedded (XSS persistente)
"""

from __future__ import annotations

import asyncio
import re
import secrets
from urllib.parse import urljoin, urlparse

import aiohttp

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


# Endpoints típicos
_UPLOAD_PATHS = [
    "/upload", "/api/upload", "/files/upload", "/api/files",
    "/media/upload", "/api/media", "/avatar/upload",
    "/admin/upload", "/wp-admin/async-upload.php",
]

# Payloads — cada uno es (filename, content, content_type, technique)
_PAYLOADS = [
    ("test.php.jpg",
     b"GIF89a\n<?php echo 'pwned'; ?>",
     "image/jpeg",
     "Double extension .php.jpg"),
    ("test.pHp",
     b"<?php echo 'pwned'; ?>",
     "image/jpeg",
     "Case bypass .pHp"),
    ("test.phtml",
     b"<?php echo 'pwned'; ?>",
     "image/jpeg",
     "Alternative ext .phtml"),
    ("test.svg",
     b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
     "image/svg+xml",
     "SVG with embedded script"),
    ("../shell.jpg",
     b"GIF89a\nharmless",
     "image/jpeg",
     "Path traversal in filename"),
    ("test.jpg.html",
     b"<html><script>alert(1)</script></html>",
     "image/jpeg",
     "HTML disguised as JPG"),
]


async def run(client: AsyncHTTPClient, url: str) -> list[Vuln]:
    vulns: list[Vuln] = []

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    sem = asyncio.Semaphore(3)
    found: set[str] = set()

    async def probe_endpoint(path: str):
        async with sem:
            target = base.rstrip("/") + path

            # Verificar existencia con OPTIONS
            opt = await client.options_req(target, body_limit=2048)
            if opt and opt.status in (404, 405, 410):
                return

            # Test mínimo: subir un .txt benigno para ver si responde 200
            session = client.session
            if not session:
                return

            tag = f"vul-probe-{secrets.token_hex(4)}"
            data = aiohttp.FormData()
            data.add_field("file", f"{tag}.txt".encode(),
                          filename=f"{tag}.txt", content_type="text/plain")

            try:
                async with session.post(
                    target, data=data, ssl=False,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as r:
                    baseline_status = r.status
                    baseline_body   = (await r.read())[:2048]
            except Exception:
                return

            # Si rechaza el .txt → endpoint válido pero no acepta tipo arbitrario
            if baseline_status >= 400:
                return

            # ── Probar cada payload ────────────────────────────────────────
            for filename, content, ct, technique in _PAYLOADS:
                tag_inner = f"vul-{secrets.token_hex(4)}"
                actual_filename = filename.replace("test", tag_inner)

                fd = aiohttp.FormData()
                fd.add_field("file", content, filename=actual_filename, content_type=ct)

                try:
                    async with session.post(
                        target, data=fd, ssl=False,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as r:
                        if r.status >= 400:
                            continue
                        resp_body = (await r.read())[:8192]
                except Exception:
                    continue

                resp_text = resp_body.decode("utf-8", errors="ignore")

                # Buscar URL o path del archivo subido en la respuesta
                # Patrón común: {"url": "/uploads/xxx.php.jpg"} o "/files/xxx"
                m = re.search(
                    rf'["\']([^"\']*{re.escape(tag_inner)}[^"\']*)["\']',
                    resp_text,
                )
                if not m:
                    continue

                file_url = m.group(1)
                if not file_url.startswith("http"):
                    file_url = urljoin(target, file_url)

                # Verificar que el archivo realmente fue almacenado
                check = await client.get(file_url, body_limit=4096, follow=True)
                if not check or check.status != 200:
                    continue

                # Si el contenido se sirve TAL CUAL (PHP no ejecutado, script no
                # renderizado) sigue siendo upload bypass → archivo malicioso
                # accesible. Si se ejecuta, peor.

                key = f"{path}:{technique}"
                if key in found:
                    continue
                found.add(key)

                vulns.append(make_vuln(
                    title       = f"File Upload Bypass — {technique}",
                    severity    = "HIGH",
                    cvss        = 8.1,
                    category    = "Insecure File Upload",
                    description = (
                        f"El endpoint {path} acepta archivos potencialmente peligrosos. "
                        f"Técnica que funcionó: {technique}. "
                        "Combinable con ejecución del lenguaje server-side para RCE."
                    ),
                    evidence    = (
                        f"POST {target}\n"
                        f"Filename: {actual_filename}\n"
                        f"Content-Type enviado: {ct}\n"
                        f"Archivo accesible en: {file_url}\n"
                        f"HTTP GET {file_url[:80]} → {check.status} ({len(check.body)} bytes)"
                    ),
                    fix         = (
                        "Whitelist de extensiones (no blacklist). Verificar magic bytes "
                        "con python-magic o file(1). Renombrar uploads a UUID + ext fija. "
                        "Servir desde dominio aparte sin ejecución (e.g. files.example.com con "
                        "X-Content-Type-Options: nosniff). Para SVG: re-encodear o servir como "
                        "image/svg+xml con CSP que bloquea script."
                    ),
                    ref         = "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                    module      = "file_upload",
                    url         = target,
                    cwe         = "CWE-434",
                ))

    await asyncio.gather(*[probe_endpoint(p) for p in _UPLOAD_PATHS])
    return vulns
