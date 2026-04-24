"""
modules/js_cve.py — Detección de librerías JavaScript con vulnerabilidades conocidas.

Estilo Retire.js: extrae versiones de librerías JS desde el HTML y las compara
contra la base de datos JS_CVE_DB de config.py.

Anti-falsos-positivos:
  - Solo reporta si se detecta la versión ESPECÍFICA en la URL del script o en
    el contenido del archivo JS (no solo el nombre de la librería).
  - No genera peticiones adicionales si la versión ya está en la URL.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln
from config import JS_CVE_DB


# Patrones para detectar versión directamente en la URL del script
# ej: jquery-1.7.2.min.js, bootstrap.3.3.7.min.js
_VERSION_IN_URL = re.compile(
    r"(jquery|bootstrap|angular|lodash|moment|handlebars|underscore)"
    r"[._\-]+"
    r"(\d+\.\d+[\.\d]*)",
    re.IGNORECASE,
)

# Patrones para detectar versión dentro del contenido del archivo JS
_VERSION_IN_CONTENT = {
    "jquery":      re.compile(r"jquery\s+v?(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    "bootstrap":   re.compile(r"bootstrap\s+v?(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    "angularjs":   re.compile(r"angular(?:js)?[:\s]+['\"]?v?(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    "lodash":      re.compile(r"lodash\s+v?(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    "moment":      re.compile(r"moment\.js[:\s]+v?(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    "handlebars":  re.compile(r"handlebars\s+v?(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    "underscore":  re.compile(r"underscore\.js\s+(\d+\.\d+[\.\d]*)", re.IGNORECASE),
}


async def run(
    client:    AsyncHTTPClient,
    url:       str,
    body_text: str | None = None,
) -> list[Vuln]:
    """
    Detecta librerías JS vulnerables en el HTML y scripts vinculados.
    Retorna lista de Vuln con CVE específicos.
    """
    vulns:   list[Vuln]  = []
    found:   set[str]    = set()  # lib:version ya reportados

    # ── 1. Extraer todas las URLs de scripts del HTML ──────────────────────────
    if not body_text:
        resp = await client.get(url, follow=True, lax_ssl=True, body_limit=131072)
        body_text = resp.text if resp else ""

    script_urls = _extract_script_urls(url, body_text)

    # ── 2. Buscar versiones en las URLs de los scripts ─────────────────────────
    detections: list[tuple[str, str, str]] = []  # (lib, version, source)

    for script_url in script_urls:
        m = _VERSION_IN_URL.search(script_url)
        if m:
            lib     = m.group(1).lower()
            version = m.group(2)
            # Normalizar nombre
            if lib == "angular":
                lib = "angularjs"
            detections.append((lib, version, script_url))

    # ── 3. Para scripts sin versión en URL, descargar y buscar en contenido ────
    sem = asyncio.Semaphore(4)

    async def check_script_content(script_url: str):
        async with sem:
            # Solo descargar si no se detectó versión desde la URL
            already_detected_urls = {src for _, _, src in detections}
            if script_url in already_detected_urls:
                return

            resp = await client.get(script_url, follow=True, lax_ssl=True, body_limit=32768)
            if not resp or resp.status != 200:
                return

            content_sample = resp.text[:4096]  # Solo inicio del archivo
            for lib, pattern in _VERSION_IN_CONTENT.items():
                m = pattern.search(content_sample)
                if m:
                    detections.append((lib, m.group(1), script_url))
                    break

    # Solo revisar contenido de los scripts más cortos (evitar descargas lentas)
    content_check_scripts = [
        s for s in script_urls
        if not _VERSION_IN_URL.search(s)
    ][:6]  # máximo 6 scripts adicionales

    await asyncio.gather(*[check_script_content(s) for s in content_check_scripts])

    # ── 4. Comparar detecciones contra JS_CVE_DB ──────────────────────────────
    for lib, version, source in detections:
        if lib not in JS_CVE_DB:
            continue

        for version_pattern, cves, sev, cvss, desc in JS_CVE_DB[lib]:
            # Construir string de búsqueda: "jquery-1.7.2" para el patrón
            check_str = f"{lib}-{version}"
            if re.search(version_pattern, check_str, re.IGNORECASE):
                key = f"{lib}:{version}"
                if key in found:
                    continue
                found.add(key)

                lib_display = lib.capitalize()
                vulns.append(make_vuln(
                    title       = f"Librería JS vulnerable: {lib_display} v{version}",
                    severity    = sev,
                    cvss        = cvss,
                    category    = "Vulnerable JS Library",
                    description = desc,
                    evidence    = (
                        f"Detectado: {lib_display} v{version}\n"
                        f"Fuente: {source}\n"
                        f"CVEs: {', '.join(cves)}"
                    ),
                    fix         = (
                        f"Actualizar {lib_display} a la última versión estable. "
                        f"CVEs afectados: {', '.join(cves)}. "
                        "Usar npm audit o retire.js para auditorías continuas."
                    ),
                    ref         = f"https://nvd.nist.gov/vuln/detail/{cves[0]}",
                    module      = "js_cve",
                    url         = source,
                ))
                break  # Solo reportar el primer match por librería/versión

    return vulns


def _extract_script_urls(base_url: str, html: str) -> list[str]:
    """Extrae todas las URLs de <script src="..."> del HTML."""
    pattern = re.compile(
        r'<script[^>]+src=["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    urls = []
    for m in pattern.finditer(html):
        src = m.group(1).strip()
        if not src or src.startswith("data:"):
            continue
        # Resolver URL relativa
        full_url = urljoin(base_url, src)
        # Solo incluir scripts del mismo dominio o CDN comunes
        parsed_base   = urlparse(base_url)
        parsed_script = urlparse(full_url)
        same_host = parsed_script.hostname == parsed_base.hostname
        known_cdn = any(cdn in (parsed_script.hostname or "") for cdn in [
            "ajax.googleapis.com", "cdnjs.cloudflare.com",
            "cdn.jsdelivr.net", "code.jquery.com", "stackpath.bootstrapcdn.com",
            "maxcdn.bootstrapcdn.com", "unpkg.com",
        ])
        if same_host or known_cdn:
            urls.append(full_url)

    # Deduplicar manteniendo orden
    seen = set()
    result = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            result.append(u)
    return result
