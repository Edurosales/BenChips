"""
modules/js_cve.py — Detección de librerías JavaScript con vulnerabilidades conocidas.

Reemplaza el regex de versión con comparación semver real:
  - Tupla (major, minor, patch) parseada del string.
  - Cada entrada de JS_CVE_DB define max_fixed_version (excluyente).
  - Una versión es vulnerable si version_tuple < max_fixed_tuple.

Anti-falsos-positivos:
  - Solo reporta cuando la versión queda estrictamente por debajo del fix.
  - Lee hasta 16 KB del JS para encontrar el banner de versión.
  - Deduplica por (lib, major.minor.patch) — un solo hallazgo por versión real.
"""

from __future__ import annotations

import asyncio
import re
from typing import Optional
from urllib.parse import urljoin, urlparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln
from config import JS_CVE_DB


_VERSION_IN_URL = re.compile(
    r"(jquery|jquery-ui|bootstrap|angular|angularjs|lodash|moment|"
    r"handlebars|underscore|vue|react|d3|axios|backbone|knockout|"
    r"prototype|mootools|ember)"
    r"[._\-/]+"
    r"(\d+(?:\.\d+){0,3})",
    re.IGNORECASE,
)

_VERSION_IN_CONTENT = {
    "jquery":      re.compile(r"jquery(?:\s+|\s+v|\s+JavaScript\s+Library\s+v)?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    "bootstrap":   re.compile(r"bootstrap(?:\s+v|\s+)(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    "angularjs":   re.compile(r"angular(?:js)?[:\s'\"]+v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    "lodash":      re.compile(r"lodash(?:\s+|\s+v)?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    "moment":      re.compile(r"moment(?:\.js)?[:\s]+v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    "handlebars":  re.compile(r"handlebars(?:\s+|\s+v)?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    "underscore":  re.compile(r"underscore(?:\.js)?\s+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    "vue":         re.compile(r"vue(?:\.js)?\s+v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    "react":       re.compile(r"react[:\s'\"]+v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    "axios":       re.compile(r"axios(?:\s+|\s+v)?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
}


def _parse_version(version: str) -> tuple[int, ...]:
    """'1.7.2' → (1, 7, 2). '3.4' → (3, 4, 0)."""
    parts = version.strip().split(".")
    nums: list[int] = []
    for p in parts:
        m = re.match(r"(\d+)", p)
        if m:
            nums.append(int(m.group(1)))
        else:
            break
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums[:3])


def _is_vulnerable(version: str, max_fixed: str) -> bool:
    """True si version < max_fixed (excluyente)."""
    return _parse_version(version) < _parse_version(max_fixed)


async def run(
    client:    AsyncHTTPClient,
    url:       str,
    body_text: str | None = None,
) -> list[Vuln]:
    """
    Detecta librerías JS vulnerables comparando semver real contra JS_CVE_DB.
    """
    vulns:   list[Vuln]  = []
    found:   set[str]    = set()

    if not body_text:
        resp = await client.get(url, follow=True, lax_ssl=True, body_limit=131072)
        body_text = resp.text if resp else ""

    script_urls = _extract_script_urls(url, body_text)

    detections: list[tuple[str, str, str]] = []  # (lib, version, source)

    for script_url in script_urls:
        m = _VERSION_IN_URL.search(script_url)
        if m:
            lib     = m.group(1).lower()
            version = m.group(2)
            if lib == "angular":
                lib = "angularjs"
            if lib == "jquery-ui":
                lib = "jquery"  # JS_CVE_DB usa jquery
            detections.append((lib, version, script_url))

    sem = asyncio.Semaphore(4)

    async def check_script_content(script_url: str):
        async with sem:
            already_detected_urls = {src for _, _, src in detections}
            if script_url in already_detected_urls:
                return

            resp = await client.get(script_url, follow=True, lax_ssl=True, body_limit=16384)
            if not resp or resp.status != 200:
                return

            content_sample = resp.text[:16384]
            for lib, pattern in _VERSION_IN_CONTENT.items():
                m = pattern.search(content_sample)
                if m:
                    detections.append((lib, m.group(1), script_url))
                    break

    content_check_scripts = [
        s for s in script_urls
        if not _VERSION_IN_URL.search(s)
    ][:8]

    await asyncio.gather(*[check_script_content(s) for s in content_check_scripts])

    # ── Comparar contra JS_CVE_DB con semver real ────────────────────────────
    for lib, version, source in detections:
        if lib not in JS_CVE_DB:
            continue

        version_tuple = _parse_version(version)

        for entry in JS_CVE_DB[lib]:
            # JS_CVE_DB usa formato dict: {max_fixed, cves, severity, cvss, description}
            if not isinstance(entry, dict):
                continue
            max_fixed = entry.get("max_fixed", "0.0.0")
            cves      = entry.get("cves", [])
            sev       = entry.get("severity", "MEDIUM")
            cvss      = entry.get("cvss", 5.0)
            desc      = entry.get("description", "")
            if not _is_vulnerable(version, max_fixed):
                continue

            key = f"{lib}:{version}"
            if key in found:
                continue
            found.add(key)

            lib_display = lib.capitalize()
            fix_msg = f"Actualizar {lib_display} a la versión {max_fixed} o superior. "

            vulns.append(make_vuln(
                title       = f"Librería JS vulnerable: {lib_display} v{version}",
                severity    = sev,
                cvss        = cvss,
                category    = "Vulnerable JS Library",
                description = desc,
                evidence    = (
                    f"Detectado: {lib_display} v{version} (tupla {version_tuple})\n"
                    f"Fuente: {source}\n"
                    f"CVEs afectados: {', '.join(cves)}\n"
                    f"Versión segura: ≥ {max_fixed}"
                ),
                fix         = (
                    fix_msg
                    + f"CVEs: {', '.join(cves)}. "
                    "Usar npm audit, snyk o retire.js para auditorías continuas."
                ),
                ref         = f"https://nvd.nist.gov/vuln/detail/{cves[0]}" if cves else "",
                module      = "js_cve",
                url         = source,
            ))
            break

    return vulns


def _extract_script_urls(base_url: str, html: str) -> list[str]:
    pattern = re.compile(
        r'<script[^>]+src=["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    urls = []
    for m in pattern.finditer(html):
        src = m.group(1).strip()
        if not src or src.startswith("data:"):
            continue
        full_url = urljoin(base_url, src)
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

    seen = set()
    result = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            result.append(u)
    return result
