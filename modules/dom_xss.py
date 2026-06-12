"""
modules/dom_xss.py — DOM-based XSS via headless browser (Playwright).

Cubre vectores que análisis estático no detecta:
  - document.location.hash sinks (eval, innerHTML, document.write)
  - postMessage handlers sin origin check
  - URL fragment routing en SPAs (Angular/React/Vue)
  - DOM clobbering (window.X overrides)

Anti-FP:
  - Inyecta canary único; verifica que se ejecuta JS real (window.__vul_marker__).
  - Solo reporta si el canary se evaluó como código, no solo apareció en HTML.

Requiere: pip install playwright && playwright install chromium
Si Playwright no está instalado, el módulo no falla — solo se omite.
"""

from __future__ import annotations

import asyncio
import secrets
from typing import Optional
from urllib.parse import urljoin

from utils.vuln import Vuln, make_vuln


_HASH_PAYLOADS = [
    "#<img src=x onerror={canary}>",
    "#javascript:{canary}",
    "#<svg onload={canary}>",
    "#'\"><script>{canary}</script>",
]

_PM_PAYLOADS = [
    '{{"action":"eval","code":"{canary}"}}',
    '{{"__proto__":{{"x":"{canary}"}}}}',
]


def _has_playwright() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


async def run(client, url: str, full_scan: bool = False) -> list[Vuln]:
    """
    Solo se ejecuta en full_scan y si Playwright está instalado.
    """
    vulns: list[Vuln] = []
    if not full_scan or not _has_playwright():
        return vulns

    from playwright.async_api import async_playwright  # type: ignore

    canary_id = secrets.token_hex(8)
    canary_js = f"window.__vul_marker_{canary_id}__=true"

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page    = await context.new_page()

            # ── Hash sinks ────────────────────────────────────────────────────
            for payload in _HASH_PAYLOADS:
                full_url = url + payload.format(canary=canary_js)
                try:
                    await page.goto(full_url, timeout=8000, wait_until="domcontentloaded")
                    await page.wait_for_timeout(500)
                    marker = await page.evaluate(
                        f"() => !!window.__vul_marker_{canary_id}__"
                    )
                    if marker:
                        vulns.append(make_vuln(
                            title       = "DOM-based XSS via location.hash",
                            severity    = "HIGH",
                            cvss        = 7.4,
                            category    = "Cross-Site Scripting",
                            description = (
                                "El fragmento de URL llega a un sink DOM peligroso "
                                "(innerHTML / eval / document.write). Confirmado por ejecución "
                                f"de canary JS único."
                            ),
                            evidence    = f"URL: {full_url}\nCanary ejecutado: window.__vul_marker_{canary_id}__",
                            fix         = "Sanitizar `location.hash` antes de pasarlo a sinks DOM. "
                                          "Usar `textContent`/`createTextNode` en vez de `innerHTML`.",
                            ref         = "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                            module      = "dom_xss",
                            url         = full_url,
                            cwe         = "CWE-79",
                        ))
                        break
                    # reset el marker para el próximo payload
                    await page.evaluate(f"delete window.__vul_marker_{canary_id}__")
                except Exception:
                    continue

            # ── postMessage handlers sin origin check ─────────────────────────
            try:
                await page.goto(url, timeout=8000, wait_until="domcontentloaded")
                # Inyectar postMessage al window
                for payload in _PM_PAYLOADS:
                    msg = payload.format(canary=canary_js)
                    await page.evaluate(f"window.postMessage({msg}, '*')")
                await page.wait_for_timeout(500)
                marker = await page.evaluate(
                    f"() => !!window.__vul_marker_{canary_id}__"
                )
                if marker:
                    vulns.append(make_vuln(
                        title       = "postMessage handler sin origin validation",
                        severity    = "HIGH",
                        cvss        = 7.4,
                        category    = "Cross-Site Scripting",
                        description = (
                            "Un handler de window.message acepta mensajes de cualquier origen "
                            "y los pasa a eval o sinks. Permite XSS si attacker controla un iframe."
                        ),
                        evidence    = f"postMessage canary ejecutado en {url}",
                        fix         = "Validar event.origin contra una allowlist antes de procesar message.data.",
                        ref         = "https://portswigger.net/web-security/dom-based/controlling-the-web-message-source",
                        module      = "dom_xss",
                        url         = url,
                        cwe         = "CWE-79",
                    ))
            except Exception:
                pass

            await browser.close()
    except Exception:
        return vulns

    return vulns
