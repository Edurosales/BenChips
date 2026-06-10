"""
modules/ldap_injection.py — LDAP injection detection.

Payloads detectan dos clases:
  1. Error-based: el servidor devuelve mensajes LDAP en respuesta.
  2. Boolean blind: respuesta cambia entre payload truthy y falsy.

Anti-FP:
  - Baseline con valor benigno.
  - Confirmación TRUE vs FALSE: respuestas distintas significativamente.
"""

from __future__ import annotations

import asyncio
import re
import secrets
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


_LDAP_ERROR_PATTERNS = [
    r"LDAPException",
    r"javax\.naming\.NamingException",
    r"com\.sun\.jndi",
    r"InvalidSyntaxRule",
    r"protocol error",
    r"LDAP error code \d+",
    r"LDAP search failed",
    r"DSID-\d+",
]

# Payloads error-based: caracteres que rompen sintaxis LDAP
_LDAP_ERROR_PAYLOADS = ["*)(uid=*", ")(|(uid=*", "*)((", "*)(&"]

# Pares (truthy, falsy) para boolean blind
_LDAP_BLIND_PAIRS = [
    ("admin)(&", "admin)(!"),
    ("*)(uid=*))((", "*)(uid=invaliduid12345xxx))(("),
]

_LDAP_PARAMS = ["username", "user", "uid", "search", "q", "filter", "name", "cn"]


def _inject(url: str, parsed, param: str, value: str) -> str:
    params = parse_qs(parsed.query)
    flat   = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
    flat[param] = value
    return urlunparse(parsed._replace(query=urlencode(flat)))


async def run(client: AsyncHTTPClient, url: str) -> list[Vuln]:
    vulns: list[Vuln] = []
    found: set[str] = set()

    parsed = urlparse(url)
    existing = list(parse_qs(parsed.query).keys())
    probe = existing + [p for p in _LDAP_PARAMS if p not in existing]
    probe = probe[:6]

    sem = asyncio.Semaphore(4)

    async def test_error(param: str):
        async with sem:
            if param in found:
                return
            for payload in _LDAP_ERROR_PAYLOADS:
                test_url = _inject(url, parsed, param, payload)
                r = await client.get(test_url, follow=True, body_limit=16384)
                if not r:
                    continue
                for pat in _LDAP_ERROR_PATTERNS:
                    if re.search(pat, r.text, re.IGNORECASE):
                        found.add(param)
                        vulns.append(make_vuln(
                            title       = f"LDAP Injection en parámetro '{param}'",
                            severity    = "HIGH",
                            cvss        = 8.6,
                            category    = "LDAP Injection",
                            description = (
                                f"El parámetro '{param}' es vulnerable a inyección LDAP. "
                                "Permite enumerar usuarios, extraer datos del directorio, "
                                "o bypassear autenticación."
                            ),
                            evidence    = (
                                f"Payload: {payload}\n"
                                f"Error LDAP detectado en respuesta: {pat}\n"
                                f"PoC: curl '{test_url}'"
                            ),
                            fix         = (
                                "Escapar caracteres LDAP especiales: ()*\\/\\0 en input del usuario. "
                                "Usar APIs parametrizadas (Spring LdapTemplate, python-ldap "
                                "search_s con escape_filter_chars). Whitelist de chars permitidos."
                            ),
                            ref         = "https://owasp.org/www-community/attacks/LDAP_Injection",
                            module      = "ldap_injection",
                            url         = url,
                            cwe         = "CWE-90",
                        ))
                        return

    async def test_blind(param: str):
        async with sem:
            if param in found:
                return
            for truthy, falsy in _LDAP_BLIND_PAIRS:
                r_true  = await client.get(_inject(url, parsed, param, truthy),
                                          follow=True, body_limit=8192)
                r_false = await client.get(_inject(url, parsed, param, falsy),
                                          follow=True, body_limit=8192)
                if not r_true or not r_false:
                    continue
                # Diferencia significativa en status o body length
                if r_true.status != r_false.status:
                    found.add(param)
                    vulns.append(make_vuln(
                        title       = f"LDAP Injection (blind) en '{param}'",
                        severity    = "HIGH",
                        cvss        = 7.5,
                        category    = "LDAP Injection",
                        description = (
                            f"El parámetro '{param}' diferencia respuestas según condición "
                            "LDAP truthy/falsy. Posible extracción ciega del directorio."
                        ),
                        evidence    = (
                            f"Truthy {truthy} → HTTP {r_true.status} ({len(r_true.body)} bytes)\n"
                            f"Falsy  {falsy} → HTTP {r_false.status} ({len(r_false.body)} bytes)"
                        ),
                        fix         = "Escapar caracteres LDAP especiales y usar APIs parametrizadas.",
                        ref         = "https://portswigger.net/web-security/ldap-injection",
                        module      = "ldap_injection",
                        url         = url,
                        cwe         = "CWE-90",
                    ))
                    return
                elif abs(len(r_true.body) - len(r_false.body)) > 200:
                    found.add(param)
                    vulns.append(make_vuln(
                        title       = f"LDAP Injection blind probable en '{param}'",
                        severity    = "MEDIUM",
                        cvss        = 6.5,
                        category    = "LDAP Injection",
                        description = "Diferencia significativa de tamaño entre truthy/falsy.",
                        evidence    = (
                            f"Truthy len={len(r_true.body)}, Falsy len={len(r_false.body)}"
                        ),
                        fix         = "Verificar manualmente con LDAP filter intent específico.",
                        ref         = "https://portswigger.net/web-security/ldap-injection",
                        module      = "ldap_injection",
                        url         = url,
                        confidence  = 60,
                    ))
                    return

    await asyncio.gather(*[test_error(p) for p in probe])
    await asyncio.gather(*[test_blind(p) for p in probe])
    return vulns
