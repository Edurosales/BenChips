"""
modules/xpath_injection.py — XPath / XQuery injection.

Endpoints típicos: búsquedas SOAP, APIs que filtran XML, configuradores
que usan XSLT.

Payloads:
  - Error-based: ' o " quiebran sintaxis y revelan stack trace
  - Boolean: '] | //* | a[' (extracción ciega)
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


_XPATH_ERROR_PATTERNS = [
    r"javax\.xml\.xpath",
    r"XPathException",
    r"net\.sf\.saxon",
    r"System\.Xml\.XPath",
    r"libxml2",
    r"xmlXPathEval",
    r"InvalidExpression",
    r"unexpected token at.*xpath",
    r"XPath syntax error",
]

_XPATH_ERROR_PAYLOADS = [
    "' or '1'='1",
    "' or 1=1 or '",
    "x' or name()='username' or 'x'='y",
    "'] | //* | a['",
]

_XPATH_PARAMS = ["q", "search", "name", "filter", "xpath", "query", "where", "expr"]


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
    probe = (existing + [p for p in _XPATH_PARAMS if p not in existing])[:6]

    sem = asyncio.Semaphore(4)

    async def test(param: str, payload: str):
        async with sem:
            if param in found:
                return
            test_url = _inject(url, parsed, param, payload)
            r = await client.get(test_url, follow=True, body_limit=16384)
            if not r:
                return
            for pat in _XPATH_ERROR_PATTERNS:
                if re.search(pat, r.text, re.IGNORECASE):
                    found.add(param)
                    vulns.append(make_vuln(
                        title       = f"XPath Injection en '{param}'",
                        severity    = "HIGH",
                        cvss        = 8.6,
                        category    = "XPath Injection",
                        description = (
                            f"El parámetro '{param}' es vulnerable a XPath injection. "
                            "Permite leer cualquier nodo del documento XML, incluyendo "
                            "credenciales si están almacenadas allí (xmlsec auth)."
                        ),
                        evidence    = (
                            f"Payload: {payload}\n"
                            f"Error XPath detectado: {pat}\n"
                            f"PoC: curl '{test_url}'"
                        ),
                        fix         = (
                            "Usar XPath parametrizado (XPathVariableResolver en Java, "
                            "lxml con xpath() y variables). Escapar comillas en input. "
                            "Mejor: migrar lookups XML a query estructurada en DB."
                        ),
                        ref         = "https://owasp.org/www-community/attacks/XPATH_Injection",
                        module      = "xpath_injection",
                        url         = url,
                        cwe         = "CWE-643",
                    ))
                    return

    tasks = []
    for param in probe:
        for payload in _XPATH_ERROR_PAYLOADS:
            tasks.append(test(param, payload))

    await asyncio.gather(*tasks)
    return vulns
