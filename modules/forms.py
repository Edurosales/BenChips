"""
modules/forms.py — Parseo de HTML y Fuzzing de Formularios.

Extrae formularios HTML (action, method, inputs) e inyecta payloads básicos
de SQLi y XSS de manera sigilosa.
Respeta campos ocultos (CSRF tokens) para evitar bloqueos.

Anti-falsos-positivos:
  - Solo reporta si se produce un error SQL claro o una reflexión clara.
  - Rate limiting controlado por AsyncHTTPClient.
"""

from __future__ import annotations

import asyncio
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urlencode

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln
from config import SQLI_PAYLOADS, SQLI_ERROR_PATTERNS, XSS_PAYLOADS


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self.current_form: dict | None = None

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        tag = tag.lower()

        if tag == "form":
            self.current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "get").lower(),
                "inputs": []
            }
        elif tag in ("input", "textarea", "select", "button") and self.current_form is not None:
            name = attr_dict.get("name")
            if not name:
                return

            input_type = attr_dict.get("type", "text" if tag == "input" else tag).lower()
            value = attr_dict.get("value", "")
            
            self.current_form["inputs"].append({
                "name": name,
                "type": input_type,
                "value": value,
                "tag": tag
            })

    def handle_endtag(self, tag):
        if tag.lower() == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


async def run(
    client:    AsyncHTTPClient,
    url:       str,
    body_text: str | None = None,
) -> list[Vuln]:
    """
    Busca formularios en el HTML inicial y lanza pruebas de inyección sigilosas.
    """
    vulns: list[Vuln] = []

    if not body_text:
        resp = await client.get(url, follow=True, lax_ssl=True, body_limit=131072)
        if not resp:
            return []
        body_text = resp.text

    parser = FormParser()
    try:
        parser.feed(body_text)
    except Exception:
        return []

    forms = parser.forms
    if not forms:
        return []

    found_sqli = set()
    found_xss = set()

    sem = asyncio.Semaphore(3)  # Muy baja concurrencia para ser sigiloso

    async def test_form(form: dict):
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        target_url = urljoin(url, action) if action else url
        
        # Filtrar inputs que no deberíamos fuzzear para no romper la petición
        # Ej: type="hidden", type="submit" mantenemos su valor original.
        fuzzable_inputs = [i for i in inputs if i["type"] not in ("hidden", "submit", "button", "file", "radio", "checkbox")]
        
        if not fuzzable_inputs:
            return

        # Para ser sigilosos, no fuzzeamos cada input con cada payload por separado,
        # sino que inyectamos el payload en un parámetro mientras mantenemos los demás en su default,
        # y solo probamos 1 o 2 payloads.
        
        sqli_payload = SQLI_PAYLOADS[0][0]  # El payload de error-based más común (comilla)
        xss_payload  = XSS_PAYLOADS[0]      # XSS clásico

        for test_type, payload in [("sqli", sqli_payload), ("xss", xss_payload)]:
            for target_input in fuzzable_inputs[:3]:  # Limitar a los primeros 3 inputs por form
                
                # Construir el cuerpo de la petición o query string
                data = {}
                for inp in inputs:
                    name = inp["name"]
                    if inp == target_input:
                        data[name] = payload
                    else:
                        # Rellenar con dummy data o su valor por defecto
                        data[name] = inp["value"] or "test"

                async with sem:
                    if method == "post":
                        # forms por defecto son urlencoded
                        resp = await client.session.post(
                            target_url, 
                            data=data, 
                            allow_redirects=True, 
                            ssl=False,
                            headers=client._build_headers()
                        )
                        # Consumir el body
                        body = await resp.text()
                        status = resp.status
                    else:
                        # GET form
                        qs = urlencode(data)
                        test_url = f"{target_url}?{qs}" if "?" not in target_url else f"{target_url}&{qs}"
                        resp_obj = await client.get(test_url, follow=True, lax_ssl=True)
                        if not resp_obj:
                            continue
                        body = resp_obj.text
                        status = resp_obj.status

                    # Evaluar SQLi
                    if test_type == "sqli":
                        body_lower = body.lower()
                        for ep in SQLI_ERROR_PATTERNS:
                            if re.search(ep, body_lower, re.IGNORECASE):
                                key = f"{target_input['name']}:{ep[:10]}"
                                if key not in found_sqli:
                                    found_sqli.add(key)
                                    vulns.append(make_vuln(
                                        title       = f"SQLi en Formulario (input '{target_input['name']}')",
                                        severity    = "CRITICAL",
                                        cvss        = 9.8,
                                        category    = "SQL Injection",
                                        description = (
                                            f"El formulario en '{target_url}' es vulnerable a SQL Injection "
                                            f"a través del campo '{target_input['name']}'."
                                        ),
                                        evidence    = f"Payload: {payload}\nMétodo: {method.upper()}\nError detectado.",
                                        fix         = "Usar consultas parametrizadas (prepared statements).",
                                        ref         = "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection",
                                        module      = "forms",
                                        url         = target_url,
                                    ))
                                break

                    # Evaluar XSS
                    elif test_type == "xss":
                        # Indicador crudo (sin escapar)
                        if payload.lower() in body.lower():
                            import html
                            if html.escape(payload).lower() not in body.lower():
                                if target_input["name"] not in found_xss:
                                    found_xss.add(target_input["name"])
                                    vulns.append(make_vuln(
                                        title       = f"XSS en Formulario (input '{target_input['name']}')",
                                        severity    = "HIGH",
                                        cvss        = 8.1,
                                        category    = "Cross-Site Scripting (XSS)",
                                        description = (
                                            f"El formulario refleja el input del campo '{target_input['name']}' sin escapar, "
                                            "permitiendo ejecución de scripts."
                                        ),
                                        evidence    = f"Payload: {payload}\nMétodo: {method.upper()}\nEncontrado sin HTML-escape.",
                                        fix         = "Sanitizar y escapar todo output HTML.",
                                        ref         = "https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)",
                                        module      = "forms",
                                        url         = target_url,
                                    ))

    tasks = [test_form(f) for f in forms[:3]] # Limitar a 3 forms por página para ser stealth
    if tasks:
        await asyncio.gather(*tasks)

    return vulns
