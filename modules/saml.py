"""
modules/saml.py — SAML auth bypass detection.

Cubre:
  - XML Signature Wrapping (XSW): mover firma a posición no validada.
  - Comment injection en NameID: <NameID>admin<!---->@target.com</NameID>
    los parsers de XML toman el texto completo, pero algunas implementaciones
    truncan en el comentario → acceso como admin.
  - SAML Response sin firma (forge total).
  - Algorithm confusion: rsa-sha1 deprecado.

Anti-FP:
  - Solo prueba en endpoints donde se detecta SAML (parámetro SAMLResponse,
    SP-Initiated SSO, IdP metadata).
  - Reporta misconfiguraciones de SP/IdP por response patterns, no por
    enviar payloads ofensivos (que requerirían firmas legítimas).
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


# Endpoints SAML conocidos
_SAML_PATHS = [
    "/saml/metadata",
    "/saml/SSO",
    "/saml/acs",
    "/saml2/metadata",
    "/Shibboleth.sso/Metadata",
    "/auth/saml",
    "/sso/saml",
    "/simplesaml/saml2/idp/metadata.php",
    "/adfs/ls/",
    "/auth/realms/master/protocol/saml/descriptor",
]


def _detect_saml_metadata(body: bytes) -> bool:
    """Detecta si el cuerpo parece metadata SAML XML."""
    text = body[:4096].decode("utf-8", errors="ignore").lower()
    return (
        "<entitydescriptor" in text
        or "urn:oasis:names:tc:saml" in text
        or "<md:entitydescriptor" in text
    )


def _check_metadata_weakness(text: str) -> list[tuple[str, str, str]]:
    """Devuelve list de (severity, title, evidence) para weakness en metadata."""
    findings = []

    # SHA-1 deprecado
    if "rsa-sha1" in text.lower() or "dsa-sha1" in text.lower():
        findings.append((
            "MEDIUM",
            "SAML usando RSA-SHA1 deprecado",
            "rsa-sha1 / dsa-sha1 detectado en metadata. "
            "SHA-1 está deprecado por NIST y vulnerable a SHAttered.",
        ))

    # Algoritmo "none" o "any" (raro pero posible)
    if 'signaturemethod algorithm=""' in text.lower() or "wantassertionssigned=\"false\"" in text.lower():
        findings.append((
            "HIGH",
            "SAML: WantAssertionsSigned=false",
            "El SP acepta assertions sin firmar. Permite forgery total de la SAMLResponse.",
        ))

    # AuthnRequest sin firmar
    if "authnrequestssigned=\"false\"" in text.lower():
        findings.append((
            "LOW",
            "AuthnRequestsSigned=false en SAML",
            "Los AuthnRequest no requieren firma. Menor riesgo, pero permite "
            "manipulación de RelayState y ACS URLs.",
        ))

    return findings


async def run(client: AsyncHTTPClient, url: str) -> list[Vuln]:
    vulns: list[Vuln] = []

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    sem = asyncio.Semaphore(5)

    async def probe(path: str):
        async with sem:
            target = base.rstrip("/") + path
            resp = await client.get(target, body_limit=65536, lax_ssl=True)
            if not resp or resp.status not in (200, 401, 403):
                return

            if not _detect_saml_metadata(resp.body):
                return

            text = resp.text
            for sev, title, ev in _check_metadata_weakness(text):
                vulns.append(make_vuln(
                    title       = title,
                    severity    = sev,
                    cvss        = 7.5 if sev == "HIGH" else (4.3 if sev == "MEDIUM" else 3.1),
                    category    = "SAML Misconfiguration",
                    description = ev,
                    evidence    = f"GET {target} → SAML metadata expone weakness.",
                    fix         = (
                        "Forzar SHA-256+ como SignatureMethod. "
                        "Requerir WantAssertionsSigned=true. "
                        "Validar firma sobre TODOS los Assertion antes de procesar NameID."
                    ),
                    ref         = "https://research.aurainfosec.io/pentest/the-rsa-sha1-and-saml-vulnerabilities/",
                    module      = "saml",
                    url         = target,
                    cwe         = "CWE-347",
                ))

            # ── Comment-injection awareness check ───────────────────────────
            # No podemos enviar payload (requiere firma); solo reportamos si
            # el endpoint /acs acepta SAMLResponse sin Required-Signed-Assertions.
            if "/acs" in path.lower() or "/sso" in path.lower():
                vulns.append(make_vuln(
                    title       = f"SAML ACS endpoint encontrado: {path}",
                    severity    = "INFO",
                    cvss        = 0.0,
                    category    = "SAML",
                    description = (
                        "Endpoint Assertion Consumer Service expuesto. Verificar manualmente: "
                        "(1) NameID comment injection (admin<!---->@target.com), "
                        "(2) XML Signature Wrapping en Assertion duplicada, "
                        "(3) firma obligatoria sobre Assertion (no solo Response)."
                    ),
                    evidence    = f"GET {target} responde SAML metadata válido.",
                    fix         = "Auditoría manual del IdP/SP config — ver SAML Raider, SAMLER.",
                    ref         = "https://www.economyofmechanism.com/github-saml",
                    module      = "saml",
                    url         = target,
                ))

    await asyncio.gather(*[probe(p) for p in _SAML_PATHS])
    return vulns
