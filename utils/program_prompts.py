"""
utils/program_prompts.py — Tuning de prompts por programa.

Cada plataforma usa criterios distintos para puntuar/aceptar bugs:
  - HackerOne: CVSS v3.1 strict + clear reproducibility.
  - Bugcrowd: P1/P2/P3/P4/P5 (VRT). Más estructurado.
  - Intigriti: CVSS pero con énfasis en impacto de negocio.
  - YesWeHack: CVSS + RCE/auth bypass priorizan.

Devolvemos extra-instructions que se appendan al prompt del triage IA.
"""

from __future__ import annotations


_PROGRAM_RULES = {
    "h1": (
        "PROGRAMA: HackerOne. Critica con CVSS v3.1 vector explícito. "
        "Marca como FP cualquier hallazgo INFO o LOW que no tenga impacto demostrable. "
        "Para HIGH/CRITICAL exige cadena de ataque clara (no solo header missing). "
        "Genera título estilo 'X allows Y in Z' (action-oriented)."
    ),
    "bugcrowd": (
        "PROGRAMA: Bugcrowd. Mapea a VRT priority: "
        "P1 = RCE/SQLi auth-no/SSRF cloud-metadata; "
        "P2 = stored XSS/IDOR/auth bypass; "
        "P3 = reflected XSS/CSRF state-changing; "
        "P4 = open redirect / clickjacking; P5 = info disclosure. "
        "Incluye campo 'vrt_priority' explícito."
    ),
    "intigriti": (
        "PROGRAMA: Intigriti. CVSS v3.1 + énfasis en business impact. "
        "Si el bug afecta datos de clientes o pagos, aumentar severidad. "
        "Solo HIGH/CRITICAL si impacto financiero o data exposure es claro."
    ),
    "yeswehack": (
        "PROGRAMA: YesWeHack. Prioriza RCE, auth bypass, SQLi explotable. "
        "XSS sin context (no cookie steal) → MEDIUM. "
        "Incluir CVE/CWE refs cuando aplique."
    ),
    "generic": (
        "Triage genérico CVSS v3.1. Conservador: en duda, FP. "
        "Solo reportar HIGH/CRITICAL con evidencia reproducible."
    ),
}


def get_program_instructions(program: str) -> str:
    """Devuelve extra-instructions para el prompt según el programa."""
    return _PROGRAM_RULES.get(program.lower(), _PROGRAM_RULES["generic"])


def list_programs() -> list[str]:
    return list(_PROGRAM_RULES.keys())


def format_for_program(vuln, program: str) -> str:
    """
    Renderiza un vuln con campos esperados por el programa.
    Útil para report.py al generar markdown específico.
    """
    program = program.lower()

    if program == "bugcrowd":
        # Determinar VRT priority desde severidad/categoría
        pri = _bc_priority(vuln)
        return (
            f"**VRT Priority:** {pri}\n"
            f"**Title:** {vuln.title}\n"
            f"**Severity:** {vuln.severity}\n"
            f"**CVSS:** {vuln.cvss} {vuln.cvss_vector or ''}\n"
            f"**Description:** {vuln.description}\n\n"
            f"**Steps to Reproduce:**\n{vuln.evidence}\n\n"
            f"**Remediation:** {vuln.fix}"
        )

    if program == "h1":
        return (
            f"### {vuln.title}\n\n"
            f"**Severity:** {vuln.severity} (CVSS {vuln.cvss})\n"
            f"**Weakness:** {vuln.cwe or vuln.category}\n\n"
            f"## Summary\n{vuln.description}\n\n"
            f"## Reproduction\n```\n{vuln.evidence}\n```\n\n"
            f"## Impact\n{vuln.description}\n\n"
            f"## Remediation\n{vuln.fix}"
        )

    # generic / intigriti / yeswehack
    return (
        f"## {vuln.title}\n"
        f"Severity: {vuln.severity} | CVSS: {vuln.cvss}\n"
        f"CWE: {vuln.cwe} | OWASP: {vuln.owasp}\n\n"
        f"{vuln.description}\n\nEvidence:\n{vuln.evidence}\n\nFix:\n{vuln.fix}"
    )


def _bc_priority(vuln) -> str:
    sev = vuln.severity.upper()
    cat = vuln.category.lower()
    if sev == "CRITICAL" or "rce" in cat or "ssrf" in cat:
        return "P1"
    if sev == "HIGH" or "idor" in cat or "auth" in cat or "stored xss" in cat:
        return "P2"
    if sev == "MEDIUM" or "csrf" in cat or "reflected xss" in cat:
        return "P3"
    if "redirect" in cat or "clickjacking" in cat:
        return "P4"
    return "P5"
