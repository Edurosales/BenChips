"""
utils/verify.py — Modo interactivo de verificación.

Tras el scan + IA triage, muestra cada vuln una a una y pregunta:
  [s]ubmit / [k]eep / [d]rop / [e]dit / [n]ext-batch

Permite filtrar FPs manualmente antes de generar reportes finales.
"""

from __future__ import annotations

from typing import Optional

from utils.vuln import Vuln


def interactive_verify(vulns: list[Vuln]) -> list[Vuln]:
    """
    Recorre vulns y pregunta al usuario qué hacer con cada una.
    Retorna la lista filtrada.
    """
    try:
        from utils.colors import C, W, G, O, R, Y, M, BOLD, DIM
    except ImportError:
        C = W = G = O = R = Y = M = BOLD = DIM = ""

    if not vulns:
        return vulns

    print(f"\n{BOLD}{C}═══ Modo verificación interactiva ═══{W}")
    print(f"{DIM}[k]eep / [d]rop / [e]dit-severity / [a]ll-keep / [s]kip-rest / [q]uit{W}\n")

    kept: list[Vuln] = []
    skip_rest = False
    keep_all = False

    for i, v in enumerate(vulns, 1):
        if skip_rest:
            kept.append(v)
            continue
        if keep_all:
            kept.append(v)
            continue

        sev_color = {"CRITICAL": R, "HIGH": O, "MEDIUM": Y, "LOW": G, "INFO": C}.get(v.severity, W)

        print(f"\n{BOLD}[{i}/{len(vulns)}]{W} {sev_color}{v.severity}{W} (CVSS {v.cvss}) — {v.title}")
        print(f"    {DIM}Category: {v.category}{W}")
        if v.url:
            print(f"    {DIM}URL: {v.url}{W}")
        print(f"    {DIM}Evidence:{W}")
        for line in v.evidence.splitlines()[:5]:
            print(f"      {line[:120]}")

        try:
            resp = input(f"  {C}?{W} [k/d/e/a/s/q]: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{O}⚠{W} Verificación cancelada — manteniendo restantes")
            kept.extend(vulns[i-1:])
            break

        if resp == "q":
            print(f"{O}⚠{W} Quit — descartando restantes")
            break
        if resp == "s":
            skip_rest = True
            kept.append(v)
            continue
        if resp == "a":
            keep_all = True
            kept.append(v)
            continue
        if resp == "d":
            print(f"  {R}✗{W} Drop (marcado como FP)")
            continue
        if resp == "e":
            new_sev = input(f"  {C}?{W} Nueva severity (CRITICAL/HIGH/MEDIUM/LOW/INFO): ").strip().upper()
            if new_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                v.severity = new_sev
                print(f"  {G}✓{W} Severity → {new_sev}")
            kept.append(v)
            continue
        # default = keep
        print(f"  {G}✓{W} Keep")
        kept.append(v)

    print(f"\n{G}✓{W} Verificación completa: {len(kept)}/{len(vulns)} hallazgos mantenidos.\n")
    return kept
