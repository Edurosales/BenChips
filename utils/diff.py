"""
utils/diff.py — Diff entre dos scans del mismo target.

Compara dos archivos JSON de reportes y muestra:
  - Nuevos hallazgos (no estaban antes)
  - Hallazgos resueltos (ya no aparecen)
  - Hallazgos persistentes
  - Cambios de severidad
"""

from __future__ import annotations

import json
from typing import Optional


def load_report(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def diff_reports(old_path: str, new_path: str) -> dict:
    """
    Retorna dict con: new, resolved, persistent, severity_changed.
    Asume formato del reporte JSON nuestro (lista en 'vulnerabilidades').
    """
    old = load_report(old_path) or {}
    new = load_report(new_path) or {}

    old_vulns = old.get("vulnerabilidades", [])
    new_vulns = new.get("vulnerabilidades", [])

    def key(v: dict) -> str:
        return f"{v.get('category','?')}::{v.get('title','?')[:60]}::{v.get('url','')}"

    old_map = {key(v): v for v in old_vulns}
    new_map = {key(v): v for v in new_vulns}

    new_found     = [v for k, v in new_map.items() if k not in old_map]
    resolved      = [v for k, v in old_map.items() if k not in new_map]
    persistent    = [(old_map[k], new_map[k]) for k in old_map if k in new_map]
    sev_changed   = [
        (o, n) for o, n in persistent
        if o.get("severity") != n.get("severity") or o.get("cvss") != n.get("cvss")
    ]

    return {
        "new":              new_found,
        "resolved":         resolved,
        "persistent":       [n for _, n in persistent],
        "severity_changed": sev_changed,
        "old_count":        len(old_vulns),
        "new_count":        len(new_vulns),
    }


def format_diff(d: dict) -> str:
    """Texto formateado del diff."""
    lines = [
        f"═══ Scan Diff ═══",
        f"Old: {d['old_count']} hallazgos | New: {d['new_count']} hallazgos",
        f"  + {len(d['new'])} nuevos",
        f"  - {len(d['resolved'])} resueltos",
        f"  ~ {len(d['severity_changed'])} cambio de severidad",
        "",
    ]
    if d["new"]:
        lines.append("NUEVOS:")
        for v in d["new"]:
            lines.append(f"  + [{v.get('severity','?')}] {v.get('title','?')}")
    if d["resolved"]:
        lines.append("")
        lines.append("RESUELTOS:")
        for v in d["resolved"]:
            lines.append(f"  - [{v.get('severity','?')}] {v.get('title','?')}")
    if d["severity_changed"]:
        lines.append("")
        lines.append("SEVERIDAD CAMBIADA:")
        for o, n in d["severity_changed"]:
            lines.append(
                f"  ~ {n.get('title','?')[:60]}: "
                f"{o.get('severity')} → {n.get('severity')} "
                f"(CVSS {o.get('cvss')} → {n.get('cvss')})"
            )
    return "\n".join(lines)
