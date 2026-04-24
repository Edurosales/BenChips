"""
utils/vuln.py — Modelo de vulnerabilidad, CVSS v3 scoring y deduplicación.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import hashlib


@dataclass
class Vuln:
    title:       str
    severity:    str      # CRITICAL | HIGH | MEDIUM | LOW | INFO
    cvss:        float    # CVSS v3 base score 0.0-10.0
    category:    str
    description: str
    evidence:    str
    fix:         str
    ref:         str = ""
    module:      str = ""
    url:         str = ""   # URL/endpoint donde se detectó

    @staticmethod
    def severity_from_cvss(score: float) -> str:
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 4.0: return "MEDIUM"
        if score >= 0.1: return "LOW"
        return "INFO"

    @property
    def dedup_key(self) -> str:
        raw = f"{self.category}:{self.title[:60]}"
        return hashlib.md5(raw.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "title":       self.title,
            "severity":    self.severity,
            "cvss":        self.cvss,
            "category":    self.category,
            "description": self.description,
            "evidence":    self.evidence[:300],
            "fix":         self.fix,
            "ref":         self.ref,
            "module":      self.module,
            "url":         self.url,
        }

    def sort_key(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(self.severity, 5)


def make_vuln(
    title: str,
    severity: str,
    cvss: float,
    category: str,
    description: str,
    evidence: str,
    fix: str,
    ref: str = "",
    module: str = "",
    url: str = "",
) -> Vuln:
    """Factory function para crear vulns de forma concisa."""
    return Vuln(
        title=title, severity=severity, cvss=cvss,
        category=category, description=description,
        evidence=evidence[:300], fix=fix,
        ref=ref, module=module, url=url,
    )


def deduplicate(vulns: list[Vuln]) -> list[Vuln]:
    """Elimina duplicados manteniendo la instancia de mayor severidad."""
    seen: dict[str, Vuln] = {}
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    for v in vulns:
        key = v.dedup_key
        if key not in seen:
            seen[key] = v
        else:
            if order.get(v.severity, 5) < order.get(seen[key].severity, 5):
                seen[key] = v

    return sorted(seen.values(), key=lambda x: x.sort_key())


def count_by_severity(vulns: list[Vuln]) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for v in vulns:
        counts[v.severity] = counts.get(v.severity, 0) + 1
    return counts


def risk_score(counts: dict[str, int]) -> tuple[int, str]:
    """Retorna (score, nivel) de riesgo global."""
    score = (
        counts.get("CRITICAL", 0) * 10 +
        counts.get("HIGH", 0) * 7 +
        counts.get("MEDIUM", 0) * 4 +
        counts.get("LOW", 0) * 1
    )
    level = (
        "CRÍTICO"  if score >= 30 else
        "ALTO"     if score >= 15 else
        "MODERADO" if score >= 7  else
        "BAJO"
    )
    return score, level
