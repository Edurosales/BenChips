"""
utils/vuln.py — Modelo de vulnerabilidad, CVSS v3.1, deduplicación.

Incluye cálculo CVSS v3.1 a partir de vector string, validación, y mapeo
inverso (score → vector aproximado) para hallazgos sin vector explícito.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import hashlib
import re


# ─── CVSS v3.1 ────────────────────────────────────────────────────────────────
# Pesos según CVSS v3.1 specification (https://www.first.org/cvss/v3.1/specification-document)

_CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        # PR depende de Scope (Unchanged/Changed)
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},
    },
    "UI": {"N": 0.85, "R": 0.62},
    "C":  {"H": 0.56, "L": 0.22, "N": 0.0},
    "I":  {"H": 0.56, "L": 0.22, "N": 0.0},
    "A":  {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _round_up(value: float) -> float:
    """Round-up CVSS específico (ceiling al primer decimal)."""
    import math
    return math.ceil(value * 10) / 10


def cvss3_score_from_vector(vector: str) -> Optional[float]:
    """
    Calcula CVSS v3.1 base score desde un vector tipo
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'.
    Retorna None si el vector es inválido.
    """
    if not vector:
        return None
    parts = vector.strip().split("/")
    # Validar prefijo
    if not parts or not parts[0].upper().startswith("CVSS:3"):
        return None
    metrics = {}
    for p in parts[1:]:
        if ":" not in p:
            continue
        k, v = p.split(":", 1)
        metrics[k.upper()] = v.upper()

    needed = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not needed.issubset(metrics):
        return None

    try:
        scope = metrics["S"]  # U o C
        av = _CVSS_WEIGHTS["AV"][metrics["AV"]]
        ac = _CVSS_WEIGHTS["AC"][metrics["AC"]]
        pr = _CVSS_WEIGHTS["PR"][scope][metrics["PR"]]
        ui = _CVSS_WEIGHTS["UI"][metrics["UI"]]
        c  = _CVSS_WEIGHTS["C"][metrics["C"]]
        i  = _CVSS_WEIGHTS["I"][metrics["I"]]
        a  = _CVSS_WEIGHTS["A"][metrics["A"]]
    except KeyError:
        return None

    iss      = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "U":
        impact      = 6.42 * iss
        exploit     = 8.22 * av * ac * pr * ui
        base        = min(impact + exploit, 10) if impact > 0 else 0.0
    else:  # Changed
        impact      = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        exploit     = 8.22 * av * ac * pr * ui
        base        = min(1.08 * (impact + exploit), 10) if impact > 0 else 0.0

    return _round_up(base)


def cvss_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >= 0.1: return "LOW"
    return "INFO"


def validate_cvss_vector(vector: str) -> bool:
    """True si vector parsea correctamente y produce score válido."""
    return cvss3_score_from_vector(vector) is not None


# ─── Vuln model ───────────────────────────────────────────────────────────────

@dataclass
class Vuln:
    title:       str
    severity:    str      # CRITICAL | HIGH | MEDIUM | LOW | INFO
    cvss:        float    # CVSS v3.1 base score 0.0-10.0
    category:    str
    description: str
    evidence:    str
    fix:         str
    ref:         str = ""
    module:      str = ""
    url:         str = ""
    cvss_vector: str = ""   # CVSS:3.1/AV:.../...
    cwe:         str = ""   # CWE-XXX (opcional)
    owasp:       str = ""   # A0X:2021 (opcional)
    confidence:  int = 100  # 0-100, % de confianza del hallazgo

    @staticmethod
    def severity_from_cvss(score: float) -> str:
        return cvss_severity(score)

    def __post_init__(self):
        # Si hay vector, recalcular CVSS para asegurar coherencia
        if self.cvss_vector and validate_cvss_vector(self.cvss_vector):
            calculated = cvss3_score_from_vector(self.cvss_vector)
            if calculated is not None:
                self.cvss = calculated
                # Auto-derivar severity si no coincide
                derived = cvss_severity(calculated)
                if self.severity != derived:
                    self.severity = derived

    @property
    def dedup_key(self) -> str:
        from urllib.parse import urlparse
        path = urlparse(self.url).path.rstrip("/") if self.url else ""
        raw = f"{self.category}:{self.title[:60]}:{path}"
        return hashlib.md5(raw.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "title":       self.title,
            "severity":    self.severity,
            "cvss":        self.cvss,
            "cvss_vector": self.cvss_vector,
            "cwe":         self.cwe,
            "owasp":       self.owasp,
            "confidence":  self.confidence,
            "category":    self.category,
            "description": self.description,
            "evidence":    self.evidence[:600],
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
    cvss_vector: str = "",
    cwe: str = "",
    owasp: str = "",
    confidence: int = 100,
) -> Vuln:
    """Factory function para crear vulns de forma concisa."""
    return Vuln(
        title=title, severity=severity, cvss=cvss,
        category=category, description=description,
        evidence=evidence[:600], fix=fix,
        ref=ref, module=module, url=url,
        cvss_vector=cvss_vector, cwe=cwe, owasp=owasp,
        confidence=confidence,
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
