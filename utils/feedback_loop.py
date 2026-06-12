"""
utils/feedback_loop.py — FP/válido feedback loop.

El usuario marca un hallazgo como FP o válido (vía cli.py verify). Aquí
guardamos esos patrones en `~/.vul/feedback.json` para que futuros scans
los descarten o promuevan automáticamente.

Reglas aprendidas:
  - Marca un hallazgo (módulo, cwe, host, signature_hash) como FP repetidos
    veces → confidence se reduce a 0 (no se reporta).
  - Marca como válido → confidence se mantiene al 100%.

El matching es por:
  - mismo (module + cwe + url_path) → match exacto
  - mismo (module + cwe + first_200_chars_evidence_hash) → match approx
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse


_FEEDBACK_FILE = os.path.join(os.path.expanduser("~"), ".vul", "feedback.json")


def _ensure_dir():
    os.makedirs(os.path.dirname(_FEEDBACK_FILE), exist_ok=True)


def _load() -> dict:
    if not os.path.exists(_FEEDBACK_FILE):
        return {"fp_signatures": {}, "valid_signatures": {}}
    try:
        with open(_FEEDBACK_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"fp_signatures": {}, "valid_signatures": {}}


def _save(data: dict) -> None:
    _ensure_dir()
    with open(_FEEDBACK_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(_FEEDBACK_FILE, 0o600)
    except OSError:
        pass


def _signature(vuln) -> str:
    """Genera firma reproducible para (module, cwe, url_path, evidence_hash)."""
    url_path = ""
    if vuln.url:
        try:
            url_path = urlparse(vuln.url).path
        except Exception:
            pass
    ev_hash = hashlib.md5(vuln.evidence[:200].encode()).hexdigest()[:10]
    return f"{vuln.module}|{vuln.cwe}|{url_path}|{ev_hash}"


def mark_fp(vuln, note: str = "") -> None:
    """Marca el patrón de este vuln como FP."""
    data = _load()
    sig = _signature(vuln)
    entry = data["fp_signatures"].get(sig, {"count": 0, "title": vuln.title, "first_seen": None})
    entry["count"]      = entry.get("count", 0) + 1
    entry["last_seen"]  = datetime.now().isoformat()
    entry["first_seen"] = entry.get("first_seen") or entry["last_seen"]
    entry["note"]       = note
    data["fp_signatures"][sig] = entry
    _save(data)


def mark_valid(vuln, payout_usd: float = 0) -> None:
    """Marca el patrón como válido (confirmado bug)."""
    data = _load()
    sig = _signature(vuln)
    entry = data["valid_signatures"].get(sig, {"count": 0, "title": vuln.title})
    entry["count"]      = entry.get("count", 0) + 1
    entry["last_seen"]  = datetime.now().isoformat()
    entry["payout_usd"] = max(entry.get("payout_usd", 0), payout_usd)
    data["valid_signatures"][sig] = entry
    _save(data)


def filter_known_fps(vulns: list, min_fp_count: int = 2) -> tuple[list, list]:
    """
    Devuelve (vulns_filtrados, vulns_descartados).
    Descarta vulns cuyo signature esté marcado como FP >= min_fp_count veces.
    """
    data = _load()
    fps = data.get("fp_signatures", {})
    kept = []
    dropped = []
    for v in vulns:
        sig = _signature(v)
        fp_count = fps.get(sig, {}).get("count", 0)
        if fp_count >= min_fp_count:
            dropped.append(v)
        else:
            kept.append(v)
    return kept, dropped


def boost_known_valid(vulns: list) -> list:
    """
    Bumps confidence de vulns cuyo patrón ya fue confirmado válido antes.
    """
    data = _load()
    valids = data.get("valid_signatures", {})
    for v in vulns:
        sig = _signature(v)
        if sig in valids:
            v.confidence = 100
    return vulns


def stats() -> dict:
    data = _load()
    return {
        "total_fp_patterns":    len(data.get("fp_signatures", {})),
        "total_valid_patterns": len(data.get("valid_signatures", {})),
        "top_fps":              sorted(
            [(s, e["count"], e.get("title", "")) for s, e in data.get("fp_signatures", {}).items()],
            key=lambda x: -x[1],
        )[:10],
        "top_valids":           sorted(
            [(s, e["count"], e.get("title", ""), e.get("payout_usd", 0))
             for s, e in data.get("valid_signatures", {}).items()],
            key=lambda x: -x[3],
        )[:10],
    }
