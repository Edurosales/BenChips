"""
utils/state.py — Checkpoint / resume support para scans largos.

Estado por scan se guarda en .vulstate/{hash_url}.json y contiene:
  - phases_completed: lista de nombres de fases (recon, headers, ssl, etc)
  - vulns_so_far: list[dict] de vulns ya encontradas
  - meta: dict acumulado
  - timestamp

Permite reanudar después de Ctrl+C o crash sin perder progreso.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Optional


_STATE_DIR = ".vulstate"


def _state_path(url: str) -> str:
    os.makedirs(_STATE_DIR, exist_ok=True)
    h = hashlib.md5(url.encode()).hexdigest()[:16]
    return os.path.join(_STATE_DIR, f"{h}.json")


def load_state(url: str) -> Optional[dict]:
    p = _state_path(url)
    if not os.path.exists(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_state(url: str, state: dict) -> None:
    p = _state_path(url)
    state["url"]       = url
    state["timestamp"] = time.time()
    try:
        with open(p, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, default=str)
    except Exception:
        pass  # No bloquear scan por error de checkpoint


def clear_state(url: str) -> None:
    p = _state_path(url)
    if os.path.exists(p):
        try:
            os.remove(p)
        except OSError:
            pass


def has_resumable(url: str, max_age_hours: int = 24) -> bool:
    """True si hay estado reciente (último día) reanudable."""
    state = load_state(url)
    if not state:
        return False
    ts = state.get("timestamp", 0)
    return (time.time() - ts) < (max_age_hours * 3600)
