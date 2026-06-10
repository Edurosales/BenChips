"""
utils/tracer.py — Verbose JSON tracing para debug de FPs.

Cada vez que un módulo emite un Vuln, se loggea el "path" de detección:
qué condiciones se cumplieron, qué baseline se comparó, etc.

Salida: .vultrace/{scan_id}.jsonl
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Optional


_TRACE_DIR = ".vultrace"
_LOCK = threading.Lock()
_ENABLED = False
_CURRENT_SCAN: Optional[str] = None


def enable(scan_id: str) -> None:
    global _ENABLED, _CURRENT_SCAN
    _ENABLED = True
    _CURRENT_SCAN = scan_id
    os.makedirs(_TRACE_DIR, exist_ok=True)


def disable() -> None:
    global _ENABLED
    _ENABLED = False


def trace(module: str, event: str, **data) -> None:
    if not _ENABLED:
        return
    entry = {
        "ts":     time.time(),
        "module": module,
        "event":  event,
        "data":   data,
    }
    path = os.path.join(_TRACE_DIR, f"{_CURRENT_SCAN}.jsonl")
    with _LOCK:
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except Exception:
            pass
