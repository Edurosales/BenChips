"""
utils/audit_log.py — Audit logging para compliance / forensics.

Loggea cada request enviado: método, URL, body hash, status, timestamp.
Útil para:
  - Compliance pentest reports (qué se probó exactamente)
  - Investigar FPs después del scan
  - Detectar si nuestro scanner causó issues (correlación con logs del target)

Formato: JSONL en .vullogs/{date}.jsonl
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from datetime import datetime
from typing import Optional


_LOG_DIR = ".vullogs"
_LOCK = threading.Lock()
_ENABLED = False


def enable(enabled: bool = True) -> None:
    global _ENABLED
    _ENABLED = enabled
    if enabled:
        os.makedirs(_LOG_DIR, exist_ok=True)


def is_enabled() -> bool:
    return _ENABLED


def _log_path() -> str:
    date = datetime.now().strftime("%Y-%m-%d")
    return os.path.join(_LOG_DIR, f"audit-{date}.jsonl")


def log_request(
    method:        str,
    url:           str,
    status:        Optional[int] = None,
    request_body:  Optional[bytes] = None,
    response_size: Optional[int] = None,
    extra:         Optional[dict] = None,
) -> None:
    if not _ENABLED:
        return

    entry = {
        "ts":       time.time(),
        "iso":      datetime.now().isoformat(),
        "method":   method,
        "url":      url[:500],
        "status":   status,
        "resp_sz":  response_size,
    }
    if request_body:
        entry["req_hash"] = hashlib.sha256(request_body).hexdigest()[:16]
        entry["req_sz"]   = len(request_body)
    if extra:
        entry["extra"] = extra

    with _LOCK:
        try:
            with open(_log_path(), "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass


def log_event(event: str, data: Optional[dict] = None) -> None:
    """Eventos no-HTTP (scan start, phase complete, etc)."""
    if not _ENABLED:
        return
    entry = {
        "ts":    time.time(),
        "iso":   datetime.now().isoformat(),
        "event": event,
        "data":  data or {},
    }
    with _LOCK:
        try:
            with open(_log_path(), "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass
