"""
utils/bounty_tracker.py — JSON ledger de submissions y payouts.

Estructura: array de entries en ~/.vul/bounty_ledger.json
Cada entry:
  { date, program, target, title, severity, payout_usd, status, ref_id }
status: submitted | triaged | accepted | duplicate | informative | resolved | paid

Funciones:
  add_entry, list_entries, update_status, stats
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Optional


_LEDGER = os.path.join(os.path.expanduser("~"), ".vul", "bounty_ledger.json")


def _ensure_dir():
    os.makedirs(os.path.dirname(_LEDGER), exist_ok=True)


def _load() -> list[dict]:
    if not os.path.exists(_LEDGER):
        return []
    try:
        with open(_LEDGER, "r", encoding="utf-8") as f:
            return json.load(f) or []
    except Exception:
        return []


def _save(entries: list[dict]) -> None:
    _ensure_dir()
    with open(_LEDGER, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)
    try:
        os.chmod(_LEDGER, 0o600)
    except OSError:
        pass


def add_entry(entry: dict) -> dict:
    entries = _load()
    entry.setdefault("date", datetime.now().strftime("%Y-%m-%d"))
    entry.setdefault("id", f"vul-{len(entries)+1:04d}")
    entry.setdefault("payout", entry.get("payout_usd", 0))
    entries.append(entry)
    _save(entries)
    return entry


def list_entries(status: Optional[str] = None) -> list[dict]:
    entries = _load()
    if status:
        entries = [e for e in entries if e.get("status") == status]
    return entries


def update_status(entry_id: str, status: str, payout: Optional[float] = None) -> bool:
    entries = _load()
    for e in entries:
        if e.get("id") == entry_id:
            e["status"] = status
            if payout is not None:
                e["payout"] = payout
            _save(entries)
            return True
    return False


def stats() -> dict:
    entries = _load()
    paid = sum(float(e.get("payout", 0)) for e in entries
               if e.get("status") in ("paid", "resolved"))
    by_sev: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for e in entries:
        by_sev[e.get("severity", "?")] = by_sev.get(e.get("severity", "?"), 0) + 1
        by_status[e.get("status", "?")] = by_status.get(e.get("status", "?"), 0) + 1
    return {
        "total":      len(entries),
        "paid":       paid,
        "by_sev":     by_sev,
        "by_status":  by_status,
    }
