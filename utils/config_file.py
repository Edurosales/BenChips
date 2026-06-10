"""
utils/config_file.py — .vulrc.yaml configuration file support.

Permite guardar opciones por proyecto:
  default_options:
    stealth: true
    full: true
    active: false
    ai_triage: true
    reports: [html, json, md_h1]
  proxies:
    - http://127.0.0.1:8080
  scope_file: .vulscope.yaml
  excluded_modules:
    - smuggling   # módulo invasivo
"""

from __future__ import annotations

import os
from typing import Optional


_RC_NAMES = [".vulrc.yaml", ".vulrc.yml", "vulrc.yaml"]


def find_rc(cwd: Optional[str] = None) -> Optional[str]:
    """Busca .vulrc.yaml en cwd o cualquier ancestro."""
    here = os.path.abspath(cwd or os.getcwd())
    while True:
        for name in _RC_NAMES:
            candidate = os.path.join(here, name)
            if os.path.isfile(candidate):
                return candidate
        parent = os.path.dirname(here)
        if parent == here:
            return None
        here = parent


def load_rc(path: Optional[str] = None) -> dict:
    if path is None:
        path = find_rc()
    if not path or not os.path.isfile(path):
        return {}
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def merge_opts_with_rc(opts: dict, rc: dict) -> dict:
    """Defaults del rc, sobreescritos por opts explícitos del usuario."""
    defaults = rc.get("default_options", {})
    out = dict(defaults)
    out.update({k: v for k, v in opts.items() if v is not None and v != ""})
    # Proxies: combinar las dos listas
    rc_proxies   = rc.get("proxies") or []
    opts_proxies = opts.get("proxies") or []
    if rc_proxies or opts_proxies:
        out["proxies"] = list({*rc_proxies, *opts_proxies})
    if rc.get("scope_file"):
        out["scope_file"] = rc["scope_file"]
    if rc.get("excluded_modules"):
        out["excluded_modules"] = rc["excluded_modules"]
    return out
