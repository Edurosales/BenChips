"""
utils/scope.py — Out-of-scope URL filtering.

Carga scope rules de .vulscope.yaml o pasadas por API:
  in_scope:
    - "*.example.com"
    - "api.example.com"
  out_of_scope:
    - "blog.example.com"
    - "*.internal.example.com"

Antes de cada request, verificar is_in_scope(url) → si no, se omite.
Crítico para programas de bug bounty con scope definido para evitar
fuera-de-alcance accidental.
"""

from __future__ import annotations

import fnmatch
import os
from typing import Optional
from urllib.parse import urlparse


class ScopeFilter:
    def __init__(
        self,
        in_scope:     Optional[list[str]] = None,
        out_of_scope: Optional[list[str]] = None,
    ):
        self.in_scope     = in_scope or []
        self.out_of_scope = out_of_scope or []

    @classmethod
    def from_file(cls, path: str) -> "ScopeFilter":
        if not os.path.exists(path):
            return cls()
        try:
            import yaml
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            return cls(
                in_scope     = data.get("in_scope") or [],
                out_of_scope = data.get("out_of_scope") or [],
            )
        except Exception:
            return cls()

    def is_in_scope(self, url: str) -> bool:
        hostname = urlparse(url).hostname or ""
        if not hostname:
            return False

        # Si hay reglas in_scope, debe matchear AL MENOS UNA
        if self.in_scope:
            if not any(fnmatch.fnmatchcase(hostname, pattern) for pattern in self.in_scope):
                return False

        # Si está en out_of_scope, denegado
        if any(fnmatch.fnmatchcase(hostname, pattern) for pattern in self.out_of_scope):
            return False

        return True

    def __repr__(self) -> str:
        return f"ScopeFilter(in_scope={self.in_scope}, out_of_scope={self.out_of_scope})"
