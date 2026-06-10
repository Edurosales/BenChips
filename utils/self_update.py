"""
utils/self_update.py — Check de releases en GitHub.

No descarga ni aplica updates automáticamente (peligroso); solo notifica
si hay versión nueva. Usuario decide cómo actualizar.
"""

from __future__ import annotations

import json
import re
from typing import Optional


_RELEASES_URL = "https://api.github.com/repos/{org}/{repo}/releases/latest"


async def check_update(
    client,                     # AsyncHTTPClient
    org:             str = "anonymous",
    repo:            str = "bugbountyhunter",
    current_version: str = "6.0",
) -> Optional[dict]:
    """
    Devuelve dict {latest, current, update_available, url} o None si falla.
    """
    url = _RELEASES_URL.format(org=org, repo=repo)
    r = await client.get(url, body_limit=8192)
    if not r or r.status != 200:
        return None
    try:
        data = json.loads(r.text)
    except Exception:
        return None

    latest = data.get("tag_name", "").lstrip("v")
    if not latest:
        return None

    def _parse(v: str) -> tuple[int, ...]:
        nums = re.findall(r"\d+", v)
        return tuple(int(n) for n in nums) if nums else (0,)

    update_available = _parse(latest) > _parse(current_version)

    return {
        "latest":           latest,
        "current":          current_version,
        "update_available": update_available,
        "url":              data.get("html_url", ""),
        "body":             (data.get("body") or "")[:500],
    }
