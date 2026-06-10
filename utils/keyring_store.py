"""
utils/keyring_store.py — Secrets at-rest cifrados usando keyring del SO.

Almacena API keys en:
  - Windows Credential Manager
  - macOS Keychain
  - Linux Secret Service (gnome-keyring / kwallet)

Fallback: si keyring no está disponible, usa el JSON con chmod 0600 (modo legacy).

Uso:
  store_secret("ai_provider_openai", "sk-...")
  load_secret("ai_provider_openai")  # → "sk-..."
"""

from __future__ import annotations

import json
import os
from typing import Optional


_SERVICE = "BugBountyHunterPro"
_FALLBACK_FILE = ".secrets.json"


def _try_keyring():
    try:
        import keyring  # type: ignore
        return keyring
    except ImportError:
        return None


def store_secret(name: str, value: str) -> bool:
    """True si se almacenó en keyring; False si fallback JSON."""
    kr = _try_keyring()
    if kr:
        try:
            kr.set_password(_SERVICE, name, value)
            return True
        except Exception:
            pass

    # Fallback JSON
    data = {}
    if os.path.exists(_FALLBACK_FILE):
        try:
            with open(_FALLBACK_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
    data[name] = value
    try:
        with open(_FALLBACK_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.chmod(_FALLBACK_FILE, 0o600)
    except OSError:
        pass
    return False


def load_secret(name: str) -> Optional[str]:
    kr = _try_keyring()
    if kr:
        try:
            v = kr.get_password(_SERVICE, name)
            if v:
                return v
        except Exception:
            pass

    if os.path.exists(_FALLBACK_FILE):
        try:
            with open(_FALLBACK_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get(name)
        except Exception:
            return None
    return None


def delete_secret(name: str) -> None:
    kr = _try_keyring()
    if kr:
        try:
            kr.delete_password(_SERVICE, name)
        except Exception:
            pass

    if os.path.exists(_FALLBACK_FILE):
        try:
            with open(_FALLBACK_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            data.pop(name, None)
            with open(_FALLBACK_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass


def has_keyring() -> bool:
    return _try_keyring() is not None
