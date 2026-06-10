"""
utils/auth.py — Configuración de autenticación para escaneos detrás de login.

Soporta:
  - Session cookies  (pegar directo desde DevTools)
  - Bearer token     (JWT, OAuth)
  - HTTP Basic Auth  (usuario:contraseña)
  - Headers custom   (X-API-Key, X-Auth-Token, etc.)
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AuthConfig:
    """Configuración de autenticación para el escáner."""
    cookies: str = ""                                   # "session=abc; csrf=xyz"
    bearer_token: str = ""                              # "eyJhbGc..." o "Bearer eyJ..."
    basic_user: str = ""
    basic_pass: str = ""
    custom_headers: dict[str, str] = field(default_factory=dict)  # {"X-API-Key": "xxx"}

    @property
    def is_configured(self) -> bool:
        return bool(
            self.cookies or self.bearer_token
            or self.basic_user or self.custom_headers
        )

    def to_headers(self) -> dict[str, str]:
        """Convierte la config a headers HTTP listos para inyectar en cada request."""
        h: dict[str, str] = {}

        if self.cookies:
            h["Cookie"] = self.cookies

        if self.bearer_token:
            tok = self.bearer_token.strip()
            if not tok.lower().startswith("bearer "):
                tok = f"Bearer {tok}"
            h["Authorization"] = tok
        elif self.basic_user:
            creds = base64.b64encode(
                f"{self.basic_user}:{self.basic_pass}".encode()
            ).decode()
            h["Authorization"] = f"Basic {creds}"

        h.update(self.custom_headers)
        return h


def prompt_auth() -> Optional[AuthConfig]:
    """
    Pregunta interactivamente si el usuario quiere configurar autenticación.
    Retorna AuthConfig si se configuró, None si no.
    """
    try:
        from utils.colors import C, W, DIM, G, O
    except ImportError:
        C = W = DIM = G = O = ""

    try:
        ans = input(f"\n  {C}?{W}  ¿Escaneo autenticado (detrás de login)? [s/N]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return None

    if ans not in ("s", "si", "sí", "y", "yes"):
        return None

    print(f"\n  {DIM}Pega tus credenciales. Cada campo es opcional, Enter para omitir.{W}")
    print(f"  {DIM}Tip cookies: DevTools (F12) → Network → cualquier request → Cookie header{W}\n")

    auth = AuthConfig()

    try:
        import getpass
        cookies = getpass.getpass(f"  {C}▶{W}  Cookies (oculto; Enter omite): ").strip()
        if cookies:
            auth.cookies = cookies

        token = getpass.getpass(f"  {C}▶{W}  Bearer Token (oculto; Enter omite): ").strip()
        if token:
            auth.bearer_token = token

        if not auth.cookies and not auth.bearer_token:
            user = input(f"  {C}▶{W}  Usuario Basic Auth: ").strip()
            if user:
                auth.basic_user = user
                auth.basic_pass = getpass.getpass(f"  {C}▶{W}  Contraseña (oculto): ").strip()

        custom = input(f"  {C}▶{W}  Header custom (Nombre: Valor, Enter para omitir): ").strip()
        if custom and ":" in custom:
            name, _, val = custom.partition(":")
            auth.custom_headers[name.strip()] = val.strip()

    except (KeyboardInterrupt, EOFError):
        return None

    if auth.is_configured:
        print(f"  {G}✓{W}  Autenticación configurada — el escáner usará estas credenciales.")
        return auth

    print(f"  {O}⚠{W}  Sin credenciales configuradas.")
    return None
