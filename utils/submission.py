"""
utils/submission.py — Auto-submission a plataformas de bug bounty.

Soporta API public de:
  - HackerOne (https://api.hackerone.com)
  - Bugcrowd  (NO public API estable; usa CLI o webhook).
  - Intigriti (https://api.intigriti.com)

IMPORTANTE:
  - Cada llamada requiere validación humana previa (vuln.confidence == 100).
  - Es OPT-IN — el CLI nunca submitea solo. Se invoca con `cli.py submit`.
  - Las credenciales se leen via utils/keyring_store.py.

Sin acceso a la API real, este módulo provee la estructura request-ready
y deja la POST opcional (dry-run por default).
"""

from __future__ import annotations

import json
import os
from typing import Optional

from utils.program_prompts import format_for_program


# ─── HackerOne ─────────────────────────────────────────────────────────────────

_H1_API = "https://api.hackerone.com/v1/reports"


async def submit_h1(client, program_handle: str, vuln, api_user: str,
                    api_token: str, dry_run: bool = True) -> dict:
    """
    Submit a hackerone via API. Devuelve {dry_run, payload, response}.
    """
    body_md = format_for_program(vuln, "h1")

    payload = {
        "data": {
            "type": "report",
            "attributes": {
                "team_handle":          program_handle,
                "title":                vuln.title[:120],
                "vulnerability_information": body_md,
                "impact":               vuln.description[:1000],
                "severity_rating":      _h1_severity(vuln.severity),
                "weakness_id":          _h1_weakness_id(vuln.cwe),
            },
        },
    }

    if dry_run:
        return {"dry_run": True, "payload": payload, "url": _H1_API}

    headers = {
        "Authorization": f"Basic {_basic_auth(api_user, api_token)}",
        "Accept":        "application/json",
        "Content-Type":  "application/json",
    }
    r = await client.session.post(_H1_API, json=payload, headers=headers)
    return {
        "dry_run":  False,
        "status":   r.status,
        "response": (await r.text())[:500],
    }


def _basic_auth(user, token) -> str:
    import base64
    return base64.b64encode(f"{user}:{token}".encode()).decode()


def _h1_severity(sev: str) -> str:
    return {
        "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
        "LOW": "low", "INFO": "none",
    }.get(sev, "low")


def _h1_weakness_id(cwe: str) -> Optional[int]:
    """Map common CWE → H1 weakness_id. Lista no exhaustiva."""
    m = {
        "CWE-79":  3,   "CWE-89":  10,  "CWE-918": 95, "CWE-22":  8,
        "CWE-352": 27,  "CWE-94":  20,  "CWE-200": 49, "CWE-601": 30,
        "CWE-862": 76,  "CWE-863": 77,  "CWE-307": 60, "CWE-798": 64,
        "CWE-347": 86,  "CWE-444": 83,
    }
    return m.get(cwe)


# ─── Intigriti ─────────────────────────────────────────────────────────────────

_INT_API = "https://api.intigriti.com/external/researcher/v2/submissions"


async def submit_intigriti(client, program_id: str, vuln, api_token: str,
                           dry_run: bool = True) -> dict:
    payload = {
        "programId": program_id,
        "title":     vuln.title[:200],
        "type":      vuln.category,
        "severity":  vuln.severity.lower(),
        "endpoint":  vuln.url,
        "description": format_for_program(vuln, "intigriti"),
    }
    if dry_run:
        return {"dry_run": True, "payload": payload, "url": _INT_API}

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type":  "application/json",
    }
    r = await client.session.post(_INT_API, json=payload, headers=headers)
    return {
        "dry_run":  False,
        "status":   r.status,
        "response": (await r.text())[:500],
    }


# ─── Top-level dispatch ───────────────────────────────────────────────────────

async def submit(platform: str, program_ref: str, vuln, creds: dict,
                 dry_run: bool = True, client=None) -> dict:
    """
    platform: 'h1' | 'intigriti' | 'bugcrowd'
    creds: {api_user?, api_token}
    """
    platform = platform.lower()
    if platform == "h1":
        return await submit_h1(client, program_ref, vuln,
                                creds.get("api_user", ""), creds["api_token"], dry_run)
    if platform == "intigriti":
        return await submit_intigriti(client, program_ref, vuln,
                                       creds["api_token"], dry_run)
    if platform == "bugcrowd":
        # Bugcrowd no tiene public submission API; mostrar instrucciones
        return {
            "platform": "bugcrowd",
            "note":     "Bugcrowd no expone API pública para submission. "
                        "Usar dashboard manualmente o invocar bugcrowd-cli.",
            "markdown": format_for_program(vuln, "bugcrowd"),
        }
    return {"error": f"plataforma desconocida: {platform}"}
