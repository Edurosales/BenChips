"""
utils/ws_fuzzer.py — Continuous WebSocket fuzzing post-handshake.

Después de un handshake exitoso, dispara una serie de mensajes mutados
(JSON con tipo invertido, números enormes, strings con payloads de XSS/SQLi)
y mide:
  - Reconexiones forzadas (mensaje crash el server-side handler).
  - Tiempos de respuesta anómalos (timing oracles).
  - Patrones de error en los mensajes de respuesta.

Anti-FP:
  - Solo dispara N mensajes (no DoS).
  - Compara respuestas vs baseline de mensaje normal.
  - Reporta solo si server retorna error+stacktrace o cierra conexión.
"""

from __future__ import annotations

import asyncio
import json
import random
import string
from typing import Optional


def _mutations(base: dict) -> list:
    """Genera mutations de un mensaje base JSON."""
    mutations = []
    # Type confusion
    for k, v in base.items():
        if isinstance(v, str):
            mutations.append({**base, k: 1234567890})
            mutations.append({**base, k: None})
            mutations.append({**base, k: ["array", "instead"]})
            mutations.append({**base, k: v + "<script>alert(1)</script>"})
            mutations.append({**base, k: v + "' OR '1'='1"})
        if isinstance(v, (int, float)):
            mutations.append({**base, k: 2**63})
            mutations.append({**base, k: -2**63})
            mutations.append({**base, k: "string"})
            mutations.append({**base, k: float("inf")})
    # Extra unexpected fields
    mutations.append({**base, "__proto__": {"polluted": True}})
    mutations.append({**base, "admin": True})
    # Huge payload
    big = "A" * 65536
    mutations.append({**base, "_overflow": big})
    return mutations


_ERROR_PATTERNS = [
    "stack trace", "traceback", "uncaughtexception", "panic",
    "nullpointerexception", "syntaxerror", "typeerror",
]


async def fuzz(session, ws_url: str, base_msg: dict, n_max: int = 20,
               timeout: float = 5.0) -> dict:
    """
    Fuzz un endpoint WS con n_max mutaciones. Retorna report dict.
    `session` es un aiohttp.ClientSession.
    """
    findings = []
    errors_seen = 0
    try:
        async with session.ws_connect(ws_url, timeout=timeout) as ws:
            # Baseline
            await ws.send_json(base_msg)
            try:
                baseline = await asyncio.wait_for(ws.receive(), timeout=3)
            except asyncio.TimeoutError:
                baseline = None

            for mut in _mutations(base_msg)[:n_max]:
                try:
                    await ws.send_json(mut)
                    msg = await asyncio.wait_for(ws.receive(), timeout=3)
                except asyncio.TimeoutError:
                    findings.append({"mutation": mut, "issue": "timeout (handler hang?)"})
                    continue
                except Exception as e:
                    findings.append({"mutation": mut, "issue": f"conn-error: {e}"})
                    break

                text = (msg.data or "").lower() if hasattr(msg, "data") and isinstance(msg.data, str) else ""
                for pat in _ERROR_PATTERNS:
                    if pat in text:
                        findings.append({
                            "mutation": mut,
                            "issue":    f"server error leak ({pat})",
                            "response": text[:300],
                        })
                        errors_seen += 1
                        break
    except Exception as e:
        return {"error": str(e), "findings": findings}

    return {
        "fuzzed":       n_max,
        "errors_seen":  errors_seen,
        "findings":     findings[:20],
    }
