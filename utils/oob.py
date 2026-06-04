"""
utils/oob.py — Out-Of-Band (OOB) detection con múltiples backends.

Backends en orden de prioridad:
  1. interactsh (oast.pro / oast.site / …) — DNS + HTTP, requiere cryptography
  2. webhook.site — HTTP-only, sin dependencias extra, funciona en redes corporativas

Si ambos fallan → OOB desactivado (degradación silenciosa, se usa detección por respuesta).

Uso:
    oob = OOBClient()
    ok, msg = await oob.register(session)
    if ok:
        payload_url = oob.new_payload("ssrf")
        # inyectar payload_url en el target
        interaction = await oob.wait_for(oob.last_uid, session, timeout=15)
        if interaction:
            # SSRF confirmado
"""
from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid
from typing import Optional

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    _CRYPTO = True
except Exception:
    _CRYPTO = False

# Servidores públicos de interactsh
_INTERACTSH_SERVERS = [
    "oast.pro", "oast.site", "oast.live", "oast.me", "oast.fun",
]

_WEBHOOK_REGISTER = "https://webhook.site/token"
_WEBHOOK_REQUESTS = "https://webhook.site/token/{uuid}/requests"


class OOBClient:
    """
    Cliente OOB multi-backend.
    Genera URLs rastreables únicas para inyectar en SSRF/XSS/SQLi blind.
    """

    def __init__(self):
        self._backend:  Optional[str] = None   # "interactsh" | "webhook"
        self._registered = False

        # interactsh state
        self._srv:        Optional[str] = None
        self._corr_id:    Optional[str] = None
        self._secret:     Optional[str] = None
        self._priv_key    = None

        # webhook.site state
        self._wh_uuid:    Optional[str] = None
        self._wh_seen:    set[str]      = set()   # UUIDs ya procesados

        # Tracking de payloads enviados
        self._pending:    dict[str, str] = {}      # uid → tag
        self.last_uid:    str            = ""

    @property
    def available(self) -> bool:
        return self._registered

    @property
    def backend(self) -> str:
        return self._backend or "ninguno"

    @property
    def correlation_id(self) -> str:
        return self._corr_id or ""

    @property
    def server(self) -> str:
        return self._srv or ""

    # ── Registro ──────────────────────────────────────────────────────────────

    async def register(self, session) -> tuple[bool, str]:
        """
        Intenta registrar con interactsh primero, luego webhook.site.
        Retorna (True, "") o (False, motivo_del_fallo).
        """
        # ── Backend 1: interactsh ─────────────────────────────────────────────
        if _CRYPTO:
            ok, err = await self._register_interactsh(session)
            if ok:
                self._backend = "interactsh"
                return True, ""
            interactsh_err = err
        else:
            interactsh_err = "cryptography no instalado"

        # ── Backend 2: webhook.site ───────────────────────────────────────────
        ok, err = await self._register_webhook(session)
        if ok:
            self._backend = "webhook"
            return True, ""

        return False, (
            f"interactsh: {interactsh_err} | "
            f"webhook.site: {err} | "
            "¿red bloquea conexiones salientes?"
        )

    async def _register_interactsh(self, session) -> tuple[bool, str]:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_b64 = base64.b64encode(
            priv.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode()
        secret  = uuid.uuid4().hex
        corr_id = uuid.uuid4().hex[:20]

        import aiohttp
        last_err = "todos los servidores fallaron"
        for srv in _INTERACTSH_SERVERS:
            try:
                async with session.post(
                    f"https://{srv}/register",
                    json={"public-key": pub_b64, "secret-key": secret, "correlation-id": corr_id},
                    timeout=aiohttp.ClientTimeout(total=8),
                    ssl=False,
                ) as r:
                    if r.status in (200, 201):
                        self._srv     = srv
                        self._corr_id = corr_id
                        self._secret  = secret
                        self._priv_key = priv
                        self._registered = True
                        return True, ""
                    last_err = f"{srv}: HTTP {r.status}"
            except asyncio.TimeoutError:
                last_err = f"{srv}: timeout"
            except Exception as e:
                last_err = f"{srv}: {type(e).__name__}"
        return False, last_err

    async def _register_webhook(self, session) -> tuple[bool, str]:
        """webhook.site — no requiere crypto ni DNS especial."""
        import aiohttp
        try:
            async with session.post(
                _WEBHOOK_REGISTER,
                json={},
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False,
            ) as r:
                if r.status in (200, 201):
                    data = await r.json()
                    self._wh_uuid    = data.get("uuid") or data.get("id")
                    self._registered = True
                    # exponer misma interfaz que interactsh
                    self._corr_id = self._wh_uuid[:8] if self._wh_uuid else "wh"
                    self._srv     = "webhook.site"
                    return True, ""
                return False, f"HTTP {r.status}"
        except asyncio.TimeoutError:
            return False, "timeout"
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"

    # ── Generación de payloads ────────────────────────────────────────────────

    def new_payload(self, tag: str = "") -> str:
        """
        Genera una URL/dominio único rastreable para inyectar como payload SSRF.
        Guarda el uid en self.last_uid para pasarlo a wait_for().
        """
        uid = uuid.uuid4().hex[:12]
        self._pending[uid] = tag
        self.last_uid = uid

        if self._backend == "interactsh":
            label = f"{uid}-{tag}" if tag else uid
            return f"http://{label}.{self._corr_id}.{self._srv}/"

        if self._backend == "webhook":
            # URL HTTP embebiendo el uid como path segment para identificarlo
            return f"https://webhook.site/{self._wh_uuid}/{uid}"

        return ""

    # ── Polling ───────────────────────────────────────────────────────────────

    async def poll(self, session) -> list[dict]:
        """Consulta interacciones recibidas. Retorna lista de eventos normalizados."""
        if self._backend == "interactsh":
            return await self._poll_interactsh(session)
        if self._backend == "webhook":
            return await self._poll_webhook(session)
        return []

    async def _poll_interactsh(self, session) -> list[dict]:
        import aiohttp
        try:
            async with session.get(
                f"https://{self._srv}/poll",
                params={"id": self._corr_id, "secret": self._secret},
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False,
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    return self._decrypt_interactsh(
                        data.get("data") or [], data.get("aes_key", "")
                    )
        except Exception:
            pass
        return []

    def _decrypt_interactsh(self, items: list[str], aes_key_b64: str) -> list[dict]:
        if not items or not aes_key_b64 or not self._priv_key:
            return []
        try:
            aes_key = self._priv_key.decrypt(
                base64.b64decode(aes_key_b64),
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            results = []
            for item in items:
                raw = base64.b64decode(item)
                iv, ct = raw[:16], raw[16:]
                dec = Cipher(algorithms.AES(aes_key), modes.CFB(iv)).decryptor()
                results.append(json.loads(dec.update(ct) + dec.finalize()))
            return results
        except Exception:
            return []

    async def _poll_webhook(self, session) -> list[dict]:
        """Consulta webhook.site por requests recibidos."""
        import aiohttp
        try:
            async with session.get(
                _WEBHOOK_REQUESTS.format(uuid=self._wh_uuid),
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False,
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    results = []
                    for req in data.get("data", []):
                        req_id = req.get("uuid", "")
                        if req_id in self._wh_seen:
                            continue
                        self._wh_seen.add(req_id)
                        # Normalizar al mismo formato que interactsh
                        url_path = req.get("url", "")
                        results.append({
                            "full-id":        url_path,   # contiene el uid del payload
                            "protocol":       "HTTP",
                            "remote-address": req.get("ip", "?"),
                            "method":         req.get("method", "GET"),
                            "url":            url_path,
                        })
                    return results
        except Exception:
            pass
        return []

    # ── Espera y recolección ──────────────────────────────────────────────────

    async def wait_for(
        self,
        uid_prefix: str,
        session,
        timeout: float = 15.0,
        interval: float = 2.0,
    ) -> Optional[dict]:
        """
        Espera hasta timeout segundos por una interacción que contenga uid_prefix.
        Funciona con ambos backends.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for inter in await self.poll(session):
                full_id = (
                    inter.get("full-id", "") or
                    inter.get("unique-id", "") or
                    inter.get("url", "")
                )
                if uid_prefix.lower() in full_id.lower():
                    return inter
            await asyncio.sleep(interval)
        return None

    async def collect_all(self, session, timeout: float = 12.0) -> list[dict]:
        """
        Recoge TODAS las interacciones pendientes en una ventana de tiempo.
        Útil para verificar varios payloads SSRF de una sola vez.
        """
        all_interactions: list[dict] = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            batch = await self.poll(session)
            all_interactions.extend(batch)
            await asyncio.sleep(2.0 if batch else 2.5)
        return all_interactions

    # ── Helpers ───────────────────────────────────────────────────────────────

    def uid_in_interaction(self, uid: str, interaction: dict) -> bool:
        """Comprueba si un uid específico está en una interacción recibida."""
        for field in ("full-id", "unique-id", "url", "full_id"):
            if uid.lower() in interaction.get(field, "").lower():
                return True
        return False
