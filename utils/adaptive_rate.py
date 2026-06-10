"""
utils/adaptive_rate.py — Rate limit adaptativo por host.

Detecta 429/503 y reduce concurrencia automáticamente. Si tras N minutos
sin 429 vuelve a subir concurrencia.

Estado por host (no global) para que un target rate-limited no afecte a otros.
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional
from urllib.parse import urlparse


class AdaptiveRateLimiter:
    """
    Maneja semáforos dinámicos por hostname.
    Llamar a record_response() después de cada request para que aprenda.
    """

    def __init__(
        self,
        initial_rate: int = 20,
        min_rate:     int = 2,
        max_rate:     int = 50,
    ):
        self.initial_rate = initial_rate
        self.min_rate     = min_rate
        self.max_rate     = max_rate
        self._semaphores: dict[str, asyncio.Semaphore] = {}
        self._current:    dict[str, int] = {}
        self._last_429:   dict[str, float] = {}
        self._last_up:    dict[str, float] = {}

    def _host(self, url: str) -> str:
        return urlparse(url).hostname or "unknown"

    def get_semaphore(self, url: str) -> asyncio.Semaphore:
        h = self._host(url)
        if h not in self._semaphores:
            self._semaphores[h] = asyncio.Semaphore(self.initial_rate)
            self._current[h]    = self.initial_rate
        return self._semaphores[h]

    def record_response(self, url: str, status: Optional[int]) -> None:
        h = self._host(url)
        if h not in self._current:
            self.get_semaphore(url)  # init

        now = time.monotonic()

        if status in (429, 503):
            # Reducir agresivamente
            self._last_429[h] = now
            new_rate = max(self.min_rate, self._current[h] // 2)
            if new_rate < self._current[h]:
                self._current[h]    = new_rate
                self._semaphores[h] = asyncio.Semaphore(new_rate)
        else:
            # Subir lento si llevamos 30 segundos sin 429
            last_429 = self._last_429.get(h, 0)
            last_up  = self._last_up.get(h, 0)
            if (now - last_429 > 30 and
                now - last_up > 15 and
                self._current[h] < self.max_rate):
                new_rate = min(self.max_rate, self._current[h] + 2)
                self._current[h]    = new_rate
                self._semaphores[h] = asyncio.Semaphore(new_rate)
                self._last_up[h]    = now

    def current_rate(self, url: str) -> int:
        return self._current.get(self._host(url), self.initial_rate)
