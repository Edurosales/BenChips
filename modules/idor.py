"""
modules/idor.py — Insecure Direct Object Reference auto-discovery.

Detecta IDs secuenciales en URLs y APIs y verifica si el acceso a IDs
distintos del propio devuelve datos sensibles.

Detección:
  1. Crawler ya descubrió URLs con patrones tipo /api/user/123, /post/456
  2. Para cada uno, probar IDs adjacentes (id-1, id-2, id+1)
  3. Comparar respuestas — si son distintas y contienen patrones tipo
     email/PII, marcar como IDOR potencial.

Anti-FP:
  - Si los responses tienen el MISMO error (401/403) → endpoint protegido.
  - Si TODOS los IDs devuelven el mismo response → no es IDOR (probable
    placeholder o error genérico).
  - Solo reportar si hay variación en el contenido.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


# Patrón URL con ID numérico en el path: /api/user/123, /post/456
_ID_PATTERN = re.compile(
    r"^(.+/(?:user|users|account|post|posts|order|orders|invoice|invoices|"
    r"product|profile|customer|item|file|document|message|ticket|case)s?/)(\d{1,8})(/.*)?$",
    re.IGNORECASE,
)

# Patrones que sugieren datos sensibles (PII) en respuesta
_PII_PATTERNS = [
    re.compile(r"\"email\"\s*:\s*\"[^\"]+@[^\"]+\""),
    re.compile(r"\"phone\"\s*:\s*\"[\d\+\-\(\)\s]{7,}\""),
    re.compile(r"\"ssn\"\s*:\s*\"\d{3}-\d{2}-\d{4}\""),
    re.compile(r"\"credit_card\""),
    re.compile(r"\"password_hash\""),
    re.compile(r"\"address\"\s*:\s*\{"),
]


async def run(
    client: AsyncHTTPClient,
    url:    str,
    crawled_urls: list[str] | None = None,
) -> list[Vuln]:
    vulns: list[Vuln] = []

    if not crawled_urls:
        return vulns

    # Filtrar URLs con IDs numéricos
    candidates: list[tuple[str, str, str, int]] = []
    seen_patterns: set[str] = set()
    for u in crawled_urls:
        m = _ID_PATTERN.match(u)
        if not m:
            continue
        prefix, id_str, suffix = m.group(1), m.group(2), m.group(3) or ""
        pattern_key = prefix + suffix
        if pattern_key in seen_patterns:
            continue
        seen_patterns.add(pattern_key)
        candidates.append((u, prefix, suffix, int(id_str)))

    if not candidates:
        return vulns

    sem = asyncio.Semaphore(3)

    async def probe_pattern(orig_url: str, prefix: str, suffix: str, orig_id: int):
        async with sem:
            # Probar 3 IDs cercanos
            test_ids = [orig_id - 1, orig_id + 1, orig_id + 100]
            results = []
            for tid in test_ids:
                if tid < 1:
                    continue
                test_url = f"{prefix}{tid}{suffix}"
                r = await client.get(test_url, body_limit=16384)
                if r:
                    results.append((tid, test_url, r))

            # Necesitamos al menos 2 respuestas para comparar
            if len(results) < 2:
                return

            # Si todas devuelven 401/403 → protegido OK
            if all(r.status in (401, 403, 404) for _, _, r in results):
                return

            # Comparar bodies — si varían y contienen PII → IDOR confirmado
            ok_results = [(tid, u, r) for tid, u, r in results if r.status == 200]
            if len(ok_results) < 2:
                return

            # Verificar que NO son todos el mismo body (página de error genérica)
            bodies = [r.text for _, _, r in ok_results]
            if all(b == bodies[0] for b in bodies):
                return

            # PII en alguna respuesta
            for tid, u, r in ok_results:
                pii_hits = sum(1 for p in _PII_PATTERNS if p.search(r.text))
                if pii_hits >= 1:
                    vulns.append(make_vuln(
                        title       = f"IDOR posible — acceso a {prefix}{{ID}}{suffix}",
                        severity    = "HIGH",
                        cvss        = 8.1,
                        category    = "Broken Access Control (IDOR)",
                        description = (
                            f"El endpoint {prefix}{{id}}{suffix} parece devolver datos "
                            "de cualquier ID sin verificar autorización. La respuesta contiene "
                            f"patrones de PII ({pii_hits} matches)."
                        ),
                        evidence    = (
                            f"URL original: {orig_url}\n"
                            f"Acceso a ID adjacente: {u} → HTTP {r.status} ({len(r.body)} bytes)\n"
                            f"PII detectada en respuesta\n"
                            f"Verificar manualmente que los datos devueltos NO pertenecen al usuario autenticado."
                        ),
                        fix         = (
                            "Verificar autorización a nivel de objeto: en cada request, "
                            "comparar que el ID solicitado pertenezca al usuario autenticado. "
                            "OWASP API Security A1:2023 BOLA. "
                            "Usar UUIDs en lugar de IDs secuenciales reduce superficie de ataque."
                        ),
                        ref         = "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                        module      = "idor",
                        url         = u,
                        cwe         = "CWE-639",
                    ))
                    return

    # Limitar a 5 patrones distintos para no explotar el tiempo
    await asyncio.gather(*[probe_pattern(*c) for c in candidates[:5]])
    return vulns
