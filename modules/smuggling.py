"""
modules/smuggling.py — HTTP Request Smuggling detection (CL.TE / TE.CL).

Técnica de timing differential (PortSwigger):
  CL.TE: front-end usa Content-Length, back-end usa Transfer-Encoding.
         Si el back-end espera más body que el que llega → timeout.
  TE.CL: inverso. Front-end usa TE, back-end usa CL.

PRECAUCIÓN: enviar requests malformados puede afectar a otros usuarios del
mismo front-end si la vulnerabilidad es real. Por eso usamos timing-only:
mandamos un request que SOLO causa timeout en el servidor vulnerable, sin
inyectar nada en la cola.

Anti-FP:
  - Mediana de 3 mediciones de baseline.
  - Diferencia debe ser > 4 segundos para confirmar (no es noise de red).
  - Solo se activa en modo full_scan (es invasivo).
"""

from __future__ import annotations

import asyncio
import time
from urllib.parse import urlparse

import aiohttp

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln


async def _measure_baseline(session: aiohttp.ClientSession, url: str, samples: int = 3) -> float:
    """Mediana de tiempos de respuesta de GET normales."""
    times = []
    for _ in range(samples):
        t0 = time.monotonic()
        try:
            async with session.get(
                url, ssl=False, timeout=aiohttp.ClientTimeout(total=20)
            ) as r:
                await r.read()
                times.append(time.monotonic() - t0)
        except Exception:
            pass
    if not times:
        return 1.0
    times.sort()
    return times[len(times) // 2]


async def _send_cl_te_probe(
    session: aiohttp.ClientSession, url: str, timeout: float
) -> float:
    """
    Manda un POST con CL y TE chunked donde el chunk-final-0 está INCOMPLETO.
    En servidor CL.TE vulnerable, el back-end espera el cierre TE → timeout largo.
    En servidor seguro, el front-end ve el CL como autoridad → cierra rápido.
    """
    # Body: chunk size "0\r\n" pero sin el \r\n final, con CL que dice 6 bytes
    # El front-end con CL=6 enviará 6 bytes; back-end con TE espera más.
    body = b"0\r\nX"  # 4 bytes; cubre 0\r\n + 1 char
    headers = {
        "Content-Length":    str(len(body)),
        "Transfer-Encoding": "chunked",
        "Content-Type":      "application/x-www-form-urlencoded",
    }
    t0 = time.monotonic()
    try:
        async with session.post(
            url, data=body, headers=headers, ssl=False,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as r:
            await r.read()
    except asyncio.TimeoutError:
        return timeout
    except Exception:
        pass
    return time.monotonic() - t0


async def _send_te_cl_probe(
    session: aiohttp.ClientSession, url: str, timeout: float
) -> float:
    """TE.CL: chunked completo pero CL pequeño → front-end vulnerable a TE."""
    body = b"3\r\nabc\r\n0\r\n\r\n"  # chunked legítimo
    headers = {
        "Content-Length":    "3",
        "Transfer-Encoding": "chunked",
        "Content-Type":      "application/x-www-form-urlencoded",
    }
    t0 = time.monotonic()
    try:
        async with session.post(
            url, data=body, headers=headers, ssl=False,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as r:
            await r.read()
    except asyncio.TimeoutError:
        return timeout
    except Exception:
        pass
    return time.monotonic() - t0


async def run(client: AsyncHTTPClient, url: str, enabled: bool = False) -> list[Vuln]:
    """
    enabled: solo testea si full_scan está activo (es invasivo).
    """
    vulns: list[Vuln] = []

    if not enabled:
        return vulns

    # Usar la session interna del cliente para reutilizar connector
    session = client.session
    if not session:
        return vulns

    baseline = await _measure_baseline(session, url)
    timeout  = max(baseline * 4, 6.0)

    cl_te_time = await _send_cl_te_probe(session, url, timeout)
    te_cl_time = await _send_te_cl_probe(session, url, timeout)

    # Si la prueba CL.TE tardó significativamente más que el baseline → vulnerable
    margin = 4.0
    if cl_te_time > baseline + margin:
        vulns.append(make_vuln(
            title       = "HTTP Request Smuggling probable (CL.TE)",
            severity    = "CRITICAL",
            cvss        = 9.0,
            category    = "HTTP Request Smuggling",
            description = (
                "Diferencia de timing significativa con request CL.TE malformado. "
                "El back-end procesa Transfer-Encoding mientras el front-end "
                "procesa Content-Length, permitiendo desync de requests. "
                "Explotable para bypass de seguridad, cache poisoning, "
                "captura de requests de otros usuarios."
            ),
            evidence    = (
                f"Baseline GET mediano: {baseline:.2f}s\n"
                f"POST CL.TE probe: {cl_te_time:.2f}s (esperado ≈ baseline)\n"
                f"Diferencia: +{cl_te_time - baseline:.2f}s (umbral: {margin}s)\n"
                "Confirmar manualmente con Burp Repeater / smuggler.py de @defparam"
            ),
            fix         = (
                "Front-end debe rechazar requests con TE y CL simultáneos. "
                "Back-end ídem. Normalizar headers ambiguos en el load balancer. "
                "Considerar usar HTTP/2 end-to-end (smuggling clásico no aplica)."
            ),
            ref         = "https://portswigger.net/web-security/request-smuggling",
            module      = "smuggling",
            url         = url,
            cwe         = "CWE-444",
            confidence  = 70,
        ))

    if te_cl_time > baseline + margin and te_cl_time != cl_te_time:
        vulns.append(make_vuln(
            title       = "HTTP Request Smuggling probable (TE.CL)",
            severity    = "CRITICAL",
            cvss        = 9.0,
            category    = "HTTP Request Smuggling",
            description = (
                "Diferencia de timing con request TE.CL. El front-end usa "
                "Transfer-Encoding y el back-end Content-Length. Desync clásico."
            ),
            evidence    = (
                f"Baseline GET mediano: {baseline:.2f}s\n"
                f"POST TE.CL probe: {te_cl_time:.2f}s\n"
                f"Diferencia: +{te_cl_time - baseline:.2f}s"
            ),
            fix         = "Igual que CL.TE: normalizar headers en el reverse proxy.",
            ref         = "https://portswigger.net/web-security/request-smuggling",
            module      = "smuggling",
            url         = url,
            cwe         = "CWE-444",
            confidence  = 70,
        ))

    return vulns
