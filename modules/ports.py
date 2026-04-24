"""
modules/ports.py — Escaneo de puertos async usando asyncio streams.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from utils.vuln import Vuln, make_vuln
from config import PORTS


async def run(
    hostname:    str,
    concurrency: int = 50,
    timeout:     float = 1.5,
    progress_cb  = None,
) -> tuple[list[Vuln], list[dict]]:
    """
    Escanea puertos de forma async.
    Retorna (vulns, open_ports_list).
    """
    vulns: list[Vuln] = []
    open_ports: list[dict] = []

    total = len(PORTS)
    done  = [0]
    sem   = asyncio.Semaphore(concurrency)
    lock  = asyncio.Lock()

    async def check_port(port: int, name: str, sev: str, cvss: float, desc: str):
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port),
                    timeout=timeout,
                )
                
                # Check for fake open ports (Firewalls that SYN-ACK but drop data)
                try:
                    writer.write(b"GET / HTTP/1.1\r\n\r\n")
                    await asyncio.wait_for(writer.drain(), timeout=1.0)
                    # Opcionalmente leer la respuesta corta para validar
                    _ = await asyncio.wait_for(reader.read(10), timeout=1.0)
                    is_open = True
                except (asyncio.TimeoutError, ConnectionResetError, OSError):
                    is_open = False
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                is_open = False

            async with lock:
                done[0] += 1
                if progress_cb:
                    progress_cb(done[0], total)

            if is_open:
                open_ports.append({
                    "port": port,
                    "name": name,
                    "sev":  sev,
                    "cvss": cvss,
                    "desc": desc,
                })

    await asyncio.gather(*[
        check_port(p, n, s, c, d) for p, n, s, c, d in PORTS
    ])

    if progress_cb:
        progress_cb(total, total)

    # ── Convertir a vulns (omitir puertos normales) ────────────────────────────
    open_ports.sort(key=lambda x: x["port"])

    for p in open_ports:
        if p["sev"] == "LOW":
            continue  # 80/443 abiertos son normales

        vulns.append(make_vuln(
            title       = f"Puerto peligroso abierto: {p['port']}/{p['name']}",
            severity    = p["sev"],
            cvss        = p["cvss"],
            category    = "Port Exposure",
            description = p["desc"],
            evidence    = f"{hostname}:{p['port']} ({p['name']}) — ABIERTO",
            fix         = (
                f"Cerrar puerto {p['port']} con firewall si no es necesario externamente. "
                "Usar VPN o allowlist de IPs para acceso administrativo."
            ),
            module      = "ports",
        ))

    return vulns, open_ports
