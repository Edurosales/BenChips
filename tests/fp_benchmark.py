"""
tests/fp_benchmark.py — Benchmark de tasa de falsos positivos.

Corre el scanner contra una lista de targets benignos (homepages que NO
deberían tener vulnerabilidades reportables) y mide cuántos hallazgos
spurious genera.

Targets sugeridos (configurables):
  - https://www.hackerone.com/
  - https://www.bugcrowd.com/
  - https://www.google.com/
  - https://github.com/
  - https://example.com/

Uso:
  python tests/fp_benchmark.py
  python tests/fp_benchmark.py --targets https://www.google.com/ https://github.com/
  python tests/fp_benchmark.py --quick     # solo pasivo, sin port scan ni activo

Salida: JSON con conteo por (target, módulo, severidad).
NOTA: requiere red. NO se ejecuta en run_all.py.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# Targets considerados benignos para benchmarking.
# Importante: solo escanear sitios donde TENGAMOS autorización implícita
# (homepages públicas con bug bounty programs activos cuentan, pero solo
# se hace fase pasiva por respeto).
_DEFAULT_TARGETS = [
    "https://www.hackerone.com/",
    "https://www.bugcrowd.com/",
    "https://github.com/",
    "https://example.com/",
]


async def _bench_target(url: str, quick: bool) -> dict:
    """Corre un scan y devuelve resumen para análisis de FPs."""
    from scanner import scan
    t0 = time.monotonic()
    try:
        vulns, meta, duration = await scan(
            url           = url,
            full_scan     = False,
            scan_ports    = False,             # benigno: sin port scan
            active_scan   = not quick,
            stealth       = True,
            use_oob       = False,
        )
    except Exception as e:
        return {"target": url, "error": str(e), "duration": time.monotonic() - t0}

    by_sev: dict[str, int] = {}
    by_mod: dict[str, int] = {}
    suspect_titles: list[str] = []

    for v in vulns:
        by_sev[v.severity] = by_sev.get(v.severity, 0) + 1
        by_mod[v.module]   = by_mod.get(v.module, 0) + 1
        # Cualquier HIGH/CRITICAL en homepage benigna es sospechoso
        if v.severity in ("CRITICAL", "HIGH"):
            suspect_titles.append(f"[{v.severity}] {v.title}")

    return {
        "target":    url,
        "duration":  round(duration, 1),
        "total":     len(vulns),
        "by_sev":    by_sev,
        "by_mod":    by_mod,
        "suspects":  suspect_titles[:20],
    }


async def main_async(targets: list[str], quick: bool, out: str | None):
    print(f"[*] FP benchmark: {len(targets)} targets, quick={quick}")
    results = []
    for url in targets:
        print(f"  → scanning {url}")
        r = await _bench_target(url, quick)
        results.append(r)
        if "error" in r:
            print(f"     ERROR: {r['error']}")
        else:
            print(f"     total={r['total']} sev={r['by_sev']} suspects={len(r['suspects'])}")

    summary = {
        "ts":      int(time.time()),
        "quick":   quick,
        "results": results,
        "fp_rate": {
            "high_or_critical": sum(len(r.get("suspects", [])) for r in results),
            "total":            sum(r.get("total", 0) for r in results),
        },
    }

    if out:
        with open(out, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print(f"[+] Wrote {out}")
    else:
        print(json.dumps(summary, indent=2))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--targets", nargs="+", default=_DEFAULT_TARGETS,
                   help="URLs a evaluar")
    p.add_argument("--quick", action="store_true",
                   help="Solo pasivo (sin escaneo activo)")
    p.add_argument("--out", default=None, help="Archivo JSON de salida")
    args = p.parse_args()
    asyncio.run(main_async(args.targets, args.quick, args.out))


if __name__ == "__main__":
    main()
