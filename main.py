"""
main.py — CLI entry point del VulnScanner Pro.
Ejecutar: python main.py
"""

from __future__ import annotations

import asyncio
import os
import sys

# ── Asegurar que vulnscanner_pro/ esté en sys.path ───────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

try:
    import aiohttp
except ImportError:
    print("❌  aiohttp no instalado. Ejecutar: pip install aiohttp")
    sys.exit(1)

from config import VERSION
from utils.colors import (
    banner, print_sep, print_section, print_vuln, print_err,
    print_ok, print_warn, print_info, disable_color,
    W, BOLD, C, G, O, R, DIM,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _fix_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def _safe_filename(url: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host   = parsed.hostname or "scan"
    return host.replace(".", "_").replace("-", "_")


def _prompt_options() -> dict:
    """Solicita opciones al usuario de forma interactiva."""
    print(f"\n  {BOLD}{C}Opciones de escaneo:{W}\n")
    print(f"  {DIM}[Enter] = NO  |  Escribe 's' o 'si' = SÍ{W}\n")

    def ask(question: str) -> bool:
        resp = input(f"  {C}?{W}  {question} [s/N]: ").strip().lower()
        return resp in ("s", "si", "sí", "y", "yes", "1")

    full   = ask("Escaneo completo  (subdominios + crt.sh)")
    active = ask("Escaneo activo    (SQLi / XSS / Traversal / SSRF)")
    ports  = not ask("Omitir puertos    (port scan)")
    html   = ask("Generar reporte   HTML")
    json_r = ask("Generar reporte   JSON")

    out_name = ""
    if html or json_r:
        out_name = input(f"\n  {C}?{W}  Nombre base del reporte (Enter = auto): ").strip()

    return {
        "full":   full,
        "active": active,
        "ports":  ports,
        "html":   html,
        "json":   json_r,
        "output": out_name,
    }


# ─── Runner ───────────────────────────────────────────────────────────────────

async def _run(url: str, opts: dict):
    from scanner import scan
    from utils.vuln import count_by_severity, risk_score
    from report import generate_html, generate_json

    banner(VERSION)
    print(f"  {BOLD}{C}Objetivo:{W} {url}")
    print(f"  {DIM}Modo: {'COMPLETO' if opts['full'] else 'ESTÁNDAR'} | "
          f"Activo: {'SÍ' if opts['active'] else 'NO'} | "
          f"Puertos: {'SÍ' if opts['ports'] else 'NO'}{W}")
    print_sep()

    try:
        vulns, meta, duration = await scan(
            url         = url,
            full_scan   = opts["full"],
            scan_ports  = opts["ports"],
            active_scan = opts["active"],
        )
    except Exception as e:
        print_err(f"Error durante el escaneo: {e}")
        import traceback; traceback.print_exc()
        return

    # ── Mostrar resultados ─────────────────────────────────────────────────────
    ips_str = ", ".join(meta.get("ips", [])) or "N/A"
    print_section("★", f"RESULTADOS — {len(vulns)} hallazgos en {duration:.1f}s")
    print(f"  {BOLD}IP del Servidor:{W} {C}{ips_str}{W}")

    counts       = count_by_severity(vulns)
    score, level = risk_score(counts)

    risk_colors = {"CRÍTICO": R, "ALTO": O, "MODERADO": O, "BAJO": G}
    rc = risk_colors.get(level, W)
    print(f"\n  {BOLD}Nivel de Riesgo: {rc}{level}{W}  {DIM}(score={score}){W}")
    print(f"  {R}💀 CRITICAL:{W} {counts['CRITICAL']:>3}  "
          f"{O}🔴 HIGH:{W} {counts['HIGH']:>3}  "
          f"\033[33m🟠 MEDIUM:{W} {counts['MEDIUM']:>3}  "
          f"{G}🟡 LOW:{W} {counts['LOW']:>3}  "
          f"{C}⚪ INFO:{W} {counts['INFO']:>3}\n")

    for i, v in enumerate(vulns, 1):
        print_vuln(i, v)

    print_sep()

    # ── Generar reportes ───────────────────────────────────────────────────────
    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)

    base_name = opts["output"] or _safe_filename(url)
    base_path = os.path.join(reports_dir, base_name)
    generated = []

    if opts["html"]:
        html_path = base_path + ".html"
        try:
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(generate_html(url, vulns, meta, duration))
            generated.append(f"HTML → {os.path.abspath(html_path)}")
        except Exception as e:
            print_err(f"Error generando HTML: {e}")

    if opts["json"]:
        json_path = base_path + ".json"
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                f.write(generate_json(url, vulns, meta, duration))
            generated.append(f"JSON → {os.path.abspath(json_path)}")
        except Exception as e:
            print_err(f"Error generando JSON: {e}")

    if generated:
        print(f"\n  {G}📄 Reportes generados:{W}")
        for g in generated:
            print(f"     {G}✓{W} {g}")

    print(f"\n  {DIM}Duración total: {duration:.2f}s{W}\n")


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    banner(VERSION)

    # ── Pedir URL ──────────────────────────────────────────────────────────────
    print(f"  {BOLD}VulnScanner Pro v{VERSION}{W} — Scanner de vulnerabilidades web\n")
    print(f"  {DIM}Solo para uso ético en sistemas propios o con autorización explícita.{W}\n")

    try:
        raw_url = input(f"  {C}▶{W}  Introduce la URL objetivo: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n\n  ⚠️  Cancelado.\n")
        sys.exit(0)

    if not raw_url:
        print_err("URL vacía. Saliendo.")
        sys.exit(1)

    url  = _fix_url(raw_url)
    opts = _prompt_options()

    try:
        asyncio.run(_run(url, opts))
    except KeyboardInterrupt:
        print("\n\n  ⚠️  Escaneo interrumpido por el usuario.\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n  ❌ Error fatal: {e}\n")
        import traceback; traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
