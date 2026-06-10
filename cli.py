"""
cli.py — CLI con subcomandos para uso scriptable.

Subcomandos:
  scan        Ejecuta un escaneo completo (no interactivo)
  recon       Solo reconocimiento (DNS, subdomains, technologies)
  active      Solo escaneo activo (SQLi, XSS, SSRF, etc)
  yaml        Solo motor YAML templates
  report      Genera reporte desde un JSON existente
  diff        Compara dos reportes JSON
  verify      Modo verificación interactiva sobre reporte JSON
  bounty      Subcomandos de tracking de bounties (list, add, stats)

Ejemplos:
  python cli.py scan https://target.com --full --active --output json,md_h1
  python cli.py diff old.json new.json
  python cli.py yaml https://target.com
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

# Asegurar imports del repo
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vul",
        description="BugBountyHunter Pro CLI — escaneo no-interactivo y utilidades",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # ── scan ─────────────────────────────────────────────────────────────────
    s = sub.add_parser("scan", help="Ejecuta un escaneo completo")
    s.add_argument("url", help="URL objetivo (con o sin esquema)")
    s.add_argument("--full",    action="store_true", help="Escaneo completo (subdominios, OOB)")
    s.add_argument("--active",  action="store_true", help="Escaneo activo (SQLi, XSS, SSRF)")
    s.add_argument("--no-ports", action="store_true", help="Omitir port scan")
    s.add_argument("--stealth", action="store_true", help="Modo sigiloso")
    s.add_argument("--ai",      action="store_true", help="Triaje con IA")
    s.add_argument("--output",  default="json,html", help="Formatos CSV: html,json,pdf,md_h1,md_bc,sarif")
    s.add_argument("--name",    default="", help="Nombre base del reporte")
    s.add_argument("--proxy",   action="append", default=[], help="Proxy URL (repetible)")
    s.add_argument("--scope",   default="", help="Archivo .vulscope.yaml")
    s.add_argument("--rc",      default="", help="Archivo .vulrc.yaml")
    s.add_argument("--audit",   action="store_true", help="Habilitar audit log")
    s.add_argument("--verify",  action="store_true", help="Verificación interactiva tras scan")
    s.add_argument("--resume",  action="store_true", help="Reanudar scan previo si existe")

    # ── recon ────────────────────────────────────────────────────────────────
    r = sub.add_parser("recon", help="Solo reconocimiento")
    r.add_argument("url")
    r.add_argument("--full", action="store_true")
    r.add_argument("--output", default="json")

    # ── yaml ─────────────────────────────────────────────────────────────────
    y = sub.add_parser("yaml", help="Solo ejecutar templates YAML")
    y.add_argument("url")
    y.add_argument("--templates", default="templates")

    # ── report ───────────────────────────────────────────────────────────────
    rep = sub.add_parser("report", help="Regenerar reporte desde JSON")
    rep.add_argument("json_path", help="JSON del escaneo")
    rep.add_argument("--format", default="html", choices=["html", "pdf", "md_h1", "md_bc", "sarif"])
    rep.add_argument("--output", default="")

    # ── diff ─────────────────────────────────────────────────────────────────
    d = sub.add_parser("diff", help="Compara dos reportes JSON")
    d.add_argument("old", help="JSON anterior")
    d.add_argument("new", help="JSON actual")
    d.add_argument("--json", action="store_true", help="Salida JSON")

    # ── verify ───────────────────────────────────────────────────────────────
    v = sub.add_parser("verify", help="Verificación interactiva")
    v.add_argument("json_path")
    v.add_argument("--output", default="", help="Path para JSON filtrado")

    # ── bounty ───────────────────────────────────────────────────────────────
    b = sub.add_parser("bounty", help="Tracking de bounties")
    b_sub = b.add_subparsers(dest="bcmd")
    b_sub.add_parser("list")
    b_sub.add_parser("stats")
    b_add = b_sub.add_parser("add")
    b_add.add_argument("--program", required=True)
    b_add.add_argument("--title",   required=True)
    b_add.add_argument("--severity", required=True)
    b_add.add_argument("--payout",  type=float, default=0.0)
    b_add.add_argument("--status",  default="submitted")

    return p


async def _cmd_scan(args) -> int:
    from scanner import scan
    from utils.audit_log import enable as audit_enable, log_event
    from utils.config_file import load_rc, merge_opts_with_rc
    from utils.state import load_state, save_state, clear_state
    from utils.scope import ScopeFilter

    # Cargar rc
    rc = load_rc(args.rc) if args.rc else load_rc()
    if args.audit or rc.get("audit_log"):
        audit_enable(True)

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    url = url.rstrip("/")

    opts = {
        "full":      args.full,
        "active":    args.active,
        "ports":     not args.no_ports,
        "stealth":   args.stealth,
        "ai_triage": args.ai,
        "proxies":   args.proxy,
    }
    opts = merge_opts_with_rc(opts, rc)

    scope = ScopeFilter()
    if args.scope:
        scope = ScopeFilter.from_file(args.scope)
    elif opts.get("scope_file"):
        scope = ScopeFilter.from_file(opts["scope_file"])
    if not scope.is_in_scope(url):
        print(f"❌ URL {url} fuera de scope ({scope})", file=sys.stderr)
        return 2

    # Resume
    state = load_state(url) if args.resume else None
    if state:
        print(f"↻ Reanudando scan previo: {len(state.get('vulns_so_far', []))} hallazgos guardados")

    log_event("scan_start", {"url": url, "opts": opts})
    vulns, meta, duration = await scan(
        url=url,
        full_scan=opts.get("full", False),
        scan_ports=opts.get("ports", True),
        active_scan=opts.get("active", False),
        stealth=opts.get("stealth", False),
        proxies=opts.get("proxies", []),
    )

    # Reportes
    from report import (
        generate_html, generate_json, generate_pdf,
        generate_markdown_h1, generate_markdown_bugcrowd, generate_sarif,
    )
    base_name = args.name or url.replace("://", "_").replace("/", "_").replace(":", "_")
    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    base_path = os.path.join(reports_dir, base_name)
    fmts = [f.strip() for f in args.output.split(",") if f.strip()]

    if "json" in fmts:
        with open(base_path + ".json", "w", encoding="utf-8") as f:
            f.write(generate_json(url, vulns, meta, duration))
        print(f"✓ JSON  → {base_path}.json")
    if "html" in fmts:
        with open(base_path + ".html", "w", encoding="utf-8") as f:
            f.write(generate_html(url, vulns, meta, duration))
        print(f"✓ HTML  → {base_path}.html")
    if "md_h1" in fmts:
        with open(base_path + ".h1.md", "w", encoding="utf-8") as f:
            f.write(generate_markdown_h1(url, vulns, meta, duration))
        print(f"✓ MD H1 → {base_path}.h1.md")
    if "md_bc" in fmts:
        with open(base_path + ".bugcrowd.md", "w", encoding="utf-8") as f:
            f.write(generate_markdown_bugcrowd(url, vulns, meta, duration))
        print(f"✓ MD BC → {base_path}.bugcrowd.md")
    if "sarif" in fmts:
        with open(base_path + ".sarif", "w", encoding="utf-8") as f:
            f.write(generate_sarif(url, vulns, meta, duration))
        print(f"✓ SARIF → {base_path}.sarif")
    if "pdf" in fmts:
        generate_pdf(url, vulns, meta, duration, base_path + ".pdf")
        print(f"✓ PDF   → {base_path}.pdf")

    log_event("scan_end", {"url": url, "vulns": len(vulns), "duration": duration})
    clear_state(url)

    if args.verify:
        from utils.verify import interactive_verify
        kept = interactive_verify(vulns)
        with open(base_path + ".verified.json", "w", encoding="utf-8") as f:
            f.write(generate_json(url, kept, meta, duration))
        print(f"✓ Verified JSON → {base_path}.verified.json")

    return 0


def _cmd_diff(args) -> int:
    from utils.diff import diff_reports, format_diff
    d = diff_reports(args.old, args.new)
    if args.json:
        print(json.dumps(d, indent=2, ensure_ascii=False, default=str))
    else:
        print(format_diff(d))
    return 0


def _cmd_verify(args) -> int:
    from utils.verify import interactive_verify
    from utils.vuln import make_vuln

    with open(args.json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    raw_vulns = data.get("vulnerabilidades", [])
    vulns = []
    for v in raw_vulns:
        vulns.append(make_vuln(
            title=v.get("title", "?"),
            severity=v.get("severity", "INFO"),
            cvss=float(v.get("cvss", 0)),
            category=v.get("category", ""),
            description=v.get("description", ""),
            evidence=v.get("evidence", ""),
            fix=v.get("fix", ""),
            ref=v.get("ref", ""),
            module=v.get("module", ""),
            url=v.get("url", ""),
            cwe=v.get("cwe", ""),
            owasp=v.get("owasp", ""),
        ))

    kept = interactive_verify(vulns)
    out_path = args.output or args.json_path.replace(".json", ".verified.json")

    data["vulnerabilidades"] = [v.to_dict() for v in kept]
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"✓ Guardado: {out_path}")
    return 0


def _cmd_bounty(args) -> int:
    from utils.bounty_tracker import list_entries, add_entry, stats
    if args.bcmd == "list":
        for e in list_entries():
            print(f"[{e['date']}] {e['program']} — {e['title'][:60]} — "
                  f"{e['severity']} — ${e.get('payout',0):.0f} — {e['status']}")
    elif args.bcmd == "add":
        add_entry({
            "program":  args.program,
            "title":    args.title,
            "severity": args.severity,
            "payout":   args.payout,
            "status":   args.status,
        })
        print("✓ Entry added")
    elif args.bcmd == "stats":
        s = stats()
        print(f"Total submissions: {s['total']}")
        print(f"Total paid:        ${s['paid']:.2f}")
        print(f"By severity:       {s['by_sev']}")
        print(f"By status:         {s['by_status']}")
    else:
        print("usage: vul bounty [list|stats|add]")
        return 1
    return 0


def _cmd_yaml(args) -> int:
    async def _run():
        from modules import yaml_engine
        from utils.http import AsyncHTTPClient
        import aiohttp
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as sess:
            client = AsyncHTTPClient(sess, rate_limit=10, timeout=10)
            url = args.url if args.url.startswith("http") else "https://" + args.url
            vulns = await yaml_engine.run(client, url)
            for v in vulns:
                print(f"[{v.severity}] {v.title}")
                print(f"  {v.evidence[:120]}\n")
            print(f"\nTotal: {len(vulns)} hallazgos YAML")
    asyncio.run(_run())
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "scan":
        return asyncio.run(_cmd_scan(args))
    if args.cmd == "diff":
        return _cmd_diff(args)
    if args.cmd == "verify":
        return _cmd_verify(args)
    if args.cmd == "bounty":
        return _cmd_bounty(args)
    if args.cmd == "yaml":
        return _cmd_yaml(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
