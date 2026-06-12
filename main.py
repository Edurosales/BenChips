"""
main.py — BugBountyHunter Pro v5.0
Scanner de vulnerabilidades con IA integrada para bug bounty profesional.

Solo para uso ético en sistemas propios o con autorización explícita.
"""

from __future__ import annotations

import asyncio
import os
import sys

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
    W, BOLD, C, G, O, R, DIM, M, Y,
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


def _prompt_ai_setup() -> dict | None:
    """
    Solicita la configuración de la API de IA al usuario.
    Si ya existe configuración guardada, ofrece reutilizarla.
    """
    from ai_engine import load_ai_config, save_ai_config, AIEngine

    saved = load_ai_config()

    if saved.get("api_key") and saved.get("base_url"):
        print(f"\n  {BOLD}{C}Configuración de IA guardada encontrada:{W}")
        print(f"  {DIM}Proveedor: {saved.get('base_url', '')}{W}")
        print(f"  {DIM}Modelo: {saved.get('model', 'desconocido')}{W}")
        print(f"  {DIM}API Key: {'*' * 20 + saved['api_key'][-4:]}{W}")
        resp = input(f"\n  {C}?{W}  ¿Usar esta configuración guardada? [S/n]: ").strip().lower()
        if resp not in ("n", "no"):
            return saved

    print(f"\n  {BOLD}{C}══ Configuración de IA ══{W}")
    print(f"  {DIM}Compatible con: OpenAI, Google Gemini, Anthropic, Mistral, Groq, Ollama, OpenRouter{W}")
    print(f"  {DIM}Ejemplo URL OpenAI: https://api.openai.com{W}")
    print(f"  {DIM}Ejemplo URL OpenRouter: https://openrouter.ai/api{W}")
    print(f"  {DIM}Ejemplo URL Ollama local: http://localhost:11434{W}")
    print(f"  {DIM}Ejemplo URL Groq: https://api.groq.com/openai{W}\n")

    try:
        base_url = input(f"  {C}▶{W}  URL del proveedor AI (Enter para omitir IA): ").strip()
    except (KeyboardInterrupt, EOFError):
        return None

    if not base_url:
        print(f"  {O}⚠{W}  Sin IA. Solo se usará el motor de análisis estático.")
        return None

    try:
        import getpass
        api_key = getpass.getpass(f"  {C}▶{W}  API Key (no se mostrará): ").strip()
        model   = input(f"  {C}▶{W}  Modelo (Enter = gpt-4o-mini): ").strip() or "gpt-4o-mini"
    except (KeyboardInterrupt, EOFError):
        return None

    if not api_key:
        print(f"  {O}⚠{W}  Sin API Key. Se omitirá el análisis IA.")
        return None

    config = {"api_key": api_key, "base_url": base_url, "model": model}

    # Test rápido de conexión
    async def _test():
        from ai_engine import AIEngine
        engine = AIEngine(api_key, base_url, model)
        ok, msg = await engine.test_connection()
        return ok, msg, engine

    try:
        ok, msg, _ = asyncio.run(_test())
        if ok:
            print(f"  {G}✓{W}  {msg}")
            save = input(f"  {C}?{W}  ¿Guardar configuración? [S/n]: ").strip().lower()
            if save not in ("n", "no"):
                save_ai_config(config)
                print(f"  {G}✓{W}  Configuración guardada.")
        else:
            print(f"  {O}⚠{W}  {msg}")
            cont = input(f"  {C}?{W}  ¿Continuar de todas formas? [s/N]: ").strip().lower()
            if cont not in ("s", "si", "sí", "y", "yes"):
                config = None
    except Exception as e:
        print(f"  {O}⚠{W}  Error al probar conexión: {e}")

    return config


def _prompt_options() -> dict:
    """Solicita opciones al usuario de forma interactiva."""
    print(f"\n  {BOLD}{C}Opciones de escaneo:{W}\n")
    print(f"  {DIM}[Enter] = NO  |  Escribe 's' o 'si' = SÍ{W}\n")

    def ask(question: str, default_yes: bool = False) -> bool:
        default_str = "S/n" if default_yes else "s/N"
        resp = input(f"  {C}?{W}  {question} [{default_str}]: ").strip().lower()
        if resp in ("s", "si", "sí", "y", "yes", "1"):
            return True
        if resp == "" and default_yes:
            return True
        return False

    full    = ask("Escaneo completo  (subdominios + crt.sh)")
    active  = ask("Escaneo activo    (SQLi / XSS / Traversal / SSRF / SSTI)")
    ports   = not ask("Omitir puertos    (port scan)")
    stealth = ask("Modo sigiloso     (UA rotation + delays, evita WAF/IDS)")
    ai_triage = ask("Triaje con IA    (elimina falsos positivos, estima bounty)", default_yes=True)

    print(f"\n  {BOLD}Reportes:{W}")
    html    = ask("Generar reporte   HTML")
    json_r  = ask("Generar reporte   JSON")
    pdf     = ask("Generar reporte   PDF ejecutivo")
    md_h1   = ask("Generar reporte   Markdown HackerOne")
    md_bc   = ask("Generar reporte   Markdown Bugcrowd")
    md_int  = ask("Generar reporte   Markdown Intigriti")
    md_ywh  = ask("Generar reporte   Markdown YesWeHack")
    md_all  = ask("Generar reporte   MD H1 SEPARADO por cada CRITICAL/HIGH")
    sarif   = ask("Generar reporte   SARIF (GitHub Code Scanning)")

    print(f"\n  {BOLD}Modo avanzado (v7.1):{W}")
    program  = input(f"  {C}?{W}  Programa de bounty (h1/bugcrowd/intigriti/yeswehack/generic) [generic]: ").strip().lower() or "generic"
    scope_f  = input(f"  {C}?{W}  Archivo de scope (.vulscope.yaml) [Enter = ninguno]: ").strip() or None
    audit    = ask("Audit log JSONL    (compliance, .vullogs/)")
    adaptive = ask("Adaptive rate     (per-host concurrency)", default_yes=True)
    tracer   = ask("Tracer JSON       (debug de FPs, .vultrace/)")
    tui      = ask("TUI live dashboard (requiere Textual instalado)")

    print()
    out = input(f"  {C}?{W}  Nombre base del reporte (Enter = auto): ").strip()

    print()
    proxy_str = input(
        f"  {C}?{W}  Proxies (lista CSV, p.ej. http://127.0.0.1:8080,http://10.0.0.1:3128; Enter omite): "
    ).strip()
    proxies = [p.strip() for p in proxy_str.split(",") if p.strip()] if proxy_str else []

    return {
        "full":      full,
        "active":    active,
        "ports":     ports,
        "stealth":   stealth,
        "ai_triage": ai_triage,
        "html":      html,
        "json":      json_r,
        "pdf":       pdf,
        "md_h1":     md_h1,
        "md_bc":     md_bc,
        "md_int":    md_int,
        "md_ywh":    md_ywh,
        "md_all":    md_all,
        "sarif":     sarif,
        "output":    out,
        "proxies":   proxies,
        # v7.1
        "program":   program,
        "scope_file": scope_f,
        "audit":     audit,
        "adaptive":  adaptive,
        "tracer":    tracer,
        "tui":       tui,
    }


# ─── Visualización de bounty ───────────────────────────────────────────────────

def _print_bounty_info(v, analysis: dict | None, bounty: dict, classification: dict):
    """Imprime info de bounty para una vulnerabilidad."""
    eligible = classification.get("eligible", "possible")
    color_map = {
        "very_likely": G,
        "likely":      G,
        "possible":    O,
        "unlikely":    R,
    }
    ec = color_map.get(eligible, W)

    fp_flag = ""
    if analysis and analysis.get("is_false_positive"):
        fp_flag = f" {R}[FALSO POSITIVO — EXCLUIDO]{W}"

    bounty_str = bounty.get("range_str", "N/A")
    program    = bounty.get("program", "Programa desconocido")

    print(f"       {BOLD}💰 Bounty:{W}    {ec}{bounty_str}{W} | {DIM}{program}{W}{fp_flag}")

    if analysis:
        confidence  = analysis.get("confidence", "?")
        real_sev    = analysis.get("real_severity", v.severity)
        exploitability = analysis.get("exploitability", "?")
        owasp       = analysis.get("owasp_category", "")
        cwe_ids     = ", ".join(analysis.get("cwe_ids") or [])

        sev_color_map = {"CRITICAL": R, "HIGH": O, "MEDIUM": Y, "LOW": G, "INFO": C}
        sc = sev_color_map.get(real_sev, W)

        print(f"       {BOLD}🤖 IA:{W}        Severidad real: {sc}{real_sev}{W} | Confianza: {confidence}% | Explotabilidad: {exploitability}")
        if owasp:
            print(f"       {BOLD}🏷️  OWASP:{W}     {owasp}  {DIM}{cwe_ids}{W}")
        if analysis.get("business_impact"):
            print(f"       {BOLD}💼 Impacto:{W}    {DIM}{analysis['business_impact'][:100]}{W}")


# ─── Runner principal ──────────────────────────────────────────────────────────

async def _run(url: str, opts: dict, ai_config: dict | None, auth_config=None):
    from scanner import scan
    from utils.vuln import count_by_severity, risk_score
    from report import generate_html, generate_json, generate_pdf
    from bounty_db import estimate_bounty, categorize_finding_for_bounty, find_program
    from urllib.parse import urlparse

    banner(VERSION)
    print(f"  {BOLD}{C}Objetivo:{W} {url}")
    stealth_tag = f" | {G}● Sigiloso{W}" if opts.get("stealth") else ""
    ai_tag      = f" | {M}🤖 IA Activa{W}" if ai_config else ""
    auth_tag    = f" | {C}🔑 Autenticado{W}" if auth_config else ""
    print(f"  {DIM}Modo: {'COMPLETO' if opts['full'] else 'ESTÁNDAR'} | "
          f"Activo: {'SÍ' if opts['active'] else 'NO'} | "
          f"Puertos: {'SÍ' if opts['ports'] else 'NO'}{stealth_tag}{ai_tag}{auth_tag}{W}")
    print_sep()

    # ── Inicializar motor AI ──────────────────────────────────────────────────
    ai_engine = None
    if ai_config and opts.get("ai_triage"):
        from ai_engine import AIEngine
        ai_engine = AIEngine(
            api_key   = ai_config["api_key"],
            base_url  = ai_config["base_url"],
            model     = ai_config.get("model", "gpt-4o-mini"),
        )
        print(f"  {M}🤖{W}  Motor IA inicializado: {ai_config.get('model', 'auto')} — presupuesto: 80K tokens")
        print_sep()

    # ── Escaneo principal ─────────────────────────────────────────────────────
    proxies = opts.get("proxies") or []

    # v7.1: tracer ID único por scan
    tracer_id = None
    if opts.get("tracer"):
        import hashlib, time as _t
        tracer_id = hashlib.md5(f"{url}{_t.time()}".encode()).hexdigest()[:12]

    try:
        vulns, meta, duration = await scan(
            url           = url,
            full_scan     = opts["full"],
            scan_ports    = opts["ports"],
            active_scan   = opts["active"],
            stealth       = opts.get("stealth", False),
            auth_config   = auth_config,
            use_oob       = opts.get("active", False),  # OOB solo en modo activo
            proxies       = proxies,
            # v7.1 pluggables
            scope_file    = opts.get("scope_file"),
            audit_enabled = opts.get("audit", False),
            tracer_id     = tracer_id,
            adaptive      = opts.get("adaptive", False),
        )
    except Exception as e:
        print_err(f"Error durante el escaneo: {e}")
        import traceback; traceback.print_exc()
        return

    # ── Análisis IA (3 llamadas totales) ──────────────────────────────────────
    ai_analyses:    dict = {}
    advanced_tests: list = []
    exec_summary:   str  = ""
    attack_chains:  list = []
    deep_dive:      dict = {}

    if ai_engine and vulns:
        print()
        print_section("🤖 IA", "Análisis de Inteligencia Artificial — 3 llamadas totales")

        ai_result = await ai_engine.full_analysis(
            vulns, url, meta, duration,
            program          = opts.get("program", "generic"),
            use_embeddings   = True,
            use_feedback_loop = True,
        )

        ai_analyses    = ai_result.get("triage", {})
        exec_summary   = ai_result.get("exec_summary", "")
        advanced_tests = ai_result.get("advanced_tests", [])
        attack_chains  = ai_result.get("attack_chains", [])
        deep_dive      = ai_result.get("deep_dive", {})

        # Filtrar falsos positivos del conjunto de vulns
        false_positives = {k for k, a in ai_analyses.items() if a.get("is_false_positive")}
        vulns_before    = len(vulns)
        vulns = [v for v in vulns if v.dedup_key not in false_positives]
        removed = vulns_before - len(vulns)

        if removed:
            print_ok(f"    ✂  {removed} falsos positivos eliminados")

        # Enriquecer el deep_dive dentro de ai_analyses para el reporte
        for k, dd in deep_dive.items():
            if k in ai_analyses:
                ai_analyses[k].update(dd)

        # Propagar CVSS vector real del deep_dive a cada vuln
        from utils.vuln import validate_cvss_vector
        for v in vulns:
            dd = deep_dive.get(v.dedup_key) or {}
            vec = dd.get("cvss_vector", "")
            if vec and validate_cvss_vector(vec):
                v.cvss_vector = vec
                # __post_init__ no se ejecuta al asignar, recalcular manualmente
                from utils.vuln import cvss3_score_from_vector, cvss_severity
                score = cvss3_score_from_vector(vec)
                if score is not None:
                    v.cvss = score
                    v.severity = cvss_severity(score)
            # Enriquecer CWE/OWASP desde el triaje IA
            triage_entry = ai_analyses.get(v.dedup_key) or {}
            if not v.cwe:
                cwes = triage_entry.get("cwe_ids") or []
                if cwes:
                    v.cwe = cwes[0] if isinstance(cwes, list) else str(cwes)
            if not v.owasp:
                v.owasp = triage_entry.get("owasp_category", "") or ""
            conf = triage_entry.get("confidence")
            if isinstance(conf, (int, float)):
                v.confidence = int(conf)


    # ── Resultados ────────────────────────────────────────────────────────────
    hostname   = urlparse(url).hostname or ""
    ips_str    = ", ".join(meta.get("ips", [])) or "N/A"
    print_section("★", f"RESULTADOS — {len(vulns)} hallazgos confirmados en {duration:.1f}s")
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

    # ── Programa de bounty detectado ──────────────────────────────────────────
    program_info = find_program(hostname)
    if program_info:
        print(f"  {G}🏆 Programa detectado:{W} {BOLD}{program_info['name']}{W} "
              f"| Plataforma: {program_info['platform']} "
              f"| Rango: ${program_info['min']:,} – ${program_info['max']:,}")
        print_sep("-")

    # ── Resumen ejecutivo IA ──────────────────────────────────────────────────
    if exec_summary:
        print(f"\n  {M}{BOLD}📋 Resumen Ejecutivo (IA):{W}")
        for line in exec_summary.split("\n"):
            if line.strip():
                print(f"  {DIM}{line}{W}")
        print()

    # ── Detalle de hallazgos ──────────────────────────────────────────────────
    for i, v in enumerate(vulns, 1):
        print_vuln(i, v)
        # Info de bounty
        analysis       = ai_analyses.get(v.dedup_key)
        bounty         = estimate_bounty(v.severity, v.category, hostname)
        classification = categorize_finding_for_bounty(v.title, v.severity)
        _print_bounty_info(v, analysis, bounty, classification)
        print()

    # ── Cadenas de Ataque ─────────────────────────────────────────────────────
    if attack_chains:
        print_sep("-")
        print(f"\n  {R}{BOLD}⛓  Cadenas de Ataque Detectadas por IA:{W}")
        for chain in attack_chains:
            sev_c = {
                "CRITICAL": R, "HIGH": O, "MEDIUM": Y,
            }.get(chain.get("severity", ""), C)
            print(f"\n  {sev_c}{BOLD}  [{chain.get('severity','')}] {chain.get('name','')}{W}")
            print(f"  {DIM}  Impacto: {chain.get('impact','')}{W}")
            for j, step in enumerate(chain.get("steps", []), 1):
                print(f"  {M}    {j}.{W} {step}")
        print()

    # ── Sugerencias IA de tests avanzados ────────────────────────────────────
    if advanced_tests:
        print_sep("-")
        print(f"\n  {M}{BOLD}🎯 Tests Avanzados Recomendados por IA:{W}")
        for i, test in enumerate(advanced_tests, 1):
            print(f"  {M}{i:02d}{W}. {test}")
        print()

    # ── Deep Dive PoC (CRITICAL/HIGH) ─────────────────────────────────────────
    if deep_dive:
        print_sep("-")
        print(f"\n  {C}{BOLD}🔬 PoC Generado por IA (Hallazgos Críticos):{W}")
        for dedup_key, dd in deep_dive.items():
            # Buscar el título de la vuln
            title = next((v.title for v in vulns if v.dedup_key == dedup_key), dedup_key)
            poc   = dd.get("poc_curl") or dd.get("exploit_steps", [])
            print(f"\n  {O}{BOLD}  → {title}{W}")
            if dd.get("report_title"):
                print(f"  {DIM}  Bug bounty title: {dd['report_title']}{W}")
            if isinstance(poc, str) and poc:
                print(f"  {DIM}  PoC:{W}")
                print(f"  {C}    {poc}{W}")
            elif isinstance(poc, list) and poc:
                print(f"  {DIM}  Pasos de explotación:{W}")
                for s in poc[:4]:
                    print(f"  {C}    • {s}{W}")
            if dd.get("impact_demo"):
                print(f"  {G}  Impacto demo: {DIM}{dd['impact_demo']}{W}")
        print()


    print_sep()

    # ── Estimación total de bounty ────────────────────────────────────────────
    total_min, total_max = 0, 0
    for v in vulns:
        if v.severity not in ("INFO",):
            b = estimate_bounty(v.severity, v.category, hostname)
            total_min += b["min"]
            total_max += b["max"]

    if total_max > 0:
        print(f"\n  {BOLD}{G}💰 Potencial de Bounty Estimado:{W}")
        print(f"  {G}  Mínimo: ${total_min:,} USD | Máximo: ${total_max:,} USD{W}")
        print(f"  {DIM}  (Estimación orientativa. Depende del programa y del PoC presentado.){W}\n")

    # ── Reportes ──────────────────────────────────────────────────────────────
    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)

    base_name = opts["output"] or _safe_filename(url)
    base_path = os.path.join(reports_dir, base_name)
    generated = []

    if opts["html"]:
        html_path = base_path + ".html"
        try:
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(generate_html(
                    url, vulns, meta, duration,
                    ai_analyses=ai_analyses,
                    exec_summary=exec_summary,
                    advanced_tests=advanced_tests,
                    attack_chains=attack_chains,
                ))
            generated.append(f"HTML → {os.path.abspath(html_path)}")
        except Exception as e:
            print_err(f"Error generando HTML: {e}")

    if opts["json"]:
        json_path = base_path + ".json"
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                f.write(generate_json(
                    url, vulns, meta, duration,
                    ai_analyses=ai_analyses,
                    exec_summary=exec_summary,
                ))
            generated.append(f"JSON → {os.path.abspath(json_path)}")
        except Exception as e:
            print_err(f"Error generando JSON: {e}")

    if opts.get("pdf"):
        pdf_path = base_path + ".pdf"
        try:
            from report import generate_pdf
            if generate_pdf(url, vulns, meta, duration, pdf_path,
                            ai_analyses=ai_analyses, exec_summary=exec_summary):
                generated.append(f"PDF  → {os.path.abspath(pdf_path)}")
        except Exception as e:
            print_err(f"Error generando PDF: {e}")

    if opts.get("md_h1"):
        md_path = base_path + ".h1.md"
        try:
            from report import generate_markdown_h1
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(generate_markdown_h1(
                    url, vulns, meta, duration,
                    ai_analyses=ai_analyses, exec_summary=exec_summary,
                ))
            generated.append(f"MD H1 → {os.path.abspath(md_path)}")
        except Exception as e:
            print_err(f"Error generando Markdown H1: {e}")

    if opts.get("md_bc"):
        md_path = base_path + ".bugcrowd.md"
        try:
            from report import generate_markdown_bugcrowd
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(generate_markdown_bugcrowd(
                    url, vulns, meta, duration,
                    ai_analyses=ai_analyses, exec_summary=exec_summary,
                ))
            generated.append(f"MD BC → {os.path.abspath(md_path)}")
        except Exception as e:
            print_err(f"Error generando Markdown Bugcrowd: {e}")

    if opts.get("md_int"):
        md_path = base_path + ".intigriti.md"
        try:
            from report import generate_markdown_intigriti
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(generate_markdown_intigriti(
                    url, vulns, meta, duration,
                    ai_analyses=ai_analyses, exec_summary=exec_summary,
                ))
            generated.append(f"MD INT → {os.path.abspath(md_path)}")
        except Exception as e:
            print_err(f"Error generando Markdown Intigriti: {e}")

    if opts.get("md_ywh"):
        md_path = base_path + ".yeswehack.md"
        try:
            from report import generate_markdown_yeswehack
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(generate_markdown_yeswehack(
                    url, vulns, meta, duration,
                    ai_analyses=ai_analyses, exec_summary=exec_summary,
                ))
            generated.append(f"MD YWH → {os.path.abspath(md_path)}")
        except Exception as e:
            print_err(f"Error generando Markdown YesWeHack: {e}")

    if opts.get("md_all"):
        try:
            from report import generate_markdown_h1_all
            files = generate_markdown_h1_all(url, vulns, meta, duration, min_severity="HIGH")
            split_dir = base_path + "_h1_split"
            os.makedirs(split_dir, exist_ok=True)
            for fname, body in files:
                with open(os.path.join(split_dir, fname), "w", encoding="utf-8") as f:
                    f.write(body)
            generated.append(f"MD H1 ALL → {os.path.abspath(split_dir)}/  ({len(files)} archivos)")
        except Exception as e:
            print_err(f"Error generando MD H1 ALL: {e}")

    if opts.get("sarif"):
        sarif_path = base_path + ".sarif"
        try:
            from report import generate_sarif
            with open(sarif_path, "w", encoding="utf-8") as f:
                f.write(generate_sarif(url, vulns, meta, duration))
            generated.append(f"SARIF → {os.path.abspath(sarif_path)}")
        except Exception as e:
            print_err(f"Error generando SARIF: {e}")

    if generated:
        print(f"\n  {G}📄 Reportes generados:{W}")
        for g in generated:
            print(f"     {G}✓{W} {g}")

    if ai_engine:
        stats = ai_engine.stats
        print(f"\n  {M}🤖 Uso de IA:{W} {stats['calls']} llamadas | {stats['tokens_used']:,} tokens | {stats['budget_pct']}% del presupuesto")

    print(f"\n  {DIM}Duración total: {duration:.2f}s{W}\n")


# ─── Web UI launcher ──────────────────────────────────────────────────────────

def _launch_web_ui(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Arranca el servidor FastAPI + Web UI y abre el navegador."""
    try:
        import uvicorn  # type: ignore
    except ImportError:
        print_err("uvicorn no instalado. Instalar: pip install fastapi uvicorn")
        print_info("Luego ejecutar: uvicorn utils.api_server:app --host 0.0.0.0 --port 8000")
        return

    import threading, webbrowser, time as _time

    url = f"http://{host}:{port}"
    print_ok(f"Web UI arrancando en {url}")
    print_info("Pulsa Ctrl+C para detener el servidor.")

    # Abrir navegador tras 1.2s (tiempo para que uvicorn esté listo)
    def _open_browser():
        _time.sleep(1.2)
        webbrowser.open(url)

    threading.Thread(target=_open_browser, daemon=True).start()

    from utils.api_server import app
    uvicorn.run(app, host=host, port=port, log_level="warning")


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    banner(VERSION)

    print(f"  {BOLD}BugBountyHunter Pro v{VERSION}{W} — IA + Vulnerabilidades web\n")
    print(f"  {DIM}Solo para uso ético en sistemas propios o con autorización explícita.{W}")
    print(f"  {DIM}Anti-FP fuerte (no garantía cero). Análisis con IA. Bounty estimate.{W}\n")

    # ── Modo Web UI (API server + dashboard) ───────────────────────────────────
    print(f"  {C}[W]{W} Modo Web UI (dashboard en navegador)  {C}[Enter]{W} Modo terminal\n", end="")
    try:
        choice = input(f"  {C}?{W}  Elige modo [w/Enter]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        choice = ""
    if choice in ("w", "web", "gui", "ui"):
        _launch_web_ui()
        return

    # ── v7.1: cargar .vulrc.yaml si existe ────────────────────────────────────
    rc_data: dict = {}
    try:
        from utils.config_file import find_rc, load_rc
        rc_path = find_rc()
        if rc_path:
            rc_data = load_rc(rc_path) or {}
            print(f"  {G}✓{W}  Config cargada: {DIM}{rc_path}{W}")
    except Exception:
        pass

    # ── Setup de IA ────────────────────────────────────────────────────────────
    ai_config = None
    try:
        ai_config = _prompt_ai_setup()
    except (KeyboardInterrupt, EOFError):
        print("\n\n  ⚠️  Cancelado.\n")
        sys.exit(0)

    # ── URL objetivo ───────────────────────────────────────────────────────────
    print()
    try:
        raw_url = input(f"  {C}▶{W}  URL objetivo: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n\n  ⚠️  Cancelado.\n")
        sys.exit(0)

    if not raw_url:
        print_err("URL vacía. Saliendo.")
        sys.exit(1)

    url  = _fix_url(raw_url)

    # ── v7.1: check de resume para esta URL ───────────────────────────────────
    try:
        from utils import state as _state
        if _state.has_resumable(url):
            r = input(f"  {O}?{W}  Hay un scan previo de este target no completado. ¿Retomarlo? [s/N]: ").strip().lower()
            if r not in ("s", "si", "sí", "y", "yes"):
                _state.clear_state(url)
    except Exception:
        pass

    opts = _prompt_options()

    # ── v7.1: aplicar defaults de .vulrc.yaml encima de los prompts ──────────
    if rc_data:
        try:
            from utils.config_file import merge_opts_with_rc
            opts = merge_opts_with_rc(opts, rc_data)
        except Exception:
            pass

    # ── Autenticación (opcional) ───────────────────────────────────────────────
    auth_config = None
    try:
        from utils.auth import prompt_auth
        auth_config = prompt_auth()
    except (KeyboardInterrupt, EOFError):
        pass

    try:
        # Suprimir el WinError 10054 (ConnectionReset) del ProactorEventLoop de Windows.
        # Ocurre cuando el host remoto cierra conexiones TCP con RST durante port scan —
        # el resultado ya fue capturado antes del error; solo falla el callback de limpieza.
        loop = asyncio.new_event_loop()

        def _suppress_win_connection_reset(loop, context):
            exc = context.get("exception")
            if isinstance(exc, ConnectionResetError):
                return  # ignorar silenciosamente
            loop.default_exception_handler(context)

        loop.set_exception_handler(_suppress_win_connection_reset)
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_run(url, opts, ai_config, auth_config=auth_config))
        finally:
            loop.close()
    except KeyboardInterrupt:
        print("\n\n  ⚠️  Escaneo interrumpido por el usuario.\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n  ❌ Error fatal: {e}\n")
        import traceback; traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
