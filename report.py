"""
report.py — Generación de reportes HTML, JSON y PDF.
BugBountyHunter Pro v5 — incluye análisis IA y estimación de bounty.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from utils.vuln import Vuln, count_by_severity, risk_score
from utils.colors import sev_bg
from config import VERSION

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle,
        Paragraph, Spacer, HRFlowable, KeepTogether,
    )
    REPORTLAB_AVAILABLE = True
    REPORTLAB_ERROR = None
except Exception as _e:
    REPORTLAB_AVAILABLE = False
    REPORTLAB_ERROR = str(_e)


# ─── JSON ─────────────────────────────────────────────────────────────────────

def generate_json(
    url: str,
    vulns: list[Vuln],
    meta: dict,
    duration: float,
    ai_analyses: Optional[dict] = None,
    exec_summary: str = "",
) -> str:
    counts       = count_by_severity(vulns)
    score, level = risk_score(counts)

    vuln_list = []
    for v in vulns:
        d = v.to_dict()
        if ai_analyses and v.dedup_key in ai_analyses:
            d["ai_analysis"] = ai_analyses[v.dedup_key]
        vuln_list.append(d)

    data = {
        "scanner":         f"BugBountyHunter Pro v{VERSION}",
        "url":             url,
        "fecha":           datetime.now().isoformat(),
        "duracion_s":      round(duration, 2),
        "riesgo":          level,
        "risk_score":      score,
        "resumen":         counts,
        "executive_summary": exec_summary,
        "meta":            meta,
        "vulnerabilidades": vuln_list,
    }
    return json.dumps(data, ensure_ascii=False, indent=2)


# ─── HTML ─────────────────────────────────────────────────────────────────────

def _render_modules_coverage_html(meta: dict) -> str:
    modules_run = meta.get("modules_run", [])
    if not modules_run:
        return ""
    rows = ""
    for m in modules_run:
        name     = m.get("name", "?")
        findings = m.get("findings", 0)
        status   = m.get("status", "ok")
        color    = "#3fb950" if findings == 0 else "#d29922" if findings < 3 else "#f85149"
        badge    = f'<span style="color:{color};font-weight:bold">{findings}</span>'
        st_color = "#3fb950" if status == "ok" else "#8b949e"
        rows += (
            f'<tr><td><code>{name}</code></td>'
            f'<td style="text-align:center">{badge}</td>'
            f'<td style="color:{st_color};text-align:center">{status}</td></tr>'
        )
    scan_flags = meta.get("scan_flags", {})
    flags_html = " ".join(
        f'<span style="background:#21262d;border:1px solid #30363d;border-radius:4px;padding:2px 6px;font-size:11px;color:#8b949e">{k}</span>'
        for k, v in scan_flags.items() if v
    )
    return (
        f'<div class="section"><h2>📋 Cobertura de módulos ejecutados ({len(modules_run)})</h2>'
        f'<div style="margin-bottom:8px">{flags_html}</div>'
        f'<table style="width:100%;border-collapse:collapse;font-size:13px">'
        f'<thead><tr style="border-bottom:1px solid #30363d">'
        f'<th style="text-align:left;padding:6px 8px;color:#8b949e">Módulo</th>'
        f'<th style="text-align:center;padding:6px 8px;color:#8b949e">Hallazgos</th>'
        f'<th style="text-align:center;padding:6px 8px;color:#8b949e">Estado</th></tr></thead>'
        f'<tbody>{rows}</tbody></table></div>'
    )


def _render_crawled_html(crawled_urls: list) -> str:
    if not crawled_urls or len(crawled_urls) <= 1:
        return ""
    items = "".join(
        f'<div class="path-row"><code><a href="{u}" target="_blank" style="color:#8b949e">{u[:100]}</a></code></div>'
        for u in crawled_urls[:60]
    )
    more = f'<div class="path-row" style="color:#8b949e;font-style:italic">... y {len(crawled_urls)-60} más</div>' if len(crawled_urls) > 60 else ""
    return f'<div class="section"><h2>🕷 URLs descubiertas por Crawler ({len(crawled_urls)})</h2>{items}{more}</div>'


def generate_html(
    url: str,
    vulns: list[Vuln],
    meta: dict,
    duration: float,
    ai_analyses: Optional[dict] = None,
    exec_summary: str = "",
    advanced_tests: Optional[list] = None,
    attack_chains: Optional[list] = None,
) -> str:
    from bounty_db import estimate_bounty, categorize_finding_for_bounty, find_program
    from urllib.parse import urlparse

    counts       = count_by_severity(vulns)
    score, level = risk_score(counts)
    hostname     = urlparse(url).hostname or ""

    risk_color = sev_bg(
        "CRITICAL" if score >= 30 else
        "HIGH"     if score >= 15 else
        "MEDIUM"   if score >= 7  else "LOW"
    )

    # Bounty program info
    program_info = find_program(hostname)
    program_html = ""
    if program_info:
        program_html = f"""
        <div class="meta-card program-card">
          <div class="lbl">🏆 Bounty Program</div>
          <div class="val">{program_info['name']}</div>
          <div class="sub">{program_info['platform']} · ${program_info['min']:,}–${program_info['max']:,}</div>
        </div>"""

    # Executive summary — sólo si la IA generó contenido real
    _FALLBACK_MSG = "Análisis ejecutivo no disponible"
    summary_html = ""
    if exec_summary and _FALLBACK_MSG not in exec_summary:
        summary_html = f"""
<div class="section">
  <h2>📋 Resumen Ejecutivo <span class="ai-badge">🤖 IA</span></h2>
  <div class="exec-summary">{exec_summary}</div>
</div>"""

    # Attack Chains
    chains_html = ""
    if attack_chains:
        chain_items = ""
        for chain in attack_chains:
            sev_map = {
                "CRITICAL": "#ff3333", "HIGH": "#ff8800",
                "MEDIUM": "#ffcc00",   "LOW": "#33cc33"
            }
            sc = sev_map.get(chain.get("severity", ""), "#58a6ff")
            steps_html = "".join(
                f'<li style="margin:4px 0">{s}</li>'
                for s in chain.get("steps", [])
            )
            chain_items += f"""
<div style="background:#1a1215;border-left:4px solid {sc};padding:12px 16px;
            border-radius:4px;margin-bottom:10px">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
    <span class="badge" style="background:{sc}">{chain.get('severity','')}</span>
    <strong style="color:#e6edf3">{chain.get('name','')}</strong>
  </div>
  <div style="color:#8b949e;font-size:.82em;margin-bottom:6px">⚡ Impacto: {chain.get('impact','')}</div>
  <ol style="margin-left:18px;color:#c9d1d9;font-size:.82em">{steps_html}</ol>
</div>"""
        chains_html = f"""
<div class="section">
  <h2>⛓ Cadenas de Ataque <span class="ai-badge">🤖 IA</span></h2>
  {chain_items}
</div>"""

    # Advanced tests suggestions
    tests_html = ""
    if advanced_tests:
        items = "".join(f"<li>{t}</li>" for t in advanced_tests)
        tests_html = f"""
<div class="section">
  <h2>🎯 Tests Avanzados Recomendados <span class="ai-badge">🤖 IA</span></h2>
  <ol class="test-list">{items}</ol>
</div>"""

    # Build rows
    rows = ""
    total_bounty_min, total_bounty_max = 0, 0

    for v in vulns:
        color   = sev_bg(v.severity)
        ref_lnk = f'<a href="{v.ref}" target="_blank">📖 Ref</a>' if v.ref else ""
        vuln_url = getattr(v, "url", "")
        url_lnk  = f'<br><a href="{vuln_url}" target="_blank" style="font-size:.8em">{vuln_url[:60]}</a>' if vuln_url else ""

        # Bounty info
        bounty         = estimate_bounty(v.severity, v.category, hostname)
        classification = categorize_finding_for_bounty(v.title, v.severity)
        eligible_color_map = {
            "very_likely": "#3fb950", "likely": "#3fb950",
            "possible": "#f0883e",    "unlikely": "#ff3333",
        }
        elig_color = eligible_color_map.get(classification.get("eligible", ""), "#aaa")
        bounty_range = bounty.get("range_str", "N/A")
        total_bounty_min += bounty.get("min", 0)
        total_bounty_max += bounty.get("max", 0)

        # AI analysis
        analysis    = (ai_analyses or {}).get(v.dedup_key, {})
        ai_html     = ""
        fp_badge    = ""
        real_sev    = v.severity

        if analysis:
            if analysis.get("is_false_positive"):
                fp_badge = '<span class="fp-badge">⚠ Falso Positivo</span>'
            real_sev = analysis.get("real_severity", v.severity)
            real_color = sev_bg(real_sev)
            confidence = analysis.get("confidence", "?")
            owasp = analysis.get("owasp_category", "")
            cwe   = ", ".join(analysis.get("cwe_ids") or [])
            impact = analysis.get("business_impact", "")
            exploit = analysis.get("exploitability", "")
            ai_html = f"""
            <div class="ai-block">
              <span class="ai-badge">🤖 IA</span>
              <span class="badge" style="background:{real_color};margin-left:6px">{real_sev}</span>
              <span class="ai-conf">Confianza: {confidence}%</span>
              <span class="ai-conf">Explotabilidad: {exploit}</span>
              {"<span class='ai-owasp'>"+owasp+"</span>" if owasp else ""}
              {"<span class='ai-cwe'>"+cwe+"</span>" if cwe else ""}
              {"<div class='ai-impact'>💼 "+impact+"</div>" if impact else ""}
            </div>"""

        detailed_fix = analysis.get("detailed_fix", v.fix) if analysis else v.fix
        poc_notes    = analysis.get("poc_notes", "") if analysis else ""

        rows += f"""
        <tr class="vuln-row">
          <td>
            <span class="badge" style="background:{color}">{v.severity}</span>
            <div class="cvss">CVSS {v.cvss:.1f}</div>
            {fp_badge}
          </td>
          <td>
            <strong>{v.title}</strong>{url_lnk}
            {ai_html}
          </td>
          <td><span class="cat">{v.category}</span></td>
          <td>{v.description}</td>
          <td><code>{v.evidence[:150]}</code></td>
          <td class="fix">
            ✅ {detailed_fix}
            {"<div class='poc-note'>🔬 PoC: "+poc_notes+"</div>" if poc_notes else ""}
            <br>{ref_lnk}
          </td>
          <td>
            <span class="bounty-range" style="color:{elig_color}">{bounty_range}</span>
            <div class="bounty-prog">{bounty.get('program','')}</div>
          </td>
        </tr>"""

    # SSL cards
    ssl_info  = meta.get("ssl", {})
    ssl_cards = "".join(
        f'<div class="ssl-card"><div class="lbl">{k.upper()}</div>'
        f'<div class="val">{v}</div></div>'
        for k, v in ssl_info.items() if v
    )

    # Ports
    ports_html = ""
    for p in meta.get("ports", []):
        c = sev_bg(p.get("sev", "LOW"))
        ports_html += (
            f'<span class="port-tag" style="border-color:{c};color:{c}">'
            f'{p["port"]}/{p["name"]}</span> '
        )

    # Paths
    paths_html = ""
    for p in meta.get("paths", []):
        c = sev_bg(p.get("sev", "LOW"))
        paths_html += (
            f'<div class="path-row"><span style="color:{c}">●</span> '
            f'<code>{p["path"]}</code> '
            f'<small>[{p["status"]}] {p["desc"]}</small></div>'
        )

    # APIs
    apis_html = ""
    for a in meta.get("api_endpoints", []):
        t_color = "#58a6ff" if a["type"] == "api" else "#8b949e"
        apis_html += (
            f'<div class="path-row">'
            f'<span style="color:{t_color};font-weight:bold;font-size:.8em;margin-right:8px">[{a["type"].upper()}]</span>'
            f'<code><a href="{a["url"]}" target="_blank" style="color:inherit">{a["url"]}</a></code>'
            f'<small style="color:#8b949e"> (Ref: {a["source"]})</small></div>'
        )

    # Subdomains / techs — con links clickeables
    subs_html = "".join(
        f'<span class="sub-tag"><a href="https://{s}" target="_blank" style="color:inherit">{s}</a></span> '
        for s in meta.get("subdomains", [])
    )
    tech_html = "".join(f'<span class="tech-tag">{t}</span>' for t in meta.get("technologies", []))

    ips        = ", ".join(meta.get("ips", []))
    waf_name   = meta.get("waf") or "No detectado"
    server     = meta.get("server", "") or "Desconocido"
    powered_by = meta.get("powered_by", "") or "N/A"

    bounty_total_html = ""
    if total_bounty_max > 0:
        bounty_total_html = f"""
<div class="section bounty-total">
  <h2>💰 Potencial de Recompensa Estimado</h2>
  <div class="bounty-grid">
    <div class="bounty-card"><div class="blbl">Mínimo</div><div class="bval">${total_bounty_min:,}</div></div>
    <div class="bounty-card"><div class="blbl">Máximo</div><div class="bval green">${total_bounty_max:,}</div></div>
    <div class="bounty-card"><div class="blbl">Hallazgos</div><div class="bval">{len(vulns)}</div></div>
  </div>
  <p class="bounty-disc">Estimación orientativa en USD. Depende del programa, el PoC presentado y la política del programa.</p>
</div>"""

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BugBountyHunter Pro — {url}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Inter',system-ui,sans-serif;background:#0a0e1a;color:#c9d1d9;line-height:1.6;font-size:14px}}
  .header{{background:linear-gradient(135deg,#0d1117 0%,#161b22 50%,#0d1117 100%);
           padding:40px;border-bottom:2px solid #1e2a3a;position:relative;overflow:hidden}}
  .header::before{{content:'';position:absolute;top:0;left:0;right:0;bottom:0;
    background:radial-gradient(ellipse at 20% 50%,rgba(88,166,255,.08) 0%,transparent 60%),
               radial-gradient(ellipse at 80% 20%,rgba(63,185,80,.05) 0%,transparent 50%);pointer-events:none}}
  .header h1{{color:#58a6ff;font-size:1.9em;margin-bottom:4px;font-weight:700;letter-spacing:-.02em}}
  .header .tool-badge{{display:inline-block;background:linear-gradient(90deg,#58a6ff,#a371f7);
    -webkit-background-clip:text;-webkit-text-fill-color:transparent;font-weight:700;font-size:.8em}}
  .header p.target{{color:#8b949e;font-size:.95em;margin-top:4px;font-family:'JetBrains Mono',monospace}}
  .meta-bar{{display:flex;gap:12px;flex-wrap:wrap;margin-top:24px}}
  .meta-card{{background:rgba(22,27,34,.8);padding:12px 18px;border-radius:10px;
              border:1px solid #21262d;min-width:110px;backdrop-filter:blur(4px)}}
  .meta-card .lbl{{color:#8b949e;font-size:.72em;text-transform:uppercase;letter-spacing:.08em}}
  .meta-card .val{{color:#e6edf3;font-size:.95em;margin-top:3px;font-weight:600}}
  .meta-card .sub{{color:#8b949e;font-size:.72em;margin-top:2px}}
  .program-card{{border-color:#f0883e!important}}
  .risk-pill{{display:inline-block;padding:4px 14px;border-radius:20px;font-weight:700;color:#000;font-size:.9em}}
  .section{{padding:28px 40px;border-bottom:1px solid #161b22}}
  .section h2{{color:#58a6ff;margin-bottom:18px;font-size:1.05em;font-weight:600;
               display:flex;align-items:center;gap:8px}}
  .sum-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:12px;margin-bottom:20px}}
  .sum-card{{background:#161b22;border-radius:12px;padding:18px;text-align:center;border:2px solid;
             transition:transform .2s;cursor:default}}
  .sum-card:hover{{transform:translateY(-2px)}}
  .sum-card .num{{font-size:2.2em;font-weight:700;font-family:'JetBrains Mono',monospace}}
  .sum-card .lbl{{font-size:.75em;color:#8b949e;margin-top:4px}}
  table{{width:100%;border-collapse:collapse;font-size:.84em}}
  th{{background:#161b22;color:#58a6ff;padding:10px 12px;text-align:left;border:1px solid #21262d;font-weight:600;font-size:.8em;text-transform:uppercase;letter-spacing:.05em}}
  td{{padding:10px 12px;border:1px solid #21262d;vertical-align:top}}
  .vuln-row:hover td{{background:rgba(88,166,255,.04)}}
  .badge{{padding:3px 9px;border-radius:12px;font-size:.72em;font-weight:700;color:#000;display:inline-block}}
  .cvss{{font-size:.72em;color:#8b949e;margin-top:3px;font-family:'JetBrains Mono',monospace}}
  .cat{{background:#21262d;padding:2px 8px;border-radius:10px;font-size:.78em;white-space:nowrap}}
  .fix{{color:#3fb950;font-size:.82em}}
  code{{background:#161b22;padding:2px 5px;border-radius:4px;font-size:.8em;color:#f0883e;
        word-break:break-all;font-family:'JetBrains Mono',monospace}}
  .port-tag,.sub-tag,.tech-tag{{border:1px solid;border-radius:12px;padding:3px 10px;
    margin:3px;display:inline-block;font-size:.8em;font-family:'JetBrains Mono',monospace}}
  .sub-tag{{border-color:#58a6ff;color:#58a6ff}}
  .tech-tag{{border-color:#3fb950;color:#3fb950}}
  .path-row{{padding:5px 0;border-bottom:1px solid #21262d;font-size:.85em}}
  .ssl-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}}
  .ssl-card{{background:#161b22;padding:12px;border-radius:8px;border:1px solid #21262d}}
  .ssl-card .lbl{{color:#8b949e;font-size:.75em;text-transform:uppercase}}
  .ssl-card .val{{color:#e6edf3;margin-top:3px;word-break:break-all;font-size:.88em;font-family:'JetBrains Mono',monospace}}
  a{{color:#58a6ff;text-decoration:none}}
  a:hover{{text-decoration:underline}}
  footer{{text-align:center;padding:20px;color:#8b949e;font-size:.8em;background:#0d1117}}
  .ai-badge{{background:linear-gradient(90deg,#a371f7,#58a6ff);color:#fff;padding:2px 7px;
             border-radius:10px;font-size:.72em;font-weight:700;vertical-align:middle}}
  .ai-block{{margin-top:6px;padding:6px 8px;background:rgba(163,113,247,.08);
             border-left:3px solid #a371f7;border-radius:4px;font-size:.82em}}
  .ai-conf{{color:#8b949e;margin-left:8px;font-size:.9em}}
  .ai-owasp{{margin-left:8px;color:#f0883e;font-size:.85em}}
  .ai-cwe{{margin-left:4px;color:#8b949e;font-size:.85em}}
  .ai-impact{{color:#8b949e;margin-top:3px;font-style:italic}}
  .fp-badge{{background:#ff333322;color:#ff6666;border:1px solid #ff3333;padding:2px 7px;
             border-radius:8px;font-size:.72em;font-weight:600}}
  .bounty-range{{font-weight:700;font-size:.9em;font-family:'JetBrains Mono',monospace}}
  .bounty-prog{{color:#8b949e;font-size:.75em;margin-top:2px}}
  .bounty-total{{background:linear-gradient(135deg,rgba(63,185,80,.05),rgba(88,166,255,.05))}}
  .bounty-grid{{display:flex;gap:20px;flex-wrap:wrap;margin-bottom:12px}}
  .bounty-card{{background:#161b22;padding:16px 24px;border-radius:10px;border:1px solid #21262d;text-align:center}}
  .bounty-card .blbl{{color:#8b949e;font-size:.75em;text-transform:uppercase;letter-spacing:.05em}}
  .bounty-card .bval{{font-size:1.8em;font-weight:700;font-family:'JetBrains Mono',monospace;color:#58a6ff;margin-top:4px}}
  .bounty-card .bval.green{{color:#3fb950}}
  .bounty-disc{{color:#8b949e;font-size:.8em;font-style:italic}}
  .exec-summary{{background:#161b22;border-left:4px solid #58a6ff;padding:16px 20px;
                 border-radius:4px;line-height:1.7;color:#c9d1d9}}
  .test-list{{margin-left:20px;color:#c9d1d9}}
  .test-list li{{margin:6px 0;padding-left:4px}}
  .poc-note{{color:#a371f7;font-size:.8em;margin-top:4px;font-style:italic}}
</style>
</head>
<body>

<div class="header">
  <h1>🔍 BugBountyHunter Pro</h1>
  <span class="tool-badge">AI-Powered · Zero False Positives · Bug Bounty Ready</span>
  <p class="target">Target: {url}</p>
  <div class="meta-bar">
    <div class="meta-card">
      <div class="lbl">Fecha</div>
      <div class="val">{datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
    </div>
    <div class="meta-card">
      <div class="lbl">Duración</div>
      <div class="val">{duration:.1f}s</div>
    </div>
    <div class="meta-card">
      <div class="lbl">IPs</div>
      <div class="val">{ips or '?'}</div>
    </div>
    <div class="meta-card">
      <div class="lbl">WAF/CDN</div>
      <div class="val">{waf_name}</div>
    </div>
    <div class="meta-card">
      <div class="lbl">Servidor</div>
      <div class="val" style="font-size:.82em">{server}</div>
    </div>
    <div class="meta-card">
      <div class="lbl">Plataforma</div>
      <div class="val" style="font-size:.82em">{powered_by}</div>
    </div>
    <div class="meta-card">
      <div class="lbl">Nivel de Riesgo</div>
      <div class="val"><span class="risk-pill" style="background:{risk_color}">{level}</span></div>
    </div>
    {program_html}
  </div>
</div>

<div class="section">
  <h2>Resumen de Vulnerabilidades</h2>
  <div class="sum-grid">
    <div class="sum-card" style="border-color:#ff3333">
      <div class="num" style="color:#ff3333">{counts['CRITICAL']}</div>
      <div class="lbl">💀 CRÍTICAS</div>
    </div>
    <div class="sum-card" style="border-color:#ff8800">
      <div class="num" style="color:#ff8800">{counts['HIGH']}</div>
      <div class="lbl">🔴 ALTAS</div>
    </div>
    <div class="sum-card" style="border-color:#ffcc00">
      <div class="num" style="color:#ffcc00">{counts['MEDIUM']}</div>
      <div class="lbl">🟠 MEDIAS</div>
    </div>
    <div class="sum-card" style="border-color:#33cc33">
      <div class="num" style="color:#33cc33">{counts['LOW']}</div>
      <div class="lbl">🟡 BAJAS</div>
    </div>
    <div class="sum-card" style="border-color:#4dd0e1">
      <div class="num" style="color:#4dd0e1">{counts['INFO']}</div>
      <div class="lbl">⚪ INFO</div>
    </div>
    <div class="sum-card" style="border-color:#58a6ff">
      <div class="num" style="color:#58a6ff">{len(vulns)}</div>
      <div class="lbl">📊 TOTAL</div>
    </div>
  </div>
</div>

{summary_html}
{chains_html}
{bounty_total_html}
{f'<div class="section"><h2>SSL/TLS</h2><div class="ssl-grid">{ssl_cards}</div></div>' if ssl_cards else ''}
{f'<div class="section"><h2>Tecnologías Detectadas</h2>{tech_html}</div>' if tech_html else ''}
{f'<div class="section"><h2>Subdominios ({len(meta.get("subdomains",[]))})</h2>{subs_html}</div>' if subs_html else ''}
{f'<div class="section"><h2>Puertos Abiertos</h2>{ports_html}</div>' if ports_html else ''}
{f'<div class="section"><h2>Paths Sensibles ({len(meta.get("paths",[]))})</h2>{paths_html}</div>' if paths_html else ''}
{f'<div class="section"><h2>API & Endpoints ({len(meta.get("api_endpoints",[]))})</h2>{apis_html}</div>' if apis_html else ''}
{_render_crawled_html(meta.get("crawled_urls", []))}
{_render_modules_coverage_html(meta)}
{tests_html}


<div class="section">
  <h2>Detalle de Vulnerabilidades</h2>
  <table>
    <thead>
      <tr>
        <th>Severidad</th><th>Vulnerabilidad</th><th>Categoría</th>
        <th>Descripción</th><th>Evidencia</th><th>Fix</th><th>💰 Bounty</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>

<footer>
  BugBountyHunter Pro v{VERSION} — Generado el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} —
  Solo para uso ético en sistemas propios o con autorización explícita
</footer>
</body>
</html>"""


# ─── PDF (reportlab — funciona en Windows sin dependencias externas) ──────────

def _build_pdf_html(
    url: str,
    vulns: list[Vuln],
    meta: dict,
    duration: float,
    ai_analyses: Optional[dict] = None,
    exec_summary: str = "",
) -> str:
    """Genera HTML optimizado para xhtml2pdf — plantilla profesional light-mode."""
    from bounty_db import estimate_bounty, find_program
    from urllib.parse import urlparse
    from utils.vuln import count_by_severity, risk_score

    counts       = count_by_severity(vulns)
    score, level = risk_score(counts)
    hostname     = urlparse(url).hostname or ""
    program      = find_program(hostname)
    now          = datetime.now().strftime("%Y-%m-%d %H:%M")

    SEV_COLOR = {
        "CRITICAL": "#c0392b", "HIGH": "#e67e22",
        "MEDIUM": "#f39c12",   "LOW": "#27ae60", "INFO": "#2980b9",
    }
    SEV_BG = {
        "CRITICAL": "#fdecea", "HIGH": "#fef3e2",
        "MEDIUM": "#fefbe6",   "LOW": "#eafaf1", "INFO": "#eaf4fb",
    }

    def badge(sev: str) -> str:
        c = SEV_COLOR.get(sev, "#555")
        return (
            f'<span style="background:{c};color:#fff;padding:2px 7px;'
            f'border-radius:3px;font-size:9px;font-weight:bold;">{sev}</span>'
        )

    def sev_label(sev: str) -> str:
        icons = {"CRITICAL": "💀", "HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "INFO": "⚪"}
        return f"{icons.get(sev, '')} {sev}"

    # Resumen ejecutivo
    summary_block = ""
    if exec_summary and "no disponible" not in exec_summary:
        clean = exec_summary.replace("**", "").replace("*", "")
        summary_block = f"""
<div class="section">
  <div class="section-title">📋 Resumen Ejecutivo <span class="ai-tag">🤖 IA</span></div>
  <p style="line-height:1.6;color:#2c3e50;font-size:10px">{clean}</p>
</div>"""

    # Program info
    program_block = ""
    if program:
        program_block = (
            f'<span style="color:#e67e22;font-weight:bold">🏆 {program["name"]}</span> '
            f'({program["platform"]}) · ${program["min"]:,}–${program["max"]:,} USD'
        )

    # Tabla de vulnerabilidades
    rows = ""
    total_min, total_max = 0, 0
    for i, v in enumerate(vulns, 1):
        sev_c     = SEV_COLOR.get(v.severity, "#555")
        sev_bg    = SEV_BG.get(v.severity, "#fff")
        analysis  = (ai_analyses or {}).get(v.dedup_key, {})
        bounty    = estimate_bounty(v.severity, v.category, hostname)
        total_min += bounty.get("min", 0)
        total_max += bounty.get("max", 0)

        # AI info
        ai_row = ""
        if analysis and not analysis.get("is_false_positive"):
            conf      = analysis.get("confidence", "")
            real_sev  = analysis.get("final_severity") or analysis.get("real_severity", v.severity)
            exploit   = analysis.get("exploitability", "")
            owasp     = analysis.get("owasp_category", "")
            impact    = (analysis.get("business_impact") or "")[:100]
            ai_row = (
                f'<div style="margin-top:3px;padding:3px 5px;background:#f0f0f8;'
                f'border-left:2px solid #6c5ce7;font-size:8px;color:#555;">'
                f'<b style="color:#6c5ce7">🤖 IA:</b> {real_sev}'
                f'{" | Conf: "+str(conf)+"%" if conf else ""}'
                f'{" | "+exploit if exploit else ""}'
                f'{" | "+owasp if owasp else ""}'
                f'{"<br><i>"+impact+"</i>" if impact else ""}'
                f'</div>'
            )

        fix_txt = (analysis.get("detailed_fix") or v.fix)[:200] if analysis else v.fix[:200]
        ev_txt  = v.evidence[:180]
        bounty_r = bounty.get("range_str", "N/A")

        rows += f"""
<tr style="background:{sev_bg}">
  <td style="width:5%;text-align:center;font-weight:bold;font-size:10px;color:{sev_c}">{i}</td>
  <td style="width:8%">{badge(v.severity)}<br><span style="font-size:8px;color:#777">CVSS {v.cvss:.1f}</span></td>
  <td style="width:25%">
    <b style="font-size:9.5px;color:#1a1a2e">{v.title}</b>
    <div style="font-size:8px;color:#666;margin-top:2px">{v.category}</div>
    {ai_row}
  </td>
  <td style="width:22%;font-size:8.5px;color:#333">{v.description[:180]}</td>
  <td style="width:22%;font-size:8px;font-family:monospace;color:#c0392b;word-break:break-all">{ev_txt}</td>
  <td style="width:18%;font-size:8.5px;color:#27ae60">{fix_txt}</td>
</tr>"""

    # Stats header row
    stat_cards = "".join(
        f'<td style="text-align:center;padding:8px 12px;border:1px solid #ddd">'
        f'<div style="font-size:22px;font-weight:bold;color:{SEV_COLOR.get(s,"#555")}">{counts[s]}</div>'
        f'<div style="font-size:8px;color:#777">{sev_label(s)}</div></td>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )

    risk_color = SEV_COLOR.get(
        "CRITICAL" if score >= 30 else "HIGH" if score >= 15 else "MEDIUM" if score >= 7 else "LOW", "#555"
    )

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  body        {{ font-family: Helvetica, Arial, sans-serif; font-size: 10px; color: #2c3e50; margin: 0; padding: 0; }}
  @page       {{ size: A4; margin: 1.5cm 1cm 1.5cm 1cm; }}
  .header     {{ background: #1a1a2e; color: #fff; padding: 16px 20px; margin-bottom: 14px; }}
  .header h1  {{ font-size: 18px; margin: 0 0 4px 0; color: #fff; }}
  .header p   {{ font-size: 9px; color: #aaa; margin: 0; }}
  .meta-row   {{ display: table; width: 100%; margin-bottom: 10px; }}
  .meta-cell  {{ display: table-cell; background: #f4f6f8; border: 1px solid #ddd;
                padding: 6px 10px; width: 20%; vertical-align: top; }}
  .meta-label {{ font-size: 7.5px; color: #888; text-transform: uppercase; letter-spacing: 0.5px; }}
  .meta-val   {{ font-size: 10px; font-weight: bold; color: #1a1a2e; margin-top: 2px; }}
  .section        {{ margin-bottom: 12px; }}
  .section-title  {{ font-size: 12px; font-weight: bold; color: #1a1a2e; border-left: 4px solid #2980b9;
                     padding-left: 8px; margin-bottom: 6px; }}
  table       {{ width: 100%; border-collapse: collapse; font-size: 9px; }}
  th          {{ background: #1a1a2e; color: #fff; padding: 6px 5px; text-align: left;
                font-size: 8px; text-transform: uppercase; letter-spacing: 0.4px; }}
  td          {{ padding: 5px; border: 1px solid #e8e8e8; vertical-align: top; }}
  tr:nth-child(even) {{ background: #fcfcfc; }}
  .ai-tag     {{ background: #6c5ce7; color: #fff; padding: 1px 6px; border-radius: 8px;
                font-size: 8px; font-weight: bold; }}
  .footer     {{ text-align: center; color: #aaa; font-size: 7.5px; margin-top: 14px;
                padding-top: 8px; border-top: 1px solid #eee; }}
  .bounty-box {{ background: #eafaf1; border: 1px solid #a9dfbf; padding: 10px 14px;
                margin: 10px 0; border-radius: 4px; }}
</style>
</head>
<body>

<div class="header">
  <h1>🔍 BugBountyHunter Pro — Reporte de Seguridad</h1>
  <p>Target: {url} &nbsp;|&nbsp; Fecha: {now} &nbsp;|&nbsp; Duración: {duration:.1f}s &nbsp;|&nbsp;
     Nivel de riesgo: <b style="color:{risk_color}">{level}</b> (score {score})</p>
  {f'<p style="color:#f39c12;margin-top:4px">{program_block}</p>' if program_block else ''}
</div>

<!-- Resumen por severidad -->
<div class="section">
  <div class="section-title">Resumen de Hallazgos</div>
  <table style="margin-bottom:6px">
    <tr>{stat_cards}</tr>
  </table>
</div>

{summary_block}

<!-- Tabla de vulnerabilidades -->
<div class="section">
  <div class="section-title">Detalle de Vulnerabilidades ({len(vulns)} confirmadas)</div>
  <table>
    <thead>
      <tr>
        <th>#</th><th>Sev.</th><th>Vulnerabilidad</th>
        <th>Descripción</th><th>Evidencia</th><th>Remediación</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>

<!-- Bounty total -->
{f'''<div class="bounty-box">
  <b>💰 Potencial de Recompensa Estimado:</b>
  &nbsp;&nbsp;Mínimo: <b>${total_min:,} USD</b>
  &nbsp;&nbsp;Máximo: <b style="color:#27ae60">${total_max:,} USD</b>
  <span style="color:#888;font-size:8px">&nbsp;&nbsp;(Estimación orientativa)</span>
</div>''' if total_max > 0 else ''}

<div class="footer">
  BugBountyHunter Pro v{VERSION} — Solo para uso ético en sistemas propios o con autorización explícita
</div>

</body>
</html>"""


def generate_pdf(
    url: str,
    vulns: list[Vuln],
    meta: dict,
    duration: float,
    output_path: str,
    ai_analyses: Optional[dict] = None,
    exec_summary: str = "",
) -> bool:
    """
    Genera PDF usando reportlab (pure-Python, Windows compatible).
    Instalar: pip install reportlab
    """
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError(
            f"reportlab no disponible: {REPORTLAB_ERROR}\n"
            "  → Instalar: pip install reportlab"
        )

    from bounty_db import estimate_bounty, find_program
    from urllib.parse import urlparse

    counts       = count_by_severity(vulns)
    score, level = risk_score(counts)
    hostname     = urlparse(url).hostname or ""
    program      = find_program(hostname)
    now          = datetime.now().strftime("%Y-%m-%d %H:%M")

    # ── Colores ───────────────────────────────────────────────────────────────
    C_DARK    = rl_colors.HexColor("#1a1a2e")
    C_BLUE    = rl_colors.HexColor("#2980b9")
    C_CRIT    = rl_colors.HexColor("#c0392b")
    C_HIGH    = rl_colors.HexColor("#e67e22")
    C_MED     = rl_colors.HexColor("#f39c12")
    C_LOW     = rl_colors.HexColor("#27ae60")
    C_INFO    = rl_colors.HexColor("#2980b9")
    C_PURPLE  = rl_colors.HexColor("#6c5ce7")
    C_GRAY    = rl_colors.HexColor("#7f8c8d")
    C_BG_CRIT = rl_colors.HexColor("#fdecea")
    C_BG_HIGH = rl_colors.HexColor("#fef3e2")
    C_BG_MED  = rl_colors.HexColor("#fefbe6")
    C_BG_LOW  = rl_colors.HexColor("#eafaf1")
    C_BG_INFO = rl_colors.HexColor("#eaf4fb")

    SEV_COLOR = {
        "CRITICAL": C_CRIT, "HIGH": C_HIGH, "MEDIUM": C_MED,
        "LOW": C_LOW, "INFO": C_INFO,
    }
    SEV_BG = {
        "CRITICAL": C_BG_CRIT, "HIGH": C_BG_HIGH, "MEDIUM": C_BG_MED,
        "LOW": C_BG_LOW, "INFO": C_BG_INFO,
    }

    # ── Estilos ───────────────────────────────────────────────────────────────
    styles = getSampleStyleSheet()

    def S(name, parent="Normal", **kw) -> ParagraphStyle:
        return ParagraphStyle(name, parent=styles[parent], **kw)

    title_style = S("TitleS",   fontSize=18, textColor=rl_colors.white,   spaceAfter=4)
    sub_style   = S("SubS",     fontSize=9,  textColor=rl_colors.HexColor("#aaaaaa"), spaceAfter=2)
    h2_style    = S("H2S",      fontSize=11, textColor=C_DARK, fontName="Helvetica-Bold", spaceBefore=8, spaceAfter=4)
    normal      = S("NormS",    fontSize=8,  textColor=C_DARK, spaceAfter=2)
    small       = S("SmallS",   fontSize=7,  textColor=C_GRAY, spaceAfter=1)
    mono        = S("MonoS",    fontSize=7,  fontName="Courier", textColor=C_CRIT, wordWrap="CJK")
    ai_style    = S("AIS",      fontSize=7,  textColor=C_PURPLE, spaceAfter=1)
    fix_style   = S("FixS",     fontSize=7,  textColor=rl_colors.HexColor("#27ae60"), spaceAfter=1)
    summary_sty = S("SumS",     fontSize=8,  textColor=C_DARK, spaceAfter=2, leading=12)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=1.5*cm, leftMargin=1.5*cm,
        topMargin=2*cm,     bottomMargin=2*cm,
        title=f"BugBountyHunter Pro — {hostname}",
        author="BugBountyHunter Pro",
    )

    story: list = []

    # ── Header block ──────────────────────────────────────────────────────────
    header_data = [[
        Paragraph("<b>🔍 BugBountyHunter Pro — Reporte de Seguridad</b>", title_style),
    ]]
    header_tbl = Table(header_data, colWidths=[doc.width])
    header_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,-1), C_DARK),
        ("TOPPADDING",  (0,0), (-1,-1), 14),
        ("BOTTOMPADDING",(0,0),(-1,-1), 14),
        ("LEFTPADDING", (0,0), (-1,-1), 16),
    ]))
    story.append(header_tbl)

    meta_data = [[
        Paragraph(f"<b>Target:</b> {url}", normal),
        Paragraph(f"<b>Fecha:</b> {now}", normal),
        Paragraph(f"<b>Duración:</b> {duration:.1f}s", normal),
        Paragraph(f"<b>Riesgo:</b> <font color='#{score}' >{level}</font>", normal),
    ]]
    meta_tbl = Table(meta_data, colWidths=[doc.width/4]*4)
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), rl_colors.HexColor("#f4f6f8")),
        ("BOX",          (0,0), (-1,-1), 0.5, rl_colors.HexColor("#dddddd")),
        ("INNERGRID",    (0,0), (-1,-1), 0.3, rl_colors.HexColor("#eeeeee")),
        ("TOPPADDING",   (0,0), (-1,-1), 6),
        ("BOTTOMPADDING",(0,0), (-1,-1), 6),
        ("LEFTPADDING",  (0,0), (-1,-1), 8),
    ]))
    story.append(meta_tbl)

    if program:
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph(
            f"🏆 <b>{program['name']}</b> ({program['platform']}) · "
            f"${program['min']:,}–${program['max']:,} USD",
            S("ProgS", fontSize=8, textColor=C_HIGH),
        ))

    story.append(Spacer(1, 0.4*cm))

    # ── Resumen por severidad ─────────────────────────────────────────────────
    story.append(Paragraph("Resumen de Hallazgos", h2_style))
    sev_labels = {"CRITICAL": "💀 CRÍTICAS", "HIGH": "🔴 ALTAS",
                  "MEDIUM": "🟠 MEDIAS", "LOW": "🟡 BAJAS", "INFO": "⚪ INFO"}
    sum_data = [
        [Paragraph(f"<b>{counts[s]}</b>", S(f"NC_{s}", fontSize=20, textColor=SEV_COLOR[s],
                                            fontName="Helvetica-Bold", alignment=TA_CENTER))
         for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO")],
        [Paragraph(sev_labels[s], S(f"NL_{s}", fontSize=7, textColor=C_GRAY, alignment=TA_CENTER))
         for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO")],
    ]
    sum_tbl = Table(sum_data, colWidths=[doc.width/5]*5)
    sum_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), rl_colors.HexColor("#f9f9f9")),
        ("BOX",          (0,0), (-1,-1), 0.5, rl_colors.HexColor("#dddddd")),
        ("INNERGRID",    (0,0), (-1,-1), 0.3, rl_colors.HexColor("#eeeeee")),
        ("TOPPADDING",   (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",(0,0), (-1,-1), 8),
        ("LINEBELOW",    (0,0), (-1,0),  0.5, rl_colors.HexColor("#dddddd")),
    ]))
    story.append(sum_tbl)
    story.append(Spacer(1, 0.3*cm))

    # ── Executive summary (IA) ─────────────────────────────────────────────────
    if exec_summary and "no disponible" not in exec_summary:
        story.append(Paragraph("📋 Resumen Ejecutivo  🤖 IA", h2_style))
        clean_summary = exec_summary.replace("**", "").replace("*", "")[:600]
        story.append(Paragraph(clean_summary, summary_sty))
        story.append(Spacer(1, 0.2*cm))

    # ── Tabla de vulnerabilidades ─────────────────────────────────────────────
    story.append(Paragraph(f"Detalle de Vulnerabilidades ({len(vulns)} confirmadas)", h2_style))

    col_w = [0.5*cm, 1.4*cm, 4.5*cm, 4.5*cm, 4.2*cm, 3.6*cm]
    hdr = [
        Paragraph("<b>#</b>",           S("TH", fontSize=7, textColor=rl_colors.white, fontName="Helvetica-Bold")),
        Paragraph("<b>Severidad</b>",   S("TH", fontSize=7, textColor=rl_colors.white, fontName="Helvetica-Bold")),
        Paragraph("<b>Vulnerabilidad</b>", S("TH", fontSize=7, textColor=rl_colors.white, fontName="Helvetica-Bold")),
        Paragraph("<b>Descripción</b>", S("TH", fontSize=7, textColor=rl_colors.white, fontName="Helvetica-Bold")),
        Paragraph("<b>Evidencia</b>",   S("TH", fontSize=7, textColor=rl_colors.white, fontName="Helvetica-Bold")),
        Paragraph("<b>Remediación</b>", S("TH", fontSize=7, textColor=rl_colors.white, fontName="Helvetica-Bold")),
    ]

    tbl_data = [hdr]
    tbl_styles = [
        ("BACKGROUND",   (0,0), (-1,0),  C_DARK),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [rl_colors.white, rl_colors.HexColor("#f9f9f9")]),
        ("BOX",          (0,0), (-1,-1), 0.5, rl_colors.HexColor("#dddddd")),
        ("INNERGRID",    (0,0), (-1,-1), 0.3, rl_colors.HexColor("#eeeeee")),
        ("TOPPADDING",   (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0), (-1,-1), 4),
        ("LEFTPADDING",  (0,0), (-1,-1), 4),
        ("VALIGN",       (0,0), (-1,-1), "TOP"),
    ]

    total_min, total_max = 0, 0
    for i, v in enumerate(vulns, 1):
        analysis = (ai_analyses or {}).get(v.dedup_key, {})
        bounty   = estimate_bounty(v.severity, v.category, hostname)
        total_min += bounty.get("min", 0)
        total_max += bounty.get("max", 0)

        sev_c  = SEV_COLOR.get(v.severity, C_GRAY)
        sev_bg = SEV_BG.get(v.severity, rl_colors.white)
        fix_t  = (analysis.get("detailed_fix") or v.fix)[:200] if analysis else v.fix[:200]

        ai_txt = ""
        if analysis and not analysis.get("is_false_positive"):
            real_sev = analysis.get("real_severity", v.severity)
            conf     = analysis.get("confidence", "")
            ai_txt   = f" [IA: {real_sev}" + (f" {conf}%" if conf else "") + "]"

        title_para = Paragraph(
            f"<b>{v.title[:80]}</b>"
            f'<br/><font color="#888888" size="6">{v.category}</font>'
            + (f'<br/><font color="#6c5ce7" size="6">{ai_txt}</font>' if ai_txt else ""),
            normal,
        )
        ev_para  = Paragraph(v.evidence[:200].replace("\n", "<br/>"), mono)
        fix_para = Paragraph(fix_t, fix_style)

        row = [
            Paragraph(str(i), small),
            Paragraph(
                f"<b>{v.severity}</b><br/>"
                f'<font size="6" color="#888888">CVSS {v.cvss:.1f}</font>'
                f'<br/><font size="6" color="#888888">{bounty.get("range_str","")}</font>',
                S(f"SevP_{i}", fontSize=7, textColor=sev_c, fontName="Helvetica-Bold"),
            ),
            title_para,
            Paragraph(v.description[:250], small),
            ev_para,
            fix_para,
        ]
        tbl_data.append(row)
        tbl_styles.append(("BACKGROUND", (0, i), (1, i), sev_bg))

    vuln_tbl = Table(tbl_data, colWidths=col_w, repeatRows=1)
    vuln_tbl.setStyle(TableStyle(tbl_styles))
    story.append(vuln_tbl)
    story.append(Spacer(1, 0.4*cm))

    # ── Bounty total ──────────────────────────────────────────────────────────
    if total_max > 0:
        bounty_data = [[
            Paragraph(f"💰 <b>Potencial de Recompensa Estimado</b>   "
                      f"Mínimo: <b>${total_min:,} USD</b>   "
                      f"Máximo: <b>${total_max:,} USD</b>   "
                      f"<font color='#888888'>(Estimación orientativa)</font>",
                      S("BountyS", fontSize=8, textColor=C_LOW)),
        ]]
        b_tbl = Table(bounty_data, colWidths=[doc.width])
        b_tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,-1), rl_colors.HexColor("#eafaf1")),
            ("BOX",          (0,0), (-1,-1), 0.5, rl_colors.HexColor("#a9dfbf")),
            ("TOPPADDING",   (0,0), (-1,-1), 8),
            ("BOTTOMPADDING",(0,0), (-1,-1), 8),
            ("LEFTPADDING",  (0,0), (-1,-1), 10),
        ]))
        story.append(b_tbl)
        story.append(Spacer(1, 0.3*cm))

    # ── Módulos ejecutados ────────────────────────────────────────────────────
    modules_run = meta.get("modules_run", [])
    if modules_run:
        story.append(Paragraph(f"📋 Cobertura de Módulos ({len(modules_run)} ejecutados)", h2_style))
        mod_data = [["Módulo", "Hallazgos", "Estado"]]
        mod_styles_list = [
            ("BACKGROUND",   (0,0), (-1,0), C_DARK),
            ("TEXTCOLOR",    (0,0), (-1,0), rl_colors.white),
            ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",     (0,0), (-1,-1), 7),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [rl_colors.HexColor("#f9f9f9"), rl_colors.white]),
            ("GRID",         (0,0), (-1,-1), 0.3, rl_colors.HexColor("#dddddd")),
            ("TOPPADDING",   (0,0), (-1,-1), 3),
            ("BOTTOMPADDING",(0,0), (-1,-1), 3),
            ("LEFTPADDING",  (0,0), (-1,-1), 5),
        ]
        for m in modules_run:
            findings = m.get("findings", 0)
            color = "#27ae60" if findings == 0 else "#e67e22" if findings < 3 else "#c0392b"
            mod_data.append([
                Paragraph(f"<font name='Courier'>{m.get('name','?')}</font>", normal),
                Paragraph(f"<font color='{color}'><b>{findings}</b></font>", normal),
                Paragraph(m.get("status", "ok"), small),
            ])
        mod_tbl = Table(mod_data, colWidths=[doc.width*0.6, doc.width*0.2, doc.width*0.2], repeatRows=1)
        mod_tbl.setStyle(TableStyle(mod_styles_list))
        story.append(mod_tbl)
        story.append(Spacer(1, 0.3*cm))

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=rl_colors.HexColor("#dddddd")))
    story.append(Paragraph(
        f"BugBountyHunter Pro v{VERSION} — Solo para uso ético en sistemas propios o con autorización explícita",
        S("FooterS", fontSize=7, textColor=C_GRAY, alignment=TA_CENTER),
    ))

    doc.build(story)
    return True


# ─── Markdown (HackerOne / Bugcrowd / genérico) ──────────────────────────────

def _md_modules_coverage(meta: dict) -> list[str]:
    modules_run = meta.get("modules_run", [])
    if not modules_run:
        return []
    lines = [
        "## Módulos ejecutados",
        "",
        f"| Módulo | Hallazgos | Estado |",
        "|--------|:---------:|:------:|",
    ]
    for m in modules_run:
        name     = m.get("name", "?")
        findings = m.get("findings", 0)
        status   = m.get("status", "ok")
        badge    = f"⚠️ {findings}" if findings > 0 else "✅ 0"
        lines.append(f"| `{name}` | {badge} | {status} |")
    scan_flags = meta.get("scan_flags", {})
    active_flags = [k for k, v in scan_flags.items() if v]
    if active_flags:
        lines += ["", f"**Flags activos:** `{'`, `'.join(active_flags)}`"]
    lines.append("")
    return lines


def _md_severity_badge(sev: str) -> str:
    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}
    return f"{icons.get(sev, '⚪')} **{sev}**"


def generate_markdown_h1(
    url: str,
    vulns: list[Vuln],
    meta: dict,
    duration: float,
    ai_analyses: Optional[dict] = None,
    exec_summary: str = "",
) -> str:
    """
    Formato HackerOne: un report por vulnerabilidad. Por defecto, retorna
    SOLO el primer CRITICAL/HIGH. Si quieres un report combinado, llamar
    generate_markdown_h1_combined.
    """
    if not vulns:
        return "# Sin hallazgos para reportar"

    top = next((v for v in vulns if v.severity in ("CRITICAL", "HIGH")), vulns[0])
    ai = (ai_analyses or {}).get(top.dedup_key, {})

    poc = ai.get("poc_curl") or "*(generar con `curl -i '" + url + "'`)*"
    report_title = ai.get("report_title") or top.title
    impact_demo = ai.get("impact_demo", "")
    cvss_vec = top.cvss_vector or ai.get("cvss_vector", "")
    cvss_extra = f" — `{cvss_vec}`" if cvss_vec else ""

    cwe_line = f"**CWE:** {top.cwe}" if top.cwe else ""
    owasp_line = f"**OWASP:** {top.owasp}" if top.owasp else ""

    impact_demo_block = ""
    if impact_demo:
        impact_demo_block = f"### Impact Demonstration\n\n{impact_demo}\n"

    cwe_ref_line = ""
    if top.cwe:
        cwe_num = top.cwe.replace("CWE-", "")
        cwe_ref_line = f"- CWE-{cwe_num}: https://cwe.mitre.org/data/definitions/{cwe_num}.html"

    return f"""## {report_title}

**Severity:** {_md_severity_badge(top.severity)} (CVSS {top.cvss}{cvss_extra})
**Category:** {top.category}
**Target:** `{url}`
{cwe_line}
{owasp_line}

### Summary

{top.description}

### Steps to Reproduce

1. Authenticate as a normal user (or anonymous if N/A).
2. Send the following request:

```bash
{poc}
```

3. Observe the response.

### Proof of Concept

```
{top.evidence}
```

{impact_demo_block}

### Impact

{ai.get("business_impact", top.description)}

### Suggested Fix

{ai.get("detailed_fix", top.fix)}

### References

- {top.ref}
{cwe_ref_line}

---
*Reported via BugBountyHunter Pro v{VERSION} — Scan duration: {duration:.1f}s*
"""


def generate_markdown_bugcrowd(
    url: str,
    vulns: list[Vuln],
    meta: dict,
    duration: float,
    ai_analyses: Optional[dict] = None,
    exec_summary: str = "",
) -> str:
    """Reporte combinado estilo Bugcrowd VRT — todos los hallazgos."""
    counts       = count_by_severity(vulns)
    score, level = risk_score(counts)

    out = [
        f"# Security Assessment — {url}",
        "",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d')}  ",
        f"**Tool:** BugBountyHunter Pro v{VERSION}  ",
        f"**Duration:** {duration:.1f}s  ",
        f"**Risk:** {level} (score {score})  ",
        f"**Findings:** "
        f"{counts['CRITICAL']}C / {counts['HIGH']}H / {counts['MEDIUM']}M / "
        f"{counts['LOW']}L / {counts['INFO']}I",
        "",
    ]

    if exec_summary:
        out += ["## Executive Summary", "", exec_summary, ""]

    techs = meta.get("technologies") or []
    ips   = meta.get("ips") or []
    out += [
        "## Target Info",
        "",
        f"- **IPs:** {', '.join(ips) or 'N/A'}",
        f"- **Server:** {meta.get('server', 'unknown')}",
        f"- **WAF:** {meta.get('waf') or 'none detected'}",
        f"- **Technologies:** {', '.join(techs) or 'unknown'}",
        "",
    ]

    out.append("## Findings")
    out.append("")

    for i, v in enumerate(vulns, 1):
        if v.severity == "INFO":
            continue
        ai = (ai_analyses or {}).get(v.dedup_key, {})
        cvss_vec = v.cvss_vector or ai.get("cvss_vector", "")
        out += [
            f"### {i}. {v.title}",
            "",
            f"- **Severity:** {_md_severity_badge(v.severity)}",
            f"- **CVSS:** {v.cvss}" + (f" `{cvss_vec}`" if cvss_vec else ""),
            f"- **Category:** {v.category}",
        ]
        if v.cwe:
            out.append(f"- **CWE:** {v.cwe}")
        if v.owasp:
            out.append(f"- **OWASP:** {v.owasp}")
        if v.url and v.url != url:
            out.append(f"- **URL:** `{v.url}`")
        out += [
            "",
            f"**Description:** {v.description}",
            "",
            "**Evidence:**",
            "",
            "```",
            v.evidence,
            "```",
            "",
            f"**Fix:** {v.fix}",
            "",
        ]
        if v.ref:
            out += [f"**Reference:** {v.ref}", ""]
        out.append("---")
        out.append("")

    out += _md_modules_coverage(meta)
    return "\n".join(out)


# ─── Markdown Intigriti / YesWeHack ──────────────────────────────────────────

def generate_markdown_intigriti(
    url: str,
    vulns: list[Vuln],
    meta: dict,
    duration: float,
    ai_analyses: Optional[dict] = None,
    exec_summary: str = "",
) -> str:
    """
    Formato Intigriti: usa estructura específica del platform
    (Issue, Steps to reproduce, Severity, CVSS, Affected URL, Suggested fix).
    """
    if not vulns:
        return "# No findings to report"

    top = next((v for v in vulns if v.severity in ("CRITICAL", "HIGH")), vulns[0])
    ai = (ai_analyses or {}).get(top.dedup_key, {})

    cvss_vec = top.cvss_vector or ai.get("cvss_vector", "")
    cvss_str = f"{top.cvss}" + (f" — {cvss_vec}" if cvss_vec else "")
    poc = ai.get("poc_curl") or f"curl -i '{url}'"

    coverage = "\n".join(_md_modules_coverage(meta))
    return f"""# {ai.get("report_title") or top.title}

## Issue

{top.description}

## Severity & Impact

- **Severity:** {top.severity}
- **CVSS Score:** {cvss_str}
- **Category:** {top.category}
- **CWE:** {top.cwe or 'N/A'}
- **Impact:** {ai.get("business_impact", top.description)}

## Affected URL

`{top.url or url}`

## Steps to Reproduce

```bash
{poc}
```

## Proof of Concept

```
{top.evidence}
```

## Suggested Fix

{ai.get("detailed_fix", top.fix)}

## References

- {top.ref}

{coverage}"""


def generate_markdown_yeswehack(
    url: str,
    vulns: list[Vuln],
    meta: dict,
    duration: float,
    ai_analyses: Optional[dict] = None,
    exec_summary: str = "",
) -> str:
    """YesWeHack format: muy similar a Intigriti pero con CVSS:3.1 vector explícito."""
    if not vulns:
        return "# No findings"

    top = next((v for v in vulns if v.severity in ("CRITICAL", "HIGH")), vulns[0])
    ai = (ai_analyses or {}).get(top.dedup_key, {})
    cvss_vec = top.cvss_vector or ai.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    poc = ai.get("poc_curl") or f"curl -i '{url}'"
    coverage = "\n".join(_md_modules_coverage(meta))

    return f"""# {top.title}

| Field           | Value |
|----------------|-------|
| **Severity**   | {top.severity} (CVSS {top.cvss}) |
| **CVSS Vector**| `{cvss_vec}` |
| **Category**   | {top.category} |
| **CWE**        | {top.cwe or 'N/A'} |
| **Endpoint**   | `{top.url or url}` |

## Description

{top.description}

## Reproduction Steps

1. Identify the vulnerable endpoint: `{top.url or url}`
2. Send the following request:

```bash
{poc}
```

3. Verify the response indicators below.

## Evidence

```
{top.evidence}
```

## Impact

{ai.get("business_impact", "Refer to description.")}

## Remediation

{ai.get("detailed_fix", top.fix)}

## References

- {top.ref}

{coverage}"""


# ─── Full per-vuln Markdown (todos los CRITICAL/HIGH, no solo el primero) ────

def generate_markdown_h1_all(
    url:        str,
    vulns:      list[Vuln],
    meta:       dict,
    duration:   float,
    min_severity: str = "HIGH",
) -> list[tuple[str, str]]:
    """
    Genera un Markdown H1 INDEPENDIENTE por cada vuln CRITICAL/HIGH (o el filtro indicado).
    Devuelve lista de (filename_sugerido, markdown_body) para que el caller los
    grabe a disco.

    Útil cuando quieres submittear cada finding como reporte separado en H1.
    """
    sev_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    threshold = sev_order.get(min_severity.upper(), 4)

    eligible = [v for v in vulns if sev_order.get(v.severity, 0) >= threshold]
    eligible.sort(key=lambda v: (-sev_order.get(v.severity, 0), -v.cvss))

    out: list[tuple[str, str]] = []

    for idx, v in enumerate(eligible, 1):
        cwe_line   = f"**Weakness:** {v.cwe}\n" if v.cwe else ""
        owasp_line = f"**OWASP:** {v.owasp}\n" if v.owasp else ""
        vector     = f" `{v.cvss_vector}`" if v.cvss_vector else ""

        body = f"""# {v.title}

**Target:** {v.url or url}
**Severity:** {v.severity} (CVSS {v.cvss}{vector})
{cwe_line}{owasp_line}
## Summary

{v.description}

## Steps to Reproduce

```
{v.evidence}
```

## Impact

{v.description}

## Remediation

{v.fix}

## References

- {v.ref or 'N/A'}

---
*Generated by BugBountyHunter Pro v7.0 — finding {idx}/{len(eligible)}*
"""
        # filename slug
        slug = "".join(c if c.isalnum() else "_" for c in v.title[:60]).strip("_")
        fname = f"{idx:02d}-{v.severity}-{slug}.md"
        out.append((fname, body))

    return out


# ─── SARIF (GitHub Code Scanning compatible) ──────────────────────────────────

def generate_sarif(
    url: str,
    vulns: list[Vuln],
    meta: dict,
    duration: float,
) -> str:
    """
    SARIF 2.1.0 export — compatible con GitHub Code Scanning, Azure DevOps,
    GitLab Security Dashboard.
    """
    sev_to_level = {
        "CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
        "LOW": "note", "INFO": "note",
    }
    rules = []
    results = []
    rule_idx: dict[str, int] = {}

    for v in vulns:
        rule_id = v.category.replace(" ", "_") + ":" + v.title[:40].replace(" ", "_")
        if rule_id not in rule_idx:
            rule_idx[rule_id] = len(rules)
            rules.append({
                "id": rule_id,
                "name": v.title,
                "shortDescription": {"text": v.title[:120]},
                "fullDescription":  {"text": v.description},
                "helpUri":          v.ref or "",
                "properties": {
                    "category": v.category,
                    "cwe":      v.cwe,
                    "owasp":    v.owasp,
                    "security-severity": str(v.cvss),
                },
            })
        results.append({
            "ruleId":  rule_id,
            "ruleIndex": rule_idx[rule_id],
            "level":   sev_to_level.get(v.severity, "warning"),
            "message": {"text": v.evidence[:500]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": v.url or url},
                }
            }],
            "properties": {
                "cvss":        v.cvss,
                "cvss_vector": v.cvss_vector,
                "confidence":  v.confidence,
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name":         "BugBountyHunter Pro",
                    "version":      VERSION,
                    "informationUri": "https://github.com/",
                    "rules":        rules,
                }
            },
            "results":   results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.utcnow().isoformat() + "Z",
            }],
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)

