"""
report.py — Generación de reportes HTML y JSON.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from utils.vuln import Vuln, count_by_severity, risk_score
from utils.colors import sev_bg
from config import VERSION

try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
    WEASYPRINT_ERROR = None
except Exception as e:
    WEASYPRINT_AVAILABLE = False
    WEASYPRINT_ERROR = str(e)


def generate_json(
    url:       str,
    vulns:     list[Vuln],
    meta:      dict,
    duration:  float,
) -> str:
    counts      = count_by_severity(vulns)
    score, level = risk_score(counts)

    data = {
        "scanner":    f"VulnScanner Pro v{VERSION}",
        "url":        url,
        "fecha":      datetime.now().isoformat(),
        "duracion_s": round(duration, 2),
        "riesgo":     level,
        "risk_score": score,
        "resumen":    counts,
        "meta":       meta,
        "vulnerabilidades": [v.to_dict() for v in vulns],
    }
    return json.dumps(data, ensure_ascii=False, indent=2)


def generate_html(
    url:      str,
    vulns:    list[Vuln],
    meta:     dict,
    duration: float,
) -> str:
    counts       = count_by_severity(vulns)
    score, level = risk_score(counts)

    risk_color = sev_bg(
        "CRITICAL" if score >= 30 else
        "HIGH"     if score >= 15 else
        "MEDIUM"   if score >= 7  else "LOW"
    )

    rows = ""
    for v in vulns:
        color    = sev_bg(v.severity)
        ref_lnk  = f'<a href="{v.ref}" target="_blank">📖 Ref</a>' if v.ref else ""
        vuln_url = getattr(v, "url", "")
        url_lnk  = f'<br><a href="{vuln_url}" target="_blank" style="font-size:.8em">{vuln_url[:60]}</a>' if vuln_url else ""
        rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{v.severity}</span>
              <div class="cvss">CVSS {v.cvss:.1f}</div></td>
          <td><strong>{v.title}</strong>{url_lnk}</td>
          <td><span class="cat">{v.category}</span></td>
          <td>{v.description}</td>
          <td><code>{v.evidence[:150]}</code></td>
          <td class="fix">✅ {v.fix}<br>{ref_lnk}</td>
        </tr>"""

    ssl_info = meta.get("ssl", {})
    ssl_cards = "".join(
        f'<div class="ssl-card"><div class="lbl">{k.upper()}</div>'
        f'<div class="val">{v}</div></div>'
        for k, v in ssl_info.items() if v
    )

    ports_html = ""
    for p in meta.get("ports", []):
        c = sev_bg(p.get("sev", "LOW"))
        ports_html += (
            f'<span class="port-tag" style="border-color:{c};color:{c}">'
            f'{p["port"]}/{p["name"]}</span> '
        )

    paths_html = ""
    for p in meta.get("paths", []):
        c = sev_bg(p.get("sev", "LOW"))
        paths_html += (
            f'<div class="path-row"><span style="color:{c}">●</span> '
            f'<code>{p["path"]}</code> '
            f'<small>[{p["status"]}] {p["desc"]}</small></div>'
        )

    apis_html = ""
    for a in meta.get("api_endpoints", []):
        t_color = "#58a6ff" if a["type"] == "api" else "#8b949e"
        apis_html += (
            f'<div class="path-row"><span style="color:{t_color}; font-weight:bold; font-size:.8em; margin-right:8px">[{a["type"].upper()}]</span> '
            f'<code><a href="{a["url"]}" target="_blank" style="color:inherit">{a["url"]}</a></code> '
            f'<small style="color:#8b949e"> (Ref: {a["source"]})</small></div>'
        )

    subs_html = ""
    for sub in meta.get("subdomains", []):
        subs_html += f'<span class="sub-tag">{sub}</span> '

    techs = meta.get("technologies", [])
    tech_html = "".join(f'<span class="tech-tag">{t}</span>' for t in techs)

    ips = ", ".join(meta.get("ips", []))
    waf = meta.get("waf") or "No detectado"
    server     = meta.get("server", "") or "Desconocido"
    powered_by = meta.get("powered_by", "") or "N/A"

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>VulnScanner Pro — {url}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6}}
  .header{{background:linear-gradient(135deg,#1a1f2e 0%,#0d1117 100%);
            padding:40px;border-bottom:2px solid #21262d}}
  .header h1{{color:#58a6ff;font-size:1.9em;margin-bottom:6px}}
  .header p{{color:#8b949e;font-size:.95em}}
  .meta-bar{{display:flex;gap:14px;flex-wrap:wrap;margin-top:24px}}
  .meta-card{{background:#161b22;padding:12px 18px;border-radius:8px;
              border:1px solid #21262d;min-width:120px}}
  .meta-card .lbl{{color:#8b949e;font-size:.8em;text-transform:uppercase;letter-spacing:.05em}}
  .meta-card .val{{color:#e6edf3;font-size:1em;margin-top:3px;font-weight:600}}
  .risk-pill{{display:inline-block;padding:4px 14px;border-radius:20px;
              font-weight:700;color:#000;font-size:.95em}}
  .section{{padding:28px 40px}}
  .section h2{{color:#58a6ff;margin-bottom:18px;font-size:1.15em;
               border-bottom:1px solid #21262d;padding-bottom:8px}}
  .sum-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));
             gap:14px;margin-bottom:28px}}
  .sum-card{{background:#161b22;border-radius:10px;padding:18px;
             text-align:center;border:2px solid}}
  .sum-card .num{{font-size:2.4em;font-weight:700}}
  .sum-card .lbl{{font-size:.8em;color:#8b949e;margin-top:4px}}
  table{{width:100%;border-collapse:collapse;font-size:.88em}}
  th{{background:#161b22;color:#58a6ff;padding:11px;text-align:left;
      border:1px solid #21262d;font-weight:600}}
  td{{padding:11px;border:1px solid #21262d;vertical-align:top}}
  tr:hover td{{background:#161b22}}
  .badge{{padding:3px 9px;border-radius:12px;font-size:.75em;
          font-weight:700;color:#000;display:inline-block}}
  .cvss{{font-size:.75em;color:#8b949e;margin-top:3px}}
  .cat{{background:#21262d;padding:2px 8px;border-radius:10px;
        font-size:.8em;white-space:nowrap}}
  .fix{{color:#3fb950;font-size:.83em}}
  code{{background:#161b22;padding:2px 5px;border-radius:4px;
        font-size:.82em;color:#f0883e;word-break:break-all}}
  .port-tag,.sub-tag,.tech-tag{{border:1px solid;border-radius:12px;
    padding:4px 11px;margin:3px;display:inline-block;font-size:.82em}}
  .sub-tag{{border-color:#58a6ff;color:#58a6ff}}
  .tech-tag{{border-color:#3fb950;color:#3fb950}}
  .path-row{{padding:5px 0;border-bottom:1px solid #21262d;font-size:.88em}}
  .ssl-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px}}
  .ssl-card{{background:#161b22;padding:14px;border-radius:8px;border:1px solid #21262d}}
  .ssl-card .lbl{{color:#8b949e;font-size:.78em;text-transform:uppercase}}
  .ssl-card .val{{color:#e6edf3;margin-top:3px;word-break:break-all;font-size:.92em}}
  a{{color:#58a6ff;text-decoration:none}}
  a:hover{{text-decoration:underline}}
  footer{{text-align:center;padding:18px;color:#8b949e;font-size:.82em;
          border-top:1px solid #21262d}}
</style>
</head>
<body>

<div class="header">
  <h1>🔍 VulnScanner Pro — Reporte de Seguridad</h1>
  <p>{url}</p>
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
      <div class="val">{waf}</div>
    </div>
    <div class="meta-card">
      <div class="lbl">Servidor</div>
      <div class="val" style="font-size:.85em">{server}</div>
    </div>
    <div class="meta-card">
      <div class="lbl">Plataforma</div>
      <div class="val" style="font-size:.85em">{powered_by}</div>
    </div>
    <div class="meta-card">
      <div class="lbl">Nivel de Riesgo</div>
      <div class="val">
        <span class="risk-pill" style="background:{risk_color}">{level}</span>
      </div>
    </div>
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

{f'<div class="section"><h2>SSL/TLS</h2><div class="ssl-grid">{ssl_cards}</div></div>' if ssl_cards else ''}

{f'<div class="section"><h2>Tecnologías Detectadas</h2>{tech_html}</div>' if tech_html else ''}

{f'<div class="section"><h2>Subdominios Encontrados ({len(meta.get("subdomains",[]))})</h2>{subs_html}</div>' if subs_html else ''}

{f'<div class="section"><h2>Puertos Abiertos</h2>{ports_html}</div>' if ports_html else ''}

{f'<div class="section"><h2>Paths Sensibles ({len(meta.get("paths",[]))})</h2>{paths_html}</div>' if paths_html else ''}

{f'<div class="section"><h2>API & Endpoints Descubiertos ({len(meta.get("api_endpoints",[]))})</h2>{apis_html}</div>' if apis_html else ''}

<div class="section">
  <h2>Detalle de Vulnerabilidades</h2>
  <table>
    <thead>
      <tr>
        <th>Severidad</th><th>Vulnerabilidad</th><th>Categoría</th>
        <th>Descripción</th><th>Evidencia</th><th>Fix</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>

<footer>
  VulnScanner Pro v{VERSION} — Generado el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} —
  Solo para uso ético en sistemas propios o con autorización explícita
</footer>
</body>
</html>"""


def generate_pdf(
    url:      str,
    vulns:    list[Vuln],
    meta:     dict,
    duration: float,
    output_path: str
) -> bool:
    """Genera un reporte PDF ejecutivo utilizando WeasyPrint."""
    if not WEASYPRINT_AVAILABLE:
        raise RuntimeError(
            f"WeasyPrint no está disponible. Error de carga: {WEASYPRINT_ERROR}. "
            "En Windows, WeasyPrint requiere que instales las librerías GTK3 de sistema "
            "(GTK3-Runtime). Para más info visita: https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#windows"
        )

    # Reutilizamos el HTML pero le inyectamos un estilo optimizado para impresión (PDF)
    # Fondo blanco, texto negro, sin estilos dark mode para que se vea formal.
    html_content = generate_html(url, vulns, meta, duration)
    
    # Reemplazar estilos oscuros por estilos claros y formales para PDF
    html_content = html_content.replace("background:#0d1117", "background:#ffffff")
    html_content = html_content.replace("color:#c9d1d9", "color:#333333")
    html_content = html_content.replace("background:#161b22", "background:#f8f9fa")
    html_content = html_content.replace("border:1px solid #21262d", "border:1px solid #dee2e6")
    html_content = html_content.replace("color:#58a6ff", "color:#0056b3")
    html_content = html_content.replace("color:#8b949e", "color:#6c757d")
    html_content = html_content.replace("background:linear-gradient(135deg,#1a1f2e 0%,#0d1117 100%)", "background:#f8f9fa")
    
    # Añadir CSS de paginación para que no corte filas
    pdf_styles = """
    <style>
      @page { size: A4; margin: 2cm; }
      table { page-break-inside: auto; }
      tr    { page-break-inside: avoid; page-break-after: auto; }
      thead { display: table-header-group; }
      tfoot { display: table-footer-group; }
      body  { font-size: 12px; }
      .header h1 { color: #000; }
    </style>
    """
    html_content = html_content.replace("</head>", f"{pdf_styles}</head>")

    HTML(string=html_content).write_pdf(output_path)
    return True

