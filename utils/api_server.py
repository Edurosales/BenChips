"""
utils/api_server.py — BugBountyHunter Pro: API HTTP + Web UI completa.

Endpoints:
  GET  /                      Web UI dashboard
  POST /scan                  Inicia scan → { task_id }
  POST /scan/{id}/stop        Cancela scan en curso
  GET  /scan/{id}             Estado + resultados
  GET  /scan/{id}/stream      SSE log en tiempo real
  GET  /scan/{id}/report/{f}  Descarga reporte
  GET  /scans                 Lista de scans
  POST /test-connection       Prueba alcanzabilidad del target
  POST /test-ai               Prueba config AI
  GET  /healthz               { ok: true }

Auth: Bearer token via VUL_API_TOKEN env var.
Run:  uvicorn utils.api_server:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import asyncio
import json as _json
import os
import uuid
from datetime import datetime
from typing import Optional

try:
    from fastapi import FastAPI, HTTPException, Header, Request
    from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, Response
    from pydantic import BaseModel
    _HAS_FASTAPI = True
except ImportError:
    _HAS_FASTAPI = False
    class FastAPI:
        def __init__(self, **kw): pass
        def get(self, *a, **kw): return lambda f: f
        def post(self, *a, **kw): return lambda f: f
    class HTTPException(Exception):
        def __init__(self, status_code=500, detail=""): pass
    Header = lambda *a, **kw: None
    class BaseModel: pass
    HTMLResponse = JSONResponse = StreamingResponse = Response = object


# ─── Modelos ──────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    url:         str
    full:        bool = False
    active:      bool = False
    ports:       bool = True
    stealth:     bool = False
    adaptive:    bool = False
    audit:       bool = False
    oob:         bool = False
    tracer:      bool = False
    program:     str  = "generic"
    proxy:       str  = ""
    scope_file:  str  = ""
    auth_bearer: str  = ""
    auth_cookie: str  = ""


class ConnectionTestRequest(BaseModel):
    url: str


class AiTestRequest(BaseModel):
    provider: str = "openai"
    model:    str = "gpt-4o-mini"
    api_key:  str = ""
    base_url: str = ""


# ─── Log sink per-scan (SSE con replay) ──────────────────────────────────────

class _ScanLog:
    """Buffer de log con notificación async para SSE con replay desde offset N."""

    def __init__(self):
        self.lines:    list[str]             = []
        self._waiters: list[asyncio.Future]  = []
        self.done:     bool                  = False

    def append(self, line: str) -> None:
        self.lines.append(line)
        for fut in self._waiters:
            if not fut.done():
                try:
                    fut.set_result(None)
                except Exception:
                    pass
        self._waiters.clear()

    async def wait_new(self, timeout: float = 25.0) -> None:
        loop = asyncio.get_event_loop()
        fut  = loop.create_future()
        self._waiters.append(fut)
        try:
            await asyncio.wait_for(asyncio.shield(fut), timeout=timeout)
        except asyncio.TimeoutError:
            if fut in self._waiters:
                self._waiters.remove(fut)


# ─── Estado global ────────────────────────────────────────────────────────────

_TOKEN      = os.environ.get("VUL_API_TOKEN", "")
_TASKS:      dict[str, dict]       = {}
_SCAN_LOGS:  dict[str, _ScanLog]   = {}
_SCAN_TASKS: dict[str, asyncio.Task] = {}


def _check_auth(authorization: Optional[str]) -> None:
    if not _TOKEN:
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    if authorization.split(" ", 1)[1].strip() != _TOKEN:
        raise HTTPException(status_code=403, detail="invalid token")


# ─── Web UI ───────────────────────────────────────────────────────────────────

_UI = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BugBountyHunter Pro v7.3</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--bg4:#2d333b;
  --border:#30363d;--text:#e6edf3;--dim:#8b949e;
  --crit:#f85149;--high:#ff7b72;--med:#ffa657;--low:#3fb950;--info:#58a6ff;
  --accent:#58a6ff;--green:#3fb950;--orange:#d29922;--purple:#bc8cff;
}
body{background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,sans-serif;height:100vh;display:flex;flex-direction:column;overflow:hidden;font-size:13px}
a{color:var(--accent);text-decoration:none}
code{font-family:'Cascadia Code',Consolas,monospace;font-size:12px;color:#7ee787;background:var(--bg3);padding:1px 5px;border-radius:3px}

/* Header */
header{background:var(--bg2);border-bottom:1px solid var(--border);padding:8px 16px;display:flex;align-items:center;gap:10px;flex-shrink:0}
header h1{font-size:14px;font-weight:700;color:var(--accent);white-space:nowrap}
header h1 span{color:var(--dim);font-weight:400;font-size:12px}
#pill{padding:2px 10px;border-radius:10px;font-size:11px;font-weight:600;background:var(--bg3);color:var(--dim);margin-left:auto;white-space:nowrap}
#pill.running{background:#122821;color:var(--green)}
#pill.done{background:#122821;color:var(--green)}
#pill.error{background:#2d1111;color:var(--crit)}
#pill.stopped{background:var(--bg3);color:var(--orange)}

/* Layout */
main{display:flex;flex:1;overflow:hidden}
aside{width:290px;background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow-y:auto;flex-shrink:0}
.aside-inner{padding:12px;display:flex;flex-direction:column;gap:10px;flex:1}
section{flex:1;display:flex;flex-direction:column;overflow:hidden}

/* Form elements */
.lbl{font-size:10px;color:var(--dim);font-weight:600;text-transform:uppercase;letter-spacing:.5px;display:block;margin-bottom:3px}
.inp{width:100%;background:var(--bg3);border:1px solid var(--border);color:var(--text);padding:6px 9px;border-radius:5px;font-size:12px;outline:none;font-family:inherit}
.inp:focus{border-color:var(--accent)}
.inp-row{display:flex;gap:5px}
.inp-row .inp{flex:1}
select.inp{cursor:pointer}

/* Toggles */
.tog-grid{display:grid;grid-template-columns:1fr 1fr;gap:3px}
.tog{display:flex;align-items:center;gap:5px;padding:4px 7px;background:var(--bg3);border:1px solid var(--border);border-radius:4px;cursor:pointer;font-size:11px;user-select:none;transition:.1s}
.tog:hover{border-color:var(--accent)}
.tog input{accent-color:var(--accent);width:12px;height:12px;cursor:pointer}
.tog input:checked ~ span{color:var(--accent)}

/* Collapsible */
.coll-hdr{display:flex;align-items:center;justify-content:space-between;cursor:pointer;padding:4px 0;color:var(--dim);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;user-select:none}
.coll-hdr:hover{color:var(--text)}
.coll-hdr .arr{transition:.2s}
.coll-body{display:none;flex-direction:column;gap:6px;padding-top:6px}
.coll-body.open{display:flex}

/* Buttons */
.btn{width:100%;padding:8px;border-radius:5px;border:none;font-size:12px;font-weight:600;cursor:pointer;transition:.15s;font-family:inherit}
.btn-primary{background:var(--accent);color:#0d1117}
.btn-primary:hover{background:#79c0ff}
.btn-primary:disabled{opacity:.4;cursor:default}
.btn-danger{background:transparent;color:var(--crit);border:1px solid var(--crit)}
.btn-danger:disabled{opacity:.3;cursor:default}
.btn-sm{width:auto;padding:5px 10px;font-size:11px}
.btn-ghost{background:var(--bg3);color:var(--dim);border:1px solid var(--border)}
.btn-ghost:hover{color:var(--text);border-color:var(--dim)}

/* Status badge */
.badge-wrap{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:10px;display:none}
#risk{font-size:20px;font-weight:700;text-align:center;padding:4px 0}
#risk.CRITICAL{color:var(--crit)}#risk.HIGH{color:var(--high)}
#risk.MEDIUM{color:var(--med)}#risk.LOW{color:var(--low)}#risk.INFO{color:var(--info)}
.cnt-row{display:flex;justify-content:space-around;margin-top:5px}
.cnt{padding:1px 7px;border-radius:8px;font-size:10px;font-weight:700}
.cnt-c{background:#2d0f0f;color:var(--crit)}.cnt-h{background:#2d1a0f;color:var(--high)}
.cnt-m{background:#2d220f;color:var(--med)}.cnt-l{background:#0f2d15;color:var(--low)}
.cnt-i{background:#0f182d;color:var(--info)}
#dur-txt{font-size:10px;color:var(--dim);text-align:center;margin-top:4px}

/* Tabs */
.tabs{display:flex;background:var(--bg2);border-bottom:1px solid var(--border);flex-shrink:0;overflow-x:auto}
.tab{padding:9px 14px;font-size:12px;cursor:pointer;border:none;background:none;color:var(--dim);border-bottom:2px solid transparent;white-space:nowrap;font-family:inherit}
.tab:hover{color:var(--text)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab-badge{background:var(--bg4);border-radius:8px;padding:1px 5px;font-size:10px;margin-left:4px}

/* Tab content */
.tc{display:none;flex:1;overflow:hidden;flex-direction:column}
.tc.active{display:flex}

/* Console */
#phase-bar{padding:6px 14px;background:var(--bg2);border-bottom:1px solid var(--border);flex-shrink:0;display:none}
#phase-label{font-size:11px;color:var(--dim)}
#phase-track{height:3px;background:var(--bg3);border-radius:2px;margin-top:4px;overflow:hidden}
#phase-fill{height:100%;background:var(--accent);border-radius:2px;width:0;transition:width .4s ease}
#console-wrap{flex:1;overflow-y:auto;padding:10px 14px}
#console-out{font-family:'Cascadia Code',Consolas,monospace;font-size:11.5px;line-height:1.65;white-space:pre-wrap;word-break:break-all;color:#7ee787}

/* Vulns */
#v-toolbar{padding:8px 14px;background:var(--bg2);border-bottom:1px solid var(--border);display:flex;gap:8px;align-items:center;flex-shrink:0}
#v-search{flex:1}
.sev-filter{display:flex;gap:4px}
.sf{padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;cursor:pointer;border:1px solid transparent;opacity:.5;transition:.1s}
.sf.on{opacity:1;border-color currentColor}
.sf-all{background:var(--bg3);color:var(--dim)}.sf-c{background:#2d0f0f;color:var(--crit)}
.sf-h{background:#2d1a0f;color:var(--high)}.sf-m{background:#2d220f;color:var(--med)}
.sf-l{background:#0f2d15;color:var(--low)}.sf-i{background:#0f182d;color:var(--info)}
#v-wrap{flex:1;overflow-y:auto;padding:10px 14px;display:flex;flex-direction:column;gap:8px}
.vcard{background:var(--bg2);border:1px solid var(--border);border-radius:6px;overflow:hidden}
.vhead{padding:9px 12px;display:flex;align-items:center;gap:8px;cursor:pointer;user-select:none}
.vhead:hover{background:var(--bg3)}
.vsev{padding:1px 7px;border-radius:8px;font-size:10px;font-weight:700;flex-shrink:0}
.sC{background:#2d0f0f;color:var(--crit)}.sH{background:#2d1a0f;color:var(--high)}
.sM{background:#2d220f;color:var(--med)}.sL{background:#0f2d15;color:var(--low)}
.sI{background:#0f182d;color:var(--info)}
.vtitle{flex:1;font-size:12px;font-weight:600}
.vcvss{font-size:10px;color:var(--dim);flex-shrink:0}
.vbounty{font-size:10px;color:var(--green);flex-shrink:0;margin-left:2px}
.vbody{display:none;padding:10px 12px;border-top:1px solid var(--border);font-size:11.5px;color:var(--dim);line-height:1.65}
.vbody.open{display:block}
.vbody strong{color:var(--text)}
.vbody pre{background:var(--bg3);padding:7px 9px;border-radius:4px;overflow-x:auto;color:#7ee787;margin:5px 0;font-size:11px}
.vfeedback{display:flex;gap:5px;margin-top:8px}
.fbtn{padding:3px 9px;border-radius:4px;border:1px solid var(--border);background:transparent;color:var(--dim);cursor:pointer;font-size:10px;font-family:inherit}
.fbtn:hover{border-color:var(--accent);color:var(--accent)}
.fbtn.fp-active{background:#2d0f0f;color:var(--crit);border-color:var(--crit)}
.fbtn.valid-active{background:#0f2d15;color:var(--green);border-color:var(--green)}

/* Coverage */
#cov-wrap{flex:1;overflow-y:auto;padding:12px 14px}
.cov-table{width:100%;border-collapse:collapse;font-size:11.5px}
.cov-table th{text-align:left;padding:5px 9px;color:var(--dim);font-weight:600;border-bottom:1px solid var(--border);font-size:10px;text-transform:uppercase}
.cov-table td{padding:5px 9px;border-bottom:1px solid #1a1f26}
.cov-table tr:hover td{background:var(--bg3)}
.m-ok{color:var(--green)}.m-warn{color:var(--orange)}.m-bad{color:var(--crit)}.m-skip{color:var(--dim);font-style:italic}
#flags-row{display:flex;flex-wrap:wrap;gap:5px;margin-top:10px}
.flag{background:var(--bg3);border:1px solid var(--border);border-radius:3px;padding:1px 7px;font-size:10px;color:var(--dim)}

/* Reports */
#rep-wrap{flex:1;overflow-y:auto;padding:14px}
.rep-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px}
.rep-btn{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:12px 8px;text-align:center;text-decoration:none;color:var(--text);display:flex;flex-direction:column;align-items:center;gap:5px;transition:.15s;cursor:pointer}
.rep-btn:hover{border-color:var(--accent);color:var(--accent)}
.rep-icon{font-size:22px}.rep-lbl{font-size:11px;font-weight:600}.rep-sub{font-size:9px;color:var(--dim)}

/* History */
#hist-wrap{flex:1;overflow-y:auto;padding:12px 14px}
.hrow{display:flex;align-items:center;gap:10px;padding:8px 10px;background:var(--bg2);border:1px solid var(--border);border-radius:5px;margin-bottom:5px;cursor:pointer}
.hrow:hover{border-color:var(--accent)}
.hst{font-size:10px;font-weight:700;padding:1px 6px;border-radius:6px;flex-shrink:0}
.hst-done{background:#122821;color:var(--green)}.hst-running{background:#122832;color:var(--accent)}
.hst-error{background:#2d0f0f;color:var(--crit)}.hst-stopped{background:var(--bg4);color:var(--dim)}
.hurl{flex:1;font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.htime{font-size:10px;color:var(--dim);flex-shrink:0}
.hrisk{font-size:10px;font-weight:700;flex-shrink:0}

/* AI test result */
#ai-result{font-size:11px;margin-top:4px;padding:4px 8px;border-radius:4px;display:none}
#ai-result.ok{background:#0f2d15;color:var(--green)}
#ai-result.err{background:#2d0f0f;color:var(--crit)}
#conn-result{font-size:11px;margin-top:4px;display:none;color:var(--green)}
#conn-result.err{color:var(--crit)}

/* Misc */
.sep{border-top:1px solid var(--border);margin:2px 0}
.empty{flex:1;display:flex;align-items:center;justify-content:center;color:var(--dim);font-size:12px}
@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
.spin{display:inline-block;animation:spin 1.2s linear infinite}
</style>
</head>
<body>
<header>
  <h1>🔐 BugBountyHunter Pro <span>v7.3</span></h1>
  <div id="pill">Idle</div>
</header>
<main>
<!-- ═══ SIDEBAR ═══ -->
<aside>
<div class="aside-inner">

  <!-- Target -->
  <div>
    <label class="lbl">Target URL</label>
    <div class="inp-row">
      <input class="inp" type="url" id="url" placeholder="https://target.example.com">
      <button class="btn btn-ghost btn-sm" onclick="testConn()" title="Test connection">⚡</button>
    </div>
    <div id="conn-result"></div>
  </div>

  <!-- Scan options -->
  <div>
    <label class="lbl">Modo de Scan</label>
    <div class="tog-grid">
      <label class="tog"><input type="checkbox" id="o-full"><span>Full Scan</span></label>
      <label class="tog"><input type="checkbox" id="o-active"><span>Active</span></label>
      <label class="tog"><input type="checkbox" id="o-ports" checked><span>Ports</span></label>
      <label class="tog"><input type="checkbox" id="o-stealth"><span>Stealth</span></label>
      <label class="tog"><input type="checkbox" id="o-adaptive"><span>Adaptive</span></label>
      <label class="tog"><input type="checkbox" id="o-audit"><span>Audit Log</span></label>
      <label class="tog"><input type="checkbox" id="o-oob"><span>OOB</span></label>
      <label class="tog"><input type="checkbox" id="o-tracer"><span>Tracer</span></label>
    </div>
  </div>

  <!-- Platform -->
  <div>
    <label class="lbl">Plataforma Bug Bounty</label>
    <select class="inp" id="program">
      <option value="generic">Generic</option>
      <option value="h1">HackerOne</option>
      <option value="bugcrowd">Bugcrowd</option>
      <option value="intigriti">Intigriti</option>
      <option value="yeswehack">YesWeHack</option>
    </select>
  </div>

  <!-- Advanced options (collapsible) -->
  <div>
    <div class="coll-hdr" onclick="toggleColl('adv')">
      <span>Opciones Avanzadas</span><span class="arr" id="arr-adv">▶</span>
    </div>
    <div class="coll-body" id="adv">
      <div>
        <label class="lbl">Proxy (opcional)</label>
        <input class="inp" type="text" id="proxy" placeholder="http://127.0.0.1:8080">
      </div>
      <div>
        <label class="lbl">Scope file (ruta en servidor)</label>
        <input class="inp" type="text" id="scope" placeholder=".vulscope.yaml">
      </div>
      <div>
        <label class="lbl">Auth — Bearer del target</label>
        <input class="inp" type="password" id="auth-bearer" placeholder="eyJhbGciOi...">
      </div>
      <div>
        <label class="lbl">Auth — Cookie del target</label>
        <input class="inp" type="text" id="auth-cookie" placeholder="session=abc123">
      </div>
    </div>
  </div>

  <!-- AI config (collapsible) -->
  <div>
    <div class="coll-hdr" onclick="toggleColl('ai')">
      <span>Configuración IA</span><span class="arr" id="arr-ai">▶</span>
    </div>
    <div class="coll-body" id="ai">
      <div>
        <label class="lbl">Proveedor</label>
        <select class="inp" id="ai-provider" onchange="onProviderChange(this.value)">
          <option value="">— Sin IA —</option>
          <option value="openai">OpenAI</option>
          <option value="anthropic">Anthropic</option>
          <option value="gemini">Google Gemini</option>
          <option value="mistral">Mistral</option>
          <option value="groq">Groq (gratis)</option>
          <option value="ollama">Ollama (local)</option>
          <option value="openrouter">OpenRouter</option>
        </select>
      </div>
      <div>
        <label class="lbl">Modelo <span id="model-hint" style="color:var(--dim);font-weight:400;font-size:9px"></span></label>
        <input class="inp" type="text" id="ai-model" placeholder="gpt-4o-mini">
      </div>
      <div>
        <label class="lbl">API Key</label>
        <input class="inp" type="password" id="ai-key" placeholder="sk-...">
      </div>
      <div>
        <label class="lbl">Base URL (Ollama / OpenRouter)</label>
        <input class="inp" type="text" id="ai-base" placeholder="http://localhost:11434">
      </div>
      <div class="inp-row">
        <button class="btn btn-ghost btn-sm" style="width:100%" onclick="testAI()">🧪 Probar conexión IA</button>
      </div>
      <div id="ai-result"></div>
    </div>
  </div>

  <!-- Server API token -->
  <div>
    <label class="lbl">API Token del servidor</label>
    <input class="inp" type="password" id="srv-token" placeholder="(si VUL_API_TOKEN está configurado)">
  </div>

  <div class="sep"></div>

  <!-- Action buttons -->
  <button class="btn btn-primary" id="btn-start" onclick="startScan()">▶ Start Scan</button>
  <button class="btn btn-danger" id="btn-stop" disabled onclick="stopScan()">■ Stop Scan</button>

  <!-- Summary -->
  <div class="badge-wrap" id="summary">
    <div id="risk">—</div>
    <div class="cnt-row">
      <span class="cnt cnt-c" id="cc">C:0</span>
      <span class="cnt cnt-h" id="ch">H:0</span>
      <span class="cnt cnt-m" id="cm">M:0</span>
      <span class="cnt cnt-l" id="cl">L:0</span>
      <span class="cnt cnt-i" id="ci">I:0</span>
    </div>
    <div id="dur-txt"></div>
  </div>

</div><!-- aside-inner -->
</aside>

<!-- ═══ MAIN PANEL ═══ -->
<section>
  <div class="tabs">
    <button class="tab active" data-tab="console">📟 Console</button>
    <button class="tab" data-tab="vulns">🐛 Vulns <span class="tab-badge" id="tb-vulns">0</span></button>
    <button class="tab" data-tab="coverage">📋 Coverage</button>
    <button class="tab" data-tab="reports">📥 Reports</button>
    <button class="tab" data-tab="history" onclick="loadHistory()">🕐 History</button>
  </div>

  <!-- CONSOLE -->
  <div class="tc active" id="tc-console">
    <div id="phase-bar">
      <div id="phase-label">Iniciando...</div>
      <div id="phase-track"><div id="phase-fill"></div></div>
    </div>
    <div id="console-wrap"><pre id="console-out">Listo. Configura el target y pulsa ▶ Start Scan.
</pre></div>
  </div>

  <!-- VULNS -->
  <div class="tc" id="tc-vulns">
    <div id="v-toolbar">
      <input class="inp v-search" type="text" id="v-search" placeholder="Buscar vuln..." oninput="filterVulns()">
      <div class="sev-filter">
        <span class="sf sf-all on" data-sev="ALL" onclick="setSevFilter('ALL')">All</span>
        <span class="sf sf-c" data-sev="CRITICAL" onclick="setSevFilter('CRITICAL')">C</span>
        <span class="sf sf-h" data-sev="HIGH" onclick="setSevFilter('HIGH')">H</span>
        <span class="sf sf-m" data-sev="MEDIUM" onclick="setSevFilter('MEDIUM')">M</span>
        <span class="sf sf-l" data-sev="LOW" onclick="setSevFilter('LOW')">L</span>
        <span class="sf sf-i" data-sev="INFO" onclick="setSevFilter('INFO')">I</span>
      </div>
    </div>
    <div id="v-wrap"><div class="empty">Sin hallazgos — inicia un scan.</div></div>
  </div>

  <!-- COVERAGE -->
  <div class="tc" id="tc-coverage">
    <div id="cov-wrap">
      <table class="cov-table">
        <thead><tr><th>Módulo</th><th>Hallazgos</th><th>Estado</th></tr></thead>
        <tbody id="cov-body"></tbody>
      </table>
      <div id="flags-row"></div>
      <div class="empty" id="cov-empty" style="display:none">Sin datos de cobertura.</div>
    </div>
  </div>

  <!-- REPORTS -->
  <div class="tc" id="tc-reports">
    <div id="rep-wrap">
      <div class="empty" id="rep-empty">Completa un scan para descargar reportes.</div>
      <div class="rep-grid" id="rep-grid" style="display:none"></div>
    </div>
  </div>

  <!-- HISTORY -->
  <div class="tc" id="tc-history">
    <div id="hist-wrap"><div class="empty">Cargando historial...</div></div>
  </div>

</section>
</main>

<script>
// ── State ───────────────────────────────────────────────────────────────────
let taskId = null, evtSrc = null, allVulns = [], _vData = [], sevFilter = 'ALL', autoScroll = true;

const PHASES = [
  'WAF','Recon','Crawler','SSL','Headers','Methods','Admin','Paths',
  'Port','Redirect','Content','JS','JWT','API','Host Header','CSP','OAuth',
  'WebSocket','IDOR','SAML','SW','Active','LDAP','XPath','Mail','CSV',
  'Upload','GQL+','Mass','HPP','BizLogic','GQL-IDOR','Rate','2FA','Race','DOM','H2'
];
let phaseIdx = 0;

// ── Tabs ────────────────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(b => b.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  document.querySelectorAll('.tc').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  document.getElementById('tc-' + b.dataset.tab).classList.add('active');
}));

// ── Collapsibles ────────────────────────────────────────────────────────────
function toggleColl(id) {
  const body = document.getElementById(id);
  const arr  = document.getElementById('arr-' + id);
  body.classList.toggle('open');
  arr.textContent = body.classList.contains('open') ? '▼' : '▶';
}

// ── Connection test ─────────────────────────────────────────────────────────
async function testConn() {
  const url = document.getElementById('url').value.trim();
  if (!url) return;
  const el = document.getElementById('conn-result');
  el.style.display = 'block'; el.className = ''; el.textContent = '⌛ Probando...';
  try {
    const r = await fetch('/test-connection', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({url})
    });
    const d = await r.json();
    if (d.ok) { el.className=''; el.textContent = `✓ Alcanzable — HTTP ${d.status} | ${d.server}`; }
    else       { el.className='err'; el.textContent = `✗ ${d.error}`; }
  } catch(e) { el.className='err'; el.textContent = '✗ ' + e.message; }
}

// ── AI test ─────────────────────────────────────────────────────────────────
async function testAI() {
  const el = document.getElementById('ai-result');
  el.style.display='block'; el.className=''; el.textContent='⌛ Probando...';
  try {
    const r = await fetch('/test-ai', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        provider: document.getElementById('ai-provider').value,
        model:    document.getElementById('ai-model').value,
        api_key:  document.getElementById('ai-key').value,
        base_url: document.getElementById('ai-base').value,
      })
    });
    const d = await r.json();
    if (d.ok) { el.className='ok'; el.textContent = '✓ ' + d.message; }
    else       { el.className='err'; el.textContent = '✗ ' + d.error; }
  } catch(e) { el.className='err'; el.textContent = '✗ ' + e.message; }
}

// ── Start scan ───────────────────────────────────────────────────────────────
async function startScan() {
  const url = document.getElementById('url').value.trim();
  if (!url) { alert('Introduce una URL válida.'); return; }

  resetUI();
  const token = document.getElementById('srv-token').value.trim();
  const hdrs  = {'Content-Type':'application/json'};
  if (token) hdrs['Authorization'] = token.startsWith('Bearer ') ? token : 'Bearer ' + token;

  // Configure AI if provided
  const aiProv = document.getElementById('ai-provider').value;
  const aiKey  = document.getElementById('ai-key').value;
  if (aiProv && aiKey) {
    try {
      await fetch('/configure-ai', {
        method:'POST', headers:hdrs,
        body: JSON.stringify({
          provider: aiProv, model: document.getElementById('ai-model').value,
          api_key: aiKey, base_url: document.getElementById('ai-base').value
        })
      });
    } catch(e) {}
  }

  const body = {
    url,
    full:        document.getElementById('o-full').checked,
    active:      document.getElementById('o-active').checked,
    ports:       document.getElementById('o-ports').checked,
    stealth:     document.getElementById('o-stealth').checked,
    adaptive:    document.getElementById('o-adaptive').checked,
    audit:       document.getElementById('o-audit').checked,
    oob:         document.getElementById('o-oob').checked,
    tracer:      document.getElementById('o-tracer').checked,
    program:     document.getElementById('program').value,
    proxy:       document.getElementById('proxy').value.trim(),
    scope_file:  document.getElementById('scope').value.trim(),
    auth_bearer: document.getElementById('auth-bearer').value.trim(),
    auth_cookie: document.getElementById('auth-cookie').value.trim(),
  };

  try {
    const res = await fetch('/scan', {method:'POST', headers:hdrs, body:JSON.stringify(body)});
    if (!res.ok) { appendCon('✗ Error: ' + await res.text()); return; }
    const d = await res.json();
    taskId = d.task_id;
    setPill('running', '● Scanning');
    document.getElementById('btn-start').disabled = true;
    document.getElementById('btn-stop').disabled = false;
    document.getElementById('phase-bar').style.display = 'block';
    appendCon('▶ Scan iniciado — task_id: ' + taskId);
    connectSSE(taskId, token);
  } catch(e) { appendCon('✗ Error: ' + e.message); }
}

// ── Stop scan ─────────────────────────────────────────────────────────────────
async function stopScan() {
  if (evtSrc) { evtSrc.close(); evtSrc = null; }
  if (taskId) {
    try { await fetch('/scan/' + taskId + '/stop', {method:'POST'}); } catch(e) {}
  }
  setPill('stopped', '■ Stopped');
  document.getElementById('btn-start').disabled = false;
  document.getElementById('btn-stop').disabled = true;
  appendCon('■ Scan detenido.');
}

// ── SSE stream ───────────────────────────────────────────────────────────────
function connectSSE(id, token) {
  if (evtSrc) evtSrc.close();
  evtSrc = new EventSource('/scan/' + id + '/stream');

  evtSrc.onmessage = e => {
    if (e.data && e.data !== ':keepalive') {
      appendCon(e.data);
      updatePhase(e.data);
    }
  };

  // Vuln individual — se añade al contador y se acumula
  evtSrc.addEventListener('vuln', e => {
    try {
      const v = JSON.parse(e.data);
      allVulns.push(v);
      document.getElementById('tb-vulns').textContent = allVulns.length;
      const msg = document.getElementById('live-count-msg');
      if (msg) {
        const sev = v.severity || 'INFO';
        const col = {CRITICAL:'var(--crit)',HIGH:'var(--high)',MEDIUM:'var(--med)',LOW:'var(--low)',INFO:'var(--info)'}[sev]||'var(--dim)';
        msg.innerHTML = allVulns.length + ' hallazgos &nbsp;&#183;&nbsp; <span style="color:'+col+'">'+esc(sev)+'</span> '+esc(v.title||'');
      }
    } catch(_) {}
  });

  evtSrc.addEventListener('done', e => {
    try {
      const result = JSON.parse(e.data);
      // Vulns ya acumuladas via 'vuln' events — solo ordenar y renderizar
      allVulns.sort((a,b) => {
        const o = {CRITICAL:5,HIGH:4,MEDIUM:3,LOW:2,INFO:1};
        return (o[b.severity]||0)-(o[a.severity]||0) || (+(b.cvss||0))-(+(a.cvss||0));
      });
      if (allVulns.length === 0) {
        document.getElementById('v-wrap').innerHTML = '<div class="empty">Sin hallazgos detectados.</div>';
      } else {
        renderVulns();
      }
      renderCoverage(result.meta || {});
      renderReports();
      renderSummary(result);
    } catch(err) { appendCon('✗ Error procesando resultados: '+err); }
    evtSrc.close(); evtSrc = null;
    setPill('done', '&#10003; Done');
    document.getElementById('btn-start').disabled = false;
    document.getElementById('btn-stop').disabled = true;
    document.getElementById('phase-fill').style.width = '100%';
    document.getElementById('phase-label').textContent = '&#10003; Completado';
    switchTab('vulns');
  });

  evtSrc.addEventListener('error', e => {
    appendCon('&#x2717; SSE error.');
    setPill('error', '&#x2717; Error');
    document.getElementById('btn-start').disabled = false;
    document.getElementById('btn-stop').disabled = true;
  });
}

// ── Phase progress ────────────────────────────────────────────────────────────
function updatePhase(line) {
  // Lines starting with "▶ " are section headers emitted by colors.py _emit
  if (!line.startsWith('▶ ')) return;
  const title = line.replace(/^▶ /, '').split(' — ').pop() || line;
  const idx = PHASES.findIndex(p => line.toUpperCase().includes(p.toUpperCase()));
  if (idx >= 0) phaseIdx = idx;
  const pct = Math.min(98, Math.round((phaseIdx / PHASES.length) * 100));
  document.getElementById('phase-fill').style.width = pct + '%';
  document.getElementById('phase-label').textContent = line.replace(/^▶ \w+\d* — /, '');
}

// ── Console ───────────────────────────────────────────────────────────────────
function appendCon(text) {
  const el   = document.getElementById('console-out');
  const wrap = document.getElementById('console-wrap');
  const clean = text.replace(/\x1b\[[0-9;]*[mGKHF]/g, '');
  el.textContent += clean + '\n';
  if (autoScroll) wrap.scrollTop = wrap.scrollHeight;
}

document.getElementById('console-wrap').addEventListener('scroll', function() {
  autoScroll = (this.scrollTop + this.clientHeight >= this.scrollHeight - 30);
});

// ── Render results ────────────────────────────────────────────────────────────
// ── Crear y añadir una tarjeta de vuln ───────────────────────────────────────
function appendVulnCard(v, idx, wrap) {
  const sc = {CRITICAL:'sC',HIGH:'sH',MEDIUM:'sM',LOW:'sL',INFO:'sI'}[v.severity]||'sI';
  const ai  = v.ai_analysis || {};
  const bounty = v.bounty_min ? ` &#x1F4B0;$${Number(v.bounty_min).toLocaleString()}&#8211;$${Number(v.bounty_max).toLocaleString()}` : '';
  const refLine   = v.ref   ? `<br><strong>Ref:</strong> <a href="${esc(v.ref)}" target="_blank">${esc(v.ref)}</a>` : '';
  const cweLine   = v.cwe   ? `<br><strong>CWE:</strong> ${esc(v.cwe)}` : '';
  const owaspLine = v.owasp ? `&nbsp;&middot;&nbsp;<strong>OWASP:</strong> ${esc(v.owasp)}` : '';
  const aiSection = ai.business_impact ? `<br><strong>&#x1F916; Impacto (IA):</strong> ${esc(ai.business_impact)}` : '';
  const fixSection= (ai.detailed_fix||v.fix) ? `<br><strong>Fix:</strong> ${esc(ai.detailed_fix||v.fix||'')}` : '';
  const pocSection= ai.poc_curl ? `<br><strong>PoC (IA):</strong><pre>${esc(ai.poc_curl)}</pre>` : '';
  const card = document.createElement('div');
  card.className = 'vcard'; card.dataset.sev = v.severity||'INFO';
  card.innerHTML = `
    <div class="vhead" onclick="toggleCard(this)">
      <span class="vsev ${sc}">${esc(v.severity||'INFO')}</span>
      <span class="vtitle">${esc(v.title||'(sin título)')}</span>
      <span class="vcvss">CVSS ${(+(v.cvss||0)).toFixed(1)}</span>
      ${bounty ? `<span class="vbounty">${bounty}</span>` : ''}
      <span style="color:var(--dim);font-size:10px">&#9660;</span>
    </div>
    <div class="vbody">
      ${v.url ? `<strong>URL:</strong> <code>${esc(v.url)}</code><br><br>` : ''}
      <strong>Descripción:</strong><br>${esc(v.description||'')}
      ${aiSection}${fixSection}
      <br><br><strong>Evidencia:</strong><pre>${esc(v.evidence||'')}</pre>
      ${pocSection}${refLine}${cweLine}${owaspLine}
      <div class="vfeedback">
        <button class="fbtn fbtn-fp"  data-idx="${idx}">&#128078; Falso positivo</button>
        <button class="fbtn fbtn-val" data-idx="${idx}">&#128077; Confirmado</button>
        <button class="fbtn fbtn-poc" data-idx="${idx}">&#128203; Copiar PoC</button>
      </div>
    </div>`;
  wrap.appendChild(card);
}

// ── Renderizar lista filtrada ─────────────────────────────────────────────────
function renderVulns() {
  const wrap = document.getElementById('v-wrap');
  const q    = (document.getElementById('v-search').value || '').toLowerCase();
  wrap.innerHTML = '';
  _vData = [];
  const filtered = allVulns.filter(v => {
    const matchSev = sevFilter === 'ALL' || v.severity === sevFilter;
    const matchQ   = !q || (v.title||'').toLowerCase().includes(q) ||
                     (v.category||'').toLowerCase().includes(q) ||
                     (v.description||'').toLowerCase().includes(q);
    return matchSev && matchQ;
  });
  if (!filtered.length) {
    wrap.innerHTML = '<div class="empty">Sin hallazgos con ese filtro.</div>';
    return;
  }
  filtered.forEach((v, i) => { _vData.push(v); appendVulnCard(v, i, wrap); });
}

// ── Render summary badge ─────────────────────────────────────────────────────
function renderSummary(result) {
  const risk = result.risk || 'INFO';
  const counts = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};
  allVulns.forEach(v => { if (counts[v.severity]!==undefined) counts[v.severity]++; });
  document.getElementById('summary').style.display = 'block';
  const rb = document.getElementById('risk'); rb.textContent = risk; rb.className = risk;
  document.getElementById('cc').textContent = 'C:'+counts.CRITICAL;
  document.getElementById('ch').textContent = 'H:'+counts.HIGH;
  document.getElementById('cm').textContent = 'M:'+counts.MEDIUM;
  document.getElementById('cl').textContent = 'L:'+counts.LOW;
  document.getElementById('ci').textContent = 'I:'+counts.INFO;
  document.getElementById('dur-txt').textContent = 'Duración: '+(result.duration||0).toFixed(1)+'s | Score: '+(result.risk_score||0);
  const execSum = result.exec_summary || '';
  if (execSum) appendCon('\n─── EXECUTIVE SUMMARY ───\n' + execSum);
}

function filterVulns() { renderVulns(); }

function setSevFilter(sev) {
  sevFilter = sev;
  document.querySelectorAll('.sf').forEach(el => {
    el.classList.toggle('on', el.dataset.sev === sev);
  });
  renderVulns();
}

function toggleCard(head) { head.nextElementSibling.classList.toggle('open'); }

// Single delegated handler — avoids all string-interpolation quoting issues
function _vWrapClick(e) {
  const btn = e.target.closest('.fbtn');
  if (!btn) return;
  const idx = parseInt(btn.dataset.idx, 10);
  const v   = _vData[idx];
  if (!v) return;
  if (btn.classList.contains('fbtn-fp')) {
    btn.classList.toggle('fp-active');
    fetch('/feedback', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({action:'fp', module: v.module||'', title: v.title||''})}).catch(()=>{});
  } else if (btn.classList.contains('fbtn-val')) {
    btn.classList.toggle('valid-active');
    fetch('/feedback', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({action:'valid', module: v.module||'', title: v.title||''})}).catch(()=>{});
  } else if (btn.classList.contains('fbtn-poc')) {
    const ai   = v.ai_analysis || {};
    const text = ai.poc_curl || v.evidence || '';
    navigator.clipboard.writeText(text).then(() => {
      const orig = btn.innerHTML;
      btn.textContent = '✓ Copiado';
      setTimeout(() => btn.innerHTML = orig, 1500);
    }).catch(() => { btn.textContent = '(no clipboard)'; });
  }
}

// ── Coverage ──────────────────────────────────────────────────────────────────
function renderCoverage(meta) {
  const body = document.getElementById('cov-body');
  body.innerHTML = '';
  const mods = meta.modules_run || [];
  const skip = meta.modules_skipped || [];

  mods.forEach(m => {
    const n   = m.findings || 0;
    const cls = n === 0 ? 'm-ok' : n < 3 ? 'm-warn' : 'm-bad';
    const b   = n === 0 ? '✅ 0' : '⚠️ ' + n;
    const tr  = document.createElement('tr');
    tr.innerHTML = `<td><code>${esc(m.name)}</code></td><td class="${cls}">${b}</td><td style="color:var(--dim)">${esc(m.status||'ok')}</td>`;
    body.appendChild(tr);
  });

  skip.forEach(m => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td><code>${esc(m)}</code></td><td class="m-skip">—</td><td class="m-skip">skipped (dep ausente)</td>`;
    body.appendChild(tr);
  });

  const flagRow = document.getElementById('flags-row');
  flagRow.innerHTML = '';
  Object.entries(meta.scan_flags || {}).filter(([,v]) => v).forEach(([k]) => {
    const c = document.createElement('span'); c.className = 'flag'; c.textContent = k;
    flagRow.appendChild(c);
  });
}

// ── Reports ───────────────────────────────────────────────────────────────────
function renderReports() {
  if (!taskId) return;
  document.getElementById('rep-empty').style.display = 'none';
  const grid = document.getElementById('rep-grid');
  grid.style.display = 'grid'; grid.innerHTML = '';
  const fmts = [
    {f:'html',        icon:'🌐', lbl:'HTML Report',    sub:'Interactivo'},
    {f:'json',        icon:'{}', lbl:'JSON Data',      sub:'Estructurado'},
    {f:'md_h1',       icon:'🐙', lbl:'HackerOne',      sub:'Markdown'},
    {f:'md_bugcrowd', icon:'🐛', lbl:'Bugcrowd',       sub:'Markdown'},
    {f:'md_intigriti',icon:'🔵', lbl:'Intigriti',      sub:'Markdown'},
    {f:'md_yeswehack',icon:'🟣', lbl:'YesWeHack',      sub:'Markdown'},
    {f:'sarif',       icon:'📊', lbl:'SARIF',           sub:'CI/CD'},
    {f:'pdf',         icon:'📄', lbl:'PDF Ejecutivo',  sub:'ReportLab'},
  ];
  fmts.forEach(({f,icon,lbl,sub}) => {
    const a = document.createElement('a');
    a.className = 'rep-btn'; a.href = '/scan/'+taskId+'/report/'+f; a.target = '_blank';
    a.innerHTML = `<span class="rep-icon">${icon}</span><span class="rep-lbl">${lbl}</span><span class="rep-sub">${sub}</span>`;
    grid.appendChild(a);
  });
}

// ── History ────────────────────────────────────────────────────────────────────
async function loadHistory() {
  const wrap = document.getElementById('hist-wrap');
  wrap.innerHTML = '<div class="empty">Cargando...</div>';
  try {
    const r = await fetch('/scans');
    const scans = await r.json();
    if (!scans.length) { wrap.innerHTML = '<div class="empty">Sin scans previos.</div>'; return; }
    wrap.innerHTML = '';
    scans.reverse().forEach(s => {
      const stCls = {done:'hst-done',running:'hst-running',error:'hst-error',stopped:'hst-stopped'}[s.status]||'hst-stopped';
      const row = document.createElement('div'); row.className = 'hrow';
      const riskColor = {CRITICAL:'var(--crit)',HIGH:'var(--high)',MEDIUM:'var(--med)',LOW:'var(--low)',INFO:'var(--info)'}[s.risk]||'var(--dim)';
      row.innerHTML = `
        <span class="hst ${stCls}">${s.status}</span>
        <span class="hurl" title="${esc(s.url||'')}">🌐 ${esc(s.url||'')}</span>
        ${s.risk ? `<span class="hrisk" style="color:${riskColor}">${s.risk}</span>` : ''}
        <span class="htime">${(s.queued_at||'').slice(0,16).replace('T',' ')}</span>`;
      row.onclick = () => { if (s.task_id) loadScanResult(s.task_id); };
      wrap.appendChild(row);
    });
  } catch(e) { wrap.innerHTML = `<div class="empty">Error: ${e.message}</div>`; }
}

async function loadScanResult(id) {
  try {
    const r = await fetch('/scan/'+id);
    const d = await r.json();
    if (d.status === 'done') {
      taskId = id;
      allVulns = (d.vulns || []).sort((a,b) => {
        const o = {CRITICAL:5,HIGH:4,MEDIUM:3,LOW:2,INFO:1};
        return (o[b.severity]||0)-(o[a.severity]||0) || (+(b.cvss||0))-(+(a.cvss||0));
      });
      document.getElementById('tb-vulns').textContent = allVulns.length;
      if (allVulns.length === 0) {
        document.getElementById('v-wrap').innerHTML = '<div class="empty">Sin hallazgos en este scan.</div>';
      } else {
        renderVulns();
      }
      renderCoverage(d.meta || {});
      renderReports();
      renderSummary(d);
      switchTab('vulns');
    }
  } catch(e) {}
}

// ── UI helpers ─────────────────────────────────────────────────────────────────
function switchTab(name) {
  document.querySelectorAll('.tab').forEach(b => b.classList.toggle('active', b.dataset.tab===name));
  document.querySelectorAll('.tc').forEach(c => c.classList.toggle('active', c.id==='tc-'+name));
}

function setPill(cls, text) {
  const el = document.getElementById('pill');
  el.className = cls; el.textContent = text;
}

function resetUI() {
  allVulns = []; _vData = []; phaseIdx = 0; autoScroll = true;
  sevFilter = 'ALL';
  document.querySelectorAll('.sf').forEach(el => el.classList.toggle('on', el.dataset.sev === 'ALL'));
  document.getElementById('v-search').value = '';
  document.getElementById('console-out').textContent = '';
  document.getElementById('v-wrap').innerHTML = `
    <div style="flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;color:var(--dim);gap:10px;padding:40px 0">
      <div class="spin" style="font-size:28px;color:var(--accent)">&#8635;</div>
      <div style="font-size:12px">Escaneando en curso...</div>
      <div id="live-count-msg" style="font-size:11px;color:var(--dim)">0 hallazgos</div>
    </div>`;
  document.getElementById('cov-body').innerHTML = '';
  document.getElementById('flags-row').innerHTML = '';
  document.getElementById('rep-grid').style.display = 'none';
  document.getElementById('rep-empty').style.display = '';
  document.getElementById('summary').style.display = 'none';
  document.getElementById('tb-vulns').textContent = '0';
  document.getElementById('phase-fill').style.width = '0%';
  document.getElementById('phase-label').textContent = 'Iniciando...';
  document.getElementById('phase-bar').style.display = 'none';
  switchTab('console');
}

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Register delegated vuln card click handler once
document.getElementById('v-wrap').addEventListener('click', _vWrapClick);

// ── Provider model hints ──────────────────────────────────────────────────────
const _MODEL_HINTS = {
  openai:      'gpt-4o-mini',
  anthropic:   'claude-haiku-4-5-20251001',
  gemini:      'gemini-1.5-flash',
  mistral:     'mistral-small-latest',
  groq:        'llama-3.3-70b-versatile',
  ollama:      'llama3.2',
  openrouter:  'openai/gpt-4o-mini',
};
function onProviderChange(prov) {
  const hint  = document.getElementById('model-hint');
  const model = document.getElementById('ai-model');
  if (_MODEL_HINTS[prov]) {
    hint.textContent = '→ ej: ' + _MODEL_HINTS[prov];
    if (!model.value) model.value = _MODEL_HINTS[prov];
  } else {
    hint.textContent = '';
  }
}

// ── Auto-load saved AI config on page load ────────────────────────────────────
(async () => {
  try {
    const r = await fetch('/ai-config');
    if (!r.ok) return;
    const cfg = await r.json();
    if (cfg.provider) document.getElementById('ai-provider').value = cfg.provider;
    if (cfg.model)    document.getElementById('ai-model').value    = cfg.model;
    if (cfg.base_url) document.getElementById('ai-base').value     = cfg.base_url;
    // api_key no se precarga por seguridad (la key en memoria = ok, enviarla al browser = no)
    onProviderChange(cfg.provider || '');
  } catch(e) {}
})();
</script>
</body>
</html>"""


# ─── FastAPI app ───────────────────────────────────────────────────────────────

if _HAS_FASTAPI:
    app = FastAPI(title="BugBountyHunter Pro", version="7.3")

    @app.get("/", response_class=HTMLResponse)
    async def ui():
        return HTMLResponse(_UI)

    @app.get("/healthz")
    def healthz():
        try:
            from config import VERSION
        except Exception:
            VERSION = "7.3"
        return {"ok": True, "version": VERSION}

    # ── Test connection ────────────────────────────────────────────────────────
    @app.post("/test-connection")
    async def test_connection(req: ConnectionTestRequest):
        import aiohttp
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as sess:
                async with sess.get(req.url, ssl=False, allow_redirects=True) as r:
                    server = r.headers.get("Server", r.headers.get("X-Powered-By", "unknown"))
                    return {"ok": True, "status": r.status, "server": server}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ── Test AI ────────────────────────────────────────────────────────────────
    @app.post("/test-ai")
    async def test_ai(req: AiTestRequest):
        if not req.api_key and req.provider not in ("ollama",):
            return {"ok": False, "error": "API key requerida"}
        try:
            import aiohttp
            provider = req.provider.lower()
            _PROVIDER_URLS = {
                "openai":      "https://api.openai.com/v1/models",
                "groq":        "https://api.groq.com/openai/v1/models",
                "mistral":     "https://api.mistral.ai/v1/models",
                "gemini":      "https://generativelanguage.googleapis.com/v1beta/models",
                "openrouter":  "https://openrouter.ai/api/v1/models",
            }
            if provider == "anthropic":
                url  = "https://api.anthropic.com/v1/models"
                hdrs = {"x-api-key": req.api_key, "anthropic-version": "2023-06-01"}
            elif provider == "ollama":
                url  = (req.base_url or "http://localhost:11434") + "/api/tags"
                hdrs = {}
            elif provider == "gemini":
                url  = _PROVIDER_URLS["gemini"] + f"?key={req.api_key}"
                hdrs = {}
            else:
                base = req.base_url.rstrip("/") if req.base_url else None
                url  = (base + "/v1/models") if base else _PROVIDER_URLS.get(provider, _PROVIDER_URLS["openai"])
                hdrs = {"Authorization": f"Bearer {req.api_key}"}

            async with aiohttp.ClientSession() as sess:
                async with sess.get(url, headers=hdrs, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as r:
                    if r.status in (200, 201):
                        return {"ok": True, "message": f"Conectado a {provider} (HTTP {r.status})"}
                    return {"ok": False, "error": f"HTTP {r.status} — {(await r.text())[:200]}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ── Configure AI (saves to ai_engine) ─────────────────────────────────────
    @app.post("/configure-ai")
    async def configure_ai(request: Request):
        try:
            data = await request.json()
            from ai_engine import save_ai_config
            cfg = {
                "provider": data.get("provider", "openai"),
                "model":    data.get("model", "gpt-4o-mini"),
                "api_key":  data.get("api_key", ""),
                "base_url": data.get("base_url", ""),
            }
            save_ai_config(cfg)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ── Get current AI config (sin api_key) ───────────────────────────────────
    @app.get("/ai-config")
    def get_ai_config():
        try:
            from ai_engine import load_ai_config
            cfg = load_ai_config()
            return {
                "provider": cfg.get("provider", ""),
                "model":    cfg.get("model", ""),
                "base_url": cfg.get("base_url", ""),
                "has_key":  bool(cfg.get("api_key")),
            }
        except Exception:
            return {"provider": "", "model": "", "base_url": "", "has_key": False}

    # ── Feedback ───────────────────────────────────────────────────────────────
    @app.post("/feedback")
    async def feedback(request: Request):
        try:
            data   = await request.json()
            from utils.feedback_loop import mark_fp, mark_valid
            action = data.get("action", "")
            class _V:
                module   = data.get("module", "")
                title    = data.get("title", "")
                url      = ""
                evidence = ""
            v = _V()
            if action == "fp":
                mark_fp(v)
            elif action == "valid":
                mark_valid(v)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ── Start scan ─────────────────────────────────────────────────────────────
    @app.post("/scan", status_code=202)
    async def start_scan(req: ScanRequest, authorization: Optional[str] = Header(None)):
        _check_auth(authorization)
        task_id = uuid.uuid4().hex[:12]
        log     = _ScanLog()
        _SCAN_LOGS[task_id] = log
        _TASKS[task_id] = {
            "status":    "pending",
            "url":       req.url,
            "queued_at": datetime.now().isoformat(),
        }

        async def _run():
            from utils.colors import set_log_sink
            set_log_sink(log)  # _ScanLog.append notifies SSE waiters
            try:
                _TASKS[task_id]["status"] = "running"
                from scanner import scan

                # Build auth_config if provided
                auth_config = None
                if req.auth_bearer or req.auth_cookie:
                    auth_config = {}
                    if req.auth_bearer:
                        auth_config["bearer"] = req.auth_bearer
                    if req.auth_cookie:
                        auth_config["cookie"] = req.auth_cookie

                proxies = [req.proxy] if req.proxy else None

                import hashlib, time as _t
                tracer_id = hashlib.md5(f"{req.url}{_t.time()}".encode()).hexdigest()[:12] if req.tracer else None

                vulns, meta, duration = await scan(
                    req.url,
                    full_scan     = req.full,
                    active_scan   = req.active,
                    scan_ports    = req.ports,
                    stealth       = req.stealth,
                    adaptive      = req.adaptive,
                    audit_enabled = req.audit,
                    use_oob       = req.oob,
                    proxies       = proxies,
                    scope_file    = req.scope_file or None,
                    tracer_id     = tracer_id,
                    auth_config   = auth_config,
                )

                from utils.vuln import count_by_severity, risk_score
                counts       = count_by_severity(vulns)
                score, level = risk_score(counts)

                # AI analysis
                exec_summary = ""
                ai_per_vuln: dict[str, dict] = {}
                try:
                    from ai_engine import AIEngine, load_ai_config
                    ai_cfg = load_ai_config()
                    if ai_cfg.get("api_key"):
                        # Resolve base_url from provider when field is empty
                        _BASES = {
                            "openai":     "https://api.openai.com",
                            "groq":       "https://api.groq.com/openai",
                            "mistral":    "https://api.mistral.ai",
                            "openrouter": "https://openrouter.ai/api",
                            "gemini":     "https://generativelanguage.googleapis.com",
                        }
                        base_url = (ai_cfg.get("base_url") or "").strip()
                        if not base_url:
                            provider_key = ai_cfg.get("provider", "openai").lower()
                            base_url = _BASES.get(provider_key, "https://api.openai.com")
                        ai_eng = AIEngine(
                            api_key  = ai_cfg["api_key"],
                            base_url = base_url,
                            model    = ai_cfg.get("model") or "gpt-4o-mini",
                        )
                        result_ai    = await ai_eng.full_analysis(
                            vulns, req.url, meta, duration,
                            program=req.program, use_embeddings=True, use_feedback_loop=True
                        )
                        exec_summary = result_ai.get("exec_summary", "")
                        # Merge triage + deep_dive data per vuln
                        triage_data  = result_ai.get("triage", {})
                        deep_data    = result_ai.get("deep_dive", {})
                        for v in vulns:
                            merged = {}
                            if v.dedup_key in triage_data:
                                merged.update(triage_data[v.dedup_key])
                            if v.dedup_key in deep_data:
                                merged.update(deep_data[v.dedup_key])
                            if merged:
                                ai_per_vuln[v.dedup_key] = merged
                except Exception as _ai_err:
                    log.append(f"  → IA: {_ai_err}")

                vuln_dicts = []
                for v in vulns:
                    d = v.to_dict()
                    if v.dedup_key in ai_per_vuln:
                        d["ai_analysis"] = ai_per_vuln[v.dedup_key]
                    vuln_dicts.append(d)

                # Stream vulns individualmente (CRITICAL primero) para carga progresiva en UI
                _sev_ord = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
                sorted_dicts = sorted(
                    vuln_dicts,
                    key=lambda d: (_sev_ord.get(d.get("severity","INFO"),4), -(d.get("cvss") or 0))
                )
                for v_dict in sorted_dicts:
                    log.append("__VULN__" + _json.dumps(v_dict, ensure_ascii=False))

                # Resumen final (sin vulns — ya streameados)
                done_at = datetime.now().isoformat()
                result_summary = {
                    "status":       "done",
                    "url":          req.url,
                    "duration":     round(duration, 2),
                    "risk":         level,
                    "risk_score":   score,
                    "exec_summary": exec_summary,
                    "meta":         meta,
                    "done_at":      done_at,
                }
                # Guardar todo en _TASKS para la descarga de reportes
                _TASKS[task_id].update({**result_summary, "vulns": vuln_dicts})
                log.append("__DONE__" + _json.dumps(result_summary, ensure_ascii=False))
            except asyncio.CancelledError:
                _TASKS[task_id]["status"] = "stopped"
                log.append("■ Scan cancelado.")
                log.append("__ERROR__Cancelado por el usuario")
            except Exception as e:
                import traceback
                _TASKS[task_id]["status"] = "error"
                _TASKS[task_id]["error"]  = str(e)
                log.append(f"✗ Error: {e}")
                log.append("__ERROR__" + str(e))
            finally:
                set_log_sink(None)
                log.done = True
                _SCAN_TASKS.pop(task_id, None)

        task = asyncio.create_task(_run())
        _SCAN_TASKS[task_id] = task
        return {"task_id": task_id}

    # ── Stop scan ──────────────────────────────────────────────────────────────
    @app.post("/scan/{task_id}/stop")
    async def stop_scan(task_id: str):
        t = _SCAN_TASKS.get(task_id)
        if t and not t.done():
            t.cancel()
        if task_id in _TASKS:
            _TASKS[task_id]["status"] = "stopped"
        log = _SCAN_LOGS.get(task_id)
        if log:
            log.append("■ Scan detenido por el usuario.")
            log.append("__ERROR__Detenido")
        return {"ok": True}

    # ── SSE stream ─────────────────────────────────────────────────────────────
    @app.get("/scan/{task_id}/stream")
    async def stream_scan(task_id: str):
        if task_id not in _SCAN_LOGS:
            raise HTTPException(status_code=404, detail="task not found")
        log = _SCAN_LOGS[task_id]

        async def gen():
            pos = 0
            while True:
                while pos < len(log.lines):
                    line = log.lines[pos]; pos += 1
                    if line.startswith("__DONE__"):
                        yield f"event: done\ndata: {line[8:]}\n\n"
                        return
                    elif line.startswith("__VULN__"):
                        yield f"event: vuln\ndata: {line[8:]}\n\n"
                    elif line.startswith("__ERROR__"):
                        yield f"event: error\ndata: {line[9:]}\n\n"
                        return
                    else:
                        safe = line.replace("\n", " ")
                        yield f"data: {safe}\n\n"

                if log.done and pos >= len(log.lines):
                    return

                try:
                    await log.wait_new(timeout=25.0)
                except Exception:
                    yield ": keepalive\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream",
            headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

    # ── Get scan result ────────────────────────────────────────────────────────
    @app.get("/scan/{task_id}")
    def get_scan(task_id: str, authorization: Optional[str] = Header(None)):
        _check_auth(authorization)
        if task_id not in _TASKS:
            raise HTTPException(status_code=404, detail="not found")
        return _TASKS[task_id]

    # ── Download report ────────────────────────────────────────────────────────
    @app.get("/scan/{task_id}/report/{fmt}")
    async def get_report(task_id: str, fmt: str, authorization: Optional[str] = Header(None)):
        _check_auth(authorization)
        if task_id not in _TASKS:
            raise HTTPException(status_code=404, detail="not found")
        t = _TASKS[task_id]
        if t.get("status") != "done":
            raise HTTPException(status_code=400, detail="scan not complete yet")

        import report as rp
        from utils.vuln import Vuln
        import dataclasses

        raw   = t.get("vulns", [])
        fields = {f.name for f in dataclasses.fields(Vuln)}
        vulns = []
        for d in raw:
            try:
                vulns.append(Vuln(**{k: v for k, v in d.items() if k in fields}))
            except Exception:
                pass

        meta     = t.get("meta", {})
        duration = t.get("duration", 0.0)
        url      = t.get("url", "")
        exec_sum = t.get("exec_summary", "")
        ai_dict  = {v.get("dedup_key",""):v.get("ai_analysis",{}) for v in raw if "ai_analysis" in v}

        fmt_map = {
            "html":         (lambda: rp.generate_html(url, vulns, meta, duration, ai_dict, exec_sum),
                             "text/html",         f"scan-{task_id}.html"),
            "json":         (lambda: rp.generate_json(url, vulns, meta, duration, ai_dict, exec_sum),
                             "application/json",  f"scan-{task_id}.json"),
            "sarif":        (lambda: rp.generate_sarif(url, vulns, meta, duration),
                             "application/json",  f"scan-{task_id}.sarif"),
            "md_h1":        (lambda: rp.generate_markdown_h1(url, vulns, meta, duration, ai_dict, exec_sum),
                             "text/markdown",     f"report-h1-{task_id}.md"),
            "md_bugcrowd":  (lambda: rp.generate_markdown_bugcrowd(url, vulns, meta, duration, ai_dict, exec_sum),
                             "text/markdown",     f"report-bugcrowd-{task_id}.md"),
            "md_intigriti": (lambda: rp.generate_markdown_intigriti(url, vulns, meta, duration, ai_dict, exec_sum),
                             "text/markdown",     f"report-intigriti-{task_id}.md"),
            "md_yeswehack": (lambda: rp.generate_markdown_yeswehack(url, vulns, meta, duration, ai_dict, exec_sum),
                             "text/markdown",     f"report-ywh-{task_id}.md"),
        }

        if fmt == "pdf":
            import tempfile, os as _os
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
                tmp = f.name
            try:
                rp.generate_pdf(url, vulns, meta, duration, tmp, ai_dict, exec_sum)
                data = open(tmp, "rb").read()
                return Response(data, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="scan-{task_id}.pdf"'})
            finally:
                try: _os.unlink(tmp)
                except: pass

        if fmt not in fmt_map:
            raise HTTPException(status_code=400, detail=f"formato desconocido: {fmt}")

        fn, mime, fname = fmt_map[fmt]
        try:
            body = fn()
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

        return Response(body, media_type=mime,
            headers={"Content-Disposition": f'attachment; filename="{fname}"'})

    # ── List scans ─────────────────────────────────────────────────────────────
    @app.get("/scans")
    def list_scans(authorization: Optional[str] = Header(None)):
        _check_auth(authorization)
        return [
            {"task_id": tid, "status": t.get("status"), "url": t.get("url"),
             "queued_at": t.get("queued_at"), "risk": t.get("risk"),
             "done_at": t.get("done_at")}
            for tid, t in _TASKS.items()
        ]

else:
    class _DummyApp:
        def get(self, *a, **kw):   return lambda f: f
        def post(self, *a, **kw):  return lambda f: f
    app = _DummyApp()
