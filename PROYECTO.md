# BugBountyHunter Pro v7.2 — Resumen del proyecto

Scanner de vulnerabilidades web async con triaje por IA, optimizado para bug bounty profesional.

---

## 1. Lo que la herramienta hace hoy

### 1.1 Reconocimiento pasivo
- DNS resolution (IPv4 + IPv6), PTR, ASN.
- Subdominios desde 5 fuentes: crt.sh, HackerTarget, AlienVault, CertSpotter, wordlist propia.
- Zone transfer attempt.
- Tecnologías (WordPress, Joomla, Drupal, Laravel, Django, Rails, Next.js, React, Angular, Vue, Spring Boot, Express, etc).
- Crawler async (50–100 páginas, profundidad 2).

### 1.2 Análisis estático
- **Security headers:** HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP.
- **CSP context-aware:** ignora `unsafe-inline` si hay `nonce-` o `strict-dynamic` (CSP3).
- **CORS** con doble confirmación (2 orígenes aleatorios).
- **Cookies:** HttpOnly, Secure, SameSite (ignora cookies de tracking).
- **SRI** (Subresource Integrity) en scripts de CDN externo.
- **Mixed content** en páginas HTTPS.
- **EOL software** (IIS, Apache, PHP, Nginx).
- **SSL/TLS:** versión, cifrado, certificado, expiración.

### 1.3 Descubrimiento de superficie
- **Sensitive paths:** 130+ rutas con validadores de contenido por tipo (29 validadores).
- **Admin panels:** 120+ rutas priorizadas según tecnología detectada.
- **HTTP methods peligrosos:** TRACE, PUT, DELETE, OPTIONS, PATCH, CONNECT.
- **Port scan:** 22 puertos críticos (DB, RDP, VNC, dev servers).
- **API & endpoint discovery:** Swagger, GraphQL, OpenAPI, links JS.
- **JS CVE detection:** semver real contra DB de jQuery, Bootstrap, AngularJS, Lodash, Moment, Handlebars, Underscore, Axios, Vue.
- **JWT analysis:** alg:none, secretos débiles (brute force offline).

### 1.4 Escaneo activo
- **SQL Injection (error-based)** con baseline hash MD5.
- **Blind SQLi (time-based)** mediana de 3 samples + margen + confirmación con sleep(0).
- **XSS reflejado** verificando que el payload aparece sin html.escape.
- **Path Traversal** con baseline + indicador secundario (`daemon:x:`) para descartar tutoriales Linux.
- **SSRF** con OOB (interactsh) confirmado vía callback, o indicadores de metadata cloud.
- **SSTI** con canary check + baseline + confirmación doble (`{{7*7}}=49` AND `{{7*8}}=56`).
- **JSON injection** en bodies de APIs REST.
- **Forms scanning** con detección de CSRF tokens.
- **GraphQL** introspección, batching abuse.
- **XXE** con OOB y file:// payloads.

### 1.5 Vulnerabilidades avanzadas v6.0
- **Host Header Injection** — 6 técnicas, detección en links (password reset poisoning).
- **Cache Poisoning** — estilo PortSwigger: detecta cacheabilidad, prueba unkeyed headers, confirma persistencia con refetch.
- **CRLF Injection** — 3 técnicas (URL-encoded, LF-only, UTF-8 overlong).
- **NoSQL Injection** — operadores MongoDB (`$ne`, `$gt`, `$regex`, `$exists`) en endpoints login/API.
- **Prototype Pollution** — server-side (Node.js `__proto__`) y client-side (heurística).
- **HTTP Request Smuggling** — CL.TE / TE.CL por timing differential (mediana + margen).

### 1.6 Vulnerabilidades nuevas v7.0
- **Race Condition / TOCTOU** — 20 requests paralelas vs secuenciales; reporta si paralelo > secuencial × 2 (double-spend, vote/like inflation).
- **GraphQL avanzado** — `__schema` introspection, alias smuggling (10 aliases), depth attack (50 niveles), field suggestions, CSRF en mutations.
- **OAuth2 / OIDC misconfiguration** — implicit flow, PKCE missing, redirect_uri bypass (`https://VICTIM@evil.com`).
- **Open Redirect avanzado** — 11 variantes: `data:`, `javascript:`, `vbscript:`, `//evil.com`, userinfo trick, fragment+userinfo, backslash, whitespace, IDN/punycode.
- **File Upload Bypass** — `.php.jpg` doble extensión, case bypass (`.pHp`), `.phtml`, SVG con `<script>`, path traversal en filename, `.jpg.html`.
- **CSV/XLSX Injection** — `=HYPERLINK(...)`, `=1+1`, `@SUM()`, `+CMD()`; verifica que el payload aparece sin escape en `/export.csv`.
- **Email Header Injection** — CRLF en email/name/subject de `/contact`; compara baseline vs injected.
- **LDAP Injection** — error-based (`LDAPException`, `javax.naming.NamingException`) + boolean blind.
- **XPath Injection** — error-based (`XPathException`, `net.sf.saxon`, `libxml2`).
- **CSP Bypass auto-detection** — CDNs bypasseables (AngularJS sandbox vía `ajax.googleapis.com`), missing base-uri, missing form-action, object-src laxo, unsafe-eval sin strict-dynamic.
- **IDOR auto-discovery** — regex de URLs con IDs (`/api/user/123`), probe id-1/id+1/id+100, busca PII patterns (email/phone/SSN/credit_card).
- **Rate Limiting** — 30 logins paralelos; reporta si zero 429/423/403.
- **2FA Bypass** — 50 OTPs paralelos a `/api/2fa/verify`.
- **WebSocket (CSWSH)** — parsea HTML por `new WebSocket()`, conecta con `Origin: evil.attacker-test.com`.

### 1.7 Motor YAML (estilo Nuclei)
- Matchers: `word`, `regex`, `status`, `binary`, `size`.
- Condition `and`/`or`, negative matchers, `matchers-condition` global.
- Extractors regex y kval.
- 8 templates de producción incluidos.

### 1.8 IA integrada (3 llamadas totales)
1. **Mass triage:** todas las vulns en una sola llamada con reglas estrictas anti-FP.
2. **Intelligence synthesis:** resumen ejecutivo, attack chains, tests avanzados, quick wins.
3. **Deep dive:** PoC curl, exploit steps, CVSS vector real, report title profesional, remediation code.

Soporta OpenAI, Anthropic, Google Gemini, Mistral, Groq, Ollama local, OpenRouter.

### 1.9 Reportes
- **HTML interactivo** con bounty estimates y attack chains.
- **PDF ejecutivo** (reportlab).
- **JSON** estructurado.
- **Markdown HackerOne** (submission-ready).
- **Markdown Bugcrowd** (combinado).
- **Markdown Intigriti** (v7.0).
- **Markdown YesWeHack** (v7.0).
- **SARIF 2.1.0** (GitHub Code Scanning, Azure DevOps, GitLab).
- **Terminal render con Rich** — tablas y paneles para preview pre-export.

---

## 2. Anti-falsos-positivos

| Mecanismo | Módulos donde aplica |
|---|---|
| Baseline hash MD5 con valor benigno | SQLi, SSTI, Path Traversal, NoSQL |
| Canary check (valor único confirma efecto) | SSTI |
| Confirmación doble matemática (`7*7=49` AND `7*8=56`) | SSTI |
| Mediana de N samples + margen estadístico | Blind SQLi, smuggling |
| Confirmación con payload neutro (sleep=0) | Blind SQLi |
| Indicador secundario estructural | Path Traversal (`daemon:x:`), passwd validator |
| Content validators por tipo de archivo | Sensitive paths (.env, .git/config, wp-config...) |
| Semver real (no regex) | JS CVE database |
| Context-aware (HTML vs API JSON) | Security headers |
| Doble confirmación con 2 orígenes aleatorios | CORS reflection |
| OOB callback confirmado | SSRF |
| Token aleatorio único por test | Host Header, Cache Poisoning, CRLF |
| Refetch limpio (cache persistence) | Cache Poisoning |
| Baseline secuencial vs paralelo (ratio > 2x) | Race Condition |
| PII pattern + status 200 obligatorio | IDOR |
| Exact payload search sin escape preceding | CSV Injection |
| Baseline vs injected diff comparison | Email Header Injection |

---

## 3. Seguridad operacional

- API key, Bearer token, cookies y Basic password vía `getpass.getpass()` — no quedan en el historial del terminal.
- `.ai_config.json` con `chmod 0600`.
- **v7.0:** **keyring del sistema** (Windows Credential Manager / macOS Keychain / freedesktop secret-service) para secretos at-rest. Fallback JSON con `0600`.
- Clasificación de errores en AI engine: `auth`, `rate_limit`, `billing`, `dns`, `tls`, `timeout` — 401/403 no reintentan.
- Proxies HTTP rotation (round-robin) en `AsyncHTTPClient`.
- Stealth mode: rotación de User-Agent + headers de browser real + delays aleatorios.
- **v7.0:** **Audit log** modo compliance — JSONL en `.vullogs/audit-{date}.jsonl`.
- **v7.0:** **Out-of-scope filtering** automático (`.vulscope.yaml`).
- **v7.0:** **Resume/checkpoint** — `.vulstate/{hash_url}.json`.
- **v7.0:** **Adaptive rate limit** por host — halves on 429/503, grows after 30s clean.
- **v7.0:** **Self-update** check vs GitHub releases.
- **v7.0:** **Tracer JSON verbose** — `.vultrace/{scan_id}.jsonl` para debug de FPs.

---

## 4. Calidad

- **55 tests** (`tests/run_all.py`):
  - CVSS v3.1 (vectors, thresholds, autoderive).
  - Semver parsing y boundary checks.
  - **Property-based tests** (semver + CVSS, seed determinista, 200+ casos aleatorios).
  - Deduplicación.
  - Soft-404 baseline (hash, ratio, title).
  - 14 validadores de contenido.
  - YAML matchers (word, regex, status, negative).
  - **E2E con mocks**: headers, redirects, http_methods, csp_bypass, paths (soft-404 anti-FP).
- **Benchmark de FP rate** runnable contra targets benignos (`tests/fp_benchmark.py`).
- CVSS v3.1 calculado desde vector con pesos oficiales FIRST.org.
- Modelo `Vuln` con `cwe`, `owasp`, `confidence`, `cvss_vector`.

---

## 5. Arquitectura

```
Vul/
├── main.py                  # Entry point + UI interactiva
├── cli.py                   # CLI scriptable (v7.0): scan/recon/yaml/report/diff/verify/bounty
├── scanner.py               # Orquestador async (10+ fases)
├── ai_engine.py             # Pipeline IA 3-llamadas
├── bounty_db.py             # Estimación de recompensas
├── report.py                # HTML/PDF/JSON/Markdown/SARIF (+ Intigriti + YesWeHack v7.0)
├── config.py                # Payloads, DBs, wordlists, signatures
├── modules/
│   ├── recon.py
│   ├── headers.py           # Security headers + CORS + SRI + mixed content
│   ├── ssl_tls.py
│   ├── http_methods.py
│   ├── paths.py             # Sensitive paths + content validators
│   ├── ports.py
│   ├── redirects.py         # v7.0: 11 variantes (data:, javascript:, IDN...)
│   ├── waf.py
│   ├── content.py           # Leakage patterns
│   ├── active.py            # SQLi/XSS/Traversal/SSRF/JSON injection
│   ├── api_discovery.py
│   ├── js_cve.py            # JS libraries vulnerabilities
│   ├── ssti.py
│   ├── admin_panels.py
│   ├── forms.py
│   ├── jwt_scan.py
│   ├── graphql.py
│   ├── xxe.py
│   ├── yaml_engine.py       # Nuclei-style templates
│   ├── host_header.py           # v6.0
│   ├── cache_poisoning.py       # v6.0
│   ├── crlf.py                  # v6.0
│   ├── nosql.py                 # v6.0
│   ├── prototype_pollution.py   # v6.0
│   ├── smuggling.py             # v6.0
│   ├── race_condition.py        # v7.0 NEW
│   ├── graphql_advanced.py      # v7.0 NEW
│   ├── oauth_oidc.py            # v7.0 NEW
│   ├── file_upload.py           # v7.0 NEW
│   ├── csv_injection.py         # v7.0 NEW
│   ├── email_header.py          # v7.0 NEW
│   ├── ldap_injection.py        # v7.0 NEW
│   ├── xpath_injection.py       # v7.0 NEW
│   ├── csp_bypass.py            # v7.0 NEW
│   ├── idor.py                  # v7.0 NEW
│   ├── rate_limit.py            # v7.0 NEW
│   ├── two_fa_bypass.py         # v7.0 NEW
│   └── websocket.py             # v7.0 NEW (CSWSH)
├── utils/
│   ├── auth.py
│   ├── colors.py
│   ├── crawler.py
│   ├── http.py              # Async client + baseline + proxies
│   ├── oob.py               # OOB (interactsh / webhook.site)
│   ├── vuln.py              # Vuln model + CVSS v3.1 calculator
│   ├── state.py             # v7.0: checkpoint/resume
│   ├── audit_log.py         # v7.0: JSONL compliance log
│   ├── adaptive_rate.py     # v7.0: per-host adaptive concurrency
│   ├── scope.py             # v7.0: .vulscope.yaml in/out filter
│   ├── keyring_store.py     # v7.0: OS keyring (fallback 0600)
│   ├── config_file.py       # v7.0: .vulrc.yaml loader
│   ├── verify.py            # v7.0: interactive k/d/e/a/s/q review
│   ├── diff.py              # v7.0: scan-vs-scan diff
│   ├── terminal_render.py   # v7.0: Rich tables/panels
│   ├── bounty_tracker.py    # v7.0: ledger JSON + stats
│   ├── self_update.py       # v7.0: GitHub releases check
│   └── tracer.py            # v7.0: JSONL FP debug trace
├── templates/               # YAML templates (8 production-ready)
└── tests/                   # 55 tests + property-based + E2E mocks + FP benchmark
```

---

## 6. Cambios v6.0 → v7.0

| Capa | v6.0 | v7.0 |
|---|---|---|
| Módulos de detección | 25 | **38** (+13 nuevos) |
| Race / TOCTOU | — | Sequential vs parallel ratio detector |
| GraphQL | Introspection + batching | + alias smuggling, depth attack, suggestions, mutation CSRF |
| OAuth/OIDC | — | implicit, PKCE, redirect_uri bypass |
| Open Redirect | 3 payloads | 11 variantes incl. data:/javascript:/IDN |
| File Upload | — | 6 técnicas de bypass |
| CSV Injection | — | Formula + verificación sin escape |
| Email Header | — | CRLF en email/subject |
| LDAP / XPath | — | Error-based + boolean blind |
| CSP | Headers ausentes | + CDN-bypass auto-detection |
| IDOR | — | Auto-discovery con PII patterns |
| Rate Limit | — | 30 parallel logins check |
| 2FA | — | 50 parallel OTP attempts |
| WebSocket | — | CSWSH via Origin check |
| Resume / checkpoint | — | `.vulstate/{hash}.json` |
| Audit log | — | `.vullogs/audit-{date}.jsonl` |
| Adaptive rate per-host | — | Halves on 429/503, grows on clean |
| Scope filter | — | `.vulscope.yaml` con fnmatch |
| Secrets at-rest | `.ai_config.json` 0600 | + OS keyring (fallback 0600) |
| Config file | — | `.vulrc.yaml` |
| Verify mode | — | k/d/e/a/s/q interactive |
| Diff scan-vs-scan | — | `cli diff old.json new.json` |
| CLI scriptable | Solo wizard | `cli.py scan/recon/yaml/report/diff/verify/bounty` |
| Terminal render | Plain text | Rich tables/panels (opcional) |
| Bounty tracker | — | JSON ledger + stats |
| Self-update | — | GitHub releases check |
| Tracer FP debug | — | `.vultrace/{scan_id}.jsonl` |
| Reportes adicionales | H1 + Bugcrowd + SARIF | + Intigriti + YesWeHack |
| Tests | 39 | 55 (+ property-based + E2E mocks + FP benchmark) |

---

## 7. Mejoras v7.0 → v7.1 (todas implementadas)

### 7.1 Cobertura técnica
- `modules/dom_xss.py` — **DOM XSS via Playwright headless**: location.hash sinks, postMessage handlers sin origin check, canary JS único confirma ejecución real (no FP por mero reflejo).
- `modules/sw_xss.py` — **Service Worker + Manifest + WebRTC**: importScripts() externos, PWA manifest con start_url externo (phishing persistente), STUN/TURN IP leak detection.
- `modules/saml.py` — **SAML XSW awareness**: detección de metadata expuesto, WantAssertionsSigned=false, RSA-SHA1 deprecado, ACS endpoints para auditoría manual.
- `modules/h2_smuggling.py` — **HTTP/2 smuggling**: TE header en H2 stream (prohibido por RFC 7540 §8.1.2.2). Requiere httpx[http2].

### 7.2 IA y triaje
- `utils/embeddings.py` — **Clustering local pre-IA**: sentence-transformers → TF-IDF → hash bucket fallback. Reduce tokens enviados a la IA 3-4×.
- `utils/feedback_loop.py` — **FP/válido learning**: `mark_fp(vuln)` / `mark_valid(vuln)` guardan firmas en `~/.vul/feedback.json`. `filter_known_fps()` descarta patrones FP repetidos automáticamente.
- `utils/program_prompts.py` — **Prompts y formatos específicos por programa**: H1 (CVSS strict), Bugcrowd VRT (P1-P5 mapping), Intigriti (business impact), YesWeHack (RCE priority).
- `report.generate_markdown_h1_all()` — Un MD H1 independiente por cada CRITICAL/HIGH (no solo el primero), filenames `01-CRITICAL-titulo.md`.

### 7.3 Operacional
- `utils/distributed.py` — **Master/Worker Redis queue**: `python -m utils.distributed master --targets list.txt` divide en workers que consumen `vul:queue` y publican en `vul:results:{scan_id}`.
- `utils/api_server.py` — **FastAPI HTTP server**: POST /scan, GET /scan/{id}, GET /scans, GET /healthz. Auth Bearer via `VUL_API_TOKEN`.
- `.github/workflows/security-scan.yml` — **GitHub Action** con SARIF upload directo a Code Scanning.
- `.gitlab-ci.yml` — **GitLab CI** con artifact SAST report.
- `utils/ws_fuzzer.py` — **WebSocket continuous fuzzing**: mutations JSON post-handshake (type confusion, overflow, prototype pollution), detección de stack traces leak.

### 7.4 Reportes y entrega
- `utils/submission.py` — **Auto-submission** a HackerOne (`POST /v1/reports`), Intigriti (`POST /external/researcher/v2/submissions`). Dry-run por default. Bugcrowd: nota explicativa (no public API).
- `utils/video_poc.py` — **Playwright video PoC**: `record_poc(steps, out=poc.webm)` graba steps JSON-driven (goto/fill/click/wait/screenshot).
- **Cobertura de módulos en reportes** — `meta["modules_run"]` (nombre, hallazgos, estado) + `meta["scan_flags"]` se reflejan en HTML (tabla interactiva), PDF (tabla), JSON (dentro de `meta`), y todos los Markdown (H1/Bugcrowd/Intigriti/YesWeHack). Muestra qué módulos corrieron aunque no encontraran nada — diferencia entre "OK" y "no ejecutado".

### 7.5 UX
- `utils/tui.py` — **Textual dashboard**: panel live de phase, vulns por severidad, requests/seg, 429 seen. Fallback plain print() si Textual no está.
- `utils/config_file.get_module_concurrency()` — **Concurrencia por módulo** vía `.vulrc.yaml: module_concurrency: { paths: 30, ports: 50 }`.

### 7.7 Vulnerabilidades de alto valor (v7.3)
- **JWT Algorithm Confusion (RS256→HS256)** — `modules/jwt_scan.py`: fetch automático de JWKS, conversión JWK→PEM manual (sin deps), forjado de token HS256 con clave pública como secreto HMAC, confirmado probando endpoints `/api/me`, `/api/user`, etc. CRITICAL solo si el servidor acepta el token forjado (anti-FP por status comparison).
- **JWT kid SQL/Path Traversal injection** — kid inyectado con `' UNION SELECT 'x'--` y `../../dev/null`, firma con secreto vacío, confirmado si el servidor devuelve 200.
- **JWT jku/x5u header injection** — detecta campos de URL de JWKS externo en el header (vector de robo de firma).
- **SSRF Cloud Metadata completo** — `modules/active.py`: 17 payloads cloud (AWS IMDS v1/v2, GCP Service Account token, Azure MSI/IMDS, DigitalOcean, OCI, K8s API, ECS Task). 10 bypass de filtros IP (decimal `2852039166`, hex `0xa9fea9fe`, octal `0251.0376`, IPv6 mapped `[::ffff:...]`, DNS rebinding via nip.io/xip.io). Indicadores críticos (credenciales IAM, OAuth tokens) → CRITICAL 10.0; indicadores generales → HIGH 8.6.
- **SPA Crawler Playwright** — `utils/crawler.py`: `crawl_spa()` headless Chromium captura peticiones de red en runtime (XHR/fetch que el HTTP crawler no ve), navega rutas SPA vía click en nav links, extrae data-href/RouterLink/ng-href. Wired en `scanner.py` como crawler complementario en `full_scan`. Fallback silencioso si Playwright no instalado.

### 7.8 Testing & quality
- `tests/test_hypothesis.py` — **Hypothesis property-based** para semver parser y CVSS vector (skip si hypothesis no instalado).
- `tests/test_integration_dvwa.py` — **DVWA / Juice Shop containerizados** (skip si los targets no responden).
- `tests/mutmut_config.py` — **Mutation testing** config: PRIORITY_PATHS (vuln.py, js_cve.py, paths.py, http.py, active.py), EXCLUDED_PATHS (tests, templates, ai_engine).

---

## 8. Web UI — reescritura completa (v7.3 · Junio 2026)

> Contexto: la primera versión de `utils/api_server.py` tenía la Web UI parcialmente conectada
> (faltaban ~12 features, el log sink roto y el Stop sin efecto real). Se hizo reescritura total.

### 8.1 Bugs corregidos

| Bug | Causa | Fix |
|---|---|---|
| SSE no era real-time (solo polling por timeout) | `set_log_sink(log.lines)` — monkey-patch de `list.append` es imposible en CPython | Pasar el objeto `_ScanLog` directamente: `set_log_sink(log)`. `_ScanLog.append()` notifica waiters async correctamente. |
| Stop no cancelaba el scan en el servidor | Solo cerraba el EventSource del cliente | `_SCAN_TASKS: dict[str, asyncio.Task]` + `task.cancel()` en `POST /scan/{id}/stop` |
| `'coroutine' object is not subscriptable` en `/test-ai` | `await r.text()[:200]` — Python parsea como `await (r.text()[:200])`, slicing sobre coroutine | Corregido a `(await r.text())[:200]` |

### 8.2 Endpoints nuevos

| Endpoint | Función |
|---|---|
| `POST /scan/{id}/stop` | Cancela el `asyncio.Task` del scan en curso (`task.cancel()`) |
| `POST /test-connection` | Prueba alcanzabilidad del target → `{ok, status, server}` |
| `POST /test-ai` | Valida config IA (OpenAI/Anthropic/Ollama/…) → `{ok, message}` |
| `POST /configure-ai` | Guarda config vía `save_ai_config()` antes de lanzar el scan |
| `POST /feedback` | Llama `mark_fp()` / `mark_valid()` del `feedback_loop` |
| `GET /healthz` | Health check `{ok, version}` |

### 8.3 ScanRequest — parámetros añadidos

Todos se pasan directamente a `scanner.scan()`:

```python
oob:         bool  = False   # → use_oob=
tracer:      bool  = False   # → tracer_id= (hex UUID)
proxy:       str   = ""      # → proxies=[proxy]
scope_file:  str   = ""      # → scope_file=
auth_bearer: str   = ""      # → auth_config["bearer"]
auth_cookie: str   = ""      # → auth_config["cookie"]
```

### 8.4 Web UI — features completos

| Feature | Implementado |
|---|---|
| Target URL + botón Test Connection ⚡ (status + Server header) | ✅ |
| 8 toggles: full / active / ports / stealth / adaptive / audit / **oob** / **tracer** | ✅ |
| Selector de plataforma (Generic / HackerOne / Bugcrowd / Intigriti / YesWeHack) | ✅ |
| Proxy, scope file, auth Bearer y Cookie del target (panel "Avanzado" colapsable) | ✅ |
| Config IA: provider / model / API key / base URL + botón "Probar conexión IA" | ✅ |
| Server API Token (Bearer) para autenticar contra el servidor | ✅ |
| Botón Start — deshabilita durante scan | ✅ |
| Botón Stop — cancela el asyncio.Task real en el servidor | ✅ |
| **Barra de progreso por fase** — parsea líneas `▶ ` del SSE, anima width CSS | ✅ |
| Console SSE real-time con auto-scroll y strip de ANSI | ✅ |
| **Executive summary de IA** mostrado en console al finalizar | ✅ |
| Tarjetas de vuln: severity, CVSS, **bounty range** (`$min–$max`), colapsables | ✅ |
| AI business impact + PoC curl por vuln (si IA activa) | ✅ |
| **Filtro por severidad** (chips CRITICAL/HIGH/MEDIUM/LOW/INFO) | ✅ |
| **Búsqueda de texto** en título / categoría / descripción | ✅ |
| **Feedback por vuln**: 👎 Falso positivo / 👍 Confirmado / 📋 Copiar PoC | ✅ |
| Tab Coverage — tabla módulo/hallazgos/estado + flag chips de `scan_flags` | ✅ |
| Tab Reports — grid de 8 formatos descargables (HTML/JSON/H1/Bugcrowd/Intigriti/YWH/SARIF/PDF) | ✅ |
| **Tab Historial** — lista de scans previos clicables, muestra risk y timestamp | ✅ |
| Badge de riesgo global + contadores C/H/M/L/I + duración + risk score | ✅ |
| Orden de vulns por severidad → CVSS desc | ✅ |
| Replay de log desde offset (SSE con posición acumulada) | ✅ |

### 8.5 Arquitectura del log sink (corregida)

```
scanner.py → print_section / print_ok / … 
   └─ colors.py: _emit(text)
        └─ _log_sink.append(text)          # _log_sink = _ScanLog instance
              └─ _ScanLog.append()
                   ├─ self.lines.append(line)   # buffer de replay
                   └─ fut.set_result(None)       # notifica waiters SSE ← REAL-TIME
                         └─ SSE gen() sale de wait_new() inmediatamente
                              └─ yield f"data: {line}\n\n" al browser
```

---

## 9. Solo uso ético

Esta herramienta es para:
- Sistemas propios.
- Programas de bug bounty con scope definido y autorización explícita.
- Engagements de pentest contratados.
- CTFs y entornos de laboratorio.

Usar contra sistemas sin autorización es ilegal en la mayoría de jurisdicciones.

---

### 8.6 Streaming progresivo de vulns (SSE multi-event)

El flujo de datos entre backend y Web UI usa **3 tipos de SSE events**:

| Event | Contenido | Cuándo |
|---|---|---|
| `message` (default) | Línea de log de progreso | Durante el scan en tiempo real |
| `event: vuln` | JSON de una vulnerabilidad (con AI analysis) | Al final, una por una (CRITICAL primero) |
| `event: done` | Resumen: risk, score, duración, exec_summary, meta | Tras todos los `vuln` events |

La UI acumula los vulns recibidos, actualiza el badge en tiempo real con el nombre del último hallazgo, y al recibir `done` ordena y renderiza las tarjetas con filtros aplicados.

### 8.7 Bugs corregidos (sesión actual)

| Bug | Fix |
|---|---|
| `AIEngine()` sin args → TypeError silenciosa | Carga config con `load_ai_config()`, pasa `api_key/base_url/model` correctamente |
| Keys del resultado `"executive_summary"` / `"vuln_analyses"` inexistentes | Cambiado a `"exec_summary"` / merge de `triage` + `deep_dive` por `dedup_key` |
| Modelo `"openai/gpt-oss-120b"` inválido en Groq | Cambiado a `"llama-3.3-70b-versatile"` |
| `base_url=""` con provider Groq → llamadas a OpenAI | Resolución automática: Groq→`api.groq.com/openai`, Mistral→`api.mistral.ai`, etc. |
| `/configure-ai` con `data: dict` frágil en FastAPI | Cambiado a `request: Request` + `await request.json()` |
| `__DONE__` con JSON de ~MB de vulns en un solo evento | Separado en N eventos `__VULN__` + `__DONE__` solo con resumen |
| Vulns tab vacía (badge 57, cards invisibles) | Newlines en `evidence` rompían innerHTML; fix: `data-idx` + delegación de eventos |
| `sevFilter` persistía entre scans | `resetUI()` ahora resetea `sevFilter='ALL'` y limpia chips |

---

## 9. Solo uso ético

Esta herramienta es para:
- Sistemas propios.
- Programas de bug bounty con scope definido y autorización explícita.
- Engagements de pentest contratados.
- CTFs y entornos de laboratorio.

Usar contra sistemas sin autorización es ilegal en la mayoría de jurisdicciones.

---

*Versión 7.3 — Junio 2026.*
*59 tests passing + property-based + Hypothesis (opt) + E2E mocks + integration (opt) + FP benchmark.*
*46 módulos de detección (38 v7.0 + dom_xss + saml + sw_xss + h2_smuggling + mass_assignment + http_param_pollution + business_logic + graphql_idor).*
*31 utils (+ api_server reescritura completa con streaming progresivo de vulns).*
*CI workflows: GitHub Action + GitLab CI.*
*Web UI v7.3 final: streaming SSE progresivo (vuln por vuln), IA activa (Groq llama-3.3-70b), carga dinámica con spinner, todas las opciones del terminal conectadas (OOB/tracer/proxy/scope/auth/stealth/adaptive). Terminal + Web UI + API totalmente funcionales y conectados.*
