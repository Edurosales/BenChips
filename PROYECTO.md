# BugBountyHunter Pro v6.0 — Resumen del proyecto

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

### 1.5 Vulnerabilidades avanzadas (módulos nuevos v6.0)
- **Host Header Injection** — 6 técnicas, detección en links (password reset poisoning).
- **Cache Poisoning** — estilo PortSwigger: detecta cacheabilidad, prueba unkeyed headers, confirma persistencia con refetch.
- **CRLF Injection** — 3 técniques (URL-encoded, LF-only, UTF-8 overlong).
- **NoSQL Injection** — operadores MongoDB (`$ne`, `$gt`, `$regex`, `$exists`) en endpoints login/API.
- **Prototype Pollution** — server-side (Node.js `__proto__`) y client-side (heurística).
- **HTTP Request Smuggling** — CL.TE / TE.CL por timing differential (mediana + margen).

### 1.6 Motor YAML (estilo Nuclei)
- Matchers: `word`, `regex`, `status`, `binary`, `size`.
- Condition `and`/`or`, negative matchers, `matchers-condition` global.
- Extractors regex y kval.
- 8 templates de producción incluidos.

### 1.7 IA integrada (3 llamadas totales)
1. **Mass triage:** todas las vulns en una sola llamada con reglas estrictas anti-FP.
2. **Intelligence synthesis:** resumen ejecutivo, attack chains, tests avanzados, quick wins.
3. **Deep dive:** PoC curl, exploit steps, CVSS vector real, report title profesional, remediation code.

Soporta OpenAI, Anthropic, Google Gemini, Mistral, Groq, Ollama local, OpenRouter.

### 1.8 Reportes
- **HTML interactivo** con bounty estimates y attack chains.
- **PDF ejecutivo** (reportlab).
- **JSON** estructurado.
- **Markdown HackerOne** (submission-ready).
- **Markdown Bugcrowd** (combinado).
- **SARIF 2.1.0** (GitHub Code Scanning, Azure DevOps, GitLab).

---

## 2. Anti-falsos-positivos

Mecanismos de control:

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

---

## 3. Seguridad operacional

- API key, Bearer token, cookies y Basic password vía `getpass.getpass()` — no quedan en el historial del terminal.
- `.ai_config.json` con `chmod 0600`.
- Clasificación de errores en AI engine: `auth`, `rate_limit`, `billing`, `dns`, `tls`, `timeout` — 401/403 no reintentan.
- Proxies HTTP rotation (round-robin) en `AsyncHTTPClient`.
- Stealth mode: rotación de User-Agent + headers de browser real + delays aleatorios.

---

## 4. Calidad

- **39 tests unitarios** (`tests/run_all.py`):
  - CVSS v3.1 (vectors, thresholds, autoderive).
  - Semver parsing y boundary checks.
  - Deduplicación.
  - Soft-404 baseline (hash, ratio, title).
  - 14 validadores de contenido.
  - YAML matchers (word, regex, status, negative).
- CVSS v3.1 calculado desde vector con pesos oficiales FIRST.org.
- Modelo `Vuln` con `cwe`, `owasp`, `confidence`, `cvss_vector`.

---

## 5. Arquitectura

```
Vul/
├── main.py              # Entry point + UI interactiva
├── scanner.py           # Orquestador async (10 fases)
├── ai_engine.py         # Pipeline IA 3-llamadas
├── bounty_db.py         # Estimación de recompensas
├── report.py            # HTML/PDF/JSON/Markdown/SARIF
├── config.py            # Payloads, DBs, wordlists, signatures
├── modules/
│   ├── recon.py
│   ├── headers.py       # Security headers + CORS + SRI + mixed content
│   ├── ssl_tls.py
│   ├── http_methods.py
│   ├── paths.py         # Sensitive paths + content validators
│   ├── ports.py
│   ├── redirects.py
│   ├── waf.py
│   ├── content.py       # Leakage patterns
│   ├── active.py        # SQLi/XSS/Traversal/SSRF/JSON injection
│   ├── api_discovery.py
│   ├── js_cve.py        # JS libraries vulnerabilities
│   ├── ssti.py
│   ├── admin_panels.py
│   ├── forms.py
│   ├── jwt_scan.py
│   ├── graphql.py
│   ├── xxe.py
│   ├── yaml_engine.py   # Nuclei-style templates
│   ├── host_header.py       # NEW v6.0
│   ├── cache_poisoning.py   # NEW v6.0
│   ├── crlf.py              # NEW v6.0
│   ├── nosql.py             # NEW v6.0
│   ├── prototype_pollution.py # NEW v6.0
│   └── smuggling.py         # NEW v6.0
├── utils/
│   ├── auth.py
│   ├── colors.py
│   ├── crawler.py
│   ├── http.py          # Async client + baseline + proxies
│   ├── oob.py           # OOB (interactsh / webhook.site)
│   └── vuln.py          # Vuln model + CVSS v3.1 calculator
├── templates/           # YAML templates (8 production-ready)
└── tests/               # 39 unit tests
```

---

## 6. Cambios v5.0 → v6.0

| Capa | v5.0 | v6.0 |
|---|---|---|
| Path Traversal | Sin baseline | Baseline + indicador secundario |
| Sensitive paths | Solo status 200 | 29 validadores de contenido por tipo |
| JS CVE DB | Regex frágil sobre strings | Semver tupla + `max_fixed` exclusivo |
| CSP | unsafe-inline siempre HIGH | Context-aware (nonce/strict-dynamic) |
| CORS | 1 origen | 2 orígenes aleatorios, dobles |
| CVSS | Score hardcoded | Vector → score real FIRST.org |
| Credentials UX | `input()` plano | `getpass.getpass()` |
| AI errors | `traceback.print_exc()` | 6 clases de error sin ruido |
| Reportes | HTML/JSON/PDF | + Markdown H1 + Markdown Bugcrowd + SARIF |
| Nuevos módulos | — | host_header, cache_poisoning, crlf, nosql, prototype_pollution, smuggling |
| YAML engine | 1 template, matchers básicos | 8 templates, extractors, AND/OR, negative |
| Proxy support | No | Round-robin con lista CSV |
| Tests | 0 | 39 unitarios passing |

---

## 7. Mejoras futuras (roadmap)

### 7.1 Cobertura técnica (prioridad alta)
- **Headless browser para DOM XSS** (Playwright async). Necesario para SPAs reales — sin esto, XSS basado en `document.location.hash`, `postMessage`, sinks de DOM clobbering, queda sin cubrir.
- **WebSocket security testing**: cross-site WebSocket hijacking (CSWSH), falta de origin check.
- **WebRTC + Service Worker analysis**: SW XSS via cache, manifest injection.
- **Race condition / TOCTOU testing**: enviar N peticiones paralelas a endpoints de cambio de estado (coupon redemption, fund transfer).
- **GraphQL avanzado**: alias query smuggling, query depth/complexity DoS, batch resolver abuse, introspection on-disable check.
- **OAuth2 / OIDC misconfiguration**: redirect_uri whitelist bypass, state/nonce missing, PKCE downgrade.
- **SAML auth bypass**: XML signature wrapping, comment injection in NameID.

### 7.2 IA y triaje (prioridad media)
- **Local embedding model** para clusterizar hallazgos similares antes de mandar a la IA (reduce tokens 3-4x).
- **Fine-tuning de prompts por programa**: H1, Bugcrowd, Intigriti tienen criterios distintos (P1/P2 vs CVSS).
- **Feedback loop**: el usuario marca un hallazgo como FP/válido y el sistema aprende qué patrones característicos descartar.
- **Generación automática de reportes** completos (no solo el primer crítico) en formato Markdown H1.

### 7.3 Operacional (prioridad media)
- **Resume/checkpoint**: si el scan se interrumpe, retomar desde la última fase completada (escribir estado JSON cada N seg).
- **Distributed mode**: dividir el target en chunks y correr en N workers (Redis queue).
- **Rate limit adaptativo por host**: detectar 429 y reducir concurrencia automáticamente.
- **Diff mode**: comparar scan actual vs scan anterior del mismo target → solo nuevos hallazgos.
- **CI integration**: GitHub Action / GitLab CI con SARIF upload directo a Security tab.
- **API mode**: exponer scanner como servicio HTTP + queue (FastAPI + Celery).

### 7.4 Reportes y entrega
- **Plantillas por programa**: estructuras específicas para H1, Bugcrowd, Intigriti, YesWeHack.
- **Auto-submission**: subir el hallazgo a la plataforma vía API una vez validado por el usuario.
- **Video PoC**: integrar Playwright para grabar GIF/MP4 reproduciendo el exploit.
- **Markdown rendering en terminal** (rich) para previsualizar el reporte antes de exportar.
- **Bounty tracking dashboard**: registrar hallazgos enviados, pagos, follow-ups.

### 7.5 Seguridad operacional
- **Cifrado at-rest** de `.ai_config.json` con keyring del sistema (Windows Credential Manager / macOS Keychain).
- **Audit log** de cada request enviado (modo compliance).
- **Out-of-scope filtering**: leer `program scope` desde la plataforma y bloquear requests automáticamente a subdominios excluidos.
- **Self-update**: chequear releases nuevas en GitHub y aplicar parches.

### 7.6 Cobertura de vulnerabilidades adicionales
- **File upload bypass**: magic byte spoofing, extension blacklist bypass, polyglot files.
- **Mass assignment / IDOR auto-discovery**: enumerar IDs secuenciales y comparar respuestas.
- **Rate limiting check**: medir cuántas requests acepta el endpoint /login antes de bloquear.
- **2FA bypass patterns**: respuesta cacheada del flujo OTP, reenvío con código viejo.
- **Open redirect avanzado**: data:, javascript:, IDN/punycode bypass, `//evil.com`, `@evil.com`.
- **CSV/XLSX injection** en exports.
- **Email header injection** en formularios de contacto.
- **LDAP injection** en endpoints de búsqueda de usuarios.
- **XPath injection** en APIs que filtran XML.
- **CSP bypass via JSONP / Angular template / Flash**: detección automática.

### 7.7 UX & Developer experience
- **Modo "verify"**: pausa después del scan, muestra cada hallazgo y pregunta SUBMIT / SKIP / EDIT antes de generar reportes.
- **CLI con subcomandos** (`vul recon`, `vul active`, `vul yaml`, `vul report`) para uso scriptable sin el wizard interactivo.
- **Config file** (`.vulrc.yaml`) para guardar opciones por proyecto.
- **Concurrencia configurable** por módulo (no solo global).
- **Modo verbose con tracing JSON** para debug de FPs sospechosos.

### 7.8 Testing & quality
- Subir cobertura a 80%+ con tests de integración (fixtures de respuestas HTTP mockeadas).
- **Tests E2E con HTTPbin / DVWA** containerizado para validar contra app vulnerable conocida.
- **Property-based testing** (Hypothesis) para los parsers de semver, CVSS y YAML.
- **Benchmark de FP rate** contra suite de targets benignos (HackerOne homepage, GitHub, etc).

---

## 8. Solo uso ético

Esta herramienta es para:
- Sistemas propios.
- Programas de bug bounty con scope definido y autorización explícita.
- Engagements de pentest contratados.
- CTFs y entornos de laboratorio.

Usar contra sistemas sin autorización es ilegal en la mayoría de jurisdicciones.

---

*Versión 6.0 — Junio 2026.*
*39 tests passing.*
*Más de 25 módulos de detección.*
