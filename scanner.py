"""
scanner.py — Orquestador principal async del VulnScanner Pro.
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional
from urllib.parse import urlparse

import aiohttp

from utils.http import AsyncHTTPClient, create_session
from utils.vuln import deduplicate, Vuln
from utils.colors import (
    print_section, print_ok, print_warn, print_err, print_info,
    print_vuln, progress_bar, print_sep, sev_color, W, BOLD, C, G, O, DIM, spinner_async
)

from modules import (
    recon, headers, ssl_tls, http_methods, paths, ports, redirects, waf, content,
    active, api_discovery, js_cve, ssti, admin_panels, forms, jwt_scan, graphql,
    xxe, yaml_engine,
    host_header, cache_poisoning, crlf, nosql, prototype_pollution, smuggling,
    # v7.0 — nuevos módulos
    race_condition, graphql_advanced, oauth_oidc, file_upload, csv_injection,
    email_header, ldap_injection, xpath_injection, csp_bypass, idor,
    rate_limit, two_fa_bypass, websocket,
    # v7.1 — extras (Playwright/HTTP2/SAML/SW)
    dom_xss, saml, sw_xss, h2_smuggling,
    # v7.3 — nuevos módulos de alto valor
    mass_assignment, http_param_pollution, business_logic, graphql_idor,
)


async def scan(
    url:         str,
    full_scan:   bool = False,
    scan_ports:  bool = True,
    active_scan: bool = False,
    no_color:    bool = False,
    stealth:     bool = False,
    auth_config  = None,      # utils.auth.AuthConfig | None
    use_oob:     bool = True, # intentar OOB con interactsh
    proxies:     list[str] | None = None,
    # v7.1 — pluggables opcionales
    scope_file:    str | None = None,   # .vulscope.yaml
    audit_enabled: bool = False,        # JSONL audit log
    tracer_id:     str | None = None,   # verbose FP trace
    adaptive:      bool = False,        # per-host adaptive rate
) -> tuple[list[Vuln], dict, float]:
    """
    Ejecuta el escaneo completo de forma async.
    Retorna (vulns_deduplicadas, meta_dict, duration_seconds).
    """
    t0 = time.monotonic()

    parsed   = urlparse(url)
    hostname = parsed.hostname or url
    scheme   = parsed.scheme or "https"

    meta: dict = {
        "hostname":     hostname,
        "ips":          [],
        "ipv6":         [],
        "ptr":          None,
        "asn":          None,
        "subdomains":   [],
        "technologies": [],
        "waf":          None,
        "real_ip_hints": [],
        "ssl":          {},
        "ports":        [],
        "paths":        [],
        "api_endpoints":[],
        "crawled_urls": [],    # URLs descubiertas por el crawler
        "server":       "",    # Server header
        "powered_by":   "",    # X-Powered-By header
        "auth":         bool(auth_config),  # si se usó autenticación
        # v7.2: trazabilidad de cobertura
        "modules_run":     [],   # lista de [{name, findings, status}]
        "modules_skipped": [],   # lista de [name] no ejecutados (opt deps faltantes)
        "scan_flags": {
            "full":      full_scan,
            "active":    active_scan,
            "ports":     scan_ports,
            "stealth":   stealth,
            "oob":       use_oob,
            "proxies":   bool(proxies),
            "adaptive":  adaptive,
            "audit":     audit_enabled,
            "tracer":    bool(tracer_id),
            "scope":     bool(scope_file),
        },
    }

    def _track(name: str, vulns_added: list, status: str = "ok"):
        meta["modules_run"].append({
            "name":     name,
            "findings": len(vulns_added),
            "status":   status,
        })

    all_vulns: list[Vuln] = []

    connector = aiohttp.TCPConnector(
        limit=100, limit_per_host=30,
        ssl=False, enable_cleanup_closed=True
    )
    session = aiohttp.ClientSession(connector=connector)
    try:
        auth_headers = auth_config.to_headers() if auth_config else {}
        client = AsyncHTTPClient(
            session, rate_limit=20, timeout=10,
            stealth=stealth, auth_headers=auth_headers,
            proxies=proxies,
        )

        # ── v7.1: pluggables opcionales ─────────────────────────────────────
        if scope_file:
            try:
                from utils.scope import ScopeFilter
                client.scope_filter = ScopeFilter.from_file(scope_file)
                print_ok(f"Scope filter cargado: {scope_file}")
            except Exception as e:
                print_warn(f"No se pudo cargar scope file: {e}")

        if adaptive:
            try:
                from utils.adaptive_rate import AdaptiveRateLimiter
                client.adaptive_rate = AdaptiveRateLimiter()
                print_ok("Adaptive rate limit per-host activo")
            except Exception:
                pass

        if audit_enabled:
            try:
                from utils import audit_log
                audit_log.enable(True)
                print_ok("Audit log activo (.vullogs/)")
            except Exception:
                pass

        if tracer_id:
            try:
                from utils import tracer
                tracer.enable(tracer_id)
                print_ok(f"Tracer activo: .vultrace/{tracer_id}.jsonl")
            except Exception:
                pass

        # ── OOB client (interactsh) ───────────────────────────────────────────
        oob_client = None
        if use_oob and active_scan:
            from utils.oob import OOBClient
            oob_client = OOBClient()
            registered, oob_error = await oob_client.register(session)
            if registered:
                print_ok(f"OOB activo: {oob_client.correlation_id[:8]}...@{oob_client.server} (SSRF ciego confirmable)")
            else:
                print_info(f"OOB desactivado: {oob_error}")
                print_info("  SSRF se detectará por indicadores en respuesta (sin callback)")
                oob_client = None

        # ── 1. WAF Detection ──────────────────────────────────────────────────
        print_section("1/9", "WAF / CDN Detection")
        async with spinner_async("Detectando WAF"):
            waf_vulns, waf_info = await waf.run(client, url, hostname)
        all_vulns.extend(waf_vulns); _track("waf", waf_vulns)
        meta["waf"]           = waf_info.get("waf")
        meta["real_ip_hints"] = waf_info.get("real_ip_hints", [])
        if meta["waf"]:
            print_ok(f"WAF detectado: {meta['waf']}")
        else:
            print_warn("Sin WAF detectado — servidor expuesto directamente")

        # ── 2. Recon ──────────────────────────────────────────────────────────
        print_section("2/9", "Reconocimiento DNS / Subdominios")
        async with spinner_async("Reconocimiento en progreso"):
            recon_vulns, recon_info = await recon.run(client, url, hostname, full_scan=full_scan)
        all_vulns.extend(recon_vulns); _track("recon", recon_vulns)
        meta["ips"]          = recon_info.get("ips", [])
        meta["ipv6"]         = recon_info.get("ipv6", [])
        meta["ptr"]          = recon_info.get("ptr")
        meta["asn"]          = recon_info.get("asn")
        meta["subdomains"]   = recon_info.get("subdomains", [])
        meta["technologies"] = recon_info.get("technologies", [])

        print_ok(f"IPs: {', '.join(meta['ips']) or 'N/A'}")
        if meta["technologies"]:
            print_ok(f"Tecnologías: {', '.join(meta['technologies'])}")
        if meta["subdomains"]:
            print_ok(f"Subdominios: {len(meta['subdomains'])} encontrados (crt.sh + HackerTarget + AlienVault + CertSpotter + wordlist)")

        # ── 2.3. Escaneo de subdominios ───────────────────────────────────────
        if full_scan and meta["subdomains"]:
            print_section("Subs", f"Escaneando subdominios ({min(len(meta['subdomains']),12)} de {len(meta['subdomains'])})")
            sub_vulns = await _scan_subdomains(
                client, meta["subdomains"], scheme, max_subs=12
            )
            all_vulns.extend(sub_vulns); _track("subdomains", sub_vulns)
            if sub_vulns:
                print_warn(f"{len(sub_vulns)} hallazgos en subdominios")
            else:
                print_ok("Sin hallazgos críticos en subdominios")

        # ── 2.5. Crawler ──────────────────────────────────────────────────────
        crawled_urls: list[str] = []
        print_section("Crawler", "Descubrimiento de endpoints (HTTP + SPA)")
        max_pages = 100 if full_scan else 50
        async with spinner_async(f"Crawleando HTTP (max {max_pages} páginas)"):
            from utils.crawler import crawl, crawl_spa
            crawled_urls = await crawl(client, url, max_pages=max_pages, max_depth=2)

        # SPA crawler Playwright — complementario al HTTP
        spa_urls: list[str] = []
        if full_scan:
            async with spinner_async("SPA crawler Playwright (opcional)"):
                try:
                    spa_urls = await crawl_spa(
                        url,
                        max_pages  = 20,
                        timeout_ms = 12_000,
                        stealth    = stealth,
                    )
                except Exception:
                    spa_urls = []
            # Fusionar sin duplicados
            existing_norm = {u.rstrip("/") for u in crawled_urls}
            for su in spa_urls:
                if su.rstrip("/") not in existing_norm:
                    crawled_urls.append(su)
                    existing_norm.add(su.rstrip("/"))

        meta["crawled_urls"] = crawled_urls
        meta["spa_urls"]     = spa_urls
        n_crawled = len(crawled_urls)
        n_spa     = len(spa_urls)
        if n_crawled > 1:
            spa_tag = f" | SPA: {n_spa} adicionales" if n_spa else " (SPA: pip install playwright)"
            print_ok(f"{n_crawled} URLs descubiertas{spa_tag}")
        else:
            print_info("Crawler: solo la URL raíz accesible")

        # ── 3. SSL/TLS ────────────────────────────────────────────────────────
        print_section("3/9", "SSL / TLS")
        ssl_port = 443 if ":" not in hostname else int(hostname.split(":")[1])
        async with spinner_async("Analizando certificados"):
            ssl_vulns, ssl_info = await ssl_tls.run(hostname.split(":")[0], port=ssl_port)
        all_vulns.extend(ssl_vulns); _track("ssl_tls", ssl_vulns)
        meta["ssl"] = ssl_info
        if ssl_info:
            print_ok(f"SSL: {ssl_info.get('version','?')} | Cifrado: {ssl_info.get('cipher','?')}")
            print_ok(f"Certificado: {ssl_info.get('subject','?')} | Issuer: {ssl_info.get('issuer','?')}")
            exp = ssl_info.get("not_after", "")
            if exp:
                print_info(f"Expira: {exp}")

        # ── 4. Security Headers ───────────────────────────────────────────────
        print_section("4/9", "Security Headers / CORS / Cookies")
        async with spinner_async("Verificando cabeceras"):
            hdr_vulns, main_resp = await headers.run(client, url)
        all_vulns.extend(hdr_vulns); _track("headers", hdr_vulns)
        n_missing = sum(1 for v in hdr_vulns if "faltante" in v.title.lower())
        # Capturar Server y X-Powered-By del response
        if main_resp:
            meta["server"]     = main_resp.headers.get("server", "")
            meta["powered_by"] = main_resp.headers.get("x-powered-by", "")
        srv_str = meta["server"] or "desconocido"
        pb_str  = f" | X-Powered-By: {meta['powered_by']}" if meta.get("powered_by") else ""
        print_ok(f"Server: {srv_str}{pb_str}")
        print_ok(f"Headers analizados — {n_missing} ausentes" if n_missing == 0
                 else f"{n_missing} security headers faltantes")

        # ── 5. HTTP Methods ───────────────────────────────────────────────────
        print_section("5/9", "HTTP Methods peligrosos")
        async with spinner_async("Comprobando métodos"):
            method_vulns = await http_methods.run(client, url)
        all_vulns.extend(method_vulns); _track("http_methods", method_vulns)
        if method_vulns:
            dangerous = [v.title for v in method_vulns]
            print_warn(f"Métodos detectados: {', '.join(dangerous)[:80]}")
        else:
            print_ok("Solo GET/POST/HEAD permitidos")

        # ── 5.5. Admin Panels ─────────────────────────────────────────────────
        print_section("Admin", "Paneles de Administración")
        async with spinner_async("Buscando paneles"):
            admin_vulns, admin_data = await admin_panels.run(client, url, technologies=meta.get("technologies", []))
        all_vulns.extend(admin_vulns); _track("admin_panels", admin_vulns)
        meta["admin_panels"] = admin_data
        exposed = [p for p in admin_data if p.get("login")]
        if exposed:
            print_warn(f"[{len(exposed)}] Paneles de administración con login expuestos")
        elif admin_data:
            print_info(f"[{len(admin_data)}] Rutas protegidas/redirigidas de admin encontradas")
        else:
            print_ok("Sin paneles de administración expuestos")

        # ── 6. Sensitive Paths ────────────────────────────────────────────────
        print_section("6/9", f"Rutas Sensibles ({len(paths.SENSITIVE_PATHS) if hasattr(paths, 'SENSITIVE_PATHS') else '...'})")
        # Usamos la lista de config
        from config import SENSITIVE_PATHS as SP
        print_info(f"Escaneando {len(SP)} rutas...")
        async with spinner_async("Escaneando rutas"):
            path_vulns, found_paths = await paths.run(client, url)
        all_vulns.extend(path_vulns); _track("paths", path_vulns)
        meta["paths"] = found_paths
        if found_paths:
            print_warn(f"{len(found_paths)} rutas accesibles encontradas")
        else:
            print_ok("Sin rutas sensibles expuestas")

        # ── 7. Port Scan ──────────────────────────────────────────────────────
        if scan_ports:
            print_section("7/9", "Port Scan")
            from config import PORTS as PORT_LIST
            print_info(f"Escaneando {len(PORT_LIST)} puertos...")

            def port_progress(done: int, total: int):
                progress_bar(done, total, label="port scan")

            port_vulns, open_ports = await ports.run(
                hostname.split(":")[0],
                progress_cb=port_progress
            )
            print()  # nueva línea tras progress bar
            all_vulns.extend(port_vulns); _track("ports", port_vulns)
            meta["ports"] = open_ports
            open_dangerous = [p for p in open_ports if p["sev"] != "LOW"]
            print_ok(f"Puertos abiertos: {len(open_ports)} | Peligrosos: {len(open_dangerous)}")
        else:
            print_section("7/9", "Port Scan [OMITIDO]")

        # ── 8. Open Redirect ──────────────────────────────────────────────────
        print_section("8/9", "Open Redirect / Content Leakage")
        async with spinner_async("Analizando redirect"):
            redir_vulns  = await redirects.run(client, url)
        all_vulns.extend(redir_vulns); _track("redirects", redir_vulns)

        # Content leakage usa el body ya obtenido si está disponible
        body_text = main_resp.text if main_resp else None
        async with spinner_async("Buscando content leakage"):
            content_vulns = await content.run(client, url, resp_body=body_text)
        all_vulns.extend(content_vulns); _track("content", content_vulns)

        if redir_vulns:
            print_warn(f"Open redirect: {len(redir_vulns)} encontrados")
        if content_vulns:
            print_warn(f"Content leakage: {len(content_vulns)} patrones")
        if not redir_vulns and not content_vulns:
            print_ok("Sin open redirect ni leakage de contenido")

        # ── 8.5. JS Vulnerable Libraries ──────────────────────────────────────
        print_section("JS", "Librerías JavaScript Vulnerables")
        async with spinner_async("Analizando JS"):
            js_vulns = await js_cve.run(client, url, body_text)
        all_vulns.extend(js_vulns); _track("js_cve", js_vulns)
        if js_vulns:
            print_warn(f"[{len(js_vulns)}] Librerías vulnerables (CVEs detectados)")
        else:
            print_ok("Sin librerías JS vulnerables conocidas")

        # ── 8.8. JWT Analysis ─────────────────────────────────────────────────
        print_section("JWT", "Análisis de Tokens JWT")
        async with spinner_async("Inspeccionando JWT"):
            jwt_vulns = await jwt_scan.run(client, url, body_text=body_text, headers=main_resp.headers if main_resp else None)
        all_vulns.extend(jwt_vulns); _track("jwt_scan", jwt_vulns)
        if jwt_vulns:
            print_warn(f"[{len(jwt_vulns)}] Vulnerabilidades en JWT encontradas")
        else:
            print_ok("Sin JWTs vulnerables detectados")

        # ── 9. API & Endpoint Discovery ───────────────────────────────────────
        print_section("9/10", "Descubrimiento de API & Endpoints")
        async with spinner_async("Descubriendo endpoints"):
            api_vulns, api_data = await api_discovery.run(client, url, body_text)
        all_vulns.extend(api_vulns); _track("api_discovery", api_vulns)
        meta["api_endpoints"] = api_data
        apis = [e for e in api_data if e["type"] == "api"]
        others = len(api_data) - len(apis)
        if apis:
            print_warn(f"[{len(apis)}] Endpoints API encontrados")
        print_ok(f"[{others}] Otros links o peticiones JS detectados")

        # ── Pasivos avanzados (siempre, son rápidos y de bajo riesgo) ──────────
        print_section("Misc", "Host Header / Cache Poisoning / SRI / Mixed Content")
        async with spinner_async("Host header injection"):
            hh_vulns = await host_header.run(client, url)
        all_vulns.extend(hh_vulns); _track("host_header", hh_vulns)

        async with spinner_async("Cache poisoning"):
            cp_vulns = await cache_poisoning.run(client, url)
        all_vulns.extend(cp_vulns); _track("cache_poisoning", cp_vulns)

        print_section("CSP", "Bypass de Content-Security-Policy")
        async with spinner_async("Analizando CSP bypass"):
            csp_vulns = await csp_bypass.run(client, url)
        all_vulns.extend(csp_vulns); _track("csp_bypass", csp_vulns)
        print_warn(f"CSP bypass: {len(csp_vulns)} hallazgos") if csp_vulns else print_ok("CSP sin bypass evidentes")

        print_section("OAuth", "OAuth2 / OIDC misconfiguration")
        async with spinner_async("Inspeccionando .well-known/openid-configuration"):
            oauth_vulns = await oauth_oidc.run(client, url)
        all_vulns.extend(oauth_vulns); _track("oauth_oidc", oauth_vulns)
        print_warn(f"OAuth/OIDC: {len(oauth_vulns)} hallazgos") if oauth_vulns else print_ok("OAuth/OIDC OK o no aplicable")

        print_section("WS", "WebSocket CSWSH (Cross-Site WebSocket Hijacking)")
        async with spinner_async("Buscando endpoints WS y handshake malicioso"):
            ws_vulns = await websocket.run(client, url)
        all_vulns.extend(ws_vulns); _track("websocket", ws_vulns)
        print_warn(f"WebSocket: {len(ws_vulns)} hallazgos") if ws_vulns else print_ok("WebSocket sin CSWSH o no aplicable")

        print_section("IDOR", "Insecure Direct Object Reference (auto-discovery)")
        async with spinner_async("Enumerando IDs y buscando PII"):
            idor_vulns = await idor.run(client, url, crawled_urls=crawled_urls)
        all_vulns.extend(idor_vulns); _track("idor", idor_vulns)
        print_warn(f"IDOR: {len(idor_vulns)} hallazgos") if idor_vulns else print_ok("IDOR sin patrones explotables")

        print_section("SAML", "SAML / SSO misconfiguration")
        async with spinner_async("Buscando metadata SAML"):
            saml_vulns = await saml.run(client, url)
        all_vulns.extend(saml_vulns); _track("saml", saml_vulns)
        print_warn(f"SAML: {len(saml_vulns)} hallazgos") if saml_vulns else print_ok("SAML no detectado o sin issues")

        print_section("SW", "Service Worker / PWA Manifest / WebRTC")
        async with spinner_async("Analizando SW y manifest"):
            sw_vulns = await sw_xss.run(client, url)
        all_vulns.extend(sw_vulns); _track("sw_xss", sw_vulns)
        print_warn(f"SW/PWA/WebRTC: {len(sw_vulns)} hallazgos") if sw_vulns else print_ok("SW/PWA OK")

        total_passive_adv = (len(hh_vulns) + len(cp_vulns) + len(csp_vulns)
                             + len(oauth_vulns) + len(ws_vulns) + len(idor_vulns)
                             + len(saml_vulns) + len(sw_vulns))

        # ── 10. Active Scan ────────────────────────────────────────────────────
        if active_scan:
            print_section("10/10", "Escaneo Activo (SQLi / SSTI / XSS / Traversal / SSRF)")
            
            # SSTI
            async with spinner_async("Probando SSTI"):
                ssti_vulns = await ssti.run(client, url, full_scan=full_scan)
            all_vulns.extend(ssti_vulns); _track("ssti", ssti_vulns)
            if ssti_vulns:
                print_warn(f"SSTI: {len(ssti_vulns)} hallazgos")
                
            # Resto de activos (SQLi, XSS, Traversal, SSRF, JSON injection)
            async with spinner_async("Escaneo activo (Inyecciones, etc)"):
                active_vulns = await active.run(
                    client, url,
                    full_scan  = full_scan,
                    oob        = oob_client,
                    extra_urls = crawled_urls[1:] if crawled_urls else [],
                )
            all_vulns.extend(active_vulns); _track("active", active_vulns)
            
            # Forms
            async with spinner_async("Probando formularios"):
                form_vulns = await forms.run(client, url, body_text=body_text)
            all_vulns.extend(form_vulns); _track("forms", form_vulns)
            if form_vulns:
                print_warn(f"Forms: {len(form_vulns)} hallazgos")

            # GraphQL
            async with spinner_async("Escaneando GraphQL"):
                gql_vulns = await graphql.run(client, url)
            all_vulns.extend(gql_vulns); _track("graphql", gql_vulns)
            if gql_vulns:
                print_warn(f"GraphQL: {len(gql_vulns)} hallazgos")

            # XXE
            async with spinner_async("Probando XXE"):
                xxe_vulns = await xxe.run(client, url, api_endpoints=meta.get("api_endpoints", []))
            all_vulns.extend(xxe_vulns); _track("xxe", xxe_vulns)
            if xxe_vulns:
                print_warn(f"XXE: {len(xxe_vulns)} hallazgos")

            # CRLF Injection
            async with spinner_async("Probando CRLF injection"):
                crlf_vulns = await crlf.run(client, url)
            all_vulns.extend(crlf_vulns); _track("crlf", crlf_vulns)
            if crlf_vulns:
                print_warn(f"CRLF: {len(crlf_vulns)} hallazgos")

            # NoSQL Injection
            async with spinner_async("Probando NoSQL injection"):
                nosql_vulns = await nosql.run(client, url)
            all_vulns.extend(nosql_vulns); _track("nosql", nosql_vulns)
            if nosql_vulns:
                print_warn(f"NoSQL: {len(nosql_vulns)} hallazgos")

            # Prototype Pollution
            async with spinner_async("Probando prototype pollution"):
                pp_vulns = await prototype_pollution.run(client, url)
            all_vulns.extend(pp_vulns); _track("prototype_pollution", pp_vulns)
            if pp_vulns:
                print_warn(f"Prototype Pollution: {len(pp_vulns)} hallazgos")

            # HTTP Request Smuggling (solo en full_scan, es invasivo)
            if full_scan:
                async with spinner_async("Probando HTTP request smuggling"):
                    sm_vulns = await smuggling.run(client, url, enabled=True)
                all_vulns.extend(sm_vulns); _track("smuggling", sm_vulns)
                if sm_vulns:
                    print_warn(f"Smuggling: {len(sm_vulns)} hallazgos")

            # YAML Engine (Nuclei-style)
            async with spinner_async("Ejecutando firmas Nuclei"):
                yaml_vulns = await yaml_engine.run(client, url)
            all_vulns.extend(yaml_vulns); _track("yaml_engine", yaml_vulns)
            if yaml_vulns:
                print_warn(f"YAML Templates: {len(yaml_vulns)} hallazgos")

            # ── v7.0: Inyecciones específicas adicionales ───────────────
            print_section("LDAP", "LDAP Injection (error-based + boolean blind)")
            async with spinner_async("Probando LDAP injection"):
                ldap_vulns = await ldap_injection.run(client, url)
            all_vulns.extend(ldap_vulns); _track("ldap_injection", ldap_vulns)
            print_warn(f"LDAP: {len(ldap_vulns)} hallazgos") if ldap_vulns else print_ok("LDAP OK o no aplicable")

            print_section("XPath", "XPath Injection")
            async with spinner_async("Probando XPath injection"):
                xpath_vulns = await xpath_injection.run(client, url)
            all_vulns.extend(xpath_vulns); _track("xpath_injection", xpath_vulns)
            print_warn(f"XPath: {len(xpath_vulns)} hallazgos") if xpath_vulns else print_ok("XPath OK o no aplicable")

            print_section("Mail", "Email Header Injection (CRLF en /contact)")
            async with spinner_async("Probando email header injection"):
                eh_vulns = await email_header.run(client, url)
            all_vulns.extend(eh_vulns); _track("email_header", eh_vulns)
            print_warn(f"Email Header: {len(eh_vulns)} hallazgos") if eh_vulns else print_ok("Email headers OK")

            print_section("CSV", "CSV/XLSX Injection (formula execution)")
            async with spinner_async("Probando CSV/XLSX injection"):
                csv_vulns = await csv_injection.run(client, url)
            all_vulns.extend(csv_vulns); _track("csv_injection", csv_vulns)
            print_warn(f"CSV: {len(csv_vulns)} hallazgos") if csv_vulns else print_ok("CSV exports sin formula injection")

            print_section("Upload", "File Upload Bypass (double-ext, polyglot, SVG)")
            async with spinner_async("Probando file upload bypass"):
                fu_vulns = await file_upload.run(client, url)
            all_vulns.extend(fu_vulns); _track("file_upload", fu_vulns)
            print_warn(f"File Upload: {len(fu_vulns)} hallazgos") if fu_vulns else print_ok("Upload sin bypass evidentes")

            print_section("GQL+", "GraphQL avanzado (alias, depth, suggestions)")
            async with spinner_async("Probando GraphQL avanzado"):
                gql_adv_vulns = await graphql_advanced.run(client, url)
            all_vulns.extend(gql_adv_vulns); _track("graphql_advanced", gql_adv_vulns)
            print_warn(f"GraphQL adv: {len(gql_adv_vulns)} hallazgos") if gql_adv_vulns else print_ok("GraphQL avanzado OK")

            # ── v7.3: Mass Assignment / HPP / Business Logic / GraphQL IDOR ─
            print_section("Mass", "Mass Assignment / Auto-binding (REST APIs)")
            async with spinner_async("Probando mass assignment"):
                mass_vulns = await mass_assignment.run(client, url, full_scan=full_scan, extra_urls=crawled_urls)
            all_vulns.extend(mass_vulns); _track("mass_assignment", mass_vulns)
            print_warn(f"Mass Assignment: {len(mass_vulns)} hallazgos") if mass_vulns else print_ok("Mass assignment OK")

            print_section("HPP", "HTTP Parameter Pollution")
            async with spinner_async("Probando HPP"):
                hpp_vulns = await http_param_pollution.run(client, url, full_scan=full_scan)
            all_vulns.extend(hpp_vulns); _track("http_param_pollution", hpp_vulns)
            print_warn(f"HPP: {len(hpp_vulns)} hallazgos") if hpp_vulns else print_ok("Sin HPP detectado")

            print_section("BizLogic", "Business Logic (precios, cupones, overflow)")
            async with spinner_async("Probando business logic"):
                bl_vulns = await business_logic.run(client, url, full_scan=full_scan, extra_urls=crawled_urls)
            all_vulns.extend(bl_vulns); _track("business_logic", bl_vulns)
            print_warn(f"Business Logic: {len(bl_vulns)} hallazgos") if bl_vulns else print_ok("Business logic OK")

            print_section("GQL-IDOR", "GraphQL IDOR (node + tipos con PII)")
            async with spinner_async("Probando GraphQL IDOR"):
                gql_idor_vulns = await graphql_idor.run(client, url, full_scan=full_scan)
            all_vulns.extend(gql_idor_vulns); _track("graphql_idor", gql_idor_vulns)
            print_warn(f"GraphQL IDOR: {len(gql_idor_vulns)} hallazgos") if gql_idor_vulns else print_ok("GraphQL IDOR OK")

            # ── v7.0/v7.1: Solo en full_scan (más invasivos) ─────────────
            rl_vulns:    list = []
            tfa_vulns:   list = []
            race_vulns:  list = []
            dom_vulns:   list = []
            h2_vulns:    list = []
            if full_scan:
                print_section("Rate", "Rate Limit check (30 logins paralelos)")
                async with spinner_async("Probando rate limit / login"):
                    rl_vulns = await rate_limit.run(client, url, full_scan=True)
                all_vulns.extend(rl_vulns); _track("rate_limit", rl_vulns)
                print_warn(f"Rate Limit: {len(rl_vulns)} hallazgos") if rl_vulns else print_ok("Rate limit OK o login no detectado")

                print_section("2FA", "2FA Bypass (50 OTPs paralelos)")
                async with spinner_async("Probando 2FA bypass"):
                    tfa_vulns = await two_fa_bypass.run(client, url, full_scan=True)
                all_vulns.extend(tfa_vulns); _track("two_fa_bypass", tfa_vulns)
                print_warn(f"2FA: {len(tfa_vulns)} hallazgos") if tfa_vulns else print_ok("2FA OK o endpoint no detectado")

                print_section("Race", "Race Condition / TOCTOU")
                async with spinner_async("Probando race condition"):
                    race_vulns = await race_condition.run(client, url, full_scan=True)
                all_vulns.extend(race_vulns); _track("race_condition", race_vulns)
                print_warn(f"Race: {len(race_vulns)} hallazgos") if race_vulns else print_ok("Race condition no detectada")

                print_section("DOM", "DOM XSS via Playwright (opcional)")
                async with spinner_async("DOM XSS headless"):
                    dom_vulns = await dom_xss.run(client, url, full_scan=True)
                all_vulns.extend(dom_vulns); _track("dom_xss", dom_vulns)
                if dom_vulns:
                    print_warn(f"DOM XSS: {len(dom_vulns)} hallazgos")
                else:
                    print_ok("DOM XSS OK o Playwright no instalado (pip install playwright)")

                print_section("H2", "HTTP/2 smuggling (opcional)")
                async with spinner_async("H2 smuggling"):
                    h2_vulns = await h2_smuggling.run(client, url, full_scan=True)
                all_vulns.extend(h2_vulns); _track("h2_smuggling", h2_vulns)
                if h2_vulns:
                    print_warn(f"H2 smuggling: {len(h2_vulns)} hallazgos")
                else:
                    print_ok("H2 smuggling OK o httpx[http2] no instalado")

            extra_active = (len(crlf_vulns) + len(nosql_vulns) + len(pp_vulns)
                            + len(ldap_vulns) + len(xpath_vulns) + len(eh_vulns)
                            + len(csv_vulns) + len(fu_vulns) + len(gql_adv_vulns)
                            + len(rl_vulns) + len(tfa_vulns) + len(race_vulns)
                            + len(mass_vulns) + len(hpp_vulns) + len(bl_vulns) + len(gql_idor_vulns))
            total_active = (
                len(ssti_vulns) + len(active_vulns) + len(form_vulns)
                + len(gql_vulns) + len(xxe_vulns) + len(yaml_vulns) + extra_active
            )
            if total_active > 0:
                print_warn(f"Activo: {total_active} hallazgos en total")
            else:
                print_ok("Sin vulnerabilidades activas detectadas")
        else:
            print_section("10/10", "Escaneo Activo [OMITIDO]")

    finally:
        try:
            await session.close()
        except AttributeError:
            pass  # Bug de aiohttp en Windows al cerrar conexiones SSL ya liberadas

    duration = time.monotonic() - t0
    deduped  = deduplicate(all_vulns)
    return deduped, meta, duration


# ─── Subdomain scanner ────────────────────────────────────────────────────────

async def _scan_subdomains(
    client: AsyncHTTPClient,
    subdomains: list[str],
    scheme: str = "https",
    max_subs: int = 12,
) -> list[Vuln]:
    """
    Aplica headers + SSL + paths sensibles a los subdominios descubiertos.
    Solo escaneamos los primeros max_subs para no tardar demasiado.
    """
    vulns: list[Vuln] = []
    sem = asyncio.Semaphore(4)  # máx. 4 subdominios en paralelo

    async def scan_one(sub: str):
        sub_url = f"{scheme}://{sub}"
        async with sem:
            # Headers de seguridad
            try:
                hdr_vulns, _ = await headers.run(client, sub_url)
                # Solo reportar MEDIUM o superior para no generar ruido
                for v in hdr_vulns:
                    if v.severity in ("CRITICAL", "HIGH", "MEDIUM"):
                        v.title = f"[{sub}] {v.title}"
                        v.url   = sub_url
                        vulns.append(v)
            except Exception:
                pass

            # Paths sensibles rápidos (solo los más críticos)
            try:
                path_vulns, _ = await paths.run(client, sub_url)
                for v in path_vulns:
                    if v.severity in ("CRITICAL", "HIGH"):
                        v.title = f"[{sub}] {v.title}"
                        v.url   = sub_url
                        vulns.append(v)
            except Exception:
                pass

    await asyncio.gather(*[scan_one(s) for s in subdomains[:max_subs]])
    return vulns
