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
    print_vuln, progress_bar, print_sep, sev_color, W, BOLD, C, G, O, DIM
)

from modules import recon, headers, ssl_tls, http_methods, paths, ports, redirects, waf, content, active, api_discovery, js_cve, ssti, admin_panels, forms, jwt_scan, graphql, xxe, yaml_engine


async def scan(
    url:         str,
    full_scan:   bool = False,
    scan_ports:  bool = True,
    active_scan: bool = False,
    no_color:    bool = False,
    stealth:     bool = False,
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
        "server":       "",    # Server header
        "powered_by":   "",    # X-Powered-By header
    }

    all_vulns: list[Vuln] = []

    connector = aiohttp.TCPConnector(
        limit=100, limit_per_host=30,
        ssl=False, enable_cleanup_closed=True
    )
    session = aiohttp.ClientSession(connector=connector)
    try:
        client = AsyncHTTPClient(session, rate_limit=20, timeout=10, stealth=stealth)

        # ── 1. WAF Detection ──────────────────────────────────────────────────
        print_section("1/9", "WAF / CDN Detection")
        waf_vulns, waf_info = await waf.run(client, url, hostname)
        all_vulns.extend(waf_vulns)
        meta["waf"]           = waf_info.get("waf")
        meta["real_ip_hints"] = waf_info.get("real_ip_hints", [])
        if meta["waf"]:
            print_ok(f"WAF detectado: {meta['waf']}")
        else:
            print_warn("Sin WAF detectado — servidor expuesto directamente")

        # ── 2. Recon ──────────────────────────────────────────────────────────
        print_section("2/9", "Reconocimiento DNS / Subdominios")
        recon_vulns, recon_info = await recon.run(client, url, hostname, full_scan=full_scan)
        all_vulns.extend(recon_vulns)
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
            print_ok(f"Subdominios: {len(meta['subdomains'])} encontrados")

        # ── 3. SSL/TLS ────────────────────────────────────────────────────────
        print_section("3/9", "SSL / TLS")
        ssl_port = 443 if ":" not in hostname else int(hostname.split(":")[1])
        ssl_vulns, ssl_info = await ssl_tls.run(hostname.split(":")[0], port=ssl_port)
        all_vulns.extend(ssl_vulns)
        meta["ssl"] = ssl_info
        if ssl_info:
            print_ok(f"SSL: {ssl_info.get('version','?')} | Cifrado: {ssl_info.get('cipher','?')}")
            print_ok(f"Certificado: {ssl_info.get('subject','?')} | Issuer: {ssl_info.get('issuer','?')}")
            exp = ssl_info.get("not_after", "")
            if exp:
                print_info(f"Expira: {exp}")

        # ── 4. Security Headers ───────────────────────────────────────────────
        print_section("4/9", "Security Headers / CORS / Cookies")
        hdr_vulns, main_resp = await headers.run(client, url)
        all_vulns.extend(hdr_vulns)
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
        method_vulns = await http_methods.run(client, url)
        all_vulns.extend(method_vulns)
        if method_vulns:
            dangerous = [v.title for v in method_vulns]
            print_warn(f"Métodos detectados: {', '.join(dangerous)[:80]}")
        else:
            print_ok("Solo GET/POST/HEAD permitidos")

        # ── 5.5. Admin Panels ─────────────────────────────────────────────────
        print_section("Admin", "Paneles de Administración")
        admin_vulns, admin_data = await admin_panels.run(client, url, technologies=meta.get("technologies", []))
        all_vulns.extend(admin_vulns)
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
        path_vulns, found_paths = await paths.run(client, url)
        all_vulns.extend(path_vulns)
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
            all_vulns.extend(port_vulns)
            meta["ports"] = open_ports
            open_dangerous = [p for p in open_ports if p["sev"] != "LOW"]
            print_ok(f"Puertos abiertos: {len(open_ports)} | Peligrosos: {len(open_dangerous)}")
        else:
            print_section("7/9", "Port Scan [OMITIDO]")

        # ── 8. Open Redirect ──────────────────────────────────────────────────
        print_section("8/9", "Open Redirect / Content Leakage")
        redir_vulns  = await redirects.run(client, url)
        all_vulns.extend(redir_vulns)

        # Content leakage usa el body ya obtenido si está disponible
        body_text = main_resp.text if main_resp else None
        content_vulns = await content.run(client, url, resp_body=body_text)
        all_vulns.extend(content_vulns)

        if redir_vulns:
            print_warn(f"Open redirect: {len(redir_vulns)} encontrados")
        if content_vulns:
            print_warn(f"Content leakage: {len(content_vulns)} patrones")
        if not redir_vulns and not content_vulns:
            print_ok("Sin open redirect ni leakage de contenido")

        # ── 8.5. JS Vulnerable Libraries ──────────────────────────────────────
        print_section("JS", "Librerías JavaScript Vulnerables")
        js_vulns = await js_cve.run(client, url, body_text)
        all_vulns.extend(js_vulns)
        if js_vulns:
            print_warn(f"[{len(js_vulns)}] Librerías vulnerables (CVEs detectados)")
        else:
            print_ok("Sin librerías JS vulnerables conocidas")

        # ── 8.8. JWT Analysis ─────────────────────────────────────────────────
        print_section("JWT", "Análisis de Tokens JWT")
        jwt_vulns = await jwt_scan.run(client, url, body_text=body_text, headers=main_resp.headers if main_resp else None)
        all_vulns.extend(jwt_vulns)
        if jwt_vulns:
            print_warn(f"[{len(jwt_vulns)}] Vulnerabilidades en JWT encontradas")
        else:
            print_ok("Sin JWTs vulnerables detectados")

        # ── 9. API & Endpoint Discovery ───────────────────────────────────────
        print_section("9/10", "Descubrimiento de API & Endpoints")
        api_vulns, api_data = await api_discovery.run(client, url, body_text)
        all_vulns.extend(api_vulns)
        meta["api_endpoints"] = api_data
        apis = [e for e in api_data if e["type"] == "api"]
        others = len(api_data) - len(apis)
        if apis:
            print_warn(f"[{len(apis)}] Endpoints API encontrados")
        print_ok(f"[{others}] Otros links o peticiones JS detectados")

        # ── 10. Active Scan ────────────────────────────────────────────────────
        if active_scan:
            print_section("10/10", "Escaneo Activo (SQLi / SSTI / XSS / Traversal / SSRF)")
            
            # SSTI
            ssti_vulns = await ssti.run(client, url, full_scan=full_scan)
            all_vulns.extend(ssti_vulns)
            if ssti_vulns:
                print_warn(f"SSTI: {len(ssti_vulns)} hallazgos")
                
            # Resto de activos
            active_vulns = await active.run(client, url, full_scan=full_scan)
            all_vulns.extend(active_vulns)
            
            # Forms
            form_vulns = await forms.run(client, url, body_text=body_text)
            all_vulns.extend(form_vulns)
            if form_vulns:
                print_warn(f"Forms: {len(form_vulns)} hallazgos")

            # GraphQL
            gql_vulns = await graphql.run(client, url)
            all_vulns.extend(gql_vulns)
            if gql_vulns:
                print_warn(f"GraphQL: {len(gql_vulns)} hallazgos")

            # XXE
            xxe_vulns = await xxe.run(client, url, api_endpoints=meta.get("api_endpoints", []))
            all_vulns.extend(xxe_vulns)
            if xxe_vulns:
                print_warn(f"XXE: {len(xxe_vulns)} hallazgos")

            # YAML Engine (Nuclei-style)
            yaml_vulns = await yaml_engine.run(client, url)
            all_vulns.extend(yaml_vulns)
            if yaml_vulns:
                print_warn(f"YAML Templates: {len(yaml_vulns)} hallazgos")

            total_active = len(ssti_vulns) + len(active_vulns) + len(form_vulns) + len(gql_vulns) + len(xxe_vulns) + len(yaml_vulns)
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
