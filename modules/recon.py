"""
modules/recon.py — DNS, subdominios (crt.sh + wordlist), ASN, zone transfer, tecnologías.
"""

from __future__ import annotations

import asyncio
import json
import re
import socket
from typing import Optional

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln
from config import SUBDOMAIN_WORDLIST, TECH_PATTERNS


async def run(
    client:    AsyncHTTPClient,
    url:       str,
    hostname:  str,
    full_scan: bool = False,
) -> tuple[list[Vuln], dict]:
    """
    Reconocimiento completo: DNS, subdominios, tecnologías.
    Retorna (vulns, info_dict).
    """
    vulns: list[Vuln] = []
    info  = {
        "ips":          [],
        "ipv6":         [],
        "ptr":          None,
        "asn":          None,
        "subdomains":   [],
        "technologies": [],
        "hostname":     hostname,
    }

    loop = asyncio.get_event_loop()

    # ── DNS básico ─────────────────────────────────────────────────────────────
    try:
        results = await loop.run_in_executor(
            None,
            lambda: socket.getaddrinfo(hostname, None, socket.AF_INET)
        )
        info["ips"] = list({r[4][0] for r in results})
    except socket.gaierror:
        vulns.append(make_vuln(
            "DNS no resuelve", "INFO", 0.0, "Recon",
            "No se pudo resolver el hostname.",
            "DNS lookup failed",
            "Verificar que el dominio existe y tiene registros DNS activos.",
            module="recon",
        ))
        return vulns, info

    # ── IPv6 ───────────────────────────────────────────────────────────────────
    try:
        r6 = await loop.run_in_executor(
            None,
            lambda: socket.getaddrinfo(hostname, None, socket.AF_INET6)
        )
        info["ipv6"] = list({r[4][0] for r in r6})
    except Exception:
        pass

    # ── PTR / Reverse DNS ─────────────────────────────────────────────────────
    for ip in info["ips"][:2]:
        try:
            ptr = await loop.run_in_executor(
                None,
                lambda i=ip: socket.gethostbyaddr(i)[0]
            )
            info["ptr"] = ptr
        except Exception:
            pass

    # ── Zone Transfer attempt ──────────────────────────────────────────────────
    zt_vuln = await _zone_transfer(hostname, loop)
    if zt_vuln:
        vulns.append(zt_vuln)

    # ── Tecnologías desde HTTP ─────────────────────────────────────────────────
    resp = await client.get(url, lax_ssl=True)
    if resp:
        techs = _detect_technologies(resp.text, resp.headers)
        info["technologies"] = techs

    # ── Subdominios ────────────────────────────────────────────────────────────
    if full_scan:
        crt_subs = await _crtsh_subdomains(client, hostname)
        wl_subs  = await _wordlist_subdomains(hostname, loop)

        all_subs = sorted(set(crt_subs) | set(wl_subs))
        info["subdomains"] = all_subs

        if all_subs:
            vulns.append(make_vuln(
                title       = f"Subdominios expuestos: {len(all_subs)} encontrados",
                severity    = "INFO",
                cvss        = 0.0,
                category    = "Recon",
                description = (
                    f"Se encontraron {len(all_subs)} subdominios. Cada uno amplía la superficie de ataque. "
                    "Revisar si alguno expone servicios internos o paneles admin."
                ),
                evidence    = ", ".join(all_subs[:10]) + ("..." if len(all_subs) > 10 else ""),
                fix         = "Auditar cada subdominio. Eliminar o proteger los que no deban ser públicos.",
                ref         = "https://owasp.org/www-project-web-security-testing-guide/",
                module      = "recon",
            ))

            takeover_vulns = await _check_subdomain_takeover(client, all_subs, hostname)
            vulns.extend(takeover_vulns)

    return vulns, info


# ─── crt.sh ───────────────────────────────────────────────────────────────────

async def _crtsh_subdomains(client: AsyncHTTPClient, hostname: str) -> list[str]:
    """Consulta Certificate Transparency logs via crt.sh."""
    url  = f"https://crt.sh/?q=%.{hostname}&output=json"
    resp = await client.get(url, lax_ssl=True)
    if not resp or resp.status != 200:
        return []

    try:
        data = json.loads(resp.text)
        subs = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.")
                if name.endswith(f".{hostname}") and name != hostname:
                    subs.add(name)
        return sorted(subs)
    except Exception:
        return []


# ─── Wordlist enumeration ─────────────────────────────────────────────────────

async def _wordlist_subdomains(hostname: str, loop) -> list[str]:
    """Enumera subdominios con wordlist via DNS resolve."""
    found: list[str] = []
    sem   = asyncio.Semaphore(50)

    async def check(word: str):
        async with sem:
            fqdn = f"{word}.{hostname}"
            try:
                result = await loop.run_in_executor(
                    None,
                    lambda: socket.getaddrinfo(fqdn, None, socket.AF_INET)
                )
                if result:
                    found.append(fqdn)
            except Exception:
                pass

    await asyncio.gather(*[check(w) for w in SUBDOMAIN_WORDLIST])
    return found


# ─── Zone Transfer ────────────────────────────────────────────────────────────

async def _zone_transfer(hostname: str, loop) -> Optional[Vuln]:
    """Intenta un DNS zone transfer (AXFR)."""
    try:
        import dns.resolver
        import dns.zone
        import dns.query

        def attempt():
            try:
                ns_answers = dns.resolver.resolve(hostname, "NS")
                for ns in ns_answers:
                    ns_host = str(ns.target).rstrip(".")
                    ns_ips  = socket.getaddrinfo(ns_host, 53, socket.AF_INET)
                    if not ns_ips:
                        continue
                    ns_ip = ns_ips[0][4][0]
                    try:
                        zone = dns.zone.from_xfr(
                            dns.query.xfr(ns_ip, hostname, timeout=5)
                        )
                        records = [str(n) for n in zone.nodes.keys()]
                        return ns_host, records[:20]
                    except Exception:
                        pass
            except Exception:
                pass
            return None, []

        ns_host, records = await loop.run_in_executor(None, attempt)
        if records:
            return make_vuln(
                title       = "DNS Zone Transfer permitido (AXFR)",
                severity    = "CRITICAL",
                cvss        = 9.8,
                category    = "DNS",
                description = (
                    "El servidor DNS permite transferencias de zona completas. "
                    "Un atacante obtiene todos los registros DNS incluyendo subdominios internos."
                ),
                evidence    = f"NS {ns_host} expuso {len(records)} registros: {', '.join(records[:5])}",
                fix         = "Restringir AXFR solo a servidores NS secundarios autorizados por IP.",
                ref         = "https://www.acunetix.com/blog/articles/dns-zone-transfers-axfr/",
                module      = "recon",
            )
    except ImportError:
        pass
    except Exception:
        pass

    return None


# ─── Technology Detection ─────────────────────────────────────────────────────

def _detect_technologies(body: str, headers: dict) -> list[str]:
    """Detecta tecnologías por patrones en body y headers."""
    found = []
    combined = body[:8192].lower() + " " + " ".join(
        f"{k}:{v}" for k, v in headers.items()
    ).lower()

    for tech, patterns in TECH_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, combined, re.IGNORECASE):
                found.append(tech)
                break

    return found


# ─── Subdomain Takeover ───────────────────────────────────────────────────────

TAKEOVER_SIGNATURES = {
    "GitHub Pages":     "there isn't a github pages site here",
    "Heroku":           "no such app",
    "Shopify":          "sorry, this shop is currently unavailable",
    "Fastly":           "fastly error: unknown domain",
    "Netlify":          "not found - request id",
    "AWS S3":           "nosuchbucket",
    "Azure":            "404 web site not found",
    "Surge.sh":         "project not found",
}

async def _check_subdomain_takeover(
    client: AsyncHTTPClient,
    subdomains: list[str],
    base_hostname: str,
) -> list[Vuln]:
    """Detecta subdominios potencialmente takeoables."""
    vulns: list[Vuln] = []
    sem   = asyncio.Semaphore(20)

    async def check(sub: str):
        async with sem:
            resp = await client.get(f"https://{sub}", lax_ssl=True)
            if not resp:
                return
            body_lower = resp.text.lower()
            for service, sig in TAKEOVER_SIGNATURES.items():
                if sig in body_lower:
                    vulns.append(make_vuln(
                        title       = f"Posible Subdomain Takeover: {sub}",
                        severity    = "HIGH",
                        cvss        = 8.1,
                        category    = "Subdomain Takeover",
                        description = (
                            f"El subdominio {sub} parece apuntar a {service} que ya no está configurado. "
                            "Un atacante puede reclamar este servicio y controlar el subdominio."
                        ),
                        evidence    = f"{sub} → {service} signature: '{sig}'",
                        fix         = (
                            f"Eliminar el registro DNS de {sub} o reconfigurarlo con el servicio correcto."
                        ),
                        ref         = "https://hackerone.com/reports/",
                        module      = "recon",
                    ))
                    break

    await asyncio.gather(*[check(s) for s in subdomains[:30]])
    return vulns
