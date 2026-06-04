"""
bounty_db.py — Base de datos de programas de Bug Bounty y estimación de recompensas.

Esta base de datos contiene rangos de recompensa basados en datos públicos de
HackerOne, Bugcrowd y programas privados conocidos.
SOLO para uso ético en sistemas propios o con autorización explícita.
"""

from __future__ import annotations

from typing import Optional


# ─── Rangos de bounty por severidad (USD) ────────────────────────────────────
# Basado en promedios reales de plataformas públicas 2024
BOUNTY_RANGES: dict[str, dict[str, tuple[int, int]]] = {
    "small":   {"CRITICAL": (500,  2500),  "HIGH": (200, 800),   "MEDIUM": (50,  300),  "LOW": (50, 150),  "INFO": (0, 50)},
    "medium":  {"CRITICAL": (2000, 10000), "HIGH": (500, 2500),  "MEDIUM": (150, 750),  "LOW": (75, 300),  "INFO": (0, 100)},
    "large":   {"CRITICAL": (5000, 25000), "HIGH": (1000, 5000), "MEDIUM": (300, 1500), "LOW": (100, 500), "INFO": (0, 200)},
    "enterprise": {"CRITICAL": (10000, 100000), "HIGH": (2000, 15000), "MEDIUM": (500, 3000), "LOW": (200, 1000), "INFO": (0, 500)},
}

# ─── Programas de bug bounty conocidos ───────────────────────────────────────
# Datos basados en información pública disponible
KNOWN_PROGRAMS: dict[str, dict] = {
    "google.com":        {"name": "Google VRP",        "platform": "Direct",   "tier": "enterprise", "min": 100,   "max": 151515},
    "microsoft.com":     {"name": "MSRC",               "platform": "Direct",   "tier": "enterprise", "min": 500,   "max": 250000},
    "apple.com":         {"name": "Apple Security",     "platform": "Direct",   "tier": "enterprise", "min": 5000,  "max": 1000000},
    "meta.com":          {"name": "Meta Bug Bounty",    "platform": "Direct",   "tier": "enterprise", "min": 500,   "max": 300000},
    "facebook.com":      {"name": "Meta Bug Bounty",    "platform": "Direct",   "tier": "enterprise", "min": 500,   "max": 300000},
    "twitter.com":       {"name": "X Security",         "platform": "HackerOne","tier": "large",      "min": 140,   "max": 15120},
    "x.com":             {"name": "X Security",         "platform": "HackerOne","tier": "large",      "min": 140,   "max": 15120},
    "github.com":        {"name": "GitHub Bug Bounty",  "platform": "HackerOne","tier": "large",      "min": 617,   "max": 30000},
    "shopify.com":       {"name": "Shopify Bug Bounty", "platform": "HackerOne","tier": "large",      "min": 500,   "max": 50000},
    "uber.com":          {"name": "Uber Bug Bounty",    "platform": "HackerOne","tier": "large",      "min": 500,   "max": 10000},
    "dropbox.com":       {"name": "Dropbox Bug Bounty", "platform": "HackerOne","tier": "large",      "min": 216,   "max": 32768},
    "paypal.com":        {"name": "PayPal Bug Bounty",  "platform": "HackerOne","tier": "large",      "min": 150,   "max": 10000},
    "yahoo.com":         {"name": "Yahoo Bug Bounty",   "platform": "HackerOne","tier": "large",      "min": 150,   "max": 15000},
    "cloudflare.com":    {"name": "Cloudflare",         "platform": "HackerOne","tier": "large",      "min": 250,   "max": 3000},
    "netflix.com":       {"name": "Netflix Bug Bounty", "platform": "Bugcrowd", "tier": "large",      "min": 250,   "max": 20000},
    "airbnb.com":        {"name": "Airbnb Bug Bounty",  "platform": "HackerOne","tier": "large",      "min": 500,   "max": 10000},
    "amazon.com":        {"name": "Amazon VDP",         "platform": "Direct",   "tier": "enterprise", "min": 100,   "max": 50000},
    "aws.amazon.com":    {"name": "AWS Security",       "platform": "Direct",   "tier": "enterprise", "min": 100,   "max": 50000},
    "gitlab.com":        {"name": "GitLab Bug Bounty",  "platform": "HackerOne","tier": "large",      "min": 300,   "max": 26250},
    "mozilla.org":       {"name": "Mozilla Bug Bounty", "platform": "Direct",   "tier": "medium",     "min": 500,   "max": 10000},
    "wordpress.org":     {"name": "WordPress",          "platform": "HackerOne","tier": "medium",     "min": 150,   "max": 1337},
    "atlassian.com":     {"name": "Atlassian BB",       "platform": "Bugcrowd", "tier": "large",      "min": 300,   "max": 12000},
    "twitch.tv":         {"name": "Twitch Bug Bounty",  "platform": "HackerOne","tier": "large",      "min": 500,   "max": 10000},
    "discord.com":       {"name": "Discord BB",         "platform": "HackerOne","tier": "large",      "min": 500,   "max": 10000},
    "hackerone.com":     {"name": "HackerOne BB",       "platform": "HackerOne","tier": "large",      "min": 1000,  "max": 20000},
    "bugcrowd.com":      {"name": "Bugcrowd BB",        "platform": "Bugcrowd", "tier": "large",      "min": 500,   "max": 10000},
    "coinbase.com":      {"name": "Coinbase BB",        "platform": "HackerOne","tier": "enterprise", "min": 200,   "max": 50000},
    "stripe.com":        {"name": "Stripe BB",          "platform": "HackerOne","tier": "enterprise", "min": 500,   "max": 50000},
    "square.com":        {"name": "Square/Block BB",    "platform": "HackerOne","tier": "enterprise", "min": 250,   "max": 50000},
    "twilio.com":        {"name": "Twilio BB",          "platform": "HackerOne","tier": "large",      "min": 150,   "max": 10000},
    "zoom.us":           {"name": "Zoom BB",            "platform": "HackerOne","tier": "large",      "min": 250,   "max": 50000},
    "slack.com":         {"name": "Slack BB",           "platform": "HackerOne","tier": "large",      "min": 100,   "max": 7500},
    "salesforce.com":    {"name": "Salesforce BB",      "platform": "Bugcrowd", "tier": "enterprise", "min": 100,   "max": 20000},
    "adobe.com":         {"name": "Adobe BB",           "platform": "HackerOne","tier": "enterprise", "min": 100,   "max": 10000},
    "intel.com":         {"name": "Intel Bug Bounty",   "platform": "HackerOne","tier": "enterprise", "min": 500,   "max": 100000},
    "samsung.com":       {"name": "Samsung Mobile BB",  "platform": "Direct",   "tier": "enterprise", "min": 200,   "max": 1000000},
    "huawei.com":        {"name": "Huawei BB",          "platform": "Direct",   "tier": "large",      "min": 200,   "max": 10000},
}

# ─── Multiplicadores por tipo de vulnerabilidad ───────────────────────────────
# Qué tipos de vuln valen más en programas de bounty
VULN_MULTIPLIERS: dict[str, float] = {
    # Mayor impacto
    "RCE":              3.5,
    "Remote Code Exec": 3.5,
    "SSRF":             2.5,
    "SQL Injection":    2.5,
    "SQLi":             2.5,
    "SQLi (Blind":      2.2,
    "Authentication":   2.0,
    "JWT":              1.8,
    "IDOR":             2.0,
    "XXE":              1.8,
    "Path Traversal":   1.7,
    "SSTI":             2.5,
    "XSS":              1.2,
    "CORS":             1.3,
    "Open Redirect":    0.8,
    "Security Header":  0.4,
    "SSL":              0.6,
    "Information Disc": 0.7,
    "Port":             0.5,
}


def find_program(hostname: str) -> Optional[dict]:
    """
    Busca si el hostname pertenece a un programa de bug bounty conocido.
    Hace fuzzy matching por dominio raíz.
    """
    hostname = hostname.lower().strip()
    # Coincidencia exacta
    if hostname in KNOWN_PROGRAMS:
        return KNOWN_PROGRAMS[hostname]
    # Buscar por dominio raíz (ej: api.github.com -> github.com)
    parts = hostname.split(".")
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate in KNOWN_PROGRAMS:
            return KNOWN_PROGRAMS[candidate]
    return None


def estimate_bounty(
    severity: str,
    vuln_category: str = "",
    hostname: str = "",
) -> dict:
    """
    Estima el rango de recompensa para una vulnerabilidad.
    Retorna dict con min, max, currency, program, platform, tier.
    """
    program = find_program(hostname) if hostname else None
    tier    = program["tier"] if program else "medium"

    ranges = BOUNTY_RANGES.get(tier, BOUNTY_RANGES["medium"])
    low, high = ranges.get(severity, (0, 100))

    # Aplicar multiplicador según tipo de vuln
    multiplier = 1.0
    for key, mult in VULN_MULTIPLIERS.items():
        if key.lower() in vuln_category.lower():
            multiplier = max(multiplier, mult)
            break

    low  = int(low  * multiplier)
    high = int(high * multiplier)

    return {
        "min":      low,
        "max":      high,
        "currency": "USD",
        "tier":     tier,
        "program":  program["name"]     if program else "Programa desconocido",
        "platform": program["platform"] if program else "HackerOne/Bugcrowd",
        "known":    program is not None,
        "range_str": f"${low:,} – ${high:,}" if high > 0 else "No monetizable",
    }


def get_top_programs_by_payout(top_n: int = 10) -> list[dict]:
    """Retorna los programas con mayor potencial de pago."""
    result = []
    for domain, info in KNOWN_PROGRAMS.items():
        result.append({
            "domain":   domain,
            "name":     info["name"],
            "platform": info["platform"],
            "max":      info["max"],
            "min":      info["min"],
            "tier":     info["tier"],
        })
    return sorted(result, key=lambda x: x["max"], reverse=True)[:top_n]


def categorize_finding_for_bounty(vuln_title: str, severity: str) -> dict:
    """
    Clasifica un hallazgo según criterios comunes de programas de bounty.
    Retorna si es likely eligible, priority, y notes.
    """
    title_lower = vuln_title.lower()

    # Tipos generalmente aceptados
    high_value = ["sql injection", "rce", "ssrf", "ssti", "xxe", "idor",
                  "authentication bypass", "privilege escalation", "jwt", "path traversal"]
    medium_value = ["xss", "cors", "csrf", "open redirect", "sensitive file",
                    "credential", "api key", "secret", "backup", "git exposed"]
    low_value = ["security header", "ssl", "tls", "information disclosure",
                 "port", "directory listing"]
    usually_excluded = ["clickjacking", "missing header", "autocomplete",
                        "rate limit", "user enumeration", "version disclosure"]

    for kw in usually_excluded:
        if kw in title_lower:
            return {
                "eligible": "unlikely",
                "priority": "LOW",
                "notes": f"'{kw}' generalmente excluido de programas de bounty sin impacto demostrable.",
            }

    for kw in high_value:
        if kw in title_lower:
            return {
                "eligible": "very_likely",
                "priority": "CRITICAL" if severity in ("CRITICAL", "HIGH") else "HIGH",
                "notes": "Alta probabilidad de ser aceptado. Documentar con PoC completo.",
            }

    for kw in medium_value:
        if kw in title_lower:
            return {
                "eligible": "likely",
                "priority": "MEDIUM",
                "notes": "Probabilidad media. Requiere demostración de impacto real.",
            }

    for kw in low_value:
        if kw in title_lower:
            return {
                "eligible": "possible",
                "priority": "LOW",
                "notes": "Depende del programa. Algunos aceptan con impacto adicional demostrado.",
            }

    return {
        "eligible": "possible",
        "priority": severity,
        "notes": "Evaluar según política del programa específico.",
    }
