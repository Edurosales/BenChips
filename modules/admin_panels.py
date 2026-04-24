"""
modules/admin_panels.py — Descubrimiento de paneles de administración y dashboards.

Features:
  - 120+ rutas conocidas de admin panels, organizadas por tecnología.
  - Detección de formularios de login (input[type=password]) en la respuesta.
  - Detección de keywords de admin en título y h1.
  - Baseline + soft-404 para eliminar falsos positivos.
  - Orden aleatorio de rutas en modo sigiloso.
  - Priorización de rutas según tecnología detectada (ASP.NET, PHP, etc.).
  - Severidad diferenciada: login form expuesto (HIGH) vs solo 200 (MEDIUM).

Anti-falsos-positivos:
  - Ignora redirects (301/302) → casi siempre son login redirects genéricos.
  - Establece baseline antes de escanear.
  - Verifica que la respuesta tiene contenido real (> 200 bytes).
  - Solo confirma panel si: código 200/401/403 Y (login form O keyword admin).
"""

from __future__ import annotations

import asyncio
import random
import re
from urllib.parse import urlparse

from utils.http import AsyncHTTPClient
from utils.vuln import Vuln, make_vuln
from config import ADMIN_PATHS


# Patterns para detectar formularios de login en el HTML
_LOGIN_FORM_PATTERNS = [
    re.compile(r'<input[^>]+type=["\']password["\']', re.IGNORECASE),
    re.compile(r'<form[^>]+action=[^>]*(login|signin|auth|session)[^>]*>', re.IGNORECASE),
    re.compile(r'name=["\']password["\']', re.IGNORECASE),
    re.compile(r'id=["\']password["\']', re.IGNORECASE),
]

# Keywords de admin en título o body (para confirmar que es un panel real)
_ADMIN_KEYWORDS = re.compile(
    r'\b(admin|administrator|dashboard|panel de control|back.?office|'
    r'management|manage|console|control panel|login|iniciar sesi[oó]n|'
    r'acceder|ingresar|bienvenido|welcome)\b',
    re.IGNORECASE,
)

# Títulos que indican panel de admin en el <title>
_ADMIN_TITLE_PATTERN = re.compile(
    r'<title[^>]*>(.*?)</title>',
    re.IGNORECASE | re.DOTALL,
)


def _detect_login_form(body: str) -> bool:
    """True si el body contiene un formulario de login."""
    return any(p.search(body) for p in _LOGIN_FORM_PATTERNS)


def _extract_title(body: str) -> str:
    """Extrae el contenido del tag <title>."""
    m = _ADMIN_TITLE_PATTERN.search(body[:4096])
    return m.group(1).strip()[:100] if m else ""


def _has_admin_content(body: str) -> bool:
    """True si el body tiene keywords de panel de admin."""
    return bool(_ADMIN_KEYWORDS.search(body[:8192]))


def _prioritize_paths(paths: list[str], technologies: list[str]) -> list[str]:
    """
    Ordena las rutas priorizando las relevantes para la tecnología detectada.
    En modo sigiloso, añade shuffle al resto para evitar patrones de escaneo.
    """
    tech_lower = [t.lower() for t in technologies]
    priority   = []
    rest       = []

    tech_prefixes: dict[str, list[str]] = {
        "iis":    [".aspx", "aspx"],
        "asp.net":[".aspx", "aspx"],
        "php":    [".php"],
        "wordpress": ["/wp-admin", "/wp-login"],
        "joomla": ["/administrator"],
        "drupal": ["/user/login"],
        "spring": ["/actuator", "/management"],
        "django": ["/django-admin"],
    }

    relevant_suffixes: list[str] = []
    for tech, prefixes in tech_prefixes.items():
        if tech in tech_lower:
            relevant_suffixes.extend(prefixes)

    for path in paths:
        if any(path.lower().endswith(s) or s in path.lower() for s in relevant_suffixes):
            priority.append(path)
        else:
            rest.append(path)

    random.shuffle(rest)
    return priority + rest


async def run(
    client:       AsyncHTTPClient,
    url:          str,
    technologies: list[str] | None = None,
    concurrency:  int = 10,
) -> tuple[list[Vuln], list[dict]]:
    """
    Escanea rutas de paneles de administración con detección inteligente.
    Retorna (vulns, found_panels_list).
    """
    vulns:        list[Vuln] = []
    found_panels: list[dict] = []

    parsed   = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    hostname = parsed.hostname or ""

    # ── Baseline para soft-404 ─────────────────────────────────────────────────
    await client.establish_baseline(base_url)

    # ── Priorizar rutas según tecnología ───────────────────────────────────────
    techs        = technologies or []
    ordered_paths = _prioritize_paths(ADMIN_PATHS, techs)

    # En modo sigiloso bajar concurrencia aún más
    effective_concurrency = min(concurrency, 5 if client.stealth else concurrency)
    sem = asyncio.Semaphore(effective_concurrency)

    async def check_path(path: str):
        async with sem:
            target = base_url.rstrip("/") + path
            resp   = await client.get(target, follow=False, lax_ssl=True, body_limit=65536)

            if not resp:
                return

            status = resp.status

            # Ignorar 4xx de "no existe" y 5xx
            if status in (404, 410, 500, 503, 400):
                return

            # Ignorar redirects — en la mayoría de servidores ANY path redirige a login
            # Solo si el redirect apunta a algo específico de admin lo registramos
            if status in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                # Si redirige a login de admin → interesante pero baja severidad
                if any(kw in location.lower() for kw in ["login", "admin", "auth", "signin"]):
                    found_panels.append({
                        "path":     path,
                        "status":   status,
                        "location": location,
                        "type":     "redirect_to_admin",
                        "title":    "",
                        "login":    False,
                    })
                return

            # Filtrar contenido vacío
            if len(resp.body) < 150:
                return

            # Soft-404 check
            if client.is_soft_404(hostname, status, resp.body):
                return

            body = resp.text

            # ── Detectar si es realmente un panel de admin ─────────────────────
            has_login  = _detect_login_form(body)
            title      = _extract_title(body)
            has_admin  = _has_admin_content(body) or (
                title and bool(_ADMIN_KEYWORDS.search(title))
            )

            # Para 401/403: el recurso existe pero está protegido
            if status in (401, 403):
                found_panels.append({
                    "path":   path,
                    "status": status,
                    "type":   "protected",
                    "title":  title,
                    "login":  has_login,
                })
                vulns.append(make_vuln(
                    title       = f"Panel admin protegido encontrado: {path}",
                    severity    = "MEDIUM",
                    cvss        = 5.3,
                    category    = "Admin Panel Discovery",
                    description = (
                        f"El panel '{path}' existe y está protegido (HTTP {status}). "
                        "Confirma la existencia del panel — útil para ataques de fuerza bruta."
                    ),
                    evidence    = (
                        f"GET {path} → HTTP {status}\n"
                        f"Título: {title or 'N/A'}\n"
                        f"Formulario login: {'Sí' if has_login else 'No'}"
                    ),
                    fix         = (
                        "Verificar que el panel requiere autenticación fuerte (2FA). "
                        "Restringir acceso por IP si es posible. "
                        "Implementar rate-limiting para prevenir fuerza bruta."
                    ),
                    ref         = "https://owasp.org/www-project-web-security-testing-guide/",
                    module      = "admin_panels",
                    url         = target,
                ))
                return

            # Para 200: verificar que es realmente un panel (no soft-404 con 200)
            if status == 200:
                if not (has_login or has_admin):
                    return  # Parece una página genérica, ignorar

                found_panels.append({
                    "path":   path,
                    "status": status,
                    "type":   "exposed" if has_login else "possible",
                    "title":  title,
                    "login":  has_login,
                })

                if has_login:
                    # Login form expuesto = HIGH
                    sev, cvss_val = "HIGH", 7.5
                    desc = (
                        f"Panel de administración con formulario de login expuesto en '{path}'. "
                        "Un atacante puede intentar fuerza bruta o explotar credenciales por defecto."
                    )
                    panel_title = f"Panel admin expuesto (login): {path}"
                else:
                    # Solo keywords de admin sin form = MEDIUM
                    sev, cvss_val = "MEDIUM", 5.3
                    desc = (
                        f"Posible panel de administración en '{path}' (HTTP 200). "
                        "Contiene contenido que sugiere interfaz de administración."
                    )
                    panel_title = f"Posible panel admin: {path}"

                vulns.append(make_vuln(
                    title       = panel_title,
                    severity    = sev,
                    cvss        = cvss_val,
                    category    = "Admin Panel Discovery",
                    description = desc,
                    evidence    = (
                        f"GET {path} → HTTP {status} ({len(resp.body)} bytes)\n"
                        f"Título: {title or 'N/A'}\n"
                        f"Formulario login detectado: {'Sí' if has_login else 'No'}\n"
                        f"Keywords admin: {'Sí' if has_admin else 'No'}"
                    ),
                    fix         = (
                        "Restringir acceso al panel por IP de origen (whitelist). "
                        "Implementar autenticación multifactor (2FA/MFA). "
                        "Cambiar ruta del panel a una no estándar. "
                        "Implementar rate-limiting y bloqueo por intentos fallidos."
                    ),
                    ref         = "https://owasp.org/www-project-web-security-testing-guide/",
                    module      = "admin_panels",
                    url         = target,
                ))

    tasks = [check_path(p) for p in ordered_paths]
    await asyncio.gather(*tasks)

    return vulns, found_panels
