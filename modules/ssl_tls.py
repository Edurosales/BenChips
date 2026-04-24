"""
modules/ssl_tls.py — Verificación de SSL/TLS: protocolo, cifrado, certificado, redirección.
"""

from __future__ import annotations

import asyncio
import ssl
import socket
from datetime import datetime
from typing import Optional

from utils.vuln import Vuln, make_vuln


async def run(hostname: str, port: int = 443) -> tuple[list[Vuln], dict]:
    """
    Verifica configuración SSL/TLS del servidor.
    Retorna (vulns, ssl_info).
    """
    vulns:    list[Vuln] = []
    ssl_info: dict       = {}

    loop = asyncio.get_event_loop()

    def _check_ssl():
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ver    = ssock.version()
                    cert   = ssock.getpeercert()
                    cipher = ssock.cipher()
                    return "ok", ver, cert, cipher, None
        except ssl.SSLCertVerificationError as e:
            return "cert_error", None, None, None, str(e)
        except ConnectionRefusedError:
            return "refused", None, None, None, None
        except socket.timeout:
            return "timeout", None, None, None, None
        except Exception as e:
            return "error", None, None, None, str(e)

    status, ver, cert, cipher, err = await loop.run_in_executor(None, _check_ssl)

    if status == "refused":
        vulns.append(make_vuln(
            "HTTPS no disponible (puerto 443 cerrado)", "HIGH", 7.5, "SSL/TLS",
            "El servidor no acepta conexiones HTTPS.",
            f"{hostname}:{port} rechazado",
            "Configurar HTTPS con certificado válido. Let's Encrypt es gratuito.",
            ref="https://letsencrypt.org/", module="ssl",
        ))
        return vulns, ssl_info

    if status == "cert_error":
        vulns.append(make_vuln(
            "Certificado SSL inválido", "HIGH", 7.4, "SSL/TLS",
            "El certificado no pasa verificación estándar.",
            str(err)[:150],
            "Obtener certificado válido de CA reconocida.",
            ref="https://letsencrypt.org/", module="ssl",
        ))
        return vulns, ssl_info

    if status in ("timeout", "error"):
        return vulns, ssl_info

    # ── Datos del certificado ──────────────────────────────────────────────────
    subject_cn = dict(x[0] for x in cert.get("subject",   [])).get("commonName",      "?")
    issuer_org = dict(x[0] for x in cert.get("issuer",    [])).get("organizationName", "?")
    issuer_cn  = dict(x[0] for x in cert.get("issuer",    [])).get("commonName",       "?")
    not_after  = cert.get("notAfter",  "?")
    not_before = cert.get("notBefore", "?")
    san_list   = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

    ssl_info = {
        "version":     ver or "?",
        "cipher":      cipher[0] if cipher else "?",
        "cipher_bits": str(cipher[2]) if cipher and cipher[2] else "?",
        "subject":     subject_cn,
        "issuer":      issuer_org or issuer_cn,
        "not_after":   not_after,
        "not_before":  not_before,
        "san_count":   str(len(san_list)),
    }

    # ── Protocolo obsoleto ─────────────────────────────────────────────────────
    if ver in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
        vuln_map = {
            "SSLv2":   ("CRITICAL", 9.8, "SSLv2 completamente roto"),
            "SSLv3":   ("CRITICAL", 9.8, "SSLv3 — vulnerable a POODLE"),
            "TLSv1":   ("HIGH",     7.5, "TLS 1.0 — vulnerable a BEAST/POODLE"),
            "TLSv1.1": ("HIGH",     7.4, "TLS 1.1 — vulnerable a LUCKY13"),
        }
        sev, cvss, desc = vuln_map.get(ver, ("HIGH", 7.0, f"Protocolo obsoleto: {ver}"))
        vulns.append(make_vuln(
            f"Protocolo TLS obsoleto: {ver}", sev, cvss, "SSL/TLS",
            f"{desc}. Atacantes en la misma red pueden descifrar el tráfico.",
            f"Protocolo negociado: {ver}",
            "Deshabilitar TLS 1.0 y 1.1. Usar solo TLS 1.2 y 1.3.",
            ref="https://ssl-config.mozilla.org/", module="ssl",
        ))

    # ── Cifrado débil ──────────────────────────────────────────────────────────
    if cipher and cipher[2]:
        bits = int(cipher[2])
        if bits < 128:
            vulns.append(make_vuln(
                f"Cifrado débil: {cipher[0]} ({bits} bits)",
                "HIGH", 7.4, "SSL/TLS",
                f"Cifrado de {bits} bits es insuficiente. Susceptible a ataques de fuerza bruta.",
                f"Cipher suite: {cipher[0]}, bits: {bits}",
                "Usar solo cipher suites AEAD (AES-GCM, ChaCha20-Poly1305) con 128+ bits.",
                ref="https://ssl-config.mozilla.org/", module="ssl",
            ))
        if cipher[0] and any(w in cipher[0].upper() for w in ("RC4", "DES", "NULL", "EXPORT", "MD5")):
            vulns.append(make_vuln(
                f"Cipher suite insegura: {cipher[0]}",
                "HIGH", 7.5, "SSL/TLS",
                "Cipher suite conocida como insegura o rota.",
                f"Cipher: {cipher[0]}",
                "Deshabilitar RC4, DES, NULL, EXPORT y MD5 cipher suites.",
                ref="https://ssl-config.mozilla.org/", module="ssl",
            ))

    # ── Expiración ─────────────────────────────────────────────────────────────
    if not_after and not_after != "?":
        try:
            exp  = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            dias = (exp - datetime.utcnow()).days
            if dias < 0:
                vulns.append(make_vuln(
                    "Certificado SSL EXPIRADO", "CRITICAL", 9.8, "SSL/TLS",
                    "El certificado ha vencido. Todos los navegadores muestran error de seguridad.",
                    f"Venció el {not_after}",
                    "Renovar certificado SSL inmediatamente. Let's Encrypt es gratuito.",
                    ref="https://letsencrypt.org/", module="ssl",
                ))
            elif dias < 14:
                vulns.append(make_vuln(
                    f"Certificado expira en {dias} días", "HIGH", 7.5, "SSL/TLS",
                    "Riesgo inminente de interrupción del servicio.",
                    f"Expira: {not_after}",
                    "Renovar certificado hoy.", module="ssl",
                ))
            elif dias < 30:
                vulns.append(make_vuln(
                    f"Certificado expira en {dias} días", "MEDIUM", 5.3, "SSL/TLS",
                    "El certificado expirará pronto.",
                    f"Expira: {not_after}",
                    "Planificar renovación esta semana.", module="ssl",
                ))
        except Exception:
            pass

    # ── Self-signed ────────────────────────────────────────────────────────────
    if issuer_cn and subject_cn and issuer_cn == subject_cn:
        vulns.append(make_vuln(
            "Certificado auto-firmado", "HIGH", 7.4, "SSL/TLS",
            "Los navegadores no confían en certificados auto-firmados. Cualquiera puede generar uno para MitM.",
            f"Issuer == Subject: {issuer_cn}",
            "Usar certificado de CA reconocida. Let's Encrypt es gratuito.",
            ref="https://letsencrypt.org/", module="ssl",
        ))

    # ── HTTP sin redirigir a HTTPS ─────────────────────────────────────────────
    http_vulns = await _check_http_redirect(hostname)
    vulns.extend(http_vulns)

    return vulns, ssl_info


async def _check_http_redirect(hostname: str) -> list[Vuln]:
    """Verifica si HTTP redirige correctamente a HTTPS."""
    import urllib.request
    import urllib.error

    vulns: list[Vuln] = []
    loop = asyncio.get_event_loop()

    def check():
        class NoRedir(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **kw): return None

        opener = urllib.request.build_opener(NoRedir())
        req    = urllib.request.Request(
            f"http://{hostname}",
            headers={"User-Agent": "VulnScanner-Pro/4.0"}
        )
        try:
            with opener.open(req, timeout=5) as r:
                return r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers) if hasattr(e, "headers") else {}
        except Exception:
            return None, {}

    status, hdrs = await loop.run_in_executor(None, check)
    if status is None:
        return vulns

    loc = hdrs.get("location", hdrs.get("Location", ""))

    if status == 200:
        vulns.append(make_vuln(
            "HTTP sirve contenido sin redirigir a HTTPS", "HIGH", 7.4, "Transport Security",
            "El sitio responde en HTTP plano. Todo el tráfico es interceptable.",
            f"http://{hostname} → HTTP {status} (sin redirección)",
            "Configurar redirección 301 a HTTPS y agregar HSTS.",
            module="ssl",
        ))
    elif status in (301, 302, 307, 308) and loc and not loc.startswith("https"):
        vulns.append(make_vuln(
            "Redirección HTTP → HTTP (no a HTTPS)", "HIGH", 7.4, "Transport Security",
            f"La redirección apunta a '{loc}' en vez de https://",
            f"http://{hostname} → {status} Location: {loc}",
            "Asegurar que la redirección apunte a https://",
            module="ssl",
        ))

    return vulns
