"""
tests/test_e2e_mock.py — Tests end-to-end con cliente HTTP mockeado.

Sin red. Cada módulo recibe un FakeHTTPClient que devuelve respuestas
canónicas para verificar su comportamiento de detección y anti-FP.
"""

from __future__ import annotations

import asyncio
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── Fake HTTP layer ──────────────────────────────────────────────────────────

class FakeResponse:
    """Mimics utils.http.Response."""

    def __init__(self, status: int = 200, headers=None, body: bytes = b"", url: str = ""):
        self.status  = status
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.body    = body
        self.url     = url
        self.text    = body.decode("utf-8", errors="ignore")

    def get_header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


class FakeHTTPClient:
    """
    Cliente HTTP que devuelve respuestas pre-programadas. Permite registrar
    handler(url, method, **kwargs) → FakeResponse para casos específicos.
    """

    def __init__(self, default: FakeResponse | None = None):
        self.default  = default or FakeResponse(404, body=b"Not Found")
        self.handlers = []  # list of (predicate, response_or_callable)
        self.calls    = []

    def add(self, url_substr: str, response: FakeResponse):
        self.handlers.append((lambda u, m, ss=url_substr: ss in u, response))

    def add_match(self, predicate, response):
        self.handlers.append((predicate, response))

    def _dispatch(self, url: str, method: str = "GET", **kwargs):
        self.calls.append((method, url))
        for pred, resp in self.handlers:
            try:
                if pred(url, method):
                    return resp
            except Exception:
                continue
        return self.default

    async def request(self, method, url, **kwargs):
        return self._dispatch(url, method, **kwargs)

    async def get(self, url, **kwargs):
        return self._dispatch(url, "GET", **kwargs)

    async def head(self, url, **kwargs):
        return self._dispatch(url, "HEAD", **kwargs)

    async def options_req(self, url, **kwargs):
        return self._dispatch(url, "OPTIONS", **kwargs)

    async def method_req(self, method, url, **kwargs):
        return self._dispatch(url, method, **kwargs)

    async def post_json(self, url, body, **kwargs):
        return self._dispatch(url, "POST", body=body, **kwargs)

    async def post_form(self, url, data, **kwargs):
        return self._dispatch(url, "POST", data=data, **kwargs)

    async def establish_baseline(self, base_url):
        pass

    def is_soft_404(self, hostname, status, body):
        return False


def _run(coro):
    return asyncio.run(coro)


# ─── Tests: headers module ────────────────────────────────────────────────────

class TestHeadersE2E(unittest.TestCase):
    def test_detects_missing_hsts(self):
        from modules import headers
        c = FakeHTTPClient()
        c.add("example.com", FakeResponse(
            200,
            headers={"content-type": "text/html"},
            body=b"<html><head><title>x</title></head><body>ok</body></html>",
            url="https://example.com",
        ))
        vulns, resp = _run(headers.run(c, "https://example.com"))
        titles = " ".join(v.title.lower() for v in vulns)
        self.assertIn("strict-transport-security", titles)

    def test_no_fp_when_all_headers_present(self):
        from modules import headers
        c = FakeHTTPClient()
        c.add("example.com", FakeResponse(
            200,
            headers={
                "content-type":              "text/html",
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "x-frame-options":           "DENY",
                "x-content-type-options":    "nosniff",
                "referrer-policy":           "no-referrer",
                "content-security-policy":   "default-src 'self'",
                "permissions-policy":        "geolocation=()",
                "cross-origin-opener-policy":   "same-origin",
                "cross-origin-resource-policy": "same-origin",
            },
            body=b"<html><head><title>x</title></head></html>",
        ))
        vulns, _ = _run(headers.run(c, "https://example.com"))
        missing = [v for v in vulns if "faltante" in v.title.lower()]
        self.assertEqual(missing, [], f"FP en headers: {[v.title for v in missing]}")


# ─── Tests: redirects module ──────────────────────────────────────────────────

class TestRedirectsE2E(unittest.TestCase):
    def test_no_fp_on_safe_redirect(self):
        from modules import redirects
        c = FakeHTTPClient(default=FakeResponse(200, body=b"<html>ok</html>"))
        vulns = _run(redirects.run(c, "https://example.com"))
        self.assertEqual(vulns, [])


# ─── Tests: http_methods module ───────────────────────────────────────────────

class TestHttpMethodsE2E(unittest.TestCase):
    def test_detects_trace_enabled(self):
        from modules import http_methods
        c = FakeHTTPClient(default=FakeResponse(405))
        c.add_match(
            lambda u, m: m == "TRACE",
            FakeResponse(200, headers={"content-type": "message/http"},
                         body=b"TRACE / HTTP/1.1\r\nHost: x\r\n\r\n"),
        )
        vulns = _run(http_methods.run(c, "https://example.com"))
        self.assertTrue(any("TRACE" in v.title for v in vulns),
                        f"TRACE no detectado en {[v.title for v in vulns]}")


# ─── Tests: csp_bypass module ─────────────────────────────────────────────────

class TestCspBypassE2E(unittest.TestCase):
    def test_detects_unsafe_eval(self):
        from modules import csp_bypass
        c = FakeHTTPClient()
        c.add("example.com", FakeResponse(
            200,
            headers={"content-security-policy":
                     "default-src 'self'; script-src 'self' 'unsafe-eval'"},
            body=b"ok",
        ))
        vulns = _run(csp_bypass.run(c, "https://example.com"))
        self.assertTrue(len(vulns) > 0,
                        "CSP con unsafe-eval debería generar al menos un hallazgo")


# ─── Tests: paths module (anti-FP soft-404) ───────────────────────────────────

class TestPathsE2E(unittest.TestCase):
    def test_no_fp_on_soft_404(self):
        """Si el server devuelve 200 con la misma página SPA en todo, no FPs.

        Mock: cualquier path responde 200 con la misma SPA → paths.py debe
        rechazarlos por content-validator (no son archivos reales).
        """
        from modules import paths

        spa = b"<html><head><title>App</title></head><body><div id=root></div></body></html>"

        class SoftSPAClient(FakeHTTPClient):
            def is_soft_404(self, hostname, status, body):
                # Simulamos que el cliente detecta soft-404 al ver la misma SPA
                return body == spa

        c = SoftSPAClient(default=FakeResponse(
            200, headers={"content-type": "text/html"}, body=spa))
        vulns, found = _run(paths.run(c, "https://example.com"))
        critical_or_high = [v for v in vulns if v.severity in ("CRITICAL", "HIGH")]
        self.assertEqual(critical_or_high, [],
                         f"FP en paths con soft-404: {[v.title for v in critical_or_high]}")


if __name__ == "__main__":
    unittest.main()
