"""
tests/test_integration_dvwa.py — Integration tests contra DVWA / Juice Shop.

Requiere un container corriendo localmente:
  docker run -p 1335:80 vulnerables/web-dvwa
  docker run -p 3000:3000 bkimminich/juice-shop

Si los targets no responden, los tests se SKIPean.
NO se ejecutan en run_all.py por default — invocar con:
  python -m unittest tests.test_integration_dvwa
"""

from __future__ import annotations

import asyncio
import os
import sys
import unittest
from urllib.request import urlopen
from urllib.error   import URLError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


_DVWA_URL       = os.environ.get("DVWA_URL",       "http://localhost:1335/")
_JUICESHOP_URL  = os.environ.get("JUICESHOP_URL",  "http://localhost:3000/")


def _is_up(url: str, timeout: int = 2) -> bool:
    try:
        urlopen(url, timeout=timeout)
        return True
    except (URLError, Exception):
        return False


@unittest.skipUnless(_is_up(_DVWA_URL), "DVWA not running at " + _DVWA_URL)
class TestDVWAIntegration(unittest.TestCase):
    def test_detects_sqli_on_dvwa(self):
        from scanner import scan
        async def _go():
            vulns, meta, dur = await scan(
                _DVWA_URL,
                full_scan=False,
                active_scan=True,
                scan_ports=False,
                use_oob=False,
            )
            return vulns
        vulns = asyncio.run(_go())
        cats = {v.category.lower() for v in vulns}
        # DVWA tiene SQLi, XSS, command injection — esperamos al menos uno
        self.assertTrue(
            any("sql" in c or "xss" in c or "injection" in c for c in cats),
            f"Esperaba SQLi/XSS en DVWA, encontré: {cats}"
        )


@unittest.skipUnless(_is_up(_JUICESHOP_URL), "Juice Shop not running at " + _JUICESHOP_URL)
class TestJuiceShopIntegration(unittest.TestCase):
    def test_detects_security_headers_missing(self):
        from scanner import scan
        async def _go():
            vulns, meta, dur = await scan(
                _JUICESHOP_URL,
                full_scan=False,
                active_scan=False,
                scan_ports=False,
                use_oob=False,
            )
            return vulns
        vulns = asyncio.run(_go())
        titles = " ".join(v.title.lower() for v in vulns)
        self.assertIn("content-security-policy", titles)


if __name__ == "__main__":
    unittest.main()
