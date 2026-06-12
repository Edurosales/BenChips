"""Tests para comparación semver en modules/js_cve.py."""

from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest

from modules.js_cve import _parse_version, _is_vulnerable


class TestSemver(unittest.TestCase):
    def test_parse_basic(self):
        self.assertEqual(_parse_version("1.2.3"), (1, 2, 3))
        self.assertEqual(_parse_version("3.4"),   (3, 4, 0))
        self.assertEqual(_parse_version("2"),     (2, 0, 0))

    def test_parse_extra(self):
        # versiones con sufijos como '3.4.0-rc1' → (3,4,0)
        self.assertEqual(_parse_version("3.4.0-rc1"), (3, 4, 0))
        self.assertEqual(_parse_version("1.7.2.min"), (1, 7, 2))

    def test_is_vulnerable_basic(self):
        # jQuery 1.7.2 < 3.0.0 → vulnerable
        self.assertTrue(_is_vulnerable("1.7.2", "3.0.0"))
        # jQuery 3.5.0 >= 3.5.0 → no vulnerable
        self.assertFalse(_is_vulnerable("3.5.0", "3.5.0"))
        # jQuery 3.5.1 > 3.5.0 → no vulnerable
        self.assertFalse(_is_vulnerable("3.5.1", "3.5.0"))

    def test_real_world_jquery_3_4_x(self):
        # 3.4.1 < 3.5.0 → vulnerable a CVE-2020-11022/11023
        self.assertTrue(_is_vulnerable("3.4.1", "3.5.0"))
        # 3.5.0 ya tiene el fix
        self.assertFalse(_is_vulnerable("3.5.0", "3.5.0"))

    def test_lodash_critical_vs_high(self):
        # lodash 4.17.11 → vulnerable a la entrada CRITICAL (< 4.17.12)
        self.assertTrue(_is_vulnerable("4.17.11", "4.17.12"))
        # 4.17.20 ya no es crítica pero sí entra a la entrada HIGH (< 4.17.21)
        self.assertFalse(_is_vulnerable("4.17.20", "4.17.12"))
        self.assertTrue (_is_vulnerable("4.17.20", "4.17.21"))


if __name__ == "__main__":
    unittest.main()
