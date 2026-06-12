"""
tests/test_property_semver.py — Property-style tests para semver y CVSS.

No usamos Hypothesis (dependencia extra). En lugar de eso, generamos casos
aleatorios deterministas con seed fijo y verificamos invariantes.
"""

from __future__ import annotations

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.js_cve import _parse_version, _is_vulnerable
from utils.vuln import cvss3_score_from_vector, cvss_severity


class TestSemverProperties(unittest.TestCase):
    """Verifica invariantes formales del parser y comparador semver."""

    def setUp(self):
        self.rng = random.Random(42)

    def _rand_version(self) -> str:
        parts = [str(self.rng.randint(0, 99))
                 for _ in range(self.rng.randint(1, 4))]
        return ".".join(parts)

    def test_parse_returns_3_tuple_always(self):
        for _ in range(200):
            v = self._rand_version()
            parsed = _parse_version(v)
            self.assertEqual(len(parsed), 3,
                             f"_parse_version({v!r}) returned {parsed!r}")
            for n in parsed:
                self.assertIsInstance(n, int)
                self.assertGreaterEqual(n, 0)

    def test_parse_is_idempotent(self):
        """parse(str(parse(v))) == parse(v) — round-trip canónico."""
        for _ in range(100):
            v = self._rand_version()
            t1 = _parse_version(v)
            canonical = ".".join(str(n) for n in t1)
            t2 = _parse_version(canonical)
            self.assertEqual(t1, t2)

    def test_reflexive_not_vulnerable(self):
        """version < version NUNCA, por lo tanto _is_vulnerable(v, v) == False."""
        for _ in range(100):
            v = self._rand_version()
            self.assertFalse(_is_vulnerable(v, v),
                             f"_is_vulnerable({v!r}, {v!r}) debe ser False")

    def test_total_order(self):
        """Para 3 versiones: si A<B y B<C ⇒ A<C (transitividad)."""
        for _ in range(50):
            a = self._rand_version()
            b = self._rand_version()
            c = self._rand_version()
            ta, tb, tc = _parse_version(a), _parse_version(b), _parse_version(c)
            if ta < tb < tc:
                self.assertTrue(_is_vulnerable(a, c))

    def test_lower_bound_always_vulnerable(self):
        """0.0.0 siempre es vulnerable contra cualquier max_fixed > 0."""
        for _ in range(50):
            v = self._rand_version()
            if _parse_version(v) > (0, 0, 0):
                self.assertTrue(_is_vulnerable("0.0.0", v))

    def test_garbage_does_not_crash(self):
        """Strings raros no deben petar; deben dar (0,0,0) o algo parseable."""
        for garbage in ["", "abc", "...", "v", "v1", "1.x.y", "1.7.2-beta.3",
                         "3.4.0-rc1+sha.abc", "1.7.2.min.gz"]:
            t = _parse_version(garbage)
            self.assertEqual(len(t), 3)


class TestCVSSProperties(unittest.TestCase):
    """Invariantes del calculador CVSS v3.1."""

    def test_score_in_valid_range(self):
        """Todos los vectores válidos producen score en [0.0, 10.0]."""
        vectors = [
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
        ]
        for v in vectors:
            s = cvss3_score_from_vector(v)
            self.assertIsNotNone(s, f"vector válido falló: {v}")
            self.assertGreaterEqual(s, 0.0)
            self.assertLessEqual(s, 10.0)

    def test_critical_higher_than_high(self):
        """RCE no-auth (CRITICAL) > XSS reflejado (MEDIUM)."""
        rce_score = cvss3_score_from_vector(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        xss_score = cvss3_score_from_vector(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
        self.assertGreater(rce_score, xss_score)

    def test_severity_thresholds(self):
        self.assertEqual(cvss_severity(0.0),  "INFO")
        self.assertEqual(cvss_severity(3.9),  "LOW")
        self.assertEqual(cvss_severity(4.0),  "MEDIUM")
        self.assertEqual(cvss_severity(6.9),  "MEDIUM")
        self.assertEqual(cvss_severity(7.0),  "HIGH")
        self.assertEqual(cvss_severity(8.9),  "HIGH")
        self.assertEqual(cvss_severity(9.0),  "CRITICAL")
        self.assertEqual(cvss_severity(10.0), "CRITICAL")

    def test_invalid_vector_returns_none(self):
        for bad in ["", "garbage", "CVSS:2.0/AV:N", "CVSS:3.1/AV:N", "X:Y"]:
            self.assertIsNone(cvss3_score_from_vector(bad))


if __name__ == "__main__":
    unittest.main()
