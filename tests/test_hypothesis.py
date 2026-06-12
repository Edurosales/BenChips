"""
tests/test_hypothesis.py — Property-based testing con Hypothesis.

Si Hypothesis no está instalado, los tests se SKIPean en lugar de fallar.

Hypothesis genera casos automáticamente intentando minimizar fallos.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


try:
    from hypothesis            import given, strategies as st, settings, HealthCheck
    _HAS_HYPOTHESIS = True
except ImportError:
    _HAS_HYPOTHESIS = False

    # Stubs para que las clases parseen aunque hypothesis no esté
    def given(*a, **kw):
        def deco(fn):
            return fn
        return deco

    def settings(*a, **kw):
        def deco(fn):
            return fn
        return deco

    class _Stub:
        def integers(self, **kw):       return None
        def text(self, **kw):           return None
        def sampled_from(self, *a, **kw): return None

    st = _Stub()
    HealthCheck = type("HC", (), {"too_slow": None})


from modules.js_cve  import _parse_version, _is_vulnerable
from utils.vuln      import cvss3_score_from_vector


@unittest.skipUnless(_HAS_HYPOTHESIS, "hypothesis not installed")
class TestHypothesisSemver(unittest.TestCase):
    @given(st.integers(min_value=0, max_value=999),
           st.integers(min_value=0, max_value=999),
           st.integers(min_value=0, max_value=999))
    def test_parse_roundtrip(self, a, b, c):
        v = f"{a}.{b}.{c}"
        t = _parse_version(v)
        self.assertEqual(t, (a, b, c))

    @given(st.text(min_size=0, max_size=50))
    def test_parse_no_crash(self, garbage):
        t = _parse_version(garbage)
        self.assertEqual(len(t), 3)
        for n in t:
            self.assertGreaterEqual(n, 0)

    @given(st.integers(min_value=0, max_value=100),
           st.integers(min_value=0, max_value=100),
           st.integers(min_value=0, max_value=100))
    def test_reflexive_not_vulnerable(self, a, b, c):
        v = f"{a}.{b}.{c}"
        self.assertFalse(_is_vulnerable(v, v))


@unittest.skipUnless(_HAS_HYPOTHESIS, "hypothesis not installed")
class TestHypothesisCVSS(unittest.TestCase):
    @given(
        av=st.sampled_from(["N", "A", "L", "P"]),
        ac=st.sampled_from(["L", "H"]),
        pr=st.sampled_from(["N", "L", "H"]),
        ui=st.sampled_from(["N", "R"]),
        s =st.sampled_from(["U", "C"]),
        c =st.sampled_from(["H", "L", "N"]),
        i =st.sampled_from(["H", "L", "N"]),
        a =st.sampled_from(["H", "L", "N"]),
    )
    @settings(suppress_health_check=[HealthCheck.too_slow], max_examples=50)
    def test_score_in_range(self, av, ac, pr, ui, s, c, i, a):
        vec = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
        score = cvss3_score_from_vector(vec)
        self.assertIsNotNone(score)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 10.0)


if __name__ == "__main__":
    unittest.main()
