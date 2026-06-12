"""Tests para utils/vuln.py — modelo, CVSS, deduplicación."""

from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest

from utils.vuln import (
    Vuln, make_vuln, deduplicate, count_by_severity, risk_score,
    cvss3_score_from_vector, cvss_severity, validate_cvss_vector,
)


class TestCVSS(unittest.TestCase):
    def test_critical_rce_vector(self):
        # RCE clásico: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score = cvss3_score_from_vector(v)
        self.assertEqual(score, 9.8)
        self.assertEqual(cvss_severity(score), "CRITICAL")

    def test_xss_reflected_vector(self):
        # XSS reflejado típico: AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N → 6.1
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        score = cvss3_score_from_vector(v)
        self.assertEqual(score, 6.1)
        self.assertEqual(cvss_severity(score), "MEDIUM")

    def test_invalid_vector(self):
        self.assertIsNone(cvss3_score_from_vector("invalid"))
        self.assertIsNone(cvss3_score_from_vector(""))
        self.assertFalse(validate_cvss_vector("CVSS:2.0/AV:N/AC:L"))

    def test_severity_thresholds(self):
        self.assertEqual(cvss_severity(0.0),  "INFO")
        self.assertEqual(cvss_severity(0.1),  "LOW")
        self.assertEqual(cvss_severity(3.9),  "LOW")
        self.assertEqual(cvss_severity(4.0),  "MEDIUM")
        self.assertEqual(cvss_severity(6.9),  "MEDIUM")
        self.assertEqual(cvss_severity(7.0),  "HIGH")
        self.assertEqual(cvss_severity(8.9),  "HIGH")
        self.assertEqual(cvss_severity(9.0),  "CRITICAL")
        self.assertEqual(cvss_severity(10.0), "CRITICAL")

    def test_vector_autoderive_severity(self):
        """Si Vuln recibe un vector válido, severity debe alinearse con el score."""
        v = make_vuln(
            "Test", "LOW", 1.0, "Cat", "desc", "ev", "fix",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
        self.assertEqual(v.cvss, 9.8)
        self.assertEqual(v.severity, "CRITICAL")


class TestDedup(unittest.TestCase):
    def test_dedup_keeps_highest(self):
        a = make_vuln("XSS", "LOW",      3.1, "XSS", "d", "e", "f", url="https://a.com/x")
        b = make_vuln("XSS", "CRITICAL", 9.8, "XSS", "d", "e", "f", url="https://a.com/x")
        result = deduplicate([a, b])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].severity, "CRITICAL")

    def test_dedup_different_urls(self):
        a = make_vuln("XSS", "HIGH", 7.5, "XSS", "d", "e", "f", url="https://a.com/x")
        b = make_vuln("XSS", "HIGH", 7.5, "XSS", "d", "e", "f", url="https://a.com/y")
        result = deduplicate([a, b])
        self.assertEqual(len(result), 2)

    def test_count_and_score(self):
        vs = [
            make_vuln("a", "CRITICAL", 9.8, "c", "d", "e", "f", url="https://1"),
            make_vuln("b", "HIGH",     7.5, "c", "d", "e", "f", url="https://2"),
            make_vuln("c", "MEDIUM",   5.0, "c", "d", "e", "f", url="https://3"),
            make_vuln("d", "LOW",      3.0, "c", "d", "e", "f", url="https://4"),
        ]
        counts = count_by_severity(vs)
        self.assertEqual(counts["CRITICAL"], 1)
        self.assertEqual(counts["HIGH"],     1)
        score, level = risk_score(counts)
        self.assertEqual(score, 10 + 7 + 4 + 1)
        self.assertEqual(level, "ALTO")


if __name__ == "__main__":
    unittest.main()
