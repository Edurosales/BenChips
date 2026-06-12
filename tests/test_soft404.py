"""Tests para Baseline / soft-404 en utils/http.py."""

from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest

from utils.http import Baseline


class TestBaseline(unittest.TestCase):
    def test_extract_title(self):
        body = b"<html><head><title>Hello World</title></head></html>"
        self.assertEqual(Baseline._extract_title(body), "hello world")

    def test_extract_title_missing(self):
        self.assertEqual(Baseline._extract_title(b"<html></html>"), "")

    def test_soft404_same_hash(self):
        body = b"<html>404 not found page</html>" * 50
        bl = Baseline(200, body)
        self.assertTrue(bl.is_soft_404(200, body))

    def test_soft404_different_size(self):
        bl = Baseline(200, b"<html>A</html>" * 100)
        # Body 10x más grande → no es soft-404
        self.assertFalse(bl.is_soft_404(200, b"<html>X</html>" * 1000))

    def test_soft404_similar_size_same_title(self):
        body1 = b"<html><title>Page Not Found</title>" + b"x" * 500 + b"</html>"
        body2 = b"<html><title>Page Not Found</title>" + b"y" * 510 + b"</html>"
        bl = Baseline(200, body1)
        self.assertTrue(bl.is_soft_404(200, body2))

    def test_no_soft404_on_404_status(self):
        # Si el baseline tenía 404 → no se aplica la heurística
        bl = Baseline(404, b"<html>Not Found</html>")
        self.assertFalse(bl.is_soft_404(404, b"<html>Not Found</html>"))


if __name__ == "__main__":
    unittest.main()
