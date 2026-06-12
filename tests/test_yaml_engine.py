"""Tests para el motor YAML."""

from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest

from modules.yaml_engine import _eval_matcher, _match_word, _match_regex, _match_status


class TestMatchers(unittest.TestCase):
    def test_word_and(self):
        self.assertTrue(_match_word(["foo", "bar"], "this has foo and bar", "and"))
        self.assertFalse(_match_word(["foo", "missing"], "this has foo only", "and"))

    def test_word_or(self):
        self.assertTrue(_match_word(["foo", "bar"], "has bar only", "or"))
        self.assertFalse(_match_word(["a", "b"], "neither here", "or"))

    def test_regex(self):
        self.assertTrue(_match_regex([r"\d+"], "user42", "and"))
        self.assertFalse(_match_regex([r"^abc"], "xyz", "and"))

    def test_status(self):
        self.assertTrue(_match_status([200, 401], 200))
        self.assertFalse(_match_status([200, 401], 404))

    def test_negative_matcher(self):
        # invert=true: cuando NO matchea → True
        m = {"type": "word", "part": "body", "words": ["notfound"], "negative": True}
        self.assertTrue(_eval_matcher(m, "this body has nothing", "", 200))
        self.assertFalse(_eval_matcher(m, "this body has notfound", "", 200))

    def test_status_matcher_eval(self):
        m = {"type": "status", "status": [200]}
        self.assertTrue(_eval_matcher(m, "any body", "", 200))
        self.assertFalse(_eval_matcher(m, "any body", "", 404))


if __name__ == "__main__":
    unittest.main()
