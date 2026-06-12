"""Tests de validación de contenido en modules/paths.py."""

from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest

from modules.paths import (
    _validate_env, _validate_git_config, _validate_passwd,
    _validate_php_config, _validate_sql_dump, _validate_actuator,
    _validate_path_content, _looks_like_html,
)


class TestContentValidators(unittest.TestCase):
    def test_env_real(self):
        body = b"APP_KEY=abc123\nDB_PASSWORD=secret\nAPP_ENV=production\n"
        self.assertTrue(_validate_env(body))

    def test_env_spa_index_is_fp(self):
        body = b"<!DOCTYPE html><html><head><title>App</title></head><body>SPA</body></html>"
        self.assertFalse(_validate_env(body))

    def test_env_empty_is_fp(self):
        self.assertFalse(_validate_env(b""))

    def test_git_config_real(self):
        body = b"[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@github.com:x/y.git"
        self.assertTrue(_validate_git_config(body))

    def test_git_config_spa(self):
        body = b"<!doctype html><html>...</html>"
        self.assertFalse(_validate_git_config(body))

    def test_passwd_real(self):
        body = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        self.assertTrue(_validate_passwd(body))

    def test_passwd_tutorial_text_is_fp(self):
        body = b"<p>The line root:x:0:0 means the user has UID 0</p>"
        self.assertFalse(_validate_passwd(body))

    def test_php_config(self):
        body = b"<?php\ndefine('DB_PASSWORD', 'secret123');\n?>"
        self.assertTrue(_validate_php_config(body))

    def test_php_rendered_is_fp(self):
        body = b"<!DOCTYPE html><html><body><h1>WordPress</h1></body></html>"
        self.assertFalse(_validate_php_config(body))

    def test_actuator_json(self):
        body = b'{"_links":{"self":{"href":"http://x/actuator"}},"status":"UP"}'
        self.assertTrue(_validate_actuator(body))

    def test_actuator_html_is_fp(self):
        body = b"<html><body>Not Found</body></html>"
        self.assertFalse(_validate_actuator(body))

    def test_sql_dump_real(self):
        body = b"-- MySQL dump 10.13  Distrib 8.0\nCREATE TABLE users (id INT);"
        self.assertTrue(_validate_sql_dump(body))


class TestPathDispatcher(unittest.TestCase):
    def test_env_dispatch(self):
        valid, _ = _validate_path_content("/.env", b"APP_KEY=x\nDB_HOST=localhost\n")
        self.assertTrue(valid)

    def test_env_html_dispatch_rejects(self):
        valid, reason = _validate_path_content("/.env", b"<!doctype html><html></html>")
        self.assertFalse(valid)
        self.assertIn("contenido no coincide", reason)


if __name__ == "__main__":
    unittest.main()
