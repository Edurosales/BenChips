"""
mutmut_config.py — Configuración de mutation testing para BugBountyHunter Pro.

Mutation testing inserta bugs deliberados en el código (mutations) y verifica
que los tests los atrapan (mutation killed). Si un mutation sobrevive, indica
un test gap.

Uso:
  pip install mutmut
  mutmut run --paths-to-mutate=Vul/modules --tests-dir=Vul/tests
  mutmut results
  mutmut show <id>

Configuración: este archivo lo lee mutmut automáticamente vía mutmut_config.py.
"""

from __future__ import annotations


def pre_mutation(context):
    """Llamado antes de cada mutation. Skip mutations en docstrings/imports."""
    if context.current_source_line.strip().startswith(("#", '"""', "'''", "from ", "import ")):
        context.skip = True


def post_mutation(context):
    """Llamado después de cada mutation."""
    pass


# Paths que NO mutar (helpers / generated)
EXCLUDED_PATHS = [
    "Vul/tests/",
    "Vul/templates/",
    "Vul/__pycache__/",
    "Vul/ai_engine.py",     # depende de servicios externos; mutaciones inútiles
    "Vul/main.py",          # interactive flow; cubierto por integration tests
]


# Paths prioritarios (los más críticos para FP/correctness)
PRIORITY_PATHS = [
    "Vul/utils/vuln.py",     # CVSS, dedup
    "Vul/modules/js_cve.py", # semver
    "Vul/modules/paths.py",  # content validators
    "Vul/utils/http.py",     # baseline soft-404
    "Vul/modules/active.py", # SQLi/XSS/Traversal baselines
]
