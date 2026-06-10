"""
utils/terminal_render.py — Renderizado rico de reportes en terminal.

Si 'rich' está instalado, usa tablas y syntax highlighting.
Sin rich, fallback a ANSI plano (siempre funciona).
"""

from __future__ import annotations

from typing import Optional

from utils.vuln import Vuln, count_by_severity, risk_score


def _try_rich():
    try:
        from rich.console import Console  # type: ignore
        from rich.table   import Table   # type: ignore
        from rich.panel   import Panel   # type: ignore
        from rich.syntax  import Syntax  # type: ignore
        return Console, Table, Panel, Syntax
    except ImportError:
        return None


def render_summary(vulns: list[Vuln], url: str, duration: float) -> None:
    """Resumen ejecutivo en terminal."""
    counts       = count_by_severity(vulns)
    score, level = risk_score(counts)

    rich_mods = _try_rich()
    if rich_mods:
        Console, Table, Panel, _ = rich_mods
        c = Console()
        c.print(Panel.fit(
            f"[bold]Target:[/bold] {url}\n"
            f"[bold]Duration:[/bold] {duration:.1f}s\n"
            f"[bold]Risk Level:[/bold] {level} (score {score})",
            title="BugBountyHunter Pro",
            border_style="cyan",
        ))
        table = Table(title="Findings by Severity", header_style="bold")
        table.add_column("Severity")
        table.add_column("Count", justify="right")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            color = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow",
                     "LOW": "green", "INFO": "cyan"}[sev]
            table.add_row(f"[{color}]{sev}[/{color}]", str(counts[sev]))
        c.print(table)
        return

    # Fallback ANSI
    print(f"\n═══ {url} ═══")
    print(f"Duration: {duration:.1f}s | Risk: {level} (score {score})")
    for sev, n in counts.items():
        print(f"  {sev:9} {n}")


def render_vuln_detail(v: Vuln) -> None:
    """Render detallado de una vulnerabilidad."""
    rich_mods = _try_rich()
    if rich_mods:
        Console, _, Panel, Syntax = rich_mods
        c = Console()
        color = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow",
                 "LOW": "green", "INFO": "cyan"}.get(v.severity, "white")
        body = (
            f"[bold]Category:[/bold] {v.category}\n"
            f"[bold]CVSS:[/bold] {v.cvss}"
            f"{f' ({v.cvss_vector})' if v.cvss_vector else ''}\n"
            + (f"[bold]CWE:[/bold] {v.cwe}\n" if v.cwe else "")
            + (f"[bold]URL:[/bold] {v.url}\n" if v.url else "")
            + f"\n[bold]Description:[/bold]\n{v.description}\n"
            + f"\n[bold]Evidence:[/bold]\n{v.evidence}\n"
            + f"\n[bold]Fix:[/bold]\n{v.fix}"
        )
        c.print(Panel(body, title=f"[{color}]{v.severity}[/{color}] {v.title}",
                      border_style=color))
        return

    print(f"\n[{v.severity}] {v.title}")
    print(f"  Category: {v.category} | CVSS: {v.cvss}")
    if v.url:
        print(f"  URL: {v.url}")
    print(f"  {v.description[:200]}")
    print(f"  Evidence:\n  {v.evidence[:300]}")
    print(f"  Fix: {v.fix[:200]}")
