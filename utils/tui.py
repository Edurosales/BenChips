"""
utils/tui.py — Dashboard live durante el scan (Textual TUI).

Muestra:
  - Progreso de cada fase (recon/headers/active/etc).
  - Vulns en tiempo real (lista actualizable).
  - Estadísticas: bytes enviados, requests/seg, 429s observados.

Si Textual no está instalado, fallback a print() con tqdm-like progress.

Uso desde main.py / cli.py:
  from utils.tui import VulnDashboard
  dashboard = VulnDashboard()
  await dashboard.run_alongside(scan_coroutine)
"""

from __future__ import annotations

import asyncio
from typing import Optional


def _has_textual() -> bool:
    try:
        import textual  # noqa: F401
        return True
    except ImportError:
        return False


# ─── State shared entre TUI y scan ────────────────────────────────────────────

class ScanState:
    def __init__(self):
        self.phase:           str = "starting"
        self.phase_progress:  float = 0.0
        self.vulns_count:     dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        self.recent_vulns:    list[str] = []
        self.requests_sent:   int = 0
        self.rate_429:        int = 0
        self.done:            bool = False

    def add_vuln(self, severity: str, title: str):
        self.vulns_count[severity] = self.vulns_count.get(severity, 0) + 1
        self.recent_vulns.insert(0, f"[{severity}] {title}")
        self.recent_vulns = self.recent_vulns[:30]

    def update_phase(self, phase: str, progress: float = 0.0):
        self.phase = phase
        self.phase_progress = progress


# ─── Textual variant ──────────────────────────────────────────────────────────

def _build_textual_app(state: ScanState):
    from textual.app        import App, ComposeResult
    from textual.widgets    import Header, Footer, Static, DataTable, ProgressBar
    from textual.containers import Horizontal, Vertical

    class _Dashboard(App):
        CSS = """
        #left  { width: 60%; }
        #right { width: 40%; }
        """

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Horizontal():
                with Vertical(id="left"):
                    yield Static("Phase: starting", id="phase")
                    yield ProgressBar(total=100, id="progress")
                    yield DataTable(id="vulns_table")
                with Vertical(id="right"):
                    yield Static("Stats", id="stats")
                    yield Static("",       id="recent")
            yield Footer()

        def on_mount(self) -> None:
            table = self.query_one("#vulns_table", DataTable)
            table.add_columns("Severity", "Count")
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                table.add_row(sev, "0")
            self.set_interval(0.5, self.refresh_state)

        def refresh_state(self) -> None:
            self.query_one("#phase",    Static).update(f"Phase: {state.phase}")
            self.query_one("#progress", ProgressBar).update(progress=int(state.phase_progress * 100))
            table = self.query_one("#vulns_table", DataTable)
            for i, sev in enumerate(("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")):
                table.update_cell_at((i, 1), str(state.vulns_count.get(sev, 0)))
            self.query_one("#stats", Static).update(
                f"Requests: {state.requests_sent}\n429 seen: {state.rate_429}"
            )
            self.query_one("#recent", Static).update("\n".join(state.recent_vulns[:15]))
            if state.done:
                self.exit()

    return _Dashboard()


# ─── Plain fallback ───────────────────────────────────────────────────────────

async def _plain_dashboard(state: ScanState):
    """Fallback sin Textual: prints periódicos."""
    while not state.done:
        print(f"\r[Phase {state.phase}] "
              f"C:{state.vulns_count['CRITICAL']} H:{state.vulns_count['HIGH']} "
              f"M:{state.vulns_count['MEDIUM']} L:{state.vulns_count['LOW']} "
              f"req={state.requests_sent}", end="", flush=True)
        await asyncio.sleep(1)
    print()


class VulnDashboard:
    """Wrapper que elige Textual o plain según disponibilidad."""

    def __init__(self):
        self.state = ScanState()

    async def run_alongside(self, scan_coro):
        """Run scan + dashboard concurrentemente."""
        if _has_textual():
            app = _build_textual_app(self.state)
            scan_task = asyncio.create_task(self._run_scan(scan_coro))
            await app.run_async()
            return await scan_task
        else:
            tui_task  = asyncio.create_task(_plain_dashboard(self.state))
            result    = await scan_coro
            self.state.done = True
            await tui_task
            return result

    async def _run_scan(self, scan_coro):
        try:
            return await scan_coro
        finally:
            self.state.done = True
