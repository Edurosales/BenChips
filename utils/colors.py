"""
utils/colors.py — Colores ANSI y helpers de output en consola.
"""

import sys
import shutil

# ─── Paleta ───────────────────────────────────────────────────────────────────
R    = "\033[91m"
O    = "\033[93m"
Y    = "\033[33m"
G    = "\033[92m"
B    = "\033[94m"
M    = "\033[95m"
C    = "\033[96m"
W    = "\033[0m"
BOLD = "\033[1m"
DIM  = "\033[2m"
UL   = "\033[4m"
BG   = "\033[100m"

_COLOR_ENABLED = True


def disable_color():
    global R, O, Y, G, B, M, C, W, BOLD, DIM, UL, BG, _COLOR_ENABLED
    R=O=Y=G=B=M=C=W=BOLD=DIM=UL=BG=""
    _COLOR_ENABLED = False


def sev_color(s: str) -> str:
    return {"CRITICAL": R, "HIGH": O, "MEDIUM": Y, "LOW": G, "INFO": C}.get(s, W)


def sev_icon(s: str) -> str:
    return {"CRITICAL": "💀", "HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "INFO": "⚪"}.get(s, "⚪")


def sev_bg(s: str) -> str:
    """Color CSS para HTML reports."""
    return {"CRITICAL": "#ff3333", "HIGH": "#ff8800", "MEDIUM": "#ffcc00",
            "LOW": "#33cc33", "INFO": "#4dd0e1"}.get(s, "#aaa")


def term_width() -> int:
    return shutil.get_terminal_size((80, 20)).columns


def sep(char="═", color=None) -> str:
    width = min(term_width(), 78)
    line  = char * width
    c     = color or C
    return f"{BOLD}{c}{line}{W}"


def print_sep(char="═", color=None):
    print(sep(char, color))


def print_section(num: str, title: str):
    width = min(term_width(), 78)
    pad   = width - len(f"  {num} — {title}  ") - 2
    print(f"\n{BOLD}{BG}  {C}{num} — {title}{W}{BG}{' ' * max(0, pad)}  {W}")


def print_ok(msg: str, detail: str = ""):
    tail = f" {DIM}{detail}{W}" if detail else ""
    print(f"  {G}✓{W} {msg}{tail}")


def print_warn(msg: str):
    print(f"  {O}⚠{W}  {msg}")


def print_err(msg: str):
    print(f"  {R}✗{W}  {msg}")


def print_info(msg: str):
    print(f"  {C}→{W}  {DIM}{msg}{W}")


def print_vuln(idx: int, v):
    color = sev_color(v.severity)
    icon  = sev_icon(v.severity)
    ref   = f"\n       {BOLD}Referencia :{W} {DIM}{v.ref}{W}" if v.ref else ""
    url_line = f"\n       {BOLD}URL        :{W} {C}{v.url}{W}" if getattr(v, "url", "") else ""
    print(f"""
  {BOLD}{color}[{idx:02d}] {icon}  {v.title}{W}
       {BOLD}Severidad  :{W} {color}{v.severity}{W}  {DIM}CVSS {v.cvss:.1f}{W}
       {BOLD}Categoría  :{W} {v.category}{url_line}
       {BOLD}Descripción:{W} {v.description}
       {BOLD}Evidencia  :{W} {R}{v.evidence[:120]}{W}
       {BOLD}Fix        :{W} {G}➜ {v.fix}{W}{ref}
       {DIM}{'─' * 68}{W}""")


def progress_bar(done: int, total: int, label: str = ""):
    if total == 0:
        return
    pct  = int((done / total) * 30)
    bar  = f"{'█' * pct}{'░' * (30 - pct)}"
    perc = int(done / total * 100)
    print(f"\r  {C}[{bar}]{W} {perc:3d}%  {DIM}{label:<40}{W}", end="", flush=True)


def banner(version: str):
    print(f"""
{C}{BOLD}
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{W}{BOLD}  Pro v{version}{W}{DIM} — Scanner de vulnerabilidades web | Solo uso ético autorizado{W}
""")
