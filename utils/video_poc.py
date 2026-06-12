"""
utils/video_poc.py — Captura de video/GIF del PoC vía Playwright.

Reproduce los steps del exploit (provistos como instrucciones simples) y
genera un .mp4 o .gif para adjuntar al reporte.

Uso:
  python -m utils.video_poc --url https://target/?q=<payload> --steps steps.json --out poc.webm

Steps JSON format:
  [
    {"action": "goto", "url": "..."},
    {"action": "fill", "selector": "#email", "value": "x@x"},
    {"action": "click", "selector": "button[type=submit]"},
    {"action": "wait", "ms": 1500},
    {"action": "screenshot", "path": "result.png"}
  ]

Requiere: pip install playwright && playwright install chromium
"""

from __future__ import annotations

import asyncio
import json
from typing import Optional


def _has_playwright() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


async def record_poc(steps: list[dict], out_path: str = "poc.webm",
                     width: int = 1280, height: int = 720,
                     headless: bool = True) -> dict:
    """
    Ejecuta los steps grabando video. Devuelve {ok, video_path, errors}.
    """
    if not _has_playwright():
        return {"ok": False, "error": "playwright not installed"}

    from playwright.async_api import async_playwright  # type: ignore

    errors = []
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=headless)
            context = await browser.new_context(
                viewport={"width": width, "height": height},
                record_video_dir=".",
                record_video_size={"width": width, "height": height},
            )
            page = await context.new_page()

            for step in steps:
                a = step.get("action")
                try:
                    if a == "goto":
                        await page.goto(step["url"], timeout=15000)
                    elif a == "fill":
                        await page.fill(step["selector"], step["value"])
                    elif a == "click":
                        await page.click(step["selector"])
                    elif a == "wait":
                        await page.wait_for_timeout(step.get("ms", 1000))
                    elif a == "screenshot":
                        await page.screenshot(path=step.get("path", "step.png"))
                    elif a == "evaluate":
                        await page.evaluate(step["script"])
                except Exception as e:
                    errors.append({"step": step, "error": str(e)})

            video = page.video
            await context.close()
            await browser.close()

            video_path = await video.path() if video else None
            if video_path and video_path != out_path:
                import os, shutil
                try:
                    shutil.move(video_path, out_path)
                except Exception:
                    out_path = video_path

            return {"ok": True, "video_path": out_path, "errors": errors}
    except Exception as e:
        return {"ok": False, "error": str(e), "errors": errors}


def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--steps", required=True, help="JSON file con steps")
    p.add_argument("--out",   default="poc.webm")
    p.add_argument("--head",  action="store_true", help="No headless (mostrar browser)")
    args = p.parse_args()

    with open(args.steps, "r", encoding="utf-8") as f:
        steps = json.load(f)

    r = asyncio.run(record_poc(steps, args.out, headless=not args.head))
    print(json.dumps(r, indent=2))


if __name__ == "__main__":
    main()
