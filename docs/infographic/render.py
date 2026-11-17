"""Regenerate the agentsec infographic PNGs from the HTML variants.

Dev-only docs tool (NOT part of the stdlib-only package). Requires Playwright + Chromium:

    uv run --with playwright python -m playwright install chromium
    uv run --with playwright python docs/infographic/render.py

Screenshots the `.sheet` element at device_scale_factor=2 so the output pixel
dimensions match the committed exports (portrait 2960w, landscape 4640w).
"""
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
# viewport width must exceed the sheet max-width AND clear the 1080px multi-column
# media-query breakpoint so the full desktop layout renders.
SPECS = [
    ("agentsec_infographic.html", 1600),
    ("agentsec_infographic_landscape.html", 2450),
]


def main() -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for name, vw in SPECS:
            page = browser.new_page(viewport={"width": vw, "height": 2000},
                                    device_scale_factor=2)
            page.goto((HERE / name).as_uri())
            page.wait_for_timeout(400)  # let fonts/layout settle
            sheet = page.query_selector(".sheet")
            assert sheet is not None, f"no .sheet in {name}"
            out = HERE / name.replace(".html", ".png")
            sheet.screenshot(path=str(out))
            print(f"wrote {out.name}")
        browser.close()


if __name__ == "__main__":
    main()
