from __future__ import annotations

from dataclasses import dataclass

from playwright.async_api import async_playwright


@dataclass(frozen=True)
class ScreenshotResult:
    mime: str
    data: bytes


async def capture_screenshot(
    url: str,
    *,
    timeout_ms: int = 12000,
    full_page: bool = False,
) -> ScreenshotResult:
    # Notes:
    # - We keep this very defensive: short timeouts, no persistent storage.
    # - This is intended for server-to-server usage.
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        )
        context = await browser.new_context(
            viewport={"width": 1365, "height": 768},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 TrustCheckScreenshot/1.0"
            ),
            java_script_enabled=True,
            ignore_https_errors=True,
        )
        page = await context.new_page()

        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            # Best-effort: give client-side apps a moment.
            await page.wait_for_timeout(450)
            data = await page.screenshot(type="png", full_page=full_page)
            return ScreenshotResult(mime="image/png", data=data)
        finally:
            await context.close()
            await browser.close()
