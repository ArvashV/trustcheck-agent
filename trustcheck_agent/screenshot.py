from __future__ import annotations

import base64
from dataclasses import dataclass

from playwright.async_api import async_playwright


@dataclass(frozen=True)
class ScreenshotResult:
    mime: str
    data: bytes


@dataclass(frozen=True)
class TimelineShot:
    at_ms: int
    mime: str
    data_base64: str


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


async def capture_screenshot_timeline(
    url: str,
    *,
    delays_ms: list[int],
    timeout_ms: int = 20000,
    full_page: bool = False,
) -> list[TimelineShot]:
    safe_delays = [int(d) for d in (delays_ms or []) if isinstance(d, int) or str(d).isdigit()]
    safe_delays = [d for d in safe_delays if 0 <= d <= 15000]
    if not safe_delays:
        safe_delays = [1000, 3000, 5000]
    safe_delays = sorted(set(safe_delays))[:6]

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

            # Small stabilization window for client-side rendering.
            await page.wait_for_timeout(250)

            shots: list[TimelineShot] = []
            last = 0
            for d in safe_delays:
                delta = max(0, d - last)
                if delta:
                    await page.wait_for_timeout(delta)
                last = d
                png = await page.screenshot(type="png", full_page=full_page)
                shots.append(
                    TimelineShot(
                        at_ms=d,
                        mime="image/png",
                        data_base64=base64.b64encode(png).decode("ascii"),
                    )
                )
            return shots
        finally:
            await context.close()
            await browser.close()
from __future__ import annotations

import base64
from dataclasses import dataclass

from playwright.async_api import async_playwright


@dataclass(frozen=True)
class ScreenshotResult:
    mime: str
    data: bytes


@dataclass(frozen=True)
class TimelineShot:
    at_ms: int
    mime: str
    data_base64: str


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


async def capture_screenshot_timeline(
    url: str,
    *,
    delays_ms: list[int],
    timeout_ms: int = 20000,
    full_page: bool = False,
) -> list[TimelineShot]:
    safe_delays = [int(d) for d in (delays_ms or []) if isinstance(d, int) or str(d).isdigit()]
    safe_delays = [d for d in safe_delays if 0 <= d <= 15000]
    if not safe_delays:
        safe_delays = [1000, 3000, 5000]
    safe_delays = sorted(set(safe_delays))[:6]

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

            # Small stabilization window for client-side rendering.
            await page.wait_for_timeout(250)

            shots: list[TimelineShot] = []
            last = 0
            for d in safe_delays:
                delta = max(0, d - last)
                if delta:
                    await page.wait_for_timeout(delta)
                last = d
                png = await page.screenshot(type="png", full_page=full_page)
                shots.append(
                    TimelineShot(
                        at_ms=d,
                        mime="image/png",
                        data_base64=base64.b64encode(png).decode("ascii"),
                    )
                )
            return shots
        finally:
            await context.close()
            await browser.close()
