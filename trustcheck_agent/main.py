from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from dotenv import load_dotenv

from .analyzer import analyze
from .models import (
    AnalyzeRequest,
    AnalyzeResponse,
    ScreenshotRequest,
    ScreenshotsRequest,
    ScreenshotsResponse,
)
from .screenshot import capture_screenshot, capture_screenshot_timeline


# Load environment variables from the repo root .env (so GEMINI_API_KEY works in local dev)
_HERE = Path(__file__).resolve()
_PY_AGENT_ROOT = _HERE.parents[1]  # python_agent/
_MONOREPO_ROOT = _HERE.parents[2]  # fraud-detector/ (when present)
load_dotenv(_PY_AGENT_ROOT / ".env", override=False)
load_dotenv(_MONOREPO_ROOT / ".env", override=False)

app = FastAPI(title="TrustCheck Python Agent", version="0.1.0")

_PLAYWRIGHT_CONCURRENCY = max(1, int(os.getenv("PLAYWRIGHT_CONCURRENCY", "1")))
_PLAYWRIGHT_ACQUIRE_TIMEOUT_S = float(os.getenv("PLAYWRIGHT_ACQUIRE_TIMEOUT_S", "0.25"))
_playwright_semaphore = asyncio.Semaphore(_PLAYWRIGHT_CONCURRENCY)


@asynccontextmanager
async def _playwright_slot():
    try:
        await asyncio.wait_for(_playwright_semaphore.acquire(), timeout=_PLAYWRIGHT_ACQUIRE_TIMEOUT_S)
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=503,
            detail="Agent busy (too many concurrent browser jobs). Please retry.",
            headers={"Retry-After": "2"},
        )
    try:
        yield
    finally:
        _playwright_semaphore.release()

def _cors_allow_origins() -> list[str]:
    raw = os.getenv("TRUSTCHECK_CORS_ORIGINS", "").strip()
    if not raw:
        return ["http://localhost:3000"]
    return [o.strip() for o in raw.split(",") if o.strip()]


# For local dev, this defaults to allowing http://localhost:3000.
# In production, set TRUSTCHECK_CORS_ORIGINS to your deployed frontend origins.
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_allow_origins(),
    allow_credentials=True,
    allow_methods=["*"] ,
    allow_headers=["*"],
)


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_endpoint(req: AnalyzeRequest):
    return analyze(req)


@app.post("/screenshot")
async def screenshot_endpoint(req: ScreenshotRequest):
    try:
        async with _playwright_slot():
            shot = await capture_screenshot(
                req.url,
                timeout_ms=req.timeout_ms,
                full_page=req.full_page,
            )
            return Response(content=shot.data, media_type=shot.mime, headers={"cache-control": "no-store"})
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Screenshot failed: {e}")


@app.post("/screenshots", response_model=ScreenshotsResponse)
async def screenshots_endpoint(req: ScreenshotsRequest):
    try:
        async with _playwright_slot():
            shots = await capture_screenshot_timeline(
                req.url,
                delays_ms=req.delays_ms,
                timeout_ms=req.timeout_ms,
                full_page=req.full_page,
            )
            return {"shots": shots}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Screenshot timeline failed: {e}")
