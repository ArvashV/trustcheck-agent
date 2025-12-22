from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from dotenv import load_dotenv

from .analyzer import analyze
from .models import AnalyzeRequest, AnalyzeResponse


# Load environment variables from the repo root .env (so GEMINI_API_KEY works in local dev)
_HERE = Path(__file__).resolve()
_PY_AGENT_ROOT = _HERE.parents[1]  # python_agent/
_MONOREPO_ROOT = _HERE.parents[2]  # fraud-detector/ (when present)
load_dotenv(_PY_AGENT_ROOT / ".env", override=False)
load_dotenv(_MONOREPO_ROOT / ".env", override=False)

app = FastAPI(title="TrustCheck Python Agent", version="0.1.0")

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
