# TrustCheck — AI-Powered Visual Scam Detection

> Built with **Gemini 3 Flash** | Multimodal Vision + Code Execution + Google Search Grounding

TrustCheck analyzes any website and tells you if it's safe — using AI that can **see** the page, **read** the content, and **search** the web for verification.

## What It Does

Paste a URL → Get a comprehensive trust report in 15-30 seconds:

- **0-100 Trust Score** with explainability
- **Visual Scam Detection** — Gemini 3 analyzes a screenshot using code execution
- **AI Summary** — Deep reasoning with `thinking_level="HIGH"` across 35+ signals
- **Google Search Grounding** — Real-time web verification
- **20+ Explainability Items** — Security, identity, content, pricing, urgency tactics

## Three Gemini 3 Features

### 1. Multimodal Vision
The homepage screenshot is sent alongside crawled text to Gemini 3, giving it both textual AND visual context for holistic judgment.

```python
parts = [
    types.Part.from_bytes(data=screenshot_bytes, mime_type="image/png"),
    types.Part.from_text(text=analysis_prompt)
]
```

### 2. Code Execution
A separate Gemini 3 call receives the screenshot with `code_execution` enabled. The model writes and runs Python code to programmatically detect fake trust badges, countdown timers, stock photos, template-clone layouts, and popup overlays.

```python
config = types.GenerateContentConfig(
    tools=[types.Tool(code_execution=types.ToolCodeExecution())],
)
```

### 3. Google Search Grounding
The AI judge has `GoogleSearch` tool access, enabling real-time verification against live web data — scam reports, business registrations, news.

```python
tools = [types.Tool(googleSearch=types.GoogleSearch())]
thinking_config = types.ThinkingConfig(thinking_level="HIGH")
```

## Architecture

```
URL Input → Parallel Data Gathering (7 concurrent tasks)
             ├── RDAP domain age lookup
             ├── HTTP fetch + redirect analysis
             ├── TLS certificate inspection
             ├── robots.txt analysis
             ├── Playwright screenshot capture
             ├── Spider crawl (up to 30 pages)
             └── External reviews (Trustpilot, SiteJabber, ScamAdviser)
                    ↓
           12 Signal Extractors
             ├── Social media links    ├── Payment providers
             ├── Phone numbers         ├── Urgency/pressure tactics
             ├── Price anomalies       ├── Meta tag completeness
             ├── Copyright freshness   ├── Social proof widgets
             ├── Outbound links        ├── Cookie/GDPR compliance
             ├── Ownership identity    └── Language quality
                    ↓
           Two Parallel Gemini 3 Calls
             ├── Main Judge (text + screenshot + search grounding + thinking)
             └── Visual Analyzer (screenshot + code execution)
                    ↓
           Score (0-100) + 20+ Explainability Items + Recommendations
```

## Requirements
- Python 3.10+
- `GEMINI_API_KEY` environment variable

## Install & Run

```bash
# Install
python -m venv .venv
.\.venv\Scripts\Activate.ps1   # Windows
# source .venv/bin/activate    # Linux/Mac

pip install -U pip
pip install -e .
playwright install chromium

# Set API key
echo "GEMINI_API_KEY=your_key_here" > .env

# Run
uvicorn trustcheck_agent.main:app --host 0.0.0.0 --port 8000
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/analyze` | Full trust analysis with AI |
| `POST` | `/screenshot` | Capture PNG screenshot |
| `POST` | `/screenshots` | Timeline screenshot capture |
| `GET` | `/healthz` | Health check |

```bash
curl -X POST http://localhost:8000/analyze \
  -H "content-type: application/json" \
  -d '{"url": "https://example.com", "advanced_crawl": true}'
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| AI Engine | Gemini 3 Flash Preview (`google-genai`) |
| API | FastAPI + Uvicorn |
| Crawler | Python ThreadPool + Rust/PyO3 fallback |
| Screenshot | Playwright (headless Chromium) |
| HTTP | httpx (HTTP/2, connection pooling) |
| Models | Pydantic v2 |
| Frontend | Next.js 15 |
| Deploy | Heroku (Docker) |

## Notes
- Some large sites block automated fetching (403/429). The agent treats missing HTML as **insufficient data**, not as a strong negative.
- This service is intended to be called server-to-server (e.g., from your Next.js API route).
