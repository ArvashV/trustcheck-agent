# TrustCheck Python Agent

A small, **multi-threaded** service that fetches public signals about a website (HTTP headers + redirect chain + basic HTML cues + RDAP domain age + TLS certificate info) and returns a calm trust assessment.

## Requirements
- Python 3.10+

## Install
From this folder:

```bash
python -m venv .venv
# Windows PowerShell
.\.venv\Scripts\Activate.ps1

pip install -U pip
pip install -e .
```

## Run

```bash
uvicorn trustcheck_agent.main:app --host 0.0.0.0 --port 8081
```

## Endpoints
- `GET /healthz`
- `POST /analyze`

Example:

```bash
curl -X POST http://localhost:8081/analyze \
  -H "content-type: application/json" \
  -d "{\"url\": \"https://amazon.com\"}"
```

## Notes
- Some large sites block automated fetching (403/429). The agent treats missing HTML as **insufficient data**, not as a strong negative.
- This service is intended to be called server-to-server (e.g., from your Next.js API route).
