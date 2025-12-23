from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal["good", "warn", "bad", "unknown"]


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1)
    # A slightly higher default helps multi-page crawling; callers can raise up to 60s.
    timeout_ms: int = Field(20000, ge=1000, le=60000)
    max_html_kb: int = Field(512, ge=0, le=4096)
    user_agent: str = Field(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 TrustCheckAgent/2.0"
    )
    check_external_reviews: bool = Field(True)


class ExplainabilityItem(BaseModel):
    key: str
    label: str
    verdict: Verdict
    detail: str


class TLSInfo(BaseModel):
    supported: bool
    issuer: str | None = None
    subject: str | None = None
    not_after: str | None = None
    days_to_expiry: int | None = None


class FetchInfo(BaseModel):
    final_url: str
    http_status: int | None
    content_type: str | None
    redirect_chain: list[str]
    headers: dict[str, str]
    html_available: bool
    html_snippet: str | None = None
    fetch_note: str | None = None


class CrawlPage(BaseModel):
    url: str
    final_url: str | None = None
    http_status: int | None = None
    content_type: str | None = None
    html_snippet: str | None = None
    fetch_note: str | None = None
    page_type: str | None = None


class CrawlInfo(BaseModel):
    pages_requested: int
    pages_fetched: int
    pages: list[CrawlPage]


class AIJudgment(BaseModel):
    legitimacy_score: int
    confidence: Literal["high", "medium", "low"]
    verdict: Literal["legitimate", "caution", "suspicious", "likely_deceptive"]
    category: str
    detected_issues: list[str]
    positive_signals: list[str]
    platform: str
    product_legitimacy: str
    business_identity: str
    summary: str
    recommendation: str


class AnalyzeResponse(BaseModel):
    normalized_url: str
    hostname: str
    score: int
    status: Literal["Low Risk", "Proceed with Caution", "High Risk Indicators Detected"]
    explainability: list[ExplainabilityItem]

    # raw-ish signals
    domain_age_days: int | None
    tls: TLSInfo
    fetch: FetchInfo
    crawl: CrawlInfo | None = None

    # AI judgment
    ai_judgment: AIJudgment | None = None
    external_reviews: str | None = None

    # metadata
    agent: Literal["python"] = "python"
    analyzed_at: str
    timings_ms: dict[str, int]
    warnings: list[str] = []


class ScreenshotRequest(BaseModel):
    url: str = Field(..., min_length=1)
    full_page: bool = Field(False)
    timeout_ms: int = Field(12000, ge=1000, le=30000)


class ScreenshotsRequest(BaseModel):
    url: str = Field(..., min_length=1)
    # Capture timeline offsets after navigation (milliseconds)
    delays_ms: list[int] = Field(default_factory=lambda: [1000, 3000, 5000])
    full_page: bool = Field(False)
    timeout_ms: int = Field(20000, ge=1000, le=60000)


class ScreenshotTimelineItem(BaseModel):
    at_ms: int
    mime: str = "image/png"
    data_base64: str


class ScreenshotsResponse(BaseModel):
    shots: list[ScreenshotTimelineItem]

