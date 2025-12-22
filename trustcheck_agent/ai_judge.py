"""
AI-powered legitimacy judge using Google Gemini.
This module uses Gemini to analyze crawled website content and determine trust scores.
"""
from __future__ import annotations

import os
import re
from typing import Any

import httpx

GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3-flash-preview")


def _build_prompt(site_data: dict[str, Any]) -> str:
    """Build the analysis prompt for Gemini."""
    return f"""You are TrustCheck AI, a world-class expert at detecting untrustworthy, deceptive, or potentially harmful websites. Your job is to analyze the provided website data and determine if the site is legitimate or potentially problematic.

## CRITICAL DETECTION RULES

### RED FLAGS (High Risk - Score should be 10-35):
1. **Fake/Impossible Products**: Claims of products that don't exist or violate physics/medicine (e.g., "non-invasive glucose meters" that aren't FDA-approved consumer devices, "miracle cures", "free energy devices")
2. **Dropshipping Scam Indicators**: Generic Shopify store + no real company info + products available cheaper on AliExpress/Amazon
3. **Too-Good-To-Be-True Pricing**: Luxury goods at 90%+ discounts, "limited time" extreme deals
4. **Missing Business Identity**: No real company name, address, phone number, or business registration
5. **Fake Reviews/Testimonials**: Generic testimonials with stock photos, suspiciously perfect reviews
6. **Pressure Tactics**: Countdown timers, "only X left", "Y people viewing this now" on every product
7. **No Real Contact**: Only a contact form, no phone/email/physical address
8. **Clone Sites**: Copying legitimate brand designs or names with slight variations
9. **Medical/Health Claims Without Credentials**: Health products with unverified claims

### YELLOW FLAGS (Caution - Score should be 36-55):
1. **Very New Domain**: Under 1 year old with limited reputation
2. **Template Store**: Generic theme with no unique branding
3. **Limited Policies**: Missing or vague refund/privacy/shipping policies
4. **No Social Proof**: No verifiable social media presence
5. **Stock-Only Images**: All product images are stock photos

### GREEN FLAGS (Lower Risk - Score can be 56-85):
1. **Established Domain**: 2+ years with consistent operation
2. **Real Business Info**: Verifiable company name, address, phone
3. **Professional Policies**: Clear refund, privacy, terms of service
4. **Social Presence**: Active, verified social media accounts
5. **Third-Party Trust Signals**: Reviews on Trustpilot, BBB, etc.
6. **Secure Checkout**: Standard payment processors (Stripe, PayPal)

### WELL-KNOWN BRANDS (Score 85-95):
Major established brands (Amazon, Walmart, Apple, etc.) should score high even if bot-blocked.

## SPECIFIC SCAM PATTERNS TO DETECT

1. **Fake Medical Devices**: "Non-invasive glucose monitor", "painless blood sugar meter" - these don't exist as consumer products without finger pricks. FDA-approved CGMs require sensor insertion.

2. **Shopify Dropship Scams**: 
   - Uses cdn.shopify.com
   - Products with generic descriptions
   - No "About Us" with real company info
   - Prices that seem too good for the product quality
   - "Free shipping" on heavy/expensive items

3. **Clone/Impersonation Sites**:
   - Domain similar to known brand
   - Copied branding elements
   - Different company behind it

## WEBSITE DATA TO ANALYZE

URL: {site_data.get('url', 'Unknown')}
Hostname: {site_data.get('hostname', 'Unknown')}
Domain Age: {site_data.get('domain_age_days', 'Unknown')} days
Is Well-Known Brand: {site_data.get('is_well_known', False)}
HTTP Status: {site_data.get('http_status', 'Unknown')}
Platform Detected: {site_data.get('platform', 'Unknown')}
Pages Crawled: {site_data.get('pages_crawled', 0)}

### External Reviews Found:
{site_data.get('external_reviews', 'No external reviews found')}

### Homepage Content:
{site_data.get('homepage_html', 'Not available')[:45000]}

### Other Pages Content:
{site_data.get('crawled_pages_text', 'Not available')[:65000]}

## RESPONSE FORMAT

Respond with ONLY valid JSON (no markdown, no code blocks):

{{
  "legitimacy_score": <0-100 integer>,
  "confidence": "<high|medium|low>",
  "verdict": "<legitimate|caution|suspicious|likely_deceptive>",
  "category": "<e-commerce|news|corporate|personal|medical|financial|unknown>",
  "detected_issues": ["<list of specific issues found>"],
  "positive_signals": ["<list of trust indicators>"],
  "platform": "<shopify|woocommerce|custom|unknown>",
  "product_legitimacy": "<real_products|questionable_products|fake_impossible_products|not_applicable>",
  "business_identity": "<verified|partial|missing|fake>",
  "summary": "<One clear sentence about the site's trustworthiness>",
  "recommendation": "<What users should do>"
}}

Be thorough. If you see impossible product claims (like non-invasive glucose meters for consumers), that's a MAJOR red flag - score should be under 30."""


def _call_gemini(prompt: str, timeout: float = 30.0) -> dict[str, Any] | None:
    """Call Gemini via the official google-genai SDK and parse JSON response."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None

    try:
        from google import genai
        from google.genai import types
    except Exception as e:
        print(f"google-genai not available: {e}")
        return None

    try:
        client = genai.Client(api_key=api_key)

        contents = [
            types.Content(
                role="user",
                parts=[types.Part.from_text(text=prompt)],
            )
        ]

        tools = [types.Tool(googleSearch=types.GoogleSearch())]

        config = types.GenerateContentConfig(
            thinking_config=types.ThinkingConfig(thinking_level="HIGH"),
            tools=tools,
            response_mime_type="application/json",
            temperature=0.2,
            max_output_tokens=4096,
        )

        # Prefer non-streaming to reliably parse a full JSON document.
        resp = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=contents,
            config=config,
        )

        text = (getattr(resp, "text", None) or "").strip()
        if not text:
            return None

        # The SDK may still return fenced JSON sometimes; strip defensively.
        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

        import json

        return json.loads(text)
    except Exception as e:
        print(f"Gemini call failed: {e}")
        return None


def fetch_external_reviews(hostname: str, timeout_ms: int = 5000) -> str:
    """Fetch external review signals from sources that are reasonably bot-tolerant.

    Note: Sites like ScamAdviser frequently sit behind Cloudflare / human verification.
    We intentionally do not scrape those pages because it produces unreliable results.
    """
    timeout = timeout_ms / 1000
    reviews_text = []

    # Try Trustpilot
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            res = client.get(
                f"https://www.trustpilot.com/review/{hostname}",
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html",
                },
            )
            if res.status_code == 200:
                html = res.text[:30000]
                # Look for trust score
                score_match = re.search(r'TrustScore\s*(\d+\.?\d*)', html, re.IGNORECASE)
                reviews_match = re.search(r'(\d+(?:,\d+)*)\s*reviews?', html, re.IGNORECASE)
                rating_match = re.search(r'"ratingValue"\s*:\s*"?(\d+\.?\d*)"?', html)

                if score_match or reviews_match or rating_match:
                    tp_info = f"Trustpilot: "
                    if rating_match:
                        tp_info += f"Rating {rating_match.group(1)}/5, "
                    if score_match:
                        tp_info += f"TrustScore {score_match.group(1)}, "
                    if reviews_match:
                        tp_info += f"{reviews_match.group(1)} reviews"
                    reviews_text.append(tp_info.rstrip(", "))
                else:
                    reviews_text.append("Trustpilot: No rating found (may be new or unlisted)")
            elif res.status_code == 404:
                reviews_text.append("Trustpilot: Not listed (no reviews)")
    except Exception:
        reviews_text.append("Trustpilot: Unavailable (blocked or network error)")

    return (
        "\n".join(reviews_text)
        if reviews_text
        else "External reviews unavailable (many sources block automated checks)"
    )


def judge_website(
    url: str,
    hostname: str,
    domain_age_days: int | None,
    is_well_known: bool,
    http_status: int | None,
    homepage_html: str | None,
    crawled_pages: list[dict[str, Any]] | None,
    external_reviews: str | None = None,
) -> dict[str, Any] | None:
    """
    Use Gemini to judge the website's legitimacy.
    Returns AI analysis result or None if failed.
    """
    # Detect platform
    platform = "unknown"
    html_lower = (homepage_html or "").lower()
    if "cdn.shopify.com" in html_lower or "shopify" in html_lower:
        platform = "shopify"
    elif "woocommerce" in html_lower or "wp-content" in html_lower:
        platform = "woocommerce"
    elif "magento" in html_lower:
        platform = "magento"

    # Combine crawled pages text
    crawled_text = ""
    if crawled_pages:
        for page in crawled_pages[:12]:
            snippet = page.get("html_snippet") or ""
            if snippet:
                page_url = page.get("final_url") or page.get("url") or "Unknown page"
                # Use smaller per-page snippets so we can fit more pages into the prompt.
                crawled_text += f"\n\n=== PAGE: {page_url} ===\n{snippet[:4500]}"
            if len(crawled_text) > 90000:
                break

    site_data = {
        "url": url,
        "hostname": hostname,
        "domain_age_days": domain_age_days if domain_age_days is not None else "Unknown",
        "is_well_known": is_well_known,
        "http_status": http_status,
        "platform": platform,
        "pages_crawled": len(crawled_pages) if crawled_pages else 0,
        "external_reviews": external_reviews or "Not checked",
        "homepage_html": homepage_html or "Not available",
        "crawled_pages_text": crawled_text or "No additional pages crawled",
    }

    prompt = _build_prompt(site_data)
    result = _call_gemini(prompt)

    if result and isinstance(result.get("legitimacy_score"), (int, float)):
        # Clamp score
        result["legitimacy_score"] = max(0, min(100, int(result["legitimacy_score"])))
        return result

    return None
