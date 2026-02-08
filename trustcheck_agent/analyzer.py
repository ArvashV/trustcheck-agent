from __future__ import annotations

import re
import socket
import ssl
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

import xml.etree.ElementTree as ET

import httpx

from .ai_judge import fetch_external_reviews, judge_website, visual_analyze_screenshot
from .models import AIJudgment, AnalyzeRequest, AnalyzeResponse, CrawlInfo, CrawlPage, ExplainabilityItem, FetchInfo, TLSInfo, Verdict


_WELL_KNOWN_DOMAINS = {
    # Tech giants
    "amazon.com", "google.com", "microsoft.com", "apple.com", "meta.com",
    "facebook.com", "instagram.com", "whatsapp.com", "youtube.com",
    "twitter.com", "x.com", "tiktok.com", "snapchat.com", "pinterest.com",
    "linkedin.com", "reddit.com", "github.com", "gitlab.com",
    "stackoverflow.com", "discord.com", "twitch.tv", "spotify.com",
    # Streaming / entertainment
    "netflix.com", "hulu.com", "disneyplus.com", "primevideo.com",
    "imdb.com", "rottentomatoes.com",
    # E-commerce
    "ebay.com", "walmart.com", "target.com", "bestbuy.com", "costco.com",
    "homedepot.com", "lowes.com", "macys.com", "nordstrom.com",
    "wayfair.com", "etsy.com", "zappos.com", "newegg.com",
    "kohls.com", "sephora.com", "ulta.com",
    "nike.com", "adidas.com", "zara.com", "hm.com", "uniqlo.com",
    "asos.com", "ikea.com", "aliexpress.com", "alibaba.com", "temu.com",
    # Finance / Payments
    "paypal.com", "stripe.com", "chase.com", "bankofamerica.com",
    "wellsfargo.com", "capitalone.com", "amex.com",
    "discover.com", "venmo.com", "wise.com",
    "coinbase.com", "robinhood.com", "fidelity.com",
    # News / media
    "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com",
    "theguardian.com", "reuters.com", "bloomberg.com",
    "forbes.com", "wsj.com", "huffpost.com",
    # Reference / education
    "wikipedia.org", "wikimedia.org", "britannica.com",
    "coursera.org", "udemy.com", "khanacademy.org",
    # Cloud / Dev tools
    "cloudflare.com", "digitalocean.com", "vercel.com", "netlify.com",
    "docker.com", "npmjs.com",
    # Hosting / CMS platforms
    "godaddy.com", "namecheap.com", "squarespace.com",
    "wix.com", "wordpress.com", "shopify.com", "bigcommerce.com",
    # Delivery / Shipping
    "usps.com", "ups.com", "fedex.com", "dhl.com",
    # Travel
    "booking.com", "airbnb.com", "expedia.com", "tripadvisor.com",
    # Food / delivery
    "doordash.com", "ubereats.com", "grubhub.com", "instacart.com",
    # Health
    "webmd.com", "mayoclinic.org", "healthline.com",
    "cvs.com", "walgreens.com",
    # Communication / Productivity
    "zoom.us", "adobe.com", "dropbox.com", "salesforce.com",
    "slack.com", "notion.so", "canva.com", "figma.com",
    # Community / Reviews
    "craigslist.org", "yelp.com", "quora.com",
    "medium.com", "substack.com", "trustpilot.com",
}


_KNOWN_TLS_ISSUER_HINTS = (
    "let's encrypt",
    "digicert",
    "globalsign",
    "sectigo",
    "comodoca",
    "godaddy",
    "amazon",
    "aws",
    "google trust services",
    "gts",
    "cloudflare",
    "microsoft",
    "entrust",
    "idenTrust".lower(),
)


# Known hosting/platform domains — redirects TO these are normal, not phishing.
_KNOWN_HOSTING_PLATFORMS: dict[str, str] = {
    "myshopify.com": "Shopify", "shopify.com": "Shopify",
    "squarespace.com": "Squarespace", "sqsp.com": "Squarespace",
    "wix.com": "Wix", "wixsite.com": "Wix",
    "weebly.com": "Weebly",
    "bigcommerce.com": "BigCommerce", "mybigcommerce.com": "BigCommerce",
    "wordpress.com": "WordPress",
    "godaddysites.com": "GoDaddy",
    "square.site": "Square", "squareup.com": "Square",
    "carrd.co": "Carrd",
    "webflow.io": "Webflow",
    "netlify.app": "Netlify",
    "vercel.app": "Vercel",
    "herokuapp.com": "Heroku",
    "azurewebsites.net": "Azure",
    "web.app": "Firebase", "firebaseapp.com": "Firebase",
    "github.io": "GitHub Pages", "gitlab.io": "GitLab Pages",
    "bigcartel.com": "Big Cartel",
    "ecwid.com": "Ecwid",
    "volusion.com": "Volusion",
    "prestashop.com": "PrestaShop",
}

# Social media URL patterns
_SOCIAL_MEDIA_PATTERNS: dict[str, re.Pattern] = {
    "facebook": re.compile(r"https?://(?:www\.)?facebook\.com/[^\"'\s>]+", re.IGNORECASE),
    "instagram": re.compile(r"https?://(?:www\.)?instagram\.com/[^\"'\s>]+", re.IGNORECASE),
    "twitter": re.compile(r"https?://(?:www\.)?(?:twitter\.com|x\.com)/[^\"'\s>]+", re.IGNORECASE),
    "tiktok": re.compile(r"https?://(?:www\.)?tiktok\.com/@[^\"'\s>]+", re.IGNORECASE),
    "youtube": re.compile(r"https?://(?:www\.)?youtube\.com/(?:@|channel/|c/)[^\"'\s>]+", re.IGNORECASE),
    "linkedin": re.compile(r"https?://(?:www\.)?linkedin\.com/(?:company|in)/[^\"'\s>]+", re.IGNORECASE),
    "pinterest": re.compile(r"https?://(?:www\.)?pinterest\.com/[^\"'\s>]+", re.IGNORECASE),
}

# Phone number pattern (broad — post-filtered)
_PHONE_RE = re.compile(
    r"(?:\+\d{1,3}[\s.-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}"
)

# Payment provider fingerprints in HTML
_PAYMENT_INDICATORS: dict[str, tuple[str, ...]] = {
    "stripe": ("stripe.com", "stripe.js", "stripe-js", "pk_live_", "pk_test_"),
    "paypal": ("paypal.com", "paypal-sdk", "paypal.Buttons", "paypal-button"),
    "square": ("squareup.com", "square-payment", "sq-payment"),
    "shopify_payments": ("shopify-payment", "shopifypay"),
    "klarna": ("klarna.com", "klarna-widget", "klarna-placement"),
    "afterpay": ("afterpay.com", "afterpay-widget"),
    "affirm": ("affirm.com", "affirm-js"),
    "apple_pay": ("apple-pay", "ApplePaySession"),
    "google_pay": ("google-pay", "GooglePayButton", "gpay"),
}

# Urgency / pressure manipulation patterns
_URGENCY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?:only|just)\s+\d+\s+left", re.I), "low stock pressure"),
    (re.compile(r"\d+\s+people?\s+(?:are\s+)?(?:viewing|watching|looking)", re.I), "fake viewer count"),
    (re.compile(r"(?:limited\s+time|ends?\s+(?:soon|today|tonight|in\s+\d))", re.I), "time pressure"),
    (re.compile(r"(?:flash\s+sale|mega\s+sale|clearance\s+sale|going\s+fast)", re.I), "sale urgency"),
    (re.compile(r"(?:don'?t\s+miss|act\s+now|hurry|rush|grab\s+(?:it|yours))", re.I), "urgency language"),
    (re.compile(r"(?:today\s+only|24.?hour|48.?hour)\s+(?:deal|sale|offer|discount)", re.I), "time-limited offer"),
    (re.compile(r"\b(?:69|79|89|9[0-9])%\s*off\b", re.I), "extreme discount claim"),
    (re.compile(r"(?:free\s+shipping\s+(?:worldwide|on\s+all|for\s+all))", re.I), "free global shipping claim"),
    (re.compile(r"countdown|timer|data-countdown|\.countdown", re.I), "countdown timer"),
    (re.compile(r"(?:sold\s+out\s+soon|selling\s+fast|almost\s+gone)", re.I), "scarcity pressure"),
]


def _clamp_score(score: int) -> int:
    return max(0, min(100, int(score)))


def _status_for(score: int) -> str:
    if score >= 75:
        return "Low Risk"
    if score >= 45:
        return "Proceed with Caution"
    return "High Risk Indicators Detected"


def _normalize_url(raw: str) -> str:
    value = raw.strip()
    if not value:
        raise ValueError("Please provide a URL.")

    if not re.match(r"^[a-zA-Z][a-zA-Z\d+.-]*://", value):
        value = "https://" + value

    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Please use an http(s) website URL.")
    if not parsed.hostname or "." not in parsed.hostname:
        raise ValueError("Please enter a valid website domain.")

    normalized = parsed._replace(fragment="")
    return urlunparse(normalized)


def _registrable_domain_guess(hostname: str) -> str:
    parts = [p for p in hostname.split(".") if p]
    if len(parts) <= 2:
        return hostname
    return ".".join(parts[-2:])


def _is_well_known(hostname: str) -> bool:
    return _registrable_domain_guess(hostname.lower()) in _WELL_KNOWN_DOMAINS


_HREF_RE = re.compile(r"href\s*=\s*([\"']?)([^\"'\s>]+)\1", re.IGNORECASE)

_EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)


def _extract_emails(text: str) -> set[str]:
    if not text:
        return set()
    emails = {m.group(0).strip().lower() for m in _EMAIL_RE.finditer(text)}
    return {e for e in emails if ".." not in e and not e.endswith("@example.com")}


def _looks_like_address(text: str) -> bool:
    t = (text or "").strip()
    if len(t) < 10:
        return False
    if any(k in t.lower() for k in ("street", "st.", "road", "rd.", "avenue", "ave", "suite", "floor", "building", "blvd", "zip", "postcode")):
        return True
    if re.search(r"\b\d{1,5}\b.*?,.*?\b[a-zA-Z]{3,}", t):
        return True
    return False


def _normalize_address(addr: str) -> str:
    a = (addr or "").strip().lower()
    a = re.sub(r"\s+", " ", a)
    a = re.sub(r"[^a-z0-9 ,.#/-]", "", a)
    return a[:200]


def _extract_jsonld_blocks(html: str) -> list[str]:
    if not html:
        return []
    blocks: list[str] = []
    for m in re.finditer(r"<script\b[^>]*type=\"application/ld\+json\"[^>]*>(.*?)</script>", html, flags=re.IGNORECASE | re.DOTALL):
        content = (m.group(1) or "").strip()
        if content:
            blocks.append(content)
    return blocks


def _try_parse_json_fragment(s: str) -> Any | None:
    if not s:
        return None
    try:
        return json.loads(s)
    except Exception:
        pass
    m = re.search(r"(\{.*\}|\[.*\])", s, flags=re.DOTALL)
    if not m:
        return None
    frag = m.group(1)
    try:
        return json.loads(frag)
    except Exception:
        return None


def _walk_json(obj: Any):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _walk_json(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_json(v)


def _extract_org_identity_from_html(html: str) -> tuple[set[str], set[str]]:
    names: set[str] = set()
    addresses: set[str] = set()

    for block in _extract_jsonld_blocks(html):
        parsed = _try_parse_json_fragment(block)
        if parsed is None:
            continue
        for node in _walk_json(parsed):
            if not isinstance(node, dict):
                continue
            t = node.get("@type")
            if isinstance(t, str) and t.lower() in ("organization", "localbusiness", "corporation"):
                name = node.get("name")
                if isinstance(name, str) and name.strip():
                    names.add(name.strip()[:120])

                addr = node.get("address")
                if isinstance(addr, dict):
                    parts: list[str] = []
                    for k in ("streetAddress", "addressLocality", "addressRegion", "postalCode", "addressCountry"):
                        v = addr.get(k)
                        if isinstance(v, str) and v.strip():
                            parts.append(v.strip())
                    joined = ", ".join(parts).strip()
                    if joined and _looks_like_address(joined):
                        addresses.add(joined[:220])
                elif isinstance(addr, str) and addr.strip() and _looks_like_address(addr):
                    addresses.add(addr.strip()[:220])

    for m in re.finditer(r"©\s*(?:19\d{2}|20\d{2})\s*([^<\n\r]{2,80})", html, flags=re.IGNORECASE):
        candidate = (m.group(1) or "").strip(" .\t")
        if candidate:
            names.add(candidate[:120])

    for m in re.finditer(r"(?:address|registered office)\s*[:\-]?\s*([^<\n\r]{12,200})", html, flags=re.IGNORECASE):
        candidate = (m.group(1) or "").strip()
        if candidate and _looks_like_address(candidate):
            addresses.add(candidate[:220])

    return names, addresses


_US_UK_PAIRS = (
    ("color", "colour"),
    ("favorite", "favourite"),
    ("organize", "organise"),
    ("center", "centre"),
    ("license", "licence"),
    ("analyze", "analyse"),
)


def _mixed_us_uk_spelling(text: str) -> bool:
    if not text:
        return False
    t = text.lower()
    for us, uk in _US_UK_PAIRS:
        if us in t and uk in t:
            return True
    return False


def _language_quality_score(text: str) -> int:
    if not text:
        return 0
    t = re.sub(r"\s+", " ", text).strip()
    if len(t) < 200:
        return 35

    score = 80
    lower = t.lower()
    if "lorem ipsum" in lower:
        score -= 30
    if re.search(r"[!?.,]{4,}", t):
        score -= 12

    letters = sum(1 for ch in t if ch.isalpha())
    nonspace = sum(1 for ch in t if not ch.isspace())
    if nonspace > 0:
        alpha_ratio = letters / nonspace
        if alpha_ratio < 0.55:
            score -= 18
        elif alpha_ratio < 0.7:
            score -= 8

    words = re.findall(r"[A-Za-z]{2,}", t)
    if len(words) < 60:
        score -= 10
    long_words = [w for w in words if len(w) >= 18]
    if len(words) > 0 and (len(long_words) / len(words)) > 0.05:
        score -= 8

    return max(0, min(100, int(score)))


def _detect_platform_from_html(html: str | None) -> str:
    h = (html or "").lower()
    if not h.strip():
        return "unknown"
    if "cdn.shopify.com" in h or "myshopify.com" in h or "shopify" in h:
        return "shopify"
    if "wp-content" in h or "wp-includes" in h or "wordpress" in h or "wp-json" in h or "woocommerce" in h:
        return "wordpress"
    return "custom"


def _strip_fragment(u: str) -> str:
    try:
        p = urlparse(u)
        return urlunparse(p._replace(fragment=""))
    except Exception:
        return u


def _is_probably_asset_url(u: str) -> bool:
    lowered = u.lower()
    return any(
        lowered.endswith(ext)
        for ext in (
            ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
            ".css", ".js", ".json", ".xml", ".pdf", ".zip",
            ".woff", ".woff2", ".ttf", ".eot",
        )
    )


def _classify_page_type(u: str, homepage_url: str | None = None) -> str:
    try:
        p = urlparse(u)
        path = (p.path or "/").lower()
    except Exception:
        return "unknown"

    if homepage_url:
        try:
            if _strip_fragment(u) == _strip_fragment(homepage_url):
                return "homepage"
        except Exception:
            pass

    if path in ("/", ""):
        return "homepage"
    if any(k in path for k in ("/about", "about-us", "our-story", "company")):
        return "about"
    if any(k in path for k in ("/contact", "contact-us", "support")):
        return "contact"
    if any(k in path for k in ("privacy", "terms", "refund", "return", "shipping", "policy", "legal")):
        return "policy"
    if any(k in path for k in ("/products/", "/product/")):
        return "product"
    if any(k in path for k in ("/collections/", "/category/", "/categories/")):
        return "collection"
    if any(k in path for k in ("/blog", "/news", "/articles/", "/post/")):
        return "blog"
    if any(k in path for k in ("/cart", "/checkout")):
        return "checkout"
    if any(k in path for k in ("/account", "/login", "/register", "/signin", "/signup")):
        return "account"
    if any(k in path for k in ("/search", "/s/", "/tag/")):
        return "search"
    return "other"


def _is_low_value_page(u: str) -> bool:
    """Exclude pages that are usually not useful for legitimacy judgments."""
    try:
        p = urlparse(u)
        path = (p.path or "").lower()
    except Exception:
        return True

    # Obvious infrastructure / bot-protection endpoints
    if path.startswith("/cdn-cgi/") or path.startswith("/.well-known/"):
        return True

    # Common high-noise endpoints
    if any(seg in path for seg in ("/cart", "/checkout", "/account", "/login", "/register", "/signin", "/signup")):
        return True
    if "/search" in path:
        return True

    # CMS/admin
    if path.startswith(("/wp-admin", "/wp-login", "/admin")):
        return True

    # Assets already handled elsewhere, but keep as defense-in-depth.
    if _is_probably_asset_url(path):
        return True

    # Avoid extremely deep paths which are often tracking or paginated noise
    if path.count("/") > 8:
        return True

    return False


_SCRIPT_RE = re.compile(r"<script\b[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)
_STYLE_RE = re.compile(r"<style\b[^>]*>.*?</style>", re.IGNORECASE | re.DOTALL)
_SCRIPT_OPEN_RE = re.compile(r"<script\b([^>]*)>", re.IGNORECASE)


def _strip_scripts_styles_keep_jsonld(html: str) -> str:
    """Remove scripts/styles to reduce noise while keeping JSON-LD (often useful).

    This is a best-effort sanitizer (we don't execute JS).
    """
    if not html:
        return html

    # Strip <style>
    cleaned = re.sub(_STYLE_RE, " ", html)

    # For <script>, keep only ld+json scripts.
    out_parts: list[str] = []
    idx = 0
    for m in re.finditer(r"<script\b[^>]*>.*?</script>", cleaned, flags=re.IGNORECASE | re.DOTALL):
        chunk = cleaned[idx:m.start()]
        if chunk:
            out_parts.append(chunk)

        block = m.group(0)
        open_m = _SCRIPT_OPEN_RE.search(block)
        attrs = (open_m.group(1) if open_m else "").lower()
        if "ld+json" in attrs:
            out_parts.append(block)
        else:
            out_parts.append(" ")
        idx = m.end()
    out_parts.append(cleaned[idx:])
    cleaned = "".join(out_parts)

    # Collapse whitespace a bit to save prompt budget.
    cleaned = re.sub(r"\s{2,}", " ", cleaned)
    return cleaned.strip()


def _extract_internal_links(html: str, base_url: str, hostname: str, limit: int = 8) -> list[str]:
    if not html:
        return []

    base_domain = _registrable_domain_guess(hostname.lower())
    candidates: list[str] = []
    seen: set[str] = set()

    for _, href in _HREF_RE.findall(html):
        href = (href or "").strip()
        if not href:
            continue
        if href.startswith("mailto:") or href.startswith("tel:") or href.startswith("javascript:"):
            continue

        abs_url = urljoin(base_url, href)
        abs_url = _strip_fragment(abs_url)

        try:
            p = urlparse(abs_url)
        except Exception:
            continue

        if p.scheme not in ("http", "https"):
            continue
        if not p.hostname:
            continue
        if _registrable_domain_guess(p.hostname.lower()) != base_domain:
            continue
        if p.path.lower().startswith(("/cdn/", "/assets/", "/static/")):
            continue
        if _is_probably_asset_url(p.path):
            continue

        normalized = urlunparse(p._replace(query=""))
        if normalized in seen:
            continue

        seen.add(normalized)
        if _is_low_value_page(normalized):
            continue

        candidates.append(normalized)

    def score_link(u: str) -> int:
        path = urlparse(u).path.lower()
        score = 0
        for kw in ("contact", "about", "privacy", "terms", "refund", "return", "shipping", "policy", "track"):
            if kw in path:
                score += 10
        if path in ("/", ""):
            score -= 10
        if "error" in path:
            score -= 10
        return score

    base_norm = _strip_fragment(base_url)
    candidates = [c for c in candidates if c != base_norm]
    candidates.sort(key=score_link, reverse=True)
    out = candidates[:limit]

    if len(out) < min(3, limit):
        origin = f"{urlparse(base_url).scheme}://{hostname}"
        is_shopify = "cdn.shopify.com" in html.lower() or "shopify" in html.lower()
        common_paths = [
            "/pages/contact",
            "/pages/about-us",
            "/search",
            "/collections/all",
            "/policies/privacy-policy",
            "/policies/refund-policy",
            "/policies/terms-of-service",
            "/policies/shipping-policy",
        ]
        for path in common_paths:
            if len(out) >= limit:
                break
            if (not is_shopify) and path.startswith("/policies/"):
                continue
            candidate = _strip_fragment(urljoin(origin, path))
            if candidate in seen:
                continue
            seen.add(candidate)
            out.append(candidate)

    return out


def _extract_nav_links(html: str, base_url: str, hostname: str, limit: int = 12) -> list[str]:
    """Try to extract human-navigation links from <nav>/<header>/menu sections.

    This is intentionally heuristic (no JS execution, no full DOM parser).
    It tends to find: About/Contact/Policies/Collections/Blog links.
    """
    if not html:
        return []

    blocks: list[str] = []

    # Prefer explicit <nav> blocks.
    for m in re.finditer(r"<nav\b[^>]*>.*?</nav>", html, flags=re.IGNORECASE | re.DOTALL):
        blocks.append(m.group(0))

    # Header often contains nav.
    for m in re.finditer(r"<header\b[^>]*>.*?</header>", html, flags=re.IGNORECASE | re.DOTALL):
        blocks.append(m.group(0))

    # Common class names for navbar/menu.
    for m in re.finditer(
        r"<[^>]+class=\"[^\"]*(?:nav|navbar|menu|topbar|header)[^\"]*\"[^>]*>.*?</[^>]+>",
        html,
        flags=re.IGNORECASE | re.DOTALL,
    ):
        blocks.append(m.group(0))

    if not blocks:
        return []

    # Deduplicate blocks a bit and cap work.
    joined = "\n".join(blocks[:6])

    base_domain = _registrable_domain_guess(hostname.lower())
    seen: set[str] = set()
    candidates: list[str] = []

    for _, href in _HREF_RE.findall(joined):
        href = (href or "").strip()
        if not href:
            continue
        if href.startswith("mailto:") or href.startswith("tel:") or href.startswith("javascript:"):
            continue

        abs_url = urljoin(base_url, href)
        abs_url = _strip_fragment(abs_url)
        try:
            p = urlparse(abs_url)
        except Exception:
            continue

        if p.scheme not in ("http", "https") or not p.hostname:
            continue
        if _registrable_domain_guess(p.hostname.lower()) != base_domain:
            continue
        if p.path.lower().startswith(("/cdn/", "/assets/", "/static/", "/cdn-cgi/")):
            continue
        if _is_probably_asset_url(p.path):
            continue

        normalized = urlunparse(p._replace(query=""))
        if normalized in seen:
            continue
        if _is_low_value_page(normalized):
            continue

        seen.add(normalized)
        candidates.append(normalized)

    def nav_score(u: str) -> int:
        path = urlparse(u).path.lower()
        score = 0
        for kw in ("contact", "about", "privacy", "terms", "refund", "return", "shipping", "policy", "track"):
            if kw in path:
                score += 30
        for kw in ("/collections/", "/products/", "/pages/", "/blog", "/news"):
            if kw in path:
                score += 10
        if path in ("/", ""):
            score -= 10
        return score

    base_norm = _strip_fragment(base_url)
    candidates = [c for c in candidates if c != base_norm]
    candidates.sort(key=nav_score, reverse=True)
    return candidates[:limit]


def _looks_like_ecommerce(html: str | None) -> bool:
    return _ecommerce_signal_count(html) >= 2


def _ecommerce_signal_count(html: str | None) -> int:
    return len(_ecommerce_signals(html))


def _ecommerce_signals(html: str | None) -> set[str]:
    """Return a set of independent ecommerce signals found in HTML.

    We intentionally require multiple distinct signals to reduce false positives.
    """
    if not html:
        return set()
    h = html.lower()
    signals: set[str] = set()

    # Platform signals
    if "cdn.shopify.com" in h or "myshopify.com" in h:
        signals.add("shopify")
    if "woocommerce" in h and ("wp-content" in h or "wp-json" in h):
        signals.add("woocommerce")
    if "magento" in h:
        signals.add("magento")

    # Commerce UI/actions
    if "add to cart" in h or "data-add-to-cart" in h or "add-to-cart" in h:
        signals.add("add_to_cart")
    if "checkout" in h or "begin checkout" in h:
        signals.add("checkout")
    if "cart" in h and ("/cart" in h or "basket" in h):
        signals.add("cart")

    # Product schema + pricing
    if "\"@type\"" in h and "\"product\"" in h:
        signals.add("product_schema")
    if "pricecurrency" in h or "itemprop=\"price\"" in h or "data-price" in h:
        signals.add("pricing")
    if "sku" in h and "variant" in h:
        signals.add("sku_variant")

    return signals


def _tls_issuer_verdict_and_detail(tls: TLSInfo) -> tuple[Verdict, str] | None:
    if not tls.supported:
        return None

    issuer = (tls.issuer or "").strip()
    subject = (tls.subject or "").strip()
    if not issuer:
        return ("unknown", "Certificate issuer was not available.")

    issuer_lower = issuer.lower()
    if subject and issuer == subject:
        return ("warn", "Certificate appears self-issued (issuer equals subject). This is unusual for public websites.")

    if any(hint in issuer_lower for hint in _KNOWN_TLS_ISSUER_HINTS):
        return ("good", "Certificate is issued by a commonly trusted public CA.")

    return ("warn", "Certificate issuer is uncommon. This can be legitimate, but it’s worth extra caution.")


def _registrable_domain_or_host(host: str) -> str:
    host = (host or "").strip().lower()
    if not host:
        return ""
    return _registrable_domain_guess(host)


def _redirect_verdict_and_detail(initial_url: str, fetch: FetchInfo) -> tuple[Verdict, str] | None:
    chain = fetch.redirect_chain or []
    if not chain:
        return None

    try:
        initial_host = urlparse(initial_url).hostname or ""
    except Exception:
        initial_host = ""
    try:
        final_host = urlparse(fetch.final_url or initial_url).hostname or ""
    except Exception:
        final_host = ""

    initial_reg = _registrable_domain_or_host(initial_host)
    final_reg = _registrable_domain_or_host(final_host)

    if initial_reg and final_reg and initial_reg != final_reg:
        # Check if the redirect target is a known hosting platform
        is_hosting, platform_name = _is_known_hosting_redirect(final_host)
        if is_hosting:
            return (
                "warn",
                f"Homepage redirected to {platform_name} hosting ({final_host}). "
                f"This is normal for sites hosted on {platform_name}.",
            )
        return (
            "bad",
            f"Homepage redirected {len(chain)} time(s) and ended on a different domain ({final_host}). This is a common phishing/scam pattern.",
        )

    return (
        "warn",
        f"Homepage redirected {len(chain)} time(s) before loading. This can be normal, but increases risk if the destination is unexpected.",
    )


def _is_product_like_url(u: str) -> bool:
    try:
        path = urlparse(u).path.lower()
    except Exception:
        return False
    # Shopify/Commerce common patterns
    if "/products/" in path or path.startswith("/product/") or "/product/" in path:
        return True
    # Other common patterns
    if path.startswith(("/p/", "/item/", "/items/")):
        return True
    return False


def _is_collection_like_url(u: str) -> bool:
    try:
        path = urlparse(u).path.lower()
    except Exception:
        return False
    if "/collections/" in path or "/category/" in path or "/categories/" in path:
        return True
    if path.endswith("/shop") or path.endswith("/store"):
        return True
    return False


def _ensure_ecommerce_pages(
    links: list[str],
    candidates: list[str],
    target_count: int,
    min_products: int = 3,
    min_collections: int = 1,
) -> list[str]:
    """Ensure we crawl a few product + collection pages when the site is e-commerce.

    We don't exceed target_count; we just bias which pages occupy the slots.
    """
    existing = list(links)
    seen = set(existing)

    def add_front(u: str):
        nonlocal existing
        if u in seen:
            return
        seen.add(u)
        existing.insert(0, u)

    def add_back(u: str):
        nonlocal existing
        if u in seen:
            return
        if len(existing) >= target_count:
            return
        seen.add(u)
        existing.append(u)

    product_existing = sum(1 for u in existing if _is_product_like_url(u))
    collection_existing = sum(1 for u in existing if _is_collection_like_url(u))

    # Prefer inserting missing product pages early (they are highly informative for scam patterns).
    if product_existing < min_products:
        for u in candidates:
            if product_existing >= min_products:
                break
            if _is_product_like_url(u):
                add_front(u)
                product_existing += 1

    if collection_existing < min_collections:
        for u in candidates:
            if collection_existing >= min_collections:
                break
            if _is_collection_like_url(u):
                add_front(u)
                collection_existing += 1

    # If we inserted beyond target_count, trim from the end (keep the prioritized front).
    return existing[:target_count]


def _fetch_sitemap_urls(base_url: str, hostname: str, timeout_ms: int, user_agent: str, limit: int = 40) -> list[str]:
    """Best-effort sitemap discovery.

    Supports Shopify-style /sitemap.xml that may reference additional sitemaps.
    Returns a list of internal page URLs (not assets).
    """
    timeout = timeout_ms / 1000
    origin = f"{urlparse(base_url).scheme}://{hostname}"
    sitemap_urls = [urljoin(origin, "/sitemap.xml")]

    discovered: list[str] = []
    seen: set[str] = set()

    def add_candidate(u: str):
        u = _strip_fragment(u)
        try:
            p = urlparse(u)
        except Exception:
            return
        if p.scheme not in ("http", "https") or not p.hostname:
            return
        if _registrable_domain_guess(p.hostname.lower()) != _registrable_domain_guess(hostname.lower()):
            return
        if _is_probably_asset_url(p.path):
            return
        if _is_low_value_page(u):
            return
        norm = urlunparse(p._replace(query=""))
        if norm in seen:
            return
        seen.add(norm)
        discovered.append(norm)

    def parse_xml(xml_text: str) -> tuple[list[str], list[str]]:
        # Returns (child_sitemaps, page_urls)
        child_maps: list[str] = []
        page_urls: list[str] = []
        try:
            root = ET.fromstring(xml_text)
        except Exception:
            return child_maps, page_urls

        def local(tag: str) -> str:
            return tag.split("}")[-1] if "}" in tag else tag

        rt = local(root.tag)
        if rt == "sitemapindex":
            for child in root:
                if local(child.tag) != "sitemap":
                    continue
                for loc in child:
                    if local(loc.tag) == "loc" and (loc.text or "").strip():
                        child_maps.append(loc.text.strip())
        elif rt == "urlset":
            for child in root:
                if local(child.tag) != "url":
                    continue
                for loc in child:
                    if local(loc.tag) == "loc" and (loc.text or "").strip():
                        page_urls.append(loc.text.strip())
        return child_maps, page_urls

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            queue = list(sitemap_urls)
            while queue and len(discovered) < limit:
                sm = queue.pop(0)
                try:
                    res = client.get(
                        sm,
                        headers={
                            "user-agent": user_agent,
                            "accept": "application/xml,text/xml;q=0.9,*/*;q=0.8",
                            "accept-language": "en-US,en;q=0.6",
                        },
                    )
                except Exception:
                    continue

                if res.status_code < 200 or res.status_code >= 300:
                    continue
                xml_text = res.text
                child_maps, page_urls = parse_xml(xml_text)
                for u in page_urls:
                    if len(discovered) >= limit:
                        break
                    add_candidate(u)

                for u in child_maps:
                    if u not in queue and len(queue) < 8:
                        queue.append(u)
    except Exception:
        return []

    return discovered


def _fetch_page(url: str, timeout_ms: int, max_html_kb: int, user_agent: str) -> CrawlPage:
    timeout = timeout_ms / 1000
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            res = client.get(
                url,
                headers={
                    "user-agent": user_agent,
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "accept-language": "en-US,en;q=0.6",
                },
            )

            content_type = res.headers.get("content-type")
            snippet = None
            note = None

            if content_type and "text/html" in content_type.lower() and max_html_kb > 0:
                limit = max_html_kb * 1024
                body = res.content[:limit]
                if body:
                    try:
                        snippet = body.decode("utf-8", errors="replace")[:12000]
                        snippet = _strip_scripts_styles_keep_jsonld(snippet)
                    except Exception:
                        snippet = None
            else:
                # Non-HTML pages are not useful for AI judgment.
                if content_type and max_html_kb > 0:
                    note = "Non-HTML content."

            if res.status_code in (403, 429) and not snippet:
                note = "Page limited automated access."

            return CrawlPage(
                url=url,
                final_url=str(res.url),
                http_status=res.status_code,
                content_type=content_type,
                html_snippet=snippet,
                fetch_note=note,
                page_type=_classify_page_type(str(res.url) or url),
            )
    except Exception:
        return CrawlPage(
            url=url,
            final_url=None,
            http_status=None,
            content_type=None,
            html_snippet=None,
            fetch_note="Unable to fetch page.",
            page_type=_classify_page_type(url),
        )


def _fetch_rdap_domain_age_days(hostname: str, timeout_ms: int) -> int | None:
    domain = _registrable_domain_guess(hostname)
    url = f"https://rdap.org/domain/{domain}"
    timeout = timeout_ms / 1000
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            res = client.get(url, headers={"accept": "application/rdap+json, application/json"})
            if res.status_code < 200 or res.status_code >= 300:
                return None
            data = res.json()

        events = data.get("events") or []
        reg_date = None
        for e in events:
            action = str(e.get("eventAction") or "").lower()
            if "registration" in action:
                reg_date = e.get("eventDate")
                break
        if not reg_date:
            return None

        created = datetime.fromisoformat(reg_date.replace("Z", "+00:00"))
        age = datetime.now(timezone.utc) - created
        days = int(age.total_seconds() // 86400)
        return days if days >= 0 else None
    except Exception:
        return None


def _fetch_http_signals(url: str, timeout_ms: int, max_html_kb: int, user_agent: str) -> FetchInfo:
    timeout = timeout_ms / 1000
    redirect_chain: list[str] = []
    headers_out: dict[str, str] = {}
    current = url
    note = None

    header_allow = {
        "server", "x-powered-by", "strict-transport-security",
        "content-security-policy", "x-frame-options", "referrer-policy", "permissions-policy",
    }

    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            for _ in range(6):
                res = client.get(
                    current,
                    headers={
                        "user-agent": user_agent,
                        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "accept-language": "en-US,en;q=0.6",
                    },
                )

                for k, v in res.headers.items():
                    lk = k.lower()
                    if lk in header_allow:
                        headers_out[lk] = v

                if 300 <= res.status_code < 400 and res.headers.get("location"):
                    redirect_chain.append(current)
                    current = str(httpx.URL(current).join(res.headers["location"]))
                    continue

                content_type = res.headers.get("content-type")
                html_available = False
                html_snippet = None

                if content_type and "text/html" in content_type.lower() and max_html_kb > 0:
                    limit = max_html_kb * 1024
                    body = res.content[:limit]
                    html_available = len(body) > 0
                    if html_available:
                        try:
                            html_snippet = body.decode("utf-8", errors="replace")[:30000]
                            html_snippet = _strip_scripts_styles_keep_jsonld(html_snippet)
                        except Exception:
                            html_snippet = None

                if res.status_code in (403, 429) and not html_available:
                    note = "Site limited automated access (common for large brands)."

                return FetchInfo(
                    final_url=current,
                    http_status=res.status_code,
                    content_type=content_type,
                    redirect_chain=redirect_chain,
                    headers=headers_out,
                    html_available=html_available,
                    html_snippet=html_snippet,
                    fetch_note=note,
                )

        return FetchInfo(
            final_url=current, http_status=None, content_type=None,
            redirect_chain=redirect_chain, headers=headers_out,
            html_available=False, html_snippet=None, fetch_note="Too many redirects.",
        )
    except Exception:
        return FetchInfo(
            final_url=url, http_status=None, content_type=None,
            redirect_chain=[], headers={}, html_available=False,
            html_snippet=None, fetch_note="Unable to fetch homepage content.",
        )


def _tls_info(hostname: str, timeout_ms: int) -> TLSInfo:
    timeout = timeout_ms / 1000
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        issuer = subject = not_after = None
        days_to_expiry = None

        if cert:
            issuer = ", ".join("=".join(x) for rdn in cert.get("issuer", ()) for x in rdn)
            subject = ", ".join("=".join(x) for rdn in cert.get("subject", ()) for x in rdn)
            not_after = cert.get("notAfter")
            if not_after:
                try:
                    dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_to_expiry = int((dt - datetime.now(timezone.utc)).total_seconds() // 86400)
                except Exception:
                    days_to_expiry = None

        return TLSInfo(supported=True, issuer=issuer, subject=subject, not_after=not_after, days_to_expiry=days_to_expiry)
    except Exception:
        return TLSInfo(supported=False)


# ── NEW: Rich signal extraction functions ────────────────────────────

def _is_known_hosting_redirect(final_host: str) -> tuple[bool, str]:
    """Check if a host belongs to a known hosting/e-commerce platform."""
    h = final_host.lower()
    for platform_domain, platform_name in _KNOWN_HOSTING_PLATFORMS.items():
        if h == platform_domain or h.endswith("." + platform_domain):
            return True, platform_name
    return False, ""


def _extract_social_media_links(html: str) -> dict[str, list[str]]:
    """Extract social media profile links from HTML."""
    if not html:
        return {}
    results: dict[str, list[str]] = {}
    for platform, pattern in _SOCIAL_MEDIA_PATTERNS.items():
        matches = pattern.findall(html)
        unique: list[str] = []
        seen: set[str] = set()
        for url in matches:
            clean = url.rstrip('/"\'')
            clean = clean.split('?')[0]
            if clean not in seen and len(clean) > 20:
                seen.add(clean)
                unique.append(clean)
        if unique:
            results[platform] = unique[:3]
    return results


def _extract_phone_numbers(html: str) -> list[str]:
    """Extract likely phone numbers from HTML."""
    if not html:
        return []
    # Work on text content (strip tags)
    text = re.sub(r"<[^>]+>", " ", html)
    candidates = _PHONE_RE.findall(text)
    phones: list[str] = []
    seen: set[str] = set()
    for p in candidates:
        p = p.strip()
        digits = re.sub(r"\D", "", p)
        if len(digits) < 7 or len(digits) > 15:
            continue
        if digits in seen:
            continue
        seen.add(digits)
        phones.append(p)
    return phones[:10]


def _detect_payment_providers(html: str) -> list[str]:
    """Detect payment providers/processors referenced in HTML."""
    if not html:
        return []
    h = html.lower()
    found: list[str] = []
    for provider, indicators in _PAYMENT_INDICATORS.items():
        if any(ind.lower() in h for ind in indicators):
            found.append(provider)
    return found


def _check_meta_completeness(html: str) -> dict[str, Any]:
    """Check for proper meta/link tags — legitimate sites usually have most."""
    if not html:
        return {"score": 0, "present": 0, "total": 9, "missing": ["all"], "checks": {}}
    checks = {
        "description": bool(re.search(r'<meta\s[^>]*name=["\']description["\'][^>]*>', html, re.I)),
        "og_title": bool(re.search(r'<meta\s[^>]*property=["\']og:title["\'][^>]*>', html, re.I)),
        "og_description": bool(re.search(r'<meta\s[^>]*property=["\']og:description["\'][^>]*>', html, re.I)),
        "og_image": bool(re.search(r'<meta\s[^>]*property=["\']og:image["\'][^>]*>', html, re.I)),
        "viewport": bool(re.search(r'<meta\s[^>]*name=["\']viewport["\'][^>]*>', html, re.I)),
        "charset": bool(re.search(r'<meta\s[^>]*charset=', html, re.I)),
        "favicon": bool(re.search(r'<link\s[^>]*rel=["\'](?:icon|shortcut icon|apple-touch-icon)["\'][^>]*>', html, re.I)),
        "title_tag": bool(re.search(r'<title[^>]*>[^<]+</title>', html, re.I)),
        "canonical": bool(re.search(r'<link\s[^>]*rel=["\']canonical["\'][^>]*>', html, re.I)),
    }
    present = sum(1 for v in checks.values() if v)
    total = len(checks)
    missing = [k for k, v in checks.items() if not v]
    return {"score": int((present / total) * 100), "present": present, "total": total, "missing": missing, "checks": checks}


def _extract_copyright_year(html: str) -> int | None:
    """Extract the most recent copyright year from HTML."""
    if not html:
        return None
    years = re.findall(r"\u00a9\s*(20\d{2})", html)  # © symbol
    if not years:
        years = re.findall(r"©\s*(20\d{2})", html)
    if not years:
        years = re.findall(r"copyright\s*(?:\u00a9?\s*)?(\d{4})", html, re.I)
    if not years:
        return None
    int_years = [int(y) for y in years if 2000 <= int(y) <= 2030]
    return max(int_years) if int_years else None


def _detect_urgency_pressure(html: str) -> list[str]:
    """Detect urgency/scarcity/pressure manipulation tactics."""
    if not html:
        return []
    text = re.sub(r"<[^>]+>", " ", html)
    found: list[str] = []
    seen_types: set[str] = set()
    for pattern, tactic_type in _URGENCY_PATTERNS:
        if tactic_type in seen_types:
            continue
        if pattern.search(text):
            found.append(tactic_type)
            seen_types.add(tactic_type)
    return found


def _detect_social_proof_widgets(html: str) -> list[str]:
    """Detect embedded third-party trust/review widgets in HTML."""
    if not html:
        return []
    h = html.lower()
    widgets: list[str] = []
    if "trustpilot" in h or "tp-widget" in h:
        widgets.append("trustpilot")
    if "bbb.org" in h or "bbb-seal" in h or "better business bureau" in h:
        widgets.append("bbb")
    if "mcafee" in h and "secure" in h:
        widgets.append("mcafee_secure")
    if "norton" in h and ("secured" in h or "seal" in h):
        widgets.append("norton_secured")
    if "google-reviews" in h or "google.com/maps" in h:
        widgets.append("google_reviews")
    if "judge.me" in h or "judgeme" in h:
        widgets.append("judge_me")
    if "stamped.io" in h or "stamped-reviews" in h:
        widgets.append("stamped")
    if "yotpo" in h:
        widgets.append("yotpo")
    if "loox" in h and "review" in h:
        widgets.append("loox")
    if "sitejabber" in h:
        widgets.append("sitejabber")
    if "shopper approved" in h or "shopperapproved" in h:
        widgets.append("shopper_approved")
    # Generic/fake trust badges (common on scam sites)
    if "trust-badge" in h or "trustbadge" in h or "safe-checkout" in h or "guaranteed-safe" in h:
        widgets.append("generic_trust_badge")
    return widgets


def _analyze_outbound_links(html: str, hostname: str) -> dict[str, Any]:
    """Analyze where outbound (external) links point."""
    if not html:
        return {"count": 0, "unique_domains": 0, "top_domains": []}
    own_domain = _registrable_domain_guess(hostname.lower())
    external_domains: dict[str, int] = {}
    for _, href in _HREF_RE.findall(html):
        href = (href or "").strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        try:
            p = urlparse(href)
            if p.scheme not in ("http", "https") or not p.hostname:
                continue
            link_domain = _registrable_domain_guess(p.hostname.lower())
            if link_domain == own_domain:
                continue
            external_domains[link_domain] = external_domains.get(link_domain, 0) + 1
        except Exception:
            continue
    sorted_domains = sorted(external_domains.items(), key=lambda kv: kv[1], reverse=True)
    return {
        "count": sum(external_domains.values()),
        "unique_domains": len(external_domains),
        "top_domains": [{"domain": d, "count": c} for d, c in sorted_domains[:10]],
    }


def _fetch_robots_txt_signals(hostname: str, timeout_ms: int, user_agent: str) -> dict[str, Any]:
    """Fetch and analyze robots.txt for suspicious patterns."""
    timeout = timeout_ms / 1000
    url = f"https://{hostname}/robots.txt"
    try:
        with httpx.Client(timeout=min(timeout, 5), follow_redirects=True) as client:
            res = client.get(url, headers={"user-agent": user_agent})
        if res.status_code == 404:
            return {"exists": False, "note": "No robots.txt"}
        if res.status_code != 200:
            return {"exists": False, "note": f"robots.txt status {res.status_code}"}
        text = res.text[:5000]
        lines = text.strip().split("\n")
        disallow_all = any(re.match(r"^\s*Disallow\s*:\s*/\s*$", ln, re.I) for ln in lines)
        has_sitemap = any("sitemap" in ln.lower() for ln in lines)
        disallow_count = sum(1 for ln in lines if ln.strip().lower().startswith("disallow"))
        return {
            "exists": True,
            "disallow_all": disallow_all,
            "has_sitemap_ref": has_sitemap,
            "disallow_count": disallow_count,
            "suspicious": disallow_all and not has_sitemap,
        }
    except Exception:
        return {"exists": False, "note": "Could not fetch robots.txt"}


def _detect_cookie_consent(html: str) -> bool:
    """Detect cookie consent / GDPR compliance indicators."""
    if not html:
        return False
    h = html.lower()
    indicators = (
        "cookie-consent", "cookie-banner", "cookie-notice", "cookie-popup",
        "cookieconsent", "cookie_consent", "gdpr", "ccpa",
        "onetrust", "cookiebot", "cookie-law", "cookie-policy",
        "accept cookies", "accept all cookies", "cookie preferences",
        "js-cookie-consent",
    )
    return any(ind in h for ind in indicators)


def _price_anomaly_signals(html: str) -> dict[str, Any]:
    """Detect suspicious pricing patterns."""
    if not html:
        return {"found": False}
    text = re.sub(r"<[^>]+>", " ", html)
    price_pattern = re.compile(
        r"(?:(?:\$|\u00a3|\u20ac|USD|GBP|EUR)\s?)(\d{1,6}(?:[.,]\d{2})?)", re.I
    )
    prices: list[float] = []
    for m in price_pattern.finditer(text):
        try:
            price = float(m.group(1).replace(",", ""))
            if 0.01 <= price <= 100000:
                prices.append(price)
        except Exception:
            continue
    if len(prices) < 3:
        return {"found": False, "price_count": len(prices)}
    avg_price = sum(prices) / len(prices)
    compare_pattern = re.compile(
        r"(?:compare\s+at|was|regular\s+price|original|retail)\s*[\$\u00a3\u20ac]?\s*(\d+(?:\.\d{2})?)", re.I
    )
    compare_prices = []
    for m in compare_pattern.finditer(text):
        try:
            compare_prices.append(float(m.group(1).replace(",", "")))
        except Exception:
            continue
    extreme_discounts = 0
    if compare_prices and prices:
        for cp in compare_prices:
            for p in prices:
                if cp > 0 and p < cp and (cp - p) / cp > 0.80:
                    extreme_discounts += 1
    return {
        "found": True,
        "price_count": len(prices),
        "avg_price": round(avg_price, 2),
        "min_price": round(min(prices), 2),
        "max_price": round(max(prices), 2),
        "extreme_discounts": extreme_discounts,
        "has_compare_pricing": len(compare_prices) > 0,
    }


# ---------------------------------------------------------------------------
# Screenshot capture bridge (async → sync)
# ---------------------------------------------------------------------------

def _capture_screenshot_sync(url: str, timeout_ms: int = 12000) -> bytes | None:
    """Capture a PNG screenshot via Playwright, bridging async → sync.

    Returns raw PNG bytes or *None* on any failure (Playwright not installed,
    browser crash, timeout, etc.).  Designed to run inside a ThreadPoolExecutor.
    """
    import asyncio

    try:
        from .screenshot import capture_screenshot
    except Exception:
        return None

    async def _run():
        result = await capture_screenshot(url, timeout_ms=timeout_ms)
        return result.data if result else None

    try:
        # Create a fresh event loop for the thread – safe inside a pool thread.
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_run())
        finally:
            loop.close()
    except Exception as exc:
        print(f"Screenshot capture failed: {exc}")
        return None


def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    t0 = time.perf_counter()

    normalized_url = _normalize_url(req.url)
    parsed = urlparse(normalized_url)
    hostname = parsed.hostname or ""
    is_well_known = _is_well_known(hostname)

    timings: dict[str, int] = {}
    warnings: list[str] = []

    def timed(name: str, fn):
        start = time.perf_counter()
        try:
            return fn()
        finally:
            timings[name] = int((time.perf_counter() - start) * 1000)

    # Parallel fetch: RDAP, HTTP signals, TLS, robots.txt, screenshot
    with ThreadPoolExecutor(max_workers=7) as pool:
        futures = {
            pool.submit(timed, "rdap", lambda: _fetch_rdap_domain_age_days(hostname, req.timeout_ms)): "rdap",
            pool.submit(timed, "fetch", lambda: _fetch_http_signals(normalized_url, req.timeout_ms, req.max_html_kb, req.user_agent)): "fetch",
            pool.submit(timed, "tls", lambda: _tls_info(hostname, req.timeout_ms)): "tls",
            pool.submit(timed, "robots", lambda: _fetch_robots_txt_signals(hostname, req.timeout_ms, req.user_agent)): "robots",
            pool.submit(timed, "screenshot", lambda: _capture_screenshot_sync(normalized_url, req.timeout_ms)): "screenshot",
        }

        domain_age_days: int | None = None
        fetch: FetchInfo | None = None
        tls: TLSInfo | None = None
        robots_signals: dict[str, Any] = {}
        screenshot_bytes: bytes | None = None

        for fut in as_completed(futures):
            name = futures[fut]
            try:
                value = fut.result()
            except Exception:
                value = None

            if name == "rdap":
                domain_age_days = value
            elif name == "fetch":
                fetch = value
            elif name == "tls":
                tls = value
            elif name == "robots":
                robots_signals = value or {}
            elif name == "screenshot":
                screenshot_bytes = value

    if fetch is None:
        fetch = FetchInfo(
            final_url=normalized_url, http_status=None, content_type=None,
            redirect_chain=[], headers={}, html_available=False,
            fetch_note="Unable to fetch homepage content.",
        )

    if tls is None:
        tls = TLSInfo(supported=False)

    ecommerce_signals = _ecommerce_signals(fetch.html_snippet)
    detected_platform = _detect_platform_from_html(fetch.html_snippet)

    # ── Extract rich signals from homepage HTML ─────────────────────
    homepage_html = fetch.html_snippet or ""
    social_links = _extract_social_media_links(homepage_html)
    phone_numbers = _extract_phone_numbers(homepage_html)
    payment_providers = _detect_payment_providers(homepage_html)
    meta_info = _check_meta_completeness(homepage_html)
    copyright_year = _extract_copyright_year(homepage_html)
    urgency_tactics = _detect_urgency_pressure(homepage_html)
    social_proof = _detect_social_proof_widgets(homepage_html)
    outbound_links = _analyze_outbound_links(homepage_html, hostname)
    has_cookie_consent = _detect_cookie_consent(homepage_html)
    price_signals = _price_anomaly_signals(homepage_html)

    # Crawl internal links for AI context
    crawl_info: CrawlInfo | None = None
    try:
        base_url_for_crawl = fetch.final_url or normalized_url

        if req.advanced_crawl:
            from .spider_crawler import spider_crawl as do_spider_crawl
            # Detect if the homepage redirected to a different host so the
            # spider knows both domains are valid crawl targets.  Without this
            # cross-platform redirects (e.g. shop.com → shop.myshopify.com)
            # cause 0 links to be followed → only 1 page crawled.
            redirect_host: str | None = None
            try:
                final_host = urlparse(base_url_for_crawl).hostname
                if final_host and final_host != hostname:
                    redirect_host = final_host
            except Exception:
                pass

            spider_result = do_spider_crawl(
                start_url=base_url_for_crawl,
                hostname=hostname,
                timeout_ms=req.timeout_ms,
                user_agent=req.user_agent,
                max_pages=30,
                max_depth=3,
                max_concurrent=8,
                redirect_hostname=redirect_host,
            )
            crawl_info = CrawlInfo(
                pages_requested=spider_result.pages_requested,
                pages_fetched=spider_result.pages_fetched,
                pages=spider_result.pages,
                crawl_mode=spider_result.crawl_mode,
                max_depth_reached=spider_result.max_depth_reached,
            )
        else:
            target_count = 12
            links: list[str] = []
            candidate_pool: list[str] = []
            if fetch.html_snippet and fetch.html_available:
                nav_links = _extract_nav_links(fetch.html_snippet, base_url_for_crawl, hostname, limit=target_count)
                for u in nav_links:
                    if u not in links:
                        links.append(u)
                candidate_pool.extend(nav_links)

                general_links = _extract_internal_links(fetch.html_snippet, base_url_for_crawl, hostname, limit=max(24, target_count))
                for u in general_links:
                    if len(links) >= target_count:
                        break
                    if u not in links:
                        links.append(u)
                candidate_pool.extend(general_links)

                more_links = _extract_internal_links(fetch.html_snippet, base_url_for_crawl, hostname, limit=40)
                candidate_pool.extend(more_links)

            sitemap_links: list[str] = []
            if len(links) < 8:
                sitemap_links = _fetch_sitemap_urls(base_url_for_crawl, hostname, timeout_ms=min(req.timeout_ms, 20000), user_agent=req.user_agent, limit=40)
                def sm_score(u: str) -> int:
                    path = urlparse(u).path.lower()
                    score = 0
                    for kw in ("about", "contact", "privacy", "terms", "refund", "return", "shipping", "policy", "track"):
                        if kw in path:
                            score += 20
                    for kw in ("/products/", "/collections/", "/pages/"):
                        if kw in path:
                            score += 5
                    if path.endswith(".xml") or path.endswith(".json"):
                        score -= 50
                    return score

                sitemap_links.sort(key=sm_score, reverse=True)
                for u in sitemap_links:
                    if len(links) >= target_count:
                        break
                    if u not in links:
                        links.append(u)

            candidate_pool.extend(sitemap_links)

            if len(ecommerce_signals) >= 2:
                pool_dedup: list[str] = []
                seen_pool: set[str] = set()
                for u in (sitemap_links + candidate_pool):
                    if u in seen_pool:
                        continue
                    if _is_low_value_page(u):
                        continue
                    seen_pool.add(u)
                    pool_dedup.append(u)
                links = _ensure_ecommerce_pages(links, pool_dedup, target_count=target_count, min_products=3, min_collections=1)

            if len(links) < 8:
                origin = f"{urlparse(base_url_for_crawl).scheme}://{hostname}"
                for path in (
                    "/pages/contact", "/pages/about-us", "/contact", "/about",
                    "/policies/privacy-policy", "/policies/refund-policy",
                    "/policies/terms-of-service", "/policies/shipping-policy",
                    "/collections/all", "/search",
                ):
                    if len(links) >= target_count:
                        break
                    u = _strip_fragment(urljoin(origin, path))
                    if u not in links and not _is_low_value_page(u):
                        links.append(u)

            pages: list[CrawlPage] = []
            if links:
                with ThreadPoolExecutor(max_workers=min(12, max(4, len(links)))) as crawl_pool:
                    crawl_futs = [
                        crawl_pool.submit(_fetch_page, link, req.timeout_ms, min(req.max_html_kb, 256), req.user_agent)
                        for link in links[:target_count]
                    ]
                    for fut in as_completed(crawl_futs):
                        try:
                            pages.append(fut.result())
                        except Exception:
                            continue

            pages_fetched = sum(1 for p in pages if p.http_status is not None)
            crawl_info = CrawlInfo(pages_requested=len(links[:target_count]), pages_fetched=pages_fetched, pages=pages, crawl_mode="basic")
    except Exception:
        crawl_info = None

    # ── Accumulate signals from crawled pages ────────────────────
    if crawl_info and crawl_info.pages:
        for cp in crawl_info.pages[:20]:
            if not cp.html_snippet:
                continue
            for platform, links in _extract_social_media_links(cp.html_snippet).items():
                if platform not in social_links:
                    social_links[platform] = []
                for lnk in links:
                    if lnk not in social_links[platform]:
                        social_links[platform].append(lnk)
            for pn in _extract_phone_numbers(cp.html_snippet):
                if pn not in phone_numbers:
                    phone_numbers.append(pn)
            for pp in _detect_payment_providers(cp.html_snippet):
                if pp not in payment_providers:
                    payment_providers.append(pp)
            for ut in _detect_urgency_pressure(cp.html_snippet):
                if ut not in urgency_tactics:
                    urgency_tactics.append(ut)
            for sp in _detect_social_proof_widgets(cp.html_snippet):
                if sp not in social_proof:
                    social_proof.append(sp)
            # Accumulate price signals from product pages
            if (cp.page_type or "") in ("product", "collection"):
                page_prices = _price_anomaly_signals(cp.html_snippet)
                if page_prices.get("found"):
                    price_signals["extreme_discounts"] = (
                        price_signals.get("extreme_discounts", 0)
                        + page_prices.get("extreme_discounts", 0)
                    )
                    price_signals["price_count"] = (
                        price_signals.get("price_count", 0)
                        + page_prices.get("price_count", 0)
                    )

    # ── Build structured signals dict for AI ───────────────────
    structured_signals: dict[str, Any] = {
        "social_media": social_links,
        "phone_numbers": phone_numbers[:5],
        "payment_providers": payment_providers,
        "meta_completeness": meta_info,
        "copyright_year": copyright_year,
        "urgency_tactics": urgency_tactics,
        "social_proof_widgets": social_proof,
        "outbound_links": outbound_links,
        "has_cookie_consent": has_cookie_consent,
        "price_signals": price_signals,
        "robots_txt": robots_signals,
        "ecommerce_signals": list(ecommerce_signals),
        "detected_platform": detected_platform,
    }

    # Build explainability items
    explainability: list[ExplainabilityItem] = []

    # HTTPS
    https_verdict: Verdict = "good" if parsed.scheme == "https" else "warn"
    explainability.append(ExplainabilityItem(
        key="https", label="HTTPS status", verdict=https_verdict,
        detail="Connection is encrypted (HTTPS)." if https_verdict == "good" else "Website is using HTTP; encryption may be missing.",
    ))

    # Domain age
    domain_verdict: Verdict = "unknown"
    domain_detail = "Domain age couldn't be determined from public registry data."
    if domain_age_days is not None:
        if domain_age_days >= 730:
            domain_verdict = "good"
            domain_detail = "Established domain (2+ years)."
        elif domain_age_days >= 180:
            domain_verdict = "warn"
            domain_detail = "Relatively new domain (under 2 years)."
        else:
            domain_verdict = "bad"
            domain_detail = "Very new domain (under 6 months)."
    explainability.append(ExplainabilityItem(key="domainAge", label="Domain age", verdict=domain_verdict, detail=domain_detail))

    # Repurposed domain heuristic: older domains that look like a generic storefront
    if (
        domain_age_days is not None
        and domain_age_days >= 365
        and not is_well_known
        and len(ecommerce_signals) >= 2
    ):
        explainability.append(
            ExplainabilityItem(
                key="domainRepurpose",
                label="Domain repurpose risk",
                verdict="warn",
                detail="Older domain now appears to operate as a storefront. Some scams repurpose aged domains; verify company identity, address, and policies.",
            )
        )

    # Platform fingerprinting
    if detected_platform != "unknown":
        platform_verdict: Verdict = "good" if detected_platform == "custom" else "warn"
        platform_detail = f"Platform fingerprint: {detected_platform}."
        if detected_platform in ("shopify", "wordpress") and not is_well_known:
            platform_detail = (
                f"Platform fingerprint: {detected_platform}. Hosted storefront platforms require extra verification of business identity and policies."
            )
        explainability.append(
            ExplainabilityItem(
                key="platform",
                label="Platform fingerprint",
                verdict=platform_verdict,
                detail=platform_detail,
            )
        )

    # Ownership identity extraction (best-effort)
    try:
        pages_for_identity: list[str] = [fetch.html_snippet or ""]
        if crawl_info and crawl_info.pages:
            for p in crawl_info.pages[:20]:
                if p.html_snippet:
                    pages_for_identity.append(p.html_snippet)

        company_names: list[str] = []
        addresses: list[str] = []
        emails: set[str] = set()
        addr_counts: dict[str, int] = {}

        for html in pages_for_identity:
            if not html:
                continue
            emails |= _extract_emails(html)
            names, addrs = _extract_org_identity_from_html(html)
            company_names.extend(list(names))
            addresses.extend(list(addrs))
            for a in addrs:
                norm = _normalize_address(a)
                if norm:
                    addr_counts[norm] = addr_counts.get(norm, 0) + 1

        name_counts: dict[str, int] = {}
        for n in company_names:
            key = (n or "").strip()
            if key:
                name_counts[key] = name_counts.get(key, 0) + 1
        top_name = sorted(name_counts.items(), key=lambda kv: kv[1], reverse=True)[0][0] if name_counts else None

        top_addr = None
        if addr_counts:
            best_norm = sorted(addr_counts.items(), key=lambda kv: kv[1], reverse=True)[0][0]
            for a in addresses:
                if _normalize_address(a) == best_norm:
                    top_addr = a
                    break

        site_reg = _registrable_domain_guess(hostname.lower())
        email_domains = sorted({e.split("@", 1)[-1] for e in emails if "@" in e})
        email_reg_domains = sorted({_registrable_domain_guess(d.lower()) for d in email_domains if d})
        email_mismatch = bool(email_reg_domains and site_reg and all(ed != site_reg for ed in email_reg_domains))

        conflicting_addresses = len(set(addr_counts.keys())) >= 2
        addr_repeated = any(c >= 2 for c in addr_counts.values()) if addr_counts else False

        details: list[str] = []
        if top_name:
            details.append(f"Company name: {top_name}")
        if top_addr:
            details.append("Address found")
        if email_domains:
            details.append(f"Email domain(s): {', '.join(email_domains[:3])}{'…' if len(email_domains) > 3 else ''}")

        ownership_verdict: Verdict = "unknown"
        if details:
            ownership_verdict = "warn"
        if top_name and (top_addr or email_domains) and not email_mismatch and not conflicting_addresses:
            ownership_verdict = "good" if addr_repeated else "warn"
            if top_addr and not addr_repeated:
                details.append("Address appears on only one page")

        if email_mismatch:
            ownership_verdict = "warn"
            details.append("Website domain and email domain do not match")
            warnings.append("Ownership identity: website domain differs from contact email domain")

        if conflicting_addresses:
            ownership_verdict = "warn"
            details.append("Different addresses appear across pages")
            warnings.append("Ownership identity: multiple different addresses detected")

        if details:
            explainability.append(
                ExplainabilityItem(
                    key="ownershipIdentity",
                    label="Ownership identity",
                    verdict=ownership_verdict,
                    detail=" • ".join(details),
                )
            )
    except Exception:
        pass

    # Language consistency (homepage vs policy pages)
    try:
        homepage_quality = _language_quality_score(fetch.html_snippet or "")
        policy_text = ""
        if crawl_info and crawl_info.pages:
            policy_snips = [p.html_snippet for p in crawl_info.pages if (p.page_type or "") == "policy" and p.html_snippet]
            policy_text = "\n\n".join(policy_snips[:6])

        policy_quality = _language_quality_score(policy_text)
        mixed_spelling = _mixed_us_uk_spelling((fetch.html_snippet or "") + "\n" + (policy_text or ""))

        lang_bits: list[str] = []
        lang_verdict: Verdict = "unknown"
        if homepage_quality:
            lang_bits.append(f"Homepage quality: {homepage_quality}/100")
        if policy_text.strip():
            lang_bits.append(f"Policy quality: {policy_quality}/100")

        if policy_text.strip() and (homepage_quality - policy_quality) >= 18 and policy_quality <= 55:
            lang_verdict = "warn"
            lang_bits.append("Policy pages read lower-quality than homepage")
        elif mixed_spelling:
            lang_verdict = "warn"
            lang_bits.append("Mixed US/UK spelling detected")
        elif homepage_quality >= 70 and (not policy_text.strip() or policy_quality >= 65):
            lang_verdict = "good"
        elif homepage_quality:
            lang_verdict = "warn"

        if lang_bits and lang_verdict != "unknown":
            explainability.append(
                ExplainabilityItem(
                    key="languageConsistency",
                    label="Language consistency",
                    verdict=lang_verdict,
                    detail=" • ".join(lang_bits),
                )
            )
    except Exception:
        pass

    # Established brand
    if is_well_known:
        explainability.append(ExplainabilityItem(
            key="establishedBrand", label="Established brand", verdict="good",
            detail="This is a widely recognized, established website.",
        ))

    # Content availability
    if not fetch.html_available:
        explainability.append(ExplainabilityItem(
            key="contentAvailability", label="Homepage content", verdict="unknown",
            detail=fetch.fetch_note or "Homepage content wasn't available for automated checks.",
        ))

    # Redirect chain
    redirect_info = _redirect_verdict_and_detail(normalized_url, fetch)
    if redirect_info is not None:
        redir_verdict, redir_detail = redirect_info
        explainability.append(
            ExplainabilityItem(
                key="redirects",
                label="Redirect behavior",
                verdict=redir_verdict,
                detail=redir_detail,
            )
        )

    # Security headers
    security_score = 0
    if "strict-transport-security" in fetch.headers:
        security_score += 1
    if "content-security-policy" in fetch.headers:
        security_score += 1
    if "x-frame-options" in fetch.headers:
        security_score += 1

    if security_score >= 2:
        explainability.append(ExplainabilityItem(
            key="securityHeaders", label="Security headers", verdict="good",
            detail="Site advertises modern security protections in HTTP headers.",
        ))
    elif security_score == 1:
        explainability.append(ExplainabilityItem(
            key="securityHeaders", label="Security headers", verdict="warn",
            detail="Some security protections are present in HTTP headers.",
        ))
    else:
        explainability.append(ExplainabilityItem(
            key="securityHeaders", label="Security headers",
            verdict="unknown" if not fetch.headers else "warn",
            detail="Security header signals were limited or not observable.",
        ))

    # TLS certificate
    if tls.supported:
        if tls.days_to_expiry is not None and tls.days_to_expiry < 7:
            explainability.append(ExplainabilityItem(
                key="tlsCert", label="TLS certificate", verdict="warn",
                detail="TLS certificate is close to expiry; this is usually a maintenance issue.",
            ))
        else:
            explainability.append(ExplainabilityItem(
                key="tlsCert", label="TLS certificate", verdict="good",
                detail="TLS certificate was observed and appears valid.",
            ))
    else:
        explainability.append(ExplainabilityItem(
            key="tlsCert", label="TLS certificate", verdict="unknown",
            detail="TLS certificate could not be checked (site may not support HTTPS on 443).",
        ))

    # TLS issuer interpretation
    issuer_info = _tls_issuer_verdict_and_detail(tls)
    if issuer_info is not None:
        issuer_verdict, issuer_detail = issuer_info
        explainability.append(
            ExplainabilityItem(
                key="tlsIssuer",
                label="Certificate issuer",
                verdict=issuer_verdict,
                detail=issuer_detail,
            )
        )

    # Fetch external reviews
    external_reviews_text: str | None = None
    if req.check_external_reviews:
        try:
            external_reviews_text = fetch_external_reviews(hostname, timeout_ms=5000)
        except Exception:
            external_reviews_text = None
            warnings.append("External reviews: unavailable (blocked or network error)")

    # ── NEW: Contact information richness ───────────────────────
    try:
        contact_details: list[str] = []
        contact_verdict: Verdict = "unknown"
        if phone_numbers:
            contact_details.append(f"{len(phone_numbers)} phone number(s) found")
        social_platforms = [p for p, links in social_links.items() if links]
        if social_platforms:
            contact_details.append(f"Social media: {', '.join(social_platforms)}")
        if phone_numbers and len(social_platforms) >= 2:
            contact_verdict = "good"
        elif phone_numbers or social_platforms:
            contact_verdict = "warn"
        else:
            contact_details.append("No phone numbers or social media links detected")
            contact_verdict = "warn" if not is_well_known else "unknown"
        if contact_details:
            explainability.append(ExplainabilityItem(
                key="contactInfo", label="Contact information",
                verdict=contact_verdict, detail=" \u2022 ".join(contact_details),
            ))
    except Exception:
        pass

    # ── NEW: Payment security ────────────────────────────────
    try:
        known_secure = {"stripe", "paypal", "square", "apple_pay", "google_pay", "shopify_payments"}
        if payment_providers:
            secure_found = [p for p in payment_providers if p in known_secure]
            if secure_found:
                explainability.append(ExplainabilityItem(
                    key="paymentSecurity", label="Payment processors",
                    verdict="good",
                    detail=f"Recognized processor(s): {', '.join(p.replace('_', ' ').title() for p in payment_providers)}",
                ))
            else:
                explainability.append(ExplainabilityItem(
                    key="paymentSecurity", label="Payment processors",
                    verdict="warn",
                    detail=f"Payment indicator(s): {', '.join(p.replace('_', ' ').title() for p in payment_providers)}",
                ))
        elif len(ecommerce_signals) >= 2:
            explainability.append(ExplainabilityItem(
                key="paymentSecurity", label="Payment processors",
                verdict="warn",
                detail="E-commerce site but no recognized payment processors detected.",
            ))
    except Exception:
        pass

    # ── NEW: Urgency / pressure tactics ───────────────────────
    if urgency_tactics:
        ut_count = len(urgency_tactics)
        ut_verdict: Verdict = "bad" if ut_count >= 3 else "warn"
        explainability.append(ExplainabilityItem(
            key="urgencyTactics", label="Urgency/pressure tactics",
            verdict=ut_verdict,
            detail=f"Detected {ut_count} manipulation pattern(s): {', '.join(urgency_tactics[:5])}. Common on scam sites.",
        ))

    # ── NEW: Social proof widgets ────────────────────────────
    try:
        generic_badges = {"generic_trust_badge"}
        real_widgets = [w for w in social_proof if w not in generic_badges]
        fake_badges = [w for w in social_proof if w in generic_badges]
        if real_widgets:
            explainability.append(ExplainabilityItem(
                key="socialProof", label="Third-party review widgets",
                verdict="good",
                detail=f"Embedded review widget(s): {', '.join(w.replace('_', ' ').title() for w in real_widgets)}",
            ))
        if fake_badges:
            explainability.append(ExplainabilityItem(
                key="genericBadges", label="Generic trust badges",
                verdict="warn",
                detail="Generic 'trust badges' or 'safe checkout' images found. Easily faked and common on scam sites.",
            ))
    except Exception:
        pass

    # ── NEW: Meta tag completeness ───────────────────────────
    try:
        if meta_info.get("score", 0) > 0:
            meta_score_val = meta_info["score"]
            meta_verdict: Verdict = "good" if meta_score_val >= 70 else ("warn" if meta_score_val >= 40 else "bad")
            missing_str = ", ".join(meta_info.get("missing", [])[:4])
            meta_detail = f"Meta tag completeness: {meta_info['present']}/{meta_info['total']}"
            if missing_str and meta_score_val < 100:
                meta_detail += f" (missing: {missing_str})"
            explainability.append(ExplainabilityItem(
                key="metaTags", label="Site metadata",
                verdict=meta_verdict, detail=meta_detail,
            ))
    except Exception:
        pass

    # ── NEW: Copyright freshness ─────────────────────────────
    try:
        if copyright_year is not None:
            current_year = datetime.now(timezone.utc).year
            if copyright_year >= current_year - 1:
                explainability.append(ExplainabilityItem(
                    key="copyrightYear", label="Copyright year",
                    verdict="good", detail=f"Copyright year ({copyright_year}) is current.",
                ))
            elif copyright_year >= current_year - 3:
                explainability.append(ExplainabilityItem(
                    key="copyrightYear", label="Copyright year",
                    verdict="warn", detail=f"Copyright year ({copyright_year}) is slightly outdated.",
                ))
            else:
                explainability.append(ExplainabilityItem(
                    key="copyrightYear", label="Copyright year",
                    verdict="warn",
                    detail=f"Copyright year ({copyright_year}) is significantly outdated \u2014 may indicate abandoned or repurposed site.",
                ))
    except Exception:
        pass

    # ── NEW: Cookie / privacy compliance ──────────────────────
    if has_cookie_consent:
        explainability.append(ExplainabilityItem(
            key="privacyCompliance", label="Privacy compliance",
            verdict="good",
            detail="Cookie consent / GDPR indicators found \u2014 suggests awareness of privacy regulations.",
        ))

    # ── NEW: Price anomaly signals ───────────────────────────
    if price_signals.get("found") and price_signals.get("extreme_discounts", 0) >= 2:
        explainability.append(ExplainabilityItem(
            key="priceAnomaly", label="Pricing patterns",
            verdict="bad",
            detail="Multiple products show extreme discounts (80%+ off 'original' price). Common scam tactic.",
        ))
    elif price_signals.get("found") and price_signals.get("extreme_discounts", 0) >= 1:
        explainability.append(ExplainabilityItem(
            key="priceAnomaly", label="Pricing patterns",
            verdict="warn",
            detail="Some products show very steep discounts from 'compare at' prices.",
        ))

    # ── NEW: robots.txt signals ─────────────────────────────
    if robots_signals.get("suspicious"):
        explainability.append(ExplainabilityItem(
            key="robotsTxt", label="robots.txt analysis",
            verdict="warn",
            detail="robots.txt blocks all crawlers with no sitemap \u2014 unusual for legitimate commercial sites.",
        ))
    elif robots_signals.get("exists") and robots_signals.get("has_sitemap_ref"):
        explainability.append(ExplainabilityItem(
            key="robotsTxt", label="robots.txt analysis",
            verdict="good",
            detail="Well-formed robots.txt with sitemap reference.",
        ))

    # AI Judgment - PRIMARY scoring mechanism
    # Run visual analysis and main AI judge in parallel for speed.
    ai_judgment: AIJudgment | None = None
    visual_result: dict[str, Any] | None = None
    crawled_pages_data = [p.model_dump() for p in (crawl_info.pages if crawl_info else [])]

    def _run_main_judge():
        return judge_website(
            url=normalized_url,
            hostname=hostname,
            domain_age_days=domain_age_days,
            is_well_known=is_well_known,
            http_status=fetch.http_status,
            homepage_html=fetch.html_snippet,
            crawled_pages=crawled_pages_data,
            external_reviews=external_reviews_text,
            structured_signals=structured_signals,
            screenshot_bytes=screenshot_bytes,
        )

    def _run_visual_analysis():
        if not screenshot_bytes:
            return None
        return visual_analyze_screenshot(screenshot_bytes, normalized_url, hostname)

    with ThreadPoolExecutor(max_workers=2) as ai_pool:
        judge_fut = ai_pool.submit(timed, "ai_judge", _run_main_judge)
        visual_fut = ai_pool.submit(timed, "visual_analysis", _run_visual_analysis)
        ai_result = judge_fut.result()
        visual_result = visual_fut.result()

    # Merge visual analysis into structured signals
    if visual_result:
        structured_signals["visual_analysis"] = visual_result

    # ── Visual analysis explainability items ──────────────────────
    if visual_result:
        try:
            vts = visual_result.get("visual_trust_score", 50)
            layout_q = visual_result.get("layout_quality", "acceptable")
            visual_summary = visual_result.get("visual_summary", "")

            # Main visual verdict
            if vts >= 70:
                v_verdict: Verdict = "good"
            elif vts >= 40:
                v_verdict = "warn"
            else:
                v_verdict = "bad"

            explainability.append(ExplainabilityItem(
                key="visualAnalysis",
                label="Visual scam detection",
                verdict=v_verdict,
                detail=f"Visual trust score: {vts}/100 • Layout: {layout_q}. {visual_summary}",
            ))

            # Specific visual red flags
            suspicious = visual_result.get("suspicious_elements", [])
            if suspicious:
                explainability.append(ExplainabilityItem(
                    key="visualRedFlags",
                    label="Visual red flags",
                    verdict="bad" if len(suspicious) >= 3 else "warn",
                    detail=f"Suspicious visual elements: {', '.join(suspicious[:5])}",
                ))

            if visual_result.get("fake_badge_detected"):
                explainability.append(ExplainabilityItem(
                    key="fakeBadgeVisual",
                    label="Fake trust badge (visual)",
                    verdict="bad",
                    detail="Visual analysis detected fake or generic trust badges in the screenshot.",
                ))

            if visual_result.get("urgency_visuals"):
                explainability.append(ExplainabilityItem(
                    key="urgencyVisual",
                    label="Urgency visuals detected",
                    verdict="warn",
                    detail="Screenshot shows countdown timers, urgency banners, or 'limited stock' visual elements.",
                ))

            if visual_result.get("popup_overlay_detected"):
                explainability.append(ExplainabilityItem(
                    key="popupOverlay",
                    label="Aggressive popups",
                    verdict="warn",
                    detail="Screenshot shows popup overlays or aggressive email/notification captures.",
                ))

            # Positive visual signals
            trust_indicators = visual_result.get("trust_indicators", [])
            if trust_indicators:
                explainability.append(ExplainabilityItem(
                    key="visualPositive",
                    label="Visual trust signals",
                    verdict="good",
                    detail=f"Positive visual indicators: {', '.join(trust_indicators[:5])}",
                ))
        except Exception:
            pass
    elif screenshot_bytes:
        # Screenshot was captured but visual analysis failed
        warnings.append("Visual analysis: screenshot captured but Gemini visual analysis failed")

    if ai_result:
        try:
            ai_judgment = AIJudgment.model_validate(ai_result)

            conf = ai_judgment.confidence
            conf_verdict: Verdict = "unknown"
            if conf == "high":
                conf_verdict = "good"
            elif conf in ("medium", "low"):
                conf_verdict = "warn"

            explainability.append(
                ExplainabilityItem(
                    key="aiConfidence",
                    label="AI confidence",
                    verdict=conf_verdict,
                    detail=f"{conf.capitalize()} confidence based on the quality/availability of evidence.",
                )
            )

            # Add AI explainability
            ai_verdict: Verdict = "unknown"
            if ai_judgment.verdict == "legitimate":
                ai_verdict = "good"
            elif ai_judgment.verdict == "caution":
                ai_verdict = "warn"
            elif ai_judgment.verdict in ("suspicious", "likely_deceptive"):
                ai_verdict = "bad"

            explainability.append(ExplainabilityItem(
                key="aiJudgment", label="AI Legitimacy Analysis", verdict=ai_verdict,
                detail=ai_judgment.summary,
            ))

            # Add detected issues
            for i, issue in enumerate(ai_judgment.detected_issues[:3]):
                explainability.append(ExplainabilityItem(
                    key=f"aiIssue{i}", label="Detected Issue",
                    verdict="bad" if ai_judgment.verdict in ("suspicious", "likely_deceptive") else "warn",
                    detail=issue,
                ))
        except Exception as e:
            warnings.append(f"AI judgment parse error: {e}")

    # Score calculation - AI IS PRIMARY when available
    if ai_judgment:
        score = int(ai_judgment.legitimacy_score)

        # Post-adjustments for high-signal technical indicators.
        # These should be small so AI remains primary.
        if redirect_info is not None:
            redir_verdict, _ = redirect_info
            if redir_verdict == "bad":
                score -= 12
            else:
                score -= 2

        if (
            domain_age_days is not None
            and domain_age_days >= 365
            and not is_well_known
            and len(ecommerce_signals) >= 2
        ):
            score -= 6

        issuer_info2 = _tls_issuer_verdict_and_detail(tls)
        if issuer_info2 is not None:
            issuer_verdict2, _ = issuer_info2
            if issuer_verdict2 == "warn":
                score -= 2

        # NEW: Urgency / pressure tactic penalties
        if urgency_tactics and len(urgency_tactics) >= 3:
            score -= 8
        elif urgency_tactics:
            score -= 3

        # NEW: Extreme pricing penalty
        if price_signals.get("extreme_discounts", 0) >= 2:
            score -= 6

        # NEW: Contact info bonus
        if phone_numbers and len(social_links) >= 2:
            score += 3

        # NEW: Recognized payment processor bonus
        known_secure_pp = {"stripe", "paypal", "square", "apple_pay", "google_pay", "shopify_payments"}
        if any(p in known_secure_pp for p in payment_providers):
            score += 2

        # NEW: Generic trust badge penalty (scam indicator)
        if "generic_trust_badge" in social_proof and not any(w in social_proof for w in ("trustpilot", "bbb", "google_reviews")):
            score -= 3

        # ── VISUAL ANALYSIS score adjustments ────────────────────
        if visual_result:
            vts = visual_result.get("visual_trust_score", 50)
            # Blend: if visual score disagrees strongly with text score, nudge
            if vts <= 30 and score >= 60:
                score -= 10  # visuals scream scam, text looks ok → lower
            elif vts >= 75 and score <= 40:
                score += 5   # visuals professional, but text signals bad → small bump
            # Specific penalties/bonuses
            if visual_result.get("fake_badge_detected"):
                score -= 5
            if visual_result.get("urgency_visuals"):
                score -= 4
            if visual_result.get("popup_overlay_detected"):
                score -= 3
            if visual_result.get("layout_quality") == "template_clone":
                score -= 4
            elif visual_result.get("layout_quality") == "professional":
                score += 3

        final_score = _clamp_score(score)
    else:
        # Fallback heuristic
        score = 50

        def add(v: Verdict, good: int, warn: int, bad: int, unknown: int):
            nonlocal score
            if v == "good":
                score += good
            elif v == "warn":
                score += warn
            elif v == "bad":
                score += bad
            else:
                score += unknown

        add(https_verdict, good=12, warn=-10, bad=-15, unknown=0)
        add(domain_verdict, good=15, warn=5, bad=-12, unknown=10 if is_well_known else 0)

        snippet_lower = (fetch.html_snippet or "").lower()
        if snippet_lower and ("cdn.shopify.com" in snippet_lower or "shopify" in snippet_lower) and not is_well_known:
            explainability.append(ExplainabilityItem(
                key="siteTemplate", label="Site template signals", verdict="warn",
                detail="Site appears to use a common hosted storefront/template; verify business identity and policies.",
            ))
            score -= 6

        if not fetch.html_available:
            score += 6 if is_well_known else 0

        score += security_score * 2
        if is_well_known:
            score += 15

        final_score = _clamp_score(score)

    timings["total"] = int((time.perf_counter() - t0) * 1000)

    return AnalyzeResponse(
        normalized_url=fetch.final_url or normalized_url,
        hostname=hostname,
        score=final_score,
        status=_status_for(final_score),
        explainability=explainability,
        domain_age_days=domain_age_days,
        tls=tls,
        fetch=fetch,
        crawl=crawl_info,
        ai_judgment=ai_judgment,
        external_reviews=external_reviews_text,
        visual_analysis=visual_result,
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        timings_ms=timings,
        warnings=warnings,
        signals=structured_signals,
    )
