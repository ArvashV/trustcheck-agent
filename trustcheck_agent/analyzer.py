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

from .ai_judge import fetch_external_reviews, judge_website
from .models import AIJudgment, AnalyzeRequest, AnalyzeResponse, CrawlInfo, CrawlPage, ExplainabilityItem, FetchInfo, TLSInfo, Verdict


_WELL_KNOWN_DOMAINS = {
    "amazon.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "github.com",
    "wikipedia.org",
    "paypal.com",
    "stripe.com",
    "netflix.com",
    "linkedin.com",
    "reddit.com",
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

    # Parallel fetch: RDAP, HTTP signals, TLS
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {
            pool.submit(timed, "rdap", lambda: _fetch_rdap_domain_age_days(hostname, req.timeout_ms)): "rdap",
            pool.submit(timed, "fetch", lambda: _fetch_http_signals(normalized_url, req.timeout_ms, req.max_html_kb, req.user_agent)): "fetch",
            pool.submit(timed, "tls", lambda: _tls_info(hostname, req.timeout_ms)): "tls",
        }

        domain_age_days: int | None = None
        fetch: FetchInfo | None = None
        tls: TLSInfo | None = None

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

    # Crawl internal links for AI context (aim: 8-12 pages). Do best-effort even if homepage HTML is blocked.
    crawl_info: CrawlInfo | None = None
    try:
        base_url_for_crawl = fetch.final_url or normalized_url
        target_count = 12

        links: list[str] = []
        candidate_pool: list[str] = []
        if fetch.html_snippet and fetch.html_available:
            # 1) Navbar/header links first (human-important pages)
            nav_links = _extract_nav_links(fetch.html_snippet, base_url_for_crawl, hostname, limit=target_count)
            for u in nav_links:
                if u not in links:
                    links.append(u)
            candidate_pool.extend(nav_links)

            # 2) Then general internal links to fill gaps
            general_links = _extract_internal_links(fetch.html_snippet, base_url_for_crawl, hostname, limit=max(24, target_count))
            for u in general_links:
                if len(links) >= target_count:
                    break
                if u not in links:
                    links.append(u)
            candidate_pool.extend(general_links)

            # 3) Build a bigger candidate pool so we can pick product pages if needed.
            more_links = _extract_internal_links(fetch.html_snippet, base_url_for_crawl, hostname, limit=40)
            candidate_pool.extend(more_links)

        # If we still don't have enough, try sitemap.xml.
        sitemap_links: list[str] = []
        if len(links) < 8:
            sitemap_links = _fetch_sitemap_urls(base_url_for_crawl, hostname, timeout_ms=min(req.timeout_ms, 20000), user_agent=req.user_agent, limit=40)
            # Prefer “human pages” first for analysis.
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

        # E-commerce enrichment: make sure we crawl some real product pages.
        if len(ecommerce_signals) >= 2:
            # Prefer sitemap candidates first (more reliable coverage than random internal links)
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

        # Final fallback: common paths (even without homepage HTML)
        if len(links) < 8:
            origin = f"{urlparse(base_url_for_crawl).scheme}://{hostname}"
            for path in (
                "/pages/contact",
                "/pages/about-us",
                "/contact",
                "/about",
                "/policies/privacy-policy",
                "/policies/refund-policy",
                "/policies/terms-of-service",
                "/policies/shipping-policy",
                "/collections/all",
                "/search",
            ):
                if len(links) >= target_count:
                    break
                u = _strip_fragment(urljoin(origin, path))
                if u not in links:
                    if not _is_low_value_page(u):
                        links.append(u)

        pages: list[CrawlPage] = []
        if links:
            # More workers because we fetch more pages now.
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
        crawl_info = CrawlInfo(pages_requested=len(links[:target_count]), pages_fetched=pages_fetched, pages=pages)
    except Exception:
        crawl_info = None

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

    # AI Judgment - PRIMARY scoring mechanism
    ai_judgment: AIJudgment | None = None
    crawled_pages_data = [p.model_dump() for p in (crawl_info.pages if crawl_info else [])]

    ai_result = judge_website(
        url=normalized_url,
        hostname=hostname,
        domain_age_days=domain_age_days,
        is_well_known=is_well_known,
        http_status=fetch.http_status,
        homepage_html=fetch.html_snippet,
        crawled_pages=crawled_pages_data,
        external_reviews=external_reviews_text,
    )

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
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        timings_ms=timings,
        warnings=warnings,
    )
