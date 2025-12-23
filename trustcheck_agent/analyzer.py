from __future__ import annotations

import re
import socket
import ssl
import time
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

    # Crawl internal links for AI context (aim: 8-12 pages). Do best-effort even if homepage HTML is blocked.
    crawl_info: CrawlInfo | None = None
    try:
        base_url_for_crawl = fetch.final_url or normalized_url
        target_count = 12

        links: list[str] = []
        if fetch.html_snippet and fetch.html_available:
            # 1) Navbar/header links first (human-important pages)
            nav_links = _extract_nav_links(fetch.html_snippet, base_url_for_crawl, hostname, limit=target_count)
            for u in nav_links:
                if u not in links:
                    links.append(u)

            # 2) Then general internal links to fill gaps
            general_links = _extract_internal_links(fetch.html_snippet, base_url_for_crawl, hostname, limit=target_count)
            for u in general_links:
                if len(links) >= target_count:
                    break
                if u not in links:
                    links.append(u)

        # If we still don't have enough, try sitemap.xml.
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
            ai_judgment = AIJudgment(
                legitimacy_score=ai_result.get("legitimacy_score", 50),
                confidence=ai_result.get("confidence", "medium"),
                verdict=ai_result.get("verdict", "caution"),
                category=ai_result.get("category", "unknown"),
                detected_issues=ai_result.get("detected_issues", []),
                positive_signals=ai_result.get("positive_signals", []),
                platform=ai_result.get("platform", "unknown"),
                product_legitimacy=ai_result.get("product_legitimacy", "unknown"),
                business_identity=ai_result.get("business_identity", "unknown"),
                summary=ai_result.get("summary", "Analysis completed"),
                recommendation=ai_result.get("recommendation", "Exercise caution"),
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
        final_score = _clamp_score(ai_judgment.legitimacy_score)
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
