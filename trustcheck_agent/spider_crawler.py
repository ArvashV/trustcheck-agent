from __future__ import annotations
from typing import Literal
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque
from urllib.parse import urlparse, urljoin, urlunparse
import logging
import re
import threading
import time
import httpx

from .models import CrawlPage, CrawlInfo

logger = logging.getLogger(__name__)

try:
    from spidercrawl import spider_crawl as rust_spider_crawl, SpiderCrawlResult
    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False

_HREF_RE = re.compile(r'''href\s*=\s*["']([^"']+)["']''', re.IGNORECASE)
_HREF_RE_NOQUOTE = re.compile(r'''href\s*=\s*([^\s>"']+)''', re.IGNORECASE)

# Common ccTLDs / second-level domains that must not be treated as registrable domains.
_CCTLD_SECOND_LEVELS = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
    "com.au", "net.au", "org.au", "edu.au",
    "co.nz", "net.nz", "org.nz",
    "co.za", "org.za", "web.za",
    "com.br", "net.br", "org.br",
    "co.jp", "or.jp", "ne.jp", "ac.jp",
    "co.kr", "or.kr", "ne.kr",
    "com.cn", "net.cn", "org.cn",
    "com.tw", "net.tw", "org.tw",
    "com.hk", "net.hk", "org.hk",
    "com.sg", "net.sg", "org.sg",
    "com.my", "net.my", "org.my",
    "co.id", "or.id", "web.id",
    "com.ph", "net.ph", "org.ph",
    "co.th", "or.th", "in.th",
    "com.vn", "net.vn", "org.vn",
    "co.il", "org.il", "net.il",
    "com.tr", "net.tr", "org.tr",
    "com.sa", "net.sa", "org.sa",
    "com.eg", "net.eg", "org.eg",
    "co.ke", "or.ke",
    "com.ng", "net.ng", "org.ng",
    "com.mx", "net.mx", "org.mx",
    "com.ar", "net.ar", "org.ar",
    "com.co", "net.co", "org.co",
    "com.pe", "net.pe", "org.pe",
    "com.ua", "net.ua", "org.ua",
    "co.de", "com.de",
    "co.it",
    "com.fr", "asso.fr",
    "com.es", "org.es", "nom.es",
    "com.pt", "org.pt",
    "com.pl", "net.pl", "org.pl",
    "com.ru", "net.ru", "org.ru",
    "com.pk", "net.pk", "org.pk",
    "com.bd", "net.bd", "org.bd",
})

class SpiderLink:
    def __init__(self, url: str, parent_url: str | None, depth: int, link_type: str):
        self.url = url
        self.parent_url = parent_url
        self.depth = depth
        self.link_type = link_type

class SpiderCrawlInfo:
    def __init__(self, pages_requested: int, pages_fetched: int, pages: list[CrawlPage], 
                 link_graph: list[SpiderLink], max_depth_reached: int, crawl_mode: str):
        self.pages_requested = pages_requested
        self.pages_fetched = pages_fetched
        self.pages = pages
        self.link_graph = link_graph
        self.max_depth_reached = max_depth_reached
        self.crawl_mode = crawl_mode

def spider_crawl(
    start_url: str,
    hostname: str,
    timeout_ms: int = 20000,
    user_agent: str = "Mozilla/5.0 TrustCheckSpider/1.0",
    max_pages: int = 30,
    max_depth: int = 3,
    max_concurrent: int = 8,
    redirect_hostname: str | None = None,
) -> SpiderCrawlInfo:
    """Crawl a website starting from *start_url*, respecting depth/page limits.

    Tries the compiled Rust spider first for speed; falls back to pure-Python.
    *max_concurrent* defaults to 8 (reduced from 20) to avoid triggering
    CDN/WAF rate-limiters on legitimate sites — aggressive concurrency was
    causing more pages to be fetched from unprotected scam sites than from
    well-secured legitimate ones, skewing trust scores.

    *redirect_hostname* — if the caller already knows the site redirected to a
    different host (e.g. ``mystore.myshopify.com``), pass it here so both the
    original and redirect domains are treated as valid crawl targets from the
    start.  Without this, cross-platform redirects (Shopify, BigCartel,
    Squarespace, etc.) cause every extracted link to be rejected by the domain
    filter, leaving the crawl stuck at 1 page.
    """
    if RUST_AVAILABLE:
        try:
            # Rust crawler currently takes a single hostname — pass the redirect
            # hostname (the one with actual content) when available.
            effective_hostname = redirect_hostname or hostname
            result = rust_spider_crawl(
                start_url, effective_hostname, timeout_ms, user_agent, max_pages, max_depth, max_concurrent
            )
            pages = [CrawlPage(
                url=p.url, final_url=p.final_url, http_status=p.http_status,
                content_type=p.content_type, html_snippet=p.html_snippet,
                fetch_note=p.fetch_note, page_type=p.page_type
            ) for p in result.pages]
            links = [SpiderLink(l.url, l.parent_url, l.depth, l.link_type) for l in result.link_graph]
            return SpiderCrawlInfo(
                result.pages_requested, result.pages_fetched, pages, links,
                result.max_depth_reached, "advanced_rust"
            )
        except Exception as exc:
            logger.warning("Rust spider_crawl failed, falling back to Python: %s", exc)
    return _python_spider_crawl(start_url, hostname, timeout_ms, user_agent, max_pages, max_depth, max_concurrent, redirect_hostname)

def _python_spider_crawl(
    start_url: str,
    hostname: str,
    timeout_ms: int,
    user_agent: str,
    max_pages: int,
    max_depth: int,
    max_concurrent: int,
    redirect_hostname: str | None = None,
) -> SpiderCrawlInfo:
    timeout = timeout_ms / 1000
    # Overall wall-clock deadline so the crawl cannot hang indefinitely.
    wall_deadline = time.monotonic() + min(timeout_ms / 1000 * 2, 120)

    pages: list[CrawlPage] = []
    link_graph: list[SpiderLink] = []
    seen_lock = threading.Lock()
    seen: set[str] = set()  # normalized original URLs
    seen_final: set[str] = set()  # final URLs after redirects (dedup)
    queue: deque[tuple[str, str | None, int]] = deque()
    max_depth_reached = 0
    rate_limited = False  # track if the target is rate-limiting us

    # ------------------------------------------------------------------
    # ALLOWED DOMAINS — the set of registrable domains we'll follow links
    # into.  This is the FIX for the "1 page crawled" bug: previously we
    # only allowed `_get_domain(hostname)`, but when a site redirects to a
    # different platform domain (e.g. shop.com → shop.myshopify.com) ALL
    # links on the redirected page were rejected because myshopify.com !=
    # shop.com.  Now we track every domain the site legitimately lives on.
    # ------------------------------------------------------------------
    allowed_domains: set[str] = set()
    allowed_domains.add(_get_domain(hostname))
    # Also allow the domain implied by the start_url itself (it may differ
    # from `hostname` when the analyzer already followed a redirect).
    try:
        start_host = urlparse(start_url).hostname
        if start_host:
            allowed_domains.add(_get_domain(start_host))
    except Exception:
        pass
    if redirect_hostname:
        allowed_domains.add(_get_domain(redirect_hostname))

    # All hostnames we know about — used for seeding common paths.
    known_hosts: list[str] = [hostname]
    if redirect_hostname and redirect_hostname != hostname:
        known_hosts.append(redirect_hostname)
    try:
        sh = urlparse(start_url).hostname
        if sh and sh not in known_hosts:
            known_hosts.append(sh)
    except Exception:
        pass

    norm_start = _normalize_crawl_url(start_url)
    queue.append((norm_start, None, 0))
    seen.add(norm_start)
    link_graph.append(SpiderLink(norm_start, None, 0, "start"))

    # Reuse a single httpx Client across all fetches — avoids redundant DNS
    # lookups and TLS handshakes, and lets HTTP/2 connection pooling work.
    client = httpx.Client(
        timeout=timeout,
        follow_redirects=True,
        headers={
            "user-agent": user_agent,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.6",
        },
        limits=httpx.Limits(max_connections=max_concurrent, max_keepalive_connections=max_concurrent),
    )

    def fetch_page(url: str) -> CrawlPage:
        nonlocal rate_limited
        try:
            res = client.get(url)
            content_type = res.headers.get("content-type")
            snippet = None
            final_url_str = str(res.url)

            # Handle rate limiting: back off gracefully instead of hammering.
            if res.status_code in (429, 503):
                rate_limited = True
                return CrawlPage(
                    url=url, final_url=final_url_str, http_status=res.status_code,
                    content_type=content_type, fetch_note="Rate limited by server.",
                    page_type=_classify(url),
                )

            if content_type and "text/html" in content_type.lower():
                raw_html = res.text[:50000]
                snippet = _strip_scripts_keep_jsonld(raw_html)
            return CrawlPage(
                url=url, final_url=final_url_str, http_status=res.status_code,
                content_type=content_type, html_snippet=snippet,
                page_type=_classify(final_url_str or url),
            )
        except Exception as e:
            return CrawlPage(url=url, fetch_note=str(e))

    def extract_links(html: str, base_url: str) -> list[tuple[str, str]]:
        """Extract internal links, checking against ALL allowed domains."""
        links = []

        hrefs: set[str] = set()
        for m in _HREF_RE.finditer(html):
            hrefs.add(m.group(1))
        for m in _HREF_RE_NOQUOTE.finditer(html):
            hrefs.add(m.group(1))

        for href in hrefs:
            href = (href or "").strip()
            if not href or href.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
                continue
            if href.startswith("//"):
                href = "https:" + href
            try:
                abs_url = urljoin(base_url, href)
                p = urlparse(abs_url)
                if p.scheme not in ("http", "https") or not p.hostname:
                    continue
                link_domain = _get_domain(p.hostname)
                if link_domain not in allowed_domains:
                    continue
                if _is_asset(p.path) or _is_low_value(p.path):
                    continue
                norm = _normalize_crawl_url(urlunparse(p._replace(fragment="")))
                # Thread-safe check — prevents duplicate queue entries.
                with seen_lock:
                    if norm not in seen:
                        links.append((norm, "internal"))
            except Exception:
                continue
        return links

    def _seed_common_paths():
        """Inject well-known trust-relevant paths on all known hosts.

        This is a critical fallback for:
        - JavaScript-heavy SPAs where no hrefs exist in raw HTML
        - Pages where all links point to external CDNs
        - Cross-domain redirects where initial link extraction found nothing

        These paths are probed in parallel alongside the BFS crawl, so they
        don't slow anything down — they just ensure we always attempt the
        pages that matter most for trust analysis.
        """
        common_paths = [
            "/contact", "/about", "/about-us", "/pages/about-us", "/pages/contact",
            "/privacy-policy", "/policies/privacy-policy", "/privacy",
            "/terms-of-service", "/policies/terms-of-service", "/terms",
            "/refund-policy", "/policies/refund-policy",
            "/shipping-policy", "/policies/shipping-policy",
            "/return-policy", "/policies/return-policy",
            "/collections/all", "/products", "/shop",
            "/faq", "/pages/faq",
        ]
        seeded = 0
        for host in known_hosts:
            scheme = "https"
            origin = f"{scheme}://{host}"
            for path in common_paths:
                if len(seen) >= max_pages * 3:
                    return seeded
                candidate = _normalize_crawl_url(urljoin(origin, path))
                with seen_lock:
                    if candidate not in seen:
                        seen.add(candidate)
                        link_graph.append(SpiderLink(candidate, norm_start, 1, "pattern_seed"))
                        queue.append((candidate, norm_start, 1))
                        seeded += 1
        return seeded

    pages_before_seed = 0
    seed_injected = False

    try:
        while queue and len(pages) < max_pages:
            # Respect wall-clock deadline.
            if time.monotonic() > wall_deadline:
                logger.info("Spider crawl hit wall-clock deadline after %d pages", len(pages))
                break

            # If we've been rate-limited, reduce concurrency to 1 and add a delay.
            effective_concurrent = 1 if rate_limited else max_concurrent
            if rate_limited:
                time.sleep(1.0)

            batch: list[tuple[str, str | None, int]] = []
            batch_size = min(effective_concurrent, max_pages - len(pages), len(queue))
            for _ in range(batch_size):
                if queue:
                    batch.append(queue.popleft())

            with ThreadPoolExecutor(max_workers=min(effective_concurrent, len(batch))) as pool:
                futures = {pool.submit(fetch_page, url): (url, parent, depth) for url, parent, depth in batch}
                for fut in as_completed(futures):
                    # Stop appending if we've already hit our target.
                    if len(pages) >= max_pages:
                        break
                    url, parent, depth = futures[fut]
                    try:
                        page = fut.result()

                        # Deduplicate on final URL after redirects.
                        final = page.final_url or url
                        final_norm = _normalize_crawl_url(final)
                        with seen_lock:
                            if final_norm in seen_final:
                                continue
                            seen_final.add(final_norm)

                        # --------------------------------------------------
                        # DYNAMIC DOMAIN DISCOVERY: if the page redirected to
                        # a new domain we haven't seen yet, add it to the
                        # allowed set so subsequent links on that domain are
                        # followed.  This handles chains like:
                        #   shop.com → www.shop.com → shop.myshopify.com
                        # --------------------------------------------------
                        try:
                            final_host = urlparse(final).hostname
                            if final_host:
                                new_domain = _get_domain(final_host)
                                if new_domain not in allowed_domains:
                                    allowed_domains.add(new_domain)
                                    if final_host not in known_hosts:
                                        known_hosts.append(final_host)
                                    logger.info(
                                        "Spider discovered new domain via redirect: %s (from %s)",
                                        new_domain, url,
                                    )
                        except Exception:
                            pass

                        pages.append(page)
                        max_depth_reached = max(max_depth_reached, depth)
                        if page.html_snippet and depth < max_depth:
                            new_links = extract_links(page.html_snippet, final)
                            with seen_lock:
                                for link_url, link_type in new_links:
                                    if link_url not in seen and len(seen) < max_pages * 3:
                                        seen.add(link_url)
                                        new_depth = depth + 1
                                        link_graph.append(SpiderLink(link_url, url, new_depth, link_type))
                                        priority = _score_link(link_url)
                                        if priority > 20:
                                            queue.appendleft((link_url, url, new_depth))
                                        else:
                                            queue.append((link_url, url, new_depth))
                    except Exception:
                        continue

            # ------------------------------------------------------------------
            # PATTERN SEED: after the first batch completes, if the queue is
            # empty or nearly empty (link extraction found very little), inject
            # well-known paths.  This runs only once and guarantees we always
            # probe about/contact/privacy/terms etc. in parallel.
            # ------------------------------------------------------------------
            if not seed_injected and len(pages) > 0 and len(queue) < 3:
                seeded = _seed_common_paths()
                seed_injected = True
                if seeded > 0:
                    logger.info(
                        "Seeded %d common trust-relevant paths (queue was nearly empty after %d pages)",
                        seeded, len(pages),
                    )
    finally:
        client.close()

    return SpiderCrawlInfo(
        len(seen), len(pages), pages, link_graph, max_depth_reached, "advanced_python"
    )

def _get_domain(host: str) -> str:
    """Extract the registrable (eTLD+1) domain from a hostname.

    The previous implementation simply took the last two labels, which fails
    catastrophically for ccTLD second-level domains like .co.uk, .com.au, etc.
    For example ``store.co.uk`` would return ``co.uk`` — making *every* .co.uk
    site appear to be the same domain, so the crawler could follow links to
    completely unrelated websites and feed their content to the AI as if it
    belonged to the target site.

    This version maintains a set of known two-part public suffixes and falls
    back to the last-two-labels heuristic only for domains that don't match.
    """
    parts = host.lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    # Check if the last two parts form a known ccTLD second-level domain.
    last_two = ".".join(parts[-2:])
    if last_two in _CCTLD_SECOND_LEVELS:
        # Need at least 3 parts for a valid domain under a ccTLD.
        if len(parts) >= 3:
            return ".".join(parts[-3:])
        return host.lower()
    return ".".join(parts[-2:])

# Pre-compiled word-boundary patterns for trust-relevant keywords.
# Plain substring matching caused false prioritization — e.g. "contact" matched
# inside "/products/contact-lens-solution", pushing product pages ahead of the
# actual /contact page.
_TRUST_KW_RE = re.compile(
    r"(?:^|/)(?:contact|about|privacy|terms|refund|returns?|shipping|policy|policies)(?:$|/|-us|-page)",
    re.IGNORECASE,
)
_COMMERCE_PATH_RE = re.compile(r"/(?:products|collections|pages)/", re.IGNORECASE)


def _score_link(url: str) -> int:
    """Score a URL for crawl priority.  Higher = fetched sooner."""
    path = urlparse(url).path.lower()
    score = 0
    if _TRUST_KW_RE.search(path):
        score += 30
    if _COMMERCE_PATH_RE.search(path):
        score += 10
    return score

def _classify(url: str) -> str:
    """Classify a page URL by its likely content type.

    Uses path-segment boundaries to avoid false matches (e.g. ``/contact-lens``
    should not classify as 'contact').
    """
    path = urlparse(url).path.lower().rstrip("/")
    if path in ("/", ""):
        return "homepage"
    segments = path.split("/")
    for seg in segments:
        if seg in ("about", "about-us", "our-story", "company"):
            return "about"
        if seg in ("contact", "contact-us", "support"):
            return "contact"
        if seg in ("privacy", "privacy-policy", "terms", "terms-of-service",
                   "policy", "policies", "refund", "refund-policy",
                   "return", "return-policy", "shipping", "shipping-policy",
                   "legal"):
            return "policy"
    if "/products/" in path or "/product/" in path or path.startswith("/p/") or "/item/" in path:
        return "product"
    if any(k in path for k in ("/collection", "/category", "/categories")):
        return "collection"
    if any(k in path for k in ("/blog", "/news", "/articles", "/post/")):
        return "blog"
    return "other"

def _is_asset(path: str) -> bool:
    return path.lower().endswith((
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".avif",
        ".css", ".js", ".mjs", ".json", ".xml", ".map",
        ".pdf", ".zip", ".gz", ".tar", ".rar",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".mp4", ".mp3", ".webm", ".ogg", ".wav", ".avi",
        ".csv", ".xlsx", ".xls", ".doc", ".docx", ".pptx",
    ))

def _is_low_value(path: str) -> bool:
    return any(seg in path.lower() for seg in ("/cart", "/checkout", "/account", "/login", "/register", "/signin", "/signup", "/search", "/cdn-cgi/", "/.well-known/"))

_RE_STYLE = re.compile(r"<style[^>]*>.*?</style>", re.IGNORECASE | re.DOTALL)
_RE_SCRIPT_OPEN = re.compile(r"<script\b([^>]*)>", re.IGNORECASE)
_RE_SCRIPT_BLOCK = re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)
_RE_WHITESPACE = re.compile(r"\s{2,}")


def _strip_scripts(html: str) -> str:
    """Legacy strip — removes ALL scripts including JSON-LD. Use
    ``_strip_scripts_keep_jsonld`` instead for pages whose structured data
    matters (which is almost always in a trust-analysis context).
    """
    html = re.sub(r"<script[^>]*>.*?</script>", " ", html, flags=re.IGNORECASE | re.DOTALL)
    html = re.sub(r"<style[^>]*>.*?</style>", " ", html, flags=re.IGNORECASE | re.DOTALL)
    html = re.sub(r"\s{2,}", " ", html)
    return html[:20000]


def _strip_scripts_keep_jsonld(html: str) -> str:
    """Remove scripts and styles but **preserve** ``<script type="application/ld+json">``
    blocks.  JSON-LD contains organization identity, product schema, and review
    data that is critical for the AI trust analysis.

    The old ``_strip_scripts`` destroyed this data, meaning the advanced spider
    crawl mode actually gave the AI *less* information than the basic mode.

    Snippet is limited to 20 000 chars (up from 12 000) so that footer/policy
    content is not truncated — headers and hero sections alone often consume
    5-8K chars, leaving no room for trust-relevant signals.
    """
    if not html:
        return html

    # Strip <style> first.
    cleaned = _RE_STYLE.sub(" ", html)

    # Selectively strip <script> blocks, keeping ld+json.
    out_parts: list[str] = []
    idx = 0
    for m in _RE_SCRIPT_BLOCK.finditer(cleaned):
        out_parts.append(cleaned[idx:m.start()])
        block = m.group(0)
        open_m = _RE_SCRIPT_OPEN.search(block)
        attrs = (open_m.group(1) if open_m else "").lower()
        if "ld+json" in attrs:
            out_parts.append(block)  # keep JSON-LD
        else:
            out_parts.append(" ")
        idx = m.end()
    out_parts.append(cleaned[idx:])
    cleaned = "".join(out_parts)

    # Collapse whitespace.
    cleaned = _RE_WHITESPACE.sub(" ", cleaned)
    return cleaned.strip()[:20000]


def _normalize_crawl_url(url: str) -> str:
    """Normalize a URL for deduplication during crawling.

    Handles: lowercase scheme/host, strips fragment, strips trailing slash on
    non-root paths, strips common tracking query params while preserving
    meaningful ones (like product variant IDs).
    """
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        path = p.path
        # Normalize trailing slash (but keep root "/" as is).
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/")
        # Strip common tracking/noise query parameters but keep meaningful ones.
        if p.query:
            from urllib.parse import parse_qs, urlencode
            params = parse_qs(p.query, keep_blank_values=False)
            # Remove known noise params.
            noise = {"utm_source", "utm_medium", "utm_campaign", "utm_term",
                     "utm_content", "ref", "fbclid", "gclid", "mc_cid",
                     "mc_eid", "_ga", "_gl"}
            filtered = {k: v for k, v in params.items() if k.lower() not in noise}
            query = urlencode(filtered, doseq=True) if filtered else ""
        else:
            query = ""
        return urlunparse((p.scheme.lower(), host, path, p.params, query, ""))
    except Exception:
        return url
