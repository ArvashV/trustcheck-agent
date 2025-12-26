from __future__ import annotations
from typing import Literal
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque
from urllib.parse import urlparse, urljoin, urlunparse
import re
import time
import httpx

from .models import CrawlPage, CrawlInfo

try:
    from spidercrawl import spider_crawl as rust_spider_crawl, SpiderCrawlResult
    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False

_HREF_RE = re.compile(r"href\s*=\s*([\"']?)([^\"'\s>]+)\1", re.IGNORECASE)

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
    max_concurrent: int = 20,
) -> SpiderCrawlInfo:
    if RUST_AVAILABLE:
        try:
            result = rust_spider_crawl(
                start_url, hostname, timeout_ms, user_agent, max_pages, max_depth, max_concurrent
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
        except Exception:
            pass
    return _python_spider_crawl(start_url, hostname, timeout_ms, user_agent, max_pages, max_depth, max_concurrent)

def _python_spider_crawl(
    start_url: str,
    hostname: str,
    timeout_ms: int,
    user_agent: str,
    max_pages: int,
    max_depth: int,
    max_concurrent: int,
) -> SpiderCrawlInfo:
    timeout = timeout_ms / 1000
    pages: list[CrawlPage] = []
    link_graph: list[SpiderLink] = []
    seen: set[str] = set()
    queue: deque[tuple[str, str | None, int]] = deque()
    max_depth_reached = 0

    queue.append((start_url, None, 0))
    seen.add(start_url)
    link_graph.append(SpiderLink(start_url, None, 0, "start"))

    def fetch_page(url: str) -> CrawlPage:
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                res = client.get(url, headers={
                    "user-agent": user_agent,
                    "accept": "text/html,*/*;q=0.8",
                    "accept-language": "en-US,en;q=0.6",
                })
                content_type = res.headers.get("content-type")
                snippet = None
                if content_type and "text/html" in content_type.lower():
                    snippet = res.text[:12000]
                    snippet = _strip_scripts(snippet)
                return CrawlPage(
                    url=url, final_url=str(res.url), http_status=res.status_code,
                    content_type=content_type, html_snippet=snippet, page_type=_classify(url)
                )
        except Exception as e:
            return CrawlPage(url=url, fetch_note=str(e))

    def extract_links(html: str, base_url: str) -> list[tuple[str, str]]:
        links = []
        base_domain = _get_domain(hostname)
        for _, href in _HREF_RE.findall(html):
            href = (href or "").strip()
            if not href or href.startswith(("mailto:", "tel:", "javascript:")):
                continue
            abs_url = urljoin(base_url, href)
            try:
                p = urlparse(abs_url)
                if p.scheme not in ("http", "https") or not p.hostname:
                    continue
                if _get_domain(p.hostname) != base_domain:
                    continue
                if _is_asset(p.path) or _is_low_value(p.path):
                    continue
                norm = urlunparse(p._replace(query="", fragment=""))
                if norm not in seen:
                    links.append((norm, "internal"))
            except Exception:
                continue
        return links

    while queue and len(pages) < max_pages:
        batch: list[tuple[str, str | None, int]] = []
        batch_size = min(max_concurrent, max_pages - len(pages), len(queue))
        for _ in range(batch_size):
            if queue:
                batch.append(queue.popleft())

        with ThreadPoolExecutor(max_workers=min(max_concurrent, len(batch))) as pool:
            futures = {pool.submit(fetch_page, url): (url, parent, depth) for url, parent, depth in batch}
            for fut in as_completed(futures):
                url, parent, depth = futures[fut]
                try:
                    page = fut.result()
                    pages.append(page)
                    max_depth_reached = max(max_depth_reached, depth)
                    if page.html_snippet and depth < max_depth:
                        new_links = extract_links(page.html_snippet, page.final_url or url)
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

    return SpiderCrawlInfo(
        len(seen), len(pages), pages, link_graph, max_depth_reached, "advanced_python"
    )

def _get_domain(host: str) -> str:
    parts = host.lower().split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host.lower()

def _score_link(url: str) -> int:
    path = url.lower()
    score = 0
    for kw in ("contact", "about", "privacy", "terms", "refund", "return", "shipping", "policy"):
        if kw in path:
            score += 30
    for kw in ("/products/", "/collections/", "/pages/"):
        if kw in path:
            score += 10
    return score

def _classify(url: str) -> str:
    path = urlparse(url).path.lower()
    if path in ("/", ""):
        return "homepage"
    if "about" in path:
        return "about"
    if "contact" in path:
        return "contact"
    if any(k in path for k in ("privacy", "terms", "policy")):
        return "policy"
    if "/product" in path:
        return "product"
    if any(k in path for k in ("/collection", "/category")):
        return "collection"
    return "other"

def _is_asset(path: str) -> bool:
    return path.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".css", ".js", ".json", ".xml", ".pdf", ".woff", ".woff2"))

def _is_low_value(path: str) -> bool:
    return any(seg in path.lower() for seg in ("/cart", "/checkout", "/account", "/login", "/register", "/signin", "/signup", "/search", "/cdn-cgi/", "/.well-known/"))

def _strip_scripts(html: str) -> str:
    html = re.sub(r"<script[^>]*>.*?</script>", " ", html, flags=re.IGNORECASE | re.DOTALL)
    html = re.sub(r"<style[^>]*>.*?</style>", " ", html, flags=re.IGNORECASE | re.DOTALL)
    html = re.sub(r"\s{2,}", " ", html)
    return html[:12000]
