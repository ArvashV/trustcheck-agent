use crate::{SpiderCrawlResult, CrawlPage, SpiderLink};
use crate::graph::LinkGraph;
use crate::fetcher::{Fetcher, FetchResult};
use scraper::{Html, Selector};
use url::Url;
use std::collections::{HashSet, VecDeque};
use once_cell::sync::Lazy;
use regex::Regex;
use tokio::runtime::Runtime;

pub fn run_spider(
    start_url: String,
    hostname: String,
    timeout_ms: u32,
    user_agent: String,
    max_pages: u32,
    max_depth: u32,
    max_concurrent: u32,
) -> SpiderCrawlResult {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        spider_async(start_url, hostname, timeout_ms, user_agent, max_pages, max_depth, max_concurrent).await
    })
}

async fn spider_async(
    start_url: String,
    hostname: String,
    timeout_ms: u32,
    user_agent: String,
    max_pages: u32,
    max_depth: u32,
    max_concurrent: u32,
) -> SpiderCrawlResult {
    let fetcher = Fetcher::new(timeout_ms, user_agent, max_concurrent);
    let graph = LinkGraph::new();
    let mut pages: Vec<CrawlPage> = Vec::new();
    let mut queue: VecDeque<(String, u32)> = VecDeque::new();
    let mut max_depth_reached: u32 = 0;

    graph.add_link(start_url.clone(), None, 0, "start");
    queue.push_back((start_url, 0));

    while let Some((url, depth)) = queue.pop_front() {
        if pages.len() >= max_pages as usize {
            break;
        }
        if depth > max_depth {
            continue;
        }

        let result = fetcher.fetch(&url).await;
        max_depth_reached = max_depth_reached.max(depth);

        let page = result_to_page(&result, &url);
        
        if let Some(ref html) = result.html {
            let links = extract_links(html, result.final_url.as_deref().unwrap_or(&url), &hostname);
            for (link_url, link_type) in links {
                if graph.len() < (max_pages * 3) as usize {
                    let new_depth = depth + 1;
                    if new_depth <= max_depth && graph.add_link(link_url.clone(), Some(url.clone()), new_depth, &link_type) {
                        let priority = score_link(&link_url);
                        if priority > 20 {
                            queue.push_front((link_url, new_depth));
                        } else {
                            queue.push_back((link_url, new_depth));
                        }
                    }
                }
            }
        }

        pages.push(page);
    }

    let entries = graph.into_entries();
    let link_graph: Vec<SpiderLink> = entries.into_iter().map(|e| SpiderLink {
        url: e.url,
        parent_url: e.parent_url,
        depth: e.depth,
        link_type: e.link_type,
    }).collect();

    SpiderCrawlResult {
        pages_requested: link_graph.len() as u32,
        pages_fetched: pages.len() as u32,
        pages,
        link_graph,
        max_depth_reached,
    }
}

fn result_to_page(result: &FetchResult, original_url: &str) -> CrawlPage {
    let page_type = classify_page(&result.final_url.as_deref().unwrap_or(original_url));
    let snippet = result.html.as_ref().map(|h| strip_scripts(h));

    CrawlPage {
        url: original_url.to_string(),
        final_url: result.final_url.clone(),
        http_status: result.status,
        content_type: result.content_type.clone(),
        html_snippet: snippet,
        fetch_note: result.error.clone(),
        page_type: Some(page_type),
    }
}

fn extract_links(html: &str, base_url: &str, hostname: &str) -> Vec<(String, String)> {
    let mut links = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let document = Html::parse_document(html);
    let selector = Selector::parse("a[href]").unwrap();
    let base = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return links,
    };
    let target_domain = get_registrable_domain(hostname);

    for element in document.select(&selector) {
        if let Some(href) = element.value().attr("href") {
            if href.starts_with("mailto:") || href.starts_with("tel:") || href.starts_with("javascript:") {
                continue;
            }
            if let Ok(abs_url) = base.join(href) {
                if let Some(host) = abs_url.host_str() {
                    // Use registrable domain comparison — prevents matching
                    // unrelated sites like evil-example.com ≠ example.com
                    // and correctly groups sub.store.co.uk = store.co.uk.
                    if get_registrable_domain(host) == target_domain {
                        let url_str = normalize_crawl_url(&abs_url.to_string());
                        if !is_asset(&url_str) && !is_low_value(&url_str) && !seen.contains(&url_str) {
                            seen.insert(url_str.clone());
                            let link_type = if is_nav_context(&element) { "nav" } else { "internal" };
                            links.push((url_str, link_type.to_string()));
                        }
                    }
                }
            }
        }
    }
    links
}

fn is_nav_context(element: &scraper::ElementRef) -> bool {
    let mut current = element.parent();
    for _ in 0..5 {
        if let Some(parent) = current {
            if let Some(el) = parent.value().as_element() {
                let tag = el.name();
                if tag == "nav" || tag == "header" {
                    return true;
                }
                if let Some(class) = el.attr("class") {
                    let c = class.to_lowercase();
                    if c.contains("nav") || c.contains("menu") || c.contains("header") {
                        return true;
                    }
                }
            }
            current = parent.parent();
        } else {
            break;
        }
    }
    false
}

/// Word-boundary-aware trust keyword regex for scoring.
static TRUST_KW_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:^|/)(?:contact|about|privacy|terms|refund|returns?|shipping|policy|policies)(?:$|/|-us|-page)").unwrap()
});
static COMMERCE_PATH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)/(?:products|collections|pages)/").unwrap()
});

fn score_link(url: &str) -> i32 {
    let path = match Url::parse(url) {
        Ok(u) => u.path().to_lowercase(),
        Err(_) => url.to_lowercase(),
    };
    let mut score = 0;
    if TRUST_KW_RE.is_match(&path) { score += 30; }
    if COMMERCE_PATH_RE.is_match(&path) { score += 10; }
    score
}

fn classify_page(url: &str) -> String {
    let path = match Url::parse(url) {
        Ok(u) => u.path().to_lowercase(),
        Err(_) => url.to_lowercase(),
    };
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "/" {
        return "homepage".to_string();
    }
    let segments: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
    for seg in &segments {
        match *seg {
            "about" | "about-us" | "our-story" | "company" => return "about".to_string(),
            "contact" | "contact-us" | "support" => return "contact".to_string(),
            "privacy" | "privacy-policy" | "terms" | "terms-of-service" |
            "policy" | "policies" | "refund" | "refund-policy" |
            "return" | "return-policy" | "shipping" | "shipping-policy" |
            "legal" => return "policy".to_string(),
            "blog" | "news" | "articles" => return "blog".to_string(),
            _ => {},
        }
    }
    if path.contains("/products/") || path.contains("/product/") || path.starts_with("/p/") || path.contains("/item/") {
        return "product".to_string();
    }
    if path.contains("/collection") || path.contains("/category") || path.contains("/categories") {
        return "collection".to_string();
    }
    "other".to_string()
}

fn is_asset(url: &str) -> bool {
    let lower = url.to_lowercase();
    [".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".avif",
     ".css", ".js", ".mjs", ".json", ".xml", ".map",
     ".pdf", ".zip", ".gz", ".tar", ".rar",
     ".woff", ".woff2", ".ttf", ".eot", ".otf",
     ".mp4", ".mp3", ".webm", ".ogg", ".wav",
     ".csv", ".xlsx", ".doc", ".docx"]
        .iter().any(|ext| lower.ends_with(ext))
}

fn is_low_value(url: &str) -> bool {
    let path = url.to_lowercase();
    ["/cart", "/checkout", "/account", "/login", "/register", "/signin", "/signup", "/search", "/cdn-cgi/", "/.well-known/"]
        .iter().any(|seg| path.contains(seg))
}

/// Lazy-compiled regexes for script/style stripping.
static RE_SCRIPT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?is)<script[^>]*>.*?</script>").unwrap()
});
static RE_STYLE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?is)<style[^>]*>.*?</style>").unwrap()
});
static RE_SCRIPT_OPEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)<script\b([^>]*)>").unwrap()
});
static RE_WHITESPACE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\s{2,}").unwrap()
});

/// Strip scripts and styles but preserve JSON-LD blocks which contain
/// structured organization/product data critical for trust analysis.
fn strip_scripts(html: &str) -> String {
    // Strip <style> first.
    let without_styles = RE_STYLE.replace_all(html, " ");
    
    // Selectively strip <script> blocks, keeping ld+json.
    let mut result = String::with_capacity(without_styles.len());
    let mut last_end = 0;
    
    for mat in RE_SCRIPT.find_iter(&without_styles) {
        result.push_str(&without_styles[last_end..mat.start()]);
        let block = mat.as_str();
        // Check if this script block is JSON-LD.
        if let Some(open_m) = RE_SCRIPT_OPEN.find(block) {
            let attrs = open_m.as_str().to_lowercase();
            if attrs.contains("ld+json") {
                result.push_str(block);  // keep JSON-LD
            } else {
                result.push(' ');
            }
        } else {
            result.push(' ');
        }
        last_end = mat.end();
    }
    result.push_str(&without_styles[last_end..]);
    
    let collapsed = RE_WHITESPACE.replace_all(&result, " ");
    collapsed.chars().take(20000).collect()
}

/// Known ccTLD second-level domains.
const CCTLD_SECOND_LEVELS: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "co.in", "net.in", "org.in",
    "com.au", "net.au", "org.au",
    "co.nz", "net.nz", "org.nz",
    "co.za", "org.za",
    "com.br", "net.br", "org.br",
    "co.jp", "or.jp",
    "co.kr", "or.kr",
    "com.cn", "net.cn", "org.cn",
    "com.tw", "net.tw",
    "com.hk", "net.hk",
    "com.sg", "net.sg",
    "com.my", "net.my",
    "co.id", "or.id",
    "com.ph", "net.ph",
    "co.th", "or.th",
    "com.tr", "net.tr",
    "com.mx", "net.mx",
    "com.ar", "net.ar",
    "com.co", "net.co",
    "com.ua", "net.ua",
    "com.pk", "net.pk",
];

/// Extract the registrable domain (eTLD+1) from a hostname.
/// Handles ccTLD second-level domains like .co.uk, .com.au correctly.
fn get_registrable_domain(host: &str) -> String {
    let lower = host.to_lowercase();
    let parts: Vec<&str> = lower.trim_end_matches('.').split('.').collect();
    if parts.len() <= 2 {
        return parts.join(".");
    }
    let last_two = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
    if CCTLD_SECOND_LEVELS.contains(&last_two.as_str()) {
        if parts.len() >= 3 {
            return format!("{}.{}", parts[parts.len() - 3], last_two);
        }
        return lower;
    }
    last_two
}

/// Normalize a URL for deduplication: lowercase host, strip fragment,
/// normalize trailing slash.
fn normalize_crawl_url(url: &str) -> String {
    match Url::parse(url) {
        Ok(mut u) => {
            u.set_fragment(None);
            let path = u.path().to_string();
            if path.len() > 1 && path.ends_with('/') {
                u.set_path(path.trim_end_matches('/'));
            }
            u.to_string()
        }
        Err(_) => url.to_string(),
    }
}
