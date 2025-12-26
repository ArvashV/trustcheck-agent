use crate::{SpiderCrawlResult, CrawlPage, SpiderLink};
use crate::graph::{LinkGraph, LinkEntry};
use crate::fetcher::{Fetcher, FetchResult};
use scraper::{Html, Selector};
use url::Url;
use std::collections::VecDeque;
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
    let document = Html::parse_document(html);
    let selector = Selector::parse("a[href]").unwrap();
    let base = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return links,
    };

    for element in document.select(&selector) {
        if let Some(href) = element.value().attr("href") {
            if href.starts_with("mailto:") || href.starts_with("tel:") || href.starts_with("javascript:") {
                continue;
            }
            if let Ok(abs_url) = base.join(href) {
                if let Some(host) = abs_url.host_str() {
                    if host.ends_with(hostname) || hostname.ends_with(host) {
                        let url_str = abs_url.to_string();
                        if !is_asset(&url_str) && !is_low_value(&url_str) {
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

fn score_link(url: &str) -> i32 {
    let path = url.to_lowercase();
    let mut score = 0;
    for kw in ["contact", "about", "privacy", "terms", "refund", "return", "shipping", "policy"] {
        if path.contains(kw) { score += 30; }
    }
    for kw in ["/products/", "/collections/", "/pages/"] {
        if path.contains(kw) { score += 10; }
    }
    score
}

fn classify_page(url: &str) -> String {
    let path = url.to_lowercase();
    if path.ends_with('/') || path.split('/').last().map(|s| s.is_empty()).unwrap_or(true) {
        return "homepage".to_string();
    }
    if path.contains("about") { return "about".to_string(); }
    if path.contains("contact") { return "contact".to_string(); }
    if path.contains("privacy") || path.contains("terms") || path.contains("policy") { return "policy".to_string(); }
    if path.contains("/product") { return "product".to_string(); }
    if path.contains("/collection") || path.contains("/category") { return "collection".to_string(); }
    "other".to_string()
}

fn is_asset(url: &str) -> bool {
    let lower = url.to_lowercase();
    [".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".css", ".js", ".json", ".xml", ".pdf", ".woff", ".woff2"]
        .iter().any(|ext| lower.ends_with(ext))
}

fn is_low_value(url: &str) -> bool {
    let path = url.to_lowercase();
    ["/cart", "/checkout", "/account", "/login", "/register", "/signin", "/signup", "/search", "/cdn-cgi/", "/.well-known/"]
        .iter().any(|seg| path.contains(seg))
}

fn strip_scripts(html: &str) -> String {
    let re_script = regex::Regex::new(r"(?is)<script[^>]*>.*?</script>").unwrap();
    let re_style = regex::Regex::new(r"(?is)<style[^>]*>.*?</style>").unwrap();
    let without_scripts = re_script.replace_all(html, " ");
    let without_styles = re_style.replace_all(&without_scripts, " ");
    let collapsed = regex::Regex::new(r"\s{2,}").unwrap().replace_all(&without_styles, " ");
    collapsed.chars().take(12000).collect()
}
