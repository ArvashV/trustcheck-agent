mod crawler;
mod fetcher;
mod graph;

use pyo3::prelude::*;
use pyo3::types::PyDict;

#[pyclass]
#[derive(Clone)]
pub struct SpiderLink {
    #[pyo3(get)]
    pub url: String,
    #[pyo3(get)]
    pub parent_url: Option<String>,
    #[pyo3(get)]
    pub depth: u32,
    #[pyo3(get)]
    pub link_type: String,
}

#[pyclass]
#[derive(Clone)]
pub struct CrawlPage {
    #[pyo3(get)]
    pub url: String,
    #[pyo3(get)]
    pub final_url: Option<String>,
    #[pyo3(get)]
    pub http_status: Option<u16>,
    #[pyo3(get)]
    pub content_type: Option<String>,
    #[pyo3(get)]
    pub html_snippet: Option<String>,
    #[pyo3(get)]
    pub fetch_note: Option<String>,
    #[pyo3(get)]
    pub page_type: Option<String>,
}

#[pyclass]
pub struct SpiderCrawlResult {
    #[pyo3(get)]
    pub pages_requested: u32,
    #[pyo3(get)]
    pub pages_fetched: u32,
    #[pyo3(get)]
    pub pages: Vec<CrawlPage>,
    #[pyo3(get)]
    pub link_graph: Vec<SpiderLink>,
    #[pyo3(get)]
    pub max_depth_reached: u32,
}

#[pyfunction]
#[pyo3(signature = (start_url, hostname, timeout_ms=20000, user_agent=None, max_pages=30, max_depth=3, max_concurrent=20))]
fn spider_crawl(
    start_url: String,
    hostname: String,
    timeout_ms: u32,
    user_agent: Option<String>,
    max_pages: u32,
    max_depth: u32,
    max_concurrent: u32,
) -> PyResult<SpiderCrawlResult> {
    let ua = user_agent.unwrap_or_else(|| {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 TrustCheckSpider/1.0".to_string()
    });
    
    let result = crawler::run_spider(
        start_url,
        hostname,
        timeout_ms,
        ua,
        max_pages,
        max_depth,
        max_concurrent,
    );
    
    Ok(result)
}

#[pymodule]
fn spidercrawl(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<SpiderLink>()?;
    m.add_class::<CrawlPage>()?;
    m.add_class::<SpiderCrawlResult>()?;
    m.add_function(wrap_pyfunction!(spider_crawl, m)?)?;
    Ok(())
}
