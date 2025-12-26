use reqwest::Client;
use std::time::Duration;
use tokio::sync::Semaphore;
use std::sync::Arc;

pub struct Fetcher {
    client: Client,
    semaphore: Arc<Semaphore>,
    user_agent: String,
}

pub struct FetchResult {
    pub url: String,
    pub final_url: Option<String>,
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub html: Option<String>,
    pub error: Option<String>,
}

impl Fetcher {
    pub fn new(timeout_ms: u32, user_agent: String, max_concurrent: u32) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_millis(timeout_ms as u64))
            .gzip(true)
            .brotli(true)
            .pool_max_idle_per_host(10)
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            client,
            semaphore: Arc::new(Semaphore::new(max_concurrent as usize)),
            user_agent,
        }
    }

    pub async fn fetch(&self, url: &str) -> FetchResult {
        let _permit = match self.semaphore.acquire().await {
            Ok(p) => p,
            Err(_) => return FetchResult {
                url: url.to_string(),
                final_url: None,
                status: None,
                content_type: None,
                html: None,
                error: Some("Semaphore closed".to_string()),
            },
        };

        let result = self.client
            .get(url)
            .header("User-Agent", &self.user_agent)
            .header("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
            .header("Accept-Language", "en-US,en;q=0.6")
            .send()
            .await;

        match result {
            Ok(resp) => {
                let final_url = resp.url().to_string();
                let status = resp.status().as_u16();
                let content_type = resp.headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let is_html = content_type.as_ref()
                    .map(|ct| ct.contains("text/html"))
                    .unwrap_or(false);

                let html = if is_html {
                    match resp.text().await {
                        Ok(text) => {
                            let truncated: String = text.chars().take(50000).collect();
                            Some(truncated)
                        }
                        Err(_) => None,
                    }
                } else {
                    None
                };

                FetchResult {
                    url: url.to_string(),
                    final_url: Some(final_url),
                    status: Some(status),
                    content_type,
                    html,
                    error: None,
                }
            }
            Err(e) => FetchResult {
                url: url.to_string(),
                final_url: None,
                status: None,
                content_type: None,
                html: None,
                error: Some(e.to_string()),
            },
        }
    }
}
