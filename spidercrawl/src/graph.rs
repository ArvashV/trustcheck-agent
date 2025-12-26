use std::collections::HashSet;
use parking_lot::Mutex;

pub struct LinkGraph {
    links: Mutex<Vec<LinkEntry>>,
    seen: Mutex<HashSet<String>>,
}

#[derive(Clone)]
pub struct LinkEntry {
    pub url: String,
    pub parent_url: Option<String>,
    pub depth: u32,
    pub link_type: String,
}

impl LinkGraph {
    pub fn new() -> Self {
        Self {
            links: Mutex::new(Vec::new()),
            seen: Mutex::new(HashSet::new()),
        }
    }

    pub fn add_link(&self, url: String, parent: Option<String>, depth: u32, link_type: &str) -> bool {
        let mut seen = self.seen.lock();
        if seen.contains(&url) {
            return false;
        }
        seen.insert(url.clone());
        drop(seen);

        self.links.lock().push(LinkEntry {
            url,
            parent_url: parent,
            depth,
            link_type: link_type.to_string(),
        });
        true
    }

    pub fn is_seen(&self, url: &str) -> bool {
        self.seen.lock().contains(url)
    }

    pub fn into_entries(self) -> Vec<LinkEntry> {
        self.links.into_inner()
    }

    pub fn len(&self) -> usize {
        self.seen.lock().len()
    }
}
