//! Resource bounds (M4 spec §10): a finite response-byte limit checked
//! before any sanitization work, and a bounded in-flight queue per dataset.

use std::sync::Arc;
use std::time::Duration;

use rmcp::model::{
    CallToolResult, ContentBlock, GetPromptResult, ReadResourceResult, ResourceContents,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::GatewayConfig;

/// Per-dataset bounds. `Debug` prints the limit and free slots.
#[derive(Clone)]
pub struct Limits {
    max_response_bytes: usize,
    slots: Arc<Semaphore>,
    queue_timeout: Duration,
}

impl std::fmt::Debug for Limits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Limits")
            .field("max_response_bytes", &self.max_response_bytes)
            .field("free", &self.slots.available_permits())
            .finish()
    }
}

/// Why a result is refused before any sanitization work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Larger than `max_response_bytes` (`resource_limit`).
    TooLarge,
    /// A content kind this build does not know (`unsupported_content`,
    /// class `content_type`): refused, never passed on unmeasured.
    UnknownKind,
}

/// Size of a content item; `None` for a kind this build does not know.
fn item_size(c: &ContentBlock) -> Option<usize> {
    Some(match c {
        ContentBlock::Text(t) => t.text.len(),
        ContentBlock::Image(i) => i.data.len(),
        ContentBlock::Audio(a) => a.data.len(),
        ContentBlock::Resource(e) => contents_size(&e.resource)?,
        ContentBlock::ResourceLink(r) => r
            .uri
            .len()
            .saturating_add(r.name.len())
            .saturating_add(r.title.as_ref().map_or(0, String::len))
            .saturating_add(r.description.as_ref().map_or(0, String::len)),
        _ => return None,
    })
}

/// Size of resource contents; `None` for an unknown kind.
fn contents_size(c: &ResourceContents) -> Option<usize> {
    match c {
        ResourceContents::TextResourceContents { text, .. } => Some(text.len()),
        ResourceContents::BlobResourceContents { blob, .. } => Some(blob.len()),
        _ => None,
    }
}

/// Sum of sizes; an unknown kind anywhere refuses the whole result.
fn sum(mut sizes: impl Iterator<Item = Option<usize>>) -> Result<usize, Refusal> {
    sizes.try_fold(0usize, |acc, s| {
        s.map(|s| acc.saturating_add(s)).ok_or(Refusal::UnknownKind)
    })
}

impl Limits {
    /// Bounds from the configuration.
    pub fn new(cfg: &GatewayConfig) -> Self {
        Limits {
            max_response_bytes: cfg.max_response_bytes,
            slots: Arc::new(Semaphore::new(cfg.max_inflight)),
            queue_timeout: cfg.queue_timeout,
        }
    }

    /// A slot, or `None` after `queue_timeout`.
    pub async fn acquire(&self) -> Option<OwnedSemaphorePermit> {
        tokio::time::timeout(self.queue_timeout, Arc::clone(&self.slots).acquire_owned())
            .await
            .ok()?
            .ok()
    }

    fn within(&self, total: usize) -> Result<(), Refusal> {
        if total <= self.max_response_bytes {
            Ok(())
        } else {
            Err(Refusal::TooLarge)
        }
    }

    /// Whether a `tools/call` result may be sanitized.
    pub fn check_call(&self, r: &CallToolResult) -> Result<(), Refusal> {
        let structured = r
            .structured_content
            .as_ref()
            .map_or(0, |v| serde_json::to_vec(v).map_or(usize::MAX, |s| s.len()));
        self.within(sum(r.content.iter().map(item_size))?.saturating_add(structured))
    }

    /// Whether a `resources/read` result may be sanitized.
    pub fn check_read(&self, r: &ReadResourceResult) -> Result<(), Refusal> {
        self.within(sum(r.contents.iter().map(contents_size))?)
    }

    /// Whether a `prompts/get` result may be sanitized.
    pub fn check_prompt(&self, r: &GetPromptResult) -> Result<(), Refusal> {
        let items = sum(r.messages.iter().map(|m| item_size(&m.content)))?;
        self.within(items.saturating_add(r.description.as_ref().map_or(0, String::len)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(max: usize) -> Limits {
        Limits::new(&GatewayConfig {
            max_response_bytes: max,
            max_inflight: 1,
            queue_timeout: Duration::from_millis(50),
            ..GatewayConfig::default()
        })
    }

    #[test]
    fn results_are_measured_before_any_work() {
        let l = limits(10);
        let text = |t: &str| CallToolResult::success(vec![ContentBlock::text(t)]);
        assert_eq!(l.check_call(&text("0123456789")), Ok(()));
        assert_eq!(l.check_call(&text("0123456789a")), Err(Refusal::TooLarge));
        let mut r = text("01234");
        r.structured_content = Some(serde_json::json!({ "k": "vvvvvv" }));
        assert_eq!(
            l.check_call(&r),
            Err(Refusal::TooLarge),
            "structured content counts"
        );
        let blob = ReadResourceResult::new(vec![ResourceContents::blob("A".repeat(11), "mem://x")]);
        assert_eq!(l.check_read(&blob), Err(Refusal::TooLarge));
        assert_eq!(l.check_prompt(&GetPromptResult::new(vec![])), Ok(()));
    }

    #[tokio::test]
    async fn a_full_queue_times_out() {
        let l = limits(10);
        let held = l.acquire().await.expect("one slot");
        assert!(l.acquire().await.is_none(), "queue_timeout elapses");
        drop(held);
        assert!(l.acquire().await.is_some());
    }
}
