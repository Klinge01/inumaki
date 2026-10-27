//! `[journal]` (M4 spec §10, §16.3): the egress journal's settings. One
//! global retention; `max_bytes` is a per-dataset budget, the oldest
//! entries swept first.

use std::time::Duration;

use inumaki_core::Error;
use serde::Deserialize;

use crate::config::{parse_bytes, parse_duration};

/// Smallest accepted `max_bytes` (64 KiB, the floor `gateway.max_response_bytes` has).
const MIN_MAX_BYTES: usize = 64 * 1024;

/// `[journal]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct JournalSection {
    /// Store released payloads at all.
    pub enabled: bool,
    /// How long an entry is kept, e.g. `24h`.
    pub retention: String,
    /// Per-dataset byte budget, e.g. `64MB`; the oldest entries go first.
    pub max_bytes: String,
}

impl Default for JournalSection {
    fn default() -> Self {
        JournalSection {
            enabled: true,
            retention: "24h".into(),
            max_bytes: "64MB".into(),
        }
    }
}

/// Validate `[journal]`: the parsed retention (non-zero) and byte budget
/// (at least 64 KiB). Errors name the key, never the value.
pub fn parse(j: &JournalSection) -> Result<(Duration, u64), Error> {
    let retention = parse_duration(&j.retention)
        .filter(|d| !d.is_zero())
        .ok_or_else(|| Error::ConfigInvalid("journal.retention".into()))?;
    let max_bytes = parse_bytes(&j.max_bytes)
        .filter(|b| *b >= MIN_MAX_BYTES)
        .ok_or_else(|| Error::ConfigInvalid("journal.max_bytes".into()))?;
    Ok((retention, max_bytes as u64))
}
