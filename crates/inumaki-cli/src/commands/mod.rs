//! Subcommand implementations and shared helpers.

use std::io::Read;
use std::path::Path;

use anyhow::{Context as _, Result};
use inumaki_core::config::CoreConfig;
use inumaki_core::engine::Engine;

pub mod activity;
pub mod bench;
pub mod bench_proxy;
pub mod canary_mcp;
pub mod connect;
pub mod daemon;
pub mod dataset;
pub mod doctor;
pub mod entities;
pub mod eval;
pub mod eval_service;
pub mod folder;
pub mod gateway;
pub mod inspect;
pub mod journal;
pub mod mail_tasks;
pub mod mailbox;
pub mod models;
pub mod rehydrate;
pub mod sanitize;
pub mod scan;
pub mod status;
pub mod tokenize;
pub mod upstream;

pub(crate) const EMBEDDED_CONFIG: &str = include_str!("../../../../configs/default.toml");

/// Load config from `path` or the embedded default.
pub fn load_config(path: Option<&Path>) -> Result<CoreConfig> {
    match path {
        Some(p) => CoreConfig::load(p).with_context(|| format!("loading config {}", p.display())),
        None => CoreConfig::from_toml(EMBEDDED_CONFIG).context("embedded config"),
    }
}

/// Build an engine for the profile, loading the NER models it names.
pub fn build_engine(
    path: Option<&Path>,
    profile: &str,
    models_dir: Option<&Path>,
) -> Result<Engine> {
    let cfg = load_config(path)?;
    let p = cfg
        .resolve_profile(profile)
        .with_context(|| format!("resolving profile {profile}"))?;
    let root = inumaki_models::resolve_models_dir(models_dir, cfg.ner.models_dir.as_deref());
    let ner = inumaki_models::ner_for_profile(&cfg, &p, &root)?;
    Engine::from_config(&cfg, profile, ner.sanitizer, ner.verifier)
        .with_context(|| format!("building engine for profile {profile}"))
}

/// Read a file or stdin (`-`).
pub fn read_input(input: &Path) -> Result<String> {
    if input.as_os_str() == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .context("reading stdin")?;
        Ok(s)
    } else {
        std::fs::read_to_string(input).with_context(|| format!("reading {}", input.display()))
    }
}

/// Read a redactions file, parsed but not yet validated (the daemon validates it against the NFC text).
pub fn read_redactions(path: &Path) -> Result<serde_json::Value> {
    let s = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&s).with_context(|| format!("parsing {}", path.display()))
}

/// `12s ago`, `3m ago`, `5h ago`, `2d ago`.
pub(crate) fn ago(secs: i64) -> String {
    match secs {
        s if s < 120 => format!("{s}s ago"),
        s if s < 7_200 => format!("{}m ago", s / 60),
        s if s < 172_800 => format!("{}h ago", s / 3_600),
        s => format!("{}d ago", s / 86_400),
    }
}

/// Unix seconds now.
pub(crate) fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A dataset id the daemon can accept (`[a-z0-9-]{1,64}`), checked before
/// it goes into a URL path.
pub(crate) fn valid_dataset(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Percent-encode a path segment: everything but `[A-Za-z0-9-._~]`.
pub fn encode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
