//! inumakid: the inumaki service.
//!
//! One process owns the models, one engine per profile (and per dataset,
//! with that dataset's known-entity detector), the vault, session contexts,
//! and a sanitization cache, and serves a JSON control API over a Unix
//! socket. Nothing here prints; the binary in `main.rs` does.
#![deny(missing_docs)]

pub mod api;
pub mod cache;
pub mod chat;
pub mod check;
pub mod client;
pub mod config;
pub mod dirs;
pub mod engines;
pub mod folders;
mod forget;
pub mod glue;
pub mod hook;
pub mod identity;
pub mod journal;
pub mod mail;
pub mod mirror_config;
pub mod pathcmp;
pub mod proxy_config;
pub mod proxy_host;
pub mod released;
pub mod revocations;
pub mod run;
pub mod server;
pub mod service;
pub mod state;
pub mod tcp_guard;

pub use cache::{CacheKey, CacheStats, CachedOutcome, CachedResult, SanitizeCache};
pub use client::{Client, ClientError, Reply};
pub use config::DaemonConfig;
pub use engines::{EngineError, Engines, ProfileStatus};
pub use state::{AppState, StartError, StartOptions};
