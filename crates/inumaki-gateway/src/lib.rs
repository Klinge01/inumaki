//! inumaki-gateway: an MCP server per dataset that wraps other MCP servers.
//!
//! Tool arguments are strictly rehydrated through a reviewed field contract
//! before they reach the real server; every model-visible field of a result
//! or a listing is sanitized, tokenized, or rejected by a fixed policy. The
//! engine is reached only through [`service::Blocks`], which the daemon
//! implements. Nothing here prints.
#![deny(missing_docs)]

pub mod activity;
pub mod aggregate;
pub mod config;
pub mod content;
pub mod contract;
pub mod discovery;
pub mod gateway;
pub mod handler;
pub mod handles;
pub mod limits;
#[cfg(feature = "test-fixtures")]
pub mod scripted;
pub mod service;
pub mod status;
pub mod upstream;

pub use activity::{ActivitySink, Hop};
pub use config::{GatewayConfig, TripwireMode};
pub use gateway::{DatasetService, Gateway, GatewayError};
pub use handler::{DatasetHandler, UpstreamContract, mcp_error};
pub use handles::Owner;
pub use service::{BlockOutcome, BlockResult, Blocks, BlocksError, FieldHint, TextBlock};
pub use status::{ContractState, DatasetStatus, GatewayStatus, UpstreamStatus};
pub use upstream::{
    BoxFut, BuiltinUpstreams, ResolvedUpstream, Running, ServerGuard, Supervision, UpstreamClient,
    UpstreamError, UpstreamEvent, UpstreamHandle, UpstreamState, connect_in_process,
};

/// Install `ring` as the process-wide rustls crypto provider unless one is
/// installed already. The HTTP upstream client is built without a provider
/// of its own, and rustls panics when it builds a client config with none
/// installed; every path that can open an HTTP upstream calls this first.
/// Idempotent and cheap.
pub fn ensure_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // `Err` means another thread installed one first; either way one is set.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}
