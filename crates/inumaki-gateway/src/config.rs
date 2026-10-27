//! `[gateway]` settings (M4 spec §10), parsed by the daemon.

use std::time::Duration;

/// What a clear value in model-written arguments does (M4 spec §16.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TripwireMode {
    /// Record and count; the call proceeds.
    #[default]
    Notify,
    /// Refuse the call with `privacy_block`, check `ClearValue`.
    Block,
}

/// Gateway settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayConfig {
    /// TCP listen address for the Streamable HTTP transport (loopback only).
    pub listen: String,
    /// Cap on the upstream restart backoff (1 s, 2 s, 4 s, … up to this).
    pub restart_max_backoff: Duration,
    /// Time an upstream gets to answer one call.
    pub call_timeout: Duration,
    /// Largest upstream result (text, structured JSON, blobs) accepted for
    /// sanitization; larger ones answer `resource_limit` (M4 spec §10).
    pub max_response_bytes: usize,
    /// In-flight inference slots per dataset.
    pub max_inflight: usize,
    /// How long a request waits for a slot before `resource_limit`.
    pub queue_timeout: Duration,
    /// What the clear-value tripwire does on a hit (M4 spec §16.1).
    pub tripwire: TripwireMode,
    /// Write released payloads to the egress journal (M4 spec §16.3).
    pub journal: bool,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        GatewayConfig {
            listen: "127.0.0.1:8789".into(),
            restart_max_backoff: Duration::from_secs(30),
            call_timeout: Duration::from_secs(60),
            max_response_bytes: 4 * 1024 * 1024,
            max_inflight: 8,
            queue_timeout: Duration::from_secs(30),
            tripwire: TripwireMode::Notify,
            journal: true,
        }
    }
}
