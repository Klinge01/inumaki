//! Proxy settings as plain data. `inumakid` parses the TOML and validates the
//! listen address (loopback only) before building a [`ProxyConfig`].

use std::net::SocketAddr;
use std::time::Duration;

use crate::routes::UpstreamId;

/// Default for [`ProxyConfig::max_request_bytes`]: 8 MiB after decompression.
/// A scan holds about 50 bytes of node heap per body byte, so this bound and
/// [`SCAN_BUDGET_PERMITS`] together cap the memory hostile bodies can pin.
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 8 << 20;

/// Default for [`ProxyConfig::max_inflight`].
pub const DEFAULT_MAX_INFLIGHT: usize = 32;

/// Admission weight: permits one body byte takes while it is scanned. The
/// JSON node list is about 50 times the body, so 64 leaves headroom.
pub const SCAN_WEIGHT: usize = 64;

/// Total admission budget over all in-flight scans, in weighted permits
/// (1 GiB of scan heap). A request needs `body bytes * SCAN_WEIGHT` of it
/// (capped at the whole budget) and is refused as busy when that much is not
/// free, so concurrent hostile bodies cannot exhaust memory.
pub const SCAN_BUDGET_PERMITS: usize = 1 << 30;

// A default-sized body must always be admissible on its own.
const _: () = assert!(DEFAULT_MAX_REQUEST_BYTES * SCAN_WEIGHT <= SCAN_BUDGET_PERMITS);

/// What to do when the verifier is unsure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UncertainMode {
    /// Refuse the request.
    Block,
    /// Send it.
    Pass,
}

/// What to do when the tripwire fires on a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TripwireMode {
    /// Send, and tell the operator.
    Notify,
    /// Refuse the request.
    Block,
}

/// Whether the NER models read the harness's own leading prompt
/// (`[proxy] harness_static_ner`, M8 spec §20, amendment of 2026-10-28).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StaticNer {
    /// A harness-static leaf (the leading system and developer messages of a
    /// trusted request) runs without the sanitizer's and the verifier's NER.
    /// Every deterministic detector, the dictionary and the verifier's other
    /// checks still run.
    #[default]
    Skip,
    /// The models read it too (the behaviour before the amendment). The
    /// static-prompt NER memo then serves it.
    Scan,
}

/// Upstream base URLs. They hold no secret.
#[derive(Debug, Clone)]
pub struct BaseUrls {
    /// Anthropic API.
    pub anthropic: String,
    /// OpenAI API.
    pub openai: String,
    /// Codex ChatGPT backend.
    pub openai_codex: String,
}

/// How binary parts outside tool results are handled (M8 §20 amendment 2026-10-11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BinaryMode {
    /// Replace the part by a fixed placeholder and send the rest of the request.
    #[default]
    Placeholder,
    /// Refuse the request (`400 unsupported_content`).
    Refuse,
    /// Forward the payload to the provider without inspecting it.
    Forward,
}

/// Request header names forwarded unchanged on one upstream each, from
/// `[proxy.upstreams.<id>] extra_headers` (M8 spec §20 amendment of
/// 2026-10-12). Names only, never values.
#[derive(Debug, Clone, Default)]
pub struct ExtraHeaders {
    /// Names forwarded to the Anthropic API.
    pub anthropic: Vec<http::HeaderName>,
    /// Names forwarded to the OpenAI API.
    pub openai: Vec<http::HeaderName>,
    /// Names forwarded to the Codex ChatGPT backend.
    pub openai_codex: Vec<http::HeaderName>,
}

impl ExtraHeaders {
    /// The names configured for `up`.
    pub fn get(&self, up: UpstreamId) -> &[http::HeaderName] {
        match up {
            UpstreamId::Anthropic => &self.anthropic,
            UpstreamId::Openai => &self.openai,
            UpstreamId::OpenaiCodex => &self.openai_codex,
        }
    }
}

/// The proxy's settings.
///
/// `Debug` is derived: every field is a flag, a number, an address, a mode,
/// a URL, a list of configured header names (`extra_headers` holds names, not
/// values), or a fixed token format. None holds request text or a credential.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Whether the proxy listens at all.
    pub enabled: bool,
    /// Listen address; loopback only.
    pub listen: SocketAddr,
    /// Sanitization profile name.
    pub profile: String,
    /// Idle time before a session's mappings are destroyed.
    pub session_ttl: Duration,
    /// Most concurrent sessions.
    pub session_cap: usize,
    /// Incremental sanitization cache size in bytes.
    pub cache_bytes: usize,
    /// Largest accepted request body in bytes, measured after decompression
    /// ([`DEFAULT_MAX_REQUEST_BYTES`] unless the user sets it).
    pub max_request_bytes: usize,
    /// Most requests in flight at once ([`DEFAULT_MAX_INFLIGHT`] unless the
    /// user sets it).
    pub max_inflight: usize,
    /// Upstream request timeout.
    pub upstream_timeout: Duration,
    /// How binary parts outside tool results are handled.
    pub binary: BinaryMode,
    /// Verifier-uncertain handling.
    pub uncertain: UncertainMode,
    /// Tripwire handling.
    pub tripwire: TripwireMode,
    /// Whether the NER models read a harness-static leaf.
    pub static_ner: StaticNer,
    /// Browser origins allowed to call the proxy.
    pub allowed_origins: Vec<String>,
    /// Upstream base URLs.
    pub base_urls: BaseUrls,
    /// Extra request header names forwarded per upstream.
    pub extra_headers: ExtraHeaders,
    /// Token format of session tokens.
    pub session_tokens: inumaki_core::config::TokenSettings,
    /// The cross-session static-prompt NER memo (`[proxy] static_cache`,
    /// default `true`; M8 spec §20, amendment 2026-10-12). It takes effect
    /// only when the host also provides a memo (`ProxyHost::ner_memo`), and
    /// only for requests with a valid client header.
    pub static_cache: bool,
    /// Fingerprint of the effective configuration.
    pub fingerprint: [u8; 32],
}
