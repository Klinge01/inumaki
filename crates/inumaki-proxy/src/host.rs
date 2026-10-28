//! What the proxy needs from its embedding daemon (M8 spec §3.1).
//!
//! `inumaki-proxy` never touches the vault or the models directly. Every
//! lookup that needs a dataset namespace, a model, or the activity writer
//! goes through one injected [`ProxyHost`], as the gateway's `Blocks` does.
//!
//! Every call blocks (vault reads, model inference). Async callers run them
//! on the blocking pool (`tokio::task::spawn_blocking`).

use std::fmt;
use std::sync::Arc;

use inumaki_core::detect::Detector;
use inumaki_core::engine::Engine;
use inumaki_core::policy::Profile;
use inumaki_core::span::EntityKind;
use zeroize::Zeroizing;

use crate::memo::NerMemo;
use crate::routes::UpstreamId;

/// Why a host call failed. Fixed classes only: never text, never a value,
/// a token, or a dataset name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HostError {
    /// A model the profile needs is not loaded.
    #[error("model_unavailable")]
    ModelUnavailable,
    /// The vault could not be read.
    #[error("vault_unavailable")]
    VaultUnavailable,
    /// The host does not support this call (for example check routes
    /// without the check support compiled in).
    #[error("unsupported")]
    Unsupported,
    /// Any other host failure.
    #[error("internal")]
    Internal,
}

/// Which namespaces a token lookup may consult.
///
/// `Debug` never prints the check dataset's name.
#[derive(Clone, PartialEq, Eq)]
pub enum Scope {
    /// Every live dataset except check datasets (normal routes).
    Datasets,
    /// One check dataset only (check routes, M8 spec §12.3).
    Check(String),
}

impl fmt::Debug for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Scope::Datasets => f.write_str("Datasets"),
            Scope::Check(_) => f.write_str("Check(..)"),
        }
    }
}

/// One block sanitized by a dataset namespace (check routes).
///
/// `Debug` prints lengths and counts only: `text` is the sanitized text.
pub struct HostBlock {
    /// The sanitized text (meaningful when `blocked` is false).
    pub text: String,
    /// The engine refused the block.
    pub blocked: bool,
    /// The verifier was uncertain.
    pub uncertain: bool,
    /// Entity kinds involved.
    pub kinds: Vec<EntityKind>,
    /// Check ids of the verdict.
    pub checks: Vec<String>,
}

impl fmt::Debug for HostBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostBlock")
            .field("len", &self.text.len())
            .field("blocked", &self.blocked)
            .field("uncertain", &self.uncertain)
            .field("kinds", &self.kinds.len())
            .field("checks", &self.checks.len())
            .finish()
    }
}

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusedVerdict {
    /// The engine blocked a block.
    Blocked,
    /// The verifier was uncertain under `uncertain = "block"`.
    Uncertain,
    /// Unsupported content (binary parts, a definition hit).
    Unsupported,
}

/// An activity event the host records (M8 spec §9). Recording never blocks
/// the request.
///
/// `Debug` prints the variant, counts, and the payload length only:
/// `payload` is sanitized text, and the dataset name is never printed.
#[derive(Clone)]
pub enum ProxyEvent {
    /// A request was forwarded. `payload` is the journal entry (the blocks
    /// that missed the cache, sanitized); empty means no journal entry.
    Released {
        /// The upstream.
        upstream: UpstreamId,
        /// Kinds tokenized, with counts.
        kinds: Vec<(EntityKind, u32)>,
        /// Journal payload (sanitized).
        payload: Vec<u8>,
    },
    /// A tool-result block was replaced by the placeholder.
    Withheld {
        /// The upstream.
        upstream: UpstreamId,
        /// The verdict was uncertain rather than blocked.
        uncertain: bool,
        /// Entity kinds involved.
        kinds: Vec<EntityKind>,
        /// Check ids of the verdict.
        checks: Vec<String>,
    },
    /// The request was refused; nothing was forwarded.
    Refused {
        /// The upstream.
        upstream: UpstreamId,
        /// Why.
        verdict: RefusedVerdict,
        /// Entity kinds involved.
        kinds: Vec<EntityKind>,
        /// Check ids of the verdict.
        checks: Vec<String>,
    },
    /// The tripwire found a known value in clear in model output.
    ClearValue {
        /// The upstream.
        upstream: UpstreamId,
        /// The dataset the value belongs to, if any.
        dataset: Option<String>,
        /// Kinds found, with counts.
        kinds: Vec<(EntityKind, u32)>,
        /// The output was blocked rather than flagged.
        blocked: bool,
    },
}

impl fmt::Debug for ProxyEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyEvent::Released { kinds, payload, .. } => f
                .debug_struct("Released")
                .field("kinds", &kinds.len())
                .field("payload", &payload.len())
                .finish(),
            ProxyEvent::Withheld { kinds, checks, .. } => f
                .debug_struct("Withheld")
                .field("kinds", &kinds.len())
                .field("checks", &checks.len())
                .finish(),
            ProxyEvent::Refused { kinds, checks, .. } => f
                .debug_struct("Refused")
                .field("kinds", &kinds.len())
                .field("checks", &checks.len())
                .finish(),
            ProxyEvent::ClearValue { kinds, .. } => f
                .debug_struct("ClearValue")
                .field("kinds", &kinds.len())
                .finish(),
        }
    }
}

/// What `inumakid` provides to the proxy. All calls block; async callers
/// use `spawn_blocking`. Errors are [`HostError`] classes, never text.
/// Resolved originals are `Zeroizing`.
pub trait ProxyHost: Send + Sync + 'static {
    /// The profile's engine. When [`ProxyHost::ner_memo`] returns a memo,
    /// this engine's sanitizer and verifier NER detectors are wrapped with
    /// [`NerMemo::wrap`] (and nothing else differs).
    fn engine(&self, profile: &str) -> Result<Arc<Engine>, HostError>;
    /// The profile's engine without memo wrappers: the same configuration
    /// as [`ProxyHost::engine`], with its NER detectors unwrapped. The
    /// pipeline uses it for every restricted-mode request (no valid client
    /// header), so such a request never reads or writes the memo, even
    /// while a trusted request's scope on the same text is open.
    ///
    /// Contract: a host that returns a memo from [`ProxyHost::ner_memo`]
    /// must return an engine without memo wrappers here. The default
    /// returns [`ProxyHost::engine`], which is right only for a host that
    /// wraps nothing.
    fn engine_unmemoized(&self, profile: &str) -> Result<Arc<Engine>, HostError> {
        self.engine(profile)
    }
    /// The profile's engine without either NER model: every deterministic
    /// detector, the dictionary and the verifier's other checks, and no
    /// model. The pipeline uses it for a harness-static leaf of a route
    /// when `[proxy] harness_static_ner` is `"skip"`
    /// ([`StaticNer`](crate::config::StaticNer)).
    ///
    /// The default returns [`ProxyHost::engine_unmemoized`], which keeps the
    /// models: a host that does not build a model-free engine scans more,
    /// never less.
    fn engine_static(&self, profile: &str) -> Result<Arc<Engine>, HostError> {
        self.engine_unmemoized(profile)
    }
    /// The profile's policy (preserve checks for dictionary hits).
    fn policy(&self, profile: &str) -> Result<Arc<Profile>, HostError>;
    /// A detector over every live, non-check dataset's known entities (§5.4).
    ///
    /// Contract (M8 spec §20, amendment 2026-10-12): the same `Arc` until
    /// its content changes. The static-prompt NER memo is cleared whenever
    /// the `Arc` changes, so a host that returns a fresh `Arc` per call
    /// clears it on every request, which disables it.
    fn dictionary(&self) -> Result<Arc<dyn Detector>, HostError>;
    /// The cross-session static-prompt NER memo (M8 spec §20, amendment
    /// 2026-10-12), if this host provides one. A host that returns one
    /// wraps the NER detectors of [`ProxyHost::engine`]'s engine with it
    /// and returns unwrapped ones from [`ProxyHost::engine_unmemoized`].
    /// `None` (the default) turns the memo off whatever `static_cache` says.
    /// It must return the same `Arc` for the host's whole lifetime, the one
    /// `engine()` wraps: the pipeline's scopes and the status counters read
    /// the memo once, at start.
    fn ner_memo(&self) -> Option<Arc<NerMemo>> {
        None
    }
    /// Tripwire scan over known entities: `(dataset, kind, count)` (§6.4).
    fn scan_known(&self, texts: &[String]) -> Result<Vec<(String, EntityKind, u32)>, HostError>;
    /// The OS user's full name and email, read once at start.
    fn identity(&self) -> Vec<(EntityKind, Zeroizing<String>)>;
    /// The logins the host's engines leave in clear where they stand in a
    /// path (`EngineOptions::preserved_logins`). The tripwire on model output
    /// ignores them there: the model saw them in clear and may write them.
    /// None (the default) preserves nothing.
    fn preserved_logins(&self) -> Vec<String> {
        Vec::new()
    }
    /// The token a live dataset already uses for `value` of `kind` (§5.4),
    /// with the vault's canonical original for it. The vault may match
    /// `value` case-insensitively, so the canonical original can differ
    /// from `value`; the caller records the canonical one.
    fn dataset_token(
        &self,
        kind: &EntityKind,
        value: &str,
    ) -> Result<Option<(String, Zeroizing<String>)>, HostError>;
    /// Dataset tokens among `tokens` that resolve in `scope`:
    /// `(token, kind, original)`. Unknown tokens are left out.
    fn resolve(
        &self,
        tokens: &[String],
        scope: &Scope,
    ) -> Result<Vec<(String, EntityKind, Zeroizing<String>)>, HostError>;
    /// Whether a block with this keyed digest was released by the gateway,
    /// the mirror, or the hook (§14).
    fn released(&self, digest: &[u8; 32]) -> bool;
    /// `scan_clear` over definitions (decision 24): kinds found, with counts.
    fn scan_definitions(&self, texts: &[String]) -> Result<Vec<(EntityKind, u32)>, HostError>;
    /// Sanitize `blocks` with a check dataset's namespace (check routes).
    fn sanitize_dataset(
        &self,
        dataset: &str,
        blocks: Vec<String>,
    ) -> Result<Vec<HostBlock>, HostError>;
    /// Record an activity event (and its journal payload). Never blocks.
    fn record(&self, event: ProxyEvent);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_carries_counts_and_lengths_only() {
        let canary = "Zyxwuria Quolnath";
        let events = [
            ProxyEvent::Released {
                upstream: UpstreamId::Anthropic,
                kinds: vec![(EntityKind::Person, 1)],
                payload: format!("hello <PERSON_abcdef> {canary}").into_bytes(),
            },
            ProxyEvent::ClearValue {
                upstream: UpstreamId::Openai,
                dataset: Some("crm-secret-slug".into()),
                kinds: vec![(EntityKind::Person, 1)],
                blocked: true,
            },
            ProxyEvent::Refused {
                upstream: UpstreamId::Openai,
                verdict: RefusedVerdict::Blocked,
                kinds: vec![EntityKind::Person],
                checks: vec!["leak".into()],
            },
        ];
        let block = HostBlock {
            text: format!("<PERSON_abcdef> {canary}"),
            blocked: false,
            uncertain: false,
            kinds: vec![EntityKind::Person],
            checks: vec![],
        };
        let all = format!(
            "{events:?} {block:?} {:?} {}",
            Scope::Check("check-secret-slug".into()),
            HostError::VaultUnavailable
        );
        for needle in [canary, "PERSON_abcdef", "secret-slug", "hello"] {
            assert!(!all.contains(needle), "{needle} in {all}");
        }
    }
}
