//! inumaki-core: local privacy engine.
//!
//! Detects identifying information, replaces it with opaque per-context
//! tokens, verifies the sanitized candidate independently, and rehydrates
//! tokens in responses. No IO, no HTTP, no model loading lives here.
#![deny(missing_docs)]

pub mod alias;
mod collapse;
pub mod config;
pub mod consistency;
pub mod detect;
pub mod engine;
pub mod error;
pub mod gazetteer;
pub mod lang;
pub mod link;
pub mod origin;
pub mod policy;
pub mod protect;
pub mod redact;
pub mod rehydrate;
pub mod resolve;
pub mod sanitize;
pub mod span;
pub mod stoplist;
pub mod token;
pub mod verify;

pub use alias::{AliasGroup, AliasTable, Aliased};
pub use config::{CoreConfig, TokenSettings};
pub use detect::{DetectCtx, Detector};
pub use engine::{Detailed, Engine, Outcome};
pub use error::Error;
pub use link::{LinkScope, LinkTier, LinkTiers, Links};
pub use origin::TextOrigin;
pub use policy::{Action, Decision, Profile};
pub use rehydrate::{RehydrateError, Rehydrator};
pub use resolve::resolve_overlaps;
pub use sanitize::{Replacement, Sanitized};
pub use span::{DetectorId, EntityKind, SecretKind, Span, valid_kind_label};
pub use token::{
    Context, ContextId, ContextStore, StoreError, SurfaceForm, Token, TokenStore, parse_token,
};
pub use verify::{CheckId, Reason, Verdict, Verifier};

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
