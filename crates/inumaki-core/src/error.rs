//! Error type. Variants never carry input text or entity values.

/// Errors produced by inumaki-core.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A span offset did not fall on a UTF-8 char boundary.
    #[error("span offset is not on a char boundary")]
    InvalidUtf8Boundary,
    /// The referenced context has expired or was never created.
    #[error("context expired")]
    ContextExpired,
    /// The context store is at capacity and could not evict.
    #[error("context cap reached")]
    ContextCapReached,
    /// A model backend is required by the profile but not available.
    #[error("model backend unavailable: {0}")]
    ModelUnavailable(String),
    /// Configuration is invalid; the payload is a key path, never a value.
    #[error("invalid configuration at {0}")]
    ConfigInvalid(String),
    /// A regular expression in configuration failed to compile.
    #[error("invalid pattern at {0}")]
    InvalidPattern(String),
}
