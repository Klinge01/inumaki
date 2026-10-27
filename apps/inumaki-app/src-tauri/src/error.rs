//! The one error type the UI sees. `kind` is a fixed string, never a daemon
//! message (which can name a dataset); `kinds` are entity kinds (for a
//! privacy block); `snippet` is the manual configuration snippet of an
//! adapter that cannot edit a file safely (shown to the local user, never
//! logged or printed by `Debug`).

use inumaki_client::ClientError;
use serde::Serialize;

/// Set once at startup when the config file that names the daemon's socket
/// cannot be read (`AppPaths::config_error`): every "the service is not
/// running" answer then says "configuration error" instead, because starting
/// the service would not help; the user has to fix the file.
static CONFIG_ERROR: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Record that the socket's config file is unusable (see [`CONFIG_ERROR`]).
pub fn note_config_error(on: bool) {
    CONFIG_ERROR.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// A command error.
#[derive(Clone, Serialize)]
pub struct CmdError {
    /// Fixed error kind.
    pub kind: &'static str,
    /// HTTP status, when the daemon answered.
    pub status: Option<u16>,
    /// Entity kinds of a privacy block.
    pub kinds: Vec<String>,
    /// Manual snippet for `cannot_edit_safely`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    /// Why, for `not_supported`: a fixed adapter reason code and sentence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<crate::harness::ops::Reason>,
}

impl std::fmt::Debug for CmdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CmdError")
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("kinds", &self.kinds)
            .finish_non_exhaustive()
    }
}

/// An entity-kind label such as `PERSON` or `IBAN`: starts with an upper-case
/// letter, then upper case, underscores, and at most four digits, at most 32
/// characters. Anything else from the daemon is dropped before it reaches the
/// UI, a notification, or a log. The shape check is what keeps a value that a
/// misbehaving daemon put into a kind field (an account number, an IBAN) out
/// of those places.
pub fn kind_ok(k: &str) -> bool {
    k.len() <= 32
        && k.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
        && k.bytes()
            .all(|b| b.is_ascii_uppercase() || b == b'_' || b.is_ascii_digit())
        && k.bytes().filter(u8::is_ascii_digit).count() <= 4
}

/// Daemon error kinds passed through; anything else becomes `error`.
const KNOWN: &[&str] = &[
    "bad_request",
    "not_found",
    "conflict",
    "privacy_block",
    "payload_too_large",
    "method_not_allowed",
    "unsupported_content",
    "unresolved",
    "resource_limit",
    "journal_record",
    "mail_auth_failed",
    "mail_unreachable",
    "mail_tls_failed",
    "mail_protocol",
    "internal",
    "unavailable",
];

impl CmdError {
    /// The service cannot be reached: `service_unreachable`, or
    /// `config_error` when the config file that names its socket is unusable.
    pub fn service_unreachable() -> CmdError {
        if CONFIG_ERROR.load(std::sync::atomic::Ordering::Relaxed) {
            CmdError::new("config_error")
        } else {
            CmdError::new("service_unreachable")
        }
    }

    /// An app-side error of `kind`.
    pub fn new(kind: &'static str) -> CmdError {
        CmdError {
            kind,
            status: None,
            kinds: Vec::new(),
            snippet: None,
            reason: None,
        }
    }

    /// The route is not served by this daemon (a lane has not merged).
    pub fn not_available() -> CmdError {
        CmdError {
            status: Some(404),
            ..CmdError::new("not_available")
        }
    }
}

impl From<ClientError> for CmdError {
    fn from(e: ClientError) -> CmdError {
        match e {
            ClientError::Connect(_) | ClientError::Http(_) => CmdError::service_unreachable(),
            ClientError::Timeout => CmdError::new("timeout"),
            ClientError::Decode => CmdError::new("bad_response"),
            ClientError::Encode => CmdError::new("bad_request"),
            ClientError::Status { status: 404, error }
                if error.as_ref().is_none_or(|d| d.message == "no such route") =>
            {
                CmdError::not_available()
            }
            ClientError::Status {
                status,
                error: Some(d),
            } => CmdError {
                kind: KNOWN
                    .iter()
                    .copied()
                    .find(|k| *k == d.kind)
                    .unwrap_or("error"),
                status: Some(status),
                kinds: d.kinds.iter().filter(|k| kind_ok(k)).cloned().collect(),
                snippet: None,
                reason: None,
            },
            ClientError::Status {
                status,
                error: None,
            } => CmdError {
                status: Some(status),
                ..CmdError::new("error")
            },
        }
    }
}
