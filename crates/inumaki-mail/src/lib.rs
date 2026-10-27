//! inumaki-mail: the draft-only mail connector (M4 spec §6).
//!
//! An in-process MCP upstream over IMAP: it lists folders, searches, reads,
//! and stores reply drafts behind random dataset-scoped handles. It never
//! sends mail, never calls the engine, and never opens the vault: the
//! daemon supplies credentials ([`MailCredentials`]) and the handle store
//! ([`MailHandles`]). Nothing here logs a folder name, an address, a
//! subject, a body, or a server message.
#![deny(missing_docs)]

pub mod account;
pub mod check;
pub mod draft;
pub mod error;
#[cfg(feature = "fake-imap")]
pub mod fake;
pub mod handles;
#[cfg(feature = "harness")]
pub mod harness;
pub mod imap;
pub mod query;
pub mod render;
pub mod server;
pub mod stream;
pub mod tolerant;

pub use account::{MailAccount, MailCredentials, Preset, StaticCredentials, is_loopback_host};
pub use check::{CheckReport, check_mailbox};
pub use draft::MAX_BODY_BYTES;
pub use error::MailError;
pub use handles::{MailHandles, MemoryHandles, MessageRef, Resolved, random_handle};
pub use server::{CONTRACT_JSON, DRAFT_TEXT, MailConfig, MailServer, TOOL_NAMES, UPSTREAM_NAME};
