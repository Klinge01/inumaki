//! Harness adapters (M6 spec §4): detection, format-preserving edits of
//! harness configuration files with backups and revert, and path status.
//! Depends on no inumaki crate; the app and the CLI fill `ConnectPlan` and
//! `SystemState` from the control API.

pub mod backup;
pub mod check;
pub mod detect;
pub mod edit;
pub mod engine;
pub mod fsio;
pub mod harness;
pub mod model;
pub mod node;
pub mod protect;
pub mod status;

pub use backup::{Backup, BackupStore, CODEX_TRUST_LEFT_NOTE, RevertReport};
pub use detect::ProbeEnv;
pub use harness::{HarnessAdapter, adapter, all_adapters};
pub use model::*;
pub use node::{Edit, Format, Node};
