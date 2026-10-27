//! inumaki-mirror: the folder mirror (M5 spec). A watched source folder is
//! kept as a sanitized copy under the mirror root; an agent-writable
//! `outbox/` inside it is restored strictly into a destination the user
//! owns. Everything below a root goes through directory handles with
//! `O_NOFOLLOW` ([`fsops`]). The engine and the manifest store are traits
//! ([`engine`]); the daemon implements them. Nothing here logs a path, a
//! name, or content.
#![deny(missing_docs)]

pub mod config;
pub mod engine;
pub mod folder;
pub mod formats;
pub mod fsops;
pub mod names;
#[doc(hidden)]
pub mod queue;
pub mod status;
#[doc(hidden)]
pub mod testing;

mod guard;
mod outbox;
mod pipeline;
mod reconcile;
mod service;
mod watch;

pub use config::MirrorConfig;
pub use engine::{
    Activity, ActivityDirection, ActivityVerdict, Block, DatasetState, EngineError, ManifestStore,
    MirrorEngine, Outcome, Side,
};
pub use folder::Folder;
pub use service::{Mirror, prepare_root};
pub use status::{Counts, FolderError, FolderState, OutboxCounts, Snapshot};
