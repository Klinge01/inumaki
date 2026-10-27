//! inumaki-vault: the persistent, encrypted token store.
//!
//! One SQLite file holds datasets, their rotation epochs, and per-epoch
//! token entries. Originals are encrypted with XChaCha20-Poly1305 (the token
//! string is the associated data), lookups go through an HMAC-SHA256 index
//! over the normalized value, and the two keys come from the OS secret store
//! or a 0600 key file. A [`Namespace`] is a `TokenStore` over one dataset's
//! current epoch. Activity records ([`activity`]) hold enums, counts, and
//! opaque ids only. Nothing in this crate prints or logs originals.
#![deny(missing_docs)]

pub mod activity;
pub mod clock;
pub mod crypto;
pub mod entities;
pub mod error;
pub mod folders;
pub mod journal;
pub mod keys;
pub mod known;
pub mod lookup;
pub mod lru;
pub mod mail_handles;
pub mod mailboxes;
pub mod namespace;
pub mod schema;
pub mod secrets;
pub mod tokens;
pub mod upstreams;
pub mod vault;

pub use activity::{
    ActivityFilter, ActivityRecord, CheckLabel, Digest, Direction, FrontDoor, KindCount, KindLabel,
    NewActivity, OpaqueId, RecordId, Verdict,
};
pub use clock::{Clock, SystemClock};
pub use entities::{EntityInfo, Forgotten};
pub use error::VaultError;
pub use folders::MIRROR_SIDES;
pub use journal::{JournalEntry, JournalSweep, JournalWriter};
pub use keys::{KeyLoad, KeySource, KeyStore, Keys, OsKeyring, load_or_create};
pub use known::{KNOWN_KINDS, KnownEntityDetector, REBUILD_AFTER, is_known_entity, is_known_kind};
pub use lookup::DatasetHead;
pub use mail_handles::{MAIL_HANDLE_LEN, MailHandleKind, MailHandleRef, is_mail_handle};
pub use mailboxes::{Mailbox, MailboxSpec, is_loopback_host, mail_password_secret, valid_preset};
pub use namespace::{Namespace, WORKING_SET};
pub use schema::SCHEMA_VERSION;
pub use secrets::valid_secret_name;
pub use tokens::{GatewayToken, TOKEN_PREFIX};
pub use upstreams::{Upstream, UpstreamKind, UpstreamSpec, valid_upstream_name};
pub use vault::{
    CHAT_DATASET, Dataset, DatasetKind, DatasetSpec, EpochInfo, RESERVED_PREFIX, Rotation,
    SweepReport, Vault, VaultOptions, valid_dataset_id,
};

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, VaultError>;
