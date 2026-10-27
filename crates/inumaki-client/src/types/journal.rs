//! Journal and entities (M6 spec §9.3, plan 2b).

use serde::{Deserialize, Serialize};

use crate::secret::Secret;

/// `label` of a journal record without values.
pub const JOURNAL_TOKENS_LABEL: &str = "released payload as sent (tokens)";
/// `label` of a journal record with `show_values=true`.
pub const JOURNAL_VALUES_LABEL: &str = "originals revealed locally — not for transmission";

/// One journal entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    /// 32 hex.
    pub id: String,
    /// Unix seconds.
    pub at: i64,
    /// Payload bytes.
    pub bytes: u64,
    /// Digest.
    pub released: String,
}

/// `GET /v1/datasets/{id}/journal`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalList {
    /// Entries.
    pub entries: Vec<JournalEntry>,
}

/// The fixed label of a journal record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JournalLabel {
    /// [`JOURNAL_TOKENS_LABEL`].
    #[serde(rename = "released payload as sent (tokens)")]
    Tokens,
    /// [`JOURNAL_VALUES_LABEL`].
    #[serde(rename = "originals revealed locally — not for transmission")]
    Values,
}

/// `GET /v1/datasets/{id}/journal/{record}`. `payload` can hold originals: never in `Debug`.
#[derive(Clone, Serialize, Deserialize)]
pub struct JournalRecord {
    /// 32 hex.
    pub id: String,
    /// Unix seconds.
    pub at: i64,
    /// Payload bytes.
    pub bytes: u64,
    /// Digest.
    pub released: String,
    /// The payload, tokens or rehydrated.
    pub payload: String,
    /// Rehydrated.
    pub show_values: bool,
    /// Tokens that could not be rehydrated.
    pub unresolved: u64,
    /// Fixed label.
    pub label: JournalLabel,
}

debug_fields!(JournalRecord {
    id,
    at,
    bytes,
    released,
    show_values,
    unresolved,
    label
});

/// One entity; `original` only with `show_values=true`.
#[derive(Clone, Serialize, Deserialize)]
pub struct Entity {
    /// Token.
    pub token: String,
    /// Kind label.
    pub kind: String,
    /// First use.
    pub first_use: i64,
    /// Last use.
    pub last_use: i64,
    /// Uses.
    pub uses: u64,
    /// Epoch.
    pub epoch_id: i64,
    /// In the current epoch.
    pub current_epoch: bool,
    /// Surface-form rows of the entity.
    #[serde(default)]
    pub surface_forms: usize,
    /// Original value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original: Option<String>,
}

debug_fields!(Entity {
    kind,
    first_use,
    last_use,
    uses,
    epoch_id,
    current_epoch,
    surface_forms
});

/// `GET /v1/datasets/{id}/entities`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityList {
    /// Entities.
    pub entities: Vec<Entity>,
}

/// `POST /v1/datasets/{id}/entities/forget` body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgetRequest {
    /// The typed value.
    pub value: Secret,
}

/// Forget answer (both forget routes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgetBody {
    /// Kinds forgotten.
    pub kinds: Vec<String>,
    /// Tokens forgotten.
    pub tokens: u64,
    /// Rows deleted.
    pub rows: u64,
}
