//! `GET/POST /v1/datasets`, `DELETE /v1/datasets/{id}`, `POST …/rotate`
//! (`inumakid/src/api/{datasets,status}.rs`).

use serde::{Deserialize, Serialize};

/// Dataset kind. `folder` arrives with M5 (§9.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatasetKind {
    /// Wrapped MCP servers.
    Generic,
    /// A mailbox (plan 3).
    Mailbox,
    /// A mirrored folder (M5).
    Folder,
    /// The proxy's reserved chat dataset (M8).
    Chat,
}

/// `DatasetBody`. `id` and `name` are the slug and display name: never in `Debug`.
#[derive(Clone, Serialize, Deserialize)]
pub struct DatasetBody {
    /// Slug.
    pub id: String,
    /// Opaque label.
    pub label: String,
    /// Display name.
    pub name: String,
    /// Profile.
    pub profile: String,
    /// Epoch length, days.
    pub rotation_days: u32,
    /// Grace period, days.
    pub grace_days: u32,
    /// Current epoch.
    pub epoch_id: i64,
    /// Current epoch start, unix seconds.
    pub epoch_started_at: i64,
    /// Entries in the current epoch.
    pub entries: u64,
    /// Kind.
    pub kind: DatasetKind,
}

debug_fields!(DatasetBody {
    label,
    profile,
    rotation_days,
    grace_days,
    epoch_id,
    epoch_started_at,
    entries,
    kind
});

/// `POST /v1/datasets` body. `allow_binary` is not offered: the daemon refuses any value.
#[derive(Clone, Serialize, Deserialize)]
pub struct CreateDataset {
    /// Slug, `[a-z0-9-]{1,64}`; the prefix `check-` is reserved (spec §8).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Profile; the daemon's default when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Epoch length; default 30.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_days: Option<u32>,
    /// Grace period; default 7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_days: Option<u32>,
    /// Kind; `generic` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<DatasetKind>,
}

impl CreateDataset {
    /// A generic dataset with the daemon's defaults.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        CreateDataset {
            id: id.into(),
            name: name.into(),
            profile: None,
            rotation_days: None,
            grace_days: None,
            kind: None,
        }
    }
}

debug_fields!(CreateDataset {
    profile,
    rotation_days,
    grace_days,
    kind
});

/// `POST /v1/datasets/{id}/rotate` answer (built with `json!`).
#[derive(Clone, Serialize, Deserialize)]
pub struct RotateBody {
    /// Slug.
    pub dataset: String,
    /// Closed epoch.
    pub old_epoch: i64,
    /// Current epoch.
    pub new_epoch: i64,
    /// Its start, unix seconds.
    pub epoch_started_at: i64,
}

debug_fields!(RotateBody {
    old_epoch,
    new_epoch,
    epoch_started_at
});
