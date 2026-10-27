//! `GET /v1/doctor` (`inumakid/src/api/doctor.rs`).

use serde::{Deserialize, Serialize};

use super::status::{ContractState, KeySource, UpstreamKind};

/// Vault health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorVault {
    /// Key source.
    pub key_source: KeySource,
    /// `PRAGMA integrity_check` passed.
    pub integrity_ok: bool,
}

/// Worst file status of a model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelFileState {
    /// All files verified.
    Ok,
    /// A file is missing.
    Missing,
    /// A file fails its hash.
    Corrupt,
}

/// One pinned model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorModel {
    /// Manifest name.
    pub name: String,
    /// Status.
    pub status: ModelFileState,
}

/// One profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorProfile {
    /// Name.
    pub name: String,
    /// Available.
    pub available: bool,
    /// `unqualified` until plan 4c.
    pub qualification: String,
}

/// One upstream.
#[derive(Clone, Serialize, Deserialize)]
pub struct DoctorUpstream {
    /// Name.
    pub name: String,
    /// Kind.
    pub kind: UpstreamKind,
    /// `ready`, `none`, or `invalid`.
    pub contract: ContractState,
    /// The vault holds secrets for it.
    pub has_secrets: bool,
}

debug_fields!(DoctorUpstream {
    kind,
    contract,
    has_secrets
});

/// One dataset.
#[derive(Clone, Serialize, Deserialize)]
pub struct DoctorDataset {
    /// Slug.
    pub id: String,
    /// Profile.
    pub profile: String,
    /// Rotation period.
    pub rotation_days: u32,
    /// Grace period.
    pub grace_days: u32,
    /// Upstreams.
    pub upstreams: Vec<DoctorUpstream>,
}

debug_fields!(DoctorDataset {
    profile,
    rotation_days,
    grace_days,
    upstreams
});

/// Gateway facts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorGateway {
    /// Listen address.
    pub listen: String,
    /// Tokens.
    pub tokens: u64,
}

/// The report. `next_steps` sentences name dataset ids and upstream names:
/// not in `Debug`.
#[derive(Clone, Serialize, Deserialize)]
pub struct DoctorBody {
    /// Vault.
    pub vault: DoctorVault,
    /// Models.
    pub models: Vec<DoctorModel>,
    /// Profiles.
    pub profiles: Vec<DoctorProfile>,
    /// Datasets.
    pub datasets: Vec<DoctorDataset>,
    /// Gateway.
    pub gateway: DoctorGateway,
    /// Fixed next-step sentences.
    pub next_steps: Vec<String>,
}

debug_fields!(DoctorBody {
    vault,
    models,
    profiles,
    datasets,
    gateway
});
