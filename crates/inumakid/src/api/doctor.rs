//! `GET /v1/doctor` (M4 spec §9): read-only local diagnostics with fixed
//! reasons and next steps. Never originals, never key values.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use inumaki_gateway::contract::Contract;
use inumaki_models::manifest::{FileStatus, Manifest, verify};
use serde::Serialize;

use super::{ApiError, blocking};
use crate::state::AppState;

/// Vault health.
#[derive(Debug, Serialize)]
pub struct DoctorVault {
    /// `keyring` or `file`.
    pub key_source: &'static str,
    /// `PRAGMA integrity_check` passed.
    pub integrity_ok: bool,
}

/// One pinned model.
#[derive(Debug, Serialize)]
pub struct DoctorModel {
    /// Manifest name.
    pub name: String,
    /// `ok`, `missing`, or `corrupt` (worst file status).
    pub status: &'static str,
}

/// One profile.
#[derive(Debug, Serialize)]
pub struct DoctorProfile {
    /// Name.
    pub name: String,
    /// Its engine can be built.
    pub available: bool,
    /// `unqualified` until plan 4 records a passing §13.1 run.
    pub qualification: &'static str,
}

/// One upstream.
#[derive(Debug, Serialize)]
pub struct DoctorUpstream {
    /// Name.
    pub name: String,
    /// Kind.
    pub kind: String,
    /// `ready`, `none`, or `invalid` (drift is known only to a running gateway).
    pub contract: &'static str,
    /// The vault holds secrets for it.
    pub has_secrets: bool,
}

/// One dataset.
#[derive(Debug, Serialize)]
pub struct DoctorDataset {
    /// Id.
    pub id: String,
    /// Profile.
    pub profile: String,
    /// Rotation period, days.
    pub rotation_days: u32,
    /// Grace period, days.
    pub grace_days: u32,
    /// Upstreams.
    pub upstreams: Vec<DoctorUpstream>,
}

/// Gateway facts.
#[derive(Debug, Serialize)]
pub struct DoctorGateway {
    /// Listen address.
    pub listen: String,
    /// Tokens in the vault.
    pub tokens: usize,
}

/// The report.
#[derive(Debug, Serialize)]
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
    /// What to do next, fixed sentences.
    pub next_steps: Vec<String>,
}

/// Handler.
pub async fn doctor(State(state): State<Arc<AppState>>) -> Result<Json<DoctorBody>, ApiError> {
    let body = blocking(move || {
        let mut next_steps = Vec::new();
        let vault = DoctorVault {
            key_source: state.vault.key_source(),
            integrity_ok: state.vault.integrity_ok().unwrap_or(false),
        };
        if !vault.integrity_ok {
            next_steps.push(
                "the vault failed its integrity check: stop the daemon and restore from a copy taken while the daemon was stopped (README, key custody)"
                    .to_string(),
            );
        }
        let root = state.engines.models_dir();
        let mut models = Vec::new();
        for m in &Manifest::embedded().models {
            let statuses = verify(root, m);
            let status = if statuses.iter().all(|(_, s)| *s == FileStatus::Ok) {
                "ok"
            } else if statuses.iter().any(|(_, s)| *s == FileStatus::Corrupt) {
                "corrupt"
            } else {
                "missing"
            };
            if status != "ok" {
                next_steps.push(format!("model {} is {status}: run `inumaki models pull`", m.name));
            }
            models.push(DoctorModel { name: m.name.clone(), status });
        }
        let profiles: Vec<DoctorProfile> = state
            .profiles()
            .into_iter()
            .map(|p| DoctorProfile { name: p.name, available: p.available, qualification: "unqualified" })
            .collect();
        next_steps.push("no profile is qualified against the M4 quality gates yet (docs/quality); treat every Pass as a reduced exposure, not a guarantee".to_string());
        let secrets = state.vault.list_secret_names()?;
        let mut datasets = Vec::new();
        for d in state
            .vault
            .datasets()?
            .into_iter()
            .filter(|d| d.kind != inumaki_vault::DatasetKind::Chat)
        {
            let mut ups = Vec::new();
            for u in state.vault.upstreams(&d.id)? {
                let contract = if u.spec.content_policy.trim() == "{}" {
                    "none"
                } else if Contract::parse(&u.spec.content_policy).is_ok() {
                    "ready"
                } else {
                    next_steps.push(format!(
                        "upstream {} of dataset {} has an invalid content policy: fix the file and add the upstream again",
                        u.spec.name, d.id
                    ));
                    "invalid"
                };
                let prefix = format!("{}/upstream/{}/", d.id, u.spec.name);
                ups.push(DoctorUpstream {
                    name: u.spec.name.clone(),
                    kind: u.spec.kind.as_str().to_string(),
                    contract,
                    has_secrets: secrets.iter().any(|s| s.starts_with(&prefix)),
                });
            }
            datasets.push(DoctorDataset {
                id: d.id,
                profile: d.profile,
                rotation_days: d.rotation_days,
                grace_days: d.grace_days,
                upstreams: ups,
            });
        }
        let tokens = state.vault.gateway_tokens()?.len();
        if tokens == 0 {
            next_steps.push(
                "no gateway tokens: run `inumaki gateway token new <label>` before connecting an agent over TCP"
                    .to_string(),
            );
        }
        Ok(DoctorBody {
            vault,
            models,
            profiles,
            datasets,
            gateway: DoctorGateway { listen: state.gateway_listen_string(), tokens },
            next_steps,
        })
    })
    .await?;
    Ok(Json(body))
}
