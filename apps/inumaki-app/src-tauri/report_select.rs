//! Which committed `docs/quality/*.json` report stands for a profile in
//! Settings. Shared by `build.rs` (`#[path]`) and a unit test in
//! `src/measured.rs`, so the build script's rule is tested on the same code.
//!
//! The rule: the profile's own PRIMARY-corpus report, the plain
//! `inumaki eval --profile P` run that the gate baselines in
//! `crates/inumaki-eval/baselines/P.toml` are recorded from, the latest of
//! them by `provenance.evaluated_at`. Never the latest report of any kind:
//! held-out, generated-only, tool-JSON, sequence, `--via-service` and
//! `--config` ablation runs are reports of the same profile on other
//! corpora or configurations and would show other numbers as the profile's.
//!
//! Primary, from fields every committed report carries (`eval.rs` in
//! `inumaki-cli` writes `family` as `tuning` for cases plus generated mails,
//! `held-out`, `cases`, `file`, `tool-json+<family>`, and appends `+service`):
//! - `provenance.family == "tuning"` exactly and `provenance.cases > 0` and
//!   `provenance.generated > 0` (built-in cases plus generated mails);
//! - the run is the canonical one:
//!   - reports that carry `provenance.canonical` (written by the eval
//!     command since the field was added): `canonical == true`. The writer
//!     sets it exactly when every option is at its default (corpus
//!     selection, generate count, seed, transforms, verifier trials, engine
//!     path, embedded configuration), so a later change of the default
//!     corpus size or seed needs no change here;
//!   - LEGACY reports (field absent): `seed == LEGACY_SEED` and
//!     `generated == LEGACY_GENERATED` (the defaults when they were
//!     recorded), `config_source` not `file`, and `config_sha256` not in
//!     `KNOWN_OVERRIDE_CONFIGS` (the one committed `--config` ablation run
//!     of plan 4a, recorded before `config_source` existed).
//!
//! A report that is missing any of these fields is unknown and never
//! primary. There is no fallback to a non-primary report: a profile with no
//! primary report gets no row. A primary report that lacks a field the row
//! needs is reported in `skipped`, and `build.rs` fails the build on it
//! rather than silently showing an older report.

use std::collections::BTreeMap;

use serde_json::Value;

/// LEGACY: the `eval` defaults when the committed reports without
/// `provenance.canonical` were recorded (`--seed 42`, `--generate 2000`).
/// Do not change; new reports carry `canonical` instead.
pub const LEGACY_SEED: u64 = 42;
/// LEGACY: see `LEGACY_SEED`.
pub const LEGACY_GENERATED: u64 = 2000;

/// LEGACY: `config_sha256` of committed reports recorded with `--config`
/// before reports carried `provenance.config_source`. Digest of the
/// ablation config of `docs/quality/2026-10-09-4a-surface-independent-*.json`
/// (identical corpus and profile as the primary run, other
/// `[tokens] surface_form`).
pub const KNOWN_OVERRIDE_CONFIGS: &[&str] =
    &["48aa264e24796f577fe1461b2f52a05f75c35541657807a12b3bca2ec53c5d03"];

/// True when `v` is the primary-corpus, canonical run of its profile (see
/// the module comment).
pub fn is_primary(v: &Value) -> bool {
    let p = &v["provenance"];
    let corpus_ok = p["family"].as_str() == Some("tuning")
        && p["cases"].as_u64().is_some_and(|n| n > 0)
        && p["generated"].as_u64().is_some_and(|n| n > 0);
    let canonical_ok = match p.get("canonical") {
        Some(c) => c.as_bool() == Some(true),
        None => {
            p["seed"].as_u64() == Some(LEGACY_SEED)
                && p["generated"].as_u64() == Some(LEGACY_GENERATED)
                && p["config_source"].as_str() != Some("file")
                && p["config_sha256"]
                    .as_str()
                    .is_some_and(|h| !KNOWN_OVERRIDE_CONFIGS.contains(&h))
        }
    };
    corpus_ok && canonical_ok
}

/// The embedded row of one report, or the name of the missing field.
pub fn row(v: &Value) -> Result<(String, i64, Value), &'static str> {
    let profile = v["profile"].as_str().ok_or("profile")?;
    // `provenance.evaluated_at` is unix seconds (an integer) in the reports.
    let at = v["provenance"]["evaluated_at"]
        .as_i64()
        .ok_or("provenance.evaluated_at")?;
    let docs = v["docs"].as_u64().ok_or("docs")?;
    let leak_docs = v["docs_with_leak"].as_u64().ok_or("docs_with_leak")?;
    let accepted = v["accepted_leak_docs"]
        .as_u64()
        .ok_or("accepted_leak_docs")?;
    let p50 = v["latency_ms"]["p50"].as_f64().ok_or("latency_ms.p50")?;
    let p95 = v["latency_ms"]["p95"].as_f64().ok_or("latency_ms.p95")?;
    let platform = v["provenance"]["platform"]
        .as_str()
        .ok_or("provenance.platform")?;
    let commit = v["provenance"]["git_commit"]
        .as_str()
        .ok_or("provenance.git_commit")?;
    Ok((
        profile.to_string(),
        at,
        serde_json::json!({
            "profile": profile,
            "docs": docs, "leak_docs": leak_docs, "accepted_leak_docs": accepted,
            "p50_ms": p50, "p95_ms": p95,
            "platform": platform, "commit": commit, "evaluated_at": at,
        }),
    ))
}

/// One selected report: its source name (as given), evaluation time, row.
pub type Selected = (String, i64, Value);

/// The primary report per profile, latest by `evaluated_at`. `reports` is
/// `(name, parsed JSON)` in a fixed order, so two reports of the same second
/// always resolve the same way (the later in the order wins a tie).
/// Non-primary and unreadable-as-row reports are skipped; `skipped` gets
/// `(name, missing field)` for primary reports that lack a row field.
pub fn select(
    reports: &[(String, Value)],
    skipped: &mut Vec<(String, &'static str)>,
) -> BTreeMap<String, Selected> {
    let mut latest: BTreeMap<String, Selected> = BTreeMap::new();
    for (name, v) in reports {
        if !is_primary(v) {
            continue;
        }
        match row(v) {
            Ok((profile, at, r)) => {
                if latest.get(&profile).is_none_or(|(_, old, _)| *old <= at) {
                    latest.insert(profile, (name.clone(), at, r));
                }
            }
            Err(field) => skipped.push((name.clone(), field)),
        }
    }
    latest
}
