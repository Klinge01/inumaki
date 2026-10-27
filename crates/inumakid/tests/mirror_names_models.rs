#![cfg(feature = "models-tests")]
//! B6 through the daemon with the real models (structured-positions plan,
//! Task 3): ordinary file-name stems the model used to tag as persons stay
//! unchanged, while surnames in file names and identifiers whose only
//! detection is the mirror's detection variant (IBAN, social security, and
//! card groups joined by `_ . -`; rulings L124(b), L129) are never released
//! in clear. Every stem is synthetic.
//!
//! Needs `INUMAKI_MODELS_DIR`. Run with `--nocapture` to see each outcome.
// The per-stem outcomes are printed for the report.
#![allow(clippy::print_stdout)]

mod common;

use std::sync::Arc;

use common::mirror::start_mirror_with_models;
use hyper::Method;
use inumakid::cache::CachedOutcome;
use serde_json::json;

/// Stems that must come back unchanged (`Pass`, text as written).
const UNCHANGED: &[&str] = &[
    "mail-anfrage",
    "notizen",
    "readme",
    "foto",
    "Foto",
    "steuer-bescheid",
    "anhang",
    "tabelle",
    "Unbenannt",
    "Neues Dokument",
    "Mappe1",
    "IMG_2034",
    "IMG_20261001_123456",
    "DSC01234",
    "scan0001",
    "Screenshot 2026-10-01 at 12.34.56",
    "foto-2025-07-14",
    "protokoll_sitzung_2026-10-01",
];

/// A stem of [`UNCHANGED`] that the verifier's bare-identifier backstop
/// (one to three capitals and five or more digits, read as a contract
/// number) withholds once the sanitizer drops the model's `PERSON` span
/// (S6): unchanged or withheld (`Blocked`, empty text), never tokenized.
/// Pending a controller ruling (Task 3 report); the verifier is not changed
/// here.
const VERIFIER_WITHHELD: &[&str] = &["DSC01234"];

/// Stems with a person's name: tokenized as `PERSON` with none of the name
/// parts left (case-insensitive), or withheld.
const NAMES: &[(&str, &[&str])] = &[
    ("Huber", &["huber"]),
    ("huber", &["huber"]),
    ("Rechnung_Huber_2026", &["huber"]),
    ("anna-gruber-cv", &["anna", "gruber"]),
    ("leitner-angebot", &["leitner"]),
    ("CV_Anna_Gruber", &["anna", "gruber"]),
    ("gruber_anna", &["gruber", "anna"]),
    ("sarah-leitner", &["sarah", "leitner"]),
];

/// Identifiers whose only detection is the detection variant (review C2):
/// never released with the listed digits.
const IDENTIFIERS: &[(&str, &str)] = &[
    ("IBAN_AT61_1904_3002_3457_3201", "3457"),
    ("AT61.1904.3002.3457.3201", "3457"),
    // L129 minor: `0532_2010_12` is no `YYYY-MM` inside the IBAN.
    ("IBAN_DE66_3704_0044_0532_2010_12", "0532"),
    ("svnr_1237-010180", "010180"),
    ("karte_4111_1111_1111_1111", "4111"),
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b6_ordinary_file_names_stay_and_names_are_tokenized() {
    let m = start_mirror_with_models().await;
    let (code, body) =
        m.d.call(
            Method::POST,
            "/v1/datasets",
            Some(
                json!({"id": "fnames", "name": "F", "profile": "support-email", "kind": "folder"}),
            ),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    let s = Arc::clone(&m.d.state);
    let failures = tokio::task::spawn_blocking(move || {
        // The ordinary stems first, in their own call: a name minted by a
        // stem of the same batch (`Rechnung_Huber_2026` mints the person
        // `Rechnung Huber 2026`) links its parts in later stems
        // (`protokoll_sitzung_2026-10-01` gets its `2026` tokenized), a
        // precision residual of the name splice, not of B6 (Task 3 report).
        let ordinary: Vec<String> = UNCHANGED.iter().map(|s| s.to_string()).collect();
        let named: Vec<String> = NAMES
            .iter()
            .map(|(s, _)| *s)
            .chain(IDENTIFIERS.iter().map(|(s, _)| *s))
            .map(str::to_string)
            .collect();
        let mut out = inumakid::service::sanitize_names(&s, "fnames", ordinary).unwrap();
        out.extend(inumakid::service::sanitize_names(&s, "fnames", named).unwrap());
        let mut failures = Vec::new();
        let (mut tokenized, mut withheld) = (0, 0);
        let mut it = out.iter();
        for stem in UNCHANGED {
            let r = it.next().unwrap();
            let ok = (r.outcome == CachedOutcome::Pass && r.text == *stem)
                || (VERIFIER_WITHHELD.contains(stem)
                    && r.outcome == CachedOutcome::Blocked
                    && r.text.is_empty());
            println!(
                "unchanged {stem:?}: {:?} {:?} {}",
                r.outcome,
                r.text,
                if ok { "ok" } else { "CHANGED" }
            );
            if !ok {
                failures.push(format!("changed: {stem}"));
            }
        }
        for (stem, parts) in NAMES {
            let r = it.next().unwrap();
            let lower = r.text.to_lowercase();
            let (ok, how) = match r.outcome {
                CachedOutcome::Pass => (
                    r.text.contains("<PERSON_") && !parts.iter().any(|p| lower.contains(p)),
                    "tokenized",
                ),
                CachedOutcome::Blocked => (r.text.is_empty(), "withheld"),
                CachedOutcome::PassUncertain => (false, "uncertain"),
            };
            println!(
                "name {stem:?}: {how} {:?} {}",
                r.text,
                if ok { "ok" } else { "IN CLEAR" }
            );
            match (ok, how) {
                (true, "tokenized") => tokenized += 1,
                (true, _) => withheld += 1,
                _ => failures.push(format!("name in clear: {stem}")),
            }
        }
        for (stem, digits) in IDENTIFIERS {
            let r = it.next().unwrap();
            let (ok, how) = match r.outcome {
                CachedOutcome::Pass => (!r.text.contains(digits), "tokenized"),
                CachedOutcome::Blocked => (r.text.is_empty(), "withheld"),
                CachedOutcome::PassUncertain => (false, "uncertain"),
            };
            println!(
                "identifier {stem:?}: {how} {:?} {}",
                r.text,
                if ok { "ok" } else { "IN CLEAR" }
            );
            match (ok, how) {
                (true, "tokenized") => tokenized += 1,
                (true, _) => withheld += 1,
                _ => failures.push(format!("identifier in clear: {stem}")),
            }
        }
        println!("never in clear: {tokenized} tokenized, {withheld} withheld");
        failures
    })
    .await
    .unwrap();
    assert!(failures.is_empty(), "{failures:#?}");
}
