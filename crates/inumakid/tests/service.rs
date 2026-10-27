//! The shared service (M4 spec §5.3): one lock per batch, one cache entry
//! per block, a final release check against the namespace's current
//! knowledge, strict restoration, and all-or-nothing on store errors.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use hyper::Method;
use inumaki_core::redact::{Redaction, RedactionAction, RedactionFile, sha256_hex};
use inumaki_core::span::EntityKind;
use inumaki_core::token::{TokenStore, parse_token};
use inumakid::AppState;
use inumakid::cache::CachedOutcome;
use inumakid::service::{
    BlockInput, FieldHint, RehydrateMode, ServiceError, inspect, rehydrate_blocks, sanitize_blocks,
    scan_clear, scan_names,
};
use serde_json::json;

fn blocks(texts: &[&str]) -> Vec<BlockInput> {
    texts.iter().map(|t| BlockInput::text(*t)).collect()
}

fn typed(text: &str, kind: EntityKind) -> BlockInput {
    BlockInput {
        text: text.to_string(),
        hint: FieldHint::Identifier(kind),
        redactions: Vec::new(),
    }
}

async fn sanitize(
    state: &Arc<AppState>,
    dataset: &str,
    texts: &[&str],
) -> Result<Vec<inumakid::service::BlockResult>, ServiceError> {
    let s = Arc::clone(state);
    let ds = dataset.to_string();
    let b = blocks(texts);
    tokio::task::spawn_blocking(move || sanitize_blocks(&s, &ds, None, b))
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batch_uses_one_cache_entry_per_block_and_reports_cached() {
    let d = start().await;
    d.dataset("mail").await;
    let a = sanitize(
        &d.state,
        "mail",
        &[
            "IBAN AT61 1904 3002 3457 3201 bitte.",
            "Rechnung RE-2026-00001 offen.",
        ],
    )
    .await
    .unwrap();
    assert_eq!(a.len(), 2);
    assert!(
        a.iter()
            .all(|r| r.outcome == CachedOutcome::Pass && !r.cached),
        "{a:?}"
    );
    assert!(a[0].text.contains("<IBAN_") && !a[0].text.contains("AT61"));
    assert_eq!(d.state.cache.stats().entries, 2);
    let b = sanitize(
        &d.state,
        "mail",
        &[
            "Rechnung RE-2026-00001 offen.",
            "IBAN AT61 1904 3002 3457 3201 bitte.",
        ],
    )
    .await
    .unwrap();
    assert!(b.iter().all(|r| r.cached), "{b:?}");
    assert_eq!(b[1].text, a[0].text, "same namespace, same token");
    d.stop().await;
}

/// Review Focus 2: block 1 teaches the namespace a customer number (the
/// domain label detects it) that block 0 carries without a label. Block 0
/// must not leave in clear in this batch: since Task 7c fix round 1 it runs
/// once more against the batch's store and leaves tokenized (it was
/// withheld before); the next batch gets the same token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn later_block_teaches_identifier_earlier_block_is_tokenized() {
    let d = start().await;
    d.dataset("mail").await;
    let first = sanitize(
        &d.state,
        "mail",
        &[
            "Kunde 8439271 hat angerufen.",
            "Kundennummer 8439271 bitte prüfen.",
        ],
    )
    .await
    .unwrap();
    assert_eq!(first[1].outcome, CachedOutcome::Pass, "{:?}", first[1]);
    assert!(first[1].text.contains("<CUSTOMER_ID_"), "{}", first[1].text);
    // Task 7c fix round 1 (review I2): the earlier block runs once more
    // against the batch's store and leaves tokenized (before: withheld).
    assert_eq!(first[0].outcome, CachedOutcome::Pass, "{:?}", first[0]);
    assert!(
        first[0].text.contains("<CUSTOMER_ID_") && !first[0].text.contains("8439271"),
        "{}",
        first[0].text
    );
    assert_eq!(
        first[0].text.split_whitespace().nth(1),
        first[1].text.split_whitespace().nth(1),
        "tokenized as the customer number block 1 taught"
    );
    let again = sanitize(&d.state, "mail", &["Kunde 8439271 hat angerufen."])
        .await
        .unwrap();
    assert_eq!(again[0].outcome, CachedOutcome::Pass, "{:?}", again[0]);
    assert!(
        again[0].text.contains("<CUSTOMER_ID_") && !again[0].text.contains("8439271"),
        "{}",
        again[0].text
    );
    assert_eq!(
        again[0].text.split_whitespace().nth(1),
        first[1].text.split_whitespace().nth(1),
        "same entity, same token"
    );
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn store_error_in_a_batch_returns_no_block_at_all() {
    let d = start().await;
    d.dataset("mail").await;
    sanitize(&d.state, "mail", &["IBAN AT61 1904 3002 3457 3201 bitte."])
        .await
        .unwrap();
    d.state.vault.delete_dataset("mail").unwrap();
    let s = Arc::clone(&d.state);
    let err = tokio::task::spawn_blocking(move || {
        sanitize_blocks(
            &s,
            "mail",
            Some("offline"),
            blocks(&["Text ohne alles.", "IBAN AT61 1904 3002 3457 3201."]),
        )
    })
    .await
    .unwrap()
    .unwrap_err();
    assert!(
        matches!(err, ServiceError::Vault(_) | ServiceError::Store(_)),
        "{err}"
    );
    assert!(!err.to_string().contains("AT61"));
    d.stop().await;
}

/// Review Focus 5: strict restoration is all-or-nothing across the batch and
/// counts removed markers as unresolved; permissive returns text with counts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rehydrate_blocks_strict_is_all_or_nothing() {
    let d = start().await;
    d.dataset("mail").await;
    let a = sanitize(&d.state, "mail", &["IBAN AT61 1904 3002 3457 3201 bitte."])
        .await
        .unwrap();
    let tok = a[0]
        .text
        .split_whitespace()
        .find(|w| w.starts_with("<IBAN_"))
        .unwrap()
        .to_string();
    let s = Arc::clone(&d.state);
    let good = tok.clone();
    let ok = tokio::task::spawn_blocking(move || {
        rehydrate_blocks(
            &s,
            "mail",
            blocks(&[&format!("Konto {good}"), "nichts"]),
            RehydrateMode::Strict,
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(ok[0].text, "Konto AT61 1904 3002 3457 3201");
    assert_eq!(ok[1].text, "nichts");
    let s = Arc::clone(&d.state);
    let bad = tok.clone();
    let err = tokio::task::spawn_blocking(move || {
        rehydrate_blocks(
            &s,
            "mail",
            blocks(&[
                &format!("Konto {bad}"),
                "<PERSON_000000> und <SECRET_REMOVED>",
            ]),
            RehydrateMode::Strict,
        )
    })
    .await
    .unwrap()
    .unwrap_err();
    assert!(
        matches!(
            err,
            ServiceError::Unresolved {
                unknown: 1,
                removed: 1
            }
        ),
        "{err}"
    );
    let s = Arc::clone(&d.state);
    let lax = tokio::task::spawn_blocking(move || {
        rehydrate_blocks(
            &s,
            "mail",
            blocks(&["<PERSON_000000> und <SECRET_REMOVED>"]),
            RehydrateMode::Permissive,
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(lax[0].text, "<PERSON_000000> und <SECRET_REMOVED>");
    assert_eq!((lax[0].unknown_tokens, lax[0].removed_markers), (1, 1));
    d.stop().await;
}

/// Daemon whose config lists `org` as a known organization and has a
/// `Ansprechpartner` label that detects a PERSON (no NER in these tests).
async fn start_with_org_and_person_label(org: &str) -> (TestDaemon, tempfile::TempDir) {
    let lists = tempfile::tempdir().unwrap();
    let orgs = lists.path().join("orgs.txt");
    std::fs::write(&orgs, format!("{org}\n")).unwrap();
    let base = BASE_CONFIG.replace(
        "organizations = []",
        &format!("organizations = [{:?}]", orgs.to_str().unwrap()),
    );
    assert_ne!(base, BASE_CONFIG);
    let d = start_with_config(
        format!(
            "{base}\n[[domain.labels]]\nlabels = [\"Ansprechpartner\"]\nkind = \"PERSON\"\nvalue = \"[A-Z][a-z]+ [A-Z][a-z]+\"\n[daemon]\ndefault_profile = \"offline\"\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"127.0.0.1:0\"\n"
        ),
        None,
        Duration::from_secs(3600),
        None,
    )
    .await;
    (d, lists)
}

/// Fix round 1: the release check and the cache-hit re-check follow the
/// request profile's policy. An ORGANIZATION a strict request minted stays in
/// clear under `offline` (preserve at >= 0.70) and the block passes, fresh or
/// cached; before the fix every such block was withheld as a leak.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn known_entity_the_profile_preserves_is_not_withheld() {
    let (d, _lists) = start_with_org_and_person_label("Quolnath Bau GmbH").await;
    d.dataset("mail").await;
    let text = "Auftrag von Quolnath Bau GmbH erhalten.";
    let a = sanitize(&d.state, "mail", &[text]).await.unwrap();
    assert_eq!(a[0].outcome, CachedOutcome::Pass, "{:?}", a[0]);
    assert!(
        a[0].text.contains("Quolnath Bau GmbH"),
        "offline preserves ORGANIZATION"
    );
    let s = Arc::clone(&d.state);
    let strict = tokio::task::spawn_blocking(move || {
        sanitize_blocks(
            &s,
            "mail",
            Some("offline-strict"),
            blocks(&["Rechnung an Quolnath Bau GmbH."]),
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert!(
        strict[0].text.contains("<ORGANIZATION_"),
        "strict mints it: {}",
        strict[0].text
    );
    // Reopen the handle: the ORGANIZATION stays in the known-entity
    // automaton but leaves the working set, so the engine's own leak check
    // no longer sees it (a busy namespace evicts it the same way) and the
    // offline policy keeps it in clear.
    d.state.close_namespace("mail");
    let b = sanitize(
        &d.state,
        "mail",
        &[text, "Termin mit Quolnath Bau GmbH morgen."],
    )
    .await
    .unwrap();
    assert!(b.iter().all(|r| r.outcome == CachedOutcome::Pass), "{b:?}");
    assert!(
        b[0].cached,
        "the cache-hit re-check keeps a result whose clear entity the policy preserves"
    );
    assert!(!b[1].cached);
    assert!(b[1].text.contains("Quolnath Bau GmbH"));
    d.stop().await;
}

/// Fix round 1, other side: a kind the profile tokenizes (PERSON, full name
/// or surname alone) never leaves in clear when a later block of the same
/// batch teaches it (since Task 7c fix round 1: re-run and tokenized, not
/// withheld).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn later_block_teaches_person_earlier_blocks_are_tokenized() {
    let (d, _lists) = start_with_org_and_person_label("Quolnath Bau GmbH").await;
    d.dataset("mail").await;
    let r = sanitize(
        &d.state,
        "mail",
        &[
            "Zyxwuria Quolnath hat angerufen.",
            // No honorific: the anchor detector would find `Frau Quolnath`.
            "Der Kollege Quolnath bittet um Rückruf.",
            "Ansprechpartner Zyxwuria Quolnath, bitte melden.",
        ],
    )
    .await
    .unwrap();
    assert_eq!(r[2].outcome, CachedOutcome::Pass, "{:?}", r[2]);
    assert!(r[2].text.contains("<PERSON_"), "{}", r[2].text);
    // Task 7c fix round 1 (review I2): the earlier blocks run once more
    // against the batch's store and leave tokenized (before: withheld).
    let st = d.state.vault.tokens();
    let person_suffixes = |b: &inumakid::service::BlockResult| -> Vec<String> {
        (0..b.replaced.len())
            .filter(|&k| b.replaced[k].kind == EntityKind::Person)
            .filter_map(|k| parse_token(st, replaced_text(b, k)).map(|p| p.suffix.to_string()))
            .collect()
    };
    let full = person_suffixes(&r[2]);
    assert_eq!(full.len(), 1, "{}", r[2].text);
    for (i, b) in r[..2].iter().enumerate() {
        assert_eq!(b.outcome, CachedOutcome::Pass, "block {i}: {b:?}");
        assert!(!b.text.contains("Quolnath"), "block {i}: {}", b.text);
        // the name is tokenized as the person block 2 taught (its token,
        // or a surface token of it for the surname alone)
        assert!(
            person_suffixes(b).contains(&full[0]),
            "block {i}: {}",
            b.text
        );
    }
    d.stop().await;
}

/// M4 spec §5.3: a typed identifier field is tokenized from its field
/// semantics even when no detector would find it, and the token equals the
/// one a text mention of the same value gets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_identifier_blocks_mint_the_same_token_as_text_mentions() {
    let d = start().await;
    d.dataset("mail").await;
    let s = Arc::clone(&d.state);
    let out = tokio::task::spawn_blocking(move || {
        sanitize_blocks(
            &s,
            "mail",
            None,
            vec![
                typed("8439271", EntityKind::CustomerId),
                BlockInput::text("Kundennummer 8439271 bitte prüfen."),
                typed("", EntityKind::CustomerId),
            ],
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(out[0].outcome, CachedOutcome::Pass);
    assert!(out[0].text.starts_with("<CUSTOMER_ID_"), "{}", out[0].text);
    assert_eq!(out[0].replacements, 1);
    assert_eq!(
        out[0].kinds.iter().map(|k| k.label()).collect::<Vec<_>>(),
        ["CUSTOMER_ID"]
    );
    assert!(!out[0].cached, "typed blocks are never cached");
    assert_eq!(
        out[1].text.split_whitespace().nth(1),
        Some(out[0].text.as_str()),
        "same entity, same token"
    );
    assert_eq!(
        out[2].text, "",
        "empty identifier stays empty, nothing minted"
    );
    assert_eq!(d.state.vault.dataset("mail").unwrap().entries, 1);
    d.stop().await;
}

/// Spec §9.1: redactions are mandatory transformations that never weaken
/// verification, and they are part of the cache identity.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redactions_transform_and_change_the_cache_identity() {
    let d = start().await;
    d.dataset("mail").await;
    let text = "Bitte an Sarah Leitner weiterleiten.";
    let plain = sanitize(&d.state, "mail", &[text]).await.unwrap();
    assert!(
        plain[0].text.contains("Sarah Leitner"),
        "offline: not detected"
    );
    let file = RedactionFile {
        input_sha256: sha256_hex(text),
        spans: vec![Redaction {
            start: 9,
            end: 22,
            kind: "PERSON".into(),
            action: RedactionAction::Tokenize,
        }],
    };
    let s = Arc::clone(&d.state);
    let f = file.clone();
    let red = tokio::task::spawn_blocking(move || {
        sanitize_blocks(
            &s,
            "mail",
            None,
            vec![BlockInput {
                text: text.into(),
                hint: FieldHint::FreeText,
                redactions: f.spans,
            }],
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert!(!red[0].cached, "different identity than the plain result");
    assert!(
        red[0].text.starts_with("Bitte an <PERSON_"),
        "{}",
        red[0].text
    );
    let again = sanitize(&d.state, "mail", &[text]).await.unwrap();
    assert!(
        !again[0].text.contains("Sarah Leitner"),
        "the namespace learned the name from the redaction: {}",
        again[0].text
    );
    d.stop().await;
}

/// Spec §9.1: inspection never mints, never dispatches, shows metadata by
/// default and values only on request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inspect_shows_spans_and_reasons_without_minting() {
    let d = start().await;
    d.dataset("mail").await;
    let text = "IBAN AT61 1904 3002 3457 3201 und Sarah Leitner.";
    let s = Arc::clone(&d.state);
    let i = tokio::task::spawn_blocking(move || inspect(&s, "mail", None, text, None, false))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(i.outcome, CachedOutcome::Pass);
    assert_eq!(i.profile, "offline");
    assert_eq!(i.spans.len(), 1);
    assert_eq!(
        (
            i.spans[0].kind.as_str(),
            i.spans[0].action.as_str(),
            i.spans[0].source.as_str()
        ),
        ("IBAN", "tokenize", "RegexValidated")
    );
    assert_eq!(
        &text[i.spans[0].start..i.spans[0].end],
        "AT61 1904 3002 3457 3201"
    );
    assert!(
        i.spans[0].original.is_none() && i.candidate.is_none(),
        "metadata only"
    );
    assert!(
        i.limitations.iter().any(|l| l.contains("no NER")),
        "{:?}",
        i.limitations
    );
    assert_eq!((i.rotation_days, i.grace_days), (30, 7));
    assert_eq!(
        d.state.vault.dataset("mail").unwrap().entries,
        0,
        "no persistent mint"
    );
    let s = Arc::clone(&d.state);
    let v = tokio::task::spawn_blocking(move || inspect(&s, "mail", None, text, None, true))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        v.spans[0].original.as_deref(),
        Some("AT61 1904 3002 3457 3201")
    );
    assert!(v.candidate.unwrap().contains("<IBAN_"));
    assert_eq!(d.state.vault.dataset("mail").unwrap().entries, 0);
    // a known entity resolves to its existing token in the preview
    let minted = sanitize(&d.state, "mail", &["IBAN AT61 1904 3002 3457 3201"])
        .await
        .unwrap();
    let tok = minted[0]
        .text
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_string();
    let s = Arc::clone(&d.state);
    let v = tokio::task::spawn_blocking(move || inspect(&s, "mail", None, text, None, true))
        .await
        .unwrap()
        .unwrap();
    assert!(v.candidate.unwrap().contains(&tok));
    // stale digest is refused
    let s = Arc::clone(&d.state);
    let bad = RedactionFile {
        input_sha256: sha256_hex("other"),
        spans: vec![],
    };
    let e = tokio::task::spawn_blocking(move || inspect(&s, "mail", None, text, Some(&bad), false))
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(e, ServiceError::Redaction(_)), "{e}");
    d.stop().await;
}

/// Fix round 1, finding 3: an identifier block carrying redactions is
/// refused before anything in the *batch* is transformed, not just before
/// that block itself — a free-text block ahead of it must not mint either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identifier_block_with_redactions_refuses_the_whole_batch_before_any_mint() {
    let d = start().await;
    d.dataset("mail").await;
    let mut bad = typed("8439271", EntityKind::CustomerId);
    bad.redactions = vec![Redaction {
        start: 0,
        end: 1,
        kind: "CUSTOMER_ID".into(),
        action: RedactionAction::Tokenize,
    }];
    let s = Arc::clone(&d.state);
    let e = tokio::task::spawn_blocking(move || {
        sanitize_blocks(
            &s,
            "mail",
            None,
            vec![BlockInput::text("Sarah Leitner ruft an."), bad],
        )
    })
    .await
    .unwrap()
    .unwrap_err();
    assert!(
        matches!(e, ServiceError::Unsupported("redactions_on_identifier")),
        "{e}"
    );
    assert_eq!(
        d.state.vault.dataset("mail").unwrap().entries,
        0,
        "the leading free-text block must not have minted either"
    );
    d.stop().await;
}

/// Fix round 1, finding 4: a whitespace-only identifier value must not
/// mint a shared token for every blank value of that kind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn whitespace_only_identifier_stays_empty_and_mints_nothing() {
    let d = start().await;
    d.dataset("mail").await;
    let s = Arc::clone(&d.state);
    let out = tokio::task::spawn_blocking(move || {
        sanitize_blocks(&s, "mail", None, vec![typed("   ", EntityKind::CustomerId)])
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(out[0].text, "", "{}", out[0].text);
    assert_eq!(out[0].replacements, 0);
    assert_eq!(d.state.vault.dataset("mail").unwrap().entries, 0);
    d.stop().await;
}

/// Plan 2c: discovery metadata runs under the dataset profile's metadata
/// profile, other free text of the same batch under the profile itself; a
/// metadata profile is neither a dataset profile nor listed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_blocks_use_the_metadata_profile() {
    let extra = "[[domain.patterns]]\nregex = \"Elektriker\"\nkind = \"PROFESSION\"\nconfidence = 0.7\n\
        [profiles.md-base]\nextends = \"offline\"\n\
        [profiles.md-base.entities]\nPROFESSION = { action = \"tokenize\", min_confidence = 0.9 }\n\
        [profiles.md-base.verifier]\nretry_profile = \"md-base\"\n\
        [profiles.md-base-metadata]\nextends = \"md-base\"\nmetadata_of = \"md-base\"\nescalate_below = 1.0\n\
        [profiles.md-base-metadata.verifier]\nretry_profile = \"md-base-metadata\"\n";
    let d = start_with("", extra, Duration::from_secs(3600), None).await;
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "md", "name": "T", "profile": "md-base" })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "md2", "name": "T", "profile": "md-base-metadata" })),
        )
        .await;
    assert_eq!(code, 400, "a metadata profile is not a dataset profile");
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert!(
        !st["profiles"].to_string().contains("md-base-metadata"),
        "{st}"
    );
    let text = "Der Elektriker kommt.";
    let s = Arc::clone(&d.state);
    let out = tokio::task::spawn_blocking(move || {
        sanitize_blocks(
            &s,
            "md",
            None,
            vec![
                BlockInput::text(text),
                BlockInput {
                    text: text.into(),
                    hint: FieldHint::Metadata,
                    redactions: Vec::new(),
                },
            ],
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        out[0].outcome,
        CachedOutcome::Blocked,
        "free text escalates under md-base"
    );
    assert_eq!(
        out[1].outcome,
        CachedOutcome::Pass,
        "metadata has no escalation band"
    );
    assert_eq!(out[1].text, text);
    d.stop().await;
}

/// Fix round 1, finding 1: a metadata profile is refused as the primary
/// profile even when it reaches `sanitize_blocks` by an explicit override
/// (never only at dataset creation, which cannot see a config edit made
/// after the dataset exists).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_metadata_profile_is_refused_as_the_primary_profile() {
    let extra = "[profiles.md-base]\nextends = \"offline\"\n\
        [profiles.md-base-metadata]\nextends = \"md-base\"\nmetadata_of = \"md-base\"\n";
    let d = start_with("", extra, Duration::from_secs(3600), None).await;
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "md", "name": "T", "profile": "md-base" })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    let s = Arc::clone(&d.state);
    let err = tokio::task::spawn_blocking(move || {
        sanitize_blocks(&s, "md", Some("md-base-metadata"), blocks(&["hi"]))
    })
    .await
    .unwrap()
    .unwrap_err();
    assert!(
        matches!(err, ServiceError::Unsupported("metadata_profile")),
        "{err}"
    );
    d.stop().await;
}

async fn name_hits(state: &Arc<AppState>, names: &[&str]) -> u32 {
    let s = Arc::clone(state);
    let v: Vec<String> = names.iter().map(|n| (*n).to_string()).collect();
    tokio::task::spawn_blocking(move || scan_names(&s, "mail", &v))
        .await
        .unwrap()
        .unwrap()
}

/// Plan 2c: in exposed names a known person, organization, or street
/// counts only when its match spans two or more words; identifier kinds
/// and validated identifiers count as in the tripwire. Plan 4a: the tripwire
/// no longer counts a one-part PERSON either (not a known entity).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn name_scan_skips_single_word_names_only() {
    let d = start().await;
    d.dataset("mail").await;
    let s = Arc::clone(&d.state);
    tokio::task::spawn_blocking(move || {
        sanitize_blocks(
            &s,
            "mail",
            None,
            vec![
                typed("Max", EntityKind::Person),
                typed("Zyxwuria Quolnath", EntityKind::Person),
                typed("8439271", EntityKind::CustomerId),
            ],
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        name_hits(
            &d.state,
            &["max_results", "max results", "max Results", "max"]
        )
        .await,
        0
    );
    assert!(name_hits(&d.state, &["zyxwuria quolnath orders"]).await > 0);
    assert!(name_hits(&d.state, &["lookup 8439271"]).await > 0);
    assert!(name_hits(&d.state, &["AT611904300234573201"]).await > 0);
    let s = Arc::clone(&d.state);
    let hits =
        tokio::task::spawn_blocking(move || scan_clear(&s, "mail", &["ask Max".to_string()]))
            .await
            .unwrap()
            .unwrap();
    assert!(
        hits.is_empty(),
        "plan 4a: a one-part PERSON is stored and restorable but is never a known entity, so the tripwire does not count it"
    );
    let s = Arc::clone(&d.state);
    let hits = tokio::task::spawn_blocking(move || {
        scan_clear(&s, "mail", &["ask Zyxwuria Quolnath".to_string()])
    })
    .await
    .unwrap()
    .unwrap();
    assert!(!hits.is_empty(), "a two-part name still counts");
    d.stop().await;
}

/// A dictionary of `names` plus the offline profile.
async fn start_with_persons(names: &str) -> (TestDaemon, tempfile::TempDir) {
    let dict = tempfile::tempdir().unwrap();
    let persons = dict.path().join("persons.txt");
    std::fs::write(&persons, names).unwrap();
    let base = BASE_CONFIG.replace(
        "persons = []",
        &format!("persons = [\"{}\"]", persons.display()),
    );
    let d = start_with_config(
        format!(
            "{base}\n[daemon]\ndefault_profile = \"offline\"\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"127.0.0.1:0\"\n"
        ),
        None,
        Duration::from_secs(3600),
        None,
    )
    .await;
    (d, dict)
}

/// What each token restores to in the `mail` namespace (prepared first, as
/// rehydration does).
fn originals(d: &TestDaemon, tokens: &[&str]) -> Vec<Option<String>> {
    let ns = d.state.namespace("mail").unwrap();
    let mut n = ns.lock().unwrap();
    let owned: Vec<String> = tokens.iter().map(|t| (*t).to_string()).collect();
    n.prepare(&owned).unwrap();
    tokens
        .iter()
        .map(|t| n.original(t).map(str::to_string))
        .collect()
}

fn replaced_text(r: &inumakid::service::BlockResult, i: usize) -> &str {
    &r.text[r.replaced[i].out_start..r.replaced[i].out_end]
}

/// Plan 4a: a later block's bare first name links to the earlier block's
/// full name within one batch; the result reports the replaced spans.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batch_links_a_later_blocks_bare_name_to_an_earlier_block() {
    let (d, _dict) = start_with_persons("Sarah Leitner\n").await;
    d.dataset("mail").await;
    let out = sanitize(
        &d.state,
        "mail",
        &["Sarah Leitner hat angerufen.", "Danke!\n\nLG Sarah"],
    )
    .await
    .unwrap();
    assert!(
        out.iter().all(|r| r.outcome == CachedOutcome::Pass),
        "{out:?}"
    );
    let full = replaced_text(&out[0], 0);
    assert_eq!(out[1].replaced.len(), 1, "{}", out[1].text);
    let bare = replaced_text(&out[1], 0);
    let s = d.state.vault.tokens();
    let (pf, pb) = (parse_token(s, full).unwrap(), parse_token(s, bare).unwrap());
    assert_eq!(
        pf.suffix, pb.suffix,
        "linked across the batch: {full} {bare}"
    );
    assert!(pf.variant.is_none() && pb.variant.is_some());
    assert_eq!(out[1].replaced[0].kind, EntityKind::Person);
    // the same sign-off in another batch: no batch scope and, by default,
    // no store-scope links (decision 4): surname and first name are both
    // own entities
    let again = sanitize(&d.state, "mail", &["Frau Leitner: Danke!\n\nLG Sarah"])
        .await
        .unwrap();
    assert_eq!(again[0].replaced.len(), 2, "{}", again[0].text);
    let (t0, t1) = (replaced_text(&again[0], 0), replaced_text(&again[0], 1));
    // restoration at service level: every token restores to exactly the text
    // it replaced, never to the full name
    let restored = originals(&d, &[full, bare, t0, t1]);
    assert_eq!(
        restored,
        [
            Some("Sarah Leitner".to_string()),
            Some("Sarah".to_string()),
            Some("Leitner".to_string()),
            Some("Sarah".to_string()),
        ],
        "full, linked sign-off, surname, own-entity first name"
    );
    let full_suffix = pf.suffix.to_string();
    assert_ne!(parse_token(s, t0).unwrap().suffix, full_suffix, "surname");
    assert_ne!(
        parse_token(s, t1).unwrap().suffix,
        full_suffix,
        "first name"
    );
    assert!(!again[0].cached);
    d.stop().await;
}

/// Review Focus 11 (decision 7): a block whose sign-off was linked through
/// the batch scope is not cached, so a later batch without that scope
/// sanitizes it fresh and gets an own-entity token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batch_linked_block_is_not_cached() {
    let (d, _dict) = start_with_persons("Sarah Leitner\n").await;
    d.dataset("mail").await;
    let first = sanitize(
        &d.state,
        "mail",
        &["Sarah Leitner hat angerufen.", "Danke!\n\nLG Sarah"],
    )
    .await
    .unwrap();
    let s = d.state.vault.tokens();
    let full = parse_token(s, replaced_text(&first[0], 0))
        .unwrap()
        .suffix
        .to_string();
    let linked = parse_token(s, replaced_text(&first[1], 0)).unwrap();
    assert_eq!(linked.suffix, full);
    assert_eq!(
        d.state.cache.stats().entries,
        1,
        "only the first block was cached"
    );
    let again = sanitize(&d.state, "mail", &["Danke!\n\nLG Sarah"])
        .await
        .unwrap();
    assert!(!again[0].cached, "{:?}", again[0]);
    let own = parse_token(s, replaced_text(&again[0], 0)).unwrap();
    assert_ne!(
        own.suffix, full,
        "without the batch scope the sign-off is its own entity"
    );
    assert_eq!(
        d.state.cache.stats().entries,
        2,
        "the own-entity result is cacheable"
    );
    // a document-tier link is cached
    let doc = sanitize(
        &d.state,
        "mail",
        &["Sarah Leitner hat angerufen.\n\nLG Sarah"],
    )
    .await
    .unwrap();
    assert_eq!(doc[0].replaced.len(), 2);
    assert_eq!(d.state.cache.stats().entries, 3);
    d.stop().await;
}

/// Task 4 follow-up (decision 7): a clear copy that only the consistency
/// pass finds, of a value an earlier request minted, is linked from the
/// store (`Window`), so its block is never cached and never served from
/// the cache to another request; a copy whose source is in the same text
/// is linked at `Document` and cached.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_store_only_consistency_link_is_not_cached() {
    let d = start().await;
    d.dataset("mail").await;
    let first = sanitize(&d.state, "mail", &["Hallo Quolnath,\nbitte um Rückruf."])
        .await
        .unwrap();
    assert_eq!(first[0].outcome, CachedOutcome::Pass, "{:?}", first[0]);
    assert!(!first[0].text.contains("Quolnath"), "{}", first[0].text);
    let entries = d.state.cache.stats().entries;
    let later = "Quolnath hat wieder angerufen.";
    for round in 0..2 {
        let r = sanitize(&d.state, "mail", &[later]).await.unwrap();
        assert_eq!(r[0].outcome, CachedOutcome::Pass, "{:?}", r[0]);
        assert!(!r[0].text.contains("Quolnath"), "{}", r[0].text);
        assert!(
            !r[0].cached,
            "round {round}: a store-linked block is never served from the cache"
        );
        assert_eq!(d.state.cache.stats().entries, entries, "round {round}");
    }
    // the source in the same text: a document-tier link, cached
    let doc = "Hallo Quolnath,\nbitte um Rückruf.\n\nGrüße an Quolnath";
    let a = sanitize(&d.state, "mail", &[doc]).await.unwrap();
    assert!(!a[0].text.contains("Quolnath"), "{}", a[0].text);
    let b = sanitize(&d.state, "mail", &[doc]).await.unwrap();
    assert!(b[0].cached, "{:?}", b[0]);
    d.stop().await;
}

/// Review Focus 9 (service half): an own-entity bare name minted by an
/// ambiguous sign-off does not become a known entity, so a later full name
/// that contains it is detected whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bare_name_entity_does_not_split_a_later_full_name() {
    let (d, _dict) = start_with_persons("Sarah Leitner\nSarah Huber\nSarah Gruber\n").await;
    d.dataset("mail").await;
    let amb = sanitize(
        &d.state,
        "mail",
        &["Sarah Leitner und Sarah Huber.\n\nLG Sarah"],
    )
    .await
    .unwrap();
    assert_eq!(amb[0].replaced.len(), 3, "{}", amb[0].text);
    let ns = d.state.namespace("mail").unwrap();
    assert_eq!(
        ns.lock().unwrap().known_entities(),
        2,
        "the bare Sarah is stored but not a known entity"
    );
    let later = sanitize(&d.state, "mail", &["Sarah Gruber schreibt."])
        .await
        .unwrap();
    assert_eq!(later[0].replaced.len(), 1, "{}", later[0].text);
    assert_eq!(
        (later[0].replaced[0].start, later[0].replaced[0].end),
        (0, "Sarah Gruber".len())
    );
    assert!(!later[0].text.contains("Gruber"));
    d.stop().await;
}

/// Review Focus 5: a cached result whose text carries surface tokens still
/// passes the hit re-check and the release check.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cached_text_with_surface_tokens_passes_recheck() {
    let (d, _dict) = start_with_persons("Sarah Leitner\n").await;
    d.dataset("mail").await;
    let text = "Sarah Leitner hat angerufen. Frau Leitner bittet um Rückruf.";
    let first = sanitize(&d.state, "mail", &[text]).await.unwrap();
    assert_eq!(first[0].replaced.len(), 2, "{}", first[0].text);
    assert!(!first[0].cached);
    // teach the namespace another entity in between
    sanitize(&d.state, "mail", &["Kundennummer K-928174 bitte prüfen."])
        .await
        .unwrap();
    let second = sanitize(&d.state, "mail", &[text]).await.unwrap();
    assert!(second[0].cached, "{:?}", second[0]);
    assert_eq!(second[0].text, first[0].text);
    assert_eq!(second[0].replaced, first[0].replaced);
    assert_eq!(second[0].outcome, CachedOutcome::Pass);
    d.stop().await;
}

/// The overlay previews a surface form of a vault entity (the foreign-parent
/// path) without minting it, and a later release still mints its own token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inspection_previews_surface_tokens_of_vault_entities_without_minting() {
    let (d, _dict) = start_with_persons("Sarah Leitner\n").await;
    d.dataset("mail").await;
    sanitize(&d.state, "mail", &["Sarah Leitner hat angerufen."])
        .await
        .unwrap();
    let before = d.state.vault.dataset("mail").unwrap().entries;
    assert_eq!(before, 1);
    let text = "Sarah Leitner hat angerufen.\n\nLG Sarah";
    let s = Arc::clone(&d.state);
    let v = tokio::task::spawn_blocking(move || inspect(&s, "mail", None, text, None, true))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v.replacements, 2, "{:?}", v.candidate);
    let cand = v.candidate.unwrap();
    assert!(!cand.contains("Sarah"), "{cand}");
    // the preview left no row behind: a surface row is not an entity, and
    // peeking again on a fresh inspection yields the same shape
    assert_eq!(d.state.vault.dataset("mail").unwrap().entries, before);
    {
        let ns = d.state.namespace("mail").unwrap();
        let mut n = ns.lock().unwrap();
        let parent = n
            .peek_token(&EntityKind::Person, "Sarah Leitner")
            .unwrap()
            .unwrap();
        assert!(
            n.peek_surface_token(parent.as_str(), "Sarah")
                .unwrap()
                .is_none(),
            "inspection must not mint the surface row"
        );
    }
    d.stop().await;
}

async fn mint(state: &Arc<AppState>, dataset: &str, value: &str, kind: EntityKind) -> String {
    let s = Arc::clone(state);
    let ds = dataset.to_string();
    let b = vec![typed(value, kind)];
    let out = tokio::task::spawn_blocking(move || sanitize_blocks(&s, &ds, None, b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(out[0].outcome, CachedOutcome::Pass, "{:?}", out[0]);
    out[0].text.clone()
}

/// Task 7c (integrator ruling L54): request 1 caches a block with a bare
/// name in clear (nothing known then); request 2 mints the full name. The
/// known-entity automaton leaves one-part names out, but the engine's
/// consistency pass tokenizes the name part, so a replay of request 1's
/// block must not come from the cache: it is a miss and re-sanitized, and
/// the name is a surface token of the full name's entity.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cached_clear_name_part_of_a_later_mint_is_a_miss_and_resanitized() {
    let d = start().await;
    d.dataset("mail").await;
    let text = "Das Paket für Quorvik liegt bereit.";
    let first = sanitize(&d.state, "mail", &[text]).await.unwrap();
    assert_eq!(first[0].outcome, CachedOutcome::Pass, "{:?}", first[0]);
    assert!(
        first[0].text.contains("Quorvik"),
        "precondition: the bare name passes in clear while nothing is known"
    );
    let warm = sanitize(&d.state, "mail", &[text]).await.unwrap();
    assert!(warm[0].cached, "precondition: cached");
    let full = mint(&d.state, "mail", "Quorvik Berger", EntityKind::Person).await;
    let misses = d.state.cache.stats().misses;
    let again = sanitize(&d.state, "mail", &[text]).await.unwrap();
    assert_eq!(again[0].outcome, CachedOutcome::Pass, "{:?}", again[0]);
    assert!(
        !again[0].text.contains("Quorvik"),
        "the cached clear copy was replayed"
    );
    assert!(!again[0].cached);
    assert_eq!(d.state.cache.stats().misses, misses + 1);
    let s = d.state.vault.tokens();
    let bare = parse_token(s, replaced_text(&again[0], 0)).unwrap();
    let parent = parse_token(s, &full).unwrap();
    assert_eq!(
        bare.suffix, parent.suffix,
        "a surface token of the full name"
    );
    assert!(bare.variant.is_some());
    d.stop().await;
}

/// Task 7c: every store kind counts, not only the known-entity kinds (a
/// CITY is not one).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cached_clear_copy_of_any_store_kind_is_a_miss() {
    let d = start().await;
    d.dataset("mail").await;
    let text = "Treffen morgen in Quarnheim beim Lager.";
    let first = sanitize(&d.state, "mail", &[text]).await.unwrap();
    assert!(first[0].text.contains("Quarnheim"), "precondition");
    mint(&d.state, "mail", "Quarnheim", EntityKind::City).await;
    let again = sanitize(&d.state, "mail", &[text]).await.unwrap();
    assert!(!again[0].cached);
    assert!(!again[0].text.contains("Quarnheim"), "{:?}", again[0].kinds);
    d.stop().await;
}

/// Task 7c, no regression: with store values present that the cached text
/// does not carry in clear (one only inside its own token), a replay is
/// still a hit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unchanged_store_still_gives_a_cache_hit() {
    let d = start().await;
    d.dataset("mail").await;
    mint(&d.state, "mail", "Quorvik Berger", EntityKind::Person).await;
    mint(&d.state, "mail", "Quarnheim", EntityKind::City).await;
    let text = "Kundennummer K-928174 bitte prüfen, Paket liegt bereit.";
    let first = sanitize(&d.state, "mail", &[text]).await.unwrap();
    assert_eq!(first[0].outcome, CachedOutcome::Pass, "{:?}", first[0]);
    assert!(!first[0].cached);
    let hits = d.state.cache.stats().hits;
    let again = sanitize(&d.state, "mail", &[text]).await.unwrap();
    assert!(again[0].cached, "{:?}", again[0]);
    assert_eq!(again[0].text, first[0].text);
    assert_eq!(d.state.cache.stats().hits, hits + 1);
    d.stop().await;
}

/// Task 7c fix round 1 (review I2): a later block of the same batch mints
/// the full name; the earlier block's bare name must not leave in clear,
/// and its clear result must not be cached.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_later_block_minting_a_full_name_covers_an_earlier_bare_name() {
    let d = start().await;
    d.dataset("mail").await;
    let text = "Das Paket für Quorvik liegt bereit.";
    let s = Arc::clone(&d.state);
    let out = tokio::task::spawn_blocking(move || {
        sanitize_blocks(
            &s,
            "mail",
            None,
            vec![
                BlockInput::text(text),
                typed("Quorvik Berger", EntityKind::Person),
            ],
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert!(
        !out[0].text.contains("Quorvik"),
        "the earlier block left with the bare name in clear"
    );
    assert_eq!(out[0].outcome, CachedOutcome::Pass, "{:?}", out[0]);
    let st = d.state.vault.tokens();
    let bare = parse_token(st, replaced_text(&out[0], 0)).unwrap();
    let full = parse_token(st, &out[1].text).unwrap();
    assert_eq!(bare.suffix, full.suffix, "a surface token of the full name");
    let again = sanitize(&d.state, "mail", &[text]).await.unwrap();
    assert!(
        !again[0].text.contains("Quorvik"),
        "nothing clear was cached"
    );
    d.stop().await;
}
