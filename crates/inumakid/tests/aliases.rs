//! M4 spec §16.5 through the daemon: a dataset with an alias line in its
//! dictionary mints a surface token of one entity for every variant,
//! restores each to the text that was replaced, and the tripwire (plan 2 Task 9) sees a variant in clear.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use hyper::Method;
use inumaki_core::span::EntityKind;
use inumakid::service::{
    BlockInput, FieldHint, RehydrateMode, rehydrate_blocks, sanitize_blocks, scan_clear,
};
use serde_json::json;

/// A block hinted as an identifier field of `kind` (M4 spec §5.3 field
/// hints), as gateway `content_policy` identifier rules produce them.
fn typed(text: &str, kind: EntityKind) -> BlockInput {
    BlockInput {
        text: text.to_string(),
        hint: FieldHint::Identifier(kind),
        redactions: Vec::new(),
    }
}

async fn daemon_with_aliases() -> (TestDaemon, tempfile::TempDir) {
    let dict = tempfile::tempdir().unwrap();
    let persons = dict.path().join("persons.txt");
    std::fs::write(&persons, "Hans-Peter Gruber | HP Gruber | Hansi\n").unwrap();
    let base = BASE_CONFIG.replace(
        "persons = []",
        &format!("persons = [\"{}\"]", persons.display()),
    );
    assert_ne!(base, BASE_CONFIG);
    let config = format!(
        "{base}\n[[dictionary.aliases]]\nkind = \"ORGANIZATION\"\nnames = [\"Muster GmbH\", \"Muster\"]\n\
         [daemon]\ndefault_profile = \"offline\"\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"127.0.0.1:0\"\n"
    );
    let d = start_with_config(config, None, Duration::from_secs(3600), None).await;
    (d, dict)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn variants_share_a_token_restore_the_canonical_and_trip_the_tripwire() {
    let (d, _dict) = daemon_with_aliases().await;
    d.dataset("crm").await;
    let s = Arc::clone(&d.state);
    let out = tokio::task::spawn_blocking(move || {
        sanitize_blocks(
            &s,
            "crm",
            None,
            vec![
                BlockInput::text("Hans-Peter Gruber ruft an."),
                BlockInput::text("HP Gruber bestätigt; Hansi auch."),
            ],
        )
    })
    .await
    .unwrap()
    .unwrap();
    let tok = out[0].text.trim_end_matches(" ruft an.").to_string();
    assert!(tok.starts_with("<PERSON_"), "{}", out[0].text);
    // every variant is a surface token of the one entity: same suffix, its own component
    let settings = inumaki_core::TokenSettings::default();
    let entity = inumaki_core::token::parse_token(&settings, &tok).unwrap();
    assert!(entity.variant.is_none());
    let variants: Vec<&str> = out[1]
        .text
        .split(|c: char| c.is_whitespace() || c == ';' || c == '.')
        .filter(|w| w.starts_with("<PERSON_"))
        .collect();
    assert_eq!(variants.len(), 2, "{}", out[1].text);
    let parsed: Vec<_> = variants
        .iter()
        .map(|t| inumaki_core::token::parse_token(&settings, t).unwrap())
        .collect();
    assert!(
        parsed.iter().all(|p| p.suffix == entity.suffix),
        "{}",
        out[1].text
    );
    assert!(parsed.iter().all(|p| p.variant.is_some()) && parsed[0].variant != parsed[1].variant);
    let listed = d.state.vault.entities("crm", 0, false).unwrap();
    assert_eq!(listed.len(), 1, "one stored entity");
    assert_eq!(listed[0].surface_forms, 2);
    assert!(d.state.vault.dataset("crm").unwrap().entries >= 1);
    let s = Arc::clone(&d.state);
    let text = out[1].text.clone();
    let back = tokio::task::spawn_blocking(move || {
        rehydrate_blocks(
            &s,
            "crm",
            vec![BlockInput::text(text)],
            RehydrateMode::Strict,
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        back[0].text, "HP Gruber bestätigt; Hansi auch.",
        "each variant restores to the text that was replaced"
    );
    // the known-entity detector knows the variants, so the tripwire fires on one in clear
    let s = Arc::clone(&d.state);
    let hits = tokio::task::spawn_blocking(move || {
        scan_clear(&s, "crm", &["bitte Hansi anrufen".to_string()])
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(hits, vec![(EntityKind::Person, 1)]);
    let s = Arc::clone(&d.state);
    let hits = tokio::task::spawn_blocking(move || {
        scan_clear(&s, "crm", &["bitte Hans Peter Gruber anrufen".to_string()])
    })
    .await
    .unwrap()
    .unwrap();
    assert!(
        hits.is_empty(),
        "the hyphenless form is a different phrase (surname-only hits are below the tripwire's confidence)"
    );
    // the config group is loaded too (the daemon started with it); `offline`
    // preserves ORGANIZATION at 0.97, so the text stays in clear here and the
    // group's token sharing on a tokenizing profile is covered by the core tests
    let (code, b) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "crm", "text": "Muster liefert; Muster GmbH bestätigt." })),
        )
        .await;
    assert_eq!(code, 200, "{b}");
    assert_eq!(b["text"], "Muster liefert; Muster GmbH bestätigt.");
    assert_eq!(
        d.state.vault.aliases().len(),
        2,
        "the persons.txt line and the [[dictionary.aliases]] group"
    );
    d.stop().await;
}

/// Final review I1: a `content_policy` identifier field bypassed alias
/// resolution and minted its own token for a variant instead of the
/// group's canonical. `sanitize_blocks`'s `FieldHint::Identifier` branch
/// now resolves to the canonical (`state.vault.aliases().canonical`)
/// before calling `token_for`, exactly like a `FreeText` block that goes
/// through the engine's `Aliased` wrap.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identifier_field_and_free_text_variant_share_one_token() {
    let (d, _dict) = daemon_with_aliases().await;
    d.dataset("crm").await;
    let s = Arc::clone(&d.state);
    let out = tokio::task::spawn_blocking(move || {
        sanitize_blocks(
            &s,
            "crm",
            None,
            vec![
                typed("HP Gruber", EntityKind::Person),
                BlockInput::text("Hans-Peter Gruber ruft an."),
            ],
        )
    })
    .await
    .unwrap()
    .unwrap();
    let identifier_token = out[0].text.clone();
    assert!(
        identifier_token.starts_with("<PERSON_"),
        "{identifier_token}"
    );
    let free_text_token = out[1].text.trim_end_matches(" ruft an.").to_string();
    assert_eq!(
        identifier_token, free_text_token,
        "the identifier field and the free-text variant share one token"
    );
    assert_eq!(
        d.state.vault.dataset("crm").unwrap().entries,
        1,
        "one stored entity, not two"
    );
    let (code, body) = d
        .call(
            Method::GET,
            "/v1/datasets/crm/entities?show_values=true",
            None,
        )
        .await;
    assert_eq!(code, 200, "{body}");
    let entities = body["entities"].as_array().unwrap();
    assert_eq!(entities.len(), 1, "{entities:?}");
    assert_eq!(
        entities[0]["original"], "Hans-Peter Gruber",
        "the stored row's original is the group's canonical, not the variant \
         minted through the identifier field"
    );
    d.stop().await;
}
