//! Surface-form rows (plan 4a, the schema version after the egress journal).
//! A surface form of an entity is a row of its own with `surface_of` set,
//! restores to exactly the text that was replaced, shares the parent's
//! suffix in `derived` mode, is invisible to the known-entity detector, is
//! counted (not listed) by `entities`, and is forgotten with its parent.
//! Rows written before the migration keep rehydrating.

mod common;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use inumaki_core::detect::DetectCtx;
use inumaki_core::rehydrate::Rehydrator;
use inumaki_core::span::EntityKind as K;
use inumaki_core::token::{StoreError, Token, TokenStore, parse_token};
use inumaki_vault::{Clock, DatasetSpec, KeySource, SCHEMA_VERSION, Vault, VaultOptions};
use rusqlite::Connection;

fn opts(dir: &Path) -> VaultOptions {
    VaultOptions::in_dir(dir).with_key_source(KeySource::File)
}

fn vault(dir: &Path) -> Vault {
    let v = Vault::open(opts(dir)).unwrap();
    v.create_dataset(&DatasetSpec::new("mail", "x", "offline"))
        .unwrap();
    v
}

fn schema_version(dir: &Path) -> String {
    let conn = Connection::open(dir.join("vault.sqlite")).unwrap();
    conn.query_row(
        "SELECT value FROM meta WHERE key = 'schema_version'",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

#[test]
fn fresh_vault_has_the_surface_column_and_index() {
    let dir = tempfile::tempdir().unwrap();
    let _v = vault(dir.path());
    assert_eq!(schema_version(dir.path()), SCHEMA_VERSION.to_string());
    let conn = Connection::open(dir.path().join("vault.sqlite")).unwrap();
    let cols: Vec<String> = conn
        .prepare("PRAGMA table_info(entries)")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(cols.contains(&"surface_of".to_string()), "{cols:?}");
    let idx: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'entries_surface_of'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(idx, 1);
}

/// Review Focus 3: rows from before the migration are untouched by it and
/// keep rehydrating next to new surface rows.
#[test]
fn rows_from_before_the_migration_keep_rehydrating() {
    let dir = tempfile::tempdir().unwrap();
    let full = {
        let v = vault(dir.path());
        let mut ns = v.namespace("mail").unwrap();
        ns.token_for(&K::Person, "Hans-Peter Gruber").unwrap()
    };
    // Rewind the file to v5 (before the surface column and the folder tables).
    {
        let conn = Connection::open(dir.path().join("vault.sqlite")).unwrap();
        common::downgrade_to(&conn, 5);
    }
    let v = Vault::open(opts(dir.path())).unwrap();
    let mut ns = v.namespace("mail").unwrap();
    assert_eq!(
        ns.token_for(&K::Person, "Hans-Peter Gruber").unwrap(),
        full,
        "the pre-migration row is the entity"
    );
    let nick = ns.surface_token(&full, "Hansi").unwrap();
    let r = Rehydrator::new(ns.settings());
    let text = format!("{} und {}", full.as_str(), nick.as_str());
    assert_eq!(
        r.rehydrate_strict(&text, &mut ns).unwrap(),
        "Hans-Peter Gruber und Hansi"
    );
    assert_eq!(schema_version(dir.path()), SCHEMA_VERSION.to_string());
}

/// A surface form restores to exactly its own text (R9: the key is the text
/// as written, so `SARAH` and `Sarah` are rows of their own), shares the
/// parent's suffix, is reused, and is loaded back after a reopen.
#[test]
fn surface_tokens_restore_the_exact_text_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    let (full, first, last, upper) = {
        let mut ns = v.namespace("mail").unwrap();
        let full = ns.token_for(&K::Person, "Sarah Leitner").unwrap();
        let first = ns.surface_token(&full, "Sarah").unwrap();
        let last = ns.surface_token(&full, "Leitner").unwrap();
        let upper = ns.surface_token(&full, "SARAH").unwrap();
        assert_eq!(
            ns.surface_token(&full, "Sarah").unwrap(),
            first,
            "same text, same row"
        );
        assert_ne!(upper, first, "another casing is a row of its own");
        let pf = parse_token(ns.settings(), full.as_str()).unwrap();
        for t in [&first, &last, &upper] {
            let p = parse_token(ns.settings(), t.as_str()).unwrap();
            assert_eq!(p.suffix, pf.suffix);
            assert!(p.variant.is_some());
        }
        assert_eq!(ns.original(first.as_str()), Some("Sarah"));
        assert_eq!(ns.original(upper.as_str()), Some("SARAH"));
        assert_eq!(ns.original(full.as_str()), Some("Sarah Leitner"));
        assert_eq!(ns.mints(), 1, "surface rows are not entity mints");
        (full, first, last, upper)
    };
    let mut ns = v.namespace("mail").unwrap();
    let r = Rehydrator::new(ns.settings());
    let text = format!(
        "{} / {} / {} / {}",
        full.as_str(),
        first.as_str(),
        last.as_str(),
        upper.as_str()
    );
    assert_eq!(
        r.rehydrate_strict(&text, &mut ns).unwrap(),
        "Sarah Leitner / Sarah / Leitner / SARAH"
    );
    assert_eq!(
        ns.surface_token(&full, "SARAH").unwrap(),
        upper,
        "found in the store after reopen"
    );
    // the same surface text under a different parent is a different row
    let other = ns.token_for(&K::Person, "Sarah Gruber").unwrap();
    let other_first = ns.surface_token(&other, "Sarah").unwrap();
    assert_ne!(other_first, first);
    assert_eq!(ns.original(other_first.as_str()), Some("Sarah"));
    // unknown or surface parents are refused
    assert_eq!(
        ns.surface_token(&Token::from("<PERSON_000000>".to_string()), "x"),
        Err(StoreError::UnknownParent)
    );
    assert_eq!(
        ns.surface_token(&first, "x"),
        Err(StoreError::UnknownParent),
        "a surface row is not a parent"
    );
    // peek never mints
    assert_eq!(
        ns.peek_surface_token(full.as_str(), "Sarah").unwrap(),
        Some(first.clone())
    );
    assert_eq!(
        ns.peek_surface_token(full.as_str(), "Sarahchen").unwrap(),
        None
    );
    assert_eq!(
        ns.peek_surface_token(full.as_str(), "Sarahchen").unwrap(),
        None,
        "still none"
    );
    // listed with the entity, not as entities of their own
    let listed = v.entities("mail", 0, false).unwrap();
    assert_eq!(listed.len(), 2, "two entities, no surface rows");
    let leitner = listed.iter().find(|e| e.token == full.as_str()).unwrap();
    assert_eq!(leitner.surface_forms, 3);
}

/// Review Focus 6: forgetting the entity forgets its surface forms.
#[test]
fn forget_removes_surface_rows() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    let (full, first) = {
        let mut ns = v.namespace("mail").unwrap();
        let full = ns.token_for(&K::Person, "Sarah Leitner").unwrap();
        (full.clone(), ns.surface_token(&full, "Sarah").unwrap())
    };
    // a handle that already holds both rows in its working set
    let mut live = v.namespace("mail").unwrap();
    live.prepare(&[full.as_str().to_string(), first.as_str().to_string()])
        .unwrap();
    let f = v.forget_by_token("mail", full.as_str()).unwrap();
    assert_eq!(f.rows, 2, "parent and surface row");
    assert!(
        f.tokens.iter().any(|t| t == first.as_str()),
        "the child is listed"
    );
    live.forget_tokens(&f.tokens).unwrap();
    assert_eq!(
        live.original(first.as_str()),
        None,
        "evicted from the working set too"
    );
    let mut ns = v.namespace("mail").unwrap();
    let r = Rehydrator::new(ns.settings());
    let err = r.rehydrate_strict(first.as_str(), &mut ns).unwrap_err();
    assert!(
        matches!(
            err,
            inumaki_core::rehydrate::RehydrateError::Unresolved { unknown: 1, .. }
        ),
        "{err:?}"
    );
    let again = ns.token_for(&K::Person, "Sarah Leitner").unwrap();
    assert_ne!(again, full);
}

/// Review Focus 9: a one-part PERSON entity is stored and restores, but is
/// never a known entity, so it cannot outrank NER on the next document or
/// trip the tripwire. Surface rows are never known entities either.
#[test]
fn bare_own_entity_names_never_become_known_entities() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    let sarah = {
        let mut ns = v.namespace("mail").unwrap();
        let sarah = ns.token_for(&K::Person, "Sarah").unwrap();
        let full = ns.token_for(&K::Person, "Sarah Leitner").unwrap();
        ns.surface_token(&full, "Leitner").unwrap();
        assert_eq!(
            ns.known_entities(),
            1,
            "neither the bare name nor a surface row is pushed into the delta"
        );
        sarah
    };
    let mut ns = v.namespace("mail").unwrap();
    assert_eq!(
        ns.known_entities(),
        1,
        "nor loaded into the main automaton after reopen"
    );
    let d = ns.detector();
    let text = "Sarah Gruber schreibt; Frau Leitner auch";
    let hits: Vec<String> = d
        .detect(text, &DetectCtx::for_text(text))
        .unwrap()
        .into_iter()
        .map(|s| s.slice(text).to_string())
        .collect();
    assert_eq!(
        hits,
        vec!["Leitner".to_string()],
        "no full-match hit on the bare Sarah"
    );
    // the bare entity still restores and is still found by value
    let r = Rehydrator::new(ns.settings());
    assert_eq!(
        r.rehydrate_strict(sarah.as_str(), &mut ns).unwrap(),
        "Sarah"
    );
    assert_eq!(ns.token_for(&K::Person, "sarah").unwrap(), sarah);
}

struct TestClock(AtomicI64);

impl Clock for TestClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// The linker's candidates are recent, current-epoch, canonical entities
/// that sanitization (not rehydration) touched. A closed-epoch parent is
/// refused as a surface parent (fail closed).
#[test]
fn link_candidates_are_recent_current_epoch_canonical_persons() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    let mut ns = v.namespace("mail").unwrap();
    let full = ns.token_for(&K::Person, "Sarah Leitner").unwrap();
    ns.surface_token(&full, "Sarah").unwrap();
    ns.token_for(&K::Organization, "Leitner Bau").unwrap();
    let window = Duration::from_secs(1800);
    let names: Vec<String> = ns
        .link_candidates(&K::Person, window)
        .iter()
        .map(|z| z.to_string())
        .collect();
    assert_eq!(
        names,
        vec!["Sarah Leitner".to_string()],
        "no surface rows, no other kinds"
    );
    // an entity another handle minted, loaded here only for rehydration, is not a recent mention
    let mut other = v.namespace("mail").unwrap();
    other.prepare(&[full.as_str().to_string()]).unwrap();
    assert_eq!(other.original(full.as_str()), Some("Sarah Leitner"));
    assert!(other.link_candidates(&K::Person, window).is_empty());
    // until sanitization uses it
    other.token_for(&K::Person, "Sarah Leitner").unwrap();
    assert_eq!(other.link_candidates(&K::Person, window).len(), 1);
    // after rotation the old entity is gone from the candidates
    v.rotate("mail").unwrap();
    ns.refresh().unwrap();
    assert!(ns.link_candidates(&K::Person, window).is_empty());
    // a rehydration-only entry (loaded from the closed epoch) is not a candidate either
    ns.prepare(&[full.as_str().to_string()]).unwrap();
    assert_eq!(ns.original(full.as_str()), Some("Sarah Leitner"));
    assert!(ns.link_candidates(&K::Person, window).is_empty());
    assert_eq!(
        ns.surface_token(&full, "Sarah"),
        Err(StoreError::UnknownParent),
        "a closed-epoch parent is refused"
    );
    let orphans: i64 = Connection::open(dir.path().join("vault.sqlite"))
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM entries WHERE surface_of IS NOT NULL AND epoch_id = ?1",
            [ns.epoch_id()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(orphans, 0, "nothing was minted for the refused parent");
}

/// A parent forgotten through the vault while a handle still holds it in its
/// working set must not get a child: the surface text would be re-stored
/// after the user forgot the entity.
#[test]
fn surface_token_for_a_forgotten_parent_stores_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    let mut ns = v.namespace("mail").unwrap();
    let full = ns.token_for(&K::Person, "Sarah Leitner").unwrap();
    assert_eq!(ns.original(full.as_str()), Some("Sarah Leitner"));
    v.forget_by_token("mail", full.as_str()).unwrap();
    assert_eq!(
        ns.surface_token(&full, "Sarah"),
        Err(StoreError::UnknownParent)
    );
    assert_eq!(
        ns.original(full.as_str()),
        None,
        "the stale parent is dropped from the handle"
    );
    let rows: i64 = Connection::open(dir.path().join("vault.sqlite"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM entries", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 0, "no orphan row re-stores the forgotten text");
}

/// One-part PERSON rows must not take the automaton's slots: the cap applies
/// to known entities, not to rows.
#[test]
fn bare_person_rows_do_not_take_automaton_slots() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TestClock(AtomicI64::new(100)));
    let mut o = opts(dir.path());
    o.automaton_max_entries = 1;
    let v = Vault::open_with_clock(o, clock.clone()).unwrap();
    v.create_dataset(&DatasetSpec::new("mail", "x", "offline"))
        .unwrap();
    {
        let mut ns = v.namespace("mail").unwrap();
        ns.token_for(&K::Person, "Sarah Leitner").unwrap();
        clock.0.store(200, Ordering::SeqCst);
        for bare in ["Anna", "Bert", "Carl"] {
            ns.token_for(&K::Person, bare).unwrap();
        }
    }
    let ns = v.namespace("mail").unwrap();
    assert_eq!(
        ns.known_entities(),
        1,
        "the newer bare names did not take the only slot"
    );
    let text = "Frau Leitner kommt";
    let hits = ns
        .detector()
        .detect(text, &DetectCtx::for_text(text))
        .unwrap();
    assert_eq!(hits.len(), 1);
}
