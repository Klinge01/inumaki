//! M5 spec §7.1: folder rows and the mirror manifest are sealed (no path in
//! the database file in clear), cascade with their dataset, and a second
//! folder for one dataset is refused. The entries generation moves on every
//! mint and forget, from any handle.

mod common;

use std::path::Path;

use inumaki_core::span::EntityKind as K;
use inumaki_core::token::TokenStore;
use inumaki_vault::{DatasetKind, DatasetSpec, KeySource, Vault, VaultError, VaultOptions};

const SOURCE: &str = "/Users/qwxzvk/Kunden/Zyxwuria Quolnath";
const REL: &[u8] = b"Quolnath GmbH/Angebot_Zyxwuria.txt";

fn open(dir: &Path) -> Vault {
    Vault::open(VaultOptions::in_dir(dir).with_key_source(KeySource::File)).unwrap()
}

fn folder_dataset(v: &Vault, id: &str) {
    let mut spec = DatasetSpec::new(id, "Qwxzvk Akten", "offline");
    spec.kind = DatasetKind::Folder;
    v.create_dataset(&spec).unwrap();
}

fn file_bytes(dir: &Path) -> Vec<u8> {
    let mut all = Vec::new();
    for name in ["vault.sqlite", "vault.sqlite-wal"] {
        if let Ok(b) = std::fs::read(dir.join(name)) {
            all.extend(b);
        }
    }
    all
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn folder_rows_and_manifest_are_sealed_and_cascade() {
    let dir = tempfile::tempdir().unwrap();
    let v = open(dir.path());
    folder_dataset(&v, "qwxzvk-akten");
    assert_eq!(v.dataset("qwxzvk-akten").unwrap().kind, DatasetKind::Folder);
    let config = format!("{{\"source\":\"{SOURCE}\"}}");
    v.create_folder("qwxzvk-akten", config.as_bytes()).unwrap();
    v.mirror_put(
        "qwxzvk-akten",
        "source",
        REL,
        b"{\"rel\":\"Quolnath GmbH/Angebot_Zyxwuria.txt\"}",
    )
    .unwrap();
    v.mirror_put(
        "qwxzvk-akten",
        "dir",
        b"Quolnath GmbH",
        b"{\"component\":\"<ORGANIZATION_a1b2c3>\"}",
    )
    .unwrap();
    assert_eq!(
        &**v.folder("qwxzvk-akten").unwrap().unwrap().0,
        config.as_bytes()
    );
    assert_eq!(v.mirror_list("qwxzvk-akten", "source").unwrap().len(), 1);
    v.checkpoint().unwrap();
    let bytes = file_bytes(dir.path());
    for needle in ["Zyxwuria", "Quolnath", "Kunden", "qwxzvk/"] {
        assert!(
            !contains(&bytes, needle.as_bytes()),
            "{needle} in the database file"
        );
    }
    assert!(matches!(
        v.create_folder("qwxzvk-akten", b"{}"),
        Err(VaultError::FolderExists)
    ));
    assert!(matches!(
        v.mirror_put("qwxzvk-akten", "other", REL, b"{}"),
        Err(VaultError::OutOfRange(_))
    ));
    // An unknown dataset fails closed.
    assert!(matches!(
        v.create_folder("nope", b"{}"),
        Err(VaultError::DatasetNotFound(_))
    ));
    assert!(matches!(
        v.mirror_put("nope", "source", REL, b"{}"),
        Err(VaultError::DatasetNotFound(_))
    ));
    v.delete_dataset("qwxzvk-akten").unwrap();
    assert!(v.folders().unwrap().is_empty());
    folder_dataset(&v, "qwxzvk-akten");
    assert!(
        v.mirror_list("qwxzvk-akten", "source").unwrap().is_empty(),
        "rows cascaded"
    );
}

#[test]
fn remove_folder_clears_the_manifest_and_keeps_the_dataset() {
    let dir = tempfile::tempdir().unwrap();
    let v = open(dir.path());
    folder_dataset(&v, "qwxzvk-akten");
    v.create_folder("qwxzvk-akten", b"{}").unwrap();
    v.mirror_put("qwxzvk-akten", "outbox", b"reply.txt", b"{}")
        .unwrap();
    assert!(v.remove_folder("qwxzvk-akten").unwrap());
    assert!(!v.remove_folder("qwxzvk-akten").unwrap());
    assert!(v.mirror_list("qwxzvk-akten", "outbox").unwrap().is_empty());
    assert!(v.dataset("qwxzvk-akten").is_ok());
}

#[test]
fn update_folder_config_replaces_sealed_and_never_creates() {
    let dir = tempfile::tempdir().unwrap();
    let v = open(dir.path());
    folder_dataset(&v, "qwxzvk-akten");
    // No folder row: nothing is written.
    assert!(!v.update_folder_config("qwxzvk-akten", b"{}").unwrap());
    assert!(v.folder("qwxzvk-akten").unwrap().is_none());
    assert!(!v.update_folder_config("nope", b"{}").unwrap());
    v.create_folder("qwxzvk-akten", b"{}").unwrap();
    v.mirror_put("qwxzvk-akten", "source", REL, b"{}").unwrap();
    let at = v.folder("qwxzvk-akten").unwrap().unwrap().1;
    let config = format!("{{\"source\":\"{SOURCE}\",\"root_id\":[1,2]}}");
    assert!(
        v.update_folder_config("qwxzvk-akten", config.as_bytes())
            .unwrap()
    );
    let (got, at2) = v.folder("qwxzvk-akten").unwrap().unwrap();
    assert_eq!(&**got, config.as_bytes());
    assert_eq!(at, at2, "creation time kept");
    assert_eq!(v.mirror_list("qwxzvk-akten", "source").unwrap().len(), 1);
    v.checkpoint().unwrap();
    let bytes = file_bytes(dir.path());
    for needle in ["Zyxwuria", "Kunden"] {
        assert!(!contains(&bytes, needle.as_bytes()), "{needle} in clear");
    }
}

#[test]
fn dataset_state_is_the_profile_and_the_open_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let v = open(dir.path());
    folder_dataset(&v, "qwxzvk-akten");
    let d = v.dataset("qwxzvk-akten").unwrap();
    assert_eq!(
        v.dataset_state("qwxzvk-akten").unwrap(),
        (d.profile.clone(), d.epoch_id)
    );
    let rot = v.rotate("qwxzvk-akten").unwrap();
    assert_eq!(v.dataset_state("qwxzvk-akten").unwrap().1, rot.new_epoch);
    assert!(matches!(
        v.dataset_state("nope"),
        Err(VaultError::DatasetNotFound(_))
    ));
}

#[test]
fn entries_generation_moves_on_mint_and_forget() {
    let dir = tempfile::tempdir().unwrap();
    let v = open(dir.path());
    folder_dataset(&v, "qwxzvk-akten");
    let g0 = v.entries_generation("qwxzvk-akten");
    let mut ns = v.namespace("qwxzvk-akten").unwrap();
    let token = ns.token_for(&K::Person, "Zyxwuria Quolnath").unwrap();
    let g1 = v.entries_generation("qwxzvk-akten");
    assert!(g1 > g0);
    let _ = ns.token_for(&K::Person, "Zyxwuria Quolnath").unwrap();
    assert_eq!(
        v.entries_generation("qwxzvk-akten"),
        g1,
        "a lookup is not a write"
    );
    v.forget_by_token("qwxzvk-akten", token.as_str()).unwrap();
    assert!(v.entries_generation("qwxzvk-akten") > g1);
    assert_eq!(v.entries_generation("other"), 0);
}

#[test]
fn entries_generation_moves_on_a_new_surface_form() {
    // Cross-lane (plan 4a surface rows): a new spelling of a known entity
    // is a write the mirror's tripwire must see; reusing one is not.
    let dir = tempfile::tempdir().unwrap();
    let v = open(dir.path());
    folder_dataset(&v, "qwxzvk-akten");
    let mut ns = v.namespace("qwxzvk-akten").unwrap();
    let full = ns.token_for(&K::Person, "Zyxwuria Quolnath").unwrap();
    let g1 = v.entries_generation("qwxzvk-akten");
    ns.surface_token(&full, "Quolnath, Zyxwuria").unwrap();
    let g2 = v.entries_generation("qwxzvk-akten");
    assert!(g2 > g1, "a minted surface form bumps the generation");
    ns.surface_token(&full, "Quolnath, Zyxwuria").unwrap();
    assert_eq!(
        v.entries_generation("qwxzvk-akten"),
        g2,
        "a reused surface form is not a write"
    );
}

#[test]
fn previous_epoch_known_returns_the_closed_epochs_originals() {
    // Review Cr2: the mirror carries these into the new epoch on rotation.
    let dir = tempfile::tempdir().unwrap();
    let v = open(dir.path());
    folder_dataset(&v, "qwxzvk-akten");
    assert!(
        v.previous_epoch_known("qwxzvk-akten").unwrap().is_empty(),
        "never rotated"
    );
    {
        let mut ns = v.namespace("qwxzvk-akten").unwrap();
        ns.token_for(&K::Person, "Zyxwuria Quolnath").unwrap();
    }
    v.rotate("qwxzvk-akten").unwrap();
    let prev = v.previous_epoch_known("qwxzvk-akten").unwrap();
    assert!(
        prev.iter()
            .any(|(k, o)| *k == K::Person && o.as_str() == "Zyxwuria Quolnath")
    );
    let ns = v.namespace("qwxzvk-akten").unwrap();
    assert_eq!(
        ns.known_entities(),
        0,
        "the new epoch starts empty: the carry is the mirror's job"
    );
}

#[test]
fn previous_epoch_known_skips_surface_rows() {
    // Cross-lane (plan 4a surface rows): the rotation carry registers
    // canonical entities only; a surface form (two words, so the one-part
    // filter would not drop it) must not come back as an entity of its own.
    let dir = tempfile::tempdir().unwrap();
    let v = open(dir.path());
    folder_dataset(&v, "qwxzvk-akten");
    {
        let mut ns = v.namespace("qwxzvk-akten").unwrap();
        let full = ns.token_for(&K::Person, "Zyxwuria Quolnath").unwrap();
        ns.surface_token(&full, "Quolnath, Zyxwuria").unwrap();
    }
    v.rotate("qwxzvk-akten").unwrap();
    let prev = v.previous_epoch_known("qwxzvk-akten").unwrap();
    let originals: Vec<&str> = prev.iter().map(|(_, o)| o.as_str()).collect();
    assert_eq!(originals, ["Zyxwuria Quolnath"], "canonical entities only");
}

#[test]
fn a_v5_file_migrates_and_the_folder_tables_work() {
    let dir = tempfile::tempdir().unwrap();
    let v = open(dir.path());
    folder_dataset(&v, "qwxzvk-akten");
    v.checkpoint().unwrap();
    drop(v);
    {
        let c = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
        // A v5 file has the mail tables and no folder tables.
        common::downgrade_to(&c, 5);
    }
    let v = open(dir.path());
    assert_eq!(
        v.dataset("qwxzvk-akten").unwrap().kind,
        DatasetKind::Folder,
        "existing rows survive"
    );
    assert!(v.folder("qwxzvk-akten").unwrap().is_none());
    v.create_folder("qwxzvk-akten", b"{\"source\":\"x\"}")
        .unwrap();
    v.mirror_put("qwxzvk-akten", "source", REL, b"{\"rel\":\"x\"}")
        .unwrap();
    assert!(v.folder("qwxzvk-akten").unwrap().is_some());
    drop(v);
    let c = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
    let version: String = c
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(version, inumaki_vault::SCHEMA_VERSION.to_string());
}
