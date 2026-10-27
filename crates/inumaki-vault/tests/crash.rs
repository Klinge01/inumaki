//! Spec §13 crash safety. The test re-runs itself as a child process that
//! opens a transaction on the vault file, inserts an entry row, and aborts
//! before committing. WAL must roll that back; rows committed before the
//! kill stay. (Every statement `Namespace` runs is a single autocommit
//! statement, so the multi-statement window simulated here is the one
//! `create_dataset` and `rotate` have.)

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use inumaki_core::span::EntityKind;
use inumaki_core::token::TokenStore;
use inumaki_vault::{DatasetSpec, KeySource, Vault, VaultOptions};
use rusqlite::params;

const CHILD_ENV: &str = "INUMAKI_VAULT_CRASH_CHILD";

fn opts(dir: &Path) -> VaultOptions {
    VaultOptions::in_dir(dir).with_key_source(KeySource::File)
}

fn child(dir: &Path) -> ! {
    let v = Vault::open(opts(dir)).unwrap();
    let ds = v.dataset("mail").unwrap();
    drop(v);
    let mut c = rusqlite::Connection::open(dir.join("vault.sqlite")).unwrap();
    c.busy_timeout(Duration::from_secs(5)).unwrap();
    let tx = c.transaction().unwrap();
    tx.execute(
        "INSERT INTO entries (epoch_id, kind, key_hmac, token, nonce, value, removed, last_used) \
         VALUES (?1, 'PERSON', x'ff', '<PERSON_dead01>', x'00', x'00', 0, 0)",
        params![ds.epoch_id],
    )
    .unwrap();
    std::process::abort();
}

#[test]
fn crash_between_insert_and_commit_leaves_vault_consistent() {
    if let Ok(dir) = std::env::var(CHILD_ENV) {
        child(Path::new(&dir));
    }
    let dir = tempfile::tempdir().unwrap();
    let v = Vault::open(opts(dir.path())).unwrap();
    v.create_dataset(&DatasetSpec::new("mail", "x", "offline"))
        .unwrap();
    let committed = v
        .namespace("mail")
        .unwrap()
        .token_for(&EntityKind::Person, "Sarah Leitner")
        .unwrap();
    drop(v);
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "crash_between_insert_and_commit_leaves_vault_consistent",
            "--nocapture",
        ])
        .env(CHILD_ENV, dir.path())
        .status()
        .unwrap();
    assert!(!status.success(), "the child must abort");
    let v = Vault::open(opts(dir.path())).unwrap();
    assert!(v.integrity_ok().unwrap());
    assert_eq!(
        v.dataset("mail").unwrap().entries,
        1,
        "uncommitted row rolled back"
    );
    let mut ns = v.namespace("mail").unwrap();
    assert_eq!(
        ns.token_for(&EntityKind::Person, "Sarah Leitner").unwrap(),
        committed
    );
    assert_eq!(ns.original("<PERSON_dead01>"), None);
}
