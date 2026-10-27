//! The mail schema version (M4 spec §4.4, §6.2): a mailbox row per mailbox
//! dataset with the username sealed like dataset names, and an encrypted
//! handle store whose handles are random, scoped to (dataset, mailbox),
//! stale after a UIDVALIDITY change, and gone with the mailbox.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use inumaki_vault::{
    Clock, DatasetKind, DatasetSpec, KeySource, MAIL_HANDLE_LEN, MailHandleKind, MailHandleRef,
    MailboxSpec, SCHEMA_VERSION, Vault, VaultError, VaultOptions, is_loopback_host, is_mail_handle,
    mail_password_secret, valid_preset,
};

mod common;

const CANARY_USER: &str = "zyxwuria.quolnath@example.test";
const CANARY_FOLDER: &str = "Kunde Zyxwuria Quolnath";

struct TestClock(AtomicI64);

impl Clock for TestClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn open(dir: &Path, clock: Arc<TestClock>) -> Vault {
    Vault::open_with_clock(
        VaultOptions::in_dir(dir).with_key_source(KeySource::File),
        clock,
    )
    .unwrap()
}

fn vault(dir: &Path) -> Vault {
    open(dir, Arc::new(TestClock(AtomicI64::new(1_000))))
}

fn tables(dir: &Path) -> Vec<String> {
    let c = rusqlite::Connection::open(dir.join("vault.sqlite")).unwrap();
    c.prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )
    .unwrap()
    .query_map([], |r| r.get(0))
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

/// The version that introduced the mailbox tables (plan 3).
const MAIL_SCHEMA_VERSION: u32 = 5;

fn version(dir: &Path) -> String {
    let c = rusqlite::Connection::open(dir.join("vault.sqlite")).unwrap();
    c.query_row(
        "SELECT value FROM meta WHERE key = 'schema_version'",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

fn mailbox_dataset(v: &Vault, id: &str) {
    let mut spec = DatasetSpec::new(id, "Mail", "offline");
    spec.kind = DatasetKind::Mailbox;
    v.create_dataset(&spec).unwrap();
}

fn spec(user: &str) -> MailboxSpec {
    MailboxSpec {
        preset: "generic".into(),
        imap_host: "imap.example.test".into(),
        imap_port: 993,
        imap_tls: true,
        username: user.into(),
        password_secret: mail_password_secret("mail"),
        drafts_folder: Some(CANARY_FOLDER.into()),
        from_address: Some(user.into()),
    }
}

fn assert_not_at_rest(dir: &Path, needles: &[&[u8]]) {
    let raw = std::fs::read(dir.join("vault.sqlite")).unwrap();
    for needle in needles {
        assert!(
            !raw.windows(needle.len()).any(|w| w == *needle),
            "{} readable at rest",
            String::from_utf8_lossy(needle)
        );
    }
}

#[test]
fn fresh_vault_has_the_mail_tables() {
    let dir = tempfile::tempdir().unwrap();
    drop(vault(dir.path()));
    let t = tables(dir.path());
    assert!(
        t.contains(&"mailboxes".to_string()) && t.contains(&"mail_handles".to_string()),
        "{t:?}"
    );
    assert_eq!(version(dir.path()), SCHEMA_VERSION.to_string());
}

#[test]
fn previous_version_file_migrates_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    mailbox_dataset(&v, "mail");
    v.checkpoint().unwrap();
    drop(v);
    {
        let c = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
        // A v4 file: the mail tables (v5), the surface column (v6) and the
        // folder tables (v7) are all created by the migration walk.
        common::downgrade_to(&c, MAIL_SCHEMA_VERSION - 1);
    }
    let v = vault(dir.path());
    assert!(v.mailbox("mail").unwrap().is_none());
    assert_eq!(
        v.dataset("mail").unwrap().kind,
        DatasetKind::Mailbox,
        "existing rows survive"
    );
    let fp = v
        .set_mailbox("mail", &spec(CANARY_USER))
        .unwrap()
        .fingerprint;
    assert!(
        v.mail_handle("mail", &fp, &MailHandleRef::folder("INBOX"))
            .is_ok(),
        "the migrated tables work"
    );
    drop(v);
    assert_eq!(version(dir.path()), SCHEMA_VERSION.to_string());
}

#[test]
fn mailbox_round_trips_sealed_and_replacement_drops_handles() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    mailbox_dataset(&v, "mail");
    assert!(v.mailbox("mail").unwrap().is_none());
    let m = v.set_mailbox("mail", &spec(CANARY_USER)).unwrap();
    assert_eq!(m.fingerprint.len(), 16);
    assert_eq!(
        m.fingerprint,
        v.mailbox_fingerprint("imap.example.test", 993, CANARY_USER)
    );
    let got = v.mailbox("mail").unwrap().unwrap();
    assert_eq!(got.spec, spec(CANARY_USER));
    assert_eq!(got.dataset_id, "mail");
    assert_eq!(got.created_at, 1_000);
    // handles minted for this mailbox
    let h = v
        .mail_handle(
            "mail",
            &m.fingerprint,
            &MailHandleRef::folder(CANARY_FOLDER),
        )
        .unwrap();
    assert!(
        v.resolve_mail_handle("mail", &m.fingerprint, &h)
            .unwrap()
            .is_some()
    );
    assert_eq!(v.mail_handle_count("mail").unwrap(), 1);
    // replacing the mailbox changes the fingerprint and drops every handle
    let m2 = v.set_mailbox("mail", &spec("other@example.test")).unwrap();
    assert_ne!(m2.fingerprint, m.fingerprint);
    assert_eq!(v.mail_handle_count("mail").unwrap(), 0);
    assert!(
        v.resolve_mail_handle("mail", &m2.fingerprint, &h)
            .unwrap()
            .is_none()
    );
    assert!(
        v.resolve_mail_handle("mail", &m.fingerprint, &h)
            .unwrap()
            .is_none(),
        "the old fingerprint does not revive it"
    );
    assert!(
        matches!(
            v.mail_handle("mail", &m.fingerprint, &MailHandleRef::folder("INBOX")),
            Err(VaultError::InvalidMailbox("fingerprint"))
        ),
        "a connector still running for the replaced mailbox cannot mint"
    );
    assert!(
        v.mail_handle("mail", &m2.fingerprint, &MailHandleRef::folder("INBOX"))
            .is_ok()
    );
    assert!(matches!(
        v.mail_handle(
            "other-without-mailbox",
            &m2.fingerprint,
            &MailHandleRef::folder("INBOX")
        ),
        Err(VaultError::MailboxNotFound)
    ));
    // nothing readable at rest
    v.checkpoint().unwrap();
    assert_not_at_rest(
        dir.path(),
        &[
            CANARY_USER.as_bytes(),
            b"other@example.test",
            CANARY_FOLDER.as_bytes(),
            b"Zyxwuria",
        ],
    );
    assert!(v.remove_mailbox("mail").unwrap());
    assert!(!v.remove_mailbox("mail").unwrap());
    assert!(v.mailbox("mail").unwrap().is_none());
    // validation and missing datasets
    assert!(matches!(
        v.set_mailbox("nope", &spec(CANARY_USER)),
        Err(VaultError::DatasetNotFound(_))
    ));
    let mut bad = spec(CANARY_USER);
    bad.preset = "exchange".into();
    assert!(matches!(
        v.set_mailbox("mail", &bad),
        Err(VaultError::InvalidMailbox("preset"))
    ));
    let mut bad = spec(CANARY_USER);
    bad.imap_port = 0;
    assert!(matches!(
        v.set_mailbox("mail", &bad),
        Err(VaultError::InvalidMailbox("imap_port"))
    ));
    let mut bad = spec(CANARY_USER);
    bad.imap_tls = false;
    assert!(
        matches!(
            v.set_mailbox("mail", &bad),
            Err(VaultError::InvalidMailbox("imap_tls"))
        ),
        "plaintext only on loopback"
    );
    bad.imap_host = "127.0.0.1".into();
    assert!(v.set_mailbox("mail", &bad).is_ok());
    let mut bad = spec(CANARY_USER);
    bad.username = "with\r\nnewline".into();
    assert!(matches!(
        v.set_mailbox("mail", &bad),
        Err(VaultError::InvalidMailbox("username"))
    ));
    let mut bad = spec(CANARY_USER);
    bad.username = String::new();
    assert!(matches!(
        v.set_mailbox("mail", &bad),
        Err(VaultError::InvalidMailbox("username"))
    ));
    let mut bad = spec(CANARY_USER);
    bad.password_secret = "Bad Name".into();
    assert!(matches!(
        v.set_mailbox("mail", &bad),
        Err(VaultError::InvalidSecretName)
    ));
    let mut bad = spec(CANARY_USER);
    bad.imap_host = "host with space".into();
    assert!(matches!(
        v.set_mailbox("mail", &bad),
        Err(VaultError::InvalidMailbox("imap_host"))
    ));
    assert!(
        valid_preset("gmail")
            && valid_preset("outlook")
            && valid_preset("generic")
            && !valid_preset("Gmail")
    );
    assert!(
        is_loopback_host("127.0.0.1")
            && is_loopback_host("::1")
            && is_loopback_host("LOCALHOST")
            && !is_loopback_host("imap.gmail.com")
    );
    // the app password's secrets-table name
    assert_eq!(mail_password_secret("mail-work"), "mail-work/mail/password");
    // deleting the dataset deletes the row (cascade)
    v.set_mailbox("mail", &spec(CANARY_USER)).unwrap();
    v.delete_dataset("mail").unwrap();
    let c = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
    let n: i64 = c
        .query_row("SELECT count(*) FROM mailboxes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0);
}

#[test]
fn handles_are_random_stable_scoped_and_stale_after_uidvalidity_changes() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    mailbox_dataset(&v, "mail");
    mailbox_dataset(&v, "other");
    let fp = v
        .set_mailbox("mail", &spec(CANARY_USER))
        .unwrap()
        .fingerprint;
    let fp2 = v
        .set_mailbox("other", &spec(CANARY_USER))
        .unwrap()
        .fingerprint;
    assert_eq!(
        fp, fp2,
        "same account, same fingerprint; the dataset id scopes the handles"
    );
    let folder = v
        .mail_handle("mail", &fp, &MailHandleRef::folder("INBOX"))
        .unwrap();
    assert_eq!(folder.len(), MAIL_HANDLE_LEN);
    assert!(
        folder.starts_with("mf_") && folder[3..].bytes().all(|b| b.is_ascii_lowercase()),
        "{folder}"
    );
    assert_eq!(is_mail_handle(&folder), Some(MailHandleKind::Folder));
    assert_eq!(
        v.mail_handle("mail", &fp, &MailHandleRef::folder("INBOX"))
            .unwrap(),
        folder,
        "stable for the same folder"
    );
    assert_ne!(
        v.mail_handle("other", &fp, &MailHandleRef::folder("INBOX"))
            .unwrap(),
        folder,
        "per dataset"
    );
    let msg = v
        .mail_handle(
            "mail",
            &fp,
            &MailHandleRef::message("INBOX", 1_790_000_000, 42),
        )
        .unwrap();
    assert!(
        msg.starts_with("mm_") && msg.len() == MAIL_HANDLE_LEN,
        "{msg}"
    );
    assert_eq!(is_mail_handle(&msg), Some(MailHandleKind::Message));
    assert_eq!(
        v.mail_handle(
            "mail",
            &fp,
            &MailHandleRef::message("INBOX", 1_790_000_000, 42)
        )
        .unwrap(),
        msg
    );
    let (kind, r) = v.resolve_mail_handle("mail", &fp, &msg).unwrap().unwrap();
    assert_eq!(kind, MailHandleKind::Message);
    assert_eq!(
        (r.folder.as_str(), r.uid_validity, r.uid),
        ("INBOX", 1_790_000_000, 42)
    );
    let (kind, r) = v
        .resolve_mail_handle("mail", &fp, &folder)
        .unwrap()
        .unwrap();
    assert_eq!((kind, r.folder.as_str()), (MailHandleKind::Folder, "INBOX"));
    assert!(v.mail_handle_known("mail", &fp, &msg).unwrap());
    // scope: another dataset, another fingerprint, a malformed string, a lookalike
    assert!(v.resolve_mail_handle("other", &fp, &msg).unwrap().is_none());
    assert!(!v.mail_handle_known("other", &fp, &msg).unwrap());
    assert!(
        v.resolve_mail_handle("mail", "0000000000000000", &msg)
            .unwrap()
            .is_none()
    );
    assert!(
        !v.mail_handle_known("mail", "0000000000000000", &msg)
            .unwrap()
    );
    let upper = format!("mm_{}", "A".repeat(16));
    let wrong_prefix = format!("mx_{}", "a".repeat(16));
    // 19 bytes with a multi-byte character across the prefix boundary
    let split_char = format!("mf\u{e9}{}", "a".repeat(15));
    assert_eq!(split_char.len(), MAIL_HANDLE_LEN);
    for bad in [
        "",
        "mm_",
        "mm_abc",
        &upper,
        &wrong_prefix,
        &split_char,
        "INBOX",
        CANARY_FOLDER,
    ] {
        assert!(is_mail_handle(bad).is_none(), "{bad:?}");
        assert!(
            v.resolve_mail_handle("mail", &fp, bad).unwrap().is_none(),
            "{bad:?}"
        );
        assert!(!v.mail_handle_known("mail", &fp, bad).unwrap());
    }
    let lookalike = format!("mm_{}", "a".repeat(16));
    assert!(
        v.resolve_mail_handle("mail", &fp, &lookalike)
            .unwrap()
            .is_none(),
        "shape is not provenance"
    );
    // UIDVALIDITY changed: message handles of the folder go, the folder handle stays
    let other_folder_msg = v
        .mail_handle("mail", &fp, &MailHandleRef::message("Sent", 5, 1))
        .unwrap();
    assert_eq!(v.invalidate_mail_folder("mail", &fp, "INBOX").unwrap(), 1);
    assert!(v.resolve_mail_handle("mail", &fp, &msg).unwrap().is_none());
    assert!(
        v.resolve_mail_handle("mail", &fp, &folder)
            .unwrap()
            .is_some()
    );
    assert!(
        v.resolve_mail_handle("mail", &fp, &other_folder_msg)
            .unwrap()
            .is_some()
    );
    // a new mint after the change is a different handle
    let again = v
        .mail_handle(
            "mail",
            &fp,
            &MailHandleRef::message("INBOX", 1_790_000_001, 42),
        )
        .unwrap();
    assert_ne!(again, msg);
    assert_eq!(v.mail_handle_count("mail").unwrap(), 3);
    // dataset deletion cascades
    v.delete_dataset("mail").unwrap();
    assert!(matches!(
        v.mail_handle_count("mail"),
        Err(VaultError::DatasetNotFound(_))
    ));
    assert_eq!(v.mail_handle_count("other").unwrap(), 1);
}

#[test]
fn handle_payloads_and_folder_names_are_sealed_at_rest() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    mailbox_dataset(&v, "mail");
    let fp = v
        .set_mailbox("mail", &spec(CANARY_USER))
        .unwrap()
        .fingerprint;
    let h = v
        .mail_handle("mail", &fp, &MailHandleRef::message(CANARY_FOLDER, 7, 9))
        .unwrap();
    v.checkpoint().unwrap();
    drop(v);
    assert_not_at_rest(
        dir.path(),
        &[CANARY_FOLDER.as_bytes(), b"Zyxwuria", b"\"f\":"],
    );
    let raw = std::fs::read(dir.path().join("vault.sqlite")).unwrap();
    assert!(
        raw.windows(h.len()).any(|w| w == h.as_bytes()),
        "the handle itself is the primary key and may be stored in clear"
    );
}

#[test]
fn mail_debug_impls_print_no_identities() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    mailbox_dataset(&v, "qwxzvk-canary-slug");
    let mut s = spec(CANARY_USER);
    s.password_secret = mail_password_secret("qwxzvk-canary-slug");
    let m = v.set_mailbox("qwxzvk-canary-slug", &s).unwrap();
    let r = MailHandleRef::message(CANARY_FOLDER, 1, 2);
    let d = format!(
        "{s:?} {m:?} {r:?} {:?}",
        v.mailbox("qwxzvk-canary-slug").unwrap()
    );
    assert!(
        !d.contains("zyxwuria")
            && !d.contains("Zyxwuria")
            && !d.contains("Quolnath")
            && !d.contains("qwxzvk"),
        "{d}"
    );
    assert!(
        d.contains("imap.example.test"),
        "host is configuration, shown"
    );
}

#[test]
fn fingerprint_input_is_length_prefixed() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    // `h:1` port 2 user `u` and `h` port 1 user `2:u` joined with `:` alone
    // are the same string; the length prefixes keep them apart.
    let a = v.mailbox_fingerprint("h:1", 2, "u");
    let b = v.mailbox_fingerprint("h", 1, "2:u");
    assert_ne!(a, b);
    assert_eq!(a.len(), 16);
    assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(a, v.mailbox_fingerprint("h:1", 2, "u"), "stable");
}
