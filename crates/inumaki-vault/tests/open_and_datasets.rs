use std::path::Path;
use std::sync::{Arc, Mutex};

use inumaki_vault::{
    DatasetSpec, KeySource, KeyStore, Keys, SCHEMA_VERSION, Vault, VaultError, VaultOptions,
};

fn opts(dir: &Path) -> VaultOptions {
    VaultOptions::in_dir(dir).with_key_source(KeySource::File)
}

struct MemStore(Mutex<Option<Vec<u8>>>);
impl KeyStore for MemStore {
    fn load(&self) -> Result<Option<Keys>, VaultError> {
        Ok(self.0.lock().unwrap().as_deref().and_then(Keys::from_bytes))
    }
    fn store(&self, keys: &Keys) -> Result<(), VaultError> {
        *self.0.lock().unwrap() = Some(keys.to_bytes().to_vec());
        Ok(())
    }
}

fn pragma(dir: &Path, name: &str) -> String {
    let c = rusqlite::Connection::open(dir.join("vault.sqlite")).unwrap();
    c.query_row(&format!("PRAGMA {name}"), [], |r| {
        r.get::<_, rusqlite::types::Value>(0)
    })
    .map(|v| format!("{v:?}"))
    .unwrap()
}

#[test]
fn open_creates_schema_with_the_required_pragmas() {
    let dir = tempfile::tempdir().unwrap();
    let v = Vault::open(opts(dir.path())).unwrap();
    assert_eq!(v.key_source(), "file");
    assert!(v.integrity_ok().unwrap());
    assert_eq!(v.tokens().suffix_len, 6);
    drop(v);
    assert!(
        pragma(dir.path(), "journal_mode")
            .to_lowercase()
            .contains("wal")
    );
    assert!(
        pragma(dir.path(), "auto_vacuum").contains('2'),
        "incremental"
    );
    let c = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
    let tables: Vec<String> = c
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        tables,
        [
            "activity",
            "datasets",
            "entries",
            "epochs",
            "folders",
            "gateway_tokens",
            "journal",
            "mail_handles",
            "mailboxes",
            "meta",
            "mirror_files",
            "secrets",
            "upstreams"
        ]
    );
    let ver: String = c
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(ver, SCHEMA_VERSION.to_string());
}

#[test]
fn reopen_with_the_same_keys_works_and_wrong_keys_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let v = Vault::open(opts(dir.path())).unwrap();
    v.create_dataset(&DatasetSpec::new(
        "mail",
        "Musterkunde GmbH",
        "support-email",
    ))
    .unwrap();
    drop(v);
    let v = Vault::open(opts(dir.path())).unwrap();
    assert_eq!(v.datasets().unwrap().len(), 1);
    drop(v);
    // swap the key file for random keys
    let other = Keys::generate().unwrap();
    std::fs::write(dir.path().join("vault.key"), *other.to_bytes()).unwrap();
    let e = Vault::open(opts(dir.path())).unwrap_err();
    assert!(matches!(e, VaultError::WrongKeys), "{e}");
}

#[test]
fn key_source_is_pinned_in_meta() {
    let dir = tempfile::tempdir().unwrap();
    drop(Vault::open(opts(dir.path())).unwrap());
    let mem: Arc<dyn KeyStore> = Arc::new(MemStore(Mutex::new(None)));
    let e = Vault::open(
        VaultOptions::in_dir(dir.path())
            .with_key_source(KeySource::Keyring)
            .with_key_store(Arc::clone(&mem)),
    )
    .unwrap_err();
    assert!(matches!(e, VaultError::KeySourceChanged { .. }), "{e}");
    // auto follows the stored source
    let v = Vault::open(
        VaultOptions::in_dir(dir.path())
            .with_key_source(KeySource::Auto)
            .with_key_store(mem),
    )
    .unwrap();
    assert_eq!(v.key_source(), "file");
}

#[test]
fn schema_newer_than_the_binary_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    drop(Vault::open(opts(dir.path())).unwrap());
    let c = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
    c.execute(
        "UPDATE meta SET value = '99' WHERE key = 'schema_version'",
        [],
    )
    .unwrap();
    drop(c);
    let e = Vault::open(opts(dir.path())).unwrap_err();
    assert!(
        matches!(
            e,
            VaultError::SchemaNewer {
                found: 99,
                supported: SCHEMA_VERSION
            }
        ),
        "{e}"
    );
}

#[test]
fn dataset_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let v = Vault::open(opts(dir.path())).unwrap();
    assert!(v.datasets().unwrap().is_empty());
    let d = v
        .create_dataset(&DatasetSpec::new(
            "mail-2026",
            "Musterkunde GmbH",
            "support-email",
        ))
        .unwrap();
    assert_eq!(d.id, "mail-2026");
    assert_eq!(d.name, "Musterkunde GmbH");
    assert_eq!(d.profile, "support-email");
    assert_eq!((d.rotation_days, d.grace_days), (30, 7));
    assert_eq!(d.entries, 0);
    assert!(d.epoch_id > 0);
    assert!(d.epoch_started_at > 0);
    let listed = v.datasets().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, "mail-2026");
    assert_eq!(v.dataset("mail-2026").unwrap().name, "Musterkunde GmbH");
    assert_eq!(v.dataset_profile("mail-2026").unwrap(), "support-email");
    assert!(matches!(
        v.dataset_profile("nope"),
        Err(VaultError::DatasetNotFound(_))
    ));
    let e = v
        .create_dataset(&DatasetSpec::new("mail-2026", "again", "offline"))
        .unwrap_err();
    assert!(
        matches!(e, VaultError::DatasetExists(ref id) if id == "mail-2026"),
        "{e}"
    );
    v.delete_dataset("mail-2026").unwrap();
    assert!(v.datasets().unwrap().is_empty());
    assert!(matches!(
        v.dataset("mail-2026"),
        Err(VaultError::DatasetNotFound(_))
    ));
    assert!(matches!(
        v.delete_dataset("mail-2026"),
        Err(VaultError::DatasetNotFound(_))
    ));
}

#[test]
fn dataset_ids_and_ranges_are_validated() {
    let dir = tempfile::tempdir().unwrap();
    let v = Vault::open(opts(dir.path())).unwrap();
    for bad in ["", "Mail", "mail 1", "mail_1", &"a".repeat(65)] {
        let e = v
            .create_dataset(&DatasetSpec::new(bad, "x", "offline"))
            .unwrap_err();
        assert!(matches!(e, VaultError::InvalidDatasetId), "{bad:?}: {e}");
    }
    let mut s = DatasetSpec::new("ok-1", "x", "offline");
    s.rotation_days = 0;
    assert!(matches!(
        v.create_dataset(&s).unwrap_err(),
        VaultError::OutOfRange("rotation_days")
    ));
    s.rotation_days = 366;
    assert!(matches!(
        v.create_dataset(&s).unwrap_err(),
        VaultError::OutOfRange("rotation_days")
    ));
    s.rotation_days = 1;
    s.grace_days = 91;
    assert!(matches!(
        v.create_dataset(&s).unwrap_err(),
        VaultError::OutOfRange("grace_days")
    ));
    s.grace_days = 0;
    v.create_dataset(&s).unwrap();
    assert!(inumaki_vault::valid_dataset_id("a-b-9"));
    assert!(!inumaki_vault::valid_dataset_id("A"));
}

#[test]
fn dataset_name_is_encrypted_at_rest() {
    let dir = tempfile::tempdir().unwrap();
    let v = Vault::open(opts(dir.path())).unwrap();
    v.create_dataset(&DatasetSpec::new(
        "mail",
        "Musterkunde GmbH",
        "support-email",
    ))
    .unwrap();
    v.checkpoint().unwrap();
    let bytes = std::fs::read(dir.path().join("vault.sqlite")).unwrap();
    let needle = b"Musterkunde";
    assert!(
        !bytes.windows(needle.len()).any(|w| w == needle),
        "display name stored in clear"
    );
    let d = format!("{:?}", v.dataset("mail").unwrap());
    assert!(!d.contains("Musterkunde"), "{d}");
    assert!(d.contains("mail"));
}

/// Review I5: the keyring item is named from `meta.vault_id`, a random id
/// generated once and stored in plaintext meta, not from a hash of the data
/// directory path. This test uses the file key source (no real OS secret
/// store in CI), but it exercises the property the fix depends on: moving
/// the data directory must not change `vault_id`, and the vault must still
/// open at the new path.
#[test]
fn vault_id_is_stable_and_the_vault_survives_moving_the_data_directory() {
    let root = tempfile::tempdir().unwrap();
    let before = root.path().join("before");
    std::fs::create_dir_all(&before).unwrap();
    let v = Vault::open(opts(&before)).unwrap();
    v.create_dataset(&DatasetSpec::new("mail", "Musterkunde GmbH", "offline"))
        .unwrap();
    v.checkpoint().unwrap();
    drop(v);

    let id_before = {
        let c = rusqlite::Connection::open(before.join("vault.sqlite")).unwrap();
        inumaki_vault::schema::meta_get(&c, "vault_id")
            .unwrap()
            .unwrap()
    };
    assert_eq!(id_before.len(), 32, "16 random bytes as hex: {id_before}");

    let after = root.path().join("after");
    std::fs::rename(&before, &after).unwrap();

    // Same key file, a different path: the vault still opens.
    let v = Vault::open(opts(&after)).unwrap();
    assert_eq!(v.datasets().unwrap().len(), 1);
    drop(v);

    let id_after = {
        let c = rusqlite::Connection::open(after.join("vault.sqlite")).unwrap();
        inumaki_vault::schema::meta_get(&c, "vault_id")
            .unwrap()
            .unwrap()
    };
    assert_eq!(
        id_before, id_after,
        "vault_id is tied to the vault, not its path"
    );
}

#[test]
fn errors_name_ids_only() {
    // `DatasetNotFound`'s Display never carries the (user-chosen) dataset
    // slug (Task 9 / M4 spec §5.4): the slug would otherwise reach logs
    // through every `error = %e` site that formats a `VaultError`.
    let e = VaultError::DatasetNotFound("mail".into());
    assert_eq!(e.to_string(), "dataset not found");
    assert!(!e.to_string().contains("mail"));
    let e = VaultError::KeySourceChanged {
        stored: "file".into(),
        requested: "keyring".into(),
    };
    assert!(e.to_string().contains("file") && e.to_string().contains("keyring"));
}

#[test]
fn opaque_id_is_stable_hex_and_not_the_slug() {
    let dir = tempfile::tempdir().unwrap();
    let v = Vault::open(opts(dir.path())).unwrap();
    let a = v.opaque_id("qwxzvk-canary-slug");
    assert_eq!(a.len(), 16);
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(a, v.opaque_id("qwxzvk-canary-slug"));
    assert_ne!(a, v.opaque_id("other"));
    assert!(!a.contains("qwxzvk"));
}
