//! Schema v2 (M4 spec §4): migration from v1, dataset kinds, secrets,
//! gateway tokens, upstreams with content policy. Nothing readable at
//! rest, nothing in Debug.

use std::path::Path;

use inumaki_core::span::EntityKind as K;
use inumaki_core::token::TokenStore;
use inumaki_vault::{
    DatasetKind, DatasetSpec, KeySource, SCHEMA_VERSION, TOKEN_PREFIX, UpstreamKind, UpstreamSpec,
    Vault, VaultError, VaultOptions, valid_secret_name, valid_upstream_name,
};

const CANARY: &str = "Zyxwuria Quolnath";

fn opts(dir: &Path) -> VaultOptions {
    VaultOptions::in_dir(dir).with_key_source(KeySource::File)
}

fn vault(dir: &Path) -> Vault {
    Vault::open(opts(dir)).unwrap()
}

fn tables(dir: &Path) -> Vec<String> {
    let c = rusqlite::Connection::open(dir.join("vault.sqlite")).unwrap();
    c.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn raw_bytes(dir: &Path) -> Vec<u8> {
    std::fs::read(dir.join("vault.sqlite")).unwrap()
}

/// The exact v1 schema (`schema.rs` before this task) so a v1 file can be
/// built without the current code.
const V1_SCHEMA: &str = "
CREATE TABLE datasets (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  profile       TEXT NOT NULL,
  rotation_days INTEGER NOT NULL DEFAULT 30,
  grace_days    INTEGER NOT NULL DEFAULT 7,
  created_at    INTEGER NOT NULL
);
CREATE TABLE epochs (
  id          INTEGER PRIMARY KEY,
  dataset_id  TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
  started_at  INTEGER NOT NULL,
  closed_at   INTEGER,
  expires_at  INTEGER
);
CREATE INDEX epochs_dataset ON epochs(dataset_id, closed_at);
CREATE TABLE entries (
  epoch_id    INTEGER NOT NULL REFERENCES epochs(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,
  key_hmac    BLOB NOT NULL,
  token       TEXT NOT NULL,
  nonce       BLOB NOT NULL,
  value       BLOB NOT NULL,
  removed     INTEGER NOT NULL DEFAULT 0,
  last_used   INTEGER NOT NULL,
  PRIMARY KEY (epoch_id, kind, key_hmac)
);
CREATE UNIQUE INDEX entries_token ON entries(token);
CREATE INDEX entries_epoch_used ON entries(epoch_id, last_used);
CREATE TABLE secrets (
  name  TEXT PRIMARY KEY,
  nonce BLOB NOT NULL,
  value BLOB NOT NULL
);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
";

#[test]
fn fresh_vault_has_the_v2_tables_and_version() {
    let dir = tempfile::tempdir().unwrap();
    drop(vault(dir.path()));
    assert_eq!(
        tables(dir.path()),
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
    let c = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
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
fn v1_file_is_migrated_in_place_and_keeps_its_datasets() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    v.create_dataset(&DatasetSpec::new("mail", "Musterkunde", "offline"))
        .unwrap();
    drop(v);
    let path = dir.path().join("vault.sqlite");
    let meta: Vec<(String, String)> = {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.prepare("SELECT key, value FROM meta")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    let datasets: Vec<(String, String, String, i64)> = {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.prepare("SELECT id, name, profile, created_at FROM datasets")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    std::fs::remove_file(&path).unwrap();
    let _ = std::fs::remove_file(dir.path().join("vault.sqlite-wal"));
    let _ = std::fs::remove_file(dir.path().join("vault.sqlite-shm"));
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch("PRAGMA auto_vacuum = INCREMENTAL;")
            .unwrap();
        c.execute_batch(V1_SCHEMA).unwrap();
        for (k, val) in &meta {
            let val = if k == "schema_version" {
                "1"
            } else {
                val.as_str()
            };
            c.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)",
                rusqlite::params![k, val],
            )
            .unwrap();
        }
        for (id, name, profile, created) in &datasets {
            c.execute(
                "INSERT INTO datasets (id, name, profile, created_at) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![id, name, profile, created],
            )
            .unwrap();
            c.execute(
                "INSERT INTO epochs (dataset_id, started_at) VALUES (?1, ?2)",
                rusqlite::params![id, created],
            )
            .unwrap();
        }
    }
    let v = vault(dir.path());
    let d = v.dataset("mail").unwrap();
    assert_eq!(d.name, "Musterkunde", "the v1 name still decrypts");
    assert_eq!(d.kind, DatasetKind::Generic);
    assert!(v.upstreams("mail").unwrap().is_empty());
    assert!(v.gateway_tokens().unwrap().is_empty());
    drop(v);
    assert!(tables(dir.path()).contains(&"gateway_tokens".to_string()));
    let c = rusqlite::Connection::open(&path).unwrap();
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
fn dataset_kind_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    let mut spec = DatasetSpec::new("mail-work", "Work", "support-email");
    spec.kind = DatasetKind::Mailbox;
    assert_eq!(v.create_dataset(&spec).unwrap().kind, DatasetKind::Mailbox);
    assert_eq!(
        v.create_dataset(&DatasetSpec::new("crm", "CRM", "strict"))
            .unwrap()
            .kind,
        DatasetKind::Generic
    );
    assert_eq!(DatasetKind::parse("mailbox"), Some(DatasetKind::Mailbox));
    assert_eq!(DatasetKind::parse("Mailbox"), None);
    assert_eq!(DatasetKind::Mailbox.as_str(), "mailbox");
    assert_eq!(
        v.datasets()
            .unwrap()
            .iter()
            .find(|d| d.id == "mail-work")
            .unwrap()
            .kind,
        DatasetKind::Mailbox
    );
}

#[test]
fn secrets_round_trip_are_sealed_at_rest_and_listed_by_name_only() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    assert!(
        v.get_secret("crm/upstream/crm/env").unwrap().is_none(),
        "missing is Ok(None)"
    );
    v.put_secret("crm/upstream/crm/env", b"{\"API_KEY\":\"hunter2-canary\"}")
        .unwrap();
    v.put_secret(
        "crm/upstream/wiki/headers",
        b"{\"Authorization\":\"Bearer hunter2-canary\"}",
    )
    .unwrap();
    let got = v.get_secret("crm/upstream/crm/env").unwrap().unwrap();
    assert!(got.starts_with(b"{\"API_KEY\""));
    v.put_secret("crm/upstream/crm/env", b"{}").unwrap();
    assert_eq!(
        &**v.get_secret("crm/upstream/crm/env").unwrap().unwrap(),
        b"{}"
    );
    assert_eq!(
        v.list_secret_names().unwrap(),
        ["crm/upstream/crm/env", "crm/upstream/wiki/headers"]
    );
    assert!(matches!(
        v.put_secret("Bad Name", b"x"),
        Err(VaultError::InvalidSecretName)
    ));
    assert!(v.delete_secret("crm/upstream/crm/env").unwrap());
    assert!(!v.delete_secret("crm/upstream/crm/env").unwrap());
    assert!(v.get_secret("crm/upstream/crm/env").unwrap().is_none());
    // a corrupted row is an error, not None (spec §4.3)
    {
        let c = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
        c.execute(
            "UPDATE secrets SET value = x'00' WHERE name = 'crm/upstream/wiki/headers'",
            [],
        )
        .unwrap();
    }
    assert!(matches!(
        v.get_secret("crm/upstream/wiki/headers"),
        Err(VaultError::Decrypt)
    ));
    v.checkpoint().unwrap();
    drop(v);
    let raw = raw_bytes(dir.path());
    let needle = b"hunter2-canary";
    assert!(
        !raw.windows(needle.len()).any(|w| w == needle),
        "secret value readable at rest"
    );
    assert!(valid_secret_name("mail-work/mail/password"));
    assert!(valid_secret_name("crm/upstream/crm-1/env"));
    assert!(!valid_secret_name(""));
    assert!(!valid_secret_name("/leading"));
    assert!(!valid_secret_name(&"a".repeat(129)));
}

#[test]
fn gateway_tokens_are_hashed_verified_in_constant_time_and_revocable() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    let (info, token) = v.create_gateway_token("claude-code").unwrap();
    assert!(token.starts_with(TOKEN_PREFIX), "{}", &*token);
    assert_eq!(
        token.len(),
        TOKEN_PREFIX.len() + 43,
        "32 bytes base64url, no padding"
    );
    assert!(
        token[TOKEN_PREFIX.len()..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    );
    assert_eq!(info.label, "claude-code");
    assert!(info.last_used.is_none());
    let (_, other) = v.create_gateway_token("codex").unwrap();
    assert_ne!(&*token, &*other);
    let hit = v.verify_gateway_token(&token).unwrap().unwrap();
    assert_eq!(hit.id, info.id);
    assert!(hit.last_used.is_some(), "verification records last_used");
    assert!(v.verify_gateway_token("inumaki-gw-nope").unwrap().is_none());
    assert!(v.verify_gateway_token("").unwrap().is_none());
    let mut flipped = token.to_string();
    flipped.pop();
    flipped.push(if token.ends_with('A') { 'B' } else { 'A' });
    assert!(v.verify_gateway_token(&flipped).unwrap().is_none());
    assert_eq!(v.gateway_tokens().unwrap().len(), 2);
    v.revoke_gateway_token(info.id).unwrap();
    assert!(v.verify_gateway_token(&token).unwrap().is_none());
    assert!(matches!(
        v.revoke_gateway_token(info.id),
        Err(VaultError::GatewayTokenNotFound(_))
    ));
    assert!(matches!(
        v.create_gateway_token(""),
        Err(VaultError::InvalidLabel)
    ));
    v.checkpoint().unwrap();
    drop(v);
    let raw = raw_bytes(dir.path());
    let needle = token.as_bytes();
    assert!(
        !raw.windows(needle.len()).any(|w| w == needle),
        "token stored in clear"
    );
}

#[test]
fn upstreams_are_per_dataset_ordered_unique_and_cascade() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    v.create_dataset(&DatasetSpec::new("crm", "CRM", "strict"))
        .unwrap();
    let mut a = UpstreamSpec::stdio("crm", "npx");
    a.args = vec!["-y".into(), "@example/crm-mcp".into()];
    a.env.insert("CRM_URL".into(), "https://crm.example".into());
    a.env_secret = Some("crm/upstream/crm/env".into());
    a.content_policy = "{\"version\":1}".into();
    let ua = v.add_upstream("crm", &a).unwrap();
    assert_eq!(ua.spec.kind, UpstreamKind::Stdio);
    assert_eq!(ua.spec.args, ["-y", "@example/crm-mcp"]);
    assert_eq!(ua.spec.env["CRM_URL"], "https://crm.example");
    assert_eq!(ua.spec.content_policy, "{\"version\":1}");
    assert!(ua.spec.schema_fingerprint.is_none());
    assert!(ua.spec.enabled);
    let mut b = UpstreamSpec::http("wiki", "http://127.0.0.1:9000/mcp");
    b.headers.insert("X-Tenant".into(), "acme".into());
    b.headers_secret = Some("crm/upstream/wiki/headers".into());
    v.add_upstream("crm", &b).unwrap();
    let names: Vec<String> = v
        .upstreams("crm")
        .unwrap()
        .iter()
        .map(|u| u.spec.name.clone())
        .collect();
    assert_eq!(names, ["crm", "wiki"], "creation order");
    v.set_upstream_fingerprint("crm", "wiki", Some("sha256:abc"))
        .unwrap();
    assert_eq!(
        v.upstreams("crm").unwrap()[1]
            .spec
            .schema_fingerprint
            .as_deref(),
        Some("sha256:abc")
    );
    v.set_upstream_fingerprint("crm", "wiki", None).unwrap();
    assert!(
        v.upstreams("crm").unwrap()[1]
            .spec
            .schema_fingerprint
            .is_none()
    );
    assert!(matches!(
        v.set_upstream_fingerprint("crm", "nope", None),
        Err(VaultError::UpstreamNotFound(_))
    ));
    assert!(
        matches!(v.add_upstream("crm", &UpstreamSpec::stdio("crm", "x")), Err(VaultError::UpstreamExists(ref n)) if n == "crm")
    );
    assert!(matches!(
        v.add_upstream("nope", &UpstreamSpec::stdio("crm", "x")),
        Err(VaultError::DatasetNotFound(_))
    ));
    assert!(matches!(
        v.add_upstream("crm", &UpstreamSpec::stdio("Bad Name", "x")),
        Err(VaultError::InvalidUpstreamName)
    ));
    assert!(matches!(
        v.add_upstream("crm", &UpstreamSpec::http("h", "ftp://x")),
        Err(VaultError::InvalidUpstream("url"))
    ));
    let mut no_cmd = UpstreamSpec::stdio("c", "x");
    no_cmd.command = None;
    assert!(matches!(
        v.add_upstream("crm", &no_cmd),
        Err(VaultError::InvalidUpstream("command"))
    ));
    let mut bad_policy = UpstreamSpec::stdio("p", "x");
    bad_policy.content_policy = "not json".into();
    assert!(matches!(
        v.add_upstream("crm", &bad_policy),
        Err(VaultError::InvalidUpstream("content_policy"))
    ));
    v.remove_upstream("crm", "wiki").unwrap();
    assert!(
        matches!(v.remove_upstream("crm", "wiki"), Err(VaultError::UpstreamNotFound(ref n)) if n == "wiki")
    );
    assert_eq!(v.upstreams("crm").unwrap().len(), 1);
    v.delete_dataset("crm").unwrap();
    assert!(matches!(
        v.upstreams("crm"),
        Err(VaultError::DatasetNotFound(_))
    ));
    assert!(valid_upstream_name("crm_1-a"));
    assert!(!valid_upstream_name("CRM"));
    assert!(!valid_upstream_name(""));
}

/// Task 3's inspection overlay looks up without minting.
#[test]
fn peek_token_finds_existing_entries_and_never_mints() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    v.create_dataset(&DatasetSpec::new("mail", "M", "offline"))
        .unwrap();
    let mut ns = v.namespace("mail").unwrap();
    assert_eq!(ns.peek_token(&K::Person, "Sarah Leitner").unwrap(), None);
    assert_eq!(v.dataset("mail").unwrap().entries, 0, "peek does not mint");
    let t = ns.token_for(&K::Person, "Sarah Leitner").unwrap();
    assert_eq!(
        ns.peek_token(&K::Person, "sarah leitner").unwrap(),
        Some(t.clone())
    );
    let mut other = v.namespace("mail").unwrap();
    assert_eq!(
        other.peek_token(&K::Person, "Sarah Leitner").unwrap(),
        Some(t),
        "found in the store, not only the working set"
    );
    assert_eq!(v.dataset("mail").unwrap().entries, 1);
}

#[test]
fn v2_debug_impls_print_no_identities() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    v.create_dataset(&DatasetSpec::new("crm", CANARY, "strict"))
        .unwrap();
    let mut u = UpstreamSpec::stdio("crm", CANARY);
    u.env.insert("WHO".into(), CANARY.into());
    u.args.push(CANARY.into());
    u.content_policy = format!("{{\"note\":\"{CANARY}\"}}");
    // M1 (controller ruling): actually store the upstream so the `Upstream`
    // Debug impl (not just `UpstreamSpec`'s) is exercised.
    v.add_upstream("crm", &u).unwrap();
    let (t, secret) = v.create_gateway_token("label").unwrap();
    let d = format!("{u:?} {t:?} {:?}", v.upstreams("crm").unwrap());
    assert!(!d.contains("Zyxwuria") && !d.contains("Quolnath"), "{d}");
    assert!(!d.contains(&secret[TOKEN_PREFIX.len()..]), "{d}");
}
