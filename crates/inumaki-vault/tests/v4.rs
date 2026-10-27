//! Schema v4 (M4 spec §16.3): the egress journal (sealed, linked to activity
//! records, swept by retention and per-dataset budget), the entity listing
//! columns, and per-entity forget across every epoch.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

use inumaki_core::alias::{AliasGroup, AliasTable};
use inumaki_core::detect::DetectCtx;
use inumaki_core::span::EntityKind as K;
use inumaki_core::token::TokenStore;
use inumaki_vault::{
    Clock, DatasetSpec, Direction, FrontDoor, KeySource, KindCount, KindLabel, NewActivity,
    RecordId, SCHEMA_VERSION, Vault, VaultError, VaultOptions, Verdict,
};

mod common;

const CANARY: &str = "Zyxwuria Quolnath";
const PAYLOAD_MARK: &[u8] = b"payload-mark-qwxzvk";

struct TestClock(AtomicI64);

impl Clock for TestClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn opts(dir: &Path) -> VaultOptions {
    VaultOptions::in_dir(dir).with_key_source(KeySource::File)
}

fn open(dir: &Path, clock: Arc<TestClock>) -> Vault {
    Vault::open_with_clock(opts(dir), clock).unwrap()
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

fn columns(dir: &Path, table: &str) -> Vec<String> {
    let c = rusqlite::Connection::open(dir.join("vault.sqlite")).unwrap();
    c.prepare(&format!("PRAGMA table_info({table})"))
        .unwrap()
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn version(dir: &Path) -> String {
    let c = rusqlite::Connection::open(dir.join("vault.sqlite")).unwrap();
    c.query_row(
        "SELECT value FROM meta WHERE key = 'schema_version'",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

fn raw_bytes(dir: &Path) -> Vec<u8> {
    std::fs::read(dir.join("vault.sqlite")).unwrap()
}

fn released(v: &Vault, dataset: &str, payload: &[u8]) -> NewActivity {
    NewActivity {
        dataset: v.opaque_ref(dataset),
        front_door: FrontDoor::Gateway,
        upstream: Some(v.opaque_upstream(dataset, "a")),
        direction: Direction::Result,
        verdict: Verdict::Released,
        checks: Vec::new(),
        kinds: vec![KindCount {
            kind: KindLabel::of(&K::Person),
            count: 1,
        }],
        tripwire: false,
        bytes: payload.len() as u64,
        released: Some(v.released_digest(payload)),
    }
}

/// An activity record plus its journal entry, as the gateway's sink writes them.
fn write_entry(v: &Vault, dataset: &str, payload: &[u8]) -> RecordId {
    let r = v.append_activity(released(v, dataset, payload)).unwrap();
    v.append_journal(dataset, &r.id, r.at, r.released.as_ref().unwrap(), payload)
        .unwrap();
    r.id
}

#[test]
fn fresh_vault_has_the_v4_tables_columns_and_version() {
    let dir = tempfile::tempdir().unwrap();
    drop(open(dir.path(), Arc::new(TestClock(AtomicI64::new(1)))));
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
    assert_eq!(version(dir.path()), SCHEMA_VERSION.to_string());
    let cols = columns(dir.path(), "entries");
    assert!(
        cols.contains(&"created_at".to_string()) && cols.contains(&"uses".to_string()),
        "{cols:?}"
    );
    assert_eq!(
        columns(dir.path(), "journal"),
        [
            "seq",
            "dataset_id",
            "record_id",
            "at",
            "released",
            "bytes",
            "nonce",
            "payload"
        ]
    );
}

#[test]
fn v3_file_migrates_to_v4_and_backfills_created_at() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TestClock(AtomicI64::new(5_000)));
    let v = open(dir.path(), Arc::clone(&clock));
    v.create_dataset(&DatasetSpec::new("crm", "CRM", "offline"))
        .unwrap();
    v.namespace("crm")
        .unwrap()
        .token_for(&K::Person, CANARY)
        .unwrap();
    v.checkpoint().unwrap();
    drop(v);
    {
        let c = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
        common::downgrade_to(&c, 3);
    }
    assert!(!columns(dir.path(), "entries").contains(&"uses".to_string()));
    let v = open(dir.path(), clock);
    assert_eq!(version(dir.path()), SCHEMA_VERSION.to_string());
    assert!(v.journal("crm", None, 10).unwrap().is_empty());
    let e = v.entities("crm", 10, false).unwrap();
    assert_eq!(e.len(), 1);
    assert_eq!(
        (e[0].first_use, e[0].last_use, e[0].uses),
        (5_000, 5_000, 1),
        "created_at backfilled from last_used, one use"
    );
    assert_eq!(e[0].kind, K::Person);
    assert!(e[0].original.is_none());
    assert!(e[0].token.starts_with("<PERSON_"));
}

#[test]
fn journal_round_trips_sealed_at_rest_newest_first_per_dataset() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TestClock(AtomicI64::new(1_000)));
    let v = open(dir.path(), Arc::clone(&clock));
    v.create_dataset(&DatasetSpec::new("crm", "CRM", "offline"))
        .unwrap();
    v.create_dataset(&DatasetSpec::new("mail", "Mail", "offline"))
        .unwrap();
    let p1 = [
        &b"{\"content\":[{\"type\":\"text\",\"text\":\"<PERSON_a1b2c3> "[..],
        PAYLOAD_MARK,
        &b"\"}]}"[..],
    ]
    .concat();
    let a = write_entry(&v, "crm", &p1);
    clock.0.store(2_000, Ordering::SeqCst);
    let b = write_entry(&v, "crm", b"{\"second\":true}");
    clock.0.store(3_000, Ordering::SeqCst);
    let m = write_entry(&v, "mail", b"{\"other\":true}");
    let list = v.journal("crm", None, 10).unwrap();
    assert_eq!(
        list.iter().map(|e| e.id.clone()).collect::<Vec<_>>(),
        [b.clone(), a.clone()],
        "newest first, this dataset only"
    );
    assert_eq!((list[1].at, list[1].bytes), (1_000, p1.len() as u64));
    assert_eq!(v.journal("crm", Some(2_000), 10).unwrap().len(), 1);
    assert_eq!(v.journal("crm", None, 1).unwrap()[0].id, b);
    assert_eq!(v.journal("mail", None, 10).unwrap()[0].id, m);
    let (entry, payload) = v.journal_payload("crm", &a).unwrap().unwrap();
    assert_eq!(entry.id, a);
    assert_eq!(&*payload, &p1[..], "exactly the released bytes");
    assert_eq!(
        entry.released,
        v.released_digest(&p1),
        "linked to the activity record's digest"
    );
    assert!(
        v.journal_payload("mail", &a).unwrap().is_none(),
        "a record id is looked up within its dataset"
    );
    assert!(matches!(
        v.journal("nope", None, 1),
        Err(VaultError::DatasetNotFound(_))
    ));
    assert!(matches!(
        v.journal_payload("nope", &a),
        Err(VaultError::DatasetNotFound(_))
    ));
    // a payload for a deleted dataset is refused, and deleting a dataset deletes its journal
    v.delete_dataset("mail").unwrap();
    let orphan = RecordId::try_from("f".repeat(32)).unwrap();
    let digest = v.released_digest(b"x");
    assert!(matches!(
        v.append_journal("mail", &orphan, 1, &digest, b"x"),
        Err(VaultError::DatasetNotFound(_))
    ));
    v.checkpoint().unwrap();
    drop(v);
    let raw = raw_bytes(dir.path());
    assert!(
        !raw.windows(PAYLOAD_MARK.len()).any(|w| w == PAYLOAD_MARK),
        "payload readable at rest"
    );
    let c = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
    let n: i64 = c
        .query_row(
            "SELECT count(*) FROM journal WHERE dataset_id = 'mail'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0, "cascade");
}

/// Review Focus 3.
#[test]
fn edited_journal_rows_fail_to_open() {
    let dir = tempfile::tempdir().unwrap();
    let v = open(dir.path(), Arc::new(TestClock(AtomicI64::new(1))));
    v.create_dataset(&DatasetSpec::new("crm", "CRM", "offline"))
        .unwrap();
    let a = write_entry(&v, "crm", b"{\"a\":1}");
    let b = write_entry(&v, "crm", b"{\"b\":2}");
    // a digest that does not match the payload is refused before anything is written
    let wrong = v.released_digest(b"other");
    let fresh = RecordId::try_from("e".repeat(32)).unwrap();
    assert!(matches!(
        v.append_journal("crm", &fresh, 1, &wrong, b"{\"a\":1}"),
        Err(VaultError::JournalRecord(_))
    ));
    v.checkpoint().unwrap();
    let c = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
    // 1. a flipped payload byte fails authentication (tampered in Rust: the
    // SQL `||` operator would coerce the BLOB to TEXT and fail the read
    // before decryption even runs)
    let mut blob: Vec<u8> = c
        .query_row(
            "SELECT payload FROM journal WHERE record_id = ?1",
            rusqlite::params![a.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 0xff;
    c.execute(
        "UPDATE journal SET payload = ?1 WHERE record_id = ?2",
        rusqlite::params![blob, a.as_str()],
    )
    .unwrap();
    assert!(matches!(
        v.journal_payload("crm", &a),
        Err(VaultError::JournalRecord(_))
    ));
    // 2. the stored digest edited: the payload opens but no longer matches its activity record
    c.execute(
        "UPDATE journal SET released = ?1 WHERE record_id = ?2",
        rusqlite::params!["0".repeat(64), b.as_str()],
    )
    .unwrap();
    let e = v.journal_payload("crm", &b).unwrap_err();
    assert!(matches!(e, VaultError::JournalRecord(_)));
    assert!(!format!("{e}").contains("{\"b\""), "{e}");
    // 3. rows re-pointed to each other's record id fail (the id is in the AAD)
    c.execute(
        "UPDATE journal SET released = ?1 WHERE record_id = ?2",
        rusqlite::params![v.released_digest(b"{\"b\":2}").as_str(), b.as_str()],
    )
    .unwrap();
    c.execute(
        "UPDATE journal SET record_id = 'tmp' WHERE record_id = ?1",
        rusqlite::params![a.as_str()],
    )
    .unwrap();
    c.execute(
        "UPDATE journal SET record_id = ?1 WHERE record_id = ?2",
        rusqlite::params![a.as_str(), b.as_str()],
    )
    .unwrap();
    assert!(matches!(
        v.journal_payload("crm", &a),
        Err(VaultError::JournalRecord(_))
    ));
    // the list still works: metadata is not authenticated, the payload is
    let e = v.journal("crm", None, 10).unwrap_err();
    let VaultError::JournalRecord(seq) = e else {
        panic!("{e:?}")
    };
    assert!(seq > 0, "the listing names the offending row: {seq}");
    assert!(!format!("{e}").contains("tmp"), "{e}");
}

/// Review Focus 4.
#[test]
fn journal_budget_is_per_dataset_oldest_first() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TestClock(AtomicI64::new(1_000)));
    let v = open(dir.path(), Arc::clone(&clock));
    v.create_dataset(&DatasetSpec::new("busy", "B", "offline"))
        .unwrap();
    v.create_dataset(&DatasetSpec::new("quiet", "Q", "offline"))
        .unwrap();
    let kb = vec![b'x'; 1_000];
    let mut busy = Vec::new();
    for i in 0..10 {
        clock.0.store(1_000 + i, Ordering::SeqCst);
        busy.push(write_entry(
            &v,
            "busy",
            &[kb.as_slice(), i.to_string().as_bytes()].concat(),
        ));
    }
    let q1 = write_entry(&v, "quiet", &kb);
    let q2 = write_entry(&v, "quiet", &kb);
    let s = v.sweep_journal(86_400, 4_500).unwrap();
    assert_eq!(
        (s.expired, s.over_budget),
        (0, 6),
        "the newest four (4 004 B) fit; the fifth would exceed 4 500"
    );
    let kept: Vec<RecordId> = v
        .journal("busy", None, 100)
        .unwrap()
        .into_iter()
        .map(|e| e.id)
        .collect();
    assert_eq!(
        kept,
        [
            busy[9].clone(),
            busy[8].clone(),
            busy[7].clone(),
            busy[6].clone()
        ]
    );
    assert_eq!(
        v.journal("quiet", None, 100).unwrap().len(),
        2,
        "the quiet dataset is untouched"
    );
    // retention: entries older than the window go, per timestamp, regardless of budget
    clock.0.store(1_009 + 100, Ordering::SeqCst);
    let s = v.sweep_journal(3, 1 << 30).unwrap();
    assert_eq!(
        (s.expired, s.over_budget),
        (6, 0),
        "everything at < 1 106 (all remaining entries)"
    );
    assert!(v.journal("busy", None, 100).unwrap().is_empty());
    assert!(v.journal("quiet", None, 100).unwrap().is_empty());
    let _ = (q1, q2);
    assert_eq!(
        v.sweep_journal(3, 1 << 30).unwrap(),
        inumaki_vault::JournalSweep::default(),
        "idempotent"
    );
}

#[test]
fn entities_list_counts_store_uses_and_reveal_values_on_request() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TestClock(AtomicI64::new(100)));
    let v = open(dir.path(), Arc::clone(&clock));
    v.create_dataset(&DatasetSpec::new("crm", "CRM", "offline"))
        .unwrap();
    let person = v
        .namespace("crm")
        .unwrap()
        .token_for(&K::Person, CANARY)
        .unwrap();
    clock.0.store(200, Ordering::SeqCst);
    let iban = v
        .namespace("crm")
        .unwrap()
        .token_for(&K::Iban, "AT61 1904 3002 3457 3201")
        .unwrap();
    clock.0.store(300, Ordering::SeqCst);
    // a new handle finds the person in the store: one more use, last_use moves
    assert_eq!(
        v.namespace("crm")
            .unwrap()
            .token_for(&K::Person, "zyxwuria quolnath")
            .unwrap(),
        person
    );
    let list = v.entities("crm", 0, false).unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].token, person.as_str(), "most recently used first");
    assert_eq!(
        (list[0].first_use, list[0].last_use, list[0].uses),
        (100, 300, 2)
    );
    assert_eq!(
        (list[1].first_use, list[1].last_use, list[1].uses),
        (200, 200, 1)
    );
    assert_eq!(list[1].token, iban.as_str());
    assert!(list.iter().all(|e| e.original.is_none() && e.current_epoch));
    assert_eq!(v.entities("crm", 1, false).unwrap().len(), 1);
    let with = v.entities("crm", 0, true).unwrap();
    assert_eq!(
        with[0].original.as_deref().map(String::as_str),
        Some(CANARY)
    );
    assert_eq!(
        with[1].original.as_deref().map(String::as_str),
        Some("AT61 1904 3002 3457 3201")
    );
    let d = format!("{:?}", with[0]);
    assert!(
        !d.contains("Zyxwuria") && !d.contains(&person.as_str()[8..12]),
        "{d}"
    );
    assert!(d.contains("has_original: true"));
    assert!(matches!(
        v.entities("nope", 0, false),
        Err(VaultError::DatasetNotFound(_))
    ));
    // removed values (secrets) are not entities
    v.namespace("crm")
        .unwrap()
        .record_removed(
            &K::Secret(inumaki_core::span::SecretKind::Generic),
            "hunter2-canary",
        )
        .unwrap();
    assert_eq!(v.entities("crm", 0, false).unwrap().len(), 2);
}

/// Review Focus 2 and 7 (vault side).
#[test]
fn forget_removes_every_epoch_and_a_fresh_token_is_minted() {
    let dir = tempfile::tempdir().unwrap();
    let v = open(dir.path(), Arc::new(TestClock(AtomicI64::new(1))));
    v.create_dataset(&DatasetSpec::new("crm", "CRM", "offline"))
        .unwrap();
    let t1 = v
        .namespace("crm")
        .unwrap()
        .token_for(&K::Person, CANARY)
        .unwrap();
    v.rotate("crm").unwrap();
    let mut ns = v.namespace("crm").unwrap();
    let t2 = ns.token_for(&K::Person, CANARY).unwrap();
    assert_ne!(t1, t2);
    ns.token_for(&K::Person, "Sarah Leitner").unwrap();
    assert_eq!(
        v.entities("crm", 0, false).unwrap().len(),
        3,
        "two epochs hold the canary, one holds Sarah"
    );
    let text = format!("Hallo {CANARY}");
    assert_eq!(
        ns.detector()
            .detect(&text, &DetectCtx::for_text(&text))
            .unwrap()
            .len(),
        1
    );
    // the ciphertext of both rows, to prove it is gone from the file and the WAL afterwards
    let ciphertexts: Vec<Vec<u8>> = {
        let c = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
        let mut stmt = c
            .prepare("SELECT value FROM entries WHERE token IN (?1, ?2)")
            .unwrap();
        stmt.query_map(rusqlite::params![t1.as_str(), t2.as_str()], |r| {
            r.get::<_, Vec<u8>>(0)
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    };
    assert_eq!(ciphertexts.len(), 2);
    // forget by the closed epoch's token: rows in both epochs go
    let f = v.forget_by_token("crm", t1.as_str()).unwrap();
    assert_eq!((f.kinds.as_slice(), f.rows), ([K::Person].as_slice(), 2));
    // Review Focus 2 (review): a TRUNCATE checkpoint (AppState::forget_entity
    // does it) leaves no pre-delete page image in the WAL; secure_delete
    // zeroes the freed content in the main file.
    v.checkpoint_truncate().unwrap();
    let mut on_disk = std::fs::read(dir.path().join("vault.sqlite")).unwrap();
    on_disk.extend(std::fs::read(dir.path().join("vault.sqlite-wal")).unwrap_or_default());
    for ct in &ciphertexts {
        assert!(
            !on_disk.windows(ct.len()).any(|w| w == ct.as_slice()),
            "forgotten ciphertext still on disk"
        );
    }
    assert_eq!(f.tokens.len(), 2);
    assert!(
        f.tokens.contains(&t1.as_str().to_string()) && f.tokens.contains(&t2.as_str().to_string())
    );
    assert!(!format!("{f:?}").contains(&t2.as_str()[8..12]));
    assert!(matches!(
        v.forget_by_token("crm", t1.as_str()),
        Err(VaultError::EntityNotFound)
    ));
    assert!(matches!(
        v.forget_by_token("nope", t1.as_str()),
        Err(VaultError::DatasetNotFound(_))
    ));
    let left = v.entities("crm", 0, false).unwrap();
    assert_eq!(left.len(), 1, "only Sarah is left");
    assert_eq!(left[0].kind, K::Person);
    assert_ne!(left[0].token, t2.as_str());
    // the open handle still has the old token in its working set until told
    assert_eq!(ns.original(t2.as_str()), Some(CANARY));
    ns.forget_tokens(&f.tokens).unwrap();
    assert!(ns.original(t2.as_str()).is_none(), "evicted");
    assert!(
        ns.detector()
            .detect(&text, &DetectCtx::for_text(&text))
            .unwrap()
            .is_empty(),
        "the automaton was rebuilt without it"
    );
    let t3 = ns.token_for(&K::Person, CANARY).unwrap();
    assert_ne!(t3, t2, "a later occurrence mints a fresh token");
    assert_ne!(t3, t1);
    // forget by value goes through the HMAC index (normalized), and alias variants resolve to the canonical
    let f = v.forget_by_value("crm", "  sarah   LEITNER ").unwrap();
    assert_eq!((f.kinds.as_slice(), f.rows), ([K::Person].as_slice(), 1));
    assert!(matches!(
        v.forget_by_value("crm", "Sarah Leitner"),
        Err(VaultError::EntityNotFound)
    ));
    let table = Arc::new(
        AliasTable::build(vec![AliasGroup {
            kind: K::Person,
            names: vec!["Hans-Peter Gruber".into(), "Hansi".into()],
        }])
        .unwrap(),
    );
    let va = Vault::open(opts(dir.path()).with_aliases(table)).unwrap();
    va.namespace("crm")
        .unwrap()
        .token_for(&K::Person, "Hans-Peter Gruber")
        .unwrap();
    // Review round 1, finding 2: a variant reached only through alias
    // expansion (the typed text "hansi" differs from the stored one) must
    // not also delete an unrelated entity of another kind that happens to
    // share the canonical's spelling.
    let org = va
        .namespace("crm")
        .unwrap()
        .token_for(&K::Organization, "Hans-Peter Gruber")
        .unwrap();
    let f = va.forget_by_value("crm", "hansi").unwrap();
    assert_eq!(
        f.rows, 1,
        "a variant forgets the group's canonical, not another kind sharing its text"
    );
    assert_eq!(
        va.namespace("crm")
            .unwrap()
            .peek_token(&K::Organization, "Hans-Peter Gruber")
            .unwrap(),
        Some(org),
        "the Organization entry with identical text survives"
    );
    // a value that maps to two kinds forgets both
    va.namespace("crm")
        .unwrap()
        .token_for(&K::City, "Wien")
        .unwrap();
    va.namespace("crm")
        .unwrap()
        .token_for(&K::Organization, "Wien")
        .unwrap();
    let f = va.forget_by_value("crm", "Wien").unwrap();
    assert_eq!((f.kinds.len(), f.rows), (2, 2));
}

/// Review item 4: the journal writer has its own connection, so a burst of
/// large payloads never holds the shared connection the request path
/// takes. Readers and working-set hits stay at idle speed; a mint that
/// coincides with one INSERT waits for that INSERT only (WAL writers
/// serialize), which the bench note in the architecture doc records. Bound
/// relaxed (preflight ruling R6) to `max(idle_p50 * 4, 10 ms)`: a debug
/// build sealing 10 x 5 MiB payloads on a loaded machine can be slow to
/// schedule the probing thread.
#[test]
fn journal_burst_does_not_stall_request_path_reads() {
    let dir = tempfile::tempdir().unwrap();
    let v = open(dir.path(), Arc::new(TestClock(AtomicI64::new(1))));
    v.create_dataset(&DatasetSpec::new("crm", "CRM", "offline"))
        .unwrap();
    let mut ns = v.namespace("crm").unwrap();
    ns.token_for(&K::Person, CANARY).unwrap();
    let probe = |ns: &mut inumaki_vault::Namespace| -> Duration {
        let t0 = Instant::now();
        v.dataset_profile("crm").unwrap(); // a request-path read on the shared connection
        ns.token_for(&K::Person, CANARY).unwrap(); // a working-set hit
        t0.elapsed()
    };
    let mut idle: Vec<Duration> = (0..20).map(|_| probe(&mut ns)).collect();
    idle.sort();
    let writer = v.journal_writer().unwrap();
    let vw = v.clone();
    let burst = std::thread::spawn(move || {
        for _ in 0..10 {
            let payload = vec![b'j'; 5 * 1024 * 1024];
            let r = vw.append_activity(released(&vw, "crm", &payload)).unwrap();
            writer
                .append("crm", &r.id, r.at, r.released.as_ref().unwrap(), &payload)
                .unwrap();
        }
    });
    let mut during: Vec<Duration> = Vec::new();
    while during.len() < 20 && !burst.is_finished() {
        during.push(probe(&mut ns));
        std::thread::sleep(Duration::from_millis(5));
    }
    burst.join().unwrap();
    assert!(
        during.len() >= 10,
        "the burst ended before enough probes ran; enlarge it"
    );
    during.sort();
    let (idle_p50, during_p50) = (idle[idle.len() / 2], during[during.len() / 2]);
    assert!(
        during_p50 <= (idle_p50 * 4).max(Duration::from_millis(10)),
        "idle p50 {idle_p50:?}, during the burst {during_p50:?}"
    );
    assert_eq!(
        v.journal("crm", None, 100).unwrap().len(),
        10,
        "every payload landed"
    );
    assert_eq!(
        format!("{:?}", v.journal_writer().unwrap()),
        "JournalWriter"
    );
}

#[test]
fn v4_debug_impls_print_no_values() {
    let dir = tempfile::tempdir().unwrap();
    let v = open(dir.path(), Arc::new(TestClock(AtomicI64::new(1))));
    v.create_dataset(&DatasetSpec::new("crm", "CRM", "offline"))
        .unwrap();
    let id = write_entry(&v, "crm", format!("{{\"text\":\"{CANARY}\"}}").as_bytes());
    let (entry, payload) = v.journal_payload("crm", &id).unwrap().unwrap();
    let d = format!("{entry:?} {:?}", v.journal("crm", None, 1).unwrap());
    assert!(!d.contains("Zyxwuria"), "{d}");
    drop(payload);
    let e = format!(
        "{} {}",
        VaultError::JournalRecord(7),
        VaultError::EntityNotFound
    );
    assert!(!e.contains("Zyxwuria"));
}
