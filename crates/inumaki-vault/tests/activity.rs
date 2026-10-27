//! M4 spec §16.4: activity records hold enums, integers, and fixed-format
//! ids only; they round-trip, filter, chain, sweep, and migrate. A row
//! edited on disk to carry text fails to load.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use inumaki_core::span::EntityKind as K;
use inumaki_core::verify::CheckId;
use inumaki_vault::{
    ActivityFilter, ActivityRecord, CheckLabel, Clock, DatasetSpec, Digest, Direction, FrontDoor,
    KeySource, KindCount, KindLabel, NewActivity, OpaqueId, RecordId, SCHEMA_VERSION, Vault,
    VaultError, VaultOptions, Verdict,
};
use proptest::prelude::*;

mod common;

const CANARY: &str = "Zyxwuria Quolnath";
const IBAN: &str = "AT61 1904 3002 3457 3201";

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

fn rec(v: &Vault, dataset: &str, verdict: Verdict) -> NewActivity {
    NewActivity {
        dataset: v.opaque_ref(dataset),
        front_door: FrontDoor::Gateway,
        upstream: Some(v.opaque_upstream(dataset, "crm-server")),
        direction: Direction::Result,
        verdict,
        checks: vec![CheckLabel::of(&CheckId::Leak)],
        kinds: vec![
            KindCount {
                kind: KindLabel::of(&K::Person),
                count: 2,
            },
            KindCount {
                kind: KindLabel::of(&K::Iban),
                count: 1,
            },
        ],
        tripwire: false,
        bytes: 1234,
        released: Some(v.released_digest(format!("{CANARY} {IBAN}").as_bytes())),
    }
}

#[test]
fn records_round_trip_newest_first_and_filter_by_dataset_and_time() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TestClock(AtomicI64::new(1_000)));
    let v = open(dir.path(), Arc::clone(&clock));
    v.create_dataset(&DatasetSpec::new("crm", "CRM", "offline"))
        .unwrap();
    v.create_dataset(&DatasetSpec::new("mail", "Mail", "offline"))
        .unwrap();
    let a = v
        .append_activity(rec(&v, "crm", Verdict::Released))
        .unwrap();
    clock.0.store(2_000, Ordering::SeqCst);
    let b = v
        .append_activity(rec(&v, "mail", Verdict::Blocked))
        .unwrap();
    clock.0.store(3_000, Ordering::SeqCst);
    let c = v
        .append_activity(rec(&v, "crm", Verdict::Unresolved))
        .unwrap();
    assert_eq!(
        (a.at, b.at, c.at),
        (1_000, 2_000, 3_000),
        "the vault stamps the time"
    );
    assert_ne!(a.id, b.id);
    let all = v
        .activity(&ActivityFilter {
            dataset: None,
            since: None,
            limit: 10,
        })
        .unwrap();
    assert_eq!(
        all.iter().map(|r| r.at).collect::<Vec<_>>(),
        [3_000, 2_000, 1_000],
        "newest first"
    );
    assert_eq!(all[2], a, "round trip is lossless");
    let crm = v
        .activity(&ActivityFilter {
            dataset: Some(v.opaque_ref("crm")),
            since: None,
            limit: 10,
        })
        .unwrap();
    assert_eq!(crm.len(), 2);
    let recent = v
        .activity(&ActivityFilter {
            dataset: None,
            since: Some(2_000),
            limit: 10,
        })
        .unwrap();
    assert_eq!(recent.len(), 2);
    let one = v
        .activity(&ActivityFilter {
            dataset: None,
            since: None,
            limit: 1,
        })
        .unwrap();
    assert_eq!(one, vec![c]);
    assert_ne!(v.opaque_ref("crm").as_str(), "crm");
    assert_ne!(
        v.opaque_upstream("crm", "a"),
        v.opaque_upstream("mail", "a"),
        "upstream ids are per dataset"
    );
}

#[test]
fn stored_records_never_contain_values_names_or_slugs() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TestClock(AtomicI64::new(1_000)));
    let v = open(dir.path(), clock);
    v.create_dataset(&DatasetSpec::new("qwxzvk-canary-slug", "Canary", "offline"))
        .unwrap();
    let r = v
        .append_activity(rec(&v, "qwxzvk-canary-slug", Verdict::Released))
        .unwrap();
    let json = serde_json::to_string(&r).unwrap();
    v.checkpoint().unwrap();
    // every stored column of every activity row (the dataset slug itself is
    // the datasets table's key, so the file as a whole is not the test)
    let c = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
    let stored: Vec<String> = c
        .prepare("SELECT id || '|' || at || '|' || dataset || '|' || record || '|' || prev || '|' || hash FROM activity")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(stored.len(), 1);
    for needle in [
        CANARY,
        "Zyxwuria",
        "AT61",
        "qwxzvk-canary-slug",
        "crm-server",
    ] {
        assert!(!json.contains(needle), "{needle} in {json}");
        assert!(
            !stored[0].contains(needle),
            "{needle} at rest: {}",
            stored[0]
        );
    }
    assert!(format!("{r:?}").len() < 2_000);
}

/// Label-shaped canaries: a name without a space (check-label shape
/// before the fix), an upper-case name (kind-label shape), and an IBAN
/// folded into a kind (digits).
const SHAPED: [&str; 3] = [
    "ZyxwuriaQuolnath",
    "ZYXWURIA_QUOLNATH",
    "IBAN_AT611904300234573201",
];

/// What a stored label goes through on load.
fn kind_loads(s: &str) -> Option<KindLabel> {
    serde_json::from_value(serde_json::json!(s)).ok()
}

fn check_loads(s: &str) -> Option<CheckLabel> {
    serde_json::from_value(serde_json::json!(s)).ok()
}

/// Every built-in kind, and every check id (typed paths only).
fn built_in_kinds() -> Vec<K> {
    vec![
        K::Person,
        K::Email,
        K::Phone,
        K::StreetAddress,
        K::City,
        K::PostalCode,
        K::Country,
        K::Organization,
        K::Iban,
        K::CreditCard,
        K::IpAddress,
        K::Url,
        K::Date,
        K::DateOfBirth,
        K::NationalId,
        K::TaxId,
        K::LicensePlate,
        K::CustomerId,
        K::ContractId,
        K::InvoiceId,
        K::Secret(inumaki_core::span::SecretKind::Jwt),
    ]
}

const CHECK_IDS: [CheckId; 6] = [
    CheckId::Leak,
    CheckId::Regex,
    CheckId::Ner,
    CheckId::Combination,
    CheckId::Policy,
    CheckId::DetectorError,
];

#[test]
fn labels_accept_fixed_formats_only() {
    assert_eq!(KindLabel::of(&K::Person).as_str(), "PERSON");
    assert_eq!(
        KindLabel::of(&K::custom("CUSTOMER_ID")).as_str(),
        "CUSTOMER_ID"
    );
    assert_eq!(
        KindLabel::of(&K::custom("Zyxwuria Quolnath")).as_str(),
        "CUSTOM",
        "a custom kind without the format never reaches a record as itself"
    );
    assert_eq!(
        CheckLabel::of(&CheckId::DetectorError).as_str(),
        "DetectorError"
    );
    for k in built_in_kinds() {
        assert_eq!(kind_loads(k.label()), Some(KindLabel::of(&k)), "{k:?}");
    }
    for c in CHECK_IDS {
        let l = CheckLabel::of(&c);
        assert_eq!(check_loads(l.as_str()), Some(l));
        assert_eq!(l.as_str(), format!("{c:?}"), "same names as before");
    }
    assert_eq!(
        CheckLabel::parse("ClearValue"),
        Some(CheckLabel::ClearValue)
    );
    assert_eq!(check_loads("ClearValue"), Some(CheckLabel::ClearValue));
    for bad in [
        CANARY,
        "zyxwuria",
        "PERSON X",
        "",
        "A-B",
        "ÄRZTIN",
        "IBAN_AT611904300234573201",
        "PERSON2",
        &"A".repeat(33),
    ] {
        assert!(kind_loads(bad).is_none(), "kind {bad:?}");
    }
    for bad in [
        CANARY,
        "ZyxwuriaQuolnath",
        "ZYXWURIA_QUOLNATH",
        "SarahLeitner",
        "leak",
        "Leak Leak",
        "Unknown",
        "",
    ] {
        assert!(check_loads(bad).is_none(), "check {bad:?}");
        assert!(CheckLabel::parse(bad).is_none(), "check {bad:?}");
    }
    // Format alone cannot exclude an upper-case name: a kind label is
    // bounded by provenance too (only `KindLabel::of(&EntityKind)` builds
    // one, and custom kinds are operator configuration).
    assert!(kind_loads("ZYXWURIA_QUOLNATH").is_some());
    assert!(OpaqueId::try_from(CANARY.to_string()).is_err());
    assert!(OpaqueId::try_from("0123456789abcdef".to_string()).is_ok());
    assert!(
        RecordId::try_from("0123456789abcdef".to_string()).is_err(),
        "record ids are 32 hex"
    );
    assert!(Digest::try_from("ab".repeat(32)).is_ok());
    assert!(Digest::try_from("AB".repeat(32)).is_err(), "lowercase only");
}

/// Adding a field to `ActivityRecord`, `NewActivity`, or `KindCount` breaks
/// these destructurings on purpose: whoever adds it must add it here, with
/// a type that cannot carry text. (The private stored body has the same
/// test in `src/activity.rs`.)
#[test]
fn record_fields_are_closed_and_typed() {
    fn check(r: ActivityRecord) {
        let ActivityRecord {
            id,
            at,
            dataset,
            front_door,
            upstream,
            direction,
            verdict,
            checks,
            kinds,
            tripwire,
            bytes,
            released,
        } = r;
        let _: (
            RecordId,
            i64,
            OpaqueId,
            FrontDoor,
            Option<OpaqueId>,
            Direction,
            Verdict,
        ) = (id, at, dataset, front_door, upstream, direction, verdict);
        let _: (Vec<CheckLabel>, Vec<KindCount>, bool, u64, Option<Digest>) =
            (checks, kinds, tripwire, bytes, released);
    }
    fn check_new(r: NewActivity) {
        let NewActivity {
            dataset,
            front_door,
            upstream,
            direction,
            verdict,
            checks,
            kinds,
            tripwire,
            bytes,
            released,
        } = r;
        let _: (OpaqueId, FrontDoor, Option<OpaqueId>, Direction, Verdict) =
            (dataset, front_door, upstream, direction, verdict);
        let _: (Vec<CheckLabel>, Vec<KindCount>, bool, u64, Option<Digest>) =
            (checks, kinds, tripwire, bytes, released);
    }
    fn check_count(c: KindCount) {
        let KindCount { kind, count } = c;
        let _: (KindLabel, u32) = (kind, count);
    }
    let dir = tempfile::tempdir().unwrap();
    let v = open(dir.path(), Arc::new(TestClock(AtomicI64::new(1))));
    v.create_dataset(&DatasetSpec::new("crm", "CRM", "offline"))
        .unwrap();
    let n = rec(&v, "crm", Verdict::Released);
    check_count(n.kinds[0].clone());
    check_new(n.clone());
    check(v.append_activity(n).unwrap());
}

proptest! {
    /// Arbitrary text and label-shaped canaries, offered where a stored
    /// label is read back: a check name is one of the fixed names or
    /// refused; a kind label has the digit-free kind shape or is refused.
    /// A record built through the typed paths (built-in kinds, check ids)
    /// never contains the canary in any case.
    #[test]
    fn arbitrary_text_never_reaches_a_record(
        s in ".{0,40}",
        pick in 0usize..6,
        k in 0usize..21,
        c in 0usize..6,
    ) {
        let s = match pick {
            0 => s,
            1 => format!("{CANARY}{s}"),
            2 => s.to_uppercase(),
            n => SHAPED[n - 3].to_string(),
        };
        if let Some(l) = kind_loads(&s) {
            prop_assert!(l.as_str().bytes().all(|b| b.is_ascii_uppercase() || b == b'_'));
            prop_assert!(!l.as_str().contains("AT61"));
        }
        if let Some(l) = check_loads(&s) {
            prop_assert!(CheckLabel::ALL.contains(&l));
        }
        prop_assert!(check_loads(SHAPED[0]).is_none() && check_loads(SHAPED[1]).is_none());
        prop_assert!(kind_loads(SHAPED[2]).is_none());
        let kind = &built_in_kinds()[k];
        let r = ActivityRecord {
            id: RecordId::try_from("0".repeat(32)).unwrap(),
            at: 0,
            dataset: OpaqueId::try_from("0".repeat(16)).unwrap(),
            front_door: FrontDoor::Gateway,
            upstream: None,
            direction: Direction::Arguments,
            verdict: Verdict::Released,
            checks: vec![CheckLabel::of(&CHECK_IDS[c]), CheckLabel::ClearValue],
            kinds: vec![KindCount { kind: KindLabel::of(kind), count: 1 }],
            tripwire: true,
            bytes: s.len() as u64,
            released: None,
        };
        let json = serde_json::to_string(&r).unwrap().to_lowercase();
        prop_assert!(!json.contains("zyxwuria") && !json.contains("at61"), "{}", json);
    }
}

#[test]
fn a_row_edited_to_carry_text_fails_to_load() {
    for (from, to) in [
        ("\"PERSON\"", format!("\"{CANARY}\"")),
        ("\"PERSON\"", "\"IBAN_AT611904300234573201\"".to_string()),
        ("\"Leak\"", "\"ZyxwuriaQuolnath\"".to_string()),
        ("\"Leak\"", "\"ZYXWURIA_QUOLNATH\"".to_string()),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let v = open(dir.path(), Arc::new(TestClock(AtomicI64::new(1))));
        v.create_dataset(&DatasetSpec::new("crm", "CRM", "offline"))
            .unwrap();
        v.append_activity(rec(&v, "crm", Verdict::Released))
            .unwrap();
        v.checkpoint().unwrap();
        drop(v);
        let c = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
        let n = c
            .execute(
                "UPDATE activity SET record = replace(record, ?1, ?2)",
                rusqlite::params![from, to],
            )
            .unwrap();
        assert_eq!(n, 1);
        let edited: String = c
            .query_row("SELECT record FROM activity", [], |r| r.get(0))
            .unwrap();
        assert!(edited.contains(&to), "{edited}");
        drop(c);
        let v = open(dir.path(), Arc::new(TestClock(AtomicI64::new(1))));
        let e = v
            .activity(&ActivityFilter {
                dataset: None,
                since: None,
                limit: 10,
            })
            .unwrap_err();
        assert!(matches!(e, VaultError::ActivityRecord), "{to}: {e:?}");
        assert!(!format!("{e} {e:?}").to_lowercase().contains("zyxwuria"));
    }
}

#[test]
fn chain_detects_edits_and_survives_sweeps() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TestClock(AtomicI64::new(0)));
    let v = open(dir.path(), Arc::clone(&clock));
    v.create_dataset(&DatasetSpec::new("crm", "CRM", "offline"))
        .unwrap();
    for day in 0..5 {
        clock.0.store(day * 86_400, Ordering::SeqCst);
        v.append_activity(rec(&v, "crm", Verdict::Released))
            .unwrap();
    }
    assert_eq!(v.verify_activity_chain().unwrap(), 5);
    clock.0.store(4 * 86_400 - 10, Ordering::SeqCst);
    assert_eq!(
        v.sweep_activity(2).unwrap(),
        2,
        "records older than two days go (days 0 and 1)"
    );
    assert_eq!(
        v.verify_activity_chain().unwrap(),
        3,
        "the chain verifies from the oldest kept row"
    );
    v.checkpoint().unwrap();
    drop(v);
    let c = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
    c.execute("UPDATE activity SET record = replace(record, '\"count\":2', '\"count\":7') WHERE seq = (SELECT max(seq) - 1 FROM activity)", []).unwrap();
    drop(c);
    let v = open(dir.path(), clock);
    assert!(matches!(
        v.verify_activity_chain(),
        Err(VaultError::ActivityChain(_))
    ));
}

#[test]
fn v2_file_migrates_to_the_current_version_with_an_empty_activity_table() {
    let dir = tempfile::tempdir().unwrap();
    let v = open(dir.path(), Arc::new(TestClock(AtomicI64::new(1))));
    v.create_dataset(&DatasetSpec::new("crm", "CRM", "offline"))
        .unwrap();
    v.checkpoint().unwrap();
    drop(v);
    let c = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
    // Simulate a v2 file: the migration then walks every later version.
    common::downgrade_to(&c, 2);
    drop(c);
    let v = open(dir.path(), Arc::new(TestClock(AtomicI64::new(1))));
    assert!(
        v.activity(&ActivityFilter {
            dataset: None,
            since: None,
            limit: 1
        })
        .unwrap()
        .is_empty()
    );
    assert_eq!(v.dataset("crm").unwrap().id, "crm");
    drop(v);
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
fn a_row_with_an_extra_key_fails_to_load() {
    let dir = tempfile::tempdir().unwrap();
    let v = open(dir.path(), Arc::new(TestClock(AtomicI64::new(1))));
    v.create_dataset(&DatasetSpec::new("crm", "CRM", "offline"))
        .unwrap();
    v.append_activity(rec(&v, "crm", Verdict::Released))
        .unwrap();
    v.checkpoint().unwrap();
    drop(v);
    let c = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
    c.execute(
        &format!("UPDATE activity SET record = replace(record, '{{', '{{\"note\":\"{CANARY}\",')"),
        [],
    )
    .unwrap();
    drop(c);
    let v = open(dir.path(), Arc::new(TestClock(AtomicI64::new(1))));
    let e = v
        .activity(&ActivityFilter {
            dataset: None,
            since: None,
            limit: 10,
        })
        .unwrap_err();
    assert!(matches!(e, VaultError::ActivityRecord), "{e:?}");
}

/// A wall-clock step back leaves a young row between old ones; the sweep
/// deletes a prefix, so the chain still verifies (review I2).
#[test]
fn a_clock_step_back_never_leaves_a_hole_in_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TestClock(AtomicI64::new(0)));
    let v = open(dir.path(), Arc::clone(&clock));
    v.create_dataset(&DatasetSpec::new("crm", "CRM", "offline"))
        .unwrap();
    for day in [5, 1, 6, 7] {
        clock.0.store(day * 86_400, Ordering::SeqCst);
        v.append_activity(rec(&v, "crm", Verdict::Released))
            .unwrap();
    }
    clock.0.store(6 * 86_400 + 10, Ordering::SeqCst);
    // cutoff day 4: the row stamped day 1 is expired, and it follows the
    // day-5 row, so both go; the day-6 and day-7 rows stay.
    assert_eq!(v.sweep_activity(2).unwrap(), 2);
    assert_eq!(v.verify_activity_chain().unwrap(), 2);
    let kept: Vec<i64> = v
        .activity(&ActivityFilter::default())
        .unwrap()
        .iter()
        .map(|r| r.at / 86_400)
        .collect();
    assert_eq!(kept, [7, 6]);
    assert_eq!(v.sweep_activity(30).unwrap(), 0, "nothing expired");
}

/// Sweeps and verification run in chunks; both cross chunk boundaries
/// correctly, and an edit in a later chunk is still found.
#[test]
fn sweep_and_verify_work_across_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TestClock(AtomicI64::new(0)));
    let v = open(dir.path(), Arc::clone(&clock));
    v.create_dataset(&DatasetSpec::new("crm", "CRM", "offline"))
        .unwrap();
    let chunk = inumaki_vault::activity::CHUNK;
    let batch = |n: usize| {
        (0..n)
            .map(|_| rec(&v, "crm", Verdict::Released))
            .collect::<Vec<_>>()
    };
    v.append_activities(batch(chunk * 2 + 5)).unwrap();
    clock.0.store(10 * 86_400, Ordering::SeqCst);
    v.append_activities(batch(chunk + 7)).unwrap();
    assert_eq!(v.verify_activity_chain().unwrap(), chunk * 3 + 12);
    clock.0.store(11 * 86_400, Ordering::SeqCst);
    assert_eq!(v.sweep_activity(5).unwrap(), chunk * 2 + 5);
    assert_eq!(v.verify_activity_chain().unwrap(), chunk + 7);
    v.checkpoint().unwrap();
    drop(v);
    let c = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
    c.execute(
        "UPDATE activity SET record = replace(record, '\"count\":2', '\"count\":7') WHERE seq = (SELECT max(seq) - 2 FROM activity)",
        [],
    )
    .unwrap();
    drop(c);
    let v = open(dir.path(), clock);
    assert!(matches!(
        v.verify_activity_chain(),
        Err(VaultError::ActivityChain(_))
    ));
}
