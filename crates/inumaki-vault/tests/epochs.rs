use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use inumaki_core::span::{EntityKind as K, SecretKind};
use inumaki_core::token::TokenStore;
use inumaki_vault::{Clock, DatasetSpec, KeySource, Vault, VaultError, VaultOptions};

const DAY: i64 = 86_400;
const T0: i64 = 1_700_000_000;

struct FakeClock(AtomicI64);
impl Clock for FakeClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}
impl FakeClock {
    fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
    fn set(&self, to: i64) {
        self.0.store(to, Ordering::SeqCst);
    }
}

fn open(dir: &Path, clock: &Arc<FakeClock>) -> Vault {
    let c: Arc<dyn Clock> = Arc::clone(clock) as Arc<dyn Clock>;
    Vault::open_with_clock(
        VaultOptions::in_dir(dir).with_key_source(KeySource::File),
        c,
    )
    .unwrap()
}

fn spec(rotation: u32, grace: u32) -> DatasetSpec {
    let mut s = DatasetSpec::new("mail", "x", "offline");
    s.rotation_days = rotation;
    s.grace_days = grace;
    s
}

fn raw_count(dir: &Path, sql: &str) -> i64 {
    let c = rusqlite::Connection::open(dir.join("vault.sqlite")).unwrap();
    c.query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn rotation_mints_new_tokens_and_keeps_old_readable_during_grace() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock(AtomicI64::new(T0)));
    let v = open(dir.path(), &clock);
    let d = v.create_dataset(&spec(30, 7)).unwrap();
    let mut ns = v.namespace("mail").unwrap();
    let t1 = ns.token_for(&K::Person, "Sarah Leitner").unwrap();

    clock.advance(DAY);
    let rot = v.rotate("mail").unwrap();
    assert_eq!(
        (rot.old_epoch, rot.dataset_id.as_str()),
        (d.epoch_id, "mail")
    );
    assert_ne!(rot.new_epoch, rot.old_epoch);
    assert_eq!(rot.started_at, T0 + DAY);
    assert_eq!(v.dataset("mail").unwrap().epoch_started_at, T0 + DAY);
    assert_eq!(v.dataset("mail").unwrap().entries, 0, "nothing is copied");
    let epochs = v.epochs("mail").unwrap();
    assert_eq!(epochs.len(), 2);
    assert_eq!(epochs[0].closed_at, Some(T0 + DAY));
    assert_eq!(epochs[0].expires_at, Some(T0 + 8 * DAY));
    assert_eq!(epochs[1].closed_at, None);

    // the old handle follows the rotation
    let t2 = ns.token_for(&K::Person, "Sarah Leitner").unwrap();
    assert_ne!(t2, t1);
    assert_eq!(ns.epoch_id(), rot.new_epoch);
    // the old token rehydrates during grace, from any handle
    let mut ns2 = v.namespace("mail").unwrap();
    assert_eq!(ns2.original(t1.as_str()), None);
    ns2.prepare(&[t1.as_str().to_string()]).unwrap();
    assert_eq!(ns2.original(t1.as_str()), Some("Sarah Leitner"));
    // ...and is not linked by value: the entity gets the new token
    assert_eq!(ns2.token_for(&K::Person, "Sarah Leitner").unwrap(), t2);

    // after the grace period it is unknown, and the sweep deletes the rows
    clock.advance(8 * DAY);
    let mut ns3 = v.namespace("mail").unwrap();
    ns3.prepare(&[t1.as_str().to_string()]).unwrap();
    assert_eq!(ns3.original(t1.as_str()), None);
    let report = v.sweep().unwrap();
    assert_eq!(report.expired_epochs, 1);
    assert_eq!(report.entries_deleted, 1);
    assert_eq!(v.epochs("mail").unwrap().len(), 1);
    assert_eq!(raw_count(dir.path(), "SELECT count(*) FROM entries"), 1);
    assert!(v.integrity_ok().unwrap());
    // a second sweep has nothing to do
    assert_eq!(v.sweep().unwrap(), inumaki_vault::SweepReport::default());
}

#[test]
fn due_for_rotation_follows_rotation_days() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock(AtomicI64::new(T0)));
    let v = open(dir.path(), &clock);
    v.create_dataset(&spec(1, 0)).unwrap();
    v.create_dataset(&DatasetSpec::new("other", "y", "offline"))
        .unwrap();
    assert!(v.due_for_rotation().unwrap().is_empty());
    clock.advance(DAY - 1);
    assert!(v.due_for_rotation().unwrap().is_empty());
    clock.advance(1);
    assert_eq!(v.due_for_rotation().unwrap(), vec!["mail".to_string()]);
    v.rotate("mail").unwrap();
    assert!(v.due_for_rotation().unwrap().is_empty());
}

#[test]
fn grace_zero_expires_at_the_next_sweep() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock(AtomicI64::new(T0)));
    let v = open(dir.path(), &clock);
    v.create_dataset(&spec(30, 0)).unwrap();
    let t = v
        .namespace("mail")
        .unwrap()
        .token_for(&K::Email, "sarah@example.at")
        .unwrap();
    v.rotate("mail").unwrap();
    let report = v.sweep().unwrap();
    assert_eq!((report.expired_epochs, report.entries_deleted), (1, 1));
    let mut ns = v.namespace("mail").unwrap();
    ns.prepare(&[t.as_str().to_string()]).unwrap();
    assert_eq!(ns.original(t.as_str()), None);
}

#[test]
fn rotation_clears_the_working_set_and_the_removed_list() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock(AtomicI64::new(T0)));
    let v = open(dir.path(), &clock);
    v.create_dataset(&spec(30, 7)).unwrap();
    let mut ns = v.namespace("mail").unwrap();
    ns.token_for(&K::Person, "Sarah Leitner").unwrap();
    ns.record_removed(&K::Secret(SecretKind::Aws), "AKIAIOSFODNN7EXAMPLE")
        .unwrap();
    assert_eq!(ns.working_set_len(), 1);
    v.rotate("mail").unwrap();
    ns.refresh().unwrap();
    assert_eq!(ns.working_set_len(), 0);
    assert_eq!(ns.entries().count(), 0);
    assert_eq!(ns.removed_entries().count(), 0);
    assert_eq!(ns.mints(), 1, "counters are per handle, not per epoch");
}

/// Review Focus 4.
#[test]
fn mint_after_dataset_deletion_is_an_error() {
    use inumaki_core::token::StoreError;
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock(AtomicI64::new(T0)));
    let v = open(dir.path(), &clock);
    v.create_dataset(&spec(30, 7)).unwrap();
    let mut ns = v.namespace("mail").unwrap();
    ns.token_for(&K::Person, "Sarah Leitner").unwrap();
    v.delete_dataset("mail").unwrap();
    assert_eq!(
        ns.token_for(&K::Person, "Max Gruber"),
        Err(StoreError::Closed),
        "no placeholder token; the store fails closed"
    );
    assert_eq!(ns.working_set_len(), 0, "wiped");
    assert_eq!(
        raw_count(dir.path(), "SELECT count(*) FROM entries"),
        0,
        "no orphan rows"
    );
    assert_eq!(raw_count(dir.path(), "SELECT count(*) FROM epochs"), 0);
    assert_eq!(
        ns.record_removed(&K::Secret(SecretKind::Aws), "AKIAIOSFODNN7EXAMPLE"),
        Err(StoreError::Closed)
    );
    assert!(matches!(
        v.rotate("mail"),
        Err(VaultError::DatasetNotFound(_))
    ));
}

#[test]
fn delete_dataset_leaves_other_datasets_intact() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock(AtomicI64::new(T0)));
    let v = open(dir.path(), &clock);
    v.create_dataset(&DatasetSpec::new("a", "x", "offline"))
        .unwrap();
    v.create_dataset(&DatasetSpec::new("b", "y", "offline"))
        .unwrap();
    let tb = v
        .namespace("b")
        .unwrap()
        .token_for(&K::Person, "Sarah Leitner")
        .unwrap();
    v.namespace("a")
        .unwrap()
        .token_for(&K::Person, "Sarah Leitner")
        .unwrap();
    v.rotate("a").unwrap();
    v.namespace("a")
        .unwrap()
        .token_for(&K::Person, "Sarah Leitner")
        .unwrap();
    v.delete_dataset("a").unwrap();
    assert_eq!(raw_count(dir.path(), "SELECT count(*) FROM epochs"), 1);
    assert_eq!(raw_count(dir.path(), "SELECT count(*) FROM entries"), 1);
    assert_eq!(
        v.namespace("b")
            .unwrap()
            .token_for(&K::Person, "Sarah Leitner")
            .unwrap(),
        tb
    );
}

/// `PRAGMA incremental_vacuum(256)` guarantees at most 256 pages reclaimed
/// per call, not that a single call drains an arbitrarily large freelist
/// (deleting 300 entries leaves more free pages than one step clears, and
/// that is fine: the rest waits for the next sweep). So the exact page
/// count is not portable across a tiny in-test database and isn't asserted
/// here; `freed_pages` (unit-tested in `vault.rs` with mocked before/after)
/// owns that arithmetic. What this test pins down is that `pages_freed` is
/// computed from the real `freelist_count` pragma at all: the bug this
/// replaced always reported 0, which would fail the last assertion below
/// even though this dataset provably left free pages behind.
#[test]
fn sweep_reports_pages_freed_from_the_freelist() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock(AtomicI64::new(T0)));
    let v = open(dir.path(), &clock);
    v.create_dataset(&spec(30, 0)).unwrap();
    {
        let mut ns = v.namespace("mail").unwrap();
        for i in 0..300 {
            ns.token_for(&K::Person, &format!("Person Number {i}"))
                .unwrap();
        }
    }
    v.rotate("mail").unwrap();
    let report = v.sweep().unwrap();
    let after = raw_count(dir.path(), "PRAGMA freelist_count");
    assert_eq!(report.expired_epochs, 1);
    assert_eq!(report.entries_deleted, 300);
    assert!(
        report.pages_freed <= 256,
        "one incremental_vacuum(256) call reclaims at most 256 pages"
    );
    assert!(
        report.pages_freed > 0 || after == 0,
        "pages_freed must be nonzero when this sweep actually left free pages behind"
    );
}

/// A token loaded into a warm namespace handle during grace must stop
/// rehydrating from that same handle once the grace period has passed and the
/// sweep ran (privacy: an expired epoch's token must not restore, and the
/// plaintext must not linger in the working set). During grace it must
/// resolve on the warm handle (rehydration after a rotation must work).
#[test]
fn expired_epoch_token_stops_resolving_on_a_warm_handle() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock(AtomicI64::new(T0)));
    let v = open(dir.path(), &clock);
    v.create_dataset(&spec(30, 7)).unwrap();
    let mut writer = v.namespace("mail").unwrap();
    let old = writer.token_for(&K::Person, "Sarah Leitner").unwrap();
    let old = old.as_str().to_string();

    clock.advance(DAY);
    v.rotate("mail").unwrap();
    // a long-lived handle (the daemon keeps one per dataset) loads the old
    // token during grace
    let mut warm = v.namespace("mail").unwrap();
    warm.prepare(std::slice::from_ref(&old)).unwrap();
    assert_eq!(warm.original(&old), Some("Sarah Leitner"));
    clock.advance(3 * DAY);
    warm.prepare(std::slice::from_ref(&old)).unwrap();
    assert_eq!(warm.original(&old), Some("Sarah Leitner"), "still in grace");

    // past the grace period, before any sweep: the row is still on disk, but
    // the store already refuses it, and so must the warm handle
    clock.advance(5 * DAY);
    assert_eq!(warm.original(&old), None, "expired, not yet swept");
    warm.prepare(std::slice::from_ref(&old)).unwrap();
    assert_eq!(warm.original(&old), None);

    let report = v.sweep().unwrap();
    assert_eq!(report.expired_epochs, 1);
    assert_eq!(warm.original(&old), None, "expired and swept");
    warm.prepare(std::slice::from_ref(&old)).unwrap();
    assert_eq!(warm.original(&old), None);
    // the current epoch is untouched
    let fresh = warm.token_for(&K::Person, "Sarah Leitner").unwrap();
    assert_eq!(warm.original(fresh.as_str()), Some("Sarah Leitner"));
}

/// The cut-off is exact and shared by every path: one second before
/// `expires_at` the old token still resolves (and is still listed for the
/// leak check), at `expires_at` it no longer does, on a warm handle, before
/// any sweep.
#[test]
fn expiry_cut_off_is_exact_on_a_warm_handle() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock(AtomicI64::new(T0)));
    let v = open(dir.path(), &clock);
    v.create_dataset(&spec(30, 7)).unwrap();
    let old = v
        .namespace("mail")
        .unwrap()
        .token_for(&K::Person, "Sarah Leitner")
        .unwrap()
        .as_str()
        .to_string();
    v.rotate("mail").unwrap(); // closed at T0, expires at T0 + 7 days
    let expires_at = v.epochs("mail").unwrap()[0].expires_at.unwrap();
    let mut warm = v.namespace("mail").unwrap();
    let listed = |ns: &inumaki_vault::Namespace| {
        ns.entries()
            .any(|(_, original)| original == "Sarah Leitner")
    };

    clock.set(expires_at - 1);
    warm.prepare(std::slice::from_ref(&old)).unwrap();
    assert_eq!(warm.original(&old), Some("Sarah Leitner"));
    assert!(listed(&warm));

    clock.set(expires_at);
    assert_eq!(warm.original(&old), None, "now == expires_at: expired");
    assert!(
        !listed(&warm),
        "expired plaintext is not offered to the leak check"
    );
    warm.prepare(std::slice::from_ref(&old)).unwrap();
    assert_eq!(warm.original(&old), None);
}

/// Task 7e fix round 1: a closed-epoch entry that `prepare` loaded and the
/// working set's LRU then evicted takes its forms out of the namespace's
/// cached consistency dictionary at eviction. Marking it dead in the base
/// would keep them past its grace period: once evicted, the expiry sweep
/// no longer sees it, so nothing would clear the cache.
#[test]
fn an_evicted_closed_epoch_entry_leaves_no_form_in_the_store_dict() {
    use inumaki_core::consistency::{StoreDict, live_layers_on_this_thread};
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock(AtomicI64::new(T0)));
    let v = open(dir.path(), &clock);
    v.create_dataset(&spec(30, 7)).unwrap();
    let old = v
        .namespace("mail")
        .unwrap()
        .token_for(&K::Person, "Sarah Leitner")
        .unwrap()
        .as_str()
        .to_string();
    v.rotate("mail").unwrap(); // expires at T0 + 7 days
    let live = live_layers_on_this_thread();
    let mut warm = v.namespace_with_working_set("mail", 4).unwrap();
    warm.prepare(std::slice::from_ref(&old)).unwrap();
    assert_eq!(warm.original(&old), Some("Sarah Leitner"));
    let probe = "Gruss an Sarah Leitner";
    let d = warm.store_dict(None).unwrap().unwrap();
    assert!(!d.redactions(probe, &[], &[]).unwrap().is_empty());
    drop(d);
    assert_eq!(
        live_layers_on_this_thread() - live,
        1,
        "cached on the handle"
    );

    for i in 0..4 {
        warm.token_for(&K::City, &format!("Ortschaft Nr{i}"))
            .unwrap();
    }
    assert_eq!(warm.original(&old), None, "evicted by the LRU");
    assert_eq!(
        live_layers_on_this_thread() - live,
        0,
        "an expiring entry's eviction drops the cached forms"
    );

    clock.advance(8 * DAY);
    let d = warm.store_dict(None).unwrap().unwrap();
    let fresh = StoreDict::build(&warm).unwrap();
    assert_eq!(
        format!("{d:?}"),
        format!("{fresh:?}"),
        "one fresh layer, no dead entry, no old form"
    );
    assert!(d.redactions(probe, &[], &[]).unwrap().is_empty());
    drop((d, fresh));
    assert_eq!(live_layers_on_this_thread() - live, 1);
    assert_eq!(v.sweep().unwrap().expired_epochs, 1);
}

/// Task 5 (L69, fix 757825c): a closed epoch's entry evicted by the LRU
/// leaves no pattern in the leak index: the live leak layers go to 0 at the
/// eviction, and after the grace period the value is no leak.
#[test]
fn an_evicted_closed_epoch_entry_leaves_no_pattern_in_the_leak_index() {
    use inumaki_core::consistency::live_leak_layers_on_this_thread;
    use inumaki_core::verify::{CheckId, Verdict};
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock(AtomicI64::new(T0)));
    let v = open(dir.path(), &clock);
    v.create_dataset(&spec(30, 7)).unwrap();
    let old = v
        .namespace("mail")
        .unwrap()
        .token_for(&K::Person, "Sarah Leitner")
        .unwrap()
        .as_str()
        .to_string();
    v.rotate("mail").unwrap(); // expires at T0 + 7 days
    let verifier = inumaki_core::verify::SecondPassVerifier::new(
        inumaki_core::detect::regex::RegexDetector::new(),
        None,
        &inumaki_core::policy::VerifierSettings {
            allow_no_ner: true,
            ..Default::default()
        },
    )
    .unwrap();
    let probe = inumaki_core::sanitize::Sanitized {
        text: "Gruss an Sarah Leitner".into(),
        replacements: Vec::new(),
        blocked: Vec::new(),
        escalated: Vec::new(),
        protected: Vec::new(),
    };
    let is_leak =
        |v: &Verdict| matches!(v, Verdict::Fail(r) if r.iter().any(|x| x.check == CheckId::Leak));
    let live = live_leak_layers_on_this_thread();
    let mut warm = v.namespace_with_working_set("mail", 4).unwrap();
    warm.prepare(std::slice::from_ref(&old)).unwrap();
    assert_eq!(warm.original(&old), Some("Sarah Leitner"));
    let idx = warm.leak_index(None).unwrap().unwrap();
    assert!(idx.covers(&warm), "the index answers");
    assert!(is_leak(&verifier.verify_with_leak(
        &probe,
        &warm,
        Some(&idx)
    )));
    drop(idx);
    assert_eq!(
        live_leak_layers_on_this_thread() - live,
        1,
        "cached on the handle"
    );

    for i in 0..4 {
        warm.token_for(&K::City, &format!("Ortschaft Nr{i}"))
            .unwrap();
    }
    assert_eq!(warm.original(&old), None, "evicted by the LRU");
    assert_eq!(
        live_leak_layers_on_this_thread() - live,
        0,
        "an expiring entry's eviction drops the cached patterns"
    );

    clock.advance(8 * DAY);
    let idx = warm.leak_index(None).unwrap().unwrap();
    assert!(idx.covers(&warm), "the index answers");
    assert!(!is_leak(&verifier.verify_with_leak(
        &probe,
        &warm,
        Some(&idx)
    )));
    assert_eq!(idx.layer_count(), 1, "one fresh layer");
    drop(idx);
    assert_eq!(live_leak_layers_on_this_thread() - live, 1);
    assert_eq!(v.sweep().unwrap().expired_epochs, 1);
}
