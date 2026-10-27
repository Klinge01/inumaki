//! M8 spec §5.3: a dataset token resolves to its owning dataset through the
//! global unique index; a token of an expired epoch does not.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use inumaki_core::span::EntityKind;
use inumaki_core::token::TokenStore;
use inumaki_vault::{Clock, DatasetSpec, KeySource, Vault, VaultOptions};

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
}

fn clocked(dir: &Path, clock: &Arc<FakeClock>) -> Vault {
    let c: Arc<dyn Clock> = Arc::clone(clock) as Arc<dyn Clock>;
    Vault::open_with_clock(
        VaultOptions::in_dir(dir).with_key_source(KeySource::File),
        c,
    )
    .unwrap()
}

fn vault(dir: &std::path::Path) -> Vault {
    Vault::open(VaultOptions::in_dir(dir).with_key_source(KeySource::File)).unwrap()
}

#[test]
fn a_token_resolves_to_its_owning_dataset_only() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    v.create_dataset(&DatasetSpec::new("kunden", "Kunden", "offline"))
        .unwrap();
    v.create_dataset(&DatasetSpec::new("lieferanten", "Lieferanten", "offline"))
        .unwrap();
    let mut a = v.namespace("kunden").unwrap();
    let t = a
        .token_for(&EntityKind::Person, "Zyxwuria Quolnath")
        .unwrap();
    assert_eq!(
        v.dataset_of_token(t.as_str()).unwrap().as_deref(),
        Some("kunden")
    );
    assert_eq!(v.dataset_of_token("<PERSON_ffffff>").unwrap(), None);
}

#[test]
fn chat_is_a_dataset_kind() {
    assert_eq!(
        inumaki_vault::DatasetKind::parse("chat"),
        Some(inumaki_vault::DatasetKind::Chat)
    );
    assert_eq!(inumaki_vault::DatasetKind::Chat.as_str(), "chat");
}

/// Fail closed: a token of a rotated epoch resolves only while the epoch is
/// inside its grace period (`expires_at > now`), and not a second longer.
#[test]
fn a_rotated_epochs_token_resolves_only_inside_its_grace_period() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock(AtomicI64::new(T0)));
    let v = clocked(dir.path(), &clock);
    let mut spec = DatasetSpec::new("kunden", "Kunden", "offline");
    spec.rotation_days = 30;
    spec.grace_days = 7;
    v.create_dataset(&spec).unwrap();
    let mut ns = v.namespace("kunden").unwrap();
    let old = ns
        .token_for(&EntityKind::Person, "Zyxwuria Quolnath")
        .unwrap();
    assert_eq!(
        v.dataset_of_token(old.as_str()).unwrap().as_deref(),
        Some("kunden")
    );

    clock.advance(DAY);
    v.rotate("kunden").unwrap(); // closed_at = T0 + DAY, expires_at = T0 + 8 days
    let new = ns
        .token_for(&EntityKind::Person, "Zyxwuria Quolnath")
        .unwrap();
    assert_ne!(new, old);

    // closed but in grace: still the owner; the new epoch's token too
    clock.advance(7 * DAY - 1);
    assert_eq!(
        v.dataset_of_token(old.as_str()).unwrap().as_deref(),
        Some("kunden")
    );
    assert_eq!(
        v.dataset_of_token(new.as_str()).unwrap().as_deref(),
        Some("kunden")
    );

    // exactly at expiry (expires_at > now no longer holds): unknown, before any sweep
    clock.advance(1);
    assert_eq!(v.dataset_of_token(old.as_str()).unwrap(), None);
    assert_eq!(
        v.dataset_of_token(new.as_str()).unwrap().as_deref(),
        Some("kunden"),
        "the current epoch never expires"
    );
    clock.advance(DAY);
    assert_eq!(v.dataset_of_token(old.as_str()).unwrap(), None);
}

/// Fail closed: a forgotten entity's token has no owner, and a row flagged
/// `removed` is skipped even if it is still stored.
#[test]
fn a_forgotten_or_removed_entry_has_no_owner() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    v.create_dataset(&DatasetSpec::new("kunden", "Kunden", "offline"))
        .unwrap();
    let mut ns = v.namespace("kunden").unwrap();
    let a = ns
        .token_for(&EntityKind::Person, "Zyxwuria Quolnath")
        .unwrap();
    let b = ns
        .token_for(&EntityKind::Person, "Brandolf Quixmere")
        .unwrap();

    v.forget_by_token("kunden", a.as_str()).unwrap();
    assert_eq!(v.dataset_of_token(a.as_str()).unwrap(), None);
    assert_eq!(
        v.dataset_of_token(b.as_str()).unwrap().as_deref(),
        Some("kunden"),
        "other entities are unaffected"
    );

    // the `removed` flag itself (set directly: no API sets it today)
    let raw = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
    raw.execute(
        "UPDATE entries SET removed = 1 WHERE token = ?1",
        [b.as_str()],
    )
    .unwrap();
    drop(raw);
    assert_eq!(v.dataset_of_token(b.as_str()).unwrap(), None);
}

/// The proxy's light listing: every dataset, in creation order (ties by
/// id), with the same ids, kinds, and times as the full listing.
#[test]
fn dataset_heads_list_every_dataset_in_creation_order() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock(AtomicI64::new(T0)));
    let v = clocked(dir.path(), &clock);
    v.create_dataset(&DatasetSpec::new("zeta", "Z", "offline"))
        .unwrap();
    clock.advance(DAY);
    let mut chat = DatasetSpec::new("inumaki-chat", "C", "offline");
    chat.kind = inumaki_vault::DatasetKind::Chat;
    v.create_dataset(&chat).unwrap();
    v.create_dataset(&DatasetSpec::new("alpha", "A", "offline"))
        .unwrap();
    let heads = v.dataset_heads().unwrap();
    let ids: Vec<&str> = heads.iter().map(|h| h.id.as_str()).collect();
    assert_eq!(ids, ["zeta", "alpha", "inumaki-chat"]);
    for h in &heads {
        let d = v.dataset(&h.id).unwrap();
        assert_eq!((h.kind, h.created_at), (d.kind, d.created_at));
    }
}
