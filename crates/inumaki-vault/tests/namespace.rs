use std::path::Path;
use std::sync::Arc;

use inumaki_core::TokenSettings;
use inumaki_core::rehydrate::Rehydrator;
use inumaki_core::span::{EntityKind as K, SecretKind};
use inumaki_core::token::TokenStore;
use inumaki_vault::{DatasetSpec, KeySource, Vault, VaultOptions};

fn opts(dir: &Path) -> VaultOptions {
    VaultOptions::in_dir(dir).with_key_source(KeySource::File)
}

fn vault_with(dir: &Path, ids: &[&str]) -> Vault {
    let v = Vault::open(opts(dir)).unwrap();
    for id in ids {
        v.create_dataset(&DatasetSpec::new(id, "Kunde", "offline"))
            .unwrap();
    }
    v
}

/// The same checks as `inumaki-core`'s `token::tests::conformance`.
fn conformance(store: &mut dyn TokenStore) {
    let n = store.settings().suffix_len;
    let (open, close) = (
        store.settings().open.clone(),
        store.settings().close.clone(),
    );
    let t = store.token_for(&K::Person, "Sarah Leitner").unwrap();
    assert!(
        t.as_str().starts_with(&format!("{open}PERSON_")),
        "{}",
        t.as_str()
    );
    assert!(t.as_str().ends_with(&close));
    let suffix = &t.as_str()[open.len() + "PERSON_".len()..t.as_str().len() - close.len()];
    assert_eq!(suffix.len(), n);
    assert!(
        suffix
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    assert_eq!(store.token_for(&K::Person, "SARAH  LEITNER").unwrap(), t);
    assert_eq!(store.token_for(&K::Person, "sarah leitner").unwrap(), t);
    assert_eq!(store.original(t.as_str()), Some("Sarah Leitner"));
    assert_eq!(
        store.original(&format!("{open}PERSON_{}{close}", "0".repeat(n))),
        None
    );
    let city = store.token_for(&K::City, "Wien").unwrap();
    let org = store.token_for(&K::Organization, "Wien").unwrap();
    assert_ne!(city, org);
    let entries: Vec<(String, String)> = store
        .entries()
        .map(|(k, o)| (k.label().to_string(), o.to_string()))
        .collect();
    assert!(
        entries.contains(&("PERSON".into(), "Sarah Leitner".into())),
        "{entries:?}"
    );
    assert!(entries.contains(&("CITY".into(), "Wien".into())));
    let secret = K::Secret(SecretKind::Generic);
    store
        .record_removed(&secret, "9f8e7d6c5b4a3210ffee")
        .unwrap();
    store
        .record_removed(&secret, "9f8e7d6c5b4a3210ffee")
        .unwrap();
    assert_eq!(store.removed_entries().count(), 1);
    assert!(store.entries().all(|(_, o)| o != "9f8e7d6c5b4a3210ffee"));
    assert_eq!(
        store.removed_marker(&secret),
        format!("{open}SECRET_REMOVED{close}")
    );
    let mut seen = std::collections::HashSet::new();
    for i in 0..200 {
        assert!(
            seen.insert(
                store
                    .token_for(&K::Person, &format!("Person Nr{i}"))
                    .unwrap()
            )
        );
    }
    store.prepare(&[t.as_str().to_string()]).unwrap();
    assert_eq!(store.original(t.as_str()), Some("Sarah Leitner"));
}

#[test]
fn namespace_conforms_to_token_store() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault_with(dir.path(), &["mail"]);
    let mut ns = v.namespace("mail").unwrap();
    conformance(&mut ns);
    assert_eq!(ns.settings().suffix_len, 6);
    assert_eq!(v.dataset("mail").unwrap().entries, 203);
}

#[test]
fn same_entity_same_token_across_handles_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault_with(dir.path(), &["mail"]);
    let t = v
        .namespace("mail")
        .unwrap()
        .token_for(&K::Person, "Sarah Leitner")
        .unwrap();
    assert_eq!(
        v.namespace("mail")
            .unwrap()
            .token_for(&K::Person, "sarah leitner")
            .unwrap(),
        t
    );
    drop(v);
    let v = Vault::open(opts(dir.path())).unwrap();
    let mut ns = v.namespace("mail").unwrap();
    assert_eq!(ns.token_for(&K::Person, "Sarah Leitner").unwrap(), t);
    assert_eq!(ns.original(t.as_str()), Some("Sarah Leitner"));
    assert_eq!(ns.mints(), 0, "a lookup is not a mint");
}

#[test]
fn hmac_index_never_stores_normkey_or_original() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault_with(dir.path(), &["mail"]);
    v.namespace("mail")
        .unwrap()
        .token_for(&K::Person, "Zyxwuria Quolnath")
        .unwrap();
    v.checkpoint().unwrap();
    let bytes = std::fs::read(dir.path().join("vault.sqlite")).unwrap();
    for needle in [
        &b"Zyxwuria"[..],
        &b"zyxwuria quolnath"[..],
        &b"Quolnath"[..],
    ] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle),
            "{} found in the vault file",
            String::from_utf8_lossy(needle)
        );
    }
}

#[test]
fn tokens_are_unique_across_two_namespaces() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault_with(dir.path(), &["a", "b"]);
    let ta = v
        .namespace("a")
        .unwrap()
        .token_for(&K::Person, "Sarah Leitner")
        .unwrap();
    let tb = v
        .namespace("b")
        .unwrap()
        .token_for(&K::Person, "Sarah Leitner")
        .unwrap();
    assert_ne!(ta, tb);
    // the unique index is what enforces it: a duplicate token row is refused
    let c = rusqlite::Connection::open(dir.path().join("vault.sqlite")).unwrap();
    let e = c
        .execute(
            "INSERT INTO entries (epoch_id, kind, key_hmac, token, nonce, value, removed, last_used) \
             VALUES ((SELECT id FROM epochs WHERE dataset_id = 'b'), 'PERSON', x'01', ?1, x'00', x'00', 0, 0)",
            [ta.as_str()],
        )
        .unwrap_err();
    assert!(e.to_string().contains("entries.token"), "{e}");
}

#[test]
fn compatible_kinds_share_tokens_and_bare_surnames_are_entities_of_their_own() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault_with(dir.path(), &["mail"]);
    let mut ns = v.namespace("mail").unwrap();
    let full = ns.token_for(&K::Person, "Sarah Leitner").unwrap();
    // Plan 4a: the store no longer links a bare surname to a full name; the
    // linker (`sanitize_linked`) does that through `surface_token`.
    let bare = ns.token_for(&K::Person, "Leitner").unwrap();
    assert_ne!(bare, full);
    assert_eq!(ns.original(bare.as_str()), Some("Leitner"));
    assert_eq!(ns.token_for(&K::Person, "leitner").unwrap(), bare);
    ns.token_for(&K::Person, "Max Gruber").unwrap();
    ns.token_for(&K::Person, "Eva Gruber").unwrap();
    let g = ns.token_for(&K::Person, "Gruber").unwrap();
    assert_ne!(g, ns.token_for(&K::Person, "Max Gruber").unwrap());
    assert_ne!(g, ns.token_for(&K::Person, "Eva Gruber").unwrap());
    assert_ne!(
        ns.token_for(&K::Organization, "Leitner").unwrap(),
        full,
        "different kind"
    );
}

#[test]
fn working_set_is_bounded_and_evicted_entries_come_back_from_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault_with(dir.path(), &["mail"]);
    let mut ns = v.namespace_with_working_set("mail", 8).unwrap();
    let first = ns.token_for(&K::Person, "Person Nr0").unwrap();
    for i in 1..30 {
        ns.token_for(&K::Person, &format!("Person Nr{i}")).unwrap();
    }
    assert!(ns.working_set_len() <= 8, "{}", ns.working_set_len());
    assert_eq!(ns.entries().count(), ns.working_set_len());
    assert_eq!(
        ns.original(first.as_str()),
        None,
        "evicted from the working set"
    );
    assert_eq!(
        ns.token_for(&K::Person, "Person Nr0").unwrap(),
        first,
        "found again in the store"
    );
    assert_eq!(ns.original(first.as_str()), Some("Person Nr0"));
    assert!(ns.working_set_len() <= 8);
    assert_eq!(v.dataset("mail").unwrap().entries, 30);
}

/// Fix round 1, minor 6: `surface_token` must load a parent that has fallen
/// out of the working set (but is still in the store) before declaring it
/// unknown.
#[test]
fn surface_token_reloads_a_parent_evicted_from_the_working_set() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault_with(dir.path(), &["mail"]);
    let mut ns = v.namespace_with_working_set("mail", 8).unwrap();
    let first = ns.token_for(&K::Person, "Person Nr0").unwrap();
    for i in 1..30 {
        ns.token_for(&K::Person, &format!("Person Nr{i}")).unwrap();
    }
    assert_eq!(
        ns.original(first.as_str()),
        None,
        "evicted from the working set"
    );
    let x = ns.surface_token(&first, "x").unwrap();
    assert_ne!(x, first, "a surface row of its own");
    assert_eq!(
        ns.original(x.as_str()),
        Some("x"),
        "reloaded from the store instead of failing UnknownParent"
    );
    assert_eq!(ns.original(first.as_str()), Some("Person Nr0"));
}

#[test]
fn removed_values_persist_for_the_leak_check() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault_with(dir.path(), &["mail"]);
    let secret = K::Secret(SecretKind::Aws);
    v.namespace("mail")
        .unwrap()
        .record_removed(&secret, "AKIAIOSFODNN7EXAMPLE")
        .unwrap();
    let ns = v.namespace("mail").unwrap();
    let removed: Vec<&str> = ns.removed_entries().map(|(_, v)| v).collect();
    assert_eq!(removed, vec!["AKIAIOSFODNN7EXAMPLE"]);
    assert_eq!(ns.entries().count(), 0);
    assert_eq!(
        v.dataset("mail").unwrap().entries,
        0,
        "removed rows are not entries"
    );
}

/// Review Focus 2.
#[test]
fn concurrent_mint_of_same_entity_yields_one_token() {
    let dir = tempfile::tempdir().unwrap();
    let v = Arc::new(vault_with(dir.path(), &["mail"]));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let v = Arc::clone(&v);
            std::thread::spawn(move || {
                let mut ns = v.namespace("mail").unwrap();
                ns.token_for(&K::Person, "Sarah Leitner").unwrap()
            })
        })
        .collect();
    let tokens: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(tokens.iter().all(|t| *t == tokens[0]), "{tokens:?}");
    assert_eq!(v.dataset("mail").unwrap().entries, 1);
}

#[test]
fn prepare_loads_originals_for_rehydration() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault_with(dir.path(), &["mail"]);
    let t = v
        .namespace("mail")
        .unwrap()
        .token_for(&K::Iban, "AT611904300234573201")
        .unwrap();
    let settings = TokenSettings {
        suffix_len: 6,
        ..TokenSettings::default()
    };
    let r = Rehydrator::new(&settings);
    let mut ns = v.namespace("mail").unwrap();
    let text = format!("Konto {} und <IBAN_000000>", t.as_str());
    assert_eq!(
        ns.original(t.as_str()),
        None,
        "fresh handle, nothing loaded yet"
    );
    let (out, unknown) = r.rehydrate_mut(&text, &mut ns).unwrap();
    assert_eq!(out, "Konto AT611904300234573201 und <IBAN_000000>");
    assert_eq!(unknown, 1);
}

#[test]
fn token_space_exhaustion_is_an_error() {
    use inumaki_core::token::StoreError;
    let dir = tempfile::tempdir().unwrap();
    let mut o = opts(dir.path());
    o.tokens.suffix_len = 1; // 16 tokens per kind
    let v = Vault::open(o).unwrap();
    v.create_dataset(&DatasetSpec::new("mail", "x", "offline"))
        .unwrap();
    let mut ns = v.namespace("mail").unwrap();
    let mut got = std::collections::HashSet::new();
    let mut exhausted = None;
    for i in 0..40 {
        match ns.token_for(&K::Person, &format!("P{i}")) {
            Ok(t) => {
                got.insert(t);
            }
            Err(e) => {
                exhausted = Some(e);
                break;
            }
        }
    }
    assert!(got.len() <= 16, "{}", got.len());
    assert_eq!(exhausted, Some(StoreError::Exhausted("PERSON".into())));
    assert_eq!(
        v.dataset("mail").unwrap().entries,
        got.len() as u64,
        "no row for the failed mint"
    );
}

/// Review Focus 4 (store side): a dataset deleted underneath an open handle
/// turns every write into `Closed` and wipes the working set.
#[test]
fn namespace_reports_closed_after_its_dataset_is_deleted() {
    use inumaki_core::token::StoreError;
    let dir = tempfile::tempdir().unwrap();
    let v = vault_with(dir.path(), &["mail"]);
    let mut ns = v.namespace("mail").unwrap();
    ns.token_for(&K::Person, "Sarah Leitner").unwrap();
    v.delete_dataset("mail").unwrap();
    assert_eq!(
        ns.token_for(&K::Person, "Max Gruber"),
        Err(StoreError::Closed)
    );
    assert_eq!(
        ns.record_removed(&K::Secret(SecretKind::Aws), "AKIAIOSFODNN7EXAMPLE"),
        Err(StoreError::Closed)
    );
    assert_eq!(ns.prepare(&[]), Err(StoreError::Closed));
    assert_eq!(ns.entries().count(), 0, "working set wiped on close");
}

/// Review I1: a surname-only mention must never link to a token loaded from
/// a closed epoch by `prepare` (a rehydrate of an older document, or a cache
/// hit's disagreement check). Otherwise the new document carries a token
/// that goes unknown once the old epoch's grace period ends, and the
/// closed-epoch token links the new document to pre-rotation traffic.
#[test]
fn surname_link_skips_closed_epoch_entries_loaded_by_prepare() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault_with(dir.path(), &["mail"]);
    let old = v
        .namespace("mail")
        .unwrap()
        .token_for(&K::Person, "Sarah Leitner")
        .unwrap();
    v.rotate("mail").unwrap();

    let mut ns = v.namespace("mail").unwrap();
    ns.prepare(&[old.as_str().to_string()]).unwrap();
    assert_eq!(
        ns.original(old.as_str()),
        Some("Sarah Leitner"),
        "prepare loaded the closed-epoch entry"
    );

    let surname = ns.token_for(&K::Person, "Leitner").unwrap();
    assert_ne!(
        surname, old,
        "a bare surname must not link to the closed epoch's token"
    );
    assert_eq!(ns.original(surname.as_str()), Some("Leitner"));
}

#[test]
fn debug_omits_originals() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault_with(dir.path(), &["mail"]);
    let mut ns = v.namespace("mail").unwrap();
    ns.token_for(&K::Person, "Sarah Leitner").unwrap();
    let d = format!("{ns:?}");
    assert!(!d.contains("Sarah"), "{d}");
    assert!(d.contains("working"));
}

/// Every consistency match of `d` in `text` as plain comparable data.
fn store_matches(
    d: &inumaki_core::consistency::StoreDict,
    text: &str,
) -> Vec<(usize, usize, String, Option<String>)> {
    let mut v: Vec<_> = d
        .redactions(text, &[], &[])
        .unwrap()
        .into_iter()
        .map(|m| {
            (
                m.redaction.start,
                m.redaction.end,
                m.redaction.kind.clone(),
                m.source.map(|s| s.to_string()),
            )
        })
        .collect();
    v.sort();
    v
}

fn ns_dict(ns: &mut inumaki_vault::Namespace) -> inumaki_core::consistency::StoreDict {
    ns.store_dict(None)
        .expect("a namespace keeps its consistency dictionary")
        .unwrap()
}

/// Task 7e (ruling L62): a namespace keeps its consistency dictionary,
/// which follows the working set (mints, LRU evictions, removed values)
/// with the same matches as a fresh build, and goes with forget, rotation,
/// and the handle itself.
#[test]
fn the_store_dict_lives_with_the_working_set() {
    use inumaki_core::consistency::{StoreDict, live_layers_on_this_thread};
    let dir = tempfile::tempdir().unwrap();
    let v = vault_with(dir.path(), &["mail"]);
    let live = live_layers_on_this_thread();
    let mut ns = v.namespace_with_working_set("mail", 8).unwrap();
    let anna = ns.token_for(&K::Person, "Anna Quorvik").unwrap();
    ns.token_for(&K::Person, "Kurt Brandlinger").unwrap();
    drop(ns_dict(&mut ns));
    assert_eq!(live_layers_on_this_thread() - live, 1, "kept on the handle");
    drop(ns_dict(&mut ns));
    assert_eq!(
        live_layers_on_this_thread() - live,
        1,
        "reused, not rebuilt"
    );
    // Evict both (working set of 8), mint more, record a removed value.
    for i in 0..10 {
        ns.token_for(&K::City, &format!("Ortschaft Nr{i}")).unwrap();
    }
    ns.record_removed(&K::Secret(SecretKind::Aws), "AKIAIOSFODNN7EXAMPLE")
        .unwrap();
    assert_eq!(ns.original(anna.as_str()), None, "evicted");
    let probes = [
        "Gruss an Anna Quorvik und Herrn Brandlinger",
        "Treffen in Ortschaft Nr9 und Ortschaft Nr1",
        "key AKIAIOSFODNN7EXAMPLE bitte",
    ];
    let cached = ns_dict(&mut ns);
    let fresh = StoreDict::build(&ns).unwrap();
    for text in probes {
        assert_eq!(store_matches(&cached, text), store_matches(&fresh, text));
    }
    assert!(
        store_matches(&cached, probes[0]).is_empty(),
        "evicted: no match"
    );
    drop((cached, fresh));
    // Reloaded into the working set: found again.
    ns.token_for(&K::Person, "Anna Quorvik").unwrap();
    let d = ns_dict(&mut ns);
    assert!(!store_matches(&d, probes[0]).is_empty());
    drop(d);
    // Forget clears the cached forms at once.
    let f = v.forget_by_token("mail", anna.as_str()).unwrap();
    ns.forget_tokens(&f.tokens).unwrap();
    assert_eq!(
        live_layers_on_this_thread() - live,
        0,
        "forget drops the forms"
    );
    assert!(store_matches(&ns_dict(&mut ns), probes[0]).is_empty());
    // Rotation, followed by this handle, clears them too.
    v.rotate("mail").unwrap();
    ns.refresh().unwrap();
    assert_eq!(
        live_layers_on_this_thread() - live,
        0,
        "rotation drops the forms"
    );
    drop(ns_dict(&mut ns));
    assert_eq!(live_layers_on_this_thread() - live, 1);
    drop(ns);
    assert_eq!(
        live_layers_on_this_thread() - live,
        0,
        "gone with the handle"
    );
}

/// A candidate with no replacements (the leak check's input).
fn leak_cand(text: &str) -> inumaki_core::sanitize::Sanitized {
    inumaki_core::sanitize::Sanitized {
        text: text.to_string(),
        replacements: Vec::new(),
        blocked: Vec::new(),
        escalated: Vec::new(),
        protected: Vec::new(),
    }
}

fn leak_verifier() -> inumaki_core::verify::SecondPassVerifier {
    let settings = inumaki_core::policy::VerifierSettings {
        allow_no_ner: true,
        ..Default::default()
    };
    inumaki_core::verify::SecondPassVerifier::new(
        inumaki_core::detect::regex::RegexDetector::new(),
        None,
        &settings,
    )
    .unwrap()
}

fn ns_leak(ns: &mut inumaki_vault::Namespace) -> inumaki_core::verify::second_pass::LeakIndex {
    ns.leak_index(None)
        .expect("a namespace keeps its leak index")
        .unwrap()
}

/// The `Leak` kinds of a verdict, as a set.
fn leak_set(v: &inumaki_core::verify::Verdict) -> std::collections::BTreeSet<String> {
    match v {
        inumaki_core::verify::Verdict::Fail(r) => r
            .iter()
            .filter(|x| x.check == inumaki_core::verify::CheckId::Leak)
            .map(|x| x.kind.label().to_string())
            .collect(),
        _ => Default::default(),
    }
}

/// Task 5 (L69): a namespace keeps its leak index in the dictionary's
/// cache: reused while unchanged, answering as a fresh per-call check after
/// LRU evictions, and gone with forget, rotation, a closed dataset, and the
/// handle itself.
#[test]
fn the_leak_index_lives_with_the_working_set() {
    use inumaki_core::consistency::{leak_builds_on_this_thread, live_leak_layers_on_this_thread};
    let dir = tempfile::tempdir().unwrap();
    let v = vault_with(dir.path(), &["mail", "other"]);
    let live = live_leak_layers_on_this_thread();
    let verifier = leak_verifier();
    let mut ns = v.namespace_with_working_set("mail", 8).unwrap();
    let anna = ns.token_for(&K::Person, "Anna Quorvik").unwrap();
    ns.token_for(&K::Person, "Kurt Brandlinger").unwrap();
    drop(ns_leak(&mut ns));
    assert_eq!(
        live_leak_layers_on_this_thread() - live,
        1,
        "kept on the handle"
    );
    let builds = leak_builds_on_this_thread();
    drop(ns_leak(&mut ns));
    assert_eq!(leak_builds_on_this_thread(), builds, "reused, not rebuilt");
    assert_eq!(live_leak_layers_on_this_thread() - live, 1);
    // Evict both (working set of 8), mint more, record a removed value.
    for i in 0..10 {
        ns.token_for(&K::City, &format!("Ortschaft Nr{i}")).unwrap();
    }
    ns.record_removed(&K::Secret(SecretKind::Aws), "AKIAIOSFODNN7EXAMPLE")
        .unwrap();
    assert_eq!(ns.original(anna.as_str()), None, "evicted");
    let probes = [
        "Gruss an Anna Quorvik und Herrn Brandlinger",
        "Treffen in Ortschaft Nr9 und Ortschaft Nr1",
        "key AKIAIOSFODNN7EXAMPLE bitte",
    ];
    let idx = ns_leak(&mut ns);
    // The index itself answers (dead base entries filtered), never the
    // per-call fallback.
    assert!(idx.covers(&ns), "the index covers the working set");
    for text in probes {
        let s = leak_cand(text);
        let cached = verifier.verify_with_leak(&s, &ns, Some(&idx));
        let fresh = verifier.verify_with_leak(&s, &ns, None);
        assert_eq!(leak_set(&cached), leak_set(&fresh), "{}", text.len());
    }
    assert!(
        leak_set(&verifier.verify_with_leak(&leak_cand(probes[0]), &ns, Some(&idx))).is_empty(),
        "an evicted value is no leak"
    );
    assert!(
        !leak_set(&verifier.verify_with_leak(&leak_cand(probes[2]), &ns, Some(&idx))).is_empty()
    );
    drop(idx);
    // Forget drops the patterns at once.
    ns.token_for(&K::Person, "Anna Quorvik").unwrap();
    drop(ns_leak(&mut ns));
    assert!(live_leak_layers_on_this_thread() - live >= 1);
    let f = v.forget_by_token("mail", anna.as_str()).unwrap();
    ns.forget_tokens(&f.tokens).unwrap();
    assert_eq!(
        live_leak_layers_on_this_thread() - live,
        0,
        "forget drops the patterns"
    );
    // Rotation, followed by this handle, drops them too.
    drop(ns_leak(&mut ns));
    assert!(live_leak_layers_on_this_thread() - live >= 1);
    v.rotate("mail").unwrap();
    ns.refresh().unwrap();
    assert_eq!(
        live_leak_layers_on_this_thread() - live,
        0,
        "rotation drops the patterns"
    );
    // A closed dataset drops them.
    ns.token_for(&K::Person, "Lena Quorvik").unwrap();
    drop(ns_leak(&mut ns));
    assert!(live_leak_layers_on_this_thread() - live >= 1);
    v.delete_dataset("mail").unwrap();
    assert!(ns.refresh().is_err());
    assert_eq!(
        live_leak_layers_on_this_thread() - live,
        0,
        "a closed dataset drops the patterns"
    );
    drop(ns);
    // Dropping the handle drops them.
    let mut other = v.namespace("other").unwrap();
    other.token_for(&K::Person, "Lena Quorvik").unwrap();
    drop(ns_leak(&mut other));
    assert_eq!(live_leak_layers_on_this_thread() - live, 1);
    drop(other);
    assert_eq!(
        live_leak_layers_on_this_thread() - live,
        0,
        "gone with the handle"
    );
}
