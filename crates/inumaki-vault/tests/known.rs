use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use inumaki_core::config::CoreConfig;
use inumaki_core::detect::{DetectCtx, Detector};
use inumaki_core::engine::{Engine, Outcome};
use inumaki_core::span::{DetectorId, EntityKind as K, Span};
use inumaki_core::token::TokenStore;
use inumaki_vault::{DatasetSpec, KeySource, Vault, VaultOptions};

fn opts(dir: &Path) -> VaultOptions {
    VaultOptions::in_dir(dir).with_key_source(KeySource::File)
}

fn vault(dir: &Path) -> Vault {
    let v = Vault::open(opts(dir)).unwrap();
    v.create_dataset(&DatasetSpec::new("mail", "x", "offline"))
        .unwrap();
    v
}

fn found(d: &dyn Detector, text: &str) -> Vec<(K, String, f32)> {
    d.detect(text, &DetectCtx::for_text(text))
        .unwrap()
        .into_iter()
        .map(|s: Span| (s.kind.clone(), s.slice(text).to_string(), s.confidence))
        .collect()
}

#[test]
fn known_entities_are_detected_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    {
        let mut ns = v.namespace("mail").unwrap();
        ns.token_for(&K::Person, "Zyxwuria Quolnath").unwrap();
        ns.token_for(&K::CustomerId, "K-928174").unwrap();
        ns.token_for(&K::City, "Wien").unwrap(); // not a known kind
    }
    let ns = v.namespace("mail").unwrap();
    assert_eq!(ns.known_entities(), 2);
    let d = ns.detector();
    assert_eq!(d.id(), DetectorId::Dictionary);
    let hits = found(
        d.as_ref(),
        "Frau ZYXWURIA QUOLNATH, Kunde K-928174 aus Wien",
    );
    assert!(
        hits.iter().any(|(k, t, c)| *k == K::Person
            && t == "ZYXWURIA QUOLNATH"
            && (*c - 0.97).abs() < 1e-6),
        "{hits:?}"
    );
    assert!(
        hits.iter()
            .any(|(k, t, _)| *k == K::CustomerId && t == "K-928174"),
        "{hits:?}"
    );
    assert!(!hits.iter().any(|(k, _, _)| *k == K::City));
    let hits = found(d.as_ref(), "Frau Quolnath\nkam");
    assert!(
        hits.iter()
            .any(|(k, t, c)| *k == K::Person && t == "Quolnath" && (*c - 0.80).abs() < 1e-6),
        "{hits:?}"
    );
}

#[test]
fn delta_matches_new_entries_before_the_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    let mut ns = v.namespace("mail").unwrap();
    let d = ns.detector();
    assert!(found(d.as_ref(), "Sarah Leitner").is_empty());
    ns.token_for(&K::Person, "Sarah Leitner").unwrap();
    assert_eq!(
        found(d.as_ref(), "Hallo Sarah Leitner").len(),
        1,
        "matched by the delta automaton"
    );
    assert_eq!(ns.detector_generation(), 0, "no rebuild yet");
    ns.token_for(&K::Person, "Sarah Leitner").unwrap(); // a lookup, not a mint
    assert_eq!(ns.known_entities(), 1);
}

#[test]
fn rebuild_after_256_mints_bumps_the_generation() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    let mut ns = v.namespace("mail").unwrap();
    for i in 0..inumaki_vault::REBUILD_AFTER {
        ns.token_for(&K::Person, &format!("Person Nr{i}")).unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while ns.detector_generation() == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(ns.detector_generation(), 1, "background rebuild ran");
    assert_eq!(ns.known_entities(), inumaki_vault::REBUILD_AFTER);
    let d = ns.detector();
    assert_eq!(found(d.as_ref(), "Person Nr0 und Person Nr255").len(), 2);
    ns.rebuild_detector_now().unwrap();
    assert_eq!(ns.detector_generation(), 2);
}

/// Review I3: an entry pushed between the rebuild's row snapshot and the
/// swap stays in the delta.
#[test]
fn entries_pushed_during_a_rebuild_are_kept() {
    use inumaki_core::alias::AliasTable;
    use inumaki_core::span::EntityKind;
    use inumaki_vault::KnownEntityDetector;
    use zeroize::Zeroizing;
    let d = KnownEntityDetector::build(Vec::new(), Arc::new(AliasTable::empty())).unwrap();
    d.push(&EntityKind::Person, "Anna Erste").unwrap();
    let seen = d.pending(); // snapshot taken: 1
    d.push(&EntityKind::Person, "Berta Zweite").unwrap(); // arrives during the rebuild
    d.replace(
        vec![(EntityKind::Person, Zeroizing::new("Anna Erste".into()))],
        seen,
    )
    .unwrap();
    assert_eq!((d.size(), d.pending(), d.generation()), (1, 1, 1));
    assert_eq!(found(&d, "Anna Erste und Berta Zweite").len(), 2);
}

#[test]
fn automaton_is_capped_by_automaton_max_entries() {
    let dir = tempfile::tempdir().unwrap();
    let mut o = opts(dir.path());
    o.automaton_max_entries = 5;
    let v = Vault::open(o).unwrap();
    v.create_dataset(&DatasetSpec::new("mail", "x", "offline"))
        .unwrap();
    let mut ns = v.namespace("mail").unwrap();
    for i in 0..10 {
        ns.token_for(&K::Person, &format!("Person Nr{i}")).unwrap();
    }
    let ns = v.namespace("mail").unwrap();
    assert_eq!(ns.known_entities(), 5);
}

#[test]
fn rotation_replaces_the_automaton_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    let mut ns = v.namespace("mail").unwrap();
    ns.token_for(&K::Person, "Sarah Leitner").unwrap();
    let d = ns.detector();
    assert_eq!(found(d.as_ref(), "Sarah Leitner").len(), 1);
    v.rotate("mail").unwrap();
    ns.refresh().unwrap();
    assert!(
        found(d.as_ref(), "Sarah Leitner").is_empty(),
        "same Arc, emptied"
    );
    assert_eq!(ns.known_entities(), 0);
}

#[test]
fn engine_with_known_detector_tokenizes_a_known_entity_deterministically() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    let mut ns = v.namespace("mail").unwrap();
    let t = ns.token_for(&K::Person, "Zyxwuria Quolnath").unwrap();
    let cfg = CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap();
    let e = Engine::from_config(&cfg, "offline", None, None)
        .unwrap()
        .with_detector(ns.detector());
    match e
        .process("Mail von Zyxwuria Quolnath wegen Rechnung.", &mut ns)
        .unwrap()
    {
        Outcome::Pass { sanitized } | Outcome::PassUncertain { sanitized, .. } => {
            assert!(sanitized.text.contains(t.as_str()), "{}", sanitized.text);
            assert!(!sanitized.text.contains("Zyxwuria"));
        }
        Outcome::Blocked { kinds, reasons } => panic!("{kinds:?} {reasons:?}"),
    }
}

#[test]
fn namespace_debug_reports_known_count_without_entries() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    let mut ns = v.namespace("mail").unwrap();
    ns.token_for(&K::Person, "Zyxwuria Quolnath").unwrap();
    let d = format!("{ns:?}");
    assert!(!d.contains("Zyxwuria"), "{d}");
    assert!(d.contains("known: 1"), "{d}");
}

/// M4 spec §16.5: once the canonical is minted, every alias variant is a
/// known entity (main automaton after reopen, delta before the rebuild).
#[test]
fn alias_variants_are_known_once_the_canonical_is_minted() {
    use inumaki_core::alias::{AliasGroup, AliasTable};
    let dir = tempfile::tempdir().unwrap();
    let table = Arc::new(
        AliasTable::build(vec![AliasGroup {
            kind: K::Person,
            names: vec![
                "Hans-Peter Gruber".into(),
                "HP Gruber".into(),
                "Hansi".into(),
            ],
        }])
        .unwrap(),
    );
    // a row minted before the group existed holds the variant, not the canonical
    {
        let plain = Vault::open(opts(dir.path())).unwrap();
        plain
            .create_dataset(&DatasetSpec::new("mail", "x", "offline"))
            .unwrap();
        plain
            .namespace("mail")
            .unwrap()
            .token_for(&K::Person, "HP Gruber")
            .unwrap();
    }
    let v = Vault::open(opts(dir.path()).with_aliases(Arc::clone(&table))).unwrap();
    assert_eq!(v.aliases().len(), 1);
    {
        let mut ns = v.namespace("mail").unwrap(); // logs `rows = 1` (split row), count only
        assert_eq!(ns.known_entities(), 1);
        let d = ns.detector();
        assert_eq!(
            found(d.as_ref(), "HP Gruber").len(),
            1,
            "the old row is still a known entity"
        );
        assert!(
            found(d.as_ref(), "Hansi kommt").is_empty(),
            "a stored variant does not expand: only canonicals do"
        );
        ns.token_for(&K::Person, "Hans-Peter Gruber").unwrap();
        // the delta covers the variants right away
        let hits = found(d.as_ref(), "HP Gruber und Hansi kommen");
        assert!(
            hits.iter()
                .any(|(k, t, c)| *k == K::Person && t == "HP Gruber" && (*c - 0.97).abs() < 1e-6),
            "{hits:?}"
        );
        assert!(
            hits.iter().any(|(k, t, _)| *k == K::Person && t == "Hansi"),
            "{hits:?}"
        );
        assert!(
            found(d.as_ref(), "Hans Peter Gruber")
                .iter()
                .all(|(_, t, _)| t == "Gruber"),
            "never fuzzy"
        );
    }
    // the main automaton after reopen expands the stored canonical too
    let ns = v.namespace("mail").unwrap();
    assert_eq!(
        ns.known_entities(),
        2,
        "the old variant row and the canonical, however many variants"
    );
    let hits = found(ns.detector().as_ref(), "Hansi!");
    assert_eq!(hits.len(), 1, "{hits:?}");
    // a vault opened without the table sees the canonical only
    let plain = Vault::open(opts(dir.path())).unwrap();
    let ns = plain.namespace("mail").unwrap();
    assert!(found(ns.detector().as_ref(), "Hansi").is_empty());
    assert_eq!(found(ns.detector().as_ref(), "Hans-Peter Gruber").len(), 1);
}
