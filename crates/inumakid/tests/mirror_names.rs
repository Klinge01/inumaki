//! M5 spec §4.3 rule 2 and §5.4: a known name is tokenized in a file name
//! whether written with spaces or underscores, the separators survive, the
//! name shares the content's token (no junk entry such as
//! `Zyxwuria_Quolnath` is minted), and `known_in_clear` finds a known
//! original in either spelling. A daemon test: `FakeEngine` cannot show the
//! minting (review I1). Also the size caps of the mirror's sanitize path
//! (spec §5.1): an oversized block withholds the batch without touching the
//! namespace.

mod common;

use common::*;
use inumaki_core::span::EntityKind;
use inumaki_core::token::TokenStore;
use inumakid::cache::CachedOutcome;
use inumakid::service::{MAX_BLOCK_BYTES, MAX_NAME_STEM_BYTES};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn names_are_sanitized_in_both_spellings_and_keep_separators() {
    let d = start().await;
    d.dataset("qwxzvk-akten").await;
    let s = std::sync::Arc::clone(&d.state);
    tokio::task::spawn_blocking(move || {
        let ns = s.namespace("qwxzvk-akten").unwrap();
        let tok = ns
            .lock()
            .unwrap()
            .token_for(&EntityKind::Person, "Zyxwuria Quolnath")
            .unwrap();
        let generation = s.vault.entries_generation("qwxzvk-akten");
        let out = inumakid::service::sanitize_names(
            &s,
            "qwxzvk-akten",
            vec![
                "Angebot_Zyxwuria_Quolnath".into(),
                "Brief an Zyxwuria Quolnath".into(),
                "Quartalsbericht".into(),
            ],
        )
        .unwrap();
        assert_eq!(
            out[0].text,
            format!("Angebot_{}", tok.as_str()),
            "the content's token"
        );
        assert_eq!(out[1].text, format!("Brief an {}", tok.as_str()));
        assert_eq!(out[2].text, "Quartalsbericht");
        assert_eq!(
            s.vault.entries_generation("qwxzvk-akten"),
            generation,
            "no new entry minted"
        );
        // A hyphenated street keeps the token its content minted as written:
        // the name does not mint a second, spaced entry for the same entity.
        let street = ns
            .lock()
            .unwrap()
            .token_for(&EntityKind::StreetAddress, "Karl-Schweighofer-Gasse 12")
            .unwrap();
        let generation = s.vault.entries_generation("qwxzvk-akten");
        let out = inumakid::service::sanitize_names(
            &s,
            "qwxzvk-akten",
            vec!["Lieferung Karl-Schweighofer-Gasse 12".into()],
        )
        .unwrap();
        assert_eq!(out[0].text, format!("Lieferung {}", street.as_str()));
        assert_eq!(
            s.vault.entries_generation("qwxzvk-akten"),
            generation,
            "no spaced twin minted"
        );
        // A non-word kind keeps its written text as the original: the dots
        // of an address are part of the value, not separators.
        let mail = inumakid::service::sanitize_names(
            &s,
            "qwxzvk-akten",
            vec!["Mail an qwxzvk.quolnath@example.invalid".into()],
        )
        .unwrap();
        let t = mail[0]
            .text
            .strip_prefix("Mail an ")
            .expect("separators kept");
        assert!(t.starts_with("<EMAIL_"), "{t}");
        assert_eq!(
            ns.lock().unwrap().original(t),
            Some("qwxzvk.quolnath@example.invalid")
        );
        let hits = inumakid::service::known_in_clear(
            &s,
            "qwxzvk-akten",
            &[
                "Kunde.Zyxwuria.Quolnath".into(),
                format!("Kunde {}", tok.as_str()),
            ],
        )
        .unwrap();
        assert!(
            hits[0].is_some() && hits[1].is_none(),
            "only the clear spelling hits"
        );
    })
    .await
    .unwrap();
}

/// One oversized block (a JSON string value, an unterminated CSV quote, a
/// verification block) withholds every block of the batch with a fixed
/// reason, before the namespace lock, the engine, or the vault is touched;
/// a name stem over the cap is blocked on its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversized_block_withholds_the_batch_without_touching_the_namespace() {
    let d = start().await;
    d.dataset("qwxzvk-akten").await;
    let s = std::sync::Arc::clone(&d.state);
    tokio::task::spawn_blocking(move || {
        let generation = s.vault.entries_generation("qwxzvk-akten");
        let big = "x".repeat(MAX_BLOCK_BYTES + 1);
        let out = inumakid::service::sanitize_bounded(
            &s,
            "qwxzvk-akten",
            vec!["Kontakt: Zyxwuria Quolnath".into(), big],
        )
        .unwrap();
        assert!(
            out.iter()
                .all(|b| b.outcome == CachedOutcome::Blocked && b.text.is_empty())
        );
        assert_eq!(out[0].reasons.len(), 1, "a fixed reason, no text");
        assert_eq!(
            s.vault.entries_generation("qwxzvk-akten"),
            generation,
            "nothing minted"
        );

        let ok = inumakid::service::sanitize_bounded(
            &s,
            "qwxzvk-akten",
            vec!["x".repeat(MAX_BLOCK_BYTES)],
        )
        .unwrap();
        assert_eq!(
            ok[0].outcome,
            CachedOutcome::Pass,
            "the cap itself is allowed"
        );

        let names = inumakid::service::sanitize_names(
            &s,
            "qwxzvk-akten",
            vec![
                "y".repeat(MAX_NAME_STEM_BYTES + 1),
                "Quartalsbericht".into(),
            ],
        )
        .unwrap();
        assert_eq!(names[0].outcome, CachedOutcome::Blocked);
        assert_eq!(names[1].text, "Quartalsbericht");
    })
    .await
    .unwrap();
}
