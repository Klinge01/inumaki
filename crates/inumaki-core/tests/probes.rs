//! Engine-level regression tests for the milestone-1 final review probes.
//! Every probe here once produced a `Pass` with an identifier in plaintext.

use std::time::Duration;

use std::sync::Arc;

use inumaki_core::config::CoreConfig;
use inumaki_core::detect::Detector;
use inumaki_core::detect::dictionary::DictionaryDetector;
use inumaki_core::detect::domain::DomainDetector;
use inumaki_core::detect::regex::RegexDetector;
use inumaki_core::detect::secrets::SecretsDetector;
use inumaki_core::engine::{Engine, Outcome};
use inumaki_core::rehydrate::Rehydrator;
use inumaki_core::span::EntityKind;
use inumaki_core::token::{Context, ContextId, parse_token};
use inumaki_core::verify::SecondPassVerifier;

// These probes exercise the regex/secrets/domain/dictionary stack without any
// NER backend, so they use the `offline` profile (the successor to milestone
// 1's `fast` profile, which had no `[ner]` sections at all).
const FAST: &str = include_str!("../../../configs/default.toml");

fn fast() -> Engine {
    let cfg = CoreConfig::from_toml(FAST).unwrap();
    Engine::from_config(&cfg, "offline", None, None).unwrap()
}

/// `default.toml`'s `offline` profile with an in-memory dictionary (no file IO in tests).
fn fast_with_dictionary(entries: &[(EntityKind, &str)]) -> Engine {
    let cfg = CoreConfig::from_toml(FAST).unwrap();
    let profile = cfg.resolve_profile("offline").unwrap();
    let retry = cfg.resolve_profile("offline-strict").unwrap();
    let regex = RegexDetector::new();
    let detectors: Vec<Arc<dyn Detector>> = vec![
        Arc::new(regex.clone()),
        Arc::new(SecretsDetector::new()),
        Arc::new(DomainDetector::from_config(&cfg.domain).unwrap()),
        Arc::new(
            DictionaryDetector::from_entries(
                entries.iter().map(|(k, v)| (k.clone(), v.to_string())),
            )
            .unwrap(),
        ),
    ];
    let verifier = Arc::new(SecondPassVerifier::new(regex, None, &profile.verifier).unwrap());
    Engine::new(profile, Some(retry), detectors, verifier)
}

fn ctx(e: &Engine) -> Context {
    Context::new(
        ContextId("probe".into()),
        Duration::from_secs(60),
        e.token_settings().clone(),
    )
}

/// The text that would be sent upstream, if any.
fn sent(o: &Outcome) -> Option<&str> {
    match o {
        Outcome::Pass { sanitized } | Outcome::PassUncertain { sanitized, .. } => {
            Some(sanitized.text.as_str())
        }
        Outcome::Blocked { .. } => None,
    }
}

/// Assert the outcome is a plain `Pass` whose text contains `token_prefix`
/// and none of `secrets`.
fn assert_pass_without(o: &Outcome, token_prefix: &str, secrets: &[&str]) {
    let Outcome::Pass { sanitized } = o else {
        panic!("expected Pass, got {o:?}");
    };
    assert!(
        sanitized.text.contains(token_prefix),
        "expected {token_prefix} in {}",
        sanitized.text
    );
    for s in secrets {
        assert!(
            !sanitized.text.contains(s),
            "{s} leaked in {}",
            sanitized.text
        );
    }
}

// ---- C1: checksum rules must try shorter extents -------------------------

#[test]
fn c1_iban_followed_by_bic_is_tokenized() {
    let e = fast();
    let o = e
        .process("IBAN AT61 1904 3002 3457 3201 BIC BKAUATWW", &mut ctx(&e))
        .unwrap();
    assert_pass_without(&o, "<IBAN_", &["AT61", "1904 3002", "3457 3201"]);
}

#[test]
fn c1_compact_iban_followed_by_bic_is_tokenized() {
    let e = fast();
    let o = e
        .process("IBAN AT611904300234573201 BIC BKAUATWW", &mut ctx(&e))
        .unwrap();
    assert_pass_without(&o, "<IBAN_", &["AT611904300234573201", "AT61"]);
}

#[test]
fn c1_iban_followed_by_capitalized_word_is_tokenized() {
    let e = fast();
    let o = e
        .process("… AT61 1904 3002 3457 3201 DANKE", &mut ctx(&e))
        .unwrap();
    assert_pass_without(&o, "<IBAN_", &["AT61", "1904 3002", "3457 3201"]);
}

#[test]
fn c1_card_followed_by_cvc_is_tokenized() {
    let e = fast();
    let o = e
        .process("Karte 4111 1111 1111 1111 123 gueltig", &mut ctx(&e))
        .unwrap();
    assert_pass_without(&o, "<CREDIT_CARD_", &["4111 1111 1111 1111", "4111"]);
}

#[test]
fn c1_card_followed_by_expiry_is_tokenized() {
    let e = fast();
    let o = e
        .process("4111 1111 1111 1111 12 26", &mut ctx(&e))
        .unwrap();
    assert_pass_without(&o, "<CREDIT_CARD_", &["4111 1111 1111 1111", "4111"]);
}

// ---- C2: preserved ranges only exempt re-scan hits of the same kind -------

#[test]
fn c2_email_inside_preserved_url_is_not_sent() {
    let e = fast();
    let o = e
        .process(
            "https://portal.example.at/kunden?email=sarah.leitner@example.at",
            &mut ctx(&e),
        )
        .unwrap();
    if let Some(t) = sent(&o) {
        assert!(!t.contains("sarah.leitner@example.at"), "leaked: {t}");
        assert!(!t.contains("sarah.leitner"), "leaked: {t}");
    }
    // `offline` retries with `offline-strict`, which tokenizes the URL.
    assert_pass_without(&o, "<URL_", &["sarah.leitner@example.at"]);
}

#[test]
fn c2_iban_inside_preserved_url_is_not_sent() {
    let e = fast();
    let o = e
        .process(
            "https://pay.example.at/?iban=AT611904300234573201",
            &mut ctx(&e),
        )
        .unwrap();
    if let Some(t) = sent(&o) {
        assert!(!t.contains("AT611904300234573201"), "leaked: {t}");
    }
    assert_pass_without(&o, "<URL_", &["AT611904300234573201"]);
}

// ---- C3: removed secrets are leak-checked --------------------------------

#[test]
fn c3_second_copy_of_removed_secret_is_not_sent() {
    let e = fast();
    let mut c = ctx(&e);
    let o = e
        .process(
            "api_key: 9f8e7d6c5b4a3210ffee. Bitte teste mit 9f8e7d6c5b4a3210ffee im Header.",
            &mut c,
        )
        .unwrap();
    if let Some(t) = sent(&o) {
        assert!(!t.contains("9f8e7d6c5b4a3210ffee"), "leaked: {t}");
    }
    // No detector finds the unlabelled copy; the referential-consistency
    // pass removes it as a copy of a removed store value (plan L3 step 2,
    // Task 4), so both copies are removed and nothing is left to leak.
    assert_pass_without(&o, "<SECRET_REMOVED>", &["9f8e7d6c5b4a3210ffee"]);
    let Outcome::Pass { sanitized } = &o else {
        unreachable!()
    };
    assert_eq!(sanitized.text.matches("<SECRET_REMOVED>").count(), 2);
    // removed values are never rehydrated
    let (back, _) = inumaki_core::rehydrate::Rehydrator::new(e.token_settings())
        .rehydrate("<SECRET_REMOVED>", &c);
    assert_eq!(back, "<SECRET_REMOVED>");
}

// ---- I1: NFC normalization at engine entry -------------------------------

#[test]
fn i1_nfd_input_matches_nfc_dictionary_entry() {
    let e = fast_with_dictionary(&[(EntityKind::Person, "Sarah Müller")]);
    let o = e
        .process("Frau Sarah Mu\u{0308}ller", &mut ctx(&e))
        .unwrap();
    assert_pass_without(&o, "<PERSON_", &["Sarah", "Mu\u{0308}ller", "Müller"]);
}

#[test]
fn i1_nfd_dictionary_entry_matches_nfc_input() {
    let e = fast_with_dictionary(&[(EntityKind::Person, "Sarah Mu\u{0308}ller")]);
    let o = e.process("Frau Sarah Müller", &mut ctx(&e)).unwrap();
    assert_pass_without(&o, "<PERSON_", &["Sarah", "Mu\u{0308}ller", "Müller"]);
}

#[test]
fn i1_nfd_surname_of_known_person_is_not_sent() {
    let e = fast();
    let mut c = ctx(&e);
    c.token_for(&EntityKind::Person, "Sarah Müller").unwrap();
    let o = e.process("Herr Mu\u{0308}ller nochmal.", &mut c).unwrap();
    if let Some(t) = sent(&o) {
        assert!(
            !t.contains("Mu\u{0308}ller") && !t.contains("Müller"),
            "leaked: {t}"
        );
    }
}

#[test]
fn i1_mixed_nfc_and_nfd_mentions_share_one_token() {
    let e = fast_with_dictionary(&[(EntityKind::Person, "Sarah Müller")]);
    let mut c = ctx(&e);
    let o = e
        .process("Sarah Müller rief an. Dann Mu\u{0308}ller nochmal.", &mut c)
        .unwrap();
    assert_pass_without(&o, "<PERSON_", &["Sarah", "Mu\u{0308}ller", "Müller"]);
    // Plan 4a: the bare (NFD) surname still links to the full (NFC) entity
    // at the store level (same suffix, one entity), but its mention text
    // ("Müller") differs from the entity's stored original ("Sarah
    // Müller"), so `sanitize` mints it a surface token rather than reusing
    // the full entity's token outright -- every token restores exactly the
    // text it replaced.
    let Outcome::Pass { sanitized } = &o else {
        panic!("expected Pass")
    };
    let toks = Rehydrator::new(e.token_settings()).tokens_in(&sanitized.text);
    assert_eq!(toks.len(), 2, "{toks:?}");
    let parsed: Vec<_> = toks
        .iter()
        .map(|t| parse_token(e.token_settings(), t).unwrap())
        .collect();
    assert_eq!(parsed[0].suffix, parsed[1].suffix, "same entity: {toks:?}");
    assert!(
        parsed[0].variant.is_none() && parsed[1].variant.is_some(),
        "the surname is a surface form: {toks:?}"
    );
    assert_eq!(
        c.len(),
        2,
        "full entity plus one surface form for the surname"
    );
}

#[test]
fn i1_detect_offsets_refer_to_the_nfc_form() {
    let e = fast();
    let raw = "Mu\u{0308}ller: sarah@example.at";
    let nfc = inumaki_core::engine::normalize_input(raw);
    let spans = e.detect(raw).unwrap();
    let email = spans.iter().find(|s| s.kind == EntityKind::Email).unwrap();
    assert_eq!(email.slice(&nfc), "sarah@example.at");
}

// ---- I9: whitespace-flexible dictionary matching -------------------------

#[test]
fn i9_name_wrapped_across_lines_is_tokenized_whole() {
    let e = fast_with_dictionary(&[(EntityKind::Person, "Sarah Leitner")]);
    let o = e.process("Sarah\nLeitner", &mut ctx(&e)).unwrap();
    assert_pass_without(&o, "<PERSON_", &["Sarah", "Leitner"]);
}

#[test]
fn i9_address_wrapped_across_lines_is_tokenized() {
    let e = fast_with_dictionary(&[(EntityKind::StreetAddress, "Neubaugasse 22")]);
    let o = e
        .process("Adresse: Neubaugasse\n22, Wien", &mut ctx(&e))
        .unwrap();
    assert_pass_without(&o, "<STREET_ADDRESS_", &["Neubaugasse"]);
}

// ---- I6: regex recall gaps ------------------------------------------------

#[test]
fn i6_recall_gaps_are_not_sent() {
    let e = fast();
    for (text, token, secrets) in [
        (
            "Tel. (0664) 123 45 67 bitte",
            "<PHONE_",
            &["123 45 67", "0664"][..],
        ),
        ("Tel. (01) 234 56 78", "<PHONE_", &["234 56 78"][..]),
        (
            "Mail an office@müller-bau.at bitte",
            "<EMAIL_",
            &["müller-bau", "office@"][..],
        ),
        (
            "Mail an jörg.huber@example.at",
            "<EMAIL_",
            &["jö", "huber"][..],
        ),
        (
            "Passwort: Sommer2024!x",
            "<SECRET_REMOVED>",
            &["Sommer2024", "!x"][..],
        ),
        (
            "Kennwort: geheim123",
            "<SECRET_REMOVED>",
            &["geheim123"][..],
        ),
    ] {
        let o = e.process(text, &mut ctx(&e)).unwrap();
        assert_pass_without(&o, token, secrets);
    }
}
