//! M8 spec decision 11: tokens that resolve in the store are protected,
//! overlapping detections are clipped, never dropped; computed on NFC text.

use std::sync::Arc;
use std::time::Duration;

use inumaki_core::config::{CoreConfig, TokenSettings};
use inumaki_core::detect::{DetectCtx, Detector};
use inumaki_core::engine::{Engine, Outcome};
use inumaki_core::redact::{Redaction, RedactionAction};
use inumaki_core::span::{DetectorId, EntityKind, Span};
use inumaki_core::token::{Context, ContextId};

const CFG: &str = r#"
    [profiles.fast]
    default_action = "tokenize"
    default_min_confidence = 0.5
    escalate_below = 0.5
    [profiles.fast.entities.SECRET]
    action = "remove"
    min_confidence = 0.0
    [profiles.fast.verifier]
    on_uncertain = "block"
    allow_no_ner = true
"#;

/// Flags every occurrence of `needle` as a PERSON with NER confidence,
/// widened by (before, after) bytes, clamped to char boundaries.
struct Finds(&'static str, usize, usize);
impl Detector for Finds {
    fn id(&self) -> DetectorId {
        DetectorId::Ner
    }
    fn detect(&self, text: &str, _: &DetectCtx) -> inumaki_core::Result<Vec<Span>> {
        Ok(text
            .match_indices(self.0)
            .map(|(i, _)| {
                let mut s = i.saturating_sub(self.1);
                while !text.is_char_boundary(s) {
                    s -= 1;
                }
                let mut e = (i + self.0.len() + self.2).min(text.len());
                while !text.is_char_boundary(e) {
                    e += 1;
                }
                Span::new(s, e, EntityKind::Person, 0.9, DetectorId::Ner)
            })
            .collect())
    }
}

fn ctx() -> Context {
    Context::new(
        ContextId("t".into()),
        Duration::from_secs(60),
        TokenSettings::default(),
    )
}

fn engine(d: Finds) -> Engine {
    let cfg = CoreConfig::from_toml(CFG).unwrap();
    Engine::from_config(&cfg, "fast", None, None)
        .unwrap()
        .with_detector(Arc::new(d))
}

fn pass(o: Outcome) -> inumaki_core::sanitize::Sanitized {
    match o {
        Outcome::Pass { sanitized } | Outcome::PassUncertain { sanitized, .. } => sanitized,
        o => panic!("expected pass, got {o:?}"),
    }
}

#[test]
fn a_resolving_token_is_kept_byte_identical_and_not_retokenized() {
    let mut c = ctx();
    let t = c
        .token_for(&EntityKind::Person, "Zyxwuria Quolnath")
        .unwrap();
    let text = format!("Bitte {} anrufen.", t.as_str());
    // The detector would flag the token's label as a person.
    let s = pass(
        engine(Finds("PERSON", 1, 7))
            .process(&text, &mut c)
            .unwrap(),
    );
    assert_eq!(s.text, text, "the protected token stays as it is");
    assert!(s.replacements.is_empty(), "{:?}", s.replacements);
    assert_eq!(s.protected.len(), 1);
    assert_eq!(&s.text[s.protected[0].clone()], t.as_str());
    assert_eq!(c.len(), 1, "nothing new was minted");
    let dbg = format!("{s:?}");
    assert!(
        !dbg.contains(t.as_str()) && !dbg.contains("Zyxwuria") && !dbg.contains("anrufen"),
        "Debug shows no token, original, or text: {dbg}"
    );
}

#[test]
fn a_detection_overlapping_a_token_is_clipped_and_the_rest_tokenized() {
    let mut c = ctx();
    let t = c
        .token_for(&EntityKind::Person, "Zyxwuria Quolnath")
        .unwrap();
    let text = format!("Herr {} Pellqwyn kam.", t.as_str());
    // Detection runs on the masked text, so anchor the hit outside the token
    // ("Herr") and widen it across the token to the end of "Pellqwyn".
    let widen = 1 + t.as_str().len() + 1 + "Pellqwyn".len();
    let s = pass(
        engine(Finds("Herr", 0, widen))
            .process(&text, &mut c)
            .unwrap(),
    );
    assert_eq!(s.protected.len(), 1, "the token is protected");
    assert_eq!(
        &s.text[s.protected[0].clone()],
        t.as_str(),
        "byte-identical"
    );
    assert_eq!(s.replacements.len(), 2, "both uncovered pieces are kept");
    assert!(
        !s.text.contains("Pellqwyn") && !s.text.contains("Herr"),
        "both pieces outside the token are tokenized"
    );
    assert!(
        s.replacements
            .iter()
            .all(|r| r.span.kind == EntityKind::Person),
        "clipped pieces keep the kind"
    );
}

#[test]
fn an_unresolvable_token_shaped_label_is_ordinary_text() {
    let mut c = ctx();
    let text = "Siehe <ZYXWURIA_QUOLNATH_abcd> im Anhang.";
    let s = pass(
        engine(Finds("ZYXWURIA", 0, 0))
            .process(text, &mut c)
            .unwrap(),
    );
    assert!(
        !s.text.contains("ZYXWURIA"),
        "a label can spell a name: {}",
        s.text
    );
    assert!(s.protected.is_empty());
}

#[test]
fn protection_is_computed_on_the_nfc_text() {
    let mut c = ctx();
    let t = c
        .token_for(&EntityKind::Person, "Zyxwuria Quolnath")
        .unwrap();
    // NFD "Mü" before the token shifts byte offsets under NFC.
    let text = format!("Herr Mu\u{0308}ller und {}.", t.as_str());
    let s = pass(
        engine(Finds("PERSON", 1, 7))
            .process(&text, &mut c)
            .unwrap(),
    );
    assert!(s.text.contains(t.as_str()), "{}", s.text);
    assert_eq!(s.protected.len(), 1);
    assert_eq!(&s.text[s.protected[0].clone()], t.as_str());
}

#[test]
fn peek_token_finds_without_minting() {
    let mut c = ctx();
    assert!(
        c.peek_token(&EntityKind::Person, "Zyxwuria Quolnath")
            .is_none()
    );
    assert_eq!(c.len(), 0);
    let t = c
        .token_for(&EntityKind::Person, "Zyxwuria Quolnath")
        .unwrap();
    assert_eq!(
        c.peek_token(&EntityKind::Person, "zyxwuria  quolnath"),
        Some(t.clone())
    );
    assert_eq!(
        c.peek_token(&EntityKind::Person, "Quolnath"),
        None,
        "the store no longer links surnames (the name linker does)"
    );
    assert_eq!(c.len(), 1, "peeking mints nothing");
    assert_eq!(c.kind_of(t.as_str()), Some(EntityKind::Person));
    assert_eq!(c.kind_of("<PERSON_ffff>"), None);
}

/// Flags every occurrence of `needle` exactly, as a PERSON from `source`.
struct Hit(DetectorId, &'static str);
impl Detector for Hit {
    fn id(&self) -> DetectorId {
        self.0
    }
    fn detect(&self, text: &str, _: &DetectCtx) -> inumaki_core::Result<Vec<Span>> {
        Ok(text
            .match_indices(self.1)
            .map(|(i, _)| Span::new(i, i + self.1.len(), EntityKind::Person, 1.0, self.0))
            .collect())
    }
}

/// Review fix round 1: overlap resolution ranks source priority above
/// length, so a high-priority hit inside a token must be clipped away
/// before resolution, or it beats the model span reaching into real text
/// and that text goes out in clear.
#[test]
fn a_high_priority_hit_inside_a_token_cannot_shadow_the_text_beside_it() {
    for source in [
        DetectorId::Dictionary,
        DetectorId::Domain,
        DetectorId::RegexValidated,
    ] {
        let mut c = ctx();
        let t = c
            .token_for(&EntityKind::Person, "Zyxwuria Quolnath")
            .unwrap();
        let text = format!("Bitte {} Pellqwyn anrufen.", t.as_str());
        // model span: the token plus " Pellqwyn"; high-priority hit: the label
        let ner = Finds("Pellqwyn", 1 + t.as_str().len(), 0);
        let e = engine(ner).with_detector(Arc::new(Hit(source, "PERSON")));
        let s = pass(e.process(&text, &mut c).unwrap());
        assert!(
            !s.text.contains("Pellqwyn"),
            "{source:?}: the name beside the token is tokenized: {}",
            s.text
        );
        assert_eq!(s.protected.len(), 1);
        assert_eq!(&s.text[s.protected[0].clone()], t.as_str(), "{source:?}");
        assert_eq!(s.replacements.len(), 1, "{source:?}");
    }
}

/// A caller's redaction over a protected token is clipped around it: the
/// pieces outside are tokenized, the token stays byte-identical.
#[test]
fn a_redaction_over_a_token_is_clipped_around_it() {
    let mut c = ctx();
    let t = c
        .token_for(&EntityKind::Person, "Zyxwuria Quolnath")
        .unwrap();
    let text = format!("Herr {} Pellqwyn kam.", t.as_str());
    let red = [Redaction {
        start: 0,
        end: text.find(" kam").unwrap(),
        kind: "PERSON".into(),
        action: RedactionAction::Tokenize,
    }];
    let o = engine(Finds("\u{0}", 0, 0))
        .process_with(&text, &mut c, &red)
        .unwrap();
    let s = pass(o);
    assert_eq!(s.protected.len(), 1);
    assert_eq!(&s.text[s.protected[0].clone()], t.as_str());
    assert_eq!(s.replacements.len(), 2, "Herr and Pellqwyn");
    assert!(
        !s.text.contains("Herr") && !s.text.contains("Pellqwyn"),
        "{}",
        s.text
    );
}

/// Review fix round 2: the plausibility filter judges the span the model
/// found, not the piece left after clipping. A short lowercase word next to
/// a protected token (`<PERSON_ab12> wu`) stays a person and is tokenized,
/// although `wu` alone, below the confident threshold, would be dropped.
#[test]
fn a_short_lowercase_piece_of_a_clipped_name_is_still_tokenized() {
    /// `needle` widened backwards by `self.1` bytes, at middling confidence.
    struct Weak(&'static str, usize);
    impl Detector for Weak {
        fn id(&self) -> DetectorId {
            DetectorId::Ner
        }
        fn detect(&self, text: &str, _: &DetectCtx) -> inumaki_core::Result<Vec<Span>> {
            Ok(text
                .match_indices(self.0)
                .map(|(i, _)| {
                    Span::new(
                        i - self.1,
                        i + self.0.len(),
                        EntityKind::Person,
                        0.7,
                        DetectorId::Ner,
                    )
                })
                .collect())
        }
    }
    let mut c = ctx();
    let t = c
        .token_for(&EntityKind::Person, "Zyxwuria Quolnath")
        .unwrap();
    let text = format!("Bitte {} wu anrufen.", t.as_str());
    let cfg = CoreConfig::from_toml(CFG).unwrap();
    let e = Engine::from_config(&cfg, "fast", None, None)
        .unwrap()
        .with_detector(Arc::new(Weak(" wu ", t.as_str().len())));
    let s = pass(e.process(&text, &mut c).unwrap());
    assert!(
        !s.text.contains(" wu "),
        "the piece is tokenized: {}",
        s.text
    );
    assert_eq!(&s.text[s.protected[0].clone()], t.as_str());
    assert_eq!(s.replacements.len(), 1);
}
