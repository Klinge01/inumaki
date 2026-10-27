#![cfg(feature = "models-tests")]

use std::path::PathBuf;
use std::sync::Arc;

use inumaki_core::detect::{DetectCtx, Detector};
use inumaki_core::span::EntityKind;
use inumaki_models::gliner::{GlinerBackend, GlinerConfig};
use inumaki_models::manifest::Manifest;
use inumaki_models::{ModelError, NerBackend, NerDetector, NerLabelSpec};

fn backend() -> GlinerBackend {
    let root = PathBuf::from(
        std::env::var("INUMAKI_MODELS_DIR")
            .expect("set INUMAKI_MODELS_DIR; run `inumaki models pull`"),
    );
    let m = Manifest::embedded();
    let e = m.get("gliner-x-small").unwrap();
    let cfg = GlinerConfig::from_file(&e.path(&root, "config").unwrap()).unwrap();
    GlinerBackend::load_with_config(
        &e.path(&root, "model").unwrap(),
        &e.path(&root, "tokenizer").unwrap(),
        cfg,
        0,
        1,
    )
    .expect("model loads")
}

fn labels() -> Vec<String> {
    vec!["person".into(), "street address".into(), "city".into()]
}

/// One threshold per `labels()` entry, in the same order.
fn thresholds() -> Vec<f32> {
    vec![0.3, 0.3, 0.3]
}

#[test]
fn reference_sentence_matches_gline_rs() {
    let b = backend();
    let text = "Sarah Leitner wohnt in der Neubaugasse 22 in Wien.";
    let out = b.predict(text, &labels(), &thresholds()).unwrap();
    let want = [
        ((0, 13), "person", 0.972),
        ((27, 41), "street address", 0.737),
        ((45, 49), "city", 0.845),
    ];
    assert_eq!(out.len(), 3, "{out:?}");
    for ((s, e), label, score) in want {
        let hit = out
            .iter()
            .find(|x| x.start == s && x.end == e && x.label == label);
        let hit = hit.unwrap_or_else(|| panic!("missing {label} {s}..{e}: {out:?}"));
        assert!(
            (hit.score - score).abs() < 0.03,
            "{label}: {} vs {score}",
            hit.score
        );
    }
}

#[test]
fn format_characters_between_words_do_not_break_detection() {
    let b = backend();
    let text = "Sarah \u{200D} Leitner wohnt in Wien.";
    let zwj_pos = text.find('\u{200D}').expect("fixture contains a ZWJ");
    let out = b.predict(text, &labels(), &thresholds()).unwrap();
    let person = out
        .iter()
        .find(|e| e.label == "person")
        .unwrap_or_else(|| panic!("{out:?}"));
    assert_eq!(person.start, 0, "{out:?}");
    assert!(
        text[person.start..person.end].ends_with("Leitner"),
        "{out:?}"
    );
    // The pin: the person span must actually span across the dropped ZWJ word (not just
    // start at 0 and separately end after "Leitner", which a span that excluded the ZWJ
    // entirely could also satisfy).
    assert!(
        person.start <= zwj_pos && zwj_pos < person.end,
        "person span {}..{} does not cover the ZWJ at {zwj_pos}: {out:?}",
        person.start,
        person.end
    );
}

#[test]
fn umlaut_offsets_are_exact() {
    let b = backend();
    let text = "Jürgen Müller aus Köln";
    let out = b.predict(text, &labels(), &thresholds()).unwrap();
    let got: Vec<&str> = out.iter().map(|e| &text[e.start..e.end]).collect();
    assert!(got.contains(&"Jürgen Müller"), "{got:?}");
    assert!(got.contains(&"Köln"), "{got:?}");
}

#[test]
fn too_long_input_is_rejected_by_the_backend() {
    let b = backend();
    let text = "Das ist ein Satz. ".repeat(200);
    assert!(matches!(
        b.predict(&text, &labels(), &thresholds()),
        Err(ModelError::InputTooLong)
    ));
}

#[test]
fn long_email_thread_is_fully_scanned_through_the_detector() {
    let backend = backend();
    let b: Arc<dyn NerBackend> = Arc::new(backend);
    let d = NerDetector::new(
        b.clone(),
        vec![NerLabelSpec {
            label: "person".into(),
            kind: EntityKind::Person,
            threshold: 0.5,
        }],
    );
    let filler = "Wir melden uns so bald wie möglich bei Ihnen zurück. ".repeat(40);
    let text = format!(
        "Sehr geehrte Frau Katharina Weiß,\n{filler}\nIhr Thomas Gruber\n\n> {filler}\n> Am Montag schrieb Sarah Leitner:\n> {filler}"
    );
    // The reference regression for the detector's chunk-size budget (factor 3, not 4;
    // detector.rs `NerDetector::new`): every chunk at the detector's actual configured
    // size must fit the backend's sub-word token budget without `InputTooLong`, so this
    // long German thread is never re-tokenized through the split path in `predict_into`.
    for c in inumaki_models::chunk::chunks(&text, d.chunk_bytes(), 200) {
        assert!(
            b.predict(c.text, &["person".to_string()], &[0.5]).is_ok(),
            "chunk at byte {} does not fit the backend; the detector would have to split it",
            c.offset
        );
    }
    let spans = d.detect(&text, &DetectCtx::for_text(&text)).unwrap();
    let names: Vec<&str> = spans.iter().map(|s| s.slice(&text)).collect();
    for n in ["Katharina Weiß", "Thomas Gruber", "Sarah Leitner"] {
        assert!(names.contains(&n), "{n} missing: {names:?}");
    }
}

/// Spec §13: two threads run inference on the same backend at once and both
/// get the reference result. With `sessions = 2` neither waits; with the
/// default of 1 the second call queues, which is also correct.
#[test]
fn two_threads_infer_concurrently_with_a_two_slot_pool() {
    let root = PathBuf::from(std::env::var("INUMAKI_MODELS_DIR").expect("set INUMAKI_MODELS_DIR"));
    let m = Manifest::embedded();
    let e = m.get("gliner-x-small").unwrap();
    let cfg = GlinerConfig::from_file(&e.path(&root, "config").unwrap()).unwrap();
    let b = Arc::new(
        GlinerBackend::load_with_config(
            &e.path(&root, "model").unwrap(),
            &e.path(&root, "tokenizer").unwrap(),
            cfg,
            0,
            2,
        )
        .expect("model loads"),
    );
    let text = "Sarah Leitner wohnt in der Neubaugasse 22 in Wien.";
    let reference = b.predict(text, &labels(), &thresholds()).unwrap();
    assert!(!reference.is_empty());
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let b = Arc::clone(&b);
            std::thread::spawn(move || b.predict(text, &labels(), &thresholds()).unwrap())
        })
        .collect();
    for h in handles {
        let got = h.join().unwrap();
        assert_eq!(got.len(), reference.len());
        for (g, r) in got.iter().zip(&reference) {
            assert_eq!(
                (g.start, g.end, g.label.as_str()),
                (r.start, r.end, r.label.as_str())
            );
            assert!(
                (g.score - r.score).abs() < 1e-4,
                "{} vs {}",
                g.score,
                r.score
            );
        }
    }
    assert_eq!(
        b.pool_waits(),
        0,
        "two slots must serve two threads without a wait"
    );
}
