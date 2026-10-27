#![cfg(feature = "models-tests")]

use std::path::PathBuf;

use inumaki_models::manifest::Manifest;
use inumaki_models::{NerBackend, TokenClassifierBackend};

fn backend() -> TokenClassifierBackend {
    let root = PathBuf::from(
        std::env::var("INUMAKI_MODELS_DIR")
            .expect("set INUMAKI_MODELS_DIR; run `inumaki models pull`"),
    );
    let m = Manifest::embedded();
    let e = m.get("mbert-ner-hrl").unwrap();
    TokenClassifierBackend::load(
        &e.path(&root, "model").unwrap(),
        &e.path(&root, "tokenizer").unwrap(),
        &e.path(&root, "config").unwrap(),
        0,
        1,
    )
    .expect("model loads")
}

#[test]
fn reference_sentence() {
    let b = backend();
    let text = "Sarah Leitner wohnt in der Neubaugasse 22 in Wien.";
    let out = b.predict(text, &[], &[]).unwrap();
    let got: Vec<(&str, &str)> = out
        .iter()
        .map(|e| (&text[e.start..e.end], e.label.as_str()))
        .collect();
    assert!(got.contains(&("Sarah Leitner", "PER")), "{got:?}");
    assert!(got.contains(&("Wien", "LOC")), "{got:?}");
}

#[test]
fn umlaut_offsets_are_exact() {
    let b = backend();
    let text = "Jürgen Müller aus Köln";
    let out = b.predict(text, &[], &[]).unwrap();
    let got: Vec<&str> = out.iter().map(|e| &text[e.start..e.end]).collect();
    assert!(got.contains(&"Jürgen Müller"), "{got:?}");
    assert!(got.contains(&"Köln"), "{got:?}");
}

#[test]
fn label_filter_keeps_only_requested_types() {
    let b = backend();
    let text = "Sarah Leitner wohnt in Wien.";
    let out = b.predict(text, &["PER".to_string()], &[0.5]).unwrap();
    assert!(!out.is_empty(), "expected at least one PER hit");
    assert!(out.iter().all(|e| e.label == "PER"), "{out:?}");
}
