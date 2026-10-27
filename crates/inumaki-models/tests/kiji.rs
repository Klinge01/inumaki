#![cfg(feature = "models-tests")]
//! The Kiji backend against the downloaded model (`inumaki models pull kiji-pii`).

use std::path::PathBuf;
use std::sync::Arc;

use inumaki_core::detect::{DetectCtx, Detector};
use inumaki_core::span::EntityKind;
use inumaki_models::manifest::Manifest;
use inumaki_models::{NerBackend, NerDetector, NerLabelSpec, TokenClassifierBackend};

fn root() -> PathBuf {
    PathBuf::from(std::env::var("INUMAKI_MODELS_DIR").expect("set INUMAKI_MODELS_DIR"))
}

#[test]
fn kiji_finds_first_and_last_names_and_merges_them() {
    let m = Manifest::embedded();
    let e = m.get("kiji-pii").unwrap();
    let b = TokenClassifierBackend::load_kiji(
        &e.path(&root(), "model").unwrap(),
        &e.path(&root(), "tokenizer").unwrap(),
        &e.path(&root(), "config").unwrap(),
        0,
        1,
    )
    .unwrap();
    assert!(!b.supports_dynamic_labels());
    let text = "Sarah Leitner wohnt in der Neubaugasse 22 in Wien. LG Sarah";
    let labels = ["NAME", "FIRSTNAME", "SURNAME", "ADDRESS", "STREET", "CITY"].map(String::from);
    let raw = b.predict(text, &labels, &[0.5; 6]).unwrap();
    let got: Vec<(&str, &str)> = raw
        .iter()
        .map(|r| (&text[r.start..r.end], r.label.as_str()))
        .collect();
    assert!(got.contains(&("Sarah Leitner", "NAME")), "{got:?}");
    assert!(
        got.iter().any(|(t, l)| *t == "Sarah" && *l == "FIRSTNAME"),
        "bare sign-off: {got:?}"
    );
    let d = NerDetector::new(
        Arc::new(b),
        vec![
            NerLabelSpec {
                label: "NAME".into(),
                kind: EntityKind::Person,
                threshold: 0.5,
            },
            NerLabelSpec {
                label: "FIRSTNAME".into(),
                kind: EntityKind::Person,
                threshold: 0.5,
            },
            NerLabelSpec {
                label: "SURNAME".into(),
                kind: EntityKind::Person,
                threshold: 0.5,
            },
            NerLabelSpec {
                label: "ADDRESS".into(),
                kind: EntityKind::StreetAddress,
                threshold: 0.5,
            },
        ],
    );
    let spans = d.detect(text, &DetectCtx::for_text(text)).unwrap();
    assert!(
        spans
            .iter()
            .any(|s| s.kind == EntityKind::Person && s.slice(text) == "Sarah Leitner")
    );
    assert!(
        spans
            .iter()
            .any(|s| s.kind == EntityKind::StreetAddress && s.slice(text) == "Neubaugasse 22"),
        "{spans:?}"
    );
}
