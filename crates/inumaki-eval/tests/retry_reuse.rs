//! Spec §9.1/§13: reusing the first pass's spans for the retry is equivalent
//! to detecting again only if detection is deterministic and `process` is
//! deterministic modulo token suffixes. Both are checked over the fixture
//! corpus (hand-written cases plus 300 generated documents) with the
//! `offline` profile, which retries into `offline-strict`.

use inumaki_core::config::CoreConfig;
use inumaki_core::engine::{Engine, Outcome};
use inumaki_core::rehydrate::Rehydrator;
use inumaki_core::token::{Context, ContextId, parse_token};
use inumaki_eval::Doc;
use inumaki_eval::cases::embedded_cases;
use inumaki_eval::generate::{GenOptions, generate};
use std::time::Duration;

fn engine() -> Engine {
    let cfg = CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap();
    Engine::from_config(&cfg, "offline", None, None).unwrap()
}

fn corpus() -> Vec<Doc> {
    let mut docs = embedded_cases();
    docs.extend(generate(&GenOptions {
        seed: 42,
        count: 300,
        transforms: true,
        ..GenOptions::default()
    }));
    docs
}

/// Sanitized text with every token's random suffix (and a surface token's
/// random two-character component) replaced by `x`.
fn masked(engine: &Engine, text: &str) -> String {
    let settings = engine.token_settings();
    let mut out = text.to_string();
    for tok in Rehydrator::new(settings).tokens_in(text) {
        let Some(p) = parse_token(settings, &tok) else {
            continue;
        };
        if p.removed {
            continue;
        }
        let variant = p.variant.map(|_| "_xx").unwrap_or_default();
        let m = format!(
            "{}{}_{}{}{}",
            settings.open,
            p.label,
            "x".repeat(p.suffix.len()),
            variant,
            settings.close
        );
        out = out.replace(&tok, &m);
    }
    out
}

fn run(engine: &Engine, docs: &[Doc]) -> Vec<(u8, usize, String)> {
    docs.iter()
        .map(|d| {
            let mut ctx = Context::new(
                ContextId(d.id.clone()),
                Duration::from_secs(60),
                engine.token_settings().clone(),
            );
            match engine.process(&d.text, &mut ctx).unwrap() {
                Outcome::Pass { sanitized } => (
                    0,
                    sanitized.replacements.len(),
                    masked(engine, &sanitized.text),
                ),
                Outcome::PassUncertain { sanitized, reasons } => {
                    (1, reasons.len(), masked(engine, &sanitized.text))
                }
                Outcome::Blocked { reasons, .. } => (2, reasons.len(), String::new()),
            }
        })
        .collect()
}

#[test]
fn detection_is_deterministic_over_the_corpus() {
    let e = engine();
    for d in corpus() {
        let a = e.detect(&d.text).unwrap();
        let b = e.detect(&d.text).unwrap();
        assert_eq!(a, b, "doc {}", d.id);
    }
}

#[test]
fn process_is_deterministic_modulo_token_suffixes() {
    let e = engine();
    let docs = corpus();
    let a = run(&e, &docs);
    let b = run(&e, &docs);
    assert_eq!(a.len(), docs.len());
    for (i, (x, y)) in a.iter().zip(&b).enumerate() {
        assert_eq!(x, y, "doc {}", docs[i].id);
    }
    // Whether the offline corpus exercises the retry path is not asserted
    // here (it may block nothing); the before/after eval JSON diff in the
    // task's Step 5 is the equivalence evidence, this test pins determinism.
}
