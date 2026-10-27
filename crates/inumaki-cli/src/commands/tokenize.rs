//! `inumaki tokenize`: print the sanitized candidate.

use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use inumaki_core::engine::{Outcome, normalize_input};
use inumaki_core::span::EntityKind;
use inumaki_core::token::{Context, ContextId};
use inumaki_core::verify::Reason;

use super::{build_engine, read_input};
use crate::exit;

pub fn run(
    config: Option<&Path>,
    profile: &str,
    models_dir: Option<&Path>,
    input: &Path,
    map: bool,
) -> Result<u8> {
    let engine = build_engine(config, profile, models_dir)?;
    // Replacement spans refer to the NFC form of the input.
    let text = normalize_input(&read_input(input)?).into_owned();
    let mut ctx = Context::new(
        ContextId("cli".into()),
        Duration::from_secs(60),
        engine.token_settings().clone(),
    );
    let outcome = engine.process(&text, &mut ctx)?;
    let (sanitized, uncertain) = match outcome {
        Outcome::Pass { sanitized } => (sanitized, None),
        Outcome::PassUncertain { sanitized, reasons } => (sanitized, Some(reasons)),
        Outcome::Blocked { reasons, kinds } => {
            eprintln!(
                "blocked: kinds={} checks={}",
                labels(&kinds),
                checks(&reasons)
            );
            return Ok(exit::BLOCKED);
        }
    };
    print!("{}", sanitized.text);
    if let Some(reasons) = uncertain {
        // Kinds and check ids only, never values.
        let kinds: Vec<EntityKind> = reasons.iter().fold(Vec::new(), |mut acc, r| {
            if !acc.contains(&r.kind) {
                acc.push(r.kind.clone());
            }
            acc
        });
        eprintln!(
            "uncertain: kinds={} checks={}",
            labels(&kinds),
            checks(&reasons)
        );
    }
    if map {
        for r in &sanitized.replacements {
            if let Some(t) = &r.token {
                eprintln!("{} => {}", t.as_str(), r.span.slice(&text));
            }
        }
    }
    Ok(exit::OK)
}

fn labels(kinds: &[EntityKind]) -> String {
    kinds
        .iter()
        .map(|k| k.label())
        .collect::<Vec<_>>()
        .join(",")
}

fn checks(reasons: &[Reason]) -> String {
    reasons
        .iter()
        .map(|r| format!("{:?}", r.check))
        .collect::<Vec<_>>()
        .join(",")
}
