//! `inumaki scan`: print detected spans. This is a local diagnostic and prints matched text.

use std::path::Path;

use anyhow::{Context as _, Result};
use serde_json::json;

use inumaki_core::TextOrigin;
use inumaki_core::engine::normalize_input;

use super::{build_engine, read_input};
use crate::exit;

pub fn run(
    config: Option<&Path>,
    profile: &str,
    models_dir: Option<&Path>,
    input: &Path,
    json: bool,
    origin: TextOrigin,
) -> Result<u8> {
    let engine = build_engine(config, profile, models_dir)?;
    // Span offsets refer to the NFC form of the input.
    let text = normalize_input(&read_input(input)?).into_owned();
    let spans = engine
        .detect_at(&text, origin)
        .context("detection failed")?;
    if json {
        let items: Vec<_> = spans
            .iter()
            .map(|s| {
                json!({
                    "kind": s.kind.label(),
                    "start": s.start,
                    "end": s.end,
                    "confidence": s.confidence,
                    "source": format!("{:?}", s.source),
                    "text": s.slice(&text),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        println!(
            "{:<16} {:>6} {:>6} {:>5}  {:<15} TEXT",
            "KIND", "START", "END", "CONF", "SOURCE"
        );
        for s in &spans {
            println!(
                "{:<16} {:>6} {:>6} {:>5.2}  {:<15} {}",
                s.kind.label(),
                s.start,
                s.end,
                s.confidence,
                format!("{:?}", s.source),
                s.slice(&text)
            );
        }
    }
    Ok(exit::OK)
}
