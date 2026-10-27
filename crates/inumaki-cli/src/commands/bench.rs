//! `inumaki bench`: per-document latency of detection alone and of the full pipeline.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use hyper::Method;
use inumaki_core::token::{Context, ContextId};
use inumaki_eval::generate::{GenFamily, GenOptions, generate};
use serde_json::json;

use super::build_engine;
use crate::client::{call, connect, error_line};
use crate::exit;

fn pct(sorted: &[f64], q: f64) -> f64 {
    sorted[((sorted.len() - 1) as f64 * q).round() as usize]
}

pub fn run(
    config: Option<&Path>,
    profile: &str,
    models_dir: Option<&Path>,
    count: usize,
    seed: u64,
) -> Result<u8> {
    let engine = build_engine(config, profile, models_dir)?;
    let docs = generate(&GenOptions {
        seed,
        count: count.max(1),
        transforms: true,
        family: GenFamily::Tuning,
    });
    // Warm-up: first model calls allocate. A dead model must fail the bench, not
    // silently benchmark an empty detector, so this propagates too.
    for d in docs.iter().take(3) {
        engine.detect(&d.text)?;
    }
    let (mut detect, mut process) = (Vec::new(), Vec::new());
    let mut bytes = 0usize;
    let t_all = Instant::now();
    for d in &docs {
        bytes += d.text.len();
        let t = Instant::now();
        engine.detect(&d.text)?;
        detect.push(t.elapsed().as_secs_f64() * 1000.0);
        let mut ctx = Context::new(
            ContextId(d.id.clone()),
            Duration::from_secs(60),
            engine.token_settings().clone(),
        );
        let t = Instant::now();
        engine.process(&d.text, &mut ctx)?;
        process.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    let secs = t_all.elapsed().as_secs_f64();
    detect.sort_by(|a, b| a.total_cmp(b));
    process.sort_by(|a, b| a.total_cmp(b));
    println!(
        "profile {profile}  docs {}  avg {} bytes",
        docs.len(),
        bytes / docs.len()
    );
    for (name, v) in [("detect", &detect), ("process", &process)] {
        println!(
            "{name:<8} p50 {:.1} ms  p95 {:.1} ms  p99 {:.1} ms",
            pct(v, 0.5),
            pct(v, 0.95),
            pct(v, 0.99)
        );
    }
    println!("throughput {:.1} docs/s", docs.len() as f64 / secs);
    Ok(exit::OK)
}

/// The milestone-2 bench over the socket: one `sanitize` per document,
/// twice. The first pass is cold (engine work), the second warm (cache
/// hits for a dataset). Each call opens its own connection, as a client
/// would.
pub fn run_via_daemon(
    socket: Option<&Path>,
    data_dir: Option<&Path>,
    config: Option<&Path>,
    dataset: Option<&str>,
    count: usize,
    seed: u64,
) -> Result<u8> {
    let c = connect(socket, data_dir, config)?;
    let docs = generate(&GenOptions {
        seed,
        count: count.max(1),
        transforms: true,
        family: GenFamily::Tuning,
    });
    let temporary = dataset.is_none();
    let ds = dataset
        .map(str::to_string)
        .unwrap_or_else(|| format!("bench-{}", std::process::id()));
    if temporary {
        let r = call(
            &c,
            Method::POST,
            "/v1/datasets",
            Some(&json!({ "id": ds, "name": "bench" })),
        )?;
        if r.status.as_u16() != 201 {
            bail!("creating the bench dataset: {}", error_line(&r));
        }
    }
    let status = call(&c, Method::GET, "/v1/status", None)?;
    let profile = status.body["datasets"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|d| d["id"] == ds.as_str())
        .and_then(|d| d["profile"].as_str())
        .unwrap_or("?")
        .to_string();
    let pass = |label: &str| -> Result<(Vec<f64>, usize, usize)> {
        let (mut times, mut hits, mut blocked) = (Vec::with_capacity(docs.len()), 0usize, 0usize);
        for d in &docs {
            let t = Instant::now();
            let r = call(
                &c,
                Method::POST,
                "/v1/sanitize",
                Some(&json!({ "dataset": ds, "text": d.text })),
            )
            .with_context(|| format!("{label} pass"))?;
            times.push(t.elapsed().as_secs_f64() * 1000.0);
            match r.status.as_u16() {
                200 => hits += usize::from(r.body["cached"] == true),
                451 => blocked += 1,
                _ => bail!("{label} pass: {}", error_line(&r)),
            }
        }
        times.sort_by(|a, b| a.total_cmp(b));
        Ok((times, hits, blocked))
    };
    let t_all = Instant::now();
    let (cold, _, blocked) = pass("cold")?;
    let cold_secs = t_all.elapsed().as_secs_f64();
    let (warm, hits, _) = pass("warm")?;
    if temporary {
        let r = call(&c, Method::DELETE, &format!("/v1/datasets/{ds}"), None)?;
        if r.status.as_u16() != 204 {
            bail!("deleting the bench dataset: {}", error_line(&r));
        }
    }
    let bytes: usize = docs.iter().map(|d| d.text.len()).sum();
    println!(
        "via daemon  dataset {ds}  profile {profile}  docs {}  avg {} bytes  blocked {blocked}",
        docs.len(),
        bytes / docs.len()
    );
    for (name, v) in [("cold", &cold), ("warm", &warm)] {
        println!(
            "{name:<8} p50 {:.1} ms  p95 {:.1} ms  p99 {:.1} ms",
            pct(v, 0.5),
            pct(v, 0.95),
            pct(v, 0.99)
        );
    }
    println!(
        "warm cache hits {hits}/{} (blocked documents excluded)",
        docs.len() - blocked
    );
    println!(
        "cold throughput {:.1} docs/s",
        docs.len() as f64 / cold_secs
    );
    Ok(exit::OK)
}
