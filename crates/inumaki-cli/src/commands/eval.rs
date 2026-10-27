//! `inumaki eval`: metrics and the baseline gate. Prints counts and rates only.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use inumaki_core::TextOrigin;
use inumaki_core::engine::Engine;
use inumaki_core::span::EntityKind;
use inumaki_core::token::{Context, ContextId};
use inumaki_eval::cases::embedded_cases;
use inumaki_eval::corpus::{digest, read_jsonl, write_jsonl};
use inumaki_eval::generate::{
    GenFamily, GenOptions, HELD_OUT_COUNT, HELD_OUT_SEED, generate, held_out,
};
use inumaki_eval::metrics::{EngineSanitizer, EvalOutcome, Provenance};
use inumaki_eval::report::{Targets, current_platform};
use inumaki_eval::tool_json::{
    ToolDoc, ToolOptions, digest_tool_docs, evaluate_tool_docs, generate_tool_docs,
};
use inumaki_eval::{Baseline, EvalOptions, evaluate_with, render_text};
use sha2::{Digest as _, Sha256};

use super::build_engine;
use crate::exit;

const LOCK: &str = include_str!("../../../../Cargo.lock");

fn sha_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn git_commit() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn model_hashes() -> std::collections::BTreeMap<String, String> {
    inumaki_models::manifest::Manifest::embedded()
        .models
        .iter()
        .filter_map(|m| {
            m.files
                .iter()
                .find(|f| f.role == "model")
                .map(|f| (m.name.clone(), f.sha256.clone()))
        })
        .collect()
}

/// Default `--generate` of `eval` (the clap default in `main.rs`).
pub const DEFAULT_GENERATE: usize = 2000;
/// Default `--seed` of `eval` (the clap default in `main.rs`).
pub const DEFAULT_SEED: u64 = 42;

/// Whether this mail-track run is the canonical one (`Provenance::canonical`):
/// every option that changes the corpus, the configuration, or the path is
/// at its default.
fn is_canonical(config: Option<&Path>, a: &EvalArgs) -> bool {
    config.is_none()
        && a.corpus.is_none()
        && !a.no_cases
        && !a.held_out
        && !a.cases_only
        && !a.no_transforms
        && !a.no_verifier_trials
        && !a.via_service
        && !a.sequences
        && a.track == "mail"
        && a.generate == DEFAULT_GENERATE
        && a.seed == DEFAULT_SEED
}

/// Provenance for a run. `config` is the loaded config text (embedded when `None`).
fn provenance(
    config: Option<&Path>,
    docs: &[inumaki_eval::Doc],
    cases: usize,
    generated: usize,
    seed: u64,
    family: &str,
) -> anyhow::Result<Provenance> {
    let (config_text, config_source) = match config {
        Some(p) => (std::fs::read_to_string(p)?, "file"),
        None => (super::EMBEDDED_CONFIG.to_string(), "embedded"),
    };
    Ok(Provenance {
        corpus_sha256: digest(docs),
        cases,
        generated,
        seed,
        family: family.to_string(),
        platform: current_platform(),
        crate_version: env!("CARGO_PKG_VERSION").to_string(),
        git_commit: git_commit(),
        config_sha256: sha_hex(config_text.as_bytes()),
        config_source: config_source.to_string(),
        canonical: false,
        lock_sha256: sha_hex(LOCK.as_bytes()),
        models: model_hashes(),
        evaluated_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    })
}

/// Options of `inumaki eval`.
pub struct EvalArgs {
    pub corpus: Option<PathBuf>,
    /// The origin the corpus is evaluated as (mail track, engine path).
    pub origin: TextOrigin,
    pub no_cases: bool,
    pub generate: usize,
    pub seed: u64,
    pub no_transforms: bool,
    pub no_verifier_trials: bool,
    pub json: bool,
    pub baseline: Option<PathBuf>,
    pub write_baseline: Option<PathBuf>,
    pub dump_corpus: Option<PathBuf>,
    pub targets: Option<PathBuf>,
    pub report_json: Option<PathBuf>,
    /// Per-document `id outcome` lines (mail track).
    pub outcomes: Option<PathBuf>,
    pub held_out: bool,
    pub cases_only: bool,
    pub track: String,
    pub via_service: bool,
    pub sequences: bool,
    pub sequence_steps: usize,
    pub sequence_seed: u64,
}

/// Engine outcome to an evaluation outcome, keeping the sanitized text
/// only (never a store error's cause: `Engine::process` already discards
/// it and hands back `Err`).
fn outcome_of(o: inumaki_core::engine::Outcome) -> EvalOutcome {
    use inumaki_core::engine::Outcome;
    match o {
        Outcome::Pass { sanitized } => EvalOutcome::Pass {
            text: sanitized.text,
            replaced: Vec::new(),
        },
        Outcome::PassUncertain { sanitized, .. } => EvalOutcome::PassUncertain {
            text: sanitized.text,
            replaced: Vec::new(),
        },
        Outcome::Blocked { .. } => EvalOutcome::Blocked,
    }
}

/// The `tool_json` track's engine path (no `--via-service`): one fresh
/// `Context` per document, shared across its blocks, matching the
/// namespace-per-document scope `--via-service`'s dataset gives it.
/// Identifier blocks are tokenized whole through `ctx.token_for`, never
/// run through detection (M4 spec §16.6: the field contract already knows
/// what they are).
fn engine_tool_sanitizer(engine: &Engine) -> impl FnMut(&ToolDoc) -> Vec<EvalOutcome> + '_ {
    use inumaki_eval::tool_json::BlockHint;
    move |d: &ToolDoc| {
        let mut ctx = Context::new(
            ContextId(d.id.clone()),
            Duration::from_secs(60),
            engine.token_settings().clone(),
        );
        let mut out = Vec::with_capacity(d.blocks.len());
        for b in &d.blocks {
            let r = match &b.hint {
                BlockHint::FreeText => engine.process(&b.text, &mut ctx).map(outcome_of),
                BlockHint::Identifier(kind) => ctx
                    .token_for(&EntityKind::from_label(kind), &b.text)
                    .map(|t| EvalOutcome::Pass {
                        text: t.as_str().to_string(),
                        replaced: Vec::new(),
                    }),
            };
            match r {
                Ok(o) => out.push(o),
                Err(_) => return vec![EvalOutcome::StoreError; d.blocks.len()],
            }
        }
        out
    }
}

/// The `tool_json` track (M4 spec §16.6): no baseline or targets gate yet
/// (spec: gates are set after the first measurement); just generate,
/// evaluate, and print/write like the mail track's tail does.
fn run_tool_json(
    config: Option<&Path>,
    profile: &str,
    models_dir: Option<&Path>,
    a: &EvalArgs,
) -> Result<u8> {
    let family = if a.held_out {
        GenFamily::HeldOut
    } else {
        GenFamily::Tuning
    };
    let docs = generate_tool_docs(&ToolOptions {
        family,
        ..ToolOptions::default()
    });
    let mut report = if a.via_service {
        let s = super::eval_service::ServiceSanitizer::start(config, profile, models_dir, None)?;
        evaluate_tool_docs(&docs, &mut |d| s.sanitize_tool_doc(d), s.token_settings())
    } else {
        let engine = build_engine(config, profile, models_dir)?;
        evaluate_tool_docs(
            &docs,
            &mut engine_tool_sanitizer(&engine),
            engine.token_settings(),
        )
    };
    report.profile = profile.to_string();
    report.provenance = provenance(
        config,
        &[],
        0,
        docs.len(),
        4243,
        &format!("tool-json+{}", family.name()),
    )?;
    report.provenance.corpus_sha256 = digest_tool_docs(&docs);
    if a.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", render_text(&report));
    }
    if let Some(p) = &a.report_json {
        std::fs::write(p, serde_json::to_string_pretty(&report)?)?;
        eprintln!("report written to {}", p.display());
    }
    Ok(exit::OK)
}

/// Persistent-dataset sequences (M4 spec §13.1, plan 4a Task 6): one dataset
/// in an in-process daemon state, driven through restarts, a rotation, clock
/// advances past the recency window and the grace period, and a sweep.
fn run_sequences(
    config: Option<&Path>,
    profile: &str,
    models_dir: Option<&Path>,
    a: &EvalArgs,
) -> Result<u8> {
    use inumaki_eval::sequence::{SeqEvent, SequenceOptions, evaluate_sequence, generate_sequence};
    let clock = super::eval_service::EvalClock::now_system();
    let s = super::eval_service::ServiceSanitizer::start(
        config,
        profile,
        models_dir,
        Some(Arc::clone(&clock) as Arc<dyn inumaki_vault::Clock>),
    )?;
    let steps = generate_sequence(&SequenceOptions {
        seed: a.sequence_seed,
        ..SequenceOptions::scaled(a.sequence_steps)
    });
    let docs: Vec<inumaki_eval::Doc> = steps.iter().map(|st| st.doc.clone()).collect();
    let opts = EvalOptions {
        verifier_trials: false,
        seed: a.sequence_seed,
        ..EvalOptions::default()
    };
    let (mut driver, events, counter) = (s.clone(), s.clone(), s);
    let mut rotated = false;
    let mut on_event = |e: &SeqEvent| -> Result<(), String> {
        match e {
            SeqEvent::Restart => events.restart().map_err(|e| e.to_string()),
            SeqEvent::Rotate => {
                rotated = true;
                events.rotate().map_err(|e| e.to_string())
            }
            SeqEvent::AdvanceClock { secs } => {
                clock.advance(*secs);
                Ok(())
            }
            SeqEvent::Sweep => {
                let summary = events.sweep().map_err(|e| e.to_string())?;
                // The last sweep follows a rotation and a clock advance past
                // the grace period: it must have deleted the closed epoch. A
                // vault sweep that failed is only logged by the daemon and
                // shows here as zero.
                if rotated && summary.expired_epochs == 0 {
                    return Err("the sweep after the grace period expired no epoch".into());
                }
                Ok(())
            }
        }
    };
    let mut cached = || counter.cache_hits();
    let mut report = evaluate_sequence(&mut driver, &steps, &opts, &mut on_event, &mut cached);
    if let Some(q) = report.sequence.as_mut() {
        q.restore_errors = counter.restore_errors();
    }
    report.profile = profile.to_string();
    report.provenance = provenance(
        config,
        &docs,
        0,
        steps.len(),
        a.sequence_seed,
        "sequence+service",
    )?;
    finish(&report, a)
}

/// Print and write a finished report, then apply `--targets`.
fn finish(report: &inumaki_eval::Report, a: &EvalArgs) -> Result<u8> {
    if a.json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        print!("{}", render_text(report));
    }
    if let Some(p) = &a.report_json {
        std::fs::write(p, serde_json::to_string_pretty(report)?)?;
        eprintln!("report written to {}", p.display());
    }
    if let Some(p) = &a.targets {
        let targets = Targets::load(p)?;
        let missed = targets.check(report);
        if !missed.is_empty() {
            for m in &missed {
                eprintln!("target missed: {m}");
            }
            return Ok(exit::TARGET_MISSED);
        }
        eprintln!("all targets met ({})", p.display());
    }
    Ok(exit::OK)
}

/// Argument checks that need no engine, so a bad combination fails before
/// any model loads. The messages never carry corpus text.
fn check_args(a: &EvalArgs) -> Result<()> {
    if a.origin != TextOrigin::Free && a.track != "mail" {
        anyhow::bail!("--origin applies to a mail-track --corpus run");
    }
    if a.origin != TextOrigin::Free && (a.baseline.is_some() || a.write_baseline.is_some()) {
        // A baseline is measured on free text; a run of any other origin
        // must not silently pass or overwrite it (L109). Its gate is
        // `--targets`.
        anyhow::bail!(
            "--origin {} has no baseline; use --targets",
            a.origin.label()
        );
    }
    if a.sequences && a.track != "mail" {
        anyhow::bail!("--sequences runs its own corpus; it cannot be combined with --track");
    }
    if a.outcomes.is_some() && (a.track != "mail" || a.sequences) {
        anyhow::bail!("--outcomes applies to a mail-track run");
    }
    Ok(())
}

pub fn run(
    config: Option<&Path>,
    profile: &str,
    models_dir: Option<&Path>,
    a: EvalArgs,
) -> Result<u8> {
    check_args(&a)?;
    if a.track == "tool-json" {
        return run_tool_json(config, profile, models_dir, &a);
    }
    if a.sequences {
        if a.baseline.is_some() || a.write_baseline.is_some() {
            anyhow::bail!("sequence reports have no baseline");
        }
        return run_sequences(config, profile, models_dir, &a);
    }
    // Reproducibility of the baseline gate does not need pinned threads: the
    // verifier's re-scans mask each token's random suffix before reading the
    // sanitized text (`SecondPassVerifier::mask_token_suffixes`), and the NER
    // detector's own tie-break is a total order independent of hash-map
    // iteration order (`NerDetector::detect`). Confirmed empirically: two
    // runs of `eval --profile support-email --generate 300` are bit-for-bit
    // identical (aside from latency) both at 1 intra-op thread and at the
    // configured default thread count.
    let (docs, cases, generated, family, seed) = match &a.corpus {
        Some(p) => (read_jsonl(p)?, 0, 0, "file", a.seed),
        None if a.held_out => (
            held_out(),
            0,
            HELD_OUT_COUNT,
            GenFamily::HeldOut.name(),
            HELD_OUT_SEED,
        ),
        None if a.cases_only => (embedded_cases(), embedded_cases().len(), 0, "cases", a.seed),
        None => {
            let mut docs = if a.no_cases {
                Vec::new()
            } else {
                embedded_cases()
            };
            let cases = docs.len();
            docs.extend(generate(&GenOptions {
                seed: a.seed,
                count: a.generate,
                transforms: !a.no_transforms,
                family: GenFamily::Tuning,
            }));
            (docs, cases, a.generate, GenFamily::Tuning.name(), a.seed)
        }
    };
    if let Some(p) = &a.dump_corpus {
        write_jsonl(p, &docs)?;
    }
    let opts = EvalOptions {
        verifier_trials: !a.no_verifier_trials,
        seed,
        ..EvalOptions::default()
    };
    let mut report = if a.via_service {
        let mut s =
            super::eval_service::ServiceSanitizer::start(config, profile, models_dir, None)?;
        evaluate_with(&mut s, profile, &docs, &opts)
    } else {
        let engine = build_engine(config, profile, models_dir)?;
        evaluate_with(
            &mut EngineSanitizer::new(&engine).with_origin(a.origin),
            profile,
            &docs,
            &opts,
        )
    };
    // the report says where it was measured
    let family = if a.via_service {
        format!("{family}+service")
    } else if a.origin != TextOrigin::Free {
        format!("{family}+{}", a.origin.label())
    } else {
        family.to_string()
    };
    report.provenance = provenance(config, &docs, cases, generated, seed, &family)?;
    report.provenance.canonical = is_canonical(config, &a);
    if a.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", render_text(&report));
    }
    if let Some(p) = &a.report_json {
        std::fs::write(p, serde_json::to_string_pretty(&report)?)?;
        eprintln!("report written to {}", p.display());
    }
    if let Some(p) = &a.outcomes {
        let mut lines = String::new();
        for o in &report.doc_outcomes {
            lines.push_str(&o.line());
            lines.push('\n');
        }
        std::fs::write(p, lines)?;
        eprintln!("outcomes written to {}", p.display());
    }
    if let Some(p) = &a.write_baseline {
        Baseline::from_report(&report).save(p)?;
        eprintln!("baseline written to {}", p.display());
    }
    if let Some(p) = &a.baseline {
        let baseline = Baseline::load(p)?;
        if let Some(measured_on) = &baseline.platform {
            let here = current_platform();
            if *measured_on != here {
                eprintln!("warning: baseline was measured on {measured_on}, this run is on {here}");
            }
        }
        let problems = baseline.check(&report);
        if !problems.is_empty() {
            for m in &problems {
                eprintln!("regression: {m}");
            }
            return Ok(exit::REGRESSION);
        }
    }
    if let Some(p) = &a.targets {
        let targets = Targets::load(p)?;
        let missed = targets.check(&report);
        if !missed.is_empty() {
            for m in &missed {
                eprintln!("target missed: {m}");
            }
            return Ok(exit::TARGET_MISSED);
        }
        eprintln!("all targets met ({})", p.display());
    }
    Ok(exit::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_args() -> EvalArgs {
        EvalArgs {
            corpus: None,
            origin: TextOrigin::Free,
            no_cases: false,
            generate: DEFAULT_GENERATE,
            seed: DEFAULT_SEED,
            no_transforms: false,
            no_verifier_trials: false,
            json: false,
            baseline: None,
            write_baseline: None,
            dump_corpus: None,
            targets: None,
            report_json: None,
            outcomes: None,
            held_out: false,
            cases_only: false,
            track: "mail".to_string(),
            via_service: false,
            sequences: false,
            sequence_steps: 300,
            sequence_seed: 777,
        }
    }

    /// A harness-static run has no baseline: both baseline flags are refused
    /// before any model loads, and `--targets` stays accepted.
    #[test]
    fn harness_static_refuses_both_baseline_flags_but_accepts_targets() {
        let mut a = default_args();
        a.origin = TextOrigin::HarnessStatic;
        a.baseline = Some(PathBuf::from("b.toml"));
        let e = check_args(&a).unwrap_err().to_string();
        assert!(e.contains("no baseline"), "{e}");
        assert!(run(None, "offline", None, a).is_err());

        let mut a = default_args();
        a.origin = TextOrigin::HarnessStatic;
        a.write_baseline = Some(PathBuf::from("b.toml"));
        assert!(check_args(&a).is_err());

        let mut a = default_args();
        a.origin = TextOrigin::HarnessStatic;
        a.targets = Some(PathBuf::from("t.toml"));
        assert!(check_args(&a).is_ok());

        // free text keeps its baselines
        let mut a = default_args();
        a.baseline = Some(PathBuf::from("b.toml"));
        assert!(check_args(&a).is_ok());
    }

    /// L109 for every origin: a file-name run has no baseline either; the
    /// refusal names the origin and carries no corpus text.
    #[test]
    fn file_name_origin_refuses_both_baseline_flags() {
        for set in [
            (|a: &mut EvalArgs| a.baseline = Some(PathBuf::from("b.toml"))) as fn(&mut EvalArgs),
            |a| a.write_baseline = Some(PathBuf::from("b.toml")),
        ] {
            let mut a = default_args();
            a.origin = TextOrigin::FileName;
            set(&mut a);
            let e = check_args(&a).unwrap_err().to_string();
            assert!(e.contains("file-name") && e.contains("no baseline"), "{e}");
        }
        let mut a = default_args();
        a.origin = TextOrigin::FileName;
        a.targets = Some(PathBuf::from("t.toml"));
        assert!(check_args(&a).is_ok());
    }

    /// The app embeds only canonical reports (`Provenance::canonical`): any
    /// option off its default must clear the marker.
    #[test]
    fn only_the_all_default_run_is_canonical() {
        assert!(is_canonical(None, &default_args()));
        let tweaks: Vec<fn(&mut EvalArgs)> = vec![
            |a| a.generate = 300,
            |a| a.seed = 7,
            |a| a.no_transforms = true,
            |a| a.no_cases = true,
            |a| a.no_verifier_trials = true,
            |a| a.held_out = true,
            |a| a.cases_only = true,
            |a| a.via_service = true,
            |a| a.sequences = true,
            |a| a.track = "tool-json".to_string(),
            |a| a.corpus = Some(PathBuf::from("c.jsonl")),
        ];
        for t in tweaks {
            let mut a = default_args();
            t(&mut a);
            assert!(!is_canonical(None, &a));
        }
        assert!(!is_canonical(Some(Path::new("c.toml")), &default_args()));
    }
}
