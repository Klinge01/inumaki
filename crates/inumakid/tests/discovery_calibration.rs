#![cfg(feature = "models-tests")]
//! Plan 2c Task 1: the scripted upstream's discovery metadata (the texts
//! the 2026-09-28 Claude Code smoke run was refused on), benign
//! descriptions from similar servers, and descriptions carrying a person or
//! an IBAN, under each model-backed base profile and under candidate
//! metadata profiles per family. Prints one line per failing text and
//! candidate, the margins, and the decision; asserts only that the smoke
//! refusal reproduces. A measurement, not a gate: `#[ignore]`, run with
//! `--ignored`. Synthetic data only, so the texts are printed.
#![allow(clippy::print_stderr)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use inumaki_core::config::CoreConfig;
use inumaki_core::detect::{DetectCtx, Detector};
use inumaki_core::engine::{Engine, Outcome};
use inumaki_core::span::EntityKind;
use inumaki_core::token::{Context, ContextId};
use inumaki_core::verify::CheckId;
use inumaki_gateway::scripted::{IBAN, IDENTITY, ScriptedUpstream};
use inumaki_models::assemble::{BackendCache, ner_for_profile_with};
use serde_json::Value;

/// Server-authored prose and enum values of the kind real MCP servers
/// list: none names a person or holds an identifier.
const BENIGN: &[&str] = &[
    "Read the complete contents of a file from the file system",
    "List all files and directories in a path",
    "Search for repositories by name or topic",
    "Create a new issue in a repository",
    "maximum number of results to return",
    "the page of results to fetch",
    "Get the current weather for a city",
    "Send a message to a channel",
    "look up an order by its number",
    "name of the customer to search for",
    "Termine eines Mitarbeiters für eine Woche anzeigen",
    "Suche nach Produkten im Katalog",
    "sort order",
    "asc",
    "desc",
    "created_at",
    "full_name",
];

/// Probe descriptions (not the scripted server's) that carry a person or
/// an IBAN, with the value that must not appear in clear.
fn probe_positives() -> Vec<(String, String)> {
    vec![
        (format!("Rückfragen an {IDENTITY}"), IDENTITY.to_string()),
        (
            "orders placed by Sarah Leitner".into(),
            "Sarah Leitner".into(),
        ),
        (
            "Ansprechpartnerin ist Maria Huber aus Wien".into(),
            "Maria Huber".into(),
        ),
        (
            "the account of Hans-Peter Gruber".into(),
            "Hans-Peter Gruber".into(),
        ),
        (format!("pays to {IBAN}"), IBAN.to_string()),
    ]
}

/// Profile families: members share one metadata calibration.
const FAMILIES: [(&str, [&str; 2]); 2] = [
    ("support-email", ["support-email", "strict"]),
    ("thorough", ["thorough", "thorough-strict"]),
];
/// Path A candidates in preference order: (PERSON `min_confidence`,
/// `escalate_below`) in hundredths, 100 = no escalation band. Capped at
/// 0.75: a dictionary surname-only match scores 0.80.
const GRID_A: [(u32, u32); 12] = [
    (60, 55),
    (60, 60),
    (60, 100),
    (65, 55),
    (65, 60),
    (65, 100),
    (70, 55),
    (70, 60),
    (70, 100),
    (75, 55),
    (75, 60),
    (75, 100),
];
/// Path B candidates: verifier NER confidence floor in hundredths.
const GRID_B: [u32; 10] = [50, 55, 60, 65, 70, 75, 80, 85, 90, 95];

fn probe_a_name(base: &str, t: u32, e: u32) -> String {
    format!("probe-{base}-{t}-{e}")
}

/// `base` with PERSON tokenized from `t`/100 and `escalate_below` `e`/100.
fn probe_a_toml(base: &str, t: u32, e: u32) -> String {
    let n = probe_a_name(base, t, e);
    format!(
        "\n[profiles.{n}]\nextends = \"{base}\"\nescalate_below = {:.2}\n\
         [profiles.{n}.entities]\nPERSON = {{ action = \"tokenize\", min_confidence = {:.2} }}\n\
         [profiles.{n}.verifier]\nretry_profile = \"{n}\"\n",
        f64::from(e) / 100.0,
        f64::from(t) / 100.0
    )
}

/// Path B: `base` without any NER and without an escalation band; the
/// probe applies the verifier floor by hand with the base's verifier NER.
fn probe_b_toml(base: &str) -> String {
    format!(
        "\n[profiles.probe-b-{base}]\nextends = \"{base}\"\nner_sanitizer = \"none\"\nner_verifier = \"none\"\nescalate_below = 1.0\n\
         [profiles.probe-b-{base}.verifier]\nallow_no_ner = true\nretry_profile = \"probe-b-{base}\"\n"
    )
}

fn build(cfg: &CoreConfig, name: &str, root: &Path, cache: &BackendCache) -> Engine {
    let p = cfg.resolve_profile(name).unwrap();
    let ner = ner_for_profile_with(cfg, &p, root, cache).unwrap();
    Engine::from_config(cfg, name, ner.sanitizer, ner.verifier).unwrap()
}

/// Outcome class, candidate (empty when blocked), check ids; a fresh
/// context per text so texts do not see each other's originals.
fn run(engine: &Engine, text: &str) -> (&'static str, String, Vec<CheckId>) {
    let mut ctx = Context::new(
        ContextId("m".into()),
        Duration::from_secs(60),
        engine.token_settings().clone(),
    );
    match engine.process(text, &mut ctx).unwrap() {
        Outcome::Pass { sanitized } => ("pass", sanitized.text, Vec::new()),
        Outcome::PassUncertain { sanitized, reasons } => (
            "uncertain",
            sanitized.text,
            reasons.into_iter().map(|r| r.check).collect(),
        ),
        Outcome::Blocked { reasons, .. } => (
            "blocked",
            String::new(),
            reasons.into_iter().map(|r| r.check).collect(),
        ),
    }
}

/// Sanitizer spans as `KIND:confidence:"excerpt"`.
fn spans(engine: &Engine, text: &str) -> String {
    engine
        .detect(text)
        .unwrap()
        .iter()
        .map(|s| {
            format!(
                "{}:{:.2}:{:?}",
                s.kind.label(),
                s.confidence,
                &text[s.start..s.end]
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Highest PERSON confidence among `engine`'s sanitizer spans.
fn person_max(engine: &Engine, text: &str) -> f32 {
    engine
        .detect(text)
        .unwrap()
        .iter()
        .filter(|s| s.kind == EntityKind::Person)
        .map(|s| s.confidence)
        .fold(0.0, f32::max)
}

/// Highest PERSON or STREET_ADDRESS confidence of a verifier re-scan (the
/// kinds its NER check counts).
fn verifier_max(v: &dyn Detector, text: &str) -> f32 {
    v.detect(text, &DetectCtx::for_text(text))
        .unwrap()
        .iter()
        .filter(|s| matches!(s.kind, EntityKind::Person | EntityKind::StreetAddress))
        .map(|s| s.confidence)
        .fold(0.0, f32::max)
}

/// No word of four or more characters of `secret` is in `out`.
fn clean(out: &str, secret: &str) -> bool {
    secret
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.chars().count() >= 4)
        .all(|w| !out.contains(w))
}

/// Every text a listing of the scripted server sends to the engine:
/// descriptions, titles, schema prose, enum values.
fn scripted_texts() -> Vec<String> {
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(o) => {
                for (k, x) in o {
                    match (k.as_str(), x) {
                        ("description" | "title", Value::String(s)) => out.push(s.clone()),
                        ("enum", Value::Array(a)) => {
                            out.extend(a.iter().filter_map(Value::as_str).map(str::to_string));
                        }
                        _ => walk(x, out),
                    }
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let s = ScriptedUpstream::default();
    let mut out = Vec::new();
    for t in s.tools() {
        out.extend(t.description.as_deref().map(str::to_string));
        out.extend(t.title.clone());
        walk(&Value::Object((*t.input_schema).clone()), &mut out);
        if let Some(o) = &t.output_schema {
            walk(&Value::Object((**o).clone()), &mut out);
        }
    }
    for p in s.prompts() {
        out.extend(p.description.clone());
        for a in p.arguments.iter().flatten() {
            out.extend(a.description.clone());
            out.extend(a.title.clone());
        }
    }
    for t in s.templates() {
        out.push(t.name.clone());
        out.extend(t.description.clone());
        out.extend(t.title.clone());
    }
    out.sort();
    out.dedup();
    out
}

/// The texts, split by what a listing needs from them.
struct Sets {
    /// Must pass unchanged (an enum value that changes fails the listing).
    benign: Vec<String>,
    /// The scripted server's texts that carry the canary or its IBAN: the
    /// listing must pass with them tokenized, or the smoke test fails.
    scripted_positives: Vec<String>,
    /// Must be tokenized or refused.
    probe_positives: Vec<(String, String)>,
}

/// The `Sets` shared by every calibration test: the scripted server's own
/// texts split into benign and canary-carrying, plus the probe positives.
fn sets() -> Sets {
    let scripted = scripted_texts();
    let carries = |t: &str| t.contains(IDENTITY) || t.contains(IBAN);
    let mut benign: Vec<String> = scripted.iter().filter(|t| !carries(t)).cloned().collect();
    benign.extend(BENIGN.iter().map(|s| (*s).to_string()));
    Sets {
        benign,
        scripted_positives: scripted.iter().filter(|t| carries(t)).cloned().collect(),
        probe_positives: probe_positives(),
    }
}

/// Path A's rule for one engine; prints every text that breaks it.
fn passes_a(label: &str, e: &Engine, s: &Sets) -> bool {
    let mut ok = true;
    for x in &s.benign {
        let (o, out, checks) = run(e, x);
        if o != "pass" || out != *x {
            ok = false;
            eprintln!(
                "  {label} benign   {o:9} {checks:?} {x:?} -> {out:?} | {}",
                spans(e, x)
            );
        }
    }
    for x in &s.scripted_positives {
        let (o, out, checks) = run(e, x);
        let tokenized = out.contains("<PERSON_") || out.contains("<IBAN_");
        if !(o == "pass" && clean(&out, IDENTITY) && clean(&out, IBAN) && tokenized) {
            ok = false;
            eprintln!("  {label} scripted {o:9} {checks:?} {x:?} -> {out:?}");
        }
    }
    for (x, secret) in &s.probe_positives {
        let (o, out, checks) = run(e, x);
        if !(o == "blocked" || clean(&out, secret)) {
            ok = false;
            eprintln!("  {label} positive {o:9} {checks:?} {x:?} -> {out:?}");
        }
    }
    eprintln!("{label}: {}", if ok { "passes" } else { "fails" });
    ok
}

/// Path B's rule, emulated: `e` has no NER; a text on which the verifier
/// NER scores at or above `floor` counts as refused. The scripted
/// positives are reported, not required: without NER the canary is
/// tokenized only when a dictionary lists it.
fn passes_b(label: &str, e: &Engine, verifier: &dyn Detector, floor: f64, s: &Sets) -> bool {
    let fires = |x: &str| f64::from(verifier_max(verifier, x)) >= floor;
    let mut ok = true;
    for x in &s.benign {
        let (o, out, _) = run(e, x);
        if o != "pass" || out != *x || fires(x) {
            ok = false;
            eprintln!("  {label} benign   {o:9} fires {} {x:?}", fires(x));
        }
    }
    for (x, secret) in &s.probe_positives {
        let (o, out, _) = run(e, x);
        if !(o == "blocked" || clean(&out, secret) || fires(x)) {
            ok = false;
            eprintln!("  {label} positive {o:9} {x:?} -> {out:?}");
        }
    }
    for x in &s.scripted_positives {
        let (o, out, _) = run(e, x);
        eprintln!(
            "  {label} scripted {o:9} fires {} {x:?} -> {out:?} (needs a dictionary entry)",
            fires(x)
        );
    }
    eprintln!("{label}: {}", if ok { "passes" } else { "fails" });
    ok
}

#[test]
#[ignore = "measurement, not a gate: run with --ignored (plan 2c Task 1)"]
fn discovery_metadata_calibration() {
    let root = PathBuf::from(std::env::var("INUMAKI_MODELS_DIR").expect("set INUMAKI_MODELS_DIR"));
    let mut toml = include_str!("../../../configs/default.toml").to_string();
    for (_, members) in FAMILIES {
        for base in members {
            for (t, e) in GRID_A {
                toml.push_str(&probe_a_toml(base, t, e));
            }
            toml.push_str(&probe_b_toml(base));
        }
    }
    let cfg = CoreConfig::from_toml(&toml).unwrap();
    let cache = BackendCache::new();

    let scripted = scripted_texts();
    let sets = sets();

    // 1. Every model-backed base as it is; the smoke refusal must
    //    reproduce under `strict` (a benign scripted text blocked by the
    //    policy check, i.e. an escalated span). `fast` is recorded for
    //    the threat model: it gets no metadata profile.
    let mut repro = false;
    for base in [
        "fast",
        "fast-strict",
        "support-email",
        "strict",
        "thorough",
        "thorough-strict",
    ] {
        let e = build(&cfg, base, &root, &cache);
        for t in &sets.benign {
            let (o, _, checks) = run(&e, t);
            if base == "strict"
                && scripted.contains(t)
                && o == "blocked"
                && checks.contains(&CheckId::Policy)
            {
                repro = true;
            }
            if o != "pass" {
                eprintln!("{base:16} {o:9} {checks:?} {t:?} | {}", spans(&e, t));
            }
        }
    }

    // 2. Per family: the first path A candidate both members pass; else
    //    the lowest path B floor both members pass.
    let mut decisions = Vec::new();
    for (family, members) in FAMILIES {
        let a = GRID_A.iter().copied().find(|&(t, e)| {
            members.iter().all(|base| {
                let engine = build(&cfg, &probe_a_name(base, t, e), &root, &cache);
                passes_a(&format!("{base} T={t} E={e}"), &engine, &sets)
            })
        });
        // Margins: highest benign PERSON score and lowest PERSON score on a
        // positive, under the family's first member.
        let e0 = build(&cfg, members[0], &root, &cache);
        let benign_top = sets
            .benign
            .iter()
            .map(|x| person_max(&e0, x))
            .fold(0.0, f32::max);
        let positive_low = sets
            .scripted_positives
            .iter()
            .chain(sets.probe_positives.iter().map(|(x, _)| x))
            .map(|x| person_max(&e0, x))
            .filter(|c| *c > 0.0)
            .fold(1.0, f32::min);
        eprintln!(
            "{family}: benign PERSON max {benign_top:.2}, positive PERSON min {positive_low:.2}"
        );
        let decision = match a {
            Some((t, e)) => format!(
                "{family}: A (PERSON min_confidence {:.2}, escalate_below {:.2})",
                f64::from(t) / 100.0,
                f64::from(e) / 100.0
            ),
            None => {
                let b = GRID_B.iter().copied().find(|&tv| {
                    members.iter().all(|base| {
                        let pair = ner_for_profile_with(
                            &cfg,
                            &cfg.resolve_profile(base).unwrap(),
                            &root,
                            &cache,
                        )
                        .unwrap();
                        let verifier = pair.verifier.expect("a verifier NER");
                        let engine = build(&cfg, &format!("probe-b-{base}"), &root, &cache);
                        passes_b(
                            &format!("{base} B={tv}"),
                            &engine,
                            &*verifier,
                            f64::from(tv) / 100.0,
                            &sets,
                        )
                    })
                });
                match b {
                    Some(tv) => format!(
                        "{family}: B (verifier floor {:.2}) -> BLOCKED, the integrator decides",
                        f64::from(tv) / 100.0
                    ),
                    None => format!("{family}: NONE -> BLOCKED, the integrator decides"),
                }
            }
        };
        decisions.push(decision);
    }
    for d in &decisions {
        eprintln!("DECISION {d}");
    }
    assert!(
        repro,
        "the 2026-09-28 smoke refusal does not reproduce under strict; stop and report"
    );
}

/// Plan 2c Task 3 addendum point 6: a confirmation, not a fresh search.
/// `configs/default.toml` unchanged (the two shipped metadata profiles, no
/// probe candidates) must pass path A's rule against the same texts the
/// calibration used. A measurement, not a gate: `#[ignore]`.
#[test]
#[ignore = "measurement, not a gate: run with --ignored (plan 2c Task 3)"]
fn shipped_metadata_profiles_pass_the_rule() {
    let root = PathBuf::from(std::env::var("INUMAKI_MODELS_DIR").expect("set INUMAKI_MODELS_DIR"));
    let cfg = CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap();
    let cache = BackendCache::new();
    let sets = sets();

    for name in ["support-email-metadata", "strict-metadata"] {
        let e = build(&cfg, name, &root, &cache);
        let benign_top = sets
            .benign
            .iter()
            .map(|x| person_max(&e, x))
            .fold(0.0, f32::max);
        let positive_low = sets
            .scripted_positives
            .iter()
            .chain(sets.probe_positives.iter().map(|(x, _)| x))
            .map(|x| person_max(&e, x))
            .filter(|c| *c > 0.0)
            .fold(1.0, f32::min);
        eprintln!(
            "{name}: benign PERSON max {benign_top:.2}, positive PERSON min {positive_low:.2}"
        );
        assert!(passes_a(name, &e, &sets), "{name} fails path A's rule");
    }
}
