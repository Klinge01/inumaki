//! Corpus metrics: detection recall/precision per kind, end-to-end leak rate,
//! verifier false-negative/false-positive rates, and latency.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use inumaki_core::config::TokenSettings;
use inumaki_core::engine::{Engine, Outcome};
use inumaki_core::policy::{Action, Decision};
use inumaki_core::resolve::resolve_overlaps;
use inumaki_core::sanitize::{Sanitized, sanitize};
use inumaki_core::span::{DetectorId, EntityKind, Span};
use inumaki_core::token::{Context, ContextId, normalize, parse_token};
use inumaki_core::verify::{Verdict, Verifier};
use inumaki_core::{LinkScope, TextOrigin};
use serde::{Deserialize, Serialize};

use crate::corpus::{Doc, GoldSpan};
use crate::rng::Rng;

/// Evaluation options.
#[derive(Debug, Clone)]
pub struct EvalOptions {
    /// Minimum intersection-over-union for a detected span to match a gold span.
    pub iou: f64,
    /// Run verifier trials (clean and broken sanitizations).
    pub verifier_trials: bool,
    /// Seed for choosing which span a broken trial drops.
    pub seed: u64,
}

impl Default for EvalOptions {
    fn default() -> Self {
        EvalOptions {
            iou: 0.5,
            verifier_trials: true,
            seed: 42,
        }
    }
}

/// Counts for one entity kind.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KindStats {
    /// Gold spans of this kind.
    pub gold: usize,
    /// Gold spans matched by a detection.
    pub gold_found: usize,
    /// Detected spans of this kind.
    pub detected: usize,
    /// Detected spans matching some gold span.
    pub detected_correct: usize,
    /// Sensitive gold spans of this kind whose text reached the sanitized output.
    pub leaked: usize,
    /// Sensitive gold spans of this kind whose identifying component (name part,
    /// street name, local part) reached the output while the whole value did not.
    #[serde(default)]
    pub partial_leaked: usize,
}

impl KindStats {
    /// Detection recall, if there is gold.
    pub fn recall(&self) -> Option<f64> {
        (self.gold > 0).then(|| self.gold_found as f64 / self.gold as f64)
    }

    /// Detection precision, if anything was detected.
    pub fn precision(&self) -> Option<f64> {
        (self.detected > 0).then(|| self.detected_correct as f64 / self.detected as f64)
    }
}

/// One replacement a sanitizer made, byte offsets into the input and the
/// output. Eval-only: never logged outside this crate's own synthetic
/// corpora.
#[derive(Debug, Clone, PartialEq)]
pub struct Replaced {
    /// Byte offset of the first byte of the original value.
    pub start: usize,
    /// Byte offset one past the last byte of the original value.
    pub end: usize,
    /// Byte offset of the first byte of the replacement in the output.
    pub out_start: usize,
    /// Byte offset one past the last byte of the replacement in the output.
    pub out_end: usize,
    /// Entity kind label, e.g. `PERSON`.
    pub kind: String,
    /// Whether the replacement is a token (`true`) or a removed-value
    /// marker (`false`).
    pub tokenized: bool,
}

/// One block's or document's sanitization result, as an evaluation track
/// needs it. Holds sanitized text only, never the original: this is the eval
/// crate's own synthetic corpora, but the derived `Debug` is still not for
/// logs outside tests.
#[derive(Debug, Clone, PartialEq)]
pub enum EvalOutcome {
    /// Released without reservation.
    Pass {
        /// Sanitized text.
        text: String,
        /// Replacements made.
        replaced: Vec<Replaced>,
    },
    /// Released, but a check could not fully confirm it.
    PassUncertain {
        /// Sanitized text.
        text: String,
        /// Replacements made.
        replaced: Vec<Replaced>,
    },
    /// Withheld; nothing crosses the boundary.
    Blocked,
    /// The token store failed; nothing was produced.
    StoreError,
}

/// A sanitizer's detection pass failed (a model backend error); the document
/// counts under `detector_errors`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectFailed;

/// Something that sanitizes evaluation documents: the bare engine, or the
/// daemon's `sanitize_blocks` in an in-process state (`inumaki eval
/// --via-service`). [`evaluate_with`] measures any of them the same way.
pub trait Sanitizer {
    /// Detection only, for the recall and precision counts.
    fn detect(&mut self, text: &str) -> Result<Vec<Span>, DetectFailed>;
    /// Sanitize one document end to end.
    fn process(&mut self, doc: &Doc) -> EvalOutcome;
    /// The original for a token of the last [`Sanitizer::process`].
    fn restore(&mut self, token: &str) -> Option<String>;
    /// The token grammar this sanitizer mints in.
    fn token_settings(&self) -> &TokenSettings;
    /// The independent verifier; `None` skips the verifier trials.
    fn verifier(&self) -> Option<Arc<dyn Verifier>>;
    /// Clear copies of store values the engine's referential-consistency
    /// step folded into the last [`Sanitizer::process`] (engine path
    /// only; other sanitizers report 0).
    fn last_consistency(&self) -> usize {
        0
    }
}

/// The engine with a fresh context per document (what [`evaluate`] always did).
pub struct EngineSanitizer<'a> {
    engine: &'a Engine,
    last: Option<Context>,
    verifier: Arc<dyn Verifier>,
    /// `Detailed::consistency` of the last document.
    consistency: usize,
    /// The origin every document is evaluated as (`inumaki eval --origin`).
    origin: TextOrigin,
}

impl<'a> EngineSanitizer<'a> {
    /// Wrap `engine`.
    pub fn new(engine: &'a Engine) -> Self {
        EngineSanitizer {
            engine,
            last: None,
            verifier: Arc::clone(engine.verifier()),
            consistency: 0,
            origin: TextOrigin::Free,
        }
    }

    /// Evaluate every document as text of `origin` (ruling L3-14); free
    /// text by default.
    #[must_use]
    pub fn with_origin(mut self, origin: TextOrigin) -> Self {
        self.origin = origin;
        self
    }
}

fn replaced_of(s: &Sanitized) -> Vec<Replaced> {
    s.replacements
        .iter()
        .map(|r| Replaced {
            start: r.span.start,
            end: r.span.end,
            out_start: r.out_range.start,
            out_end: r.out_range.end,
            kind: r.span.kind.label().to_string(),
            tokenized: r.action == Action::Tokenize,
        })
        .collect()
}

impl Sanitizer for EngineSanitizer<'_> {
    fn detect(&mut self, text: &str) -> Result<Vec<Span>, DetectFailed> {
        self.engine
            .detect_at(text, self.origin)
            .map_err(|_| DetectFailed)
    }
    fn process(&mut self, doc: &Doc) -> EvalOutcome {
        let mut ctx = fresh_ctx(self.engine.token_settings(), &doc.id);
        let detailed = self.engine.process_scoped_at(
            &doc.text,
            &mut ctx,
            &[],
            &LinkScope::empty(),
            self.origin,
        );
        self.consistency = detailed.as_ref().map_or(0, |d| d.consistency);
        let out = match detailed.map(|d| d.outcome) {
            Err(_) => EvalOutcome::StoreError,
            Ok(Outcome::Blocked { .. }) => EvalOutcome::Blocked,
            Ok(Outcome::Pass { sanitized }) => EvalOutcome::Pass {
                replaced: replaced_of(&sanitized),
                text: sanitized.text,
            },
            Ok(Outcome::PassUncertain { sanitized, .. }) => EvalOutcome::PassUncertain {
                replaced: replaced_of(&sanitized),
                text: sanitized.text,
            },
        };
        self.last = Some(ctx);
        out
    }
    fn restore(&mut self, token: &str) -> Option<String> {
        self.last
            .as_ref()
            .and_then(|c| c.original(token))
            .map(str::to_string)
    }
    fn token_settings(&self) -> &TokenSettings {
        self.engine.token_settings()
    }
    fn verifier(&self) -> Option<Arc<dyn Verifier>> {
        Some(Arc::clone(&self.verifier))
    }
    fn last_consistency(&self) -> usize {
        self.consistency
    }
}

/// Latency percentiles in milliseconds.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LatencyStats {
    /// Median.
    pub p50: f64,
    /// 95th percentile.
    pub p95: f64,
    /// 99th percentile.
    pub p99: f64,
    /// Mean.
    pub mean: f64,
    /// Maximum.
    pub max: f64,
}

/// Counts for one language (`de`, `en`, `mixed`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LangStats {
    /// Documents.
    pub docs: usize,
    /// Outcome `Pass`.
    pub accepted: usize,
    /// Outcome `PassUncertain`.
    pub uncertain: usize,
    /// Outcome `Blocked`.
    pub blocked: usize,
    /// Accepted documents with any residue.
    pub accepted_leak: usize,
}

/// How a report was produced (spec §13.1: pinned corpus, models,
/// configuration, seed, build, platform). Filled by the caller; the eval
/// crate knows the corpus and seed, the CLI knows the rest.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    /// SHA-256 of the evaluated corpus (JSONL serialization).
    pub corpus_sha256: String,
    /// Built-in cases included.
    pub cases: usize,
    /// Generated documents included.
    pub generated: usize,
    /// Generator seed.
    pub seed: u64,
    /// Generator family: `tuning`, `held-out`, or `file`.
    pub family: String,
    /// `<os>-<arch>`.
    pub platform: String,
    /// inumaki crate version.
    pub crate_version: String,
    /// Git commit, or `unknown`.
    pub git_commit: String,
    /// SHA-256 of the configuration text.
    pub config_sha256: String,
    /// `embedded` (the shipped default configuration) or `file` (a
    /// `--config` override). Empty in reports recorded before this field
    /// existed; the app's report selection then falls back to the digest.
    #[serde(default)]
    pub config_source: String,
    /// True exactly when the run is the canonical `inumaki eval --profile P`
    /// run that the gate baselines are recorded from: built-in cases plus
    /// generated mails of the tuning family, default generate count, seed
    /// and transforms, verifier trials on, engine path, embedded
    /// configuration. Absent (false) in reports recorded before this field
    /// existed.
    #[serde(default)]
    pub canonical: bool,
    /// SHA-256 of `Cargo.lock` (pins every crate version).
    pub lock_sha256: String,
    /// Model name to SHA-256 of its model file, from the manifest.
    pub models: BTreeMap<String, String>,
    /// Unix seconds when the evaluation finished.
    pub evaluated_at: u64,
}

/// One document's outcome, for `eval --outcomes`: the corpus id and what the
/// engine did with the document, never any text.
#[derive(Debug, Clone, PartialEq)]
pub struct DocOutcome {
    /// Corpus document id.
    pub id: String,
    /// `pass`, `uncertain` or `blocked`. A store error counts as `blocked`
    /// (nothing was released).
    pub outcome: &'static str,
    /// Released text kept a sensitive gold value (full or partial).
    pub residue: bool,
}

impl DocOutcome {
    /// The line `name-shape-outcomes.sh --compare` reads: `id outcome[+residue]`.
    pub fn line(&self) -> String {
        format!(
            "{} {}{}",
            self.id,
            self.outcome,
            if self.residue { "+residue" } else { "" }
        )
    }
}

/// Evaluation result. Contains counts and rates only, never text.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Report {
    /// Profile evaluated.
    pub profile: String,
    /// Documents evaluated.
    pub docs: usize,
    /// Per-kind counts.
    pub per_kind: BTreeMap<String, KindStats>,
    /// Documents with outcome `Pass`.
    pub pass_docs: usize,
    /// Documents with outcome `PassUncertain`.
    pub uncertain_docs: usize,
    /// Documents with outcome `Blocked`.
    pub blocked_docs: usize,
    /// Documents where at least one sensitive gold value reached the output.
    pub docs_with_leak: usize,
    /// `Pass` documents with any residue (full or partial).
    #[serde(default)]
    pub accepted_leak_docs: usize,
    /// `Pass` documents whose only residue was partial.
    #[serde(default)]
    pub accepted_partial_only_docs: usize,
    /// `PassUncertain` documents with any residue (withheld by the gateway; reported separately).
    #[serde(default)]
    pub uncertain_leak_docs: usize,
    /// Per-language counts.
    #[serde(default)]
    pub per_lang: BTreeMap<String, LangStats>,
    /// Documents where `Engine::process` returned a store error.
    #[serde(default)]
    pub store_errors: usize,
    /// How this report was produced.
    #[serde(default)]
    pub provenance: Provenance,
    /// Correct sanitizations verified.
    pub verifier_clean_trials: usize,
    /// Correct sanitizations the verifier failed.
    pub verifier_false_positives: usize,
    /// Broken sanitizations verified.
    pub verifier_broken_trials: usize,
    /// Broken sanitizations the verifier did not fail.
    pub verifier_false_negatives: usize,
    /// `Engine::process` latency per document.
    pub latency_ms: LatencyStats,
    /// Documents where `engine.detect` returned `Err` (e.g. a model backend failed). Detection
    /// recall/precision for these documents is silently zero rather than "not measured", since
    /// a failed detector produces no spans; this count makes that distinction visible instead
    /// of letting a broken model backend masquerade as low recall.
    #[serde(default)]
    pub detector_errors: usize,
    /// Name-linking and referential-consistency counts over released documents.
    #[serde(default)]
    pub links: LinkStats,
    /// Correct sanitizations the verifier failed, by check (`Regex`, `Leak`, ...):
    /// one count per distinct check in a failed trial's reasons.
    #[serde(default)]
    pub verifier_fp_by_check: BTreeMap<String, usize>,
    /// The same false positives by entity kind label.
    #[serde(default)]
    pub verifier_fp_by_kind: BTreeMap<String, usize>,
    /// Persistent-dataset sequence counts (`eval --sequences`); `None` for
    /// every other run.
    #[serde(default)]
    pub sequence: Option<crate::sequence::SequenceStats>,
    /// Clear copies of store values the engine's referential-consistency
    /// step tokenized or removed, summed over documents (engine path only;
    /// 0 through the service).
    #[serde(default)]
    pub consistency_redactions: usize,
    /// Per-document outcomes in corpus order (`eval --outcomes`). Ids and
    /// outcomes only; not part of the JSON report.
    #[serde(skip)]
    pub doc_outcomes: Vec<DocOutcome>,
}

/// Linking metrics (plan 4a): how well the tokens preserve who is who, and
/// whether any token restores to the wrong text. Counts only, never text.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LinkStats {
    /// Documents where a gold entity has two or more PERSON mentions with
    /// different normalized texts.
    pub coref_docs: usize,
    /// Of those, documents where every such entity's mentions all lie inside
    /// tokenized spans whose tokens share one suffix: an agent asked "who
    /// signed this?" can answer from the tokens alone exactly then (the
    /// surface-form task proxy).
    pub coref_recoverable_docs: usize,
    /// Tokenized PERSON replacements.
    pub person_mentions_tokenized: usize,
    /// Of those, tokens that carry a surface component.
    pub surface_mentions: usize,
    /// Tokenized PERSON replacements whose token restores to something other
    /// than the replaced text. Must be zero.
    pub wrong_restorations: usize,
    /// Tokenized PERSON replacements covering a gold mention of a different
    /// entity than the first one seen for that token suffix in the document:
    /// two people behind one suffix.
    pub wrong_links: usize,
    /// Tokenized replacements.
    pub tokens_total: usize,
    /// Distinct token strings per document, summed over documents.
    pub distinct_tokens_total: usize,
}

impl Report {
    /// Documents with a leak ÷ documents.
    pub fn leak_rate(&self) -> f64 {
        if self.docs == 0 {
            0.0
        } else {
            self.docs_with_leak as f64 / self.docs as f64
        }
    }

    /// Accepted (`Pass`) documents.
    pub fn accepted_docs(&self) -> usize {
        self.pass_docs
    }

    /// Accepted documents with residue ÷ accepted documents; `None` (N/A)
    /// when nothing was accepted, which fails the utility gate (spec §13.1).
    pub fn accepted_leak_rate(&self) -> Option<f64> {
        (self.pass_docs > 0).then(|| self.accepted_leak_docs as f64 / self.pass_docs as f64)
    }

    /// Withheld documents (blocked plus uncertain) ÷ documents.
    pub fn block_rate(&self) -> f64 {
        if self.docs == 0 {
            0.0
        } else {
            (self.blocked_docs + self.uncertain_docs) as f64 / self.docs as f64
        }
    }

    /// Verifier false negatives ÷ broken trials.
    pub fn verifier_fn_rate(&self) -> Option<f64> {
        (self.verifier_broken_trials > 0)
            .then(|| self.verifier_false_negatives as f64 / self.verifier_broken_trials as f64)
    }

    /// Verifier false positives ÷ clean trials.
    pub fn verifier_fp_rate(&self) -> Option<f64> {
        (self.verifier_clean_trials > 0)
            .then(|| self.verifier_false_positives as f64 / self.verifier_clean_trials as f64)
    }
}

pub(crate) fn iou(a: (usize, usize), b: (usize, usize)) -> f64 {
    let inter = a.1.min(b.1).saturating_sub(a.0.max(b.0));
    let union = a.1.max(b.1) - a.0.min(b.0);
    if union == 0 {
        0.0
    } else {
        inter as f64 / union as f64
    }
}

pub(crate) fn compatible(gold: &str, detected: &str) -> bool {
    gold == detected
        || (detected == "LOCATION" && matches!(gold, "CITY" | "STREET_ADDRESS"))
        || (detected == "DATE" && gold == "DATE_OF_BIRTH")
}

fn percentile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    sorted[((sorted.len() - 1) as f64 * q).round() as usize]
}

fn decisions(text_spans: &[&GoldSpan]) -> Vec<Decision> {
    let spans = text_spans
        .iter()
        .map(|g| {
            Span::new(
                g.start,
                g.end,
                EntityKind::from_label(&g.kind),
                1.0,
                DetectorId::Dictionary,
            )
        })
        .collect();
    let by_start: BTreeMap<usize, bool> =
        text_spans.iter().map(|g| (g.start, g.sensitive)).collect();
    resolve_overlaps(spans)
        .into_iter()
        .map(|span| {
            let sensitive = by_start.get(&span.start).copied().unwrap_or(true);
            Decision {
                span,
                action: if sensitive {
                    Action::Tokenize
                } else {
                    Action::Preserve
                },
            }
        })
        .collect()
}

fn fresh_ctx(settings: &TokenSettings, id: &str) -> Context {
    Context::new(
        ContextId(id.to_string()),
        Duration::from_secs(60),
        settings.clone(),
    )
}

fn suffix_of(settings: &TokenSettings, token: &str) -> Option<(String, bool)> {
    parse_token(settings, token).map(|p| (p.suffix.to_string(), p.variant.is_some()))
}

/// Coreference proxy, exact restoration, and wrong links for one released
/// document.
fn link_stats(l: &mut LinkStats, s: &mut dyn Sanitizer, d: &Doc, out: &str, replaced: &[Replaced]) {
    let settings = s.token_settings().clone();
    let mut distinct: HashSet<&str> = HashSet::new();
    let mut suffix_entity: HashMap<String, String> = HashMap::new();
    for r in replaced.iter().filter(|r| r.tokenized) {
        let Some(token) = out.get(r.out_start..r.out_end) else {
            continue;
        };
        l.tokens_total += 1;
        distinct.insert(token);
        if r.kind != "PERSON" {
            continue;
        }
        l.person_mentions_tokenized += 1;
        let Some((suffix, variant)) = suffix_of(&settings, token) else {
            continue;
        };
        l.surface_mentions += usize::from(variant);
        if s.restore(token).as_deref() != d.text.get(r.start..r.end) {
            l.wrong_restorations += 1;
        }
        // every gold mention this span covers (a merged span can cover
        // several): a second entity behind the same suffix is a wrong link,
        // counted once per replaced span
        let mut wrong = false;
        for e in d
            .spans
            .iter()
            .filter(|g| g.kind == "PERSON" && r.start <= g.start && g.end <= r.end)
            .filter_map(|g| g.entity.as_ref())
        {
            match suffix_entity.get(&suffix) {
                Some(first) if first != e => wrong = true,
                Some(_) => {}
                None => {
                    suffix_entity.insert(suffix.clone(), e.clone());
                }
            }
        }
        l.wrong_links += usize::from(wrong);
    }
    l.distinct_tokens_total += distinct.len();
    // coreference proxy: entities with two or more distinct surface forms
    let mut by_entity: BTreeMap<&str, Vec<&GoldSpan>> = BTreeMap::new();
    for g in d.spans.iter().filter(|g| g.kind == "PERSON") {
        if let Some(e) = &g.entity {
            by_entity.entry(e.as_str()).or_default().push(g);
        }
    }
    let multi: Vec<&Vec<&GoldSpan>> = by_entity
        .values()
        .filter(|ms| {
            let forms: HashSet<String> = ms
                .iter()
                .filter_map(|g| d.text.get(g.start..g.end))
                .map(|t| normalize(t).as_str().to_string())
                .collect();
            forms.len() >= 2
        })
        .collect();
    if multi.is_empty() {
        return;
    }
    l.coref_docs += 1;
    let recoverable = multi.iter().all(|ms| {
        let mut suffixes: HashSet<String> = HashSet::new();
        for g in ms.iter() {
            let Some(r) = replaced
                .iter()
                .find(|r| r.tokenized && r.start <= g.start && g.end <= r.end)
            else {
                return false;
            };
            let Some((suffix, _)) = out
                .get(r.out_start..r.out_end)
                .and_then(|t| suffix_of(&settings, t))
            else {
                return false;
            };
            suffixes.insert(suffix);
        }
        suffixes.len() == 1
    });
    l.coref_recoverable_docs += usize::from(recoverable);
}

/// What one document did to the report.
pub(crate) struct DocStats {
    /// Outcome `Pass`.
    pub accepted: bool,
    /// Outcome `PassUncertain`.
    pub uncertain: bool,
    /// Outcome `Blocked`.
    pub blocked: bool,
    /// Any residue (full or partial) in the released text.
    pub leaked: bool,
    /// The sanitizer's store failed; nothing else was counted.
    pub store_error: bool,
}

/// Latency percentiles of `times` (milliseconds, any order).
pub(crate) fn latency(times: &[f64]) -> LatencyStats {
    let mut t = times.to_vec();
    t.sort_by(|a, b| a.total_cmp(b));
    LatencyStats {
        p50: percentile(&t, 0.50),
        p95: percentile(&t, 0.95),
        p99: percentile(&t, 0.99),
        mean: if t.is_empty() {
            0.0
        } else {
            t.iter().sum::<f64>() / t.len() as f64
        },
        max: t.last().copied().unwrap_or(0.0),
    }
}

/// Account one document's outcome in `r`: outcome counts, residue,
/// per-language counts, link stats, and (when `opts.verifier_trials` and `s`
/// has a verifier) the verifier trials. `rng` chooses the span a broken
/// verifier trial drops.
pub(crate) fn doc_stats(
    r: &mut Report,
    s: &mut dyn Sanitizer,
    d: &Doc,
    outcome: &EvalOutcome,
    opts: &EvalOptions,
    rng: &mut Rng,
) -> DocStats {
    let mut ds = DocStats {
        accepted: false,
        uncertain: false,
        blocked: false,
        leaked: false,
        store_error: false,
    };
    let verifier = s.verifier();
    if *outcome == EvalOutcome::StoreError {
        r.store_errors += 1;
        ds.store_error = true;
        return ds;
    }
    let lang = r.per_lang.entry(d.lang.clone()).or_default();
    lang.docs += 1;
    let released = match outcome {
        EvalOutcome::Blocked | EvalOutcome::StoreError => {
            r.blocked_docs += 1;
            lang.blocked += 1;
            ds.blocked = true;
            None
        }
        EvalOutcome::Pass { text, replaced } => {
            ds.accepted = true;
            Some((text, replaced))
        }
        EvalOutcome::PassUncertain { text, replaced } => {
            ds.uncertain = true;
            Some((text, replaced))
        }
    };
    if let Some((out, replaced)) = released {
        if ds.uncertain {
            r.uncertain_docs += 1;
            lang.uncertain += 1;
        } else {
            r.pass_docs += 1;
            lang.accepted += 1;
        }
        let (mut full, mut partial) = (false, false);
        for g in d.spans.iter().filter(|g| g.sensitive) {
            let value = &d.text[g.start..g.end];
            match crate::residue::find_residue(&g.kind, value, out) {
                Some(crate::residue::Residue::Full) => {
                    r.per_kind.entry(g.kind.clone()).or_default().leaked += 1;
                    full = true;
                }
                Some(crate::residue::Residue::Partial) => {
                    r.per_kind.entry(g.kind.clone()).or_default().partial_leaked += 1;
                    partial = true;
                }
                None => {}
            }
        }
        ds.leaked = full || partial;
        r.docs_with_leak += usize::from(ds.leaked);
        if ds.uncertain {
            r.uncertain_leak_docs += usize::from(ds.leaked);
        } else {
            r.accepted_leak_docs += usize::from(ds.leaked);
            r.accepted_partial_only_docs += usize::from(partial && !full);
            r.per_lang.entry(d.lang.clone()).or_default().accepted_leak += usize::from(ds.leaked);
        }
        link_stats(&mut r.links, s, d, out, replaced);
    }

    if let (true, Some(verifier)) = (opts.verifier_trials, &verifier) {
        let all: Vec<&GoldSpan> = d.spans.iter().collect();
        let sensitive: Vec<usize> = (0..all.len()).filter(|&i| all[i].sensitive).collect();
        if !sensitive.is_empty() {
            let mut ctx = fresh_ctx(s.token_settings(), &d.id);
            let clean = sanitize(&d.text, &decisions(&all), &mut ctx)
                .expect("an in-memory context never fails");
            r.verifier_clean_trials += 1;
            if let Verdict::Fail(reasons) = verifier.verify(&clean, &ctx) {
                r.verifier_false_positives += 1;
                let mut checks: Vec<String> =
                    reasons.iter().map(|x| format!("{:?}", x.check)).collect();
                checks.sort();
                checks.dedup();
                for c in checks {
                    *r.verifier_fp_by_check.entry(c).or_default() += 1;
                }
                let mut kinds: Vec<&str> = reasons.iter().map(|x| x.kind.label()).collect();
                kinds.sort();
                kinds.dedup();
                for k in kinds {
                    *r.verifier_fp_by_kind.entry(k.to_string()).or_default() += 1;
                }
            }
            let drop = sensitive[rng.below(sensitive.len())];
            let dropped = &d.text[all[drop].start..all[drop].end];
            let rest: Vec<&GoldSpan> = (0..all.len())
                .filter(|&i| i != drop)
                .map(|i| all[i])
                .collect();
            let also_tokenized = rest
                .iter()
                .any(|g| g.sensitive && &d.text[g.start..g.end] == dropped);
            if !also_tokenized {
                let mut ctx = fresh_ctx(s.token_settings(), &d.id);
                let broken = sanitize(&d.text, &decisions(&rest), &mut ctx)
                    .expect("an in-memory context never fails");
                r.verifier_broken_trials += 1;
                if !matches!(verifier.verify(&broken, &ctx), Verdict::Fail(_)) {
                    r.verifier_false_negatives += 1;
                }
            }
        }
    }
    ds
}

/// Evaluate `engine` (built for `profile`) on `docs`.
///
/// Residue is decided by [`crate::residue::find_residue`]: `docs_with_leak` counts full or
/// partial residue found in any released document (`Pass` or `PassUncertain`); `accepted_leak_docs`
/// counts `Pass` documents only, with `PassUncertain` residue tracked separately in
/// `uncertain_leak_docs` since the gateway withholds those documents rather than releasing them.
/// `also_tokenized` (deciding whether a verifier trial's dropped value would
/// still be caught because some other, still-present replacement carries the identical text)
/// compares the dropped span's exact text against other sensitive spans' exact text only; it
/// does not do fuzzy or substring matching, so two spans with the same value modulo whitespace
/// or case are not recognized as "the same value" here.
pub fn evaluate(engine: &Engine, profile: &str, docs: &[Doc], opts: &EvalOptions) -> Report {
    evaluate_with(&mut EngineSanitizer::new(engine), profile, docs, opts)
}

/// [`evaluate`] over any [`Sanitizer`]: the engine, or the service path.
/// Latency is measured around [`Sanitizer::process`]; the link metrics
/// (`Report::links`) are computed over released documents from the
/// replaced spans it reports.
pub fn evaluate_with(
    s: &mut dyn Sanitizer,
    profile: &str,
    docs: &[Doc],
    opts: &EvalOptions,
) -> Report {
    let mut r = Report {
        profile: profile.to_string(),
        docs: docs.len(),
        ..Default::default()
    };
    let mut rng = Rng::new(opts.seed);
    let mut times = Vec::with_capacity(docs.len());
    for d in docs {
        let detected = match s.detect(&d.text) {
            Ok(spans) => spans,
            Err(_) => {
                r.detector_errors += 1;
                Vec::new()
            }
        };
        for g in &d.spans {
            let found = detected.iter().any(|s| {
                compatible(&g.kind, s.kind.label())
                    && iou((g.start, g.end), (s.start, s.end)) >= opts.iou
            });
            let e = r.per_kind.entry(g.kind.clone()).or_default();
            e.gold += 1;
            e.gold_found += usize::from(found);
        }
        for s in &detected {
            let label = s.kind.label().to_string();
            let correct = d.spans.iter().any(|g| {
                compatible(&g.kind, &label) && iou((g.start, g.end), (s.start, s.end)) >= opts.iou
            });
            let e = r.per_kind.entry(label).or_default();
            e.detected += 1;
            e.detected_correct += usize::from(correct);
        }

        let t = Instant::now();
        let outcome = s.process(d);
        let elapsed = t.elapsed().as_secs_f64() * 1000.0;
        r.consistency_redactions += s.last_consistency();
        let ds = doc_stats(&mut r, s, d, &outcome, opts, &mut rng);
        r.doc_outcomes.push(DocOutcome {
            id: d.id.clone(),
            outcome: if ds.accepted {
                "pass"
            } else if ds.uncertain {
                "uncertain"
            } else {
                "blocked"
            },
            residue: ds.leaked,
        });
        if !ds.store_error {
            times.push(elapsed);
        }
    }
    r.latency_ms = latency(&times);
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use inumaki_core::config::CoreConfig;
    use inumaki_core::detect::regex::RegexDetector;
    use inumaki_core::detect::{DetectCtx, Detector};
    use inumaki_core::verify::SecondPassVerifier;

    fn engine() -> Engine {
        let cfg = CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap();
        Engine::from_config(&cfg, "offline", None, None).unwrap()
    }

    /// Always fails, standing in for a model backend that is down or misbehaving.
    struct FailingDetector;

    impl Detector for FailingDetector {
        fn id(&self) -> DetectorId {
            DetectorId::Ner
        }
        fn detect(&self, _text: &str, _ctx: &DetectCtx) -> inumaki_core::Result<Vec<Span>> {
            Err(inumaki_core::Error::ModelUnavailable("mock".into()))
        }
    }

    #[test]
    fn detect_errors_are_counted_not_silently_treated_as_no_findings() {
        let cfg = CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap();
        let profile = cfg.resolve_profile("offline").unwrap();
        let verifier =
            SecondPassVerifier::new(RegexDetector::new(), None, &profile.verifier).unwrap();
        let failing_engine = Engine::new(
            profile,
            None,
            vec![std::sync::Arc::new(FailingDetector)],
            std::sync::Arc::new(verifier),
        );
        let docs = vec![doc("d1", "Hallo Welt.", &[])];
        let r = evaluate(
            &failing_engine,
            "offline",
            &docs,
            &EvalOptions {
                verifier_trials: false,
                ..EvalOptions::default()
            },
        );
        assert_eq!(r.detector_errors, 1);
        assert!(
            r.per_kind.is_empty(),
            "a failed detect finds nothing, not something"
        );
    }

    fn doc(id: &str, text: &str, spans: &[(&str, &str)]) -> Doc {
        let mut out = Vec::new();
        for (needle, kind) in spans {
            let start = text.find(needle).unwrap();
            out.push(GoldSpan {
                start,
                end: start + needle.len(),
                kind: (*kind).into(),
                sensitive: crate::corpus::default_sensitive(kind),
                entity: None,
            });
        }
        out.sort_by_key(|s| s.start);
        Doc {
            id: id.into(),
            lang: "de".into(),
            text: text.into(),
            spans: out,
            why: None,
        }
    }

    #[test]
    fn doc_outcomes_list_every_document_once() {
        let docs = vec![
            doc("a", "Hallo Welt.", &[]),
            doc(
                "b",
                "Bitte rufen Sie Sarah Leitner zurück.",
                &[("Sarah Leitner", "PERSON")],
            ),
        ];
        let r = evaluate(
            &engine(),
            "offline",
            &docs,
            &EvalOptions {
                verifier_trials: false,
                ..EvalOptions::default()
            },
        );
        let lines: Vec<String> = r.doc_outcomes.iter().map(DocOutcome::line).collect();
        assert_eq!(lines, ["a pass", "b pass+residue"]);
    }

    #[test]
    fn offline_profile_finds_ibans_and_leaks_names() {
        let docs = vec![
            doc(
                "iban",
                "Meine IBAN ist AT61 1904 3002 3457 3201, danke.",
                &[("AT61 1904 3002 3457 3201", "IBAN")],
            ),
            doc(
                "name",
                "Bitte rufen Sie Sarah Leitner zurück.",
                &[("Sarah Leitner", "PERSON")],
            ),
        ];
        let r = evaluate(&engine(), "offline", &docs, &EvalOptions::default());
        assert_eq!(r.per_kind["IBAN"].recall(), Some(1.0));
        assert_eq!(r.per_kind["PERSON"].recall(), Some(0.0));
        assert_eq!(r.docs_with_leak, 1);
        assert_eq!(r.accepted_leak_docs, 1);
        assert_eq!(r.per_lang["de"].docs, 2);
        assert!((r.leak_rate() - 0.5).abs() < 1e-9);
        // IBAN dropped from a trial is caught by the regex re-scan; the name is not (no NER).
        assert_eq!(r.verifier_broken_trials, 2);
        assert_eq!(r.verifier_false_negatives, 1);
        assert_eq!(r.verifier_false_positives, 0);
        assert!(r.latency_ms.p50 >= 0.0);
    }

    /// Spec §13.1: accepted means `Pass`; uncertain is withheld and reported
    /// separately; partial residue counts; per-language counts are kept.
    #[test]
    fn accepted_leak_rate_counts_pass_documents_and_partial_residue() {
        let docs = vec![
            doc(
                "full",
                "Bitte rufen Sie Sarah Leitner zurück.",
                &[("Sarah Leitner", "PERSON")],
            ),
            doc(
                "iban",
                "Meine IBAN ist AT61 1904 3002 3457 3201, danke.",
                &[("AT61 1904 3002 3457 3201", "IBAN")],
            ),
        ];
        let mut en = doc(
            "en",
            "Please call Sarah Leitner back.",
            &[("Sarah Leitner", "PERSON")],
        );
        en.lang = "en".into();
        let mut docs = docs;
        docs.push(en);
        let r = evaluate(
            &engine(),
            "offline",
            &docs,
            &EvalOptions {
                verifier_trials: false,
                ..EvalOptions::default()
            },
        );
        assert_eq!(r.pass_docs, 3);
        assert_eq!(
            r.accepted_leak_docs, 2,
            "the two name documents leak the full name"
        );
        assert_eq!(r.accepted_partial_only_docs, 0);
        assert_eq!(r.uncertain_leak_docs, 0);
        assert!((r.accepted_leak_rate().unwrap() - 2.0 / 3.0).abs() < 1e-9);
        assert_eq!(r.block_rate(), 0.0);
        assert_eq!(r.per_lang["de"].docs, 2);
        assert_eq!(r.per_lang["de"].accepted_leak, 1);
        assert_eq!(r.per_lang["en"].accepted_leak, 1);
        assert_eq!(r.per_kind["PERSON"].leaked, 2);
        assert_eq!(r.per_kind["PERSON"].partial_leaked, 0);
    }

    #[test]
    fn accepted_leak_rate_is_none_without_accepted_documents() {
        let r = Report {
            docs: 5,
            blocked_docs: 5,
            ..Report::default()
        };
        assert_eq!(r.accepted_leak_rate(), None);
        assert!((r.block_rate() - 1.0).abs() < 1e-9);
        let r = Report {
            docs: 4,
            pass_docs: 2,
            uncertain_docs: 1,
            blocked_docs: 1,
            ..Report::default()
        };
        assert!((r.block_rate() - 0.5).abs() < 1e-9, "uncertain is withheld");
    }

    #[test]
    fn partial_residue_is_counted_separately_from_full() {
        // A dictionary-only profile knows the full address and tokenizes it;
        // a later lower-case mention of the street name alone is neither a
        // dictionary hit (the entry is the whole address), nor a leak-check
        // hit (only persons get name-part patterns), nor (after Task 3) a
        // bare-street regex hit (lower case), so it survives as partial residue.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("addresses.txt");
        std::fs::write(&p, "Neubaugasse 22\n").unwrap();
        let toml = include_str!("../../../configs/default.toml").replace(
            "addresses = []",
            &format!("addresses = [\"{}\"]", p.display()),
        );
        let cfg = CoreConfig::from_toml(&toml).unwrap();
        let engine = Engine::from_config(&cfg, "offline", None, None).unwrap();
        let docs = vec![doc(
            "d",
            "Neubaugasse 22 ist die Adresse. in der neubaugasse ist es laut.",
            &[("Neubaugasse 22", "STREET_ADDRESS")],
        )];
        let r = evaluate(
            &engine,
            "offline",
            &docs,
            &EvalOptions {
                verifier_trials: false,
                ..EvalOptions::default()
            },
        );
        assert_eq!(r.pass_docs, 1, "{r:?}");
        assert_eq!(r.per_kind["STREET_ADDRESS"].leaked, 0);
        assert_eq!(r.per_kind["STREET_ADDRESS"].partial_leaked, 1);
        assert_eq!(r.accepted_leak_docs, 1);
        assert_eq!(r.accepted_partial_only_docs, 1);
    }

    /// Plan 4a: coreference proxy, exact restoration, and wrong links from
    /// a scripted sanitizer.
    #[test]
    fn link_stats_from_a_scripted_sanitizer() {
        struct Scripted {
            settings: TokenSettings,
            out: Vec<(String, Vec<Replaced>)>,
            restore: HashMap<String, String>,
        }
        impl Sanitizer for Scripted {
            fn detect(&mut self, _: &str) -> Result<Vec<Span>, DetectFailed> {
                Ok(Vec::new())
            }
            fn process(&mut self, doc: &Doc) -> EvalOutcome {
                let i: usize = doc.id.parse().unwrap();
                let (text, replaced) = self.out[i].clone();
                EvalOutcome::Pass { text, replaced }
            }
            fn restore(&mut self, token: &str) -> Option<String> {
                self.restore.get(token).cloned()
            }
            fn token_settings(&self) -> &TokenSettings {
                &self.settings
            }
            fn verifier(&self) -> Option<Arc<dyn Verifier>> {
                None
            }
        }
        // a replacement of `input[start..end]` by the token at `out_start` in `out`
        fn rep(start: usize, end: usize, out: &str, token: &str) -> Replaced {
            let out_start = out.find(token).unwrap();
            Replaced {
                start,
                end,
                out_start,
                out_end: out_start + token.len(),
                kind: "PERSON".into(),
                tokenized: true,
            }
        }
        let mut d0 = doc(
            "0",
            "Sarah Leitner rief an. LG Sarah",
            &[("Sarah Leitner", "PERSON")],
        );
        let s0 = d0.text.rfind("Sarah").unwrap();
        d0.spans.push(GoldSpan {
            start: s0,
            end: s0 + 5,
            kind: "PERSON".into(),
            sensitive: true,
            entity: Some("p".into()),
        });
        d0.spans[0].entity = Some("p".into());
        // doc 0: derived tokens, exact restoration: recoverable
        let t0 = "<PERSON_a7f2> rief an. LG <PERSON_a7f2_3e>";
        let out0 = (
            t0.to_string(),
            vec![
                rep(0, 13, t0, "<PERSON_a7f2>"),
                rep(s0, s0 + 5, t0, "<PERSON_a7f2_3e>"),
            ],
        );
        // doc 1: independent tokens, and the sign-off restores to the full
        // name: a wrong restoration
        let mut d1 = d0.clone();
        d1.id = "1".into();
        let t1 = "<PERSON_a7f2> rief an. LG <PERSON_b81e>";
        let out1 = (
            t1.to_string(),
            vec![
                rep(0, 13, t1, "<PERSON_a7f2>"),
                rep(s0, s0 + 5, t1, "<PERSON_b81e>"),
            ],
        );
        // doc 2: two people behind one suffix: a wrong link
        let mut d2 = doc(
            "2",
            "Sarah Leitner und Max Gruber",
            &[("Sarah Leitner", "PERSON"), ("Max Gruber", "PERSON")],
        );
        d2.spans[0].entity = Some("p".into());
        d2.spans[1].entity = Some("q".into());
        let t2 = "<PERSON_c1d2> und <PERSON_c1d2_3e>";
        let out2 = (
            t2.to_string(),
            vec![
                rep(0, 13, t2, "<PERSON_c1d2>"),
                rep(18, 28, t2, "<PERSON_c1d2_3e>"),
            ],
        );
        let restore = [
            ("<PERSON_a7f2>", "Sarah Leitner"),
            ("<PERSON_a7f2_3e>", "Sarah"),
            ("<PERSON_b81e>", "Sarah Leitner"),
            ("<PERSON_c1d2>", "Sarah Leitner"),
            ("<PERSON_c1d2_3e>", "Max Gruber"),
        ]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
        let mut sc = Scripted {
            settings: TokenSettings::default(),
            out: vec![out0, out1, out2],
            restore,
        };
        let r = evaluate_with(
            &mut sc,
            "scripted",
            &[d0, d1, d2],
            &EvalOptions {
                verifier_trials: false,
                ..EvalOptions::default()
            },
        );
        assert_eq!(
            r.links.coref_docs, 2,
            "docs 0 and 1 have two surface forms of p"
        );
        assert_eq!(r.links.coref_recoverable_docs, 1, "doc 0 only");
        assert_eq!(r.links.wrong_restorations, 1, "doc 1's sign-off");
        assert_eq!(r.links.wrong_links, 1, "doc 2");
        assert_eq!(r.links.person_mentions_tokenized, 6);
        assert_eq!(r.links.surface_mentions, 2);
        assert_eq!(
            (r.links.tokens_total, r.links.distinct_tokens_total),
            (6, 6)
        );
        assert_eq!(r.pass_docs, 3);
        assert_eq!(r.accepted_leak_docs, 0);
    }

    #[test]
    fn verifier_false_positives_are_broken_down_by_check_and_kind() {
        let docs = vec![doc(
            "iban",
            "Meine IBAN ist AT61 1904 3002 3457 3201, danke.",
            &[("AT61 1904 3002 3457 3201", "IBAN")],
        )];
        // a verifier that fails every clean trial with a Regex reason
        struct AlwaysRegex;
        impl Verifier for AlwaysRegex {
            fn verify(&self, _: &Sanitized, _: &dyn inumaki_core::token::TokenStore) -> Verdict {
                Verdict::Fail(vec![inumaki_core::verify::Reason {
                    kind: EntityKind::Iban,
                    check: inumaki_core::verify::CheckId::Regex,
                }])
            }
        }
        let cfg = CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap();
        let profile = cfg.resolve_profile("offline").unwrap();
        let e = Engine::new(profile, None, vec![], Arc::new(AlwaysRegex));
        let r = evaluate(&e, "offline", &docs, &EvalOptions::default());
        assert_eq!(r.verifier_false_positives, 1);
        assert_eq!(r.verifier_fp_by_check.get("Regex"), Some(&1));
        assert_eq!(r.verifier_fp_by_kind.get("IBAN"), Some(&1));
    }

    #[test]
    fn iou_and_compatibility() {
        assert!((iou((0, 10), (0, 10)) - 1.0).abs() < 1e-9);
        assert!((iou((0, 10), (5, 15)) - 5.0 / 15.0).abs() < 1e-9);
        assert_eq!(iou((0, 5), (5, 10)), 0.0);
        assert!(compatible("CITY", "LOCATION"));
        assert!(compatible("DATE_OF_BIRTH", "DATE"));
        assert!(!compatible("PERSON", "ORGANIZATION"));
    }
}
