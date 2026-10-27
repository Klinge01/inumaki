//! Text rendering of a [`Report`] and the baseline regression gate.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::corpus::EvalError;
use crate::metrics::Report;

/// Allowed recall drop per kind before the gate fails (0.5 percentage points).
pub const RECALL_TOLERANCE: f64 = 0.005;
/// Allowed rise of the verifier false-negative rate.
pub const FN_TOLERANCE: f64 = 0.005;
/// Kinds with fewer gold spans are not gated (too noisy).
pub const MIN_GOLD_FOR_GATE: usize = 20;
/// Allowed rise of the block rate before the gate fails (0.5 percentage points).
pub const BLOCK_TOLERANCE: f64 = 0.005;

/// Human-readable report.
pub fn render_text(r: &Report) -> String {
    let pct =
        |v: Option<f64>| v.map_or_else(|| "   -  ".to_string(), |x| format!("{:6.2}%", x * 100.0));
    // Tracks without a separate detection pass (`tool_json`, M4 spec §16.6:
    // a block is tokenized whole or sanitized as free text, never scored
    // against a detector) leave every kind's `detected` at zero; recall and
    // precision were never measured there; show them as "not measured"
    // rather than a misleading 0.00%.
    let no_detection = !r.per_kind.is_empty() && r.per_kind.values().all(|k| k.detected == 0);
    let mut s = String::new();
    let _ = writeln!(s, "profile {}  docs {}", r.profile, r.docs);
    let _ = writeln!(
        s,
        "{:<16} {:>6} {:>8} {:>8} {:>9} {:>7} {:>7}",
        "KIND", "GOLD", "RECALL", "DETECTED", "PRECISION", "LEAKED", "PARTIAL"
    );
    for (k, st) in &r.per_kind {
        let _ = writeln!(
            s,
            "{:<16} {:>6} {:>8} {:>8} {:>9} {:>7} {:>7}",
            k,
            st.gold,
            if no_detection {
                "   -  ".to_string()
            } else {
                pct(st.recall())
            },
            st.detected,
            if no_detection {
                "   -  ".to_string()
            } else {
                pct(st.precision())
            },
            st.leaked,
            st.partial_leaked
        );
    }
    let _ = writeln!(
        s,
        "outcomes: pass {}  uncertain {}  blocked {}",
        r.pass_docs, r.uncertain_docs, r.blocked_docs
    );
    let _ = writeln!(
        s,
        "leak rate: {}  ({} docs)",
        pct(Some(r.leak_rate())),
        r.docs_with_leak
    );
    let _ = writeln!(
        s,
        "accepted leak rate: {}  ({} of {} accepted; {} partial only)  uncertain with residue: {}",
        pct(r.accepted_leak_rate()),
        r.accepted_leak_docs,
        r.pass_docs,
        r.accepted_partial_only_docs,
        r.uncertain_leak_docs
    );
    let _ = writeln!(
        s,
        "block rate: {}  (blocked + uncertain)",
        pct(Some(r.block_rate()))
    );
    for (lang, l) in &r.per_lang {
        let _ = writeln!(
            s,
            "lang {lang:<5} docs {:>5}  accepted {:>5}  uncertain {:>4}  blocked {:>4}  accepted with residue {:>4}",
            l.docs, l.accepted, l.uncertain, l.blocked, l.accepted_leak
        );
    }
    let _ = writeln!(
        s,
        "verifier: false-negative rate {} of {} broken, false-positive rate {} of {} clean",
        pct(r.verifier_fn_rate()),
        r.verifier_broken_trials,
        pct(r.verifier_fp_rate()),
        r.verifier_clean_trials
    );
    let k = &r.links;
    let _ = writeln!(
        s,
        "links: coref docs {}  recoverable {}  person mentions {}  surface {}  wrong restorations {}  wrong links {}  tokens {} (distinct {})",
        k.coref_docs,
        k.coref_recoverable_docs,
        k.person_mentions_tokenized,
        k.surface_mentions,
        k.wrong_restorations,
        k.wrong_links,
        k.tokens_total,
        k.distinct_tokens_total
    );
    let _ = writeln!(
        s,
        "consistency redactions: {} (engine path only)",
        r.consistency_redactions
    );
    if !r.verifier_fp_by_check.is_empty() {
        let _ = writeln!(
            s,
            "verifier false positives by check: {:?}  by kind: {:?}",
            r.verifier_fp_by_check, r.verifier_fp_by_kind
        );
    }
    if let Some(q) = &r.sequence {
        let _ = writeln!(
            s,
            "sequence: steps {}  restarts {}  rotations {}  cache hits {}  repeats cached {} of {} expected ({} total){}",
            q.steps,
            q.restarts,
            q.rotations,
            q.cache_hits,
            q.repeats_cached,
            q.repeats_expected_cached,
            q.repeats,
            if q.event_failures > 0 {
                format!("  EVENT FAILURES {}", q.event_failures)
            } else {
                String::new()
            }
        );
        let _ = writeln!(
            s,
            "  {:<20} {:>5} {:>8} {:>8} {:>6} {:>6} {:>9}",
            "LABEL", "DOCS", "ACCEPTED", "BLOCKED", "LINKS", "WRONG", "SAME-TEXT"
        );
        for (label, v) in &q.per_label {
            let _ = writeln!(
                s,
                "  {:<20} {:>5} {:>8} {:>8} {:>6} {:>6} {:>9}",
                label, v.docs, v.accepted, v.blocked, v.links, v.wrong_links, v.same_text_reuse
            );
        }
        let _ = writeln!(
            s,
            "  wrong links: ambiguous {}  surname-other {}  all labels {}",
            q.wrong_links_ambiguous, q.wrong_links_surname_other, q.wrong_links_cross_step
        );
        let _ = writeln!(
            s,
            "  grace: {} pre-rotation tokens; resolve during grace {}; unresolved after expiry {}; reused after rotation {}; restore errors {}",
            q.pre_rotation_tokens,
            q.resolved_within_grace,
            q.unresolved_after_grace,
            q.reused_after_rotation,
            q.restore_errors
        );
    }
    let l = &r.latency_ms;
    let _ = writeln!(
        s,
        "latency ms: p50 {:.1}  p95 {:.1}  p99 {:.1}  mean {:.1}  max {:.1}",
        l.p50, l.p95, l.p99, l.mean, l.max
    );
    if r.detector_errors > 0 {
        let _ = writeln!(
            s,
            "detector errors: {} docs (detection skipped, counted as zero recall)",
            r.detector_errors
        );
    }
    if r.store_errors > 0 {
        let _ = writeln!(
            s,
            "store_errors: {} docs (never pass, uncertain, or blocked; still counted in the block-rate and leak-rate denominators)",
            r.store_errors
        );
    }
    s
}

/// Committed reference numbers for one profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Baseline {
    /// Profile the baseline was measured with.
    pub profile: String,
    /// Documents in the measured corpus.
    pub docs: usize,
    /// Detection recall per gated kind.
    pub recall: BTreeMap<String, f64>,
    /// End-to-end leak rate.
    pub leak_rate: f64,
    /// Verifier false-negative rate.
    pub verifier_fn_rate: f64,
    /// `<os>-<arch>` the baseline was measured on (`std::env::consts::OS`/`ARCH`), e.g.
    /// `macos-aarch64`. `None` for baselines written before this field existed. int8 ONNX
    /// Runtime kernels differ across platforms (VNNI/AVX2 on x86, NEON dot on ARM), so a
    /// model-dependent baseline compared on a different platform than it was measured on can
    /// fail the gate for reasons unrelated to a real regression (final review I3).
    #[serde(default)]
    pub platform: Option<String>,
    /// Accepted (`Pass`) documents with residue ÷ accepted documents. `None` for
    /// baselines written before this field existed.
    #[serde(default)]
    pub accepted_leak_rate: Option<f64>,
    /// Withheld documents ÷ documents.
    #[serde(default)]
    pub block_rate: Option<f64>,
}

/// `<os>-<arch>` of the machine running now, e.g. `macos-aarch64` or `linux-x86_64`.
pub fn current_platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

impl Baseline {
    /// Baseline from a report; kinds with fewer than [`MIN_GOLD_FOR_GATE`] gold spans are left out.
    pub fn from_report(r: &Report) -> Self {
        Baseline {
            profile: r.profile.clone(),
            docs: r.docs,
            recall: r
                .per_kind
                .iter()
                .filter(|(_, s)| s.gold >= MIN_GOLD_FOR_GATE)
                .filter_map(|(k, s)| s.recall().map(|v| (k.clone(), v)))
                .collect(),
            leak_rate: r.leak_rate(),
            verifier_fn_rate: r.verifier_fn_rate().unwrap_or(0.0),
            platform: Some(current_platform()),
            accepted_leak_rate: r.accepted_leak_rate(),
            block_rate: Some(r.block_rate()),
        }
    }

    /// Regressions of `r` against this baseline, one message each; empty when none.
    ///
    /// A profile or corpus-size mismatch is reported as a regression too: comparing
    /// today's `support-email` run against a `strict` baseline, or against one measured
    /// on a differently sized corpus, produces numbers that are not comparable, and
    /// silently comparing them anyway could mask a real regression or manufacture a
    /// fake one.
    pub fn check(&self, r: &Report) -> Vec<String> {
        let mut out = Vec::new();
        if r.profile != self.profile {
            out.push(format!(
                "profile mismatch: baseline {}, run {}",
                self.profile, r.profile
            ));
        }
        if r.docs != self.docs {
            out.push(format!(
                "corpus size differs: baseline {} docs, run {} docs",
                self.docs, r.docs
            ));
        }
        for (k, base) in &self.recall {
            let now = r.per_kind.get(k).and_then(|s| s.recall()).unwrap_or(0.0);
            if now < base - RECALL_TOLERANCE {
                out.push(format!(
                    "{k} recall {:.2}% < baseline {:.2}%",
                    now * 100.0,
                    base * 100.0
                ));
            }
        }
        if r.leak_rate() > self.leak_rate + 1e-12 {
            out.push(format!(
                "leak rate {:.3}% > baseline {:.3}%",
                r.leak_rate() * 100.0,
                self.leak_rate * 100.0
            ));
        }
        if let (Some(base), Some(now)) = (self.accepted_leak_rate, r.accepted_leak_rate()) {
            if now > base + 1e-12 {
                out.push(format!(
                    "accepted leak rate {:.3}% > baseline {:.3}%",
                    now * 100.0,
                    base * 100.0
                ));
            }
        }
        if self.accepted_leak_rate.is_some() && r.accepted_leak_rate().is_none() {
            out.push("accepted leak rate N/A: no document was accepted".to_string());
        }
        if let Some(base) = self.block_rate {
            if r.block_rate() > base + BLOCK_TOLERANCE {
                out.push(format!(
                    "block rate {:.2}% > baseline {:.2}%",
                    r.block_rate() * 100.0,
                    base * 100.0
                ));
            }
        }
        let fnr = r.verifier_fn_rate().unwrap_or(0.0);
        if fnr > self.verifier_fn_rate + FN_TOLERANCE {
            out.push(format!(
                "verifier false-negative rate {:.2}% > baseline {:.2}%",
                fnr * 100.0,
                self.verifier_fn_rate * 100.0
            ));
        }
        out
    }

    /// Read a baseline TOML file.
    pub fn load(path: &Path) -> Result<Self, EvalError> {
        let s =
            std::fs::read_to_string(path).map_err(|_| EvalError::Io(path.display().to_string()))?;
        toml::from_str(&s).map_err(|_| EvalError::Parse(path.display().to_string()))
    }

    /// Write a baseline TOML file.
    pub fn save(&self, path: &Path) -> Result<(), EvalError> {
        let s = toml::to_string_pretty(self)
            .map_err(|_| EvalError::Parse(path.display().to_string()))?;
        std::fs::write(path, s).map_err(|_| EvalError::Io(path.display().to_string()))
    }
}

/// Absolute engineering targets (spec §13.1). Unlike a baseline, a target
/// does not move with measurements; it changes only with a spec revision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Targets {
    /// Accepted leak rate must not exceed this.
    pub max_accepted_leak_rate: f64,
    /// Block rate (blocked plus uncertain) must not exceed this.
    pub max_block_rate: f64,
    /// Clean verifier false-positive rate must not exceed this.
    pub max_verifier_fp_rate: f64,
    /// Per-kind minimum detection recall.
    #[serde(default)]
    pub min_recall: BTreeMap<String, f64>,
    /// No residue at all in accepted or uncertain output (curated safety suite).
    #[serde(default)]
    pub zero_residue: bool,
    /// No tokenized PERSON replacement restores to text other than what it replaced.
    #[serde(default)]
    pub zero_wrong_restorations: bool,
    /// Wrong links in labeled ambiguity cases must not exceed this
    /// (`eval --sequences` only).
    #[serde(default)]
    pub max_wrong_links_ambiguous: Option<usize>,
    /// Wrong links in surname-collision cases must not exceed this
    /// (`eval --sequences` only).
    #[serde(default)]
    pub max_wrong_links_surname_other: Option<usize>,
    /// Cross-request links in steps that name a first name of a person never
    /// seen in full (`BareRecentOther`) must not exceed this: wrong by
    /// definition, and zero under the default configuration. The opt-in
    /// `first_names_across_requests` run is measured, not gated
    /// (`eval --sequences` only).
    #[serde(default)]
    pub max_wrong_links_bare_other: Option<usize>,
    /// Tokens of a closed epoch that still resolve after the grace period
    /// must not exceed this (`eval --sequences` only).
    #[serde(default)]
    pub max_resolved_after_grace: Option<usize>,
    /// Every token minted before a rotation must still resolve during the
    /// grace period, on the warm handle (a failure breaks rehydration after
    /// a rotation; `eval --sequences` only).
    #[serde(default)]
    pub all_resolve_within_grace: bool,
    /// Tokens issued before a rotation that a later document carried again
    /// must not exceed this (`eval --sequences` only).
    #[serde(default)]
    pub max_reused_after_rotation: Option<usize>,
    /// Per-kind maximum of detected spans (`per_kind[kind].detected`), e.g.
    /// `PERSON = 0` for the harness-static corpus, where every span is a
    /// false positive. Kinds not listed are not capped.
    #[serde(default)]
    pub max_detected: BTreeMap<String, usize>,
}

/// Steps of `label` that released text (accepted or uncertain): a gate on
/// links says nothing about a label whose every step was blocked.
fn released_steps(seq: &crate::sequence::SequenceStats, label: &str) -> usize {
    seq.per_label
        .get(label)
        .map_or(0, |l| l.accepted + l.uncertain)
}

impl Targets {
    /// Read a targets TOML file.
    pub fn load(path: &Path) -> Result<Self, EvalError> {
        let s =
            std::fs::read_to_string(path).map_err(|_| EvalError::Io(path.display().to_string()))?;
        toml::from_str(&s).map_err(|_| EvalError::Parse(path.display().to_string()))
    }

    /// Missed targets, one message each; empty when every target is met.
    pub fn check(&self, r: &Report) -> Vec<String> {
        let mut out = Vec::new();
        match r.accepted_leak_rate() {
            None => out.push(
                "accepted leak rate N/A: no document was accepted (utility gate failed)".into(),
            ),
            Some(v) if v > self.max_accepted_leak_rate + 1e-12 => out.push(format!(
                "accepted leak rate {:.3}% > target {:.3}% ({} of {} accepted documents)",
                v * 100.0,
                self.max_accepted_leak_rate * 100.0,
                r.accepted_leak_docs,
                r.pass_docs
            )),
            Some(_) => {}
        }
        if r.block_rate() > self.max_block_rate + 1e-12 {
            out.push(format!(
                "block rate {:.2}% > target {:.2}% ({} blocked + {} uncertain of {})",
                r.block_rate() * 100.0,
                self.max_block_rate * 100.0,
                r.blocked_docs,
                r.uncertain_docs,
                r.docs
            ));
        }
        if let Some(fp) = r.verifier_fp_rate() {
            if fp > self.max_verifier_fp_rate + 1e-12 {
                out.push(format!(
                    "verifier false-positive rate {:.2}% > target {:.2}%",
                    fp * 100.0,
                    self.max_verifier_fp_rate * 100.0
                ));
            }
        }
        for (k, min) in &self.min_recall {
            let now = r.per_kind.get(k).and_then(|s| s.recall());
            match now {
                Some(v) if v + 1e-12 >= *min => {}
                Some(v) => out.push(format!(
                    "{k} recall {:.2}% < target {:.2}%",
                    v * 100.0,
                    min * 100.0
                )),
                None => out.push(format!("{k} recall not measured (no gold spans)")),
            }
        }
        if self.zero_residue && (r.accepted_leak_docs + r.uncertain_leak_docs) > 0 {
            out.push(format!(
                "residue in {} accepted and {} uncertain documents; target is zero",
                r.accepted_leak_docs, r.uncertain_leak_docs
            ));
        }
        if self.zero_wrong_restorations && r.links.wrong_restorations > 0 {
            out.push(format!(
                "wrong restorations: {}; target is zero",
                r.links.wrong_restorations
            ));
        }
        if let Some(max) = self.max_wrong_links_ambiguous {
            match &r.sequence {
                Some(seq) if seq.wrong_links_ambiguous > max => out.push(format!(
                    "wrong links in ambiguity cases: {} > {max}",
                    seq.wrong_links_ambiguous
                )),
                Some(seq) if released_steps(seq, "Ambiguous") == 0 => out.push(
                    "no ambiguity step was released; the ambiguity gate measured nothing".into(),
                ),
                Some(_) => {}
                None => out.push(
                    "no sequence stats in this report; the ambiguity gate needs `eval --sequences`"
                        .into(),
                ),
            }
        }
        if let Some(max) = self.max_wrong_links_bare_other {
            match &r.sequence {
                Some(seq) => {
                    let wrong = seq
                        .per_label
                        .get("BareRecentOther")
                        .map_or(0, |l| l.wrong_links);
                    if wrong > max {
                        out.push(format!(
                            "wrong links in bare-first-name cases (never seen in full): {wrong} > {max}"
                        ));
                    } else if released_steps(seq, "BareRecentOther") == 0 {
                        out.push(
                            "no bare-first-name step was released; the bare-name gate measured nothing"
                                .into(),
                        );
                    }
                }
                None => out.push(
                    "no sequence stats in this report; the bare-name gate needs `eval --sequences`"
                        .into(),
                ),
            }
        }
        if let Some(max) = self.max_wrong_links_surname_other {
            match &r.sequence {
                Some(seq) if seq.wrong_links_surname_other > max => out.push(format!(
                    "wrong links in surname-collision cases: {} > {max}",
                    seq.wrong_links_surname_other
                )),
                Some(seq) if released_steps(seq, "SurnameRecentOther") == 0 => out.push(
                    "no surname-collision step was released; the surname gate measured nothing"
                        .into(),
                ),
                Some(_) => {}
                None => out.push(
                    "no sequence stats in this report; the surname gate needs `eval --sequences`"
                        .into(),
                ),
            }
        }
        if self.max_resolved_after_grace.is_some() || self.all_resolve_within_grace {
            match &r.sequence {
                Some(seq) => {
                    if seq.rotations == 0 || seq.pre_rotation_tokens == 0 {
                        out.push(
                            "no token minted before a rotation was checked; the grace gate measured nothing"
                                .into(),
                        );
                    }
                    if let Some(max) = self.max_resolved_after_grace {
                        let resolved = seq
                            .pre_rotation_tokens
                            .saturating_sub(seq.unresolved_after_grace);
                        if resolved > max {
                            out.push(format!(
                                "tokens of an expired epoch still resolve after the grace period: {resolved} > {max}"
                            ));
                        }
                    }
                    if self.all_resolve_within_grace
                        && seq.resolved_within_grace < seq.pre_rotation_tokens
                    {
                        out.push(format!(
                            "tokens of the closed epoch stopped resolving during the grace period: {} of {} resolve",
                            seq.resolved_within_grace, seq.pre_rotation_tokens
                        ));
                    }
                }
                None => out.push(
                    "no sequence stats in this report; the grace gate needs `eval --sequences`"
                        .into(),
                ),
            }
        }
        if let Some(max) = self.max_reused_after_rotation {
            match &r.sequence {
                Some(seq) if seq.reused_after_rotation > max => out.push(format!(
                    "tokens issued before the rotation appeared again after it: {} > {max}",
                    seq.reused_after_rotation
                )),
                Some(_) => {}
                None => out.push(
                    "no sequence stats in this report; the rotation gate needs `eval --sequences`"
                        .into(),
                ),
            }
        }
        if let Some(seq) = &r.sequence {
            if seq.event_failures > 0 {
                out.push(format!(
                    "{} sequence events failed (restart, rotation, or sweep); the run is not a measurement",
                    seq.event_failures
                ));
            }
            if seq.restore_errors > 0 {
                out.push(format!(
                    "{} token lookups failed with a vault error; the grace checks are not a measurement",
                    seq.restore_errors
                ));
            }
        }
        for (k, max) in &self.max_detected {
            let n = r.per_kind.get(k).map_or(0, |s| s.detected);
            if n > *max {
                out.push(format!("{k} detected {n} > target {max}"));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::{KindStats, Report};

    fn report(recall_hits: usize, leaks: usize) -> Report {
        let mut r = Report {
            profile: "p".into(),
            docs: 100,
            ..Default::default()
        };
        r.per_kind.insert(
            "PERSON".into(),
            KindStats {
                gold: 100,
                gold_found: recall_hits,
                ..Default::default()
            },
        );
        r.per_kind.insert(
            "TAX_ID".into(),
            KindStats {
                gold: 3,
                gold_found: 1,
                ..Default::default()
            },
        );
        r.docs_with_leak = leaks;
        r.verifier_broken_trials = 100;
        r.verifier_false_negatives = 10;
        r
    }

    #[test]
    fn baseline_ignores_small_kinds_and_flags_regressions() {
        let b = Baseline::from_report(&report(90, 2));
        assert!(b.recall.contains_key("PERSON"));
        assert!(
            !b.recall.contains_key("TAX_ID"),
            "fewer than MIN_GOLD_FOR_GATE gold spans"
        );
        assert!(b.check(&report(90, 2)).is_empty(), "equal is fine");
        let recall_drop = b.check(&report(88, 2));
        assert!(
            recall_drop.iter().any(|m| m.contains("PERSON")),
            "{recall_drop:?}"
        );
        let leak_rise = b.check(&report(90, 3));
        assert!(
            leak_rise.iter().any(|m| m.contains("leak")),
            "{leak_rise:?}"
        );
    }

    #[test]
    fn baseline_round_trips_through_toml() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("b.toml");
        let b = Baseline::from_report(&report(90, 2));
        assert_eq!(b.platform.as_deref(), Some(current_platform().as_str()));
        b.save(&p).unwrap();
        assert_eq!(Baseline::load(&p).unwrap(), b);
    }

    /// I3: a baseline file saved before `platform` existed still loads, with `platform: None`.
    #[test]
    fn baseline_without_a_platform_field_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("b.toml");
        std::fs::write(
            &p,
            "profile = \"p\"\ndocs = 1\nleak_rate = 0.0\nverifier_fn_rate = 0.0\n[recall]\n",
        )
        .unwrap();
        let b = Baseline::load(&p).unwrap();
        assert_eq!(b.platform, None);
    }

    #[test]
    fn check_flags_profile_mismatch() {
        let b = Baseline::from_report(&report(90, 2));
        let mut r = report(90, 2);
        r.profile = "other-profile".into();
        let out = b.check(&r);
        assert!(
            out.iter()
                .any(|m| m.contains("profile mismatch") && m.contains("other-profile")),
            "{out:?}"
        );
    }

    #[test]
    fn check_flags_corpus_size_mismatch() {
        let b = Baseline::from_report(&report(90, 2));
        let mut r = report(90, 2);
        r.docs = 50;
        let out = b.check(&r);
        assert!(
            out.iter()
                .any(|m| m.contains("corpus size differs") && m.contains("50")),
            "{out:?}"
        );
    }

    /// The harness-static gate (plan 2026-10-12): a kind's detection count
    /// above `max_detected` misses the target; a kind with none counts as 0.
    #[test]
    fn max_detected_caps_detections_per_kind() {
        let t: Targets = toml::from_str(
            "max_accepted_leak_rate = 0.0\nmax_block_rate = 0.0\nmax_verifier_fp_rate = 1.0\n[max_detected]\nPERSON = 0\n",
        )
        .unwrap();
        let mut r = Report {
            profile: "p".into(),
            docs: 3,
            pass_docs: 3,
            ..Default::default()
        };
        assert!(t.check(&r).is_empty(), "{:?}", t.check(&r));
        r.per_kind.insert(
            "PERSON".into(),
            KindStats {
                detected: 2,
                ..Default::default()
            },
        );
        let missed = t.check(&r);
        assert_eq!(missed.len(), 1, "{missed:?}");
        assert!(
            missed[0].contains("PERSON") && missed[0].contains('2'),
            "{missed:?}"
        );
    }

    #[test]
    fn targets_flag_each_missed_gate_and_na_acceptance() {
        let t = Targets {
            max_accepted_leak_rate: 0.01,
            max_block_rate: 0.20,
            max_verifier_fp_rate: 0.05,
            min_recall: [("PERSON".to_string(), 0.95)].into_iter().collect(),
            zero_residue: false,
            zero_wrong_restorations: false,
            max_wrong_links_ambiguous: None,
            max_wrong_links_surname_other: None,
            max_wrong_links_bare_other: None,
            max_resolved_after_grace: None,
            all_resolve_within_grace: false,
            max_reused_after_rotation: None,
            max_detected: BTreeMap::new(),
        };
        let mut r = report(96, 2);
        r.pass_docs = 80;
        r.uncertain_docs = 5;
        r.blocked_docs = 15;
        r.accepted_leak_docs = 0;
        r.verifier_clean_trials = 100;
        r.verifier_false_positives = 2;
        assert!(t.check(&r).is_empty(), "{:?}", t.check(&r));
        r.accepted_leak_docs = 1; // 1.25 %
        r.blocked_docs = 20; // 25 %
        r.verifier_false_positives = 6;
        let mut r2 = r.clone();
        r2.per_kind.get_mut("PERSON").unwrap().gold_found = 90;
        let out = t.check(&r2);
        assert_eq!(out.len(), 4, "{out:?}");
        let mut na = report(96, 0);
        na.pass_docs = 0;
        na.blocked_docs = 100;
        assert!(t.check(&na).iter().any(|m| m.contains("N/A")));
        let safety = Targets {
            zero_residue: true,
            ..t.clone()
        };
        let mut s = report(96, 0);
        s.pass_docs = 100;
        s.uncertain_leak_docs = 1;
        assert!(safety.check(&s).iter().any(|m| m.contains("residue")));
    }

    #[test]
    fn sequence_targets_gate_restorations_and_ambiguous_links() {
        let t = Targets::load(std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/targets/sequence.toml"
        )))
        .unwrap();
        assert!(t.zero_wrong_restorations && t.max_wrong_links_ambiguous == Some(0));
        let mut r = report(96, 0);
        r.pass_docs = 100;
        let released = crate::sequence::LabelStats {
            docs: 3,
            accepted: 2,
            blocked: 1,
            ..Default::default()
        };
        r.sequence = Some(crate::sequence::SequenceStats {
            rotations: 1,
            pre_rotation_tokens: 5,
            resolved_within_grace: 5,
            unresolved_after_grace: 5,
            per_label: [
                ("Ambiguous".to_string(), released.clone()),
                ("BareRecentOther".to_string(), released.clone()),
                ("SurnameRecentOther".to_string(), released),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        });
        assert!(t.check(&r).is_empty(), "{:?}", t.check(&r));
        r.links.wrong_restorations = 1;
        assert!(t.check(&r).iter().any(|m| m.contains("wrong restorations")));
        r.links.wrong_restorations = 0;
        r.sequence.as_mut().unwrap().wrong_links_ambiguous = 2;
        assert!(t.check(&r).iter().any(|m| m.contains("ambiguity")));
        r.sequence.as_mut().unwrap().wrong_links_ambiguous = 0;
        r.sequence.as_mut().unwrap().wrong_links_surname_other = 1;
        assert!(t.check(&r).iter().any(|m| m.contains("surname")));
        r.sequence.as_mut().unwrap().wrong_links_surname_other = 0;
        // a gated label whose every step was blocked measured nothing
        let all_blocked = crate::sequence::LabelStats {
            docs: 3,
            blocked: 3,
            ..Default::default()
        };
        let kept = r.sequence.as_ref().unwrap().per_label.clone();
        r.sequence
            .as_mut()
            .unwrap()
            .per_label
            .insert("Ambiguous".into(), all_blocked.clone());
        assert!(
            t.check(&r)
                .iter()
                .any(|m| m.contains("ambiguity gate measured nothing"))
        );
        r.sequence.as_mut().unwrap().per_label = kept.clone();
        r.sequence
            .as_mut()
            .unwrap()
            .per_label
            .insert("SurnameRecentOther".into(), all_blocked);
        assert!(
            t.check(&r)
                .iter()
                .any(|m| m.contains("surname gate measured nothing"))
        );
        r.sequence.as_mut().unwrap().per_label = kept;
        assert!(t.check(&r).is_empty(), "{:?}", t.check(&r));
        // an expired token that still resolves is a privacy failure
        r.sequence.as_mut().unwrap().unresolved_after_grace = 4;
        assert!(t.check(&r).iter().any(|m| m.contains("still resolve")));
        // ... and so is a run that checked no expired token at all
        r.sequence.as_mut().unwrap().pre_rotation_tokens = 0;
        r.sequence.as_mut().unwrap().unresolved_after_grace = 0;
        assert!(t.check(&r).iter().any(|m| m.contains("measured nothing")));
        r.sequence.as_mut().unwrap().pre_rotation_tokens = 5;
        r.sequence.as_mut().unwrap().unresolved_after_grace = 5;
        // ... a run with no rotation at all
        r.sequence.as_mut().unwrap().rotations = 0;
        assert!(t.check(&r).iter().any(|m| m.contains("measured nothing")));
        r.sequence.as_mut().unwrap().rotations = 1;
        // a token that stopped resolving too early breaks rehydration
        r.sequence.as_mut().unwrap().resolved_within_grace = 4;
        assert!(
            t.check(&r)
                .iter()
                .any(|m| m.contains("during the grace period"))
        );
        r.sequence.as_mut().unwrap().resolved_within_grace = 5;
        // a token issued before the rotation that came back after it
        r.sequence.as_mut().unwrap().reused_after_rotation = 1;
        assert!(t.check(&r).iter().any(|m| m.contains("appeared again")));
        r.sequence.as_mut().unwrap().reused_after_rotation = 0;
        r.sequence.as_mut().unwrap().restore_errors = 1;
        assert!(t.check(&r).iter().any(|m| m.contains("vault error")));
        r.sequence.as_mut().unwrap().restore_errors = 0;
        r.sequence.as_mut().unwrap().event_failures = 1;
        assert!(t.check(&r).iter().any(|m| m.contains("events failed")));
        // a first-name link in a BareRecentOther step (default config: zero)
        r.sequence
            .as_mut()
            .unwrap()
            .per_label
            .get_mut("BareRecentOther")
            .unwrap()
            .wrong_links = 2;
        assert!(t.check(&r).iter().any(|m| m.contains("bare-first-name")));
        r.sequence
            .as_mut()
            .unwrap()
            .per_label
            .get_mut("BareRecentOther")
            .unwrap()
            .wrong_links = 0;
        r.sequence = None;
        assert!(
            t.check(&r).iter().any(|m| m.contains("no sequence")),
            "a sequence gate needs sequence stats"
        );
    }

    #[test]
    fn baseline_gates_accepted_leak_and_block_rate() {
        let mut base = report(90, 2);
        base.pass_docs = 90;
        base.blocked_docs = 10;
        base.accepted_leak_docs = 3;
        let b = Baseline::from_report(&base);
        assert_eq!(b.accepted_leak_rate, Some(3.0 / 90.0));
        assert_eq!(b.block_rate, Some(0.1));
        let mut worse = base.clone();
        worse.accepted_leak_docs = 4;
        assert!(b.check(&worse).iter().any(|m| m.contains("accepted leak")));
        let mut blockier = base.clone();
        blockier.pass_docs = 85;
        blockier.blocked_docs = 15;
        assert!(b.check(&blockier).iter().any(|m| m.contains("block rate")));
        assert!(b.check(&base).is_empty());
    }

    #[test]
    fn text_report_has_the_headline_numbers() {
        let t = render_text(&report(90, 2));
        assert!(
            t.contains("PERSON") && t.contains("leak rate") && t.contains("verifier"),
            "{t}"
        );
    }
}
