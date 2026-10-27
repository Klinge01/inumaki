//! The closure shadow mode's counters (spec §20, 2026-10-12). Compiled in
//! only by the non-default `closure-shadow` feature: a measurement build.
//!
//! For every leaf step 6b projects, the pipeline also runs today's full
//! re-run and forwards that. This module compares the two and counts the
//! differences. Counts and fixed labels only (entity kind labels, check
//! ids, abandonment reasons): no text, token, value or position ever
//! enters a counter, and every working copy of text lives in `Zeroizing`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::ops::Range;
use std::sync::{Mutex, PoisonError};

use inumaki_core::policy::Action;
use inumaki_core::sanitize::Sanitized;
use inumaki_core::span::EntityKind;
use inumaki_core::verify::second_pass::fold_diacritics;
use regex::Regex;
use zeroize::Zeroizing;

/// The divergence counts of a measurement run. `Debug` is derived over
/// counts and labels only.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ShadowCounts {
    /// Projections attempted.
    pub attempted: u64,
    /// Projections that produced a forwardable text.
    pub projected: u64,
    /// Projections abandoned.
    pub abandoned: u64,
    /// Clear-byte invariant violations the projection reported.
    pub invariant_violations: u64,
    /// D1, recall by word: kind label to count.
    pub d1: BTreeMap<String, u64>,
    /// D2, recall by verdict: (check id, kind label) to count.
    pub d2: BTreeMap<(String, String), u64>,
    /// R1, precision: kind label to count.
    pub r1: BTreeMap<String, u64>,
    /// R2: abandonment reason name to count.
    pub r2: BTreeMap<String, u64>,
}

impl ShadowCounts {
    const fn empty() -> Self {
        Self {
            attempted: 0,
            projected: 0,
            abandoned: 0,
            invariant_violations: 0,
            d1: BTreeMap::new(),
            d2: BTreeMap::new(),
            r1: BTreeMap::new(),
            r2: BTreeMap::new(),
        }
    }

    /// One line per key: labels and numbers only.
    pub fn report(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "attempted {}", self.attempted);
        let _ = writeln!(s, "projected {}", self.projected);
        let _ = writeln!(s, "abandoned {}", self.abandoned);
        let _ = writeln!(s, "invariant_violations {}", self.invariant_violations);
        for (k, n) in &self.d1 {
            let _ = writeln!(s, "D1 {k} {n}");
        }
        for ((check, kind), n) in &self.d2 {
            let _ = writeln!(s, "D2 {check} {kind} {n}");
        }
        for (k, n) in &self.r1 {
            let _ = writeln!(s, "R1 {k} {n}");
        }
        for (k, n) in &self.r2 {
            let _ = writeln!(s, "R2 {k} {n}");
        }
        s
    }
}

static COUNTS: Mutex<ShadowCounts> = Mutex::new(ShadowCounts::empty());

fn with<R>(f: impl FnOnce(&mut ShadowCounts) -> R) -> R {
    f(&mut COUNTS.lock().unwrap_or_else(PoisonError::into_inner))
}

/// Held by a test across "count, then `take()`", so two tests that read the
/// global back do not take each other's counts.
#[cfg(test)]
pub(crate) static TAKE_LOCK: Mutex<()> = Mutex::new(());

/// The counts so far; the counters start again from zero.
pub fn take() -> ShadowCounts {
    with(std::mem::take)
}

/// A projection was attempted.
pub(crate) fn attempted() {
    with(|c| c.attempted += 1);
}

/// A projection produced a forwardable text.
pub(crate) fn projected() {
    with(|c| c.projected += 1);
}

/// A projection was abandoned.
pub(crate) fn abandoned() {
    with(|c| c.abandoned += 1);
}

/// The projection reported a clear-byte invariant violation.
pub(crate) fn invariant_violation() {
    with(|c| c.invariant_violations += 1);
}

/// R2: a projection abandoned for `reason` (a fixed enum name) where the
/// full re-run passed.
pub(crate) fn r2(reason: &str) {
    with(|c| *c.r2.entry(reason.to_string()).or_default() += 1);
}

/// D2: the full re-run did not settle a leaf the projection passed.
pub(crate) fn d2(check: &str, kind: &str) {
    with(|c| {
        *c.d2
            .entry((check.to_string(), kind.to_string()))
            .or_default() += 1;
    });
}

/// `s` with every token match blanked, folded and lower-cased.
fn plain(s: &str, tokens: &Regex) -> Zeroizing<String> {
    let blanked = Zeroizing::new(tokens.replace_all(s, " ").into_owned());
    let folded = Zeroizing::new(fold_diacritics(&blanked));
    Zeroizing::new(folded.to_lowercase())
}

/// Whether `needle` is in `hay` bounded by non-alphanumeric characters (or
/// the ends). Both are already folded and lower-cased.
fn contains_bounded(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let mut from = 0;
    while let Some(at) = hay[from..].find(needle) {
        let start = from + at;
        let end = start + needle.len();
        let before = hay[..start].chars().next_back();
        let after = hay[end..].chars().next();
        if !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric) {
            return true;
        }
        // Step one character, not one byte, to stay on a boundary.
        from = start + hay[start..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// The kind labels of D1: each `Tokenize` or `Remove` replacement of the
/// full re-run `full` (over `nfc`) of which a word of two or more letters
/// of the original slice is in clear in `p`, the projection's text (word
/// bounded, case-insensitive, folded, token matches removed). One label
/// per such replacement.
pub(crate) fn d1_kinds(full: &Sanitized, nfc: &str, p: &str, tokens: &Regex) -> Vec<String> {
    let p = plain(p, tokens);
    let mut out = Vec::new();
    for r in &full.replacements {
        if !matches!(r.action, Action::Tokenize | Action::Remove) {
            continue;
        }
        let Some(slice) = nfc.get(r.span.start..r.span.end) else {
            continue;
        };
        let slice = plain(slice, tokens);
        let hit = slice
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| w.chars().filter(|c| c.is_alphabetic()).count() >= 2)
            .any(|w| contains_bounded(&p, w));
        if hit {
            out.push(r.span.kind.label().to_string());
        }
    }
    out
}

/// D1 (recall by word): see [`d1_kinds`]; counts each kind label.
pub(crate) fn d1(full: &Sanitized, nfc: &str, p: &str, tokens: &Regex) {
    let kinds = d1_kinds(full, nfc, p, tokens);
    with(|c| {
        for k in kinds {
            *c.d1.entry(k).or_default() += 1;
        }
    });
}

/// R1 (precision): for each projected `(range, kind)`, count the kind when
/// the slice of `t0` at that range is in clear in the full re-run's text.
pub(crate) fn r1(
    replaced: &[(Range<usize>, EntityKind)],
    t0: &str,
    full_text: &str,
    tokens: &Regex,
) {
    let full = plain(full_text, tokens);
    let mut kinds = Vec::new();
    for (range, kind) in replaced {
        let Some(slice) = t0.get(range.clone()) else {
            continue;
        };
        let slice = plain(slice, tokens);
        if contains_bounded(&full, slice.trim()) {
            kinds.push(kind.label().to_string());
        }
    }
    with(|c| {
        for k in kinds {
            *c.r1.entry(k).or_default() += 1;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use inumaki_core::sanitize::Replacement;
    use inumaki_core::span::{DetectorId, Span};

    fn tokens() -> Regex {
        Regex::new(r"<[A-Z_]+_[0-9a-f]{4}>").unwrap()
    }

    fn sanitized_person(nfc: &str, slice: &str) -> Sanitized {
        let start = nfc.find(slice).unwrap();
        let span = Span::new(
            start,
            start + slice.len(),
            EntityKind::Person,
            0.9,
            DetectorId::Ner,
        );
        Sanitized {
            text: "Bitte <PERSON_a7f2> anrufen.".to_string(),
            replacements: vec![Replacement {
                span,
                action: Action::Tokenize,
                token: None,
                out_range: 6..19,
            }],
            blocked: Vec::new(),
            escalated: Vec::new(),
            protected: Vec::new(),
        }
    }

    /// The counters hold kind labels and numbers only: a D1 recorded from
    /// the slice "Qorvex Brandl" shows `PERSON` in `Debug` and the report,
    /// and no part of the slice.
    #[test]
    fn shadow_counts_debug_and_report_carry_no_text() {
        let _g = TAKE_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        let nfc = "Bitte Qorvex Brandl anrufen.";
        let full = sanitized_person(nfc, "Qorvex Brandl");
        // P still holds "Brandl" in clear beside a real-looking token.
        d1(&full, nfc, "Bitte Brandl <PERSON_a7f2> anrufen.", &tokens());
        let c = take();
        // Other tests of the process may count into the same global.
        assert!(c.d1.get("PERSON").is_some_and(|n| *n >= 1));
        let dbg = format!("{c:?}");
        let rep = c.report();
        for out in [&dbg, &rep] {
            assert!(out.contains("PERSON"));
            for part in ["Qorvex", "Brandl", "qorvex", "brandl"] {
                assert!(!out.contains(part), "{part} in a counter output");
            }
        }
    }

    /// A word inside a token or a longer word is not a clear copy.
    #[test]
    fn d1_ignores_tokens_and_longer_words() {
        let nfc = "Bitte Qorvex Brandl anrufen.";
        let full = sanitized_person(nfc, "Qorvex Brandl");
        let t = tokens();
        assert!(d1_kinds(&full, nfc, "Bitte <PERSON_a7f2> anrufen.", &t).is_empty());
        assert!(d1_kinds(&full, nfc, "Bitte Brandlmayer anrufen.", &t).is_empty());
        assert_eq!(
            d1_kinds(&full, nfc, "Bitte BRANDL anrufen.", &t),
            vec!["PERSON".to_string()]
        );
    }
}
