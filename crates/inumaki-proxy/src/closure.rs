//! The leak closure's dictionary (M8 spec §5 step 6b): what the verifier's
//! leak check searches for (`second_pass::leak_patterns`), as dictionary
//! automata, so the proxy can find every store value left in clear in a
//! leaf and redact it on a re-run.
//!
//! Privacy: the patterns are originals. Every copy made here is held in
//! `Zeroizing` and wiped on drop; the automata keep their own copy of the
//! pattern bytes, which cannot be wiped. `Debug` prints counts only.

use std::fmt;
use std::sync::Arc;

use inumaki_core::detect::dictionary::DictionaryDetector;
use inumaki_core::detect::plausible::is_greeting_only_value;
use inumaki_core::detect::{DetectCtx, Detector, validate_span};
use inumaki_core::span::{EntityKind, Span};
use inumaki_core::token::TokenStore;
use inumaki_core::verify::second_pass::{fold_diacritics, transliterate};
use zeroize::Zeroizing;

use crate::error::Fail;
use crate::session::SessionView;

/// Shorter originals are not searched (the leak check's minimum).
const MIN_ORIGINAL_CHARS: usize = 3;

/// Which store entries a closure dictionary takes: `(removed, kind, value)`.
pub(crate) type Keep<'k> = dyn Fn(bool, &EntityKind, &str) -> bool + 'k;

/// The closure's dictionaries (step 6b): the store's originals (tokenized
/// on a re-run) and its removed values (removed on a re-run, never made a
/// restorable token).
///
/// Built from every original the request's store knows (the session's at
/// request start, plus every value this request minted or resolved) with
/// its transliterated and diacritic-folded forms; each PERSON's name parts
/// in the same three forms; every removed value, also without a trailing
/// sentence mark. Case and whitespace runs are the dictionary's own
/// (`DictionaryDetector`), as in the leak check.
pub(crate) struct ClosureDict {
    originals: Option<DictionaryDetector>,
    removed: Option<DictionaryDetector>,
    /// Entries (patterns before the dictionary's case variants), for `Debug`.
    counts: (usize, usize),
}

impl fmt::Debug for ClosureDict {
    /// Pattern counts only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClosureDict")
            .field("originals", &self.counts.0)
            .field("removed", &self.counts.1)
            .finish()
    }
}

/// One dictionary over `values`, each with its extra forms; `None` when no
/// form is long enough. Every copy is wiped on drop, kept or not; the
/// length is counted in whitespace-collapsed form without another copy.
fn dictionary<'a>(
    values: impl Iterator<Item = (&'a EntityKind, &'a str)>,
    forms: impl Fn(&mut dyn FnMut(String), &EntityKind, &str),
) -> Result<(Option<DictionaryDetector>, usize), Fail> {
    let mut entries: Vec<(EntityKind, Zeroizing<String>)> = Vec::new();
    for (k, v) in values {
        forms(
            &mut |form: String| {
                let form = Zeroizing::new(form);
                let (words, chars) = form
                    .split_whitespace()
                    .fold((0usize, 0usize), |(w, c), x| (w + 1, c + x.chars().count()));
                if chars + words.saturating_sub(1) >= MIN_ORIGINAL_CHARS {
                    entries.push((k.clone(), form));
                }
            },
            k,
            v,
        );
    }
    if entries.is_empty() {
        return Ok((None, 0));
    }
    // `from_entries` borrows; the automaton keeps its own pattern bytes.
    let n = entries.len();
    DictionaryDetector::from_entries(entries.iter().map(|(k, v)| (k.clone(), v.as_str())))
        .map(|d| (Some(d), n))
        .map_err(|_| Fail::Internal)
}

/// Whether `text` (token-shaped) is a token of `store`: one it resolved or
/// minted, or a removed marker whose label the system emits. A forged
/// token-shaped string is not, so it hides nothing from the closure's scan.
///
/// A removed marker (`<LABEL_REMOVED>`) carries no suffix to look up, and
/// any `[A-Z][A-Z0-9_]*` label parses, so a store value such as "Brandl"
/// would hide inside `<BRANDL_REMOVED>`. The label must therefore be a
/// built-in kind's, or the label of a kind the store holds (a custom kind
/// configured in a profile reaches the store only when it minted or
/// removed a value; a marker of a custom kind the store has never seen is
/// treated as forged, which fails closed).
///
/// The rule lives in core (`inumaki_core::engine::real_token`), so the
/// closure and `Engine::project` share one definition.
pub(crate) fn real_token<S: TokenStore + ?Sized>(store: &S, text: &str) -> bool {
    inumaki_core::engine::real_token(store, text)
}

impl ClosureDict {
    /// The dictionaries over `originals` and `removed` (a store's
    /// `entries()` and `removed_entries()`, or a subset). Empty when
    /// neither holds a value long enough.
    pub(crate) fn build<'a>(
        originals: impl Iterator<Item = (&'a EntityKind, &'a str)>,
        removed: impl Iterator<Item = (&'a EntityKind, &'a str)>,
    ) -> Result<ClosureDict, Fail> {
        // Task 7d: a whole greeting-only value identifies no one and is no
        // leak-check pattern, so it triggers and redacts nothing here.
        let originals = originals.filter(|(k, o)| !is_greeting_only_value(k, o));
        let (originals, n_o) = dictionary(originals, |push, k, o| {
            push(String::from(o));
            push(transliterate(o));
            push(fold_diacritics(o));
            if *k == EntityKind::Person {
                for part in inumaki_core::stoplist::name_parts(o) {
                    push(String::from(part));
                    push(transliterate(part));
                    push(fold_diacritics(part));
                }
            }
        })?;
        let (removed, n_r) = dictionary(removed, |push, _, r| {
            push(String::from(r));
            push(String::from(
                r.trim_end_matches(['.', ',', ';', ':', '!', '?', ')']),
            ));
        })?;
        Ok(ClosureDict {
            originals,
            removed,
            counts: (n_o, n_r),
        })
    }

    /// The dictionaries over the view's entries that `keep` accepts (step
    /// 6b's first scan takes those the request added).
    pub(crate) fn from_view(view: &SessionView<'_>, keep: &Keep<'_>) -> Result<ClosureDict, Fail> {
        Self::build(
            view.entries().filter(|(k, o)| keep(false, k, o)),
            view.removed_entries().filter(|(k, r)| keep(true, k, r)),
        )
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.originals.is_none() && self.removed.is_none()
    }

    /// Entries in both dictionaries (before case variants), for `Debug`.
    pub(crate) fn patterns(&self) -> usize {
        self.counts.0 + self.counts.1
    }

    /// Full-match spans (>= 0.9) in `text`, each with whether it is a
    /// removed value; a detector error or an invalid span fails closed. The
    /// dictionary ignores the language hint, so none is detected (that pass
    /// would cost a word scan of every cached leaf).
    pub(crate) fn spans(&self, text: &str) -> Result<Vec<(Span, bool)>, Fail> {
        let ctx = DetectCtx {
            language: inumaki_core::lang::Language::Unknown,
        };
        let mut out = Vec::new();
        for (dict, removed) in [(&self.originals, false), (&self.removed, true)] {
            let Some(dict) = dict else { continue };
            for s in dict.detect(text, &ctx).map_err(|_| Fail::Internal)? {
                validate_span(text, &s).map_err(|_| Fail::Internal)?;
                if s.confidence >= 0.9 && s.start < s.end {
                    out.push((s, removed));
                }
            }
        }
        Ok(out)
    }

    /// The store values left in clear in `text`, as the leak check sees
    /// them (R3 (7)): every overlapping word-bounded match (>= 0.9) of
    /// either dictionary, not the resolved set, so a longer match touching
    /// a token cannot hide a shorter clear one. A match is dropped only when
    /// it lies inside a *real* token (`real(token text)`); a forged
    /// token-shaped string hides nothing. A detector error or an invalid
    /// span fails closed. Empty when the text is clean.
    pub(crate) fn clear_spans(
        &self,
        tokens: &regex::Regex,
        real: &dyn Fn(&str) -> bool,
        text: &str,
    ) -> Result<Vec<Span>, Fail> {
        let mut spans: Vec<Span> = Vec::new();
        for dict in [&self.originals, &self.removed].into_iter().flatten() {
            for s in dict.detect_all(text).map_err(|_| Fail::Internal)? {
                validate_span(text, &s).map_err(|_| Fail::Internal)?;
                if s.confidence >= 0.9 && s.start < s.end {
                    spans.push(s);
                }
            }
        }
        // One occurrence comes back once per case variant: keep one.
        let mut seen = std::collections::HashSet::new();
        spans.retain(|s| seen.insert((s.start, s.end, s.kind.clone())));
        Ok(outside_real_tokens(spans, tokens, real, text))
    }
}

/// `spans` without those lying entirely inside a *real* token of `text`
/// (`real(token text)`): the rule of [`ClosureDict::clear_spans`], shared
/// with every scanned-leaf check. A forged token-shaped string hides
/// nothing.
pub(crate) fn outside_real_tokens(
    mut spans: Vec<Span>,
    tokens: &regex::Regex,
    real: &dyn Fn(&str) -> bool,
    text: &str,
) -> Vec<Span> {
    if spans.is_empty() {
        return spans; // most leaves: no token scan needed
    }
    let toks: Vec<std::ops::Range<usize>> = tokens
        .find_iter(text)
        .filter(|m| real(m.as_str()))
        .map(|m| m.range())
        .collect();
    spans.retain(|s| !toks.iter().any(|t| t.start <= s.start && s.end <= t.end));
    spans
}

/// A position in a session context's two append-only logs: how many
/// entries (tokenized originals) and how many removed values it held. Both
/// logs only grow within a session, so a `Gen` names a stable prefix of
/// each. `Debug` prints the two counts (positions only, no text).
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Gen {
    /// Length of the entry log.
    pub entries: u32,
    /// Length of the removed-value log.
    pub removed: u32,
}

impl Gen {
    /// The empty prefix.
    pub const ZERO: Gen = Gen {
        entries: 0,
        removed: 0,
    };

    /// Whether `self` is at or past `o` in both logs.
    pub fn covers(self, o: Gen) -> bool {
        self.entries >= o.entries && self.removed >= o.removed
    }

    /// The component-wise maximum.
    pub fn max(self, o: Gen) -> Gen {
        Gen {
            entries: self.entries.max(o.entries),
            removed: self.removed.max(o.removed),
        }
    }
}

/// The closure dictionary over the log entries in `[from, to)` (both logs).
pub(crate) struct Segment {
    pub from: Gen,
    pub to: Gen,
    pub dict: ClosureDict,
}

impl fmt::Debug for Segment {
    /// Positions and pattern counts only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Segment")
            .field("from", &self.from)
            .field("to", &self.to)
            .field("dict", &self.dict)
            .finish()
    }
}

/// One session's closure-form dictionary (`Session::closure_dict`): every
/// original in the session context's logs with its closure forms, in three
/// segments (Task 6, ruling L2-07): a base `[0, b)`, a middle segment
/// `[b, m)`, and a delta `[m, upto)`. The delta is rebuilt when the logs
/// grow; past [`TOP_MAX`](inumaki_core::consistency::TOP_MAX) entries it
/// merges into the middle segment (rebuilt over `[b, upto)`), and past
/// [`mid_limit`](inumaki_core::consistency::mid_limit) of the base the base
/// is rebuilt over everything. The logs never shrink, so the segments carry
/// no eviction lifetime (Q7). Used by the first pass, by step 2 for scanned
/// leaves, and by step 6b, so a form one of them finds, all of them find.
pub(crate) struct SessionDict {
    base: Option<Arc<Segment>>,
    mid: Option<Arc<Segment>>,
    delta: Option<Arc<Segment>>,
    /// The logs' lengths this dictionary covers.
    pub upto: Gen,
}

impl fmt::Debug for SessionDict {
    /// Positions and pattern counts only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionDict")
            .field("upto", &self.upto)
            .field("segments", &self.segments().count())
            .field("patterns", &self.patterns())
            .finish()
    }
}

impl SessionDict {
    /// A dictionary over `base`, `mid`, and `delta` (each continuing the
    /// one before), covering the logs up to `upto`.
    pub(crate) fn new(
        base: Option<Arc<Segment>>,
        mid: Option<Arc<Segment>>,
        delta: Option<Arc<Segment>>,
        upto: Gen,
    ) -> SessionDict {
        SessionDict {
            base,
            mid,
            delta,
            upto,
        }
    }

    /// The base segment, shared by the next delta or middle rebuild.
    pub(crate) fn base(&self) -> Option<&Arc<Segment>> {
        self.base.as_ref()
    }

    /// The middle segment, shared by the next delta rebuild.
    pub(crate) fn mid(&self) -> Option<&Arc<Segment>> {
        self.mid.as_ref()
    }

    /// Base, then middle, then delta.
    pub(crate) fn segments(&self) -> impl Iterator<Item = &Segment> {
        self.base
            .iter()
            .chain(self.mid.iter())
            .chain(self.delta.iter())
            .map(|s| &**s)
    }

    /// Segments holding an entry at or after `g` (a superset of what a
    /// leaf verified up to `g` lacks). The stamped cache hits use it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn since(&self, g: Gen) -> impl Iterator<Item = &Segment> {
        self.segments()
            .filter(move |s| s.to.entries > g.entries || s.to.removed > g.removed)
    }

    /// Entries over every segment (before case variants), for `Debug`.
    pub(crate) fn patterns(&self) -> usize {
        self.segments().map(|s| s.dict.patterns()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use inumaki_core::config::TokenSettings;
    use inumaki_core::rehydrate::Rehydrator;
    use inumaki_core::token::{Context, ContextId};
    use std::time::Duration;

    /// R3 (7): the longest match no longer hides a shorter one. The
    /// ORGANIZATION original holds token-shaped text and touches a real
    /// token; "Brandl" (a PERSON name part) is in clear in the same text.
    /// Only a match inside a real token is exempt, and a forged
    /// token-shaped string is not a token (M4).
    #[test]
    fn a_longer_match_touching_a_token_never_hides_a_shorter_clear_one() {
        let mut c = Context::new(
            ContextId(String::new()),
            Duration::from_secs(60),
            TokenSettings::default(),
        );
        let t = c.token_for(&EntityKind::Person, "Qorvex Brandl").unwrap();
        let org = format!("Brandl {}", t.as_str()); // an original holding token-shaped text
        c.token_for(&EntityKind::Organization, &org).unwrap();
        let d = ClosureDict::build(c.entries(), c.removed_entries()).unwrap();
        let tokens = regex::Regex::new(&Rehydrator::pattern(&TokenSettings::default())).unwrap();
        let real = |x: &str| c.original(x).is_some(); // stands in for the view
        let kinds: Vec<_> = d
            .clear_spans(&tokens, &real, &format!("Gruss {org}."))
            .unwrap()
            .into_iter()
            .map(|s| s.kind)
            .collect();
        assert!(
            kinds.contains(&EntityKind::Person),
            "\"Brandl\" is in clear: {kinds:?}"
        );
        // M4: a forged token-shaped string hides nothing.
        assert!(
            !d.clear_spans(&tokens, &real, "Gruss <BRANDL_abcd>.")
                .unwrap()
                .is_empty(),
            "forged token"
        );
    }

    /// A store with a PERSON, and an ORGANIZATION "Person" that is a
    /// word-bounded substring of every PERSON token (`<PERSON_…>`), so the
    /// drop branch of `clear_spans` is reached.
    fn store() -> (Context, String) {
        let mut c = Context::new(
            ContextId(String::new()),
            Duration::from_secs(60),
            TokenSettings::default(),
        );
        let t = c.token_for(&EntityKind::Person, "Qorvex Brandl").unwrap();
        c.token_for(&EntityKind::Organization, "Person").unwrap();
        (c, t.as_str().to_string())
    }

    fn clear(c: &Context, text: &str) -> usize {
        let d = ClosureDict::build(c.entries(), c.removed_entries()).unwrap();
        let tokens = regex::Regex::new(&Rehydrator::pattern(&TokenSettings::default())).unwrap();
        d.clear_spans(&tokens, &|x| real_token(c, x), text)
            .unwrap()
            .len()
    }

    /// The drop branch: a match inside a real token is exempt, the same
    /// label with an unresolvable suffix is not.
    #[test]
    fn a_match_inside_a_real_token_is_exempt_and_inside_a_forged_one_is_not() {
        let (c, t) = store();
        assert_eq!(clear(&c, &format!("Gruss {t}.")), 0, "real token");
        let mut forged = t.clone();
        for h in ['0', '1', '2'] {
            forged.replace_range(forged.len() - 2..forged.len() - 1, &h.to_string());
            if c.original(&forged).is_none() {
                break;
            }
        }
        assert!(c.original(&forged).is_none());
        assert_ne!(forged, t);
        assert!(clear(&c, &format!("Gruss {forged}.")) > 0, "forged suffix");
    }

    /// A removed marker is real only for a kind label the system emits:
    /// `<PERSON_REMOVED>` is exempt, `<BRANDL_REMOVED>` and
    /// `<QORVEX_BRANDL_REMOVED>` (labels that are store values) are not.
    #[test]
    fn a_forged_removed_marker_hides_nothing() {
        let (c, _) = store();
        assert_eq!(clear(&c, "Gruss <PERSON_REMOVED>."), 0, "real marker");
        assert!(clear(&c, "Gruss <BRANDL_REMOVED>.") > 0, "forged marker");
        assert!(
            clear(&c, "Gruss <QORVEX_BRANDL_REMOVED>.") > 0,
            "forged two-word marker"
        );
    }

    /// `Debug` prints counts, never the originals.
    #[test]
    fn debug_prints_counts_only() {
        let (c, _) = store();
        let d = ClosureDict::build(c.entries(), c.removed_entries()).unwrap();
        let s = format!("{d:?}");
        assert!(s.contains("originals"), "{s}");
        for secret in ["Qorvex", "Brandl", "Person"] {
            assert!(!s.contains(secret), "{s}");
        }
    }
}
