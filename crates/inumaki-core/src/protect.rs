//! Protected tokens (M8 spec decision 11).
//!
//! A text can already contain tokens: a gateway result's dataset token, a
//! mirrored file's token, a chat session's own token from an earlier turn.
//! Every token-shaped substring of the NFC text that [`parse_token`] accepts
//! (removed markers excluded) is offered to [`TokenStore::prepare`]; those
//! for which [`TokenStore::original`] then answers `Some` are **protected**:
//!
//! - detection runs on the text with their random parts masked to `x`
//!   ([`mask`], same length, so every offset holds);
//! - a detected span that overlaps one is cut into the pieces outside it
//!   ([`clip_spans`]); each piece is trimmed of whitespace and kept with the
//!   same kind, confidence, and source if it still holds an alphanumeric
//!   character. Clipped, never dropped: the rest of the entity is still
//!   tokenized. The clip runs on the detector output after the
//!   plausibility filter (which judges each span whole, so a short
//!   lowercase piece of a longer name is not dropped as a value) and
//!   **before** overlap resolution: resolution ranks source
//!   priority above length, so a dictionary, domain, or regex hit lying
//!   inside a token (its label) would otherwise beat an overlapping model
//!   span that reaches into real text, be clipped to nothing afterwards,
//!   and leave that text undetected;
//! - redaction-derived decisions are clipped the same way after merging
//!   ([`clip_decisions`]);
//! - the sanitized result carries their output ranges
//!   ([`Sanitized::protected`](crate::sanitize::Sanitized::protected), from
//!   [`out_ranges`]), and the verifier treats them like minted tokens:
//!   masked before its re-scans, exempt from them, skipped by the leak check.
//!
//! A token-shaped string the store cannot resolve is ordinary text and gets
//! no protection, because its label can spell a name
//! (`<SARAH_LEITNER_abcd>`).
//!
//! # Stable surface
//!
//! [`find`], [`mask`], [`clip_spans`], [`clip_decisions`], [`out_ranges`],
//! `Sanitized::protected`, `Context::peek_token`, and `Context::kind_of`
//! are the interface other passes build on; [`crate::engine::Engine`]'s
//! `process_detailed` is the one caller that wires them together today.
//!
//! # Contract for later passes
//!
//! Any detector, linker, or rewriting pass added to the pipeline (for
//! example plan 4a-late's `link` module and anchor detector, or a release
//! re-check in `inumakid`) must honor protected ranges: it never emits a
//! span, a link, or an anchor inside one, and never rewrites its bytes. A
//! new span source belongs in the detector stack (its output is clipped
//! with the rest before resolution); a pass that adds spans or decisions
//! after resolution must clip them itself, before they compete with or
//! replace other spans. Today the only later source is the caller's
//! redactions, clipped by [`clip_decisions`] after merging.
//! Decisions reaching `sanitize` must not overlap a protected range;
//! [`out_ranges`] drops a range that does (so its bytes are judged by the
//! verifier like any text, the fail-closed direction), but the token in it
//! would no longer be byte-identical.
//!
//! # Cost
//!
//! [`find`] is one substring check for the opening delimiter when the text
//! holds no token (the common case), else one linear regex pass over the
//! text plus one `prepare` call. The clip and mask helpers return their
//! input unchanged when nothing is protected.

use std::ops::Range;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use regex::Regex;

use crate::config::TokenSettings;
use crate::policy::Decision;
use crate::rehydrate::Rehydrator;
use crate::sanitize::Replacement;
use crate::span::Span;
use crate::token::{StoreError, TokenStore, parse_token};

/// One compiled token pattern per delimiter pair (settings rarely differ).
/// Shared through `Arc` so the regex's search caches are pooled, not
/// rebuilt per call.
fn pattern(settings: &TokenSettings) -> Arc<Regex> {
    type Cache = Mutex<Vec<(String, String, Arc<Regex>)>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let mut c = CACHE
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if let Some((_, _, re)) = c
        .iter()
        .find(|(o, cl, _)| *o == settings.open && *cl == settings.close)
    {
        return Arc::clone(re);
    }
    let re = Arc::new(
        Regex::new(&Rehydrator::pattern(settings))
            .expect("escaped delimiters form a valid pattern"),
    );
    c.push((
        settings.open.clone(),
        settings.close.clone(),
        Arc::clone(&re),
    ));
    re
}

/// Byte ranges (into `text`, which must be NFC) of token-shaped substrings
/// that resolve in `store`, in text order, non-overlapping. Calls
/// `store.prepare` once, with each distinct candidate token, and only when
/// there is one. A store error fails the whole call (nothing is protected
/// and nothing may be sent).
pub fn find(text: &str, store: &mut dyn TokenStore) -> Result<Vec<Range<usize>>, StoreError> {
    let found: Vec<Range<usize>> = {
        let settings = store.settings();
        if !text.contains(settings.open.as_str()) {
            return Ok(Vec::new());
        }
        pattern(settings)
            .find_iter(text)
            .filter(|m| parse_token(settings, m.as_str()).is_some_and(|p| !p.removed))
            .map(|m| m.range())
            .collect()
    };
    if found.is_empty() {
        return Ok(found);
    }
    let mut tokens: Vec<String> = found.iter().map(|r| text[r.clone()].to_string()).collect();
    tokens.sort_unstable();
    tokens.dedup();
    store.prepare(&tokens)?;
    Ok(found
        .into_iter()
        .filter(|r| store.original(&text[r.clone()]).is_some())
        .collect())
}

/// Overwrite the random parts of the token at `range` in `text` (its hex
/// suffix and, for a surface-form token, its two-character component) with
/// `x`, keeping delimiters, label, and separators; same byte length. Does
/// nothing when `text[range]` is not a well-formed token or is a removed
/// marker. The one masking rule for minted and protected tokens alike.
pub(crate) fn mask_token(text: &mut String, range: Range<usize>, settings: &TokenSettings) {
    // Lengths only: the borrow of `text` behind `parse_token`'s result must
    // end before `text` is mutated below.
    let Some((label_len, suffix_len, variant_len)) = text
        .get(range.clone())
        .and_then(|t| parse_token(settings, t))
        .filter(|p| !p.removed && !p.suffix.is_empty())
        .map(|p| (p.label.len(), p.suffix.len(), p.variant.map(str::len)))
    else {
        return;
    };
    let suffix_start = range.start + settings.open.len() + label_len + 1;
    let suffix_end = suffix_start + suffix_len;
    text.replace_range(suffix_start..suffix_end, &"x".repeat(suffix_len));
    if let Some(variant_len) = variant_len {
        let c_start = suffix_end + 1;
        text.replace_range(c_start..c_start + variant_len, &"x".repeat(variant_len));
    }
}

/// `text` with each protected token's random parts masked (see the module
/// docs), same byte length; `None` when nothing is protected. The result
/// holds the input's plaintext: the caller wraps it in `Zeroizing`.
pub fn mask(text: &str, protected: &[Range<usize>], settings: &TokenSettings) -> Option<String> {
    if protected.is_empty() {
        return None;
    }
    let mut out = text.to_string();
    for r in protected {
        mask_token(&mut out, r.clone(), settings);
    }
    Some(out)
}

/// The parts of `start..end` outside every protected range, each trimmed of
/// whitespace, kept only when it still holds an alphanumeric character.
fn pieces(text: &str, start: usize, end: usize, protected: &[Range<usize>]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut cur = start;
    for r in overlapping(protected, start, end) {
        if cur < r.start {
            out.push((cur, r.start));
        }
        cur = cur.max(r.end);
    }
    if cur < end {
        out.push((cur, end));
    }
    out.into_iter()
        .filter_map(|(s, e)| {
            let seg = &text[s..e];
            let lead = seg.len() - seg.trim_start().len();
            let trail = seg.len() - seg.trim_end().len();
            let (s, e) = (s + lead, e - trail);
            (s < e && text[s..e].chars().any(char::is_alphanumeric)).then_some((s, e))
        })
        .collect()
}

/// The protected ranges overlapping `start..end`. `protected` is sorted and
/// non-overlapping (as [`find`] returns it), so ends are sorted too and two
/// binary searches bound the slice: O(log P) per span, not O(P).
fn overlapping(protected: &[Range<usize>], start: usize, end: usize) -> &[Range<usize>] {
    let i = protected.partition_point(|r| r.end <= start);
    let j = i + protected[i..].partition_point(|r| r.start < end);
    &protected[i..j]
}

fn overlaps(protected: &[Range<usize>], start: usize, end: usize) -> bool {
    !overlapping(protected, start, end).is_empty()
}

/// `spans` with every protected byte cut out; each piece keeps kind,
/// confidence, and source. Order is kept (pieces of one span in text
/// order). `protected` must be sorted, as [`find`] returns it.
pub fn clip_spans(text: &str, spans: Vec<Span>, protected: &[Range<usize>]) -> Vec<Span> {
    if protected.is_empty() {
        return spans;
    }
    let mut out = Vec::with_capacity(spans.len());
    for sp in spans {
        if !overlaps(protected, sp.start, sp.end) {
            out.push(sp);
            continue;
        }
        for (s, e) in pieces(text, sp.start, sp.end, protected) {
            out.push(Span {
                start: s,
                end: e,
                ..sp.clone()
            });
        }
    }
    out
}

/// [`clip_spans`] for decisions (redactions merged into policy decisions):
/// each piece keeps the decision's action, kind, confidence, and source.
pub fn clip_decisions(
    text: &str,
    decisions: Vec<Decision>,
    protected: &[Range<usize>],
) -> Vec<Decision> {
    if protected.is_empty() {
        return decisions;
    }
    let mut out = Vec::with_capacity(decisions.len());
    for d in decisions {
        if !overlaps(protected, d.span.start, d.span.end) {
            out.push(d);
            continue;
        }
        for (s, e) in pieces(text, d.span.start, d.span.end, protected) {
            out.push(Decision {
                span: Span {
                    start: s,
                    end: e,
                    ..d.span.clone()
                },
                action: d.action,
            });
        }
    }
    out
}

/// Where each protected input range lands in the sanitized output, given
/// the applied `replacements` (sorted, as `sanitize` returns them). A
/// protected range that overlaps a replacement's input span is dropped:
/// its bytes were rewritten, so it is no longer a token the verifier may
/// exempt (fail closed; see the module docs' contract).
pub fn out_ranges(protected: &[Range<usize>], replacements: &[Replacement]) -> Vec<Range<usize>> {
    let mut out = Vec::with_capacity(protected.len());
    let mut shift: isize = 0;
    let mut i = 0;
    for r in protected {
        // Replacements wholly before this range shift it.
        while i < replacements.len() && replacements[i].span.end <= r.start {
            let x = &replacements[i];
            shift += x.out_range.len() as isize - (x.span.end - x.span.start) as isize;
            i += 1;
        }
        if replacements[i..]
            .iter()
            .take_while(|x| x.span.start < r.end)
            .any(|x| r.start < x.span.end)
        {
            continue;
        }
        let s = r.start.saturating_add_signed(shift);
        out.push(s..s + r.len());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::span::EntityKind;
    use crate::token::{Context, ContextId, Token};
    use std::time::Duration;
    use zeroize::Zeroizing;

    /// A store that claims to know every token, records what `prepare`
    /// was given, and otherwise delegates to a `Context`.
    struct KnowsAll(Context, Vec<String>);
    impl TokenStore for KnowsAll {
        fn token_for(&mut self, k: &EntityKind, o: &str) -> Result<Token, StoreError> {
            self.0.token_for(k, o)
        }
        fn original(&self, _: &str) -> Option<&str> {
            Some("x")
        }
        fn entries(&self) -> Box<dyn Iterator<Item = (&EntityKind, &str)> + '_> {
            Box::new(self.0.entries())
        }
        fn record_removed(&mut self, k: &EntityKind, o: &str) -> Result<(), StoreError> {
            self.0.record_removed(k, o);
            Ok(())
        }
        fn removed_entries(&self) -> Box<dyn Iterator<Item = (&EntityKind, &str)> + '_> {
            Box::new(self.0.removed_entries())
        }
        fn removed_marker(&self, k: &EntityKind) -> String {
            self.0.removed_marker(k)
        }
        fn settings(&self) -> &TokenSettings {
            self.0.settings()
        }
        fn prepare(&mut self, tokens: &[String]) -> Result<(), StoreError> {
            self.1.extend_from_slice(tokens);
            Ok(())
        }
        fn surface_token(&mut self, p: &Token, s: &str) -> Result<Token, StoreError> {
            self.0.surface_token(p, s)
        }
        fn link_candidates(&self, _: &EntityKind, _: Duration) -> Vec<Zeroizing<String>> {
            Vec::new()
        }
    }

    fn ctx() -> Context {
        Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            TokenSettings::default(),
        )
    }

    /// Removed markers are never protected (nor offered to `prepare`), even
    /// to a store that would answer for them; repeats are prepared once.
    #[test]
    fn removed_markers_are_not_protected_and_prepare_sees_each_token_once() {
        let text = "a <SECRET_REMOVED> b <PERSON_ab12> c <PERSON_ab12_3e> <PERSON_ab12>";
        let mut s = KnowsAll(ctx(), Vec::new());
        let p = find(text, &mut s).unwrap();
        let got: Vec<&str> = p.iter().map(|r| &text[r.clone()]).collect();
        assert_eq!(got, ["<PERSON_ab12>", "<PERSON_ab12_3e>", "<PERSON_ab12>"]);
        assert_eq!(s.1, ["<PERSON_ab12>", "<PERSON_ab12_3e>"]);
        assert!(find("no tokens here", &mut s).unwrap().is_empty());
        assert_eq!(s.1.len(), 2, "no prepare without a candidate");
    }

    /// A span inside a protected token disappears; one around it is split;
    /// whitespace-only and punctuation-only pieces go.
    #[test]
    fn clipping_splits_trims_and_drops_empty_pieces() {
        let text = "Herr <PERSON_ab12> Pellqwyn, <PERSON_cd34>.";
        let a = text.find("<PERSON_ab12>").unwrap();
        let b = text.find("<PERSON_cd34>").unwrap();
        let protected = [a..a + 13, b..b + 13];
        let sp = |s: usize, e: usize| {
            Span::new(s, e, EntityKind::Person, 0.7, crate::span::DetectorId::Ner)
        };
        let out = clip_spans(text, vec![sp(0, text.len()), sp(a + 1, a + 7)], &protected);
        let got: Vec<&str> = out.iter().map(|s| s.slice(text)).collect();
        assert_eq!(got, ["Herr", "Pellqwyn,"]);
        assert!(out.iter().all(|s| s.confidence == 0.7));
        assert_eq!(
            mask(text, &protected, &TokenSettings::default()).unwrap(),
            "Herr <PERSON_xxxx> Pellqwyn, <PERSON_xxxx>."
        );
    }

    /// A protected range shifted by an earlier replacement lands where the
    /// token now sits; one a replacement overlaps is dropped (fail closed:
    /// its bytes are no longer exempt).
    #[test]
    fn out_ranges_shifts_and_drops_overlapped_ranges() {
        use crate::policy::Action;
        let rep = |s: usize, e: usize, out: Range<usize>| Replacement {
            span: Span::new(s, e, EntityKind::Person, 0.9, crate::span::DetectorId::Ner),
            action: Action::Tokenize,
            token: None,
            out_range: out,
        };
        // 5..8 (3 bytes) became 13 bytes: +10; 28..35 overlaps 30..43.
        let reps = [rep(5, 8, 5..18), rep(28, 35, 38..51)];
        assert_eq!(out_ranges(&[10..23, 30..43], &reps), vec![20..33; 1]);
        assert_eq!(out_ranges(&[0..4, 10..23], &reps[..1]), [0..4, 20..33]);
    }
}
