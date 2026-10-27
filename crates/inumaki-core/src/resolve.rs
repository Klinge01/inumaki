//! Deterministic overlap resolution: source priority, then length, then confidence,
//! accepted greedily best first.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::span::Span;

/// Best first: higher source priority, then longer, then higher
/// confidence, then earlier start.
fn rank(a: &Span, b: &Span) -> Ordering {
    b.source
        .priority()
        .cmp(&a.source.priority())
        .then(b.len().cmp(&a.len()))
        .then(b.confidence.total_cmp(&a.confidence))
        .then(a.start.cmp(&b.start))
}

/// True when `start..end` overlaps an interval in `accepted` (a set of
/// non-overlapping, non-empty intervals keyed by start, valued by end).
///
/// Because accepted intervals do not overlap, the one with the greatest
/// start before `end` also has the greatest end among them; it alone
/// decides.
pub(crate) fn overlaps_accepted(
    accepted: &BTreeMap<usize, usize>,
    start: usize,
    end: usize,
) -> bool {
    accepted
        .range(..end)
        .next_back()
        .is_some_and(|(_, &e)| e > start)
}

/// Confidence of a full-name dictionary hit; below it a PERSON hit is a
/// fragment the dictionary derived from a known full name (its surname).
const DICTIONARY_FULL_NAME_CONFIDENCE: f32 = 0.97;

/// Whether `container` is a span that `fragment` must yield to: a
/// [`DetectorId::Dictionary`] fragment strictly inside a longer span of the
/// same kind from another detector, when either
///
/// - the fragment is a derived PERSON surname (confidence below a
///   full-name hit) and the container is any PERSON span: source priority
///   would otherwise cut `Sarah Gruber` in two when the store knows only
///   `Thomas Gruber`; or
/// - `container_ok(container)` holds (the caller's policy check; the engine
///   passes "every active profile tokenizes, removes, or blocks it"): a
///   store's bare `Hauptstraße` must not cut the street regex's `Wiedner
///   Hauptstraße 61` and leave `Wiedner` and `61` in clear, and a weak
///   regex or NER span never evicts a known entity.
///
/// A span that merely overlaps, a container of another kind (possibly a
/// preserved one), and an identical range never make a fragment yield.
fn yields_to(fragment: &Span, container: &Span, container_ok: &dyn Fn(&Span) -> bool) -> bool {
    use crate::span::{DetectorId, EntityKind};
    fragment.source == DetectorId::Dictionary
        && container.source != DetectorId::Dictionary
        && container.kind == fragment.kind
        && container.start <= fragment.start
        && fragment.end <= container.end
        && container.len() > fragment.len()
        && ((fragment.kind == EntityKind::Person
            && fragment.confidence < DICTIONARY_FULL_NAME_CONFIDENCE)
            || container_ok(container))
}

/// Reorder `ranked` (best first) so that every fragment comes right after
/// the last span it yields to (see [`yields_to`]), instead of being
/// dropped: when a container is accepted the fragment overlaps it and is
/// skipped, and when every container loses to some other span the
/// fragment still competes, so the value it covers is never left
/// uncovered (review I1).
fn rank_fragments_after_containers(
    ranked: Vec<Span>,
    container_ok: &dyn Fn(&Span) -> bool,
) -> Vec<Span> {
    use crate::span::DetectorId;
    if !ranked.iter().any(|s| s.source == DetectorId::Dictionary) {
        return ranked;
    }
    let keys: Vec<(usize, u8, usize)> = (0..ranked.len())
        .map(|i| {
            // Only a dictionary span can be a fragment (see `yields_to`), so
            // every other span skips the scan over all candidates.
            if ranked[i].source != DetectorId::Dictionary {
                return (i, 0, i);
            }
            let last = (0..ranked.len())
                .filter(|&j| yields_to(&ranked[i], &ranked[j], container_ok))
                .max();
            match last {
                Some(j) if j > i => (j, 1, i),
                _ => (i, 0, i),
            }
        })
        .collect();
    let mut order: Vec<usize> = (0..ranked.len()).collect();
    order.sort_by_key(|&i| keys[i]);
    let mut slots: Vec<Option<Span>> = ranked.into_iter().map(Some).collect();
    order.into_iter().filter_map(|i| slots[i].take()).collect()
}

/// Reduce candidate spans to a non-overlapping set, sorted by start offset.
///
/// Candidates are ranked best first: higher-priority source, then longer
/// span, then higher confidence, then earlier start. Each candidate is
/// accepted when it overlaps no already-accepted span. A span that loses to
/// a better one is therefore judged only against spans that are actually
/// kept, never against one that was itself displaced.
///
/// With no policy at hand, a dictionary span strictly inside a longer span
/// of the same kind keeps its priority, except a derived PERSON surname
/// fragment; see [`resolve_overlaps_with`].
pub fn resolve_overlaps(spans: Vec<Span>) -> Vec<Span> {
    resolve_overlaps_with(spans, &|_| false)
}

/// [`resolve_overlaps`], where a dictionary span strictly inside a longer
/// non-dictionary span of the same kind is ranked right after that span
/// when `container_ok(longer span)` holds (the caller's policy check: the
/// longer span is confident enough to be tokenized). The fragment then
/// yields when the container is kept and competes when it is not.
pub fn resolve_overlaps_with(
    mut spans: Vec<Span>,
    container_ok: &dyn Fn(&Span) -> bool,
) -> Vec<Span> {
    spans.retain(|s| !s.is_empty());
    spans.sort_by(rank);
    let spans = rank_fragments_after_containers(spans, container_ok);
    let mut accepted: BTreeMap<usize, usize> = BTreeMap::new();
    let mut out: Vec<Span> = Vec::with_capacity(spans.len());
    for s in spans {
        if overlaps_accepted(&accepted, s.start, s.end) {
            continue;
        }
        accepted.insert(s.start, s.end);
        out.push(s);
    }
    out.sort_by_key(|s| s.start);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::span::{DetectorId as D, EntityKind as K, Span};

    fn s(start: usize, end: usize, k: K, c: f32, d: D) -> Span {
        Span::new(start, end, k, c, d)
    }

    #[test]
    fn higher_priority_source_wins_even_when_shorter() {
        let out = resolve_overlaps(vec![
            s(0, 30, K::Organization, 0.9, D::Ner),
            s(5, 25, K::Iban, 0.99, D::RegexValidated),
        ]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, K::Iban);
    }

    /// A dictionary surname fragment never splits a longer PERSON span of
    /// another detector; full-name hits, mere overlaps, and other kinds keep
    /// the usual priority.
    #[test]
    fn dictionary_surname_fragment_does_not_split_a_containing_person() {
        let ner = s(0, 12, K::Person, 0.9, D::Ner);
        let fragment = s(6, 12, K::Person, 0.80, D::Dictionary);
        assert_eq!(
            resolve_overlaps(vec![ner.clone(), fragment]),
            vec![ner.clone()]
        );
        // a full-name hit (0.97) still wins over the containing NER span
        let full = s(6, 12, K::Person, 0.97, D::Dictionary);
        assert_eq!(
            resolve_overlaps(vec![ner.clone(), full.clone()]),
            vec![full]
        );
        // an overlap that is not containment still wins
        let partial = s(6, 20, K::Person, 0.80, D::Dictionary);
        assert_eq!(
            resolve_overlaps(vec![ner.clone(), partial.clone()]),
            vec![partial]
        );
        // a fragment of another kind, and an identical range, keep priority
        let org = s(6, 12, K::Organization, 0.80, D::Dictionary);
        assert_eq!(resolve_overlaps(vec![ner.clone(), org.clone()]), vec![org]);
        let same = s(0, 12, K::Person, 0.80, D::Dictionary);
        assert_eq!(resolve_overlaps(vec![ner, same.clone()]), vec![same]);
    }

    #[test]
    fn equal_priority_longer_wins() {
        let out = resolve_overlaps(vec![
            s(0, 5, K::Person, 0.99, D::Ner),
            s(0, 13, K::Person, 0.80, D::Ner),
        ]);
        assert_eq!(out, vec![s(0, 13, K::Person, 0.80, D::Ner)]);
    }

    #[test]
    fn equal_priority_and_length_higher_confidence_wins() {
        let out = resolve_overlaps(vec![
            s(0, 5, K::City, 0.6, D::Ner),
            s(0, 5, K::Person, 0.9, D::Ner),
        ]);
        assert_eq!(out[0].kind, K::Person);
    }

    #[test]
    fn adjacent_spans_are_both_kept_and_sorted() {
        let out = resolve_overlaps(vec![
            s(10, 20, K::Phone, 0.85, D::RegexSyntax),
            s(0, 10, K::Person, 0.9, D::Ner),
        ]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].start, 0);
        assert_eq!(out[1].start, 10);
    }

    #[test]
    fn chain_of_overlaps() {
        // A(0-10, ner) B(5-15, dictionary) C(12-20, ner): B beats A, C overlaps B and loses.
        let out = resolve_overlaps(vec![
            s(0, 10, K::Person, 0.9, D::Ner),
            s(5, 15, K::Person, 0.97, D::Dictionary),
            s(12, 20, K::Person, 0.9, D::Ner),
        ]);
        assert_eq!(out, vec![s(5, 15, K::Person, 0.97, D::Dictionary)]);
    }

    /// I3: a span that lost to a span which was itself later evicted must
    /// come back. Domain [0,30) beats Person [2,10) but loses to IBAN
    /// [20,40); Person no longer overlaps anything kept and must survive.
    #[test]
    fn span_that_lost_to_an_evicted_span_survives() {
        let out = resolve_overlaps(vec![
            s(0, 30, K::CustomerId, 0.95, D::Domain),
            s(2, 10, K::Person, 0.97, D::Dictionary),
            s(20, 40, K::Iban, 0.99, D::RegexValidated),
        ]);
        assert_eq!(
            out,
            vec![
                s(2, 10, K::Person, 0.97, D::Dictionary),
                s(20, 40, K::Iban, 0.99, D::RegexValidated),
            ]
        );
    }

    #[test]
    fn exact_ties_keep_the_earlier_span() {
        let out = resolve_overlaps(vec![
            s(0, 5, K::City, 0.9, D::Ner),
            s(3, 8, K::Person, 0.9, D::Ner),
        ]);
        assert_eq!(out, vec![s(0, 5, K::City, 0.9, D::Ner)]);
    }

    #[test]
    fn empty_input() {
        assert!(resolve_overlaps(vec![]).is_empty());
    }

    /// Fix round 1 (L30): a dictionary fragment strictly inside a longer
    /// span of the same kind that the policy accepts is dropped, for any
    /// kind (street, organization, a full-name PERSON hit); a container the
    /// policy rejects, a container of another kind, and a mere overlap
    /// leave the fragment its priority.
    #[test]
    fn contained_dictionary_fragment_yields_to_an_accepted_same_kind_span() {
        let ok = |s: &Span| s.confidence >= 0.5;
        let street = s(0, 22, K::StreetAddress, 0.9, D::RegexSyntax);
        let frag = s(8, 19, K::StreetAddress, 0.97, D::Dictionary);
        assert_eq!(
            resolve_overlaps_with(vec![street.clone(), frag.clone()], &ok),
            vec![street.clone()]
        );
        let org = s(0, 16, K::Organization, 0.8, D::Ner);
        let known_org = s(0, 11, K::Organization, 0.97, D::Dictionary);
        assert_eq!(
            resolve_overlaps_with(vec![org.clone(), known_org], &ok),
            vec![org]
        );
        // the policy would not tokenize the container: the known entity wins
        let weak = s(0, 22, K::StreetAddress, 0.3, D::Ner);
        assert_eq!(
            resolve_overlaps_with(vec![weak, frag.clone()], &ok),
            vec![frag.clone()]
        );
        // another kind never swallows a store value
        let city = s(0, 22, K::City, 0.9, D::Ner);
        assert_eq!(
            resolve_overlaps_with(vec![city, frag.clone()], &ok),
            vec![frag.clone()]
        );
        // without a policy (`resolve_overlaps`) nothing changes
        assert_eq!(resolve_overlaps(vec![street, frag.clone()]), vec![frag]);
    }

    /// Review I1: a fragment whose container loses to a higher-priority
    /// span of another kind (one that does not overlap the fragment) still
    /// competes, so the known value is covered: `Hauptstraße 5, 1010 Wien`
    /// with an NER street over the whole line, the known street, and the
    /// regex postal code.
    #[test]
    fn fragment_competes_when_its_container_loses() {
        let ok = |_: &Span| true;
        let text = "Hauptstraße 5, 1010 Wien";
        assert_eq!(text.len(), 25);
        let ner = s(0, 25, K::StreetAddress, 0.9, D::Ner);
        let known = s(0, 14, K::StreetAddress, 0.97, D::Dictionary);
        let postal = s(16, 20, K::PostalCode, 0.9, D::RegexSyntax);
        assert_eq!(
            resolve_overlaps_with(vec![ner, known.clone(), postal.clone()], &ok),
            vec![known, postal]
        );
    }

    /// Review I1, PERSON: a derived surname fragment inside an NER person
    /// span that loses to a customer ID still competes.
    #[test]
    fn surname_fragment_competes_when_its_container_loses() {
        // "Sarah Gruber K-482913": NER over-extends into the ID
        let ner = s(0, 21, K::Person, 0.9, D::Ner);
        let surname = s(6, 12, K::Person, 0.80, D::Dictionary);
        let id = s(13, 21, K::CustomerId, 0.95, D::Domain);
        assert_eq!(
            resolve_overlaps(vec![ner, surname.clone(), id.clone()]),
            vec![surname, id]
        );
    }
}
