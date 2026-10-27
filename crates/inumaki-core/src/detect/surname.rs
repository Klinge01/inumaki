//! Surname continuation for model-found person spans (L3 step 2, ruling a).
//!
//! A model sometimes stops a person span at the first name and leaves the
//! surname after it in clear: `lukas petrović`, lower-case and with
//! diacritics, reads to it like an ordinary word. When the span ends with a
//! first name the DACH gazetteer knows, the next word on the same line is
//! the likeliest surname, and this module extends the span over it.
//!
//! The rule is deliberately narrow:
//! - only PERSON spans from NER or anchors (a known-entity span keeps the
//!   exact value the store holds);
//! - only when the span's last word is a gazetteer first name;
//! - only one word, made of letters (diacritics allowed, any case), with
//!   parts joined by `-` or an apostrophe (`müller-lang`, `O'Brien`) taken
//!   whole or not at all, separated from the span by same-line Unicode
//!   spaces (tabs, no-break, thin), never by a line break;
//! - an apostrophe before an English clitic that ends the word (`'s`,
//!   `'t`, `'re`, `'ll`, `'ve`, `'d`, `'m`) ends the word there: the stem
//!   is the candidate (`petrović's` takes `petrović`, `don't` is judged as
//!   `don`), unless the clitic is joined on to more letters
//!   (`Meyer's-Lang` stays whole);
//! - never a common word or a salutation word (`bitte`, `Team`), unless the
//!   common word is also a plausible surname (`Smith`, `Lang`);
//! - never a word a protected token covers, nor one another span covers
//!   that would keep it covered on its own (see [`extend_over_surnames`]).

use std::ops::Range;

use crate::gazetteer::is_first_name;
use crate::span::{DetectorId, EntityKind, Span};
use crate::stoplist::{is_common_word, is_name_like_word, is_salutation_word};

/// What may stand between a first name and its surname: any Unicode space
/// on the same line (space, tab, the no-break, thin and figure spaces a
/// mail client or word processor inserts), never a line break or a line
/// or paragraph separator (ruling L66).
fn is_gap(c: char) -> bool {
    c.is_whitespace()
        && !matches!(
            c,
            '\n' | '\r' | '\u{000B}' | '\u{000C}' | '\u{0085}' | '\u{2028}' | '\u{2029}'
        )
}

/// What joins the parts of one surname (`müller-lang`, `O'Brien`,
/// `O’Brien`).
const JOINERS: &[char] = &['-', '\'', '\u{2019}'];

/// True when `rest` (the text right after an apostrophe) is an English
/// clitic that ends the word (`'s`, `'t`, `'re`, `'ll`, `'ve`, `'d`, `'m`,
/// any case): a possessive or contraction, not part of a surname (ruling
/// L3-02). `O'Brien`, `O'Dell` go on with letters and stay joined, and so
/// does a clitic joined on to more letters (`Meyer's-Lang`): cutting there
/// would leave the rest in clear.
fn is_clitic(rest: &str) -> bool {
    let len: usize = rest
        .chars()
        .take_while(|c| c.is_alphabetic())
        .map(char::len_utf8)
        .sum();
    let mut after = rest[len..].chars();
    let joined_on = after.next().is_some_and(|c| JOINERS.contains(&c))
        && after.next().is_some_and(char::is_alphabetic);
    !joined_on
        && matches!(
            rest[..len].to_lowercase().as_str(),
            "s" | "t" | "re" | "ll" | "ve" | "d" | "m"
        )
}

/// The byte range of the surname candidate after `end`, if the rule allows
/// one. `end` is the end of a span whose last word is a first name.
fn next_word(text: &str, end: usize) -> Option<Range<usize>> {
    let rest = text.get(end..)?;
    let gap = rest.len() - rest.trim_start_matches(is_gap).len();
    if gap == 0 {
        return None;
    }
    let start = end + gap;
    // letters, and a joiner only between two letters (`müller-lang`,
    // `O'Brien`): a trailing joiner ends the word and fails the clean-end
    // test below, so the word is taken whole or not at all (ruling L43 iii).
    // An apostrophe before an English clitic ends the word cleanly: the
    // stem (`petrović` of `petrović's`, `don` of `don't`) is the candidate.
    let mut word_end = start;
    let mut clitic = false;
    let mut chars = text[start..].char_indices().peekable();
    while let Some((k, c)) = chars.next() {
        if c.is_alphabetic() {
            word_end = start + k + c.len_utf8();
        } else if matches!(c, '\'' | '\u{2019}')
            && k > 0
            && is_clitic(&text[start + k + c.len_utf8()..])
        {
            clitic = true;
            break;
        } else if JOINERS.contains(&c)
            && k > 0
            && chars.peek().is_some_and(|(_, n)| n.is_alphabetic())
        {
            continue;
        } else {
            break;
        }
    }
    let word = &text[start..word_end];
    if word.chars().count() < 2 {
        return None;
    }
    let mut after = text[word_end..].chars();
    let ends_cleanly = clitic
        || match after.next() {
            None => true,
            Some(c) if c.is_whitespace() => true,
            Some(',' | ';' | ':' | '!' | '?' | ')') => true,
            Some('.') => !after.next().is_some_and(char::is_alphanumeric),
            Some(_) => false,
        };
    // A common word that is also a plausible surname (`Smith`, `Lang`)
    // may be taken, as the anchor detector does (re-review 3 I1).
    let common = |w: &str| is_common_word(w) && !is_name_like_word(w);
    // a joined word counts only when one of its parts does, as in the retry
    // guard (ruling L45): `müller-lang` is a candidate, `Support-Team` is not
    let counts = |w: &str| !w.is_empty() && !common(w) && !is_salutation_word(w);
    if !ends_cleanly || !counts(word) || !word.split(JOINERS).any(counts) {
        return None;
    }
    Some(start..word_end)
}

/// The last word of `span`, when the span ends at a word boundary.
fn last_word<'a>(text: &'a str, span: &Span) -> Option<&'a str> {
    if text[span.end..]
        .chars()
        .next()
        .is_some_and(char::is_alphabetic)
    {
        return None;
    }
    let inner = &text[span.start..span.end];
    let len: usize = inner
        .chars()
        .rev()
        .take_while(|c| c.is_alphabetic())
        .map(char::len_utf8)
        .sum();
    (len > 0).then(|| &inner[inner.len() - len..])
}

/// `spans` with every NER or anchor PERSON span that ends with a gazetteer
/// first name extended over the surname candidate after it (see the
/// module docs). `protected` are the masked token ranges (sorted or not).
///
/// Another span over the candidate stops the extension, unless the
/// extended span would win overlap resolution against it (no higher
/// source priority, and it lies inside the word) and it would not keep
/// the word covered by itself: a PERSON span (the extended one carries the
/// surname whatever its own score), or a span some profile preserves or
/// drops. `acted_on` says whether every profile that may settle the text
/// tokenizes, removes, or blocks a span (re-review 2: a sub-threshold
/// `petrović` PERSON 0.3, or a preserved CITY, must not leave the surname
/// in clear).
pub fn extend_over_surnames(
    text: &str,
    mut spans: Vec<Span>,
    protected: &[Range<usize>],
    acted_on: &dyn Fn(&Span) -> bool,
) -> Vec<Span> {
    let mut extensions = Vec::new();
    for (i, s) in spans.iter().enumerate() {
        if s.kind != EntityKind::Person || !matches!(s.source, DetectorId::Ner | DetectorId::Anchor)
        {
            continue;
        }
        let Some(first) = last_word(text, s) else {
            continue;
        };
        if !is_first_name(first) {
            continue;
        }
        let Some(word) = next_word(text, s.end) else {
            continue;
        };
        let yields = |o: &Span| {
            o.source.priority() <= s.source.priority()
                && word.start <= o.start
                && o.end <= word.end
                && (o.kind == EntityKind::Person || !acted_on(o))
        };
        let taken = protected
            .iter()
            .any(|r| r.start < word.end && word.start < r.end)
            || spans
                .iter()
                .enumerate()
                .any(|(j, o)| j != i && o.start < word.end && word.start < o.end && !yields(o));
        if !taken {
            extensions.push((i, word.end));
        }
    }
    for (i, end) in extensions {
        spans[i].end = end;
    }
    spans
}

#[cfg(test)]
mod tests {
    use super::*;

    fn person(text: &str, needle: &str, source: DetectorId) -> Span {
        let i = text.find(needle).unwrap();
        Span::new(i, i + needle.len(), EntityKind::Person, 0.9, source)
    }

    fn extended(text: &str, needle: &str) -> String {
        let s = extend_over_surnames(
            text,
            vec![person(text, needle, DetectorId::Ner)],
            &[],
            &|_| true,
        );
        s[0].slice(text).to_string()
    }

    #[test]
    fn a_surname_after_a_first_name_joins_the_span() {
        assert_eq!(extended("Grüße\nlukas petrović", "lukas"), "lukas petrović");
        assert_eq!(extended("Anna Šimić, bitte", "Anna"), "Anna Šimić");
        assert_eq!(
            extended("an anna\n\n--\nanna kovač.", "anna\n\n--\nanna"),
            "anna\n\n--\nanna kovač"
        );
    }

    #[test]
    fn a_joined_surname_or_a_no_break_space_gap_extends_whole() {
        // final review 2: hyphen- and apostrophe-joined surnames, and a
        // no-break space between first name and surname
        assert_eq!(
            extended("Danke, lukas müller-lang.", "lukas"),
            "lukas müller-lang"
        );
        assert_eq!(extended("an anna O'Brien, bitte", "anna"), "anna O'Brien");
        assert_eq!(
            extended("an anna O\u{2019}Brien", "anna"),
            "anna O\u{2019}Brien"
        );
        assert_eq!(
            extended("Anna\u{00A0}Berger schreibt", "Anna"),
            "Anna\u{00A0}Berger"
        );
        assert_eq!(extended("Anna\u{202F}Berger", "Anna"), "Anna\u{202F}Berger");
        // ruling L66: any same-line Unicode space (thin, figure)
        assert_eq!(extended("Anna\u{2009}Berger", "Anna"), "Anna\u{2009}Berger");
        assert_eq!(extended("Anna\u{2007}Berger", "Anna"), "Anna\u{2007}Berger");
        // a line or paragraph separator is a line break, not a gap
        assert_eq!(extended("Anna\u{2028}Berger", "Anna"), "Anna");
        assert_eq!(extended("Anna\u{0085}Berger", "Anna"), "Anna");
    }

    #[test]
    fn an_english_clitic_is_not_part_of_the_surname() {
        // ruling L3-02: a possessive or contraction ends the word before
        // the apostrophe; the stem goes through the usual checks
        assert_eq!(
            extended("I met lukas petrović's sister", "lukas"),
            "lukas petrović"
        );
        assert_eq!(
            extended("I met lukas petrović\u{2019}s sister", "lukas"),
            "lukas petrović"
        );
        assert_eq!(extended("ask anna O'Brien's team", "anna"), "anna O'Brien");
        assert_eq!(extended("ask anna O'Brien.", "anna"), "anna O'Brien");
        // a clitic joined on to more letters is no cut: the word stays
        // whole, never `-Lang` left clear
        assert_eq!(extended("anna Meyer's-Lang", "anna"), "anna Meyer's-Lang");
        assert_eq!(
            extended("anna Meyer\u{2019}s-Lang, bitte", "anna"),
            "anna Meyer\u{2019}s-Lang"
        );
        assert_eq!(extended("anna Meyer'd'Arc", "anna"), "anna Meyer'd'Arc");
        for text in [
            "anna don't know",
            "Anna isn't here",
            "Anna Don’t",
            "anna can'T",
        ] {
            let first = text.split(' ').next().unwrap();
            let got = extended(text, first);
            assert!(!got.contains(['\'', '\u{2019}']), "{text}: {got}");
        }
    }

    #[test]
    fn a_hyphen_never_glues_a_following_word() {
        // extended whole or not at all, never partly (ruling L43 iii): a
        // trailing or line-break hyphen leaves the span as it was, and a
        // dash used as punctuation ends the surname
        assert_eq!(extended("lukas müller-\nlang", "lukas"), "lukas");
        assert_eq!(extended("lukas müller- lang", "lukas"), "lukas");
        assert_eq!(extended("lukas müller-lang-", "lukas"), "lukas");
        assert_eq!(extended("lukas müller - lang", "lukas"), "lukas müller");
        assert_eq!(extended("lukas - müller", "lukas"), "lukas");
        assert_eq!(extended("lukas müller--lang", "lukas"), "lukas");
        // a joined word counts only when one of its parts does (ruling L45)
        assert_eq!(extended("lukas Support-Team", "lukas"), "lukas");
    }

    #[test]
    fn the_rule_stays_narrow() {
        // a common word, a next-line word, a trailing-hyphen or digit word,
        // a span that does not end in a first name
        assert_eq!(extended("Sag lukas bitte", "lukas"), "lukas");
        assert_eq!(extended("lukas\npetrović", "lukas"), "lukas");
        assert_eq!(extended("lukas petrović-", "lukas"), "lukas");
        assert_eq!(extended("lukas p4trović", "lukas"), "lukas");
        assert_eq!(extended("Xqzt petrović", "Xqzt"), "Xqzt");
        assert_eq!(extended("lukas Team", "lukas"), "lukas");
        // a known entity keeps its exact value
        let text = "lukas petrović";
        let s = extend_over_surnames(
            text,
            vec![person(text, "lukas", DetectorId::Dictionary)],
            &[],
            &|_| true,
        );
        assert_eq!(s[0].slice(text), "lukas");
        let with = |other: Span, acted_on: bool| {
            let s = extend_over_surnames(
                text,
                vec![person(text, "lukas", DetectorId::Ner), other],
                &[],
                &|_| acted_on,
            );
            s[0].slice(text).to_string()
        };
        let city = |source| Span {
            kind: EntityKind::City,
            ..person(text, "petrović", source)
        };
        // re-review 2: a PERSON span over the surname, at any score, and a
        // span some profile preserves or drops, do not stop the extension
        let mut weak = person(text, "petrović", DetectorId::Ner);
        weak.confidence = 0.3;
        assert_eq!(with(weak, true), "lukas petrović");
        assert_eq!(with(city(DetectorId::Ner), false), "lukas petrović");
        // a span every profile acts on keeps its own kind, and a span of
        // higher priority would win the overlap: both stop it
        assert_eq!(with(city(DetectorId::Ner), true), "lukas");
        assert_eq!(
            with(person(text, "petrović", DetectorId::Dictionary), false),
            "lukas"
        );
        // a protected token over the word stops it
        let s = extend_over_surnames(
            text,
            vec![person(text, "lukas", DetectorId::Ner)],
            &[Range { start: 6, end: 15 }],
            &|_| true,
        );
        assert_eq!(s[0].slice(text), "lukas");
    }
}
