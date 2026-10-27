//! Plausibility filter for model-found person spans.
//!
//! A token classifier scores some ordinary tokens as `PERSON` at middling
//! confidence: sort keys and tiers in tool results (`asc`, `vip`), mail
//! folder names (`INBOX`), message ids (`mm_9f3a…`), and capitalized
//! business words (`Rechnung`, `Ihnen`). Each one lands in the escalation
//! band and, under a blocking profile, refuses the whole text. A single
//! word that no name could be is not a person; this module says which.
//!
//! The filter is deliberately narrow, because a dropped person span is a
//! possible leak: it only looks at **one-word** spans below
//! [`CONFIDENT`], never at multi-word spans, never at a word the DACH
//! first-name gazetteer knows, and never at anything with digits or
//! punctuation (an identifier may still identify someone).

use crate::detect::anchor::is_sign_off_phrase;
use crate::gazetteer::is_first_name;
use crate::span::{DetectorId, EntityKind, Span};
use crate::stoplist::{is_common_word, is_name_like_word, is_salutation_word};

/// At or above this confidence a model-found one-word person span is kept
/// whatever it looks like.
pub const CONFIDENT: f32 = 0.85;

/// Longest all-lowercase word [`implausible_person`] treats as a value.
const MAX_LOWERCASE_VALUE: usize = 3;

/// Tool-result and mail vocabulary a model tags as a person: sort orders,
/// tiers, states, folder names, subject-line words. Salutations (`Madam`,
/// `Herren`, `Hello`) are not listed: dropping them also stops the
/// escalations that happen to block mails whose real leaks sit elsewhere,
/// and that trade belongs to the mail-corpus gates, not to this filter.
const NOT_A_PERSON: &[&str] = &[
    "asc",
    "desc",
    "vip",
    "re",
    "inbox",
    "rechnung",
    "invoice",
    "ihnen",
    "adressänderung",
    "rückruf",
    "kontoinhaber",
];

/// Ordinary words that are also surnames when capitalized (`Low`, `High`) or
/// that sit next to names in tool results and mail metadata: listed only for
/// the all-lowercase spelling, so `Pending` or `Active` written like a name
/// is still escalated.
///
/// The list is closed and grows only with plain status, field-value, folder
/// and label vocabulary that no first-name gazetteer or stoplist entry
/// shares. When in doubt leave a word out: `read`, `sent` and `normal` are
/// also surnames, so they are not here.
const NOT_A_PERSON_LOWERCASE: &[&str] = &[
    "none",
    "null",
    "true",
    "false",
    "open",
    "done",
    "todo",
    "high",
    "low",
    // states and field values
    "status",
    "pending",
    "active",
    "inactive",
    "closed",
    "draft",
    "drafts",
    "unread",
    "queued",
    "failed",
    "error",
    "enabled",
    "disabled",
    "unknown",
    "default",
    "empty",
    "unset",
    "archived",
    "deleted",
    "resolved",
    "completed",
    // mail folders and labels
    "outbox",
    "trash",
    "spam",
    "junk",
    "starred",
    "flagged",
    "important",
    "archive",
    "folder",
    "label",
    // German equivalents
    "erledigt",
    "gesendet",
    "gelesen",
    "ungelesen",
    "entwurf",
    "entwürfe",
    "aktiv",
    "inaktiv",
    "erfolg",
    "ausstehend",
    "fehlgeschlagen",
    "gelöscht",
    "archiviert",
    "posteingang",
    "papierkorb",
    "ordner",
];

fn is_not_a_person(word: &str) -> bool {
    let w = word.to_lowercase();
    NOT_A_PERSON.contains(&w.as_str()) || (w == word && NOT_A_PERSON_LOWERCASE.contains(&word))
}

/// A machine id such as `mm_feb0f87e1cc53caa`: a short letter prefix, an
/// underscore, and at least eight hex digits. A username like
/// `sarah_leitner85` is not one.
fn is_machine_id(word: &str) -> bool {
    word.split_once('_').is_some_and(|(prefix, rest)| {
        (1..=4).contains(&prefix.len())
            && prefix.chars().all(|c| c.is_ascii_alphabetic())
            && rest.len() >= 8
            && rest.chars().all(|c| c.is_ascii_hexdigit())
    })
}

/// True when `surface`, found by a model at `confidence`, cannot be a person.
pub fn implausible_person(surface: &str, confidence: f32) -> bool {
    let word = surface.trim_matches(|c: char| !c.is_alphanumeric());
    if confidence >= CONFIDENT || word.is_empty() || word.split_whitespace().count() != 1 {
        return false;
    }
    if is_first_name(word) {
        return false;
    }
    if is_machine_id(word) {
        return true;
    }
    // Anything else with digits or punctuation (`V-1234`, `anna.berger`,
    // an address) may be an identifier that still identifies someone, so it
    // is left to the other detectors and the policy.
    if word
        .chars()
        .any(|c| !(c.is_alphabetic() || matches!(c, '-' | '\'' | '’')))
    {
        return false;
    }
    // A very short lowercase word (`vip`, `asc`) is a value. Longer lowercase
    // words stay unless listed: lowercase surnames in informal mail
    // (`illichmann`, `eder`) score no higher than these do, so only length
    // and the non-name list separate them.
    if is_not_a_person(word) {
        return true;
    }
    let letters = || word.chars().filter(|c| c.is_alphabetic());
    // Uncased scripts (CJK, Arabic, Hebrew, Thai) have no lowercase letter, so
    // a short name written in one is never mistaken for a value.
    letters().all(char::is_lowercase)
        && letters().count() >= 1
        && letters().count() <= MAX_LOWERCASE_VALUE
        && !is_common_word(word)
}

/// Remove the model-found person spans in `spans` that [`implausible_person`]
/// rejects. Spans from any other detector, and any other kind, pass through.
pub fn drop_implausible_persons(text: &str, spans: Vec<Span>) -> Vec<Span> {
    spans
        .into_iter()
        .filter(|s| {
            !(s.kind == EntityKind::Person
                && s.source == DetectorId::Ner
                && text
                    .get(s.start..s.end)
                    .is_some_and(|t| implausible_person(t, s.confidence)))
        })
        .collect()
}

/// True when `word` (one word, non-alphanumerics already trimmed) is
/// greeting vocabulary that no name could be: a salutation word (`Hallo`,
/// `Liebes`, `Team`) or a stoplist function or greeting-target word (`und`,
/// `Madam`, `Best`), and neither a common word that is also a name (`Rose`,
/// `May`, `Lang`) nor a gazetteer first name.
fn is_greeting_word(word: &str) -> bool {
    (is_salutation_word(word) || is_common_word(word))
        && !is_name_like_word(word)
        && !is_first_name(word)
}

/// Honorifics and address words that stand before a name (`Herr Lieber`,
/// `Frau Best`, `Firma Best`): a piece holding one is never greeting-only,
/// even when the name after it is a common or salutation word (review I1).
/// `herren` (`Damen und Herren`) is not one.
pub(crate) const HONORIFICS: &[&str] = &[
    "herr", "herrn", "frau", "firma", "familie", "hr", "fr", "mr", "mrs", "ms", "dr", "doktor",
    "doktorin",
];

/// True when `piece` holds no honorific ([`HONORIFICS`]) and is wholly a
/// sign-off phrase (`Viele Grüße`, `Kind
/// regards`; ruling L50), or when every word of it (split on whitespace and
/// `-`, each trimmed of non-alphanumerics) is greeting vocabulary
/// ([`is_greeting_word`]): `Sehr geehrte Damen und Herren`, `Liebes
/// Support-Team`, `Dear Sir or Madam`. A piece with no word at all (`--`)
/// holds nothing that identifies anyone and counts as one too. A single
/// other word (`Hallo Sarah`, `Dear Rose`, `Huber-Team`) makes it false.
pub fn is_greeting_only(piece: &str) -> bool {
    let words = || {
        piece
            .split(|c: char| c.is_whitespace() || c == '-')
            .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
            .filter(|w| !w.is_empty())
    };
    if words().any(|w| HONORIFICS.contains(&w.to_lowercase().as_str())) {
        return false;
    }
    is_sign_off_phrase(piece) || words().all(is_greeting_word)
}

/// True when a whole stored value identifies no one (Task 7d, ruling L56):
/// a `PERSON` or `ORGANIZATION` original that holds at least one
/// alphanumeric character and is, as a whole, [`is_greeting_only`]
/// (`Hello`, `Best`, `Viele Grüße`). The whole value is judged, never a
/// part of it: `Hallo Anna`, `LG Sarah`, and `Dear Mr Smith` hold a name or
/// an honorific and are not. Removed values and other kinds never count.
///
/// Such a value is no leak-check pattern and no proxy closure trigger. It
/// stays a referential-consistency form, because a clear greeting word in
/// a new text draws a verifier NER refusal.
pub fn is_greeting_only_value(kind: &EntityKind, value: &str) -> bool {
    matches!(kind, EntityKind::Person | EntityKind::Organization)
        && value.chars().any(char::is_alphanumeric)
        && is_greeting_only(value)
}

/// Cut model-found `PERSON` and `ORGANIZATION` spans at line breaks and drop
/// the pieces that are only greeting vocabulary (L3 step 2, Task 7 and
/// integrator ruling L48).
///
/// A model often merges a sign-off name with the next line's greeting
/// (`Piotr Mayer\nLiebes Support-Team`), or tags a greeting line on its own
/// (`Sehr geehrte Damen und Herren`). Tokenized whole, the greeting turns into
/// a store value, and every later clear copy of it reads as a leak.
///
/// - A span from [`DetectorId::Ner`] of either kind that contains a line
///   break is cut into its whitespace-trimmed, non-empty line pieces. Each
///   piece keeps every other field of the span (kind, confidence, source,
///   and the [`Span::crossed_line_break`] flag set before this step), so
///   the retry's guard still treats it as part of a multi-line span.
/// - A piece, or a single-line span of two or more whitespace-separated
///   words, is dropped only when [`is_greeting_only`] holds. A single-word
///   single-line span (`Madam`, `Hallo`) is kept and left to policy
///   (ruling L50). Any piece with another word is kept, so a
///   name split over lines (`Maria\nHuber`) stays covered.
/// - Spans of other kinds or from other detectors pass through unchanged.
///
/// The output is sorted by start.
pub fn split_and_drop_greeting_spans(text: &str, spans: Vec<Span>) -> Vec<Span> {
    let mut out = Vec::with_capacity(spans.len());
    for span in spans {
        let surface = match text.get(span.start..span.end) {
            Some(t)
                if span.source == DetectorId::Ner
                    && matches!(span.kind, EntityKind::Person | EntityKind::Organization) =>
            {
                t
            }
            _ => {
                out.push(span);
                continue;
            }
        };
        if !surface.contains(['\n', '\r']) {
            // Ruling L50: a single-word span (`Madam`, `Hallo`) is left to
            // policy; only two or more words are judged here.
            let words = surface
                .split_whitespace()
                .filter(|w| w.chars().any(char::is_alphanumeric))
                .count();
            if words < 2 || !is_greeting_only(surface) {
                out.push(span);
            }
            continue;
        }
        let mut at = span.start;
        for line in surface.split(['\n', '\r']) {
            let piece = line.trim();
            if !piece.is_empty() && !is_greeting_only(piece) {
                let start = at + (line.len() - line.trim_start().len());
                out.push(Span {
                    start,
                    end: start + piece.len(),
                    ..span.clone()
                });
            }
            at += line.len() + 1;
        }
    }
    out.sort_by_key(|s| s.start);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_labels_ids_and_business_words_are_not_people() {
        for w in [
            "vip",
            "asc",
            "desc",
            "low",
            "INBOX",
            "mm_feb0f87e1cc53caa",
            "Re",
            "Ihnen",
        ] {
            assert!(implausible_person(w, 0.6), "{w}");
        }
    }

    /// The listed vocabulary is ordinary words only: none is a gazetteer first
    /// name or a stoplist (ambiguous-name) entry, and each is all lowercase.
    #[test]
    fn listed_vocabulary_never_overlaps_names() {
        // `done` predates this check and is a gazetteer entry, so
        // `implausible_person` already keeps it (the name test runs first).
        let legacy = ["done"];
        for w in NOT_A_PERSON.iter().chain(NOT_A_PERSON_LOWERCASE) {
            assert_eq!(*w, w.to_lowercase(), "{w}");
            assert!(
                legacy.contains(w) || !is_first_name(w),
                "{w} is a first name"
            );
        }
        for w in NOT_A_PERSON_LOWERCASE {
            assert!(!is_common_word(w), "{w} is in the stoplist");
        }
    }

    /// The extended words drop only as lowercase low-confidence values; a
    /// name-shaped spelling or a confident span is kept.
    #[test]
    fn tool_result_words_drop_only_when_lowercase_and_unsure() {
        for w in [
            "status",
            "pending",
            "inactive",
            "unread",
            "gesendet",
            "papierkorb",
        ] {
            assert!(implausible_person(w, 0.6), "{w}");
            assert!(!implausible_person(w, 0.9), "{w} confident");
            let capitalised = format!("{}{}", w[..1].to_uppercase(), &w[1..]);
            assert!(!implausible_person(&capitalised, 0.6), "{capitalised}");
        }
        // not widened: an unlisted lowercase word of four or more letters stays
        assert!(!implausible_person("wagner", 0.6));
    }

    /// Recall guard: names, and anything the model is sure about, survive.
    #[test]
    fn names_and_confident_spans_are_kept() {
        for (w, c) in [
            ("Leitner", 0.55),
            ("Sarah", 0.55),
            ("sarah", 0.55),
            ("O'Brien", 0.55),
            ("Leitner,", 0.55),
            ("Hans-Peter", 0.55),
            ("Sarah Leitner", 0.55),
            ("vip", 0.9),
            ("illichmann", 0.5),
            ("eder", 0.5),
            ("Grace", 0.55),
            ("May", 0.55),
            ("may", 0.55),
            ("李明", 0.55),
            ("王伟", 0.55),
            ("김민준", 0.55),
            ("علي", 0.55),
            ("Low", 0.55),
            ("anna_meier_85", 0.55),
            ("محمد", 0.55),
            ("Madam", 0.55),
            ("V-97009082", 0.6),
            ("yasmin.neumann", 0.6),
            ("anna_meier", 0.6),
            ("sarah_leitner85", 0.6),
        ] {
            assert!(!implausible_person(w, c), "{w} {c}");
        }
    }

    fn ner(text: &str, needle: &str, kind: EntityKind) -> Span {
        let start = text.find(needle).unwrap();
        Span::new(start, start + needle.len(), kind, 0.7, DetectorId::Ner)
    }

    fn slices<'a>(text: &'a str, spans: &[Span]) -> Vec<&'a str> {
        spans.iter().map(|s| s.slice(text)).collect()
    }

    /// Review Focus 5.
    #[test]
    fn person_spans_are_cut_at_line_breaks_and_greeting_pieces_dropped() {
        let text = "LG\nPiotr Mayer\nLiebes Support-Team,\n";
        let s = ner(text, "Piotr Mayer\nLiebes Support-Team", EntityKind::Person);
        let out = split_and_drop_greeting_spans(text, vec![s]);
        assert_eq!(slices(text, &out), vec!["Piotr Mayer"]);
        let text = "Maria\nHuber";
        let out = split_and_drop_greeting_spans(text, vec![ner(text, text, EntityKind::Person)]);
        assert_eq!(
            slices(text, &out),
            vec!["Maria", "Huber"],
            "a real name split across lines stays covered"
        );
        let text = "Thanks\nRose";
        let out = split_and_drop_greeting_spans(text, vec![ner(text, text, EntityKind::Person)]);
        assert_eq!(
            slices(text, &out),
            vec!["Rose"],
            "a name-like word is never dropped"
        );
    }

    /// Ruling L50: a line piece that is wholly a sign-off phrase (`Viele
    /// Grüße`, `Kind regards`, `Mit freundlichen Grüßen`) is dropped, though
    /// some of its words (`Viele`, `Kind`) are in no greeting list; the name
    /// piece stays.
    #[test]
    fn sign_off_phrase_pieces_are_dropped() {
        for (text, span, name) in [
            (
                "Danke.\nViele Grüße\nAnna Berger",
                "Viele Grüße\nAnna Berger",
                "Anna Berger",
            ),
            ("Ok.\nKind regards\nRose", "Kind regards\nRose", "Rose"),
            (
                "Ok.\nMit freundlichen Grüßen\nAnna",
                "Mit freundlichen Grüßen\nAnna",
                "Anna",
            ),
            ("Ok.\nviele gruesse,\nanna", "viele gruesse,\nanna", "anna"),
        ] {
            let out =
                split_and_drop_greeting_spans(text, vec![ner(text, span, EntityKind::Person)]);
            assert_eq!(slices(text, &out), vec![name], "{span:?}");
        }
    }

    /// Integrator L48: model ORGANIZATION spans are cut the same way, and
    /// each piece keeps the kind the model gave, its confidence, source and
    /// line-break flag (ruling L37).
    #[test]
    fn organization_spans_are_cut_and_pieces_keep_their_fields() {
        let text = "Grüße\nMaria\nLiebes Support-Team,\nwir";
        let s = ner(text, "Maria\nLiebes Support-Team", EntityKind::Organization);
        let out = split_and_drop_greeting_spans(text, vec![s]);
        assert_eq!(slices(text, &out), vec!["Maria"]);
        assert_eq!(out[0].kind, EntityKind::Organization);
        assert_eq!(out[0].confidence, 0.7);
        assert_eq!(out[0].source, DetectorId::Ner);
        // a flagged PERSON span: every piece keeps the flag
        let text = "anna\n\n--\r\n  anna Ng ";
        let s = Span {
            crossed_line_break: true,
            ..ner(text, "anna\n\n--\r\n  anna Ng", EntityKind::Person)
        };
        let out = split_and_drop_greeting_spans(text, vec![s]);
        assert_eq!(slices(text, &out), vec!["anna", "anna Ng"]);
        assert!(
            out.iter()
                .all(|s| s.crossed_line_break && s.confidence == 0.7)
        );
    }

    /// Integrator L48 narrowed by L50: a single-line model PERSON or
    /// ORGANIZATION span of two or more words made only of greeting words, or
    /// wholly a sign-off phrase, is dropped; any other word keeps the span
    /// whole, and a single-word span (`Madam`, `Hallo`) is left to policy.
    #[test]
    fn single_line_greeting_spans_are_dropped_and_names_kept_whole() {
        for (t, kind) in [
            ("Sehr geehrte Damen und Herren", EntityKind::Person),
            ("Dear support team", EntityKind::Organization),
            ("Dear Sir or Madam", EntityKind::Person),
            ("Viele Grüße", EntityKind::Person),
            ("Mit  freundlichen Grüßen,", EntityKind::Person),
        ] {
            let out = split_and_drop_greeting_spans(t, vec![ner(t, t, kind)]);
            assert!(out.is_empty(), "{t}");
        }
        for t in [
            "Madam",
            "Hallo",
            "Best",
            "Dear Rose",
            "Hallo Sarah",
            "Liebes Huber-Team",
            "Herr Gruber",
        ] {
            let out = split_and_drop_greeting_spans(t, vec![ner(t, t, EntityKind::Person)]);
            assert_eq!(slices(t, &out), vec![t], "{t}");
        }
    }

    /// Review I1: an honorific (`Herr`, `Frau`, `Firma`, …) in front of a
    /// surname that is also a greeting or common word (`Lieber`, `Best`,
    /// `Ober`) keeps the span, single-line and as a piece.
    #[test]
    fn honorific_spans_are_never_greeting_only() {
        for (t, kind) in [
            ("Herr Lieber", EntityKind::Person),
            ("Frau Best", EntityKind::Person),
            ("Sehr geehrter Herr Ober", EntityKind::Person),
            ("Firma Best", EntityKind::Organization),
            ("Hr. Lieber", EntityKind::Person),
            ("Doktor Lieber", EntityKind::Person),
            ("Sehr geehrte Frau Doktorin Lieber", EntityKind::Person),
        ] {
            let out = split_and_drop_greeting_spans(t, vec![ner(t, t, kind)]);
            assert_eq!(slices(t, &out), vec![t], "{t}");
        }
        for (text, span, kept) in [
            (
                "Ok.\nHerr Lieber\nLiebes Support-Team,",
                "Herr Lieber\nLiebes Support-Team",
                "Herr Lieber",
            ),
            ("Ok.\nDanke\nFrau Best\n", "Danke\nFrau Best", "Frau Best"),
        ] {
            let out =
                split_and_drop_greeting_spans(text, vec![ner(text, span, EntityKind::Person)]);
            assert_eq!(slices(text, &out), vec![kept], "{span:?}");
        }
    }

    /// Other detectors and other kinds pass through untouched, and the
    /// output is sorted by start.
    #[test]
    fn only_model_person_and_organization_spans_are_split() {
        let text = "Hallo\nWien Graz";
        let whole = |kind, source| Span::new(0, text.len(), kind, 0.7, source);
        let out = split_and_drop_greeting_spans(
            text,
            vec![
                Span::new(11, 15, EntityKind::City, 0.7, DetectorId::Ner),
                whole(EntityKind::Person, DetectorId::Dictionary),
                whole(EntityKind::City, DetectorId::Ner),
                whole(EntityKind::Person, DetectorId::Ner),
            ],
        );
        assert_eq!(
            slices(text, &out),
            vec![text, text, "Wien Graz", "Graz"],
            "non-model and non-person spans unchanged, the model PERSON cut"
        );
    }

    #[test]
    fn only_model_person_spans_are_filtered() {
        let text = "vip vip vip";
        let ner = |kind, source| Span::new(0, 3, kind, 0.6, source);
        let out = drop_implausible_persons(
            text,
            vec![
                ner(EntityKind::Person, DetectorId::Ner),
                ner(EntityKind::Person, DetectorId::Dictionary),
                ner(EntityKind::City, DetectorId::Ner),
            ],
        );
        assert_eq!(out.len(), 2);
        assert!(
            out.iter()
                .all(|s| s.source != DetectorId::Ner || s.kind != EntityKind::Person)
        );
    }

    /// Task 7d: a whole stored value that is only greeting vocabulary
    /// identifies no one; a greeting next to any name part, an honorific,
    /// a value without a word, or a removed-style kind does not count.
    #[test]
    fn greeting_only_values_are_whole_greetings_of_person_or_org_kind() {
        for v in [
            "Hello",
            "Hallo",
            "Best",
            "Viele Grüße",
            "Sehr geehrte Damen und Herren",
        ] {
            assert!(
                is_greeting_only_value(&EntityKind::Person, v),
                "{}",
                v.len()
            );
        }
        assert!(is_greeting_only_value(&EntityKind::Organization, "Hallo"));
        for v in [
            "Hallo Anna",
            "LG Sarah",
            "Dear Mr Smith",
            "Herr Lieber",
            "Anna",
            "--",
            "",
        ] {
            assert!(
                !is_greeting_only(v) || v.trim_matches('-').is_empty(),
                "{}",
                v.len()
            );
            assert!(
                !is_greeting_only_value(&EntityKind::Person, v),
                "{}",
                v.len()
            );
        }
        assert!(!is_greeting_only_value(
            &EntityKind::custom("SECRET"),
            "Hallo"
        ));
        assert!(!is_greeting_only_value(&EntityKind::City, "Hallo"));
    }
}
