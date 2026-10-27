//! Per-workflow policy: which entity kinds get which action at which confidence.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::lang::Language;
use crate::span::{EntityKind, Span};

/// What the sanitizer does with a detected span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Replace with an opaque token and remember the mapping.
    Tokenize,
    /// Leave the text unchanged.
    Preserve,
    /// Replace with a `_REMOVED` marker; never rehydrate.
    Remove,
    /// Refuse to send anything.
    Block,
    /// Leave unchanged but flag for the verifier policy.
    Escalate,
}

/// Action and threshold for one entity kind.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
pub struct EntityPolicy {
    /// Action when confidence is at or above `min_confidence`.
    pub action: Action,
    /// Minimum confidence for `action` to apply.
    pub min_confidence: f32,
}

/// What to do when the verifier returns `Uncertain`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OnUncertain {
    /// Refuse to send.
    Block,
    /// Send, flagged.
    Escalate,
    /// Send, flagged.
    Pass,
    /// Tokenize spans the policy escalates (L70); a verifier Uncertain or Fail still refuses.
    /// Only kinds the profile tokenizes or preserves: a `remove` kind's band
    /// span is removed, a `block` kind's still refuses (L3-13).
    Tokenize,
}

/// Verifier behaviour for a profile.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct VerifierSettings {
    /// Behaviour on `Uncertain`.
    pub on_uncertain: OnUncertain,
    /// Profile used for the single retry after `Fail`.
    pub retry_profile: Option<String>,
    /// Allow running without an NER re-scan. Must be explicit.
    pub allow_no_ner: bool,
    /// Distinct preserved kinds in one sentence that trigger `Uncertain`.
    pub combination_threshold: usize,
}

impl Default for VerifierSettings {
    fn default() -> Self {
        VerifierSettings {
            on_uncertain: OnUncertain::Block,
            retry_profile: None,
            allow_no_ner: false,
            combination_threshold: 3,
        }
    }
}

/// A resolved policy profile.
#[derive(Debug, Clone)]
pub struct Profile {
    /// Profile name from configuration.
    pub name: String,
    /// Forced language, or `None` for auto.
    pub language: Option<Language>,
    /// Per-kind policies keyed by [`EntityKind::label`].
    pub entities: HashMap<String, EntityPolicy>,
    /// Policy for kinds not listed in `entities`.
    pub default: EntityPolicy,
    /// Below this confidence a span is dropped; between this and `min_confidence` it escalates.
    pub escalate_below: f32,
    /// Verifier behaviour.
    pub verifier: VerifierSettings,
    /// NER section used for detection, if any.
    pub ner_sanitizer: Option<String>,
    /// NER section used by the verifier, if any.
    pub ner_verifier: Option<String>,
}

/// True for a value that reads as an identifier rather than a name: no
/// whitespace and at least five digits (`K-482913`, `V-12345678`).
/// `ISO-9001` and `Muster GmbH` are not.
pub fn identifier_shaped(text: &str) -> bool {
    !text.chars().any(char::is_whitespace) && text.chars().filter(char::is_ascii_digit).count() >= 5
}

/// A span paired with the action policy chose for it.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    /// The span.
    pub span: Span,
    /// The action.
    pub action: Action,
}

impl Profile {
    /// Policy for a kind, falling back to the default.
    pub fn policy_for(&self, kind: &EntityKind) -> EntityPolicy {
        self.entities
            .get(kind.label())
            .copied()
            .unwrap_or(self.default)
    }

    /// The action this profile takes on `span`, or `None` when the span is
    /// below `escalate_below` and dropped.
    pub fn action_for(&self, span: &Span) -> Option<Action> {
        let p = self.policy_for(&span.kind);
        if span.confidence >= p.min_confidence {
            Some(p.action)
        } else if span.confidence >= self.escalate_below {
            Some(Action::Escalate)
        } else {
            None
        }
    }

    /// Map resolved spans to decisions. Input must be non-overlapping and sorted.
    pub fn apply(&self, spans: Vec<Span>) -> Vec<Decision> {
        spans
            .into_iter()
            .filter_map(|span| {
                let action = self.action_for(&span)?;
                Some(Decision { span, action })
            })
            .collect()
    }

    /// [`Profile::apply`], plus: an ORGANIZATION span whose text is
    /// identifier-shaped (see [`identifier_shaped`]) is tokenized wherever
    /// the profile would preserve, escalate, or drop it. Models mislabel
    /// short ID values (`K-482913`) as organizations, and a preserved
    /// organization name is harmless but a preserved identifier is a leak.
    /// `Block` and `Remove` are kept; the kind stays ORGANIZATION.
    /// `text` is the text the span offsets refer to.
    pub fn apply_to_text(&self, text: &str, spans: Vec<Span>) -> Vec<Decision> {
        spans
            .into_iter()
            .filter_map(|span| {
                let action = match self.action_for(&span) {
                    Some(a @ (Action::Tokenize | Action::Remove | Action::Block)) => a,
                    other => {
                        if span.kind == EntityKind::Organization
                            && identifier_shaped(span.slice(text))
                        {
                            Action::Tokenize
                        } else {
                            other?
                        }
                    }
                };
                Some(Decision { span, action })
            })
            .collect()
    }
}

/// Retry guard (L3 step 2, integrator rulings b, L41, L44): in a retry
/// pass, a PERSON span the primary profile was uncertain about (below the
/// primary's PERSON `min_confidence`) that crossed a line break keeps the
/// action the retry used to give it, `Escalate`, instead of the retry's
/// `Tokenize`, **when a name candidate abuts it** (see [`adjacent_words`],
/// [`is_name_candidate`]). A multi-line uncertain span is the model's guess
/// at a signature block; a name-like word right next to it (a surname on
/// the next line, `anna\nNg`) is what it may have missed, and would cross
/// in clear. With no such neighbour the span is tokenized whole, store
/// copies inside it included. Under `on_uncertain = "block"` an escalation
/// refuses the text (the caller applies the guard there in the retry only);
/// under `on_uncertain = "tokenize"` the caller applies it in every pass
/// (L70), and an escalation it leaves refuses there too.
///
/// "Crossed a line break" is the span's [`Span::crossed_line_break`] flag,
/// set in detection before any split, or a line break in its text. A
/// `Tokenize` or a `Remove` decision is changed (L106: a retry profile that
/// removes PERSON would otherwise remove the span alone and forward the
/// missed surname in clear); `Block` stays. `text` is the
/// text the span offsets refer to; `primary` is the profile whose
/// verifier failure triggered the retry.
pub fn escalate_uncertain_multiline_persons(
    text: &str,
    decisions: &mut [Decision],
    primary: &Profile,
) {
    let floor = primary.policy_for(&EntityKind::Person).min_confidence;
    let guarded: Vec<usize> = decisions
        .iter()
        .enumerate()
        .filter(|(_, d)| {
            // L106: a removed span is guarded like a tokenized one.
            matches!(d.action, Action::Tokenize | Action::Remove)
                && d.span.kind == EntityKind::Person
                && d.span.confidence < floor
                && (d.span.crossed_line_break
                    || text
                        .get(d.span.start..d.span.end)
                        .is_some_and(|t| t.contains(['\n', '\r'])))
        })
        .map(|(i, _)| i)
        .collect();
    let escalate: Vec<usize> = guarded
        .into_iter()
        .filter(|&i| {
            let span = &decisions[i].span;
            adjacent_words(text, span.start, span.end)
                .into_iter()
                .any(|w| {
                    is_name_candidate(&text[w.clone()])
                        && !is_signature_label(text, w.clone())
                        && !decisions.iter().enumerate().any(|(j, d)| {
                            j != i
                                && matches!(d.action, Action::Tokenize | Action::Remove)
                                && d.span.start <= w.start
                                && w.end <= d.span.end
                        })
                })
        })
        .collect();
    for i in escalate {
        decisions[i].action = Action::Escalate;
    }
}

/// A word that could be a name part next to a guarded span: letters, with
/// internal hyphens (`müller-lang`), and not a common word, a salutation
/// word, or a sign-off abbreviation (`LG`, ruling L44 a). Short surnames
/// (`Ng`, `Wu`) and surnames that are also ordinary words
/// (`is_name_like_word`: `Smith`, `Lang`) count. A hyphenated word counts only when one of its parts
/// does (ruling L45): `müller-lang` is a candidate, `Support-Team` is not.
fn is_name_candidate(word: &str) -> bool {
    // A common word that is also a plausible name (`Smith`, `Lang`) still
    // counts (re-review 3 I1), as in the anchor detector.
    let one = |w: &str| {
        !w.is_empty()
            && (!crate::stoplist::is_common_word(w) || crate::stoplist::is_name_like_word(w))
            && !crate::stoplist::is_salutation_word(w)
            && !crate::stoplist::is_sign_off_abbreviation(w)
    };
    one(word) && word.split('-').any(one)
}

/// True when the word at `w` is a signature label used as one (ruling
/// L51): it is a contact-field label (the shared list,
/// [`crate::stoplist::is_contact_field_label`]) and is followed by `.` or
/// `:`, or by spaces and a phone number (a digit, `+`, `(`), an email address, or a
/// web address (`tel. +43 …`, `E-Mail: …`, `Handy 0664 …`,
/// `email office@…`, `www.example.at`). A label word standing alone, as a
/// surname would (`Handy`), stays a name candidate.
fn is_signature_label(text: &str, w: std::ops::Range<usize>) -> bool {
    if !crate::stoplist::is_contact_field_label(&text[w.clone()]) {
        return false;
    }
    let rest = &text[w.end..];
    if rest.starts_with(['.', ':']) {
        return true;
    }
    if !rest.starts_with([' ', '\t']) {
        return false;
    }
    let value = rest.trim_start_matches([' ', '\t']);
    let token = value.split_whitespace().next().unwrap_or("").to_lowercase();
    value
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_digit() || c == '+' || c == '(')
        || token.contains('@')
        || token.starts_with("www.")
        || token.starts_with("http")
}

fn is_line_break(c: char) -> bool {
    c == '\n' || c == '\r'
}

/// The letters-and-internal-hyphens word starting at byte `at`, if a
/// letter starts there.
fn word_from(text: &str, at: usize) -> Option<std::ops::Range<usize>> {
    let rest = text.get(at..)?;
    if !rest.chars().next().is_some_and(char::is_alphabetic) {
        return None;
    }
    let mut end = at;
    let mut chars = rest.char_indices().peekable();
    while let Some((k, c)) = chars.next() {
        if c.is_alphabetic() {
            end = at + k + c.len_utf8();
        } else if c == '-' && chars.peek().is_some_and(|(_, n)| n.is_alphabetic()) {
            continue;
        } else {
            break;
        }
    }
    Some(at..end)
}

/// The letters-and-internal-hyphens word ending at byte `end`, if a letter
/// ends there.
fn word_to(text: &str, end: usize) -> Option<std::ops::Range<usize>> {
    let head = text.get(..end)?;
    if !head.chars().next_back().is_some_and(char::is_alphabetic) {
        return None;
    }
    let mut start = end;
    let mut chars = head.char_indices().rev().peekable();
    while let Some((k, c)) = chars.next() {
        if c.is_alphabetic() {
            start = k;
        } else if c == '-' && chars.peek().is_some_and(|(_, p)| p.is_alphabetic()) {
            continue;
        } else {
            break;
        }
    }
    Some(start..end)
}

/// The words that abut the span `start..end` (ruling L41, L44 c):
/// - after: the word right after it on its last line (spaces and tabs
///   between); when only whitespace follows it to the line end, the first
///   word of the next non-empty line; a trailing `-` (hyphenated
///   continuation) keeps adjacency across it. Any other character
///   (terminal punctuation) ends the name: no word after.
/// - before: the mirror image on its first line and the previous non-empty
///   line.
fn adjacent_words(text: &str, start: usize, end: usize) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    // after
    let mut k = end;
    let skip_blank = |k: &mut usize| {
        while let Some(c) = text[*k..].chars().next() {
            if c == ' ' || c == '\t' {
                *k += 1;
            } else {
                break;
            }
        }
    };
    skip_blank(&mut k);
    if text[k..].starts_with('-') {
        k += 1;
        skip_blank(&mut k);
    }
    match text[k..].chars().next() {
        Some(c) if c.is_alphabetic() => out.extend(word_from(text, k)),
        Some(c) if is_line_break(c) => {
            // the first word of the next non-empty line
            let next = text[k..]
                .split(['\n', '\r'])
                .scan(k, |pos, line| {
                    let at = *pos;
                    *pos += line.len() + 1;
                    Some((at, line))
                })
                .skip(1)
                .find(|(_, line)| !line.trim().is_empty());
            if let Some((at, line)) = next {
                let lead = line.len() - line.trim_start_matches([' ', '\t']).len();
                out.extend(word_from(text, at + lead));
            }
        }
        _ => {}
    }
    // before
    let mut k = start;
    let back_blank = |k: &mut usize| {
        while let Some(c) = text[..*k].chars().next_back() {
            if c == ' ' || c == '\t' {
                *k -= 1;
            } else {
                break;
            }
        }
    };
    back_blank(&mut k);
    if text[..k].ends_with('-') {
        k -= 1;
        back_blank(&mut k);
    }
    match text[..k].chars().next_back() {
        Some(c) if c.is_alphabetic() => out.extend(word_to(text, k)),
        Some(c) if is_line_break(c) => {
            // the last word of the previous non-empty line
            let head = &text[..k];
            let prev = head
                .rsplit(['\n', '\r'])
                .scan(k, |pos, line| {
                    let at = *pos - line.len();
                    *pos = at.saturating_sub(1);
                    Some((at, line))
                })
                .skip(1)
                .find(|(_, line)| !line.trim().is_empty());
            if let Some((at, line)) = prev {
                let mut e = at + line.trim_end_matches([' ', '\t']).len();
                if text[..e].ends_with('-') {
                    e -= 1;
                    let mut b = e;
                    back_blank(&mut b);
                    e = b;
                }
                out.extend(word_to(text, e));
            }
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::span::{DetectorId as D, EntityKind as K, Span};
    use std::collections::HashMap;

    fn profile() -> Profile {
        let mut entities = HashMap::new();
        entities.insert(
            "PERSON".into(),
            EntityPolicy {
                action: Action::Tokenize,
                min_confidence: 0.6,
            },
        );
        entities.insert(
            "CITY".into(),
            EntityPolicy {
                action: Action::Preserve,
                min_confidence: 0.0,
            },
        );
        entities.insert(
            "SECRET".into(),
            EntityPolicy {
                action: Action::Remove,
                min_confidence: 0.0,
            },
        );
        Profile {
            name: "t".into(),
            language: None,
            entities,
            default: EntityPolicy {
                action: Action::Tokenize,
                min_confidence: 0.5,
            },
            escalate_below: 0.4,
            verifier: VerifierSettings::default(),
            ner_sanitizer: None,
            ner_verifier: None,
        }
    }

    /// A model-labelled ORGANIZATION that is really an identifier is
    /// tokenized even where organizations are preserved; names stay.
    /// Ruling (b) with L41/L44: only an uncertain (below the primary's
    /// 0.6) PERSON `Tokenize` that crossed a line break **and** has a name
    /// candidate next to it is escalated. A piece cut from such a span
    /// (Task 7's split) counts through its flag even though its own text
    /// holds no line break.
    #[test]
    fn retry_guard_escalates_only_uncertain_multiline_persons_with_a_neighbour() {
        // "anna\n\n--\nanna" is 0..13; " Ng" follows on the same line.
        let text = "anna\n\n--\nanna Ng\nRosenweg 1";
        let primary = profile();
        let dec = |start, end, kind, conf, action, flag| Decision {
            span: Span {
                crossed_line_break: flag,
                ..Span::new(start, end, kind, conf, D::Ner)
            },
            action,
        };
        let run = |mut ds: Vec<Decision>| {
            escalate_uncertain_multiline_persons(text, &mut ds, &primary);
            ds.iter().map(|d| d.action).collect::<Vec<_>>()
        };
        use Action::{Block, Escalate, Tokenize};
        // multi-line, uncertain, `Ng` after it: escalated
        assert_eq!(
            run(vec![dec(0, 13, K::Person, 0.55, Tokenize, false)]),
            [Escalate]
        );
        // a split piece (no line break in its own text) through its flag
        assert_eq!(
            run(vec![dec(9, 13, K::Person, 0.55, Tokenize, true)]),
            [Escalate]
        );
        // the neighbour inside another tokenized span is not a candidate
        assert_eq!(
            run(vec![
                dec(0, 13, K::Person, 0.55, Tokenize, false),
                dec(14, 16, K::Person, 0.9, Tokenize, false),
            ]),
            [Tokenize, Tokenize]
        );
        // one line, confident, stronger action, other kind: untouched
        assert_eq!(
            run(vec![dec(9, 13, K::Person, 0.55, Tokenize, false)]),
            [Tokenize]
        );
        assert_eq!(
            run(vec![dec(0, 13, K::Person, 0.70, Tokenize, false)]),
            [Tokenize]
        );
        assert_eq!(
            run(vec![dec(0, 13, K::Person, 0.55, Block, false)]),
            [Block]
        );
        // L106: a removed span (a retry that removes PERSON) is guarded too
        assert_eq!(
            run(vec![dec(0, 13, K::Person, 0.55, Action::Remove, false)]),
            [Escalate]
        );
        assert_eq!(
            run(vec![dec(0, 13, K::StreetAddress, 0.55, Tokenize, false)]),
            [Tokenize]
        );
    }

    /// L51: a signature label on the next line (`tel. +43 …`, `E-Mail:`,
    /// `www.…`) is not a name candidate, so a guarded company-line piece
    /// before it is tokenized; a bare surname there (`Ng`) still escalates,
    /// and so does a label word written as a name (`Handy` alone).
    #[test]
    fn retry_guard_skips_signature_labels_on_the_next_line() {
        let primary = profile();
        let run = |text: &str, piece: &str| {
            let s = text.find(piece).unwrap();
            // The name line above is its own, confident, tokenized span.
            let mut ds = vec![
                Decision {
                    span: Span {
                        crossed_line_break: true,
                        ..Span::new(s, s + piece.len(), K::Person, 0.51, D::Ner)
                    },
                    action: Action::Tokenize,
                },
                Decision {
                    span: Span::new(0, "anna berger".len(), K::Person, 0.9, D::Ner),
                    action: Action::Tokenize,
                },
            ];
            escalate_uncertain_multiline_persons(text, &mut ds, &primary);
            ds[0].action
        };
        let piece = "huber bau gmbh";
        for next in [
            "tel. +43 1 234 56 78",
            "Tel: 01 234 56 78",
            "Telefon 01 234 56 78",
            "fax +43 1 234 56 79",
            "Mobil: +43 664 123 45 67",
            "Handy 0664 123 45 67",
            "E-Mail: office@example.at",
            "email office@example.at",
            "Web: www.example.at",
            "www.example.at",
            "Adresse: Hauptstraße 5",
            "UID: ATU12345678",
            "UST-ID: ATU12345678",
            "IBAN: AT61 1904 3002 3457 3201",
            "BIC: BKAUATWW",
        ] {
            let text = format!("anna berger\n{piece}\n{next}");
            assert_eq!(run(&text, piece), Action::Tokenize, "{next:?}");
        }
        // label words standing alone, as a name would, stay candidates
        for next in ["Ng", "Handy", "Ng tel. +43 1 234", "Iban", "Bic"] {
            let text = format!("anna berger\n{piece}\n{next}");
            assert_eq!(run(&text, piece), Action::Escalate, "{next:?}");
        }
    }

    /// L41/L44 adjacency: same-line words, the next/previous non-empty
    /// line across a bare line end, a trailing hyphen keeps adjacency,
    /// terminal punctuation ends it.
    #[test]
    fn adjacent_words_follow_line_ends_and_stop_at_punctuation() {
        let words = |text: &str, span: &str| -> Vec<String> {
            let s = text.find(span).unwrap();
            adjacent_words(text, s, s + span.len())
                .into_iter()
                .map(|r| text[r].to_string())
                .collect()
        };
        assert_eq!(
            words("LG anna\nbea müller-lang!", "anna\nbea"),
            ["müller-lang", "LG"]
        );
        assert_eq!(
            words("Grüße\n\nanna\nbea\n\n  Ng ruft an", "anna\nbea"),
            ["Ng", "Grüße"]
        );
        assert_eq!(
            words("Grüße,\nanna\nbea,\nNg", "anna\nbea"),
            Vec::<String>::new()
        );
        assert_eq!(words("Vor-\nanna\nbea -\nNg", "anna\nbea"), ["Ng", "Vor"]);
        assert_eq!(words("anna\nbea", "anna\nbea"), Vec::<String>::new());
        assert!(!is_name_candidate("LG") && !is_name_candidate("MfG"));
        assert!(!is_name_candidate("Grüße") && !is_name_candidate("we"));
        assert!(is_name_candidate("Ng") && is_name_candidate("müller-lang"));
        // L45: every part a stoplist or salutation word
        assert!(!is_name_candidate("Support-Team") && !is_name_candidate("Kunden-Service"));
        assert!(is_name_candidate("Team-Müller"));
    }

    #[test]
    fn identifier_shaped_organization_is_tokenized_not_preserved() {
        let mut p = profile();
        p.entities.insert(
            "ORGANIZATION".into(),
            EntityPolicy {
                action: Action::Preserve,
                min_confidence: 0.70,
            },
        );
        let text = "Kunde K-482913 bei Muster GmbH, ISO-9001, Ref X-12345.";
        let at = |needle: &str, conf: f32| {
            let i = text.find(needle).unwrap();
            Span::new(i, i + needle.len(), K::Organization, conf, D::Ner)
        };
        let d = p.apply_to_text(
            text,
            vec![
                at("K-482913", 0.80),
                at("Muster GmbH", 0.80),
                at("ISO-9001", 0.80),
                at("X-12345", 0.50),
            ],
        );
        let actions: Vec<Action> = d.iter().map(|x| x.action).collect();
        assert_eq!(
            actions,
            [
                Action::Tokenize,
                Action::Preserve,
                Action::Preserve,
                Action::Tokenize
            ],
            "below min_confidence the ID is still tokenized, not escalated"
        );
        assert!(d.iter().all(|x| x.span.kind == K::Organization));
        // a stronger action is never weakened
        p.entities.insert(
            "ORGANIZATION".into(),
            EntityPolicy {
                action: Action::Block,
                min_confidence: 0.0,
            },
        );
        let d = p.apply_to_text(text, vec![at("K-482913", 0.80)]);
        assert_eq!(d[0].action, Action::Block);
    }

    #[test]
    fn maps_kinds_to_actions() {
        let p = profile();
        let d = p.apply(vec![
            Span::new(0, 1, K::Person, 0.9, D::Ner),
            Span::new(2, 3, K::City, 0.9, D::Ner),
            Span::new(
                4,
                5,
                K::Secret(crate::span::SecretKind::Jwt),
                0.95,
                D::Secrets,
            ),
            Span::new(6, 7, K::Iban, 0.99, D::RegexValidated),
        ]);
        let actions: Vec<Action> = d.iter().map(|x| x.action).collect();
        assert_eq!(
            actions,
            vec![
                Action::Tokenize,
                Action::Preserve,
                Action::Remove,
                Action::Tokenize
            ]
        );
    }

    #[test]
    fn confidence_bands() {
        let p = profile();
        let d = p.apply(vec![
            Span::new(0, 1, K::Person, 0.5, D::Ner), // below 0.6, above 0.4 → Escalate
            Span::new(2, 3, K::Person, 0.3, D::Ner), // below 0.4 → dropped
        ]);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].action, Action::Escalate);
        assert_eq!(
            p.action_for(&Span::new(0, 1, K::Person, 0.5, D::Ner)),
            Some(Action::Escalate)
        );
        assert_eq!(p.action_for(&Span::new(0, 1, K::Person, 0.3, D::Ner)), None);
        assert_eq!(
            p.action_for(&Span::new(0, 1, K::City, 0.3, D::Ner)),
            Some(Action::Preserve)
        );
    }

    #[test]
    fn unknown_kind_uses_default() {
        let p = profile();
        assert_eq!(
            p.policy_for(&K::custom("meter_point")).action,
            Action::Tokenize
        );
    }
}
