//! Greeting, sign-off, and honorific anchors (research §2, recommendation 2):
//! `Hallo X`, `Liebe X`, `LG X`, `Mit freundlichen Grüßen\nX`, `Frau X`,
//! `Sehr geehrte Frau Mag. X`. Deterministic; confidence 0.85 with a
//! gazetteer hit or an honorific, 0.62 for a bare capitalized word after a
//! greeting or sign-off, so policy tokenizes it at PERSON's 0.60 floor.
//!
//! Sign-off phrases include the closings (`Viele Grüße`, `Kind regards`, …),
//! the thanks phrases `Danke im Voraus`, `Vielen Dank`, `Thanks in advance`
//! and `Thank you`, and bare `Grüße`/`Gruß`, each with an optional place tail
//! (`Schöne Grüße aus 5280 Braunau am Inn`). Bare `Danke` is not a phrase: it
//! also opens ordinary sentences. A name on its own line below a sign-off may
//! be a name-like common word (`Rose`, `May`, `Hunter`); a group word
//! (`Team`, `Kundenservice`) or a pronoun (`Ihr Support-Team`) never is.
//!
//! A one-word line one typo away from a single-word sign-off of five or more
//! letters (`Thansk,`, `Regrads,`), or a spelling variant of one (`Grüsse`),
//! anchors the name on the line below it the same way (ruling L49).

use std::sync::LazyLock;

use regex::Regex;

use super::{DetectCtx, Detector};
use crate::gazetteer::is_first_name;
use crate::span::{DetectorId, EntityKind, Span};
use crate::stoplist::{is_common_word, is_name_like_word};

/// A name after a greeting or sign-off when a word of it is in the gazetteer.
pub const ANCHOR_WITH_GAZETTEER: f32 = 0.85;
/// A name after `Frau`, `Herr`, `Ms`, `Mr`, … (with optional titles).
pub const ANCHOR_HONORIFIC: f32 = 0.85;
/// A capitalized word after a greeting or sign-off that the gazetteer does
/// not know: above PERSON's 0.60 policy floor, so it is tokenized, and low
/// enough that a longer NER span wins overlap resolution on equal length.
pub const ANCHOR_ALONE: f32 = 0.62;

/// One or two name words: a letter run that may contain hyphens or
/// apostrophes, optionally followed by a second one on the same line.
const NAME: &str = r"(\p{L}[\p{L}\p{M}'’\-]*(?:[ \t]+\p{L}[\p{L}\p{M}'’\-]*)?)";

fn greeting() -> String {
    format!(
        r"(?m)(?:^|[.!?]\s+)(?:Hallo|Hi|Hey|Servus|Liebe|Lieber|Guten Tag|Guten Morgen|Grüß Gott|Dear|Hello)[ \t]+{NAME}"
    )
}

/// The sign-off phrase alternation, longer phrases before their prefixes.
/// Shared by the sign-off rule and the check that a candidate name line is
/// itself the start of another sign-off.
const SIGN_OFF_PHRASES: &str = r"LG|VG|MfG|GLG|Liebe Grüße|Viele Grüße|Beste Grüße|Schöne Grüße|Herzliche Grüße|Mit freundlichen Grüßen|Mit besten Grüßen|Danke und (?:beste |liebe |viele )?Grüße|Freundliche Grüße|Danke im Voraus|Vielen Dank|Thanks in advance|Thank you|Kind regards|Best regards|Warm regards|Regards|Best|Thanks|Many thanks|Cheers|Yours sincerely|Sincerely|Grüße|Gruß";

fn sign_off() -> String {
    format!(
        r"(?m)(?:^|\n)[ \t]*(?:{SIGN_OFF_PHRASES})\b(?:[ \t]+(?:aus|from)[ \t]+[^\n]{{1,60}})?[,!.]?(?:[ \t]*\n){{0,2}}[ \t]*{NAME}[ \t]*(?:\n|$)"
    )
}

fn honorific() -> String {
    format!(
        r"\b(?:Frau|Herr|Herrn|Fr\.|Hr\.|Ms\.?|Mrs\.?|Mr\.?|Miss)(?:[ \t]+(?:Dr\.|Mag\.|Dipl\.-Ing\.|DI|Ing\.|Prof\.|MSc|BSc|MBA|Dr\.med\.))*[ \t]+{NAME}"
    )
}

struct Rules {
    sign_off_line: Regex,
    name_line: Regex,
    greeting: Regex,
    greeting_ci: Regex,
    sign_off: Regex,
    sign_off_ci: Regex,
    honorific: Regex,
    honorific_ci: Regex,
}

static RULES: LazyLock<Rules> = LazyLock::new(|| {
    let ci = |s: &str| Regex::new(&format!("(?i){s}")).expect("anchor pattern compiles");
    Rules {
        sign_off_line: Regex::new(&format!(r"(?i)^[ \t]*(?:{SIGN_OFF_PHRASES})\b"))
            .expect("anchor pattern compiles"),
        name_line: Regex::new(&format!(r"(?i)^[ \t]*{NAME}[ \t]*$"))
            .expect("anchor pattern compiles"),
        greeting: Regex::new(&greeting()).expect("anchor pattern compiles"),
        greeting_ci: ci(&greeting()),
        sign_off: Regex::new(&sign_off()).expect("anchor pattern compiles"),
        sign_off_ci: ci(&sign_off()),
        honorific: Regex::new(&honorific()).expect("anchor pattern compiles"),
        honorific_ci: ci(&honorific()),
    }
});

/// Deterministic anchor detector. Stateless; `Debug` prints its name.
#[derive(Default)]
pub struct AnchorDetector;

impl std::fmt::Debug for AnchorDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AnchorDetector")
    }
}

impl AnchorDetector {
    /// Build.
    pub fn new() -> Self {
        AnchorDetector
    }
}

/// Words of a candidate name, in order, with their byte ranges.
fn words(text: &str, start: usize, end: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut cur: Option<usize> = None;
    for (i, c) in text[start..end].char_indices() {
        let at = start + i;
        if c.is_whitespace() {
            if let Some(s) = cur.take() {
                out.push((s, at));
            }
        } else if cur.is_none() {
            cur = Some(at);
        }
    }
    if let Some(s) = cur {
        out.push((s, end));
    }
    out
}

/// Spelled-out titles that may precede a name after an honorific or greeting
/// (`Frau Doktor Berger`, `Herr Professor Müller`): skipped rather than
/// ending the candidate, as long as a name can still follow. Abbreviated
/// titles (`Dr.`, `Mag.`, `Prof.`, `Ing.`, `DI`, `Dipl.-Ing.`, `MSc`, `BSc`,
/// `MBA`) are already consumed by the honorific pattern itself and never
/// reach here.
const SPELLED_OUT_TITLES: &[&str] = &[
    "doktor",
    "doktorin",
    "professor",
    "professorin",
    "magister",
    "magistra",
    "ingenieur",
    "ingenieurin",
    "diplomingenieur",
    "diplomingenieurin",
];

/// Pronouns and possessives that follow a sign-off in a signature block
/// (`Ihr Support-Team`, `Your Team`) and are never a person's name. Private to
/// the sign-off rule: the shared stoplist does not move.
fn not_a_sign_off_name(word: &str) -> bool {
    const WORDS: &[&str] = &[
        "wir", "ihr", "ihre", "ihnen", "uns", "unser", "unsere", "euer", "eure", "dein", "deine",
        "sie", "your", "our",
    ];
    let w = word
        .trim_matches(|c: char| !c.is_alphanumeric())
        .to_lowercase();
    WORDS.contains(&w.as_str())
}

fn is_spelled_out_title(word: &str) -> bool {
    SPELLED_OUT_TITLES.contains(&word.to_lowercase().as_str())
}

/// Trim the candidate to the words that can be a name: every word must
/// start with an uppercase letter (unless the whole text is lower case) and
/// must not be a common word; the candidate is cut at the first word that
/// fails. A spelled-out title is skipped instead of ending the candidate,
/// but only while a word still follows it — a title with nothing after it
/// falls through to the common-word check below and rejects as before, so
/// a title alone (`Frau Doktor hat angerufen`) still yields nothing.
/// Returns the range of the kept words (the title itself is excluded) and
/// whether any of them is in the gazetteer.
///
/// `own_line` (a sign-off name alone on the line below the phrase) lets a
/// name-like common word through; `sign_off` rejects pronouns and possessives
/// (`Ihr Support-Team`), which can follow a sign-off but are never a name.
fn accept(
    text: &str,
    start: usize,
    end: usize,
    relaxed: bool,
    own_line: bool,
    sign_off: bool,
) -> Option<(usize, usize, bool)> {
    let ws = words(text, start, end);
    let mut i = 0;
    while i + 1 < ws.len() && is_spelled_out_title(&text[ws[i].0..ws[i].1]) {
        i += 1;
    }
    let mut kept_start = None;
    let mut kept_end = None;
    let mut gaz = false;
    for (k, &(s, e)) in ws.iter().enumerate().skip(i) {
        let w = &text[s..e];
        let first = w.chars().next()?;
        if sign_off && not_a_sign_off_name(w) {
            // `Deine Anna`, `Eure Lisa`: a leading possessive is skipped like a
            // title, but only when a known first name follows. `Ihr
            // Support-Team` has no such name and ends the candidate.
            let name_follows = kept_start.is_none()
                && ws
                    .get(k + 1)
                    .is_some_and(|&(ns, ne)| is_first_name(&text[ns..ne]));
            if name_follows {
                continue;
            }
            break;
        }
        let common = is_common_word(w) && !(own_line && is_name_like_word(w));
        if !(relaxed || first.is_uppercase()) || common || w.chars().count() < 2 {
            break;
        }
        kept_start.get_or_insert(s);
        gaz |= is_first_name(w);
        kept_end = Some(e);
    }
    Some((kept_start?, kept_end?, gaz))
}

/// The single-word sign-off phrases of at least five letters (`Regards`,
/// `Thanks`, `Cheers`, `Sincerely`, `Grüße`), folded (see [`fold`]): the
/// phrases a one-word line may misspell and still count as a sign-off
/// (ruling L49). Shorter ones (`Best`, `Gruß`, `LG`) are too close to
/// ordinary words to fuzz.
static FUZZY_SIGN_OFFS: LazyLock<Vec<Vec<char>>> = LazyLock::new(|| {
    SIGN_OFF_PHRASES
        .split('|')
        .filter(|p| p.chars().all(char::is_alphabetic) && p.chars().count() >= 5)
        .map(fold)
        .collect()
});

/// [`SIGN_OFF_PHRASES`] as a whole-text match, case-insensitive.
static SIGN_OFF_WHOLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"(?i)^(?:{SIGN_OFF_PHRASES})$")).expect("anchor pattern compiles")
});

/// The plain (regex-free) [`SIGN_OFF_PHRASES`] entries, folded (see
/// [`fold`]), so spelling variants (`Viele Gruesse`, `Grüsse`) match too.
static SIGN_OFF_FOLDED: LazyLock<Vec<Vec<char>>> = LazyLock::new(|| {
    SIGN_OFF_PHRASES
        .split('|')
        .filter(|p| p.chars().all(|c| c.is_alphabetic() || c == ' '))
        .map(fold)
        .collect()
});

/// True when `text`, trimmed of non-alphanumerics at both ends and with
/// whitespace runs normalized to one space, is wholly one sign-off phrase
/// (`Viele Grüße`, `Kind regards`, `Mit freundlichen Grüßen`), compared
/// case-insensitively and also after [`fold`] (ruling L50).
pub(crate) fn is_sign_off_phrase(text: &str) -> bool {
    let t = text
        .trim_matches(|c: char| !c.is_alphanumeric())
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    !t.is_empty() && (SIGN_OFF_WHOLE.is_match(&t) || SIGN_OFF_FOLDED.contains(&fold(&t)))
}

/// Every single-word sign-off phrase, of any length (`LG`, `Best`, `Gruß`),
/// folded: a one-word line fold-equal to one (`Gruss`) is a sign-off line
/// (review minor; the five-letter floor applies only to typos).
static SINGLE_WORD_SIGN_OFFS: LazyLock<Vec<Vec<char>>> = LazyLock::new(|| {
    SIGN_OFF_PHRASES
        .split('|')
        .filter(|p| p.chars().all(char::is_alphabetic))
        .map(fold)
        .collect()
});

/// Lower case, with `ß` as `ss` and umlauts as `ae`/`oe`/`ue`, so the
/// spelling variants `Grüsse` and `Gruesse` of `Grüße` compare equal.
fn fold(word: &str) -> Vec<char> {
    let mut out = Vec::with_capacity(word.len());
    for c in word.chars().flat_map(char::to_lowercase) {
        match c {
            'ß' => out.extend(['s', 's']),
            'ä' => out.extend(['a', 'e']),
            'ö' => out.extend(['o', 'e']),
            'ü' => out.extend(['u', 'e']),
            c => out.push(c),
        }
    }
    out
}

/// Damerau-Levenshtein distance at most one: equal, or one substitution,
/// insertion, deletion, or swap of two adjacent letters.
fn within_one_edit(a: &[char], b: &[char]) -> bool {
    let (short, long) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    if long.len() - short.len() > 1 {
        return false;
    }
    let p = short.iter().zip(long).take_while(|(x, y)| x == y).count();
    if p == short.len() {
        return true; // equal, or one letter appended
    }
    if short.len() == long.len() {
        // one substitution, or one adjacent swap
        short[p + 1..] == long[p + 1..]
            || (p + 1 < short.len()
                && short[p] == long[p + 1]
                && short[p + 1] == long[p]
                && short[p + 2..] == long[p + 2..])
    } else {
        // one letter inserted into the longer word at `p`
        short[p..] == long[p + 1..]
    }
}

/// True when `word` is one letter run within one edit
/// ([`within_one_edit`]) of a single-word sign-off phrase of at least five
/// letters, after [`fold`] (`Thansk`, `Regrads`, `Grüsse`, `sincerly`), or
/// equal after [`fold`] to a single-word phrase of any length (`Gruss`).
fn is_fuzzy_sign_off(word: &str) -> bool {
    if word.is_empty() || !word.chars().all(char::is_alphabetic) {
        return false;
    }
    let w = fold(word);
    SINGLE_WORD_SIGN_OFFS.contains(&w) || FUZZY_SIGN_OFFS.iter().any(|p| within_one_edit(&w, p))
}

/// Ruling L49: a line holding one word (optionally followed by `,`, `!`, or
/// `.`, as in the exact rule)
/// that [`is_fuzzy_sign_off`] accepts is a sign-off line for the own-line
/// name rule: the next line, or the one after a single blank line, is a
/// name candidate under the same [`accept`] rules as an exact sign-off.
fn fuzzy_sign_off_names(text: &str, relaxed: bool, spans: &mut Vec<Span>) {
    let r = &*RULES;
    let lines: Vec<(usize, &str)> = text
        .split('\n')
        .scan(0usize, |at, line| {
            let start = *at;
            *at += line.len() + 1;
            Some((start, line))
        })
        .collect();
    for (i, &(_, line)) in lines.iter().enumerate() {
        let t = line.trim();
        let word = t.strip_suffix([',', '!', '.']).map_or(t, str::trim_end);
        if !is_fuzzy_sign_off(word) {
            continue;
        }
        // the next line, or the one after a single blank line
        let mut next = lines.get(i + 1);
        if next.is_some_and(|(_, l)| l.trim().is_empty()) {
            next = lines.get(i + 2);
        }
        let Some(&(at, cand)) = next else {
            continue;
        };
        let cand = cand.strip_suffix('\r').unwrap_or(cand);
        if r.sign_off_line.is_match(cand) {
            continue;
        }
        let Some(m) = r.name_line.captures(cand).and_then(|c| c.get(1)) else {
            continue;
        };
        let Some((s, e, gaz)) = accept(text, at + m.start(), at + m.end(), relaxed, true, true)
        else {
            continue;
        };
        if spans.iter().any(|x| x.start < e && s < x.end) {
            continue;
        }
        let confidence = if gaz {
            ANCHOR_WITH_GAZETTEER
        } else {
            ANCHOR_ALONE
        };
        spans.push(Span::new(
            s,
            e,
            EntityKind::Person,
            confidence,
            DetectorId::Anchor,
        ));
    }
}

impl Detector for AnchorDetector {
    fn id(&self) -> DetectorId {
        DetectorId::Anchor
    }

    fn detect(&self, text: &str, _ctx: &DetectCtx) -> crate::Result<Vec<Span>> {
        let relaxed = !text.chars().any(char::is_uppercase);
        let r = &*RULES;
        let sets: [(&Regex, f32); 3] = if relaxed {
            [
                (&r.greeting_ci, ANCHOR_WITH_GAZETTEER),
                (&r.sign_off_ci, ANCHOR_WITH_GAZETTEER),
                (&r.honorific_ci, ANCHOR_HONORIFIC),
            ]
        } else {
            [
                (&r.greeting, ANCHOR_WITH_GAZETTEER),
                (&r.sign_off, ANCHOR_WITH_GAZETTEER),
                (&r.honorific, ANCHOR_HONORIFIC),
            ]
        };
        let mut spans: Vec<Span> = Vec::new();
        for (idx, (re, conf)) in sets.iter().enumerate() {
            let sign_off = idx == 1;
            // `captures_iter` does not overlap, so a skipped sign-off match
            // would swallow the next line's own sign-off. The rules therefore
            // resume explicitly; only the sign-off rule ever skips.
            let mut pos = 0;
            while pos <= text.len() {
                let Some(caps) = re.captures_at(text, pos) else {
                    break;
                };
                let whole = caps.get(0).expect("group 0 always matches");
                let next = whole.end().max(pos + 1);
                let Some(m) = caps.get(1) else {
                    pos = next;
                    continue;
                };
                let line_start = text[..m.start()].rfind('\n').map_or(0, |i| i + 1);
                let own_line = sign_off
                    && line_start > whole.start()
                    && text[line_start..m.start()].trim().is_empty();
                if own_line && r.sign_off_line.is_match(&text[line_start..]) {
                    // The candidate line starts another sign-off: it is not the
                    // name of this one. Rescan from it. `line_start >
                    // whole.start() >= pos`, so this always makes progress.
                    pos = line_start;
                    continue;
                }
                pos = next;
                let Some((s, e, gaz)) =
                    accept(text, m.start(), m.end(), relaxed, own_line, sign_off)
                else {
                    continue;
                };
                let confidence = if idx == 2 || gaz { *conf } else { ANCHOR_ALONE };
                if spans.iter().any(|x| x.start < e && s < x.end) {
                    continue;
                }
                spans.push(Span::new(
                    s,
                    e,
                    EntityKind::Person,
                    confidence,
                    DetectorId::Anchor,
                ));
            }
        }
        fuzzy_sign_off_names(text, relaxed, &mut spans);
        spans.sort_by_key(|s| s.start);
        Ok(spans)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::DetectCtx;
    use crate::span::EntityKind as K;

    fn found(text: &str) -> Vec<(String, f32)> {
        AnchorDetector::new()
            .detect(text, &DetectCtx::for_text(text))
            .unwrap()
            .into_iter()
            .map(|s| {
                assert_eq!(s.kind, K::Person);
                assert_eq!(s.source, DetectorId::Anchor);
                (s.slice(text).to_string(), s.confidence)
            })
            .collect()
    }

    #[test]
    fn greetings_and_sign_offs_yield_the_name() {
        assert_eq!(
            found("Hallo Sarah,\nwie geht es dir?"),
            vec![("Sarah".to_string(), ANCHOR_WITH_GAZETTEER)]
        );
        assert_eq!(
            found("Liebe Ayşe, danke!"),
            vec![("Ayşe".to_string(), ANCHOR_WITH_GAZETTEER)]
        );
        assert_eq!(
            found("Danke.\n\nLG Sarah"),
            vec![("Sarah".to_string(), ANCHOR_WITH_GAZETTEER)]
        );
        assert_eq!(
            found("Mit freundlichen Grüßen\nSarah Leitner"),
            vec![("Sarah Leitner".to_string(), ANCHOR_WITH_GAZETTEER)]
        );
        assert_eq!(
            found("Mit freundlichen Grüßen\n\nSarah Leitner"),
            vec![("Sarah Leitner".to_string(), ANCHOR_WITH_GAZETTEER)],
            "one blank line is allowed"
        );
        assert!(
            found("Mit freundlichen Grüßen\n\n\nSarah Leitner").is_empty(),
            "two blank lines are not"
        );
        assert_eq!(
            found("Kind regards,\nThomas"),
            vec![("Thomas".to_string(), ANCHOR_WITH_GAZETTEER)]
        );
        assert_eq!(
            found("Best,\nZyxwuria"),
            vec![("Zyxwuria".to_string(), ANCHOR_ALONE)],
            "unknown name after a sign-off: low confidence, still a span"
        );
        assert_eq!(
            found("Viele Grüße\nQuolnath Zyxwuria\nExample GmbH"),
            vec![("Quolnath Zyxwuria".to_string(), ANCHOR_ALONE)]
        );
    }

    /// Review Focus 7.
    #[test]
    fn anchors_skip_group_greetings_and_catch_names() {
        for text in [
            "Hallo Team, bitte prüfen.",
            "Sehr geehrte Damen und Herren,",
            "Liebes Support-Team,",
            "Hallo zusammen!",
            "Hallo alle, kurze Frage",
            "Guten Tag, ich habe eine Frage.",
            "Hello, I have a question.",
            "Dear Sir or Madam,",
            "LG und danke",
            "Best regards",
            "Best Wishes",
            "Kind regards\nKundenservice",
            "Cheers Mate",
            "Hallo",
        ] {
            assert!(found(text).is_empty(), "{text}: {:?}", found(text));
        }
        assert_eq!(
            found("Sehr geehrte Frau Mag. Leitner,"),
            vec![("Leitner".to_string(), ANCHOR_HONORIFIC)]
        );
        assert_eq!(
            found("Sehr geehrter Herr Dr. Thomas Berger,"),
            vec![("Thomas Berger".to_string(), ANCHOR_HONORIFIC)]
        );
        assert_eq!(
            found("Bitte an Frau Leitner weiterleiten."),
            vec![("Leitner".to_string(), ANCHOR_HONORIFIC)]
        );
        assert_eq!(
            found("Our contact is Ms Auer."),
            vec![("Auer".to_string(), ANCHOR_HONORIFIC)]
        );
        assert_eq!(
            found("Mr Okonkwo asked me to forward this."),
            vec![("Okonkwo".to_string(), ANCHOR_HONORIFIC)]
        );
        assert!(found("Frau Doktor hat angerufen").is_empty(), "stoplisted");
        assert!(found("Herr Ober, zahlen bitte").is_empty(), "stoplisted");
    }

    /// Fix round 1: a spelled-out title before the surname must be skipped,
    /// not treated as ending the candidate (which previously dropped the
    /// whole match, losing the name — the dangerous false-negative failure
    /// mode).
    #[test]
    fn spelled_out_titles_are_skipped_but_a_bare_title_still_yields_nothing() {
        assert_eq!(
            found("Sehr geehrte Frau Doktor Berger,"),
            vec![("Berger".to_string(), ANCHOR_HONORIFIC)]
        );
        assert_eq!(
            found("Herr Doktor Huber"),
            vec![("Huber".to_string(), ANCHOR_HONORIFIC)]
        );
        assert_eq!(
            found("Herr Professor Müller"),
            vec![("Müller".to_string(), ANCHOR_HONORIFIC)]
        );
        assert!(
            found("Frau Doktor hat angerufen").is_empty(),
            "a spelled-out title with nothing after it is still no name"
        );
    }

    /// Ruling L47: a name particle (`von`) in all-lower-case text does not
    /// end the honorific's name; the particles are not common words.
    #[test]
    fn a_lower_case_name_particle_keeps_the_name() {
        let hits = found("bitte an herr von weizsäcker weiterleiten.");
        assert!(
            hits.iter().any(|(t, _)| t.contains("weizsäcker")),
            "{hits:?}"
        );
    }

    #[test]
    fn lower_cased_text_is_matched_case_insensitively() {
        // 8 % of generated documents are lower-cased whole; with no
        // uppercase letter anywhere the anchors match case-insensitively
        // and the capitalization requirement on the name is dropped.
        assert_eq!(
            found("hallo,\n\nich wohne jetzt hier.\n\nlg sarah"),
            vec![("sarah".to_string(), ANCHOR_WITH_GAZETTEER)]
        );
        assert!(
            found("hallo, ich wohne hier. lg sarah").is_empty(),
            "sign-offs are recognized at a line start only"
        );
        // mixed-case text keeps both: a lower-case anchor does not fire and
        // a lower-case name is not accepted
        assert!(found("Danke. lg sarah\nSarah").is_empty());
        assert!(found("Hallo sarah, danke").is_empty());
    }

    #[test]
    fn offsets_are_on_the_original_text() {
        let text = "Grüße aus Wien. Liebe Frau Großmann,\nLG İlker";
        let v = found(text);
        assert!(
            v.iter()
                .any(|(t, c)| t == "Großmann" && *c == ANCHOR_HONORIFIC),
            "{v:?}"
        );
        assert!(v.iter().any(|(t, _)| t == "İlker"), "{v:?}");
        for s in AnchorDetector::new()
            .detect(text, &DetectCtx::for_text(text))
            .unwrap()
        {
            crate::detect::validate_span(text, &s).unwrap();
        }
    }

    fn names(text: &str) -> Vec<String> {
        found(text).into_iter().map(|(t, _)| t).collect()
    }

    /// Review Focus 1: a sign-off name on its own line may be a word that is
    /// also an ordinary word; a group word after a sign-off is never a name.
    #[test]
    fn own_line_sign_off_names_may_be_name_like_common_words() {
        assert_eq!(names("Danke.\n\nViele Grüße\nRose"), vec!["Rose"]);
        // a line that itself starts a sign-off is never the name of the one above
        assert_eq!(names("Vielen Dank.\n\nViele Grüße\nRose"), vec!["Rose"]);
        assert_eq!(
            names("Please call.\n\nThanks,\nMay\n\n> On 02.06.2025 wrote:"),
            vec!["May"]
        );
        assert_eq!(names("Bis bald.\n\nViele Grüße\nHunter"), vec!["Hunter"]);
        // a leading possessive is skipped when a known first name follows
        assert_eq!(names("Liebe Grüße\nDeine Anna"), vec!["Anna"]);
        assert_eq!(names("Liebe Grüße\nDein Thomas"), vec!["Thomas"]);
        assert_eq!(names("Liebe Grüße\nEure Lisa"), vec!["Lisa"]);
        for text in [
            "Best Wishes",
            "Cheers Mate",
            "Kind regards\nKundenservice",
            "Viele Grüße\nIhr Support-Team",
            "Viele Grüße\nIhr Team",
            "Grüße\nTeam",
            "Danke,\nich melde mich morgen.", // guard (bare `Danke` is not a phrase)
            "Danke!\nWir melden uns.",        // guard
        ] {
            assert!(found(text).is_empty(), "{text}: {:?}", found(text));
        }
    }

    #[test]
    fn greetings_from_a_place_and_thanks_are_sign_offs() {
        assert_eq!(
            names("Bitte erstatten.\n\nSchöne Grüße aus 5280 Braunau am Inn\nLeonie"),
            vec!["Leonie"]
        );
        assert_eq!(
            names("bitte erstatten sie den betrag.\n\ndanke im voraus,\nines illichmann"),
            vec!["ines illichmann"]
        );
        assert_eq!(
            names("die alte wohnung.\n\nschöne grüße aus 2500 baden\nzeynep"),
            vec!["zeynep"]
        );
        assert_eq!(
            names("Alles klar.\n\nVielen Dank\nSarah Leitner"),
            vec!["Sarah Leitner"]
        );
    }

    /// Ruling L49: a one-word line one typo away from a single-word
    /// sign-off phrase (`Thansk,`, `Regrads,`), or a spelling variant of one
    /// (`Grüsse`), is a sign-off line for the own-line name rule.
    #[test]
    fn a_misspelled_one_word_sign_off_still_anchors_the_name() {
        assert_eq!(names("Bitte prüfen.\n\nThansk,\nRose"), vec!["Rose"]);
        assert_eq!(
            names("Bitte prüfen.\n\nRegrads,\nAnna Berger"),
            vec!["Anna Berger"]
        );
        assert_eq!(names("Bitte prüfen.\n\nGrüsse\nLeonie"), vec!["Leonie"]);
        // review minors: a trailing `.` as in the exact rule, and the Swiss
        // spelling of the four-letter `Gruß`
        assert_eq!(names("Bitte prüfen.\n\nThansk.\nAnna"), vec!["Anna"]);
        assert_eq!(names("Bitte prüfen.\n\nGruss\nAnna"), vec!["Anna"]);
        assert_eq!(
            names("bitte rückruf.\n\nthansk!\n\nivan\n\n> on 04.10.2026 wrote:"),
            vec!["ivan"]
        );
        // Task 1's accept rules still apply
        assert_eq!(names("Ok.\n\nCheesr,\nDeine Anna"), vec!["Anna"]);
        assert!(names("Ok.\n\nThansk,\nIhr Support-Team").is_empty());
    }

    /// Ruling L49 kept narrow: a sentence on the next line is no name, and a
    /// word two edits from every phrase (`Banks`, `Best` is too short to
    /// fuzz) is no sign-off.
    #[test]
    fn a_fuzzy_sign_off_needs_one_word_one_edit_and_a_name_line() {
        assert!(!is_fuzzy_sign_off("Banks"));
        assert!(!is_fuzzy_sign_off("Bset"), "Best is shorter than five");
        assert!(!is_fuzzy_sign_off("Grus"), "Gruß is shorter than five");
        assert!(is_fuzzy_sign_off("Gruss"), "fold-equal to Gruß");
        assert!(is_fuzzy_sign_off("Thansk"));
        assert!(is_fuzzy_sign_off("sincerly"));
        for text in [
            "Thansk,\nwe will call you tomorrow.",
            "Banks,\nAnna",
            "Thansk you,\nAnna",
        ] {
            assert!(found(text).is_empty(), "{text}: {:?}", found(text));
        }
    }

    #[test]
    fn debug_prints_no_text() {
        assert_eq!(format!("{:?}", AnchorDetector::new()), "AnchorDetector");
    }
}
