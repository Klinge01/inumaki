//! Name linking (M4 spec §16.2): which mentions are surface forms of which
//! entity. This file holds the data types every pass shares; the linker
//! itself is [`link_mentions`] (plan 4a Task 4).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::ops::Range;
use std::time::Duration;

use serde::Deserialize;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::gazetteer::is_first_name;
use crate::resolve::overlaps_accepted;
use crate::span::{DetectorId, EntityKind, Span};
use crate::stoplist::is_common_word;
use crate::token::{NormKey, TokenStore, normalize};

/// Which tier a link was decided at (plan 4a decision 7 keys caching on it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkTier {
    /// A full name in the same text.
    Document,
    /// A full name from an earlier block of the same batch.
    Batch,
    /// An entity from the store's recency window.
    Window,
}

/// Link counts per tier.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkTiers {
    /// Links decided from a full name in the same text.
    pub document: usize,
    /// Links decided from an earlier block of the same batch.
    pub batch: usize,
    /// Links decided from the store's recency window.
    pub window: usize,
}

impl LinkTiers {
    /// True when any link depended on state outside the text itself.
    pub fn cross_request(&self) -> bool {
        self.batch + self.window > 0
    }
}

/// Mention start offset (in the NFC text) → the original text of the
/// entity it belongs to and the tier that decided it. The sanitizer mints
/// the parent's token and then a surface token for the mention.
#[derive(Default, Clone)]
pub struct Links {
    by_start: HashMap<usize, (Zeroizing<String>, LinkTier)>,
}

impl fmt::Debug for Links {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Links({})", self.by_start.len())
    }
}

impl Links {
    /// No links.
    pub fn empty() -> Self {
        Links::default()
    }
    /// Link the mention starting at `start` to the entity whose original is `parent`.
    pub fn insert(&mut self, start: usize, parent: &str, tier: LinkTier) {
        self.by_start
            .insert(start, (Zeroizing::new(parent.to_string()), tier));
    }
    /// The parent original of the mention starting at `start`.
    pub fn parent(&self, start: usize) -> Option<&str> {
        self.by_start.get(&start).map(|(z, _)| z.as_str())
    }
    /// How many links each tier decided.
    pub fn tiers(&self) -> LinkTiers {
        let mut t = LinkTiers::default();
        for (_, tier) in self.by_start.values() {
            match tier {
                LinkTier::Document => t.document += 1,
                LinkTier::Batch => t.batch += 1,
                LinkTier::Window => t.window += 1,
            }
        }
        t
    }
    /// Number of linked mentions.
    pub fn len(&self) -> usize {
        self.by_start.len()
    }
    /// True when nothing is linked.
    pub fn is_empty(&self) -> bool {
        self.by_start.is_empty()
    }
}

/// Full names of persons seen in earlier blocks of the same batch (tier 2
/// of the linker). Held in `Zeroizing`; dropped with the batch.
#[derive(Default)]
pub struct LinkScope {
    persons: Vec<Zeroizing<String>>,
}

impl fmt::Debug for LinkScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LinkScope({})", self.persons.len())
    }
}

impl LinkScope {
    /// Nothing seen yet.
    pub fn empty() -> Self {
        LinkScope::default()
    }
    /// Remember a full name (two or more parts); one-part names are ignored.
    pub fn push(&mut self, full_name: &str) {
        if full_name.split_whitespace().count() >= 2
            && !self.persons.iter().any(|p| p.as_str() == full_name)
        {
            self.persons.push(Zeroizing::new(full_name.to_string()));
        }
    }
    /// The remembered names.
    pub fn persons(&self) -> impl Iterator<Item = &str> {
        self.persons.iter().map(|p| p.as_str())
    }
    /// Count.
    pub fn len(&self) -> usize {
        self.persons.len()
    }
    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.persons.is_empty()
    }
}

fn d_true() -> bool {
    true
}

fn d_window() -> u64 {
    30
}

/// `[linking]` (M4 spec §16.2, plan 4a decisions 3 and 4).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LinkingConfig {
    /// Run the linker after detection.
    pub enabled: bool,
    /// Recency window for the store tier, in minutes (at least 1).
    pub window_minutes: u64,
    /// Let a bare surname link to a person of an earlier request within the
    /// window. Off by default: a stale `Gruber` would capture a new one.
    pub surnames_across_requests: bool,
    /// Let a bare first name link to a person of an earlier request. Off
    /// by default: a stale correspondent would capture a new one's sign-off.
    pub first_names_across_requests: bool,
    /// Add the greeting/sign-off/honorific anchor detector to the stack.
    pub anchors: bool,
}

impl Default for LinkingConfig {
    fn default() -> Self {
        LinkingConfig {
            enabled: true,
            window_minutes: d_window(),
            surnames_across_requests: false,
            first_names_across_requests: false,
            anchors: d_true(),
        }
    }
}

impl LinkingConfig {
    /// The recency window as a duration.
    pub fn window(&self) -> Duration {
        Duration::from_secs(self.window_minutes.saturating_mul(60))
    }
}

/// Confidence of a mention the linker emits.
pub const LINK_CONFIDENCE: f32 = 0.90;

/// Position of a part inside a full name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartRole {
    /// Any part but the last.
    First,
    /// The last part.
    Last,
}

/// One normalized part of a full name.
#[derive(Debug, Clone)]
pub struct NamePart {
    /// Normalized text with `ä/ö/ü` folded to `ae/oe/ue` (redacted `Debug`).
    pub key: NormKey,
    /// The plain [`normalize`] key when it differs from `key` (a part with
    /// an umlaut): `Muller`, spelled without the dots, still matches.
    pub alt: Option<NormKey>,
    /// First or last.
    pub role: PartRole,
}

impl NamePart {
    fn matches(&self, k: &Keys) -> bool {
        k.all()
            .any(|m| *m == self.key || self.alt.as_ref() == Some(m))
    }
}

/// The two comparison keys of a word: with `ä/ö/ü` spelled `ae/oe/ue` (as
/// the gazetteer does, M4 spec §16.2), and the store's plain normalization.
/// Two words are the same name part when either pair of keys is equal, so
/// `Müller`, `Mueller`, and the umlaut-dropped `Muller` agree, while
/// `Bauer` and `Baur` stay apart (never fuzzy). Not applied in
/// [`normalize`]: other kinds must keep `ü` and `ue` apart.
struct Keys {
    folded: NormKey,
    plain: Option<NormKey>,
}

impl Keys {
    fn of(s: &str) -> Keys {
        let mut folded = Zeroizing::new(String::with_capacity(s.len() + 4));
        for c in s.nfc() {
            match c {
                'ä' => folded.push_str("ae"),
                'ö' => folded.push_str("oe"),
                'ü' => folded.push_str("ue"),
                'Ä' => folded.push_str("Ae"),
                'Ö' => folded.push_str("Oe"),
                'Ü' => folded.push_str("Ue"),
                _ => folded.push(c),
            }
        }
        let folded = normalize(&folded);
        let plain = normalize(s);
        let plain = (plain != folded).then_some(plain);
        Keys { folded, plain }
    }

    fn all(&self) -> impl Iterator<Item = &NormKey> {
        std::iter::once(&self.folded).chain(self.plain.as_ref())
    }
}

/// A part qualifies with four or more characters when it is not a common
/// word or a legal form (`GmbH`), or with three when the gazetteer knows it.
fn qualifies(part: &str) -> bool {
    let n = part.chars().count();
    !is_common_word(part)
        && !crate::stoplist::is_legal_form(part)
        && (n >= 4 || (n >= 3 && is_first_name(part)))
}

/// The parts of `full` that may identify a person on their own.
pub fn name_parts_of(full: &str) -> Vec<NamePart> {
    let words: Vec<&str> = full
        .split_whitespace()
        .map(|p| p.trim_matches(|c: char| !c.is_alphanumeric()))
        .filter(|p| !p.is_empty())
        .collect();
    let last = words.len().saturating_sub(1);
    words
        .iter()
        .enumerate()
        .filter(|(_, p)| qualifies(p))
        .map(|(i, p)| {
            let k = Keys::of(p);
            NamePart {
                key: k.folded,
                alt: k.plain,
                role: if i == last {
                    PartRole::Last
                } else {
                    PartRole::First
                },
            }
        })
        .collect()
}

struct Candidate {
    original: Zeroizing<String>,
    parts: Vec<NamePart>,
}

/// Sign-off and greeting phrases (lower case, whole words) a detector span
/// may swallow in front of a name (`LG Hannah`, `Beste Grüße Hannah`): not
/// part of the name, and not a title, so they must not shift the roles of
/// the words after them. Matched as word sequences, so `Best` only strips as
/// part of `Best regards`, never from a surname `Best`.
const SIGNOFF_PHRASES: &[&[&str]] = &[
    &["lg"],
    &["vg"],
    &["mfg"],
    &["glg"],
    &["hallo"],
    &["hi"],
    &["hey"],
    &["liebe"],
    &["lieber"],
    &["dear"],
    &["cheers"],
    &["danke"],
    &["thanks"],
    &["gruß"],
    &["grüße"],
    &["gruss"],
    &["gruesse"],
    &["viele", "grüße"],
    &["beste", "grüße"],
    &["herzliche", "grüße"],
    &["schöne", "grüße"],
    &["freundliche", "grüße"],
    &["mit", "freundlichen", "grüßen"],
    &["mit", "besten", "grüßen"],
    &["kind", "regards"],
    &["best", "regards"],
    &["warm", "regards"],
    &["best", "wishes"],
];

/// `n` without leading sign-off or greeting phrases. A span `LG Hannah` is
/// the first name `Hannah`, not a two-word name whose last part is
/// `Hannah`: read as the latter, a later bare `Hannah` of another person
/// would link to it through the surname role.
fn strip_signoff(n: &str) -> &str {
    let mut rest = n.trim_start();
    loop {
        let words: Vec<String> = rest
            .split_whitespace()
            .take(3)
            .map(|w| {
                w.trim_matches(|c: char| !c.is_alphanumeric())
                    .to_lowercase()
            })
            .collect();
        // a phrase must leave at least one word of the name
        let Some(len) = SIGNOFF_PHRASES
            .iter()
            .filter(|p| words.len() > p.len() && p.iter().zip(&words).all(|(a, b)| a == b))
            .map(|p| p.len())
            .max()
        else {
            return rest;
        };
        for _ in 0..len {
            rest = rest
                .trim_start()
                .split_once(char::is_whitespace)
                .map_or("", |(_, tail)| tail);
        }
        rest = rest.trim_start();
    }
}

fn candidates<'a>(names: impl Iterator<Item = &'a str>) -> Vec<Candidate> {
    let mut seen: HashSet<NormKey> = HashSet::new();
    let mut out = Vec::new();
    for n in names {
        // A candidate is a multi-word name as detected (`LG Hannah` counts);
        // its roles are read from the name proper, and the candidate keeps
        // the full original (the store's parent text).
        if n.split_whitespace().count() < 2 {
            continue;
        }
        let core = strip_signoff(n);
        // The same name in two spellings (`Müller`/`Muller`) is one candidate.
        let k = Keys::of(core);
        let fresh = k.all().all(|x| !seen.contains(x));
        seen.extend(k.all().cloned());
        if !fresh {
            continue;
        }
        let mut parts = name_parts_of(core);
        if core.split_whitespace().count() < 2 {
            // `Hi Anna`: a first name, never a surname
            for p in &mut parts {
                p.role = PartRole::First;
            }
        }
        if !parts.is_empty() {
            out.push(Candidate {
                original: Zeroizing::new(n.to_string()),
                parts,
            });
        }
    }
    out
}

/// Which roles a tier may match on.
#[derive(Clone, Copy)]
struct Roles {
    first: bool,
    last: bool,
}

fn has_part(c: &Candidate, k: &Keys, roles: Roles) -> bool {
    c.parts.iter().any(|p| {
        p.matches(k)
            && match p.role {
                PartRole::First => roles.first,
                PartRole::Last => roles.last,
            }
    })
}

/// Exactly one candidate at the first tier that has any candidate with the
/// part; two or more at that tier mean no link.
fn resolve<'a>(
    k: &Keys,
    tiers: &[(&'a [Candidate], Roles, LinkTier)],
) -> Option<(&'a str, LinkTier)> {
    for (cands, roles, tier) in tiers {
        let mut hits = cands.iter().filter(|c| has_part(c, k, *roles));
        match (hits.next(), hits.next()) {
            (None, _) => continue,
            (Some(one), None) => return Some((one.original.as_str(), *tier)),
            (Some(_), Some(_)) => return None,
        }
    }
    None
}

/// True when `start..end` overlaps a protected range. `protected` is sorted
/// and non-overlapping.
fn hits_protected(protected: &[Range<usize>], start: usize, end: usize) -> bool {
    let i = protected.partition_point(|r| r.end <= start);
    protected.get(i).is_some_and(|r| r.start < end)
}

fn is_name_char(c: char) -> bool {
    c.is_alphabetic()
        || unicode_normalization::char::is_combining_mark(c)
        || matches!(c, '\'' | '’' | '-')
}

/// Maximal runs of name characters, trailing `'’-` trimmed. A run that
/// overlaps a protected range is dropped whole.
fn words(text: &str, protected: &[Range<usize>]) -> Vec<(usize, usize)> {
    let mut runs = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in text.char_indices() {
        match (is_name_char(c), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                runs.push((s, i));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        runs.push((s, text.len()));
    }
    runs.into_iter()
        .filter(|&(s, e)| !hits_protected(protected, s, e))
        .map(|(s, e)| {
            let trimmed = text[s..e].trim_end_matches(['\'', '’', '-']);
            (s, s + trimmed.len())
        })
        .filter(|(s, e)| e > s)
        .collect()
}

/// Email-derived name parts (M4 spec §16.2): pieces of the local part.
fn email_parts(text: &str, spans: &[Span], protected: &[Range<usize>]) -> Vec<Keys> {
    let mut out = Vec::new();
    for s in spans
        .iter()
        .filter(|s| s.kind == EntityKind::Email && !hits_protected(protected, s.start, s.end))
    {
        let local = s.slice(text).split('@').next().unwrap_or("");
        for piece in local.split(['.', '_', '-']) {
            if piece.chars().count() >= 3
                && piece.chars().all(char::is_alphabetic)
                && qualifies(piece)
            {
                out.push(Keys::of(piece));
            }
        }
    }
    out
}

/// Link single-word PERSON mentions to the entity they belong to and emit
/// the bare name parts the detectors missed. `spans` are resolved,
/// non-overlapping, sorted; the result is too. See the module docs and the
/// plan's rules for the tiers.
///
/// `protected` are sorted, non-overlapping byte ranges of already-minted
/// token text in `text` (callers without any pass `&[]`). Nothing is emitted
/// inside or across them, and a span overlapping one is neither a candidate
/// nor altered nor linked.
pub fn link_mentions(
    text: &str,
    spans: Vec<Span>,
    scope: &LinkScope,
    store: Option<&dyn TokenStore>,
    cfg: &LinkingConfig,
    protected: &[Range<usize>],
) -> (Vec<Span>, Links) {
    let clear = |s: &&Span| !hits_protected(protected, s.start, s.end);
    let in_doc = candidates(
        spans
            .iter()
            .filter(|s| s.kind == EntityKind::Person)
            .filter(clear)
            .map(|s| s.slice(text)),
    );
    let batch = candidates(scope.persons());
    // With both cross-request flags off the window contributes nothing, so
    // the store is not asked (the call decrypts and scans recent entries).
    let window_names = store
        .filter(|_| cfg.surnames_across_requests || cfg.first_names_across_requests)
        .map(|s| s.link_candidates(&EntityKind::Person, cfg.window()))
        .unwrap_or_default();
    let window = candidates(window_names.iter().map(|z| z.as_str()));
    let all = Roles {
        first: true,
        last: true,
    };
    let window_roles = Roles {
        first: cfg.first_names_across_requests,
        last: cfg.surnames_across_requests,
    };

    let mut known: HashSet<NormKey> = HashSet::new();
    let add = |known: &mut HashSet<NormKey>, p: &NamePart| {
        known.insert(p.key.clone());
        known.extend(p.alt.clone());
    };
    for c in in_doc.iter().chain(&batch) {
        for p in &c.parts {
            add(&mut known, p);
        }
    }
    for c in &window {
        for p in c.parts.iter().filter(|p| match p.role {
            PartRole::First => window_roles.first,
            PartRole::Last => window_roles.last,
        }) {
            add(&mut known, p);
        }
    }
    for k in email_parts(text, &spans, protected) {
        known.extend(k.all().cloned());
    }

    // Upper case inside already-minted tokens (`<PERSON_a7f2>`) does not
    // count: it must not switch the lower-case rule off.
    let relaxed = !text
        .char_indices()
        .any(|(i, c)| c.is_uppercase() && !hits_protected(protected, i, i + c.len_utf8()));
    // A regex town after a postal code (`10234 Gruber`) does not hold its
    // word against a known name part: the linked PERSON replaces it
    // (ruling L53).
    let mut accepted: BTreeMap<usize, usize> = spans
        .iter()
        .filter(|s| !crate::detect::regex::is_town_span(s))
        .map(|s| (s.start, s.end))
        .collect();
    let mut out = spans;
    if !known.is_empty() {
        for (start, end) in words(text, protected) {
            if overlaps_accepted(&accepted, start, end) {
                continue;
            }
            let w = &text[start..end];
            let Some(first) = w.chars().next() else {
                continue;
            };
            if !(relaxed || first.is_uppercase()) || w.chars().count() < 3 || is_common_word(w) {
                continue;
            }
            if Keys::of(w).all().any(|k| known.contains(k)) {
                out.push(Span::new(
                    start,
                    end,
                    EntityKind::Person,
                    LINK_CONFIDENCE,
                    DetectorId::Link,
                ));
                accepted.insert(start, end);
            }
        }
    }
    let linked: Vec<(usize, usize)> = out
        .iter()
        .filter(|s| s.source == DetectorId::Link)
        .map(|s| (s.start, s.end))
        .collect();
    out.retain(|s| {
        !(crate::detect::regex::is_town_span(s)
            && linked.iter().any(|&(a, b)| a < s.end && s.start < b))
    });
    out.sort_by_key(|s| s.start);

    let tiers: [(&[Candidate], Roles, LinkTier); 3] = [
        (&in_doc, all, LinkTier::Document),
        (&batch, all, LinkTier::Batch),
        (&window, window_roles, LinkTier::Window),
    ];
    let mut links = Links::empty();
    for s in out
        .iter()
        .filter(|s| s.kind == EntityKind::Person)
        .filter(clear)
    {
        let t = s.slice(text);
        if t.split_whitespace().count() != 1 {
            continue;
        }
        let k = Keys::of(t.trim_matches(|c: char| !c.is_alphanumeric()));
        if let Some((parent, tier)) = resolve(&k, &tiers) {
            links.insert(s.start, parent, tier);
        }
    }
    (out, links)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alias::{AliasGroup, AliasTable, Aliased};
    use crate::config::TokenSettings;
    use crate::policy::{Action, Decision};
    use crate::sanitize::sanitize_linked;
    use crate::span::{DetectorId as D, EntityKind as K, Span};
    use crate::token::{Context, ContextId, parse_token};
    use std::time::Duration;

    fn person(text: &str, needle: &str, nth: usize) -> Span {
        let start = text.match_indices(needle).nth(nth).map(|(i, _)| i).unwrap();
        Span::new(start, start + needle.len(), K::Person, 0.9, D::Ner)
    }
    fn texts<'a>(text: &'a str, spans: &[Span]) -> Vec<&'a str> {
        spans.iter().map(|s| s.slice(text)).collect()
    }
    fn cfg() -> LinkingConfig {
        LinkingConfig::default()
    }
    fn ctx() -> Context {
        Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            TokenSettings::default(),
        )
    }

    /// Review Focus 1.
    #[test]
    fn ambiguous_part_gets_its_own_entity_and_is_never_clear() {
        let text = "Sarah Leitner und Sarah Gruber kommen.\n\nLG Sarah";
        let spans = vec![
            person(text, "Sarah Leitner", 0),
            person(text, "Sarah Gruber", 0),
        ];
        let (out, links) = link_mentions(text, spans, &LinkScope::empty(), None, &cfg(), &[]);
        assert_eq!(
            texts(text, &out),
            ["Sarah Leitner", "Sarah Gruber", "Sarah"],
            "still emitted, so it is tokenized"
        );
        assert!(links.is_empty(), "two candidates share the part: no link");
        // a full name that occurs twice is one candidate, not an ambiguity
        let text = "Sarah Leitner kam. Sarah Leitner ging.\n\nLG Sarah";
        let spans = vec![
            person(text, "Sarah Leitner", 0),
            person(text, "Sarah Leitner", 1),
        ];
        let (out, links) = link_mentions(text, spans, &LinkScope::empty(), None, &cfg(), &[]);
        assert_eq!(texts(text, &out).last().copied(), Some("Sarah"));
        assert_eq!(links.parent(out[2].start), Some("Sarah Leitner"));
    }

    /// Review Focus 4.
    #[test]
    fn offsets_survive_case_and_combining_marks() {
        // ẞ (U+1E9E, 3 bytes) lower-cases to ß (2 bytes); İ (U+0130) to i + U+0307.
        let text = "Anna Großmann schreibt.\nFrau GROẞMANN bittet um Rückruf. LG İlker, MFG Anna";
        let spans = vec![person(text, "Anna Großmann", 0)];
        let (out, links) = link_mentions(text, spans, &LinkScope::empty(), None, &cfg(), &[]);
        let got = texts(text, &out);
        assert!(got.contains(&"GROẞMANN"), "{got:?}");
        assert!(got.contains(&"Anna"), "{got:?}");
        for s in &out {
            crate::detect::validate_span(text, s).unwrap();
        }
        let big = out.iter().find(|s| s.slice(text) == "GROẞMANN").unwrap();
        assert_eq!(links.parent(big.start), Some("Anna Großmann"));
        assert!(
            !got.contains(&"İlker"),
            "not a known part; the anchor detector handles sign-offs"
        );
        // NFD input: combining marks in the text
        let nfd = "Jo\u{0308}rg Mu\u{0308}ller ruft an.\n\nLG Jo\u{0308}rg";
        let spans = vec![Span::new(
            0,
            "Jo\u{0308}rg Mu\u{0308}ller".len(),
            K::Person,
            0.9,
            D::Ner,
        )];
        let (out, links) = link_mentions(nfd, spans, &LinkScope::empty(), None, &cfg(), &[]);
        assert_eq!(texts(nfd, &out).last().copied(), Some("Jo\u{0308}rg"));
        assert_eq!(links.len(), 1);
    }

    /// R11: `ä/ö/ü` and `ae/oe/ue` are the same name part on both sides.
    #[test]
    fn umlaut_and_transliterated_spellings_are_one_part() {
        let text = "Hans Müller ruft an. Herr Mueller bittet um Rückruf. Frau MÜLLER auch.";
        let spans = vec![person(text, "Hans Müller", 0)];
        let (out, links) = link_mentions(text, spans, &LinkScope::empty(), None, &cfg(), &[]);
        assert_eq!(
            texts(text, &out),
            ["Hans Müller", "Mueller", "MÜLLER"],
            "{:?}",
            texts(text, &out)
        );
        assert_eq!(links.len(), 2);
        assert_eq!(links.parent(out[1].start), Some("Hans Müller"));
        // the other direction: the document's full name is transliterated
        let text = "Hans Mueller ruft an. Herr Müller bittet um Rückruf.";
        let spans = vec![person(text, "Hans Mueller", 0)];
        let (out, links) = link_mentions(text, spans, &LinkScope::empty(), None, &cfg(), &[]);
        assert_eq!(texts(text, &out), ["Hans Mueller", "Müller"]);
        assert_eq!(links.parent(out[1].start), Some("Hans Mueller"));
        // umlaut dropped (ASCII systems, `hans.muller@` addresses), both ways
        let text = "Hans Müller ruft an. Herr Muller bittet um Rückruf.";
        let spans = vec![person(text, "Hans Müller", 0)];
        let (out, links) = link_mentions(text, spans, &LinkScope::empty(), None, &cfg(), &[]);
        assert_eq!(texts(text, &out), ["Hans Müller", "Muller"]);
        assert_eq!(links.parent(out[1].start), Some("Hans Müller"));
        let text = "Hans Muller ruft an. Herr Müller bittet um Rückruf.";
        let spans = vec![person(text, "Hans Muller", 0)];
        let (out, links) = link_mentions(text, spans, &LinkScope::empty(), None, &cfg(), &[]);
        assert_eq!(texts(text, &out), ["Hans Muller", "Müller"]);
        assert_eq!(links.parent(out[1].start), Some("Hans Muller"));
        let text = "Von: hans.muller@example.at\n\nHerr Müller bittet um Rückruf.";
        let at = text.find("hans.muller@example.at").unwrap();
        let email = Span::new(
            at,
            at + "hans.muller@example.at".len(),
            K::Email,
            0.95,
            D::RegexValidated,
        );
        let (out, _) = link_mentions(text, vec![email], &LinkScope::empty(), None, &cfg(), &[]);
        assert_eq!(texts(text, &out).last().copied(), Some("Müller"));
        // never fuzzy: different names stay apart
        let text = "Hans Bauer ruft an. Herr Baur bittet um Rückruf.";
        let spans = vec![person(text, "Hans Bauer", 0)];
        let (out, links) = link_mentions(text, spans, &LinkScope::empty(), None, &cfg(), &[]);
        assert_eq!(texts(text, &out), ["Hans Bauer"]);
        assert!(links.is_empty());
        // the store's own normalization is unchanged: other kinds keep ü and ue apart
        assert_ne!(
            crate::token::normalize("Müller").as_str(),
            crate::token::normalize("Mueller").as_str()
        );
    }

    /// Decision 4: the store tier is off by default; surnames and first
    /// names each need their flag, and the tier is recorded on the link.
    #[test]
    fn store_tier_is_off_by_default_and_each_role_needs_its_flag() {
        let mut store = ctx();
        store.token_for(&K::Person, "Sarah Leitner").unwrap();
        let run = |text: &str, c: &LinkingConfig| {
            let (out, links) =
                link_mentions(text, Vec::new(), &LinkScope::empty(), Some(&store), c, &[]);
            let found: Vec<String> = texts(text, &out).iter().map(|t| t.to_string()).collect();
            (found, out, links)
        };
        let text = "Frau Leitner bittet um Rückruf.\n\nLG Sarah";
        let (found, _, links) = run(text, &cfg());
        assert!(
            found.is_empty() && links.is_empty(),
            "off by default: {found:?}"
        );
        let surnames = LinkingConfig {
            surnames_across_requests: true,
            ..cfg()
        };
        let (found, out, links) = run(text, &surnames);
        assert_eq!(
            found,
            ["Leitner"],
            "the surname flag alone does not link Sarah"
        );
        assert_eq!(links.parent(out[0].start), Some("Sarah Leitner"));
        assert_eq!(
            links.tiers(),
            LinkTiers {
                document: 0,
                batch: 0,
                window: 1
            }
        );
        let firsts = LinkingConfig {
            first_names_across_requests: true,
            ..cfg()
        };
        let (found, out, links) = run(text, &firsts);
        assert_eq!(
            found,
            ["Sarah"],
            "the first-name flag alone does not link Leitner"
        );
        assert_eq!(links.parent(out[0].start), Some("Sarah Leitner"));
        assert_eq!(links.tiers().window, 1);
        // a detector-found bare name is resolved by the same rule
        let spans = vec![person(text, "Sarah", 0), person(text, "Leitner", 0)];
        let (out, links) =
            link_mentions(text, spans, &LinkScope::empty(), Some(&store), &cfg(), &[]);
        assert_eq!(out.len(), 2);
        assert!(links.is_empty(), "own entities: tokenized, not linked");
        // outside the window nothing links, even with both flags
        let cold = LinkingConfig {
            window_minutes: 0,
            surnames_across_requests: true,
            first_names_across_requests: true,
            ..cfg()
        };
        let (found, _, links) = run(text, &cold);
        assert!(found.is_empty() && links.is_empty(), "{found:?}");
    }

    /// A detector span that swallowed the sign-off (`LG Hannah`) is the first
    /// name `Hannah`: as a window candidate it must not give `Hannah` the
    /// surname role (found by the sequence eval: with
    /// `surnames_across_requests`, a bare `Hannah` of another person linked to
    /// it), while a title (`Herr Steiner`) still marks a surname.
    #[test]
    fn a_swallowed_sign_off_does_not_make_a_first_name_a_surname() {
        let surnames = LinkingConfig {
            surnames_across_requests: true,
            ..cfg()
        };
        let run = |earlier: &str, text: &str| {
            let mut store = ctx();
            store.token_for(&K::Person, earlier).unwrap();
            let (out, links) = link_mentions(
                text,
                Vec::new(),
                &LinkScope::empty(),
                Some(&store),
                &surnames,
                &[],
            );
            (texts(text, &out).len(), links.len())
        };
        let text = "wie mit Hannah besprochen, geht es um die Rechnung.\n\nVielen Dank";
        assert_eq!(
            run("LG Hannah", text),
            (0, 0),
            "no surname role for a sign-off + first name"
        );
        // control: a title before a surname keeps the surname role
        let text = "Hannah bittet um Rückruf.\n\nVielen Dank";
        let (found, linked) = run("Herr Hannah", text);
        assert_eq!((found, linked), (1, 1));
        // control: a real full name still links by surname
        let text = "Frau Okonkwo bittet um Rückruf.\n\nVielen Dank";
        assert_eq!(run("Hannah Okonkwo", text), (1, 1));
        // the in-document tier is not confused by a swallowed sign-off either:
        // `LG Hannah` next to `Hannah Okonkwo` is not a second `Hannah` candidate
        let text = "Hannah Okonkwo schreibt: hallo.\n\nLG Hannah";
        let spans = vec![
            person(text, "Hannah Okonkwo", 0),
            person(text, "LG Hannah", 0),
        ];
        let (out, links) = link_mentions(text, spans, &LinkScope::empty(), None, &cfg(), &[]);
        assert_eq!(out.len(), 2);
        assert!(links.is_empty(), "the span stays whole; nothing to join");
    }

    /// A detected `Hi Anna` is still the document's only source of `Anna`:
    /// a bare `Anna` the detectors missed is emitted and linked to it, and a
    /// multi-word sign-off (`Beste Grüße Hannah`) leaves a first name.
    #[test]
    fn a_greeting_span_still_supplies_its_first_name() {
        let text = "Hi Anna, bitte um Rückruf. Später sagte Anna Bescheid.";
        let spans = vec![person(text, "Hi Anna", 0)];
        let (out, links) = link_mentions(text, spans, &LinkScope::empty(), None, &cfg(), &[]);
        assert_eq!(texts(text, &out), ["Hi Anna", "Anna"]);
        assert_eq!(links.parent(out[1].start), Some("Hi Anna"));
        for name in ["Beste Grüße Hannah", "Best regards Hannah"] {
            let c = candidates([name].into_iter());
            assert_eq!(c.len(), 1, "{name}");
            assert_eq!(c[0].parts.len(), 1);
            assert_eq!(c[0].parts[0].role, PartRole::First, "{name}");
        }
        // `Best` alone is a surname, not a sign-off
        assert_eq!(strip_signoff("Best Hannah"), "Best Hannah");
        assert_eq!(strip_signoff("Best regards Hannah"), "Hannah");
    }

    /// Upper case inside a protected token does not switch the lower-case
    /// rule off.
    #[test]
    fn protected_upper_case_does_not_disable_the_lower_case_rule() {
        let text = "hallo <PERSON_a7f2c9> hier sarah leitner.\n\nlg sarah";
        let tok_start = text.find('<').unwrap();
        let tok = tok_start..tok_start + "<PERSON_a7f2c9>".len();
        let spans = vec![person(text, "sarah leitner", 0)];
        let (out, links) = link_mentions(
            text,
            spans,
            &LinkScope::empty(),
            None,
            &cfg(),
            std::slice::from_ref(&tok),
        );
        assert_eq!(texts(text, &out), ["sarah leitner", "sarah"]);
        assert_eq!(links.len(), 1);
    }

    /// Lane L2 contract: text a pass already minted is never scanned, never
    /// emitted from, and a span overlapping it is neither altered nor linked.
    #[test]
    fn protected_token_text_yields_no_emission_and_no_link() {
        // a kind whose label letters normalize to a known part
        let text = "Sarah Leitner schreibt. Ticket <LEITNER_a7f2c9> offen.\n\nLG Sarah";
        let tok_start = text.find("<LEITNER_a7f2c9>").unwrap();
        let tok = tok_start..tok_start + "<LEITNER_a7f2c9>".len();
        let spans = || vec![person(text, "Sarah Leitner", 0)];
        // control: unprotected, the label letters are emitted
        let (out, _) = link_mentions(text, spans(), &LinkScope::empty(), None, &cfg(), &[]);
        assert!(
            out.iter().any(|s| s.start >= tok.start && s.end <= tok.end),
            "control: {:?}",
            texts(text, &out)
        );
        // protected: nothing inside, the rest of the text still links
        let (out, links) = link_mentions(
            text,
            spans(),
            &LinkScope::empty(),
            None,
            &cfg(),
            std::slice::from_ref(&tok),
        );
        assert!(
            out.iter().all(|s| s.end <= tok.start || s.start >= tok.end),
            "{:?}",
            texts(text, &out)
        );
        assert_eq!(texts(text, &out), ["Sarah Leitner", "Sarah"]);
        assert_eq!(links.len(), 1);
        // an incoming single-word span inside the token is left untouched and unlinked
        let inside = Span::new(tok.start + 1, tok.start + 8, K::Person, 0.9, D::Ner);
        let mut with = spans();
        with.insert(1, inside.clone());
        let (out, links) = link_mentions(
            text,
            with,
            &LinkScope::empty(),
            None,
            &cfg(),
            std::slice::from_ref(&tok),
        );
        assert!(
            out.iter()
                .any(|s| s.start == inside.start && s.end == inside.end)
        );
        assert_eq!(links.parent(inside.start), None);
    }

    /// Review Focus 10: the linker picks the document's full name, which is
    /// an alias variant; the bare surname becomes a surface of the canonical.
    #[test]
    fn alias_variant_full_name_links_a_bare_surname() {
        let table = AliasTable::build(vec![AliasGroup {
            kind: K::Person,
            names: vec![
                "Hans-Peter Gruber".into(),
                "HP Gruber".into(),
                "Hansi".into(),
            ],
        }])
        .unwrap();
        let text = "HP Gruber ruft an. Herr Gruber bittet um Rückruf.";
        let spans = vec![person(text, "HP Gruber", 0)];
        let (out, links) = link_mentions(text, spans, &LinkScope::empty(), None, &cfg(), &[]);
        assert_eq!(texts(text, &out), ["HP Gruber", "Gruber"]);
        assert_eq!(links.parent(out[1].start), Some("HP Gruber"));
        let decisions: Vec<Decision> = out
            .iter()
            .map(|s| Decision {
                span: s.clone(),
                action: Action::Tokenize,
            })
            .collect();
        let mut c = ctx();
        let mut a = Aliased::new(&mut c, &table);
        let sanitized = sanitize_linked(text, &decisions, &links, &mut a).unwrap();
        let toks: Vec<&str> = sanitized
            .replacements
            .iter()
            .map(|r| r.token.as_ref().unwrap().as_str())
            .collect();
        let parsed: Vec<_> = toks
            .iter()
            .map(|t| parse_token(a.settings(), t).unwrap())
            .collect();
        assert_eq!(
            parsed[0].suffix, parsed[1].suffix,
            "both are surface forms of the canonical: {toks:?}"
        );
        assert!(parsed[0].variant.is_some() && parsed[1].variant.is_some());
        assert_eq!(a.original(toks[1]), Some("Gruber"));
    }
}
