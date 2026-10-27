//! Known business data (customers, employees, addresses) as a high-confidence source.

use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::hash::BuildHasher;
use std::path::PathBuf;

use aho_corasick::{AhoCorasick, MatchKind};
use serde::Deserialize;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use super::{DetectCtx, Detector};
use crate::alias::AliasGroup;
use crate::collapse::{Collapsed, collapse_pattern};
use crate::resolve::overlaps_accepted;
use crate::span::{DetectorId, EntityKind, Span, valid_kind_label};
use crate::stoplist::is_common_word;
use crate::{Error, Result};

/// One `[[dictionary.aliases]]` group: variants of one entity.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AliasEntry {
    /// Kind label (`PERSON`, `ORGANIZATION`, a custom label).
    pub kind: String,
    /// First-listed name first; two or more.
    pub names: Vec<String>,
}

/// `[dictionary]` configuration table. Paths are resolved by the loader.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DictionaryConfig {
    /// Files with one full person name per line; a line may list alias
    /// variants separated by `|` (M4 spec §16.5).
    #[serde(default)]
    pub persons: Vec<PathBuf>,
    /// Files with one street address per line.
    #[serde(default)]
    pub addresses: Vec<PathBuf>,
    /// Files with one organization name per line.
    #[serde(default)]
    pub organizations: Vec<PathBuf>,
    /// Alias groups declared in configuration.
    #[serde(default)]
    pub aliases: Vec<AliasEntry>,
}

/// True when `text[start..end]` is delimited by non-alphanumeric characters or string ends.
pub fn word_bounded(text: &str, start: usize, end: usize) -> bool {
    let before_ok = text[..start]
        .chars()
        .next_back()
        .is_none_or(|c| !c.is_alphanumeric());
    let after_ok = text[end..]
        .chars()
        .next()
        .is_none_or(|c| !c.is_alphanumeric());
    before_ok && after_ok
}

/// Split a dictionary line on `|`, trimming each part. A plain line is one
/// part; an empty part (`a | | b`, `a |`) is a configuration error.
pub fn split_alias_line(line: &str) -> Result<Vec<String>> {
    let parts: Vec<String> = line.split('|').map(|p| p.trim().to_string()).collect();
    if parts.iter().any(String::is_empty) {
        return Err(Error::ConfigInvalid(
            "dictionary: empty alias variant".into(),
        ));
    }
    Ok(parts)
}

/// Every entry of the configured dictionaries as a group: a plain line is a
/// one-name group, an alias line or `[[dictionary.aliases]]` entry an
/// n-name group with the first-listed name first. Only `persons.txt` lines
/// are split on `|`; an address or organization line is taken whole (a `|`
/// in a company name is a legitimate character there), and alias groups
/// for those kinds are declared in `[[dictionary.aliases]]`.
pub fn read_groups(cfg: &DictionaryConfig) -> Result<Vec<AliasGroup>> {
    let mut groups = Vec::new();
    let files = [
        (EntityKind::Person, &cfg.persons, true),
        (EntityKind::StreetAddress, &cfg.addresses, false),
        (EntityKind::Organization, &cfg.organizations, false),
    ];
    for (kind, paths, split) in files {
        for path in paths {
            let content = std::fs::read_to_string(path)
                .map_err(|_| Error::ConfigInvalid(format!("dictionary file {}", path.display())))?;
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let names = if split {
                    split_alias_line(line)?
                } else {
                    vec![line.to_string()]
                };
                groups.push(AliasGroup {
                    kind: kind.clone(),
                    names,
                });
            }
        }
    }
    for a in &cfg.aliases {
        let label = a.kind.trim();
        if !valid_kind_label(&label.to_ascii_uppercase()) {
            return Err(Error::ConfigInvalid("dictionary.aliases: kind".into()));
        }
        if a.names.len() < 2 {
            return Err(Error::ConfigInvalid(
                "dictionary.aliases: a group needs two or more names".into(),
            ));
        }
        let names: Vec<String> = a.names.iter().map(|n| n.trim().to_string()).collect();
        if names.iter().any(String::is_empty) {
            return Err(Error::ConfigInvalid(
                "dictionary.aliases: empty name".into(),
            ));
        }
        groups.push(AliasGroup {
            kind: EntityKind::from_label(label),
            names,
        });
    }
    Ok(groups)
}

/// Which input entries produced each pattern of a dictionary built by
/// [`DictionaryDetector::from_entries_traced`]: a pattern (a case variant,
/// a surname) can come from several entries. Positions only, no text.
#[derive(Debug, Default)]
pub struct PatternOrigins {
    /// The first entry behind each pattern.
    first: Vec<u32>,
    /// Further entries, for the few patterns that have them.
    more: HashMap<u32, Vec<u32>>,
}

impl PatternOrigins {
    fn push(&mut self, entry: usize) {
        self.first.push(u32::try_from(entry).unwrap_or(u32::MAX));
    }

    fn add(&mut self, pattern: usize, entry: usize) {
        let e = u32::try_from(entry).unwrap_or(u32::MAX);
        if self.first[pattern] == e {
            return;
        }
        let more = self
            .more
            .entry(u32::try_from(pattern).unwrap_or(u32::MAX))
            .or_default();
        if !more.contains(&e) {
            more.push(e);
        }
    }

    /// The entries (positions in the builder's input) behind `pattern`.
    pub fn of(&self, pattern: usize) -> impl Iterator<Item = usize> + '_ {
        let more = u32::try_from(pattern)
            .ok()
            .and_then(|p| self.more.get(&p))
            .map_or(&[][..], Vec::as_slice);
        self.first
            .get(pattern)
            .into_iter()
            .chain(more)
            .map(|&e| e as usize)
    }
}

/// Aho-Corasick over known entities (customer names, addresses, organizations).
pub struct DictionaryDetector {
    ac: Option<AhoCorasick>,
    meta: Vec<(EntityKind, f32)>,
}

impl fmt::Debug for DictionaryDetector {
    /// Prints entry counts only; never the configured names, addresses, or
    /// organizations themselves.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DictionaryDetector")
            .field("patterns", &self.meta.len())
            .finish()
    }
}

impl DictionaryDetector {
    /// Build from in-memory entries. Entries are borrowed: every copy this
    /// builder makes (the NFC form, the case variants) is held in
    /// `Zeroizing` and wiped when the build ends. The automaton keeps its
    /// own copy of the pattern bytes, which cannot be wiped.
    pub fn from_entries<S: AsRef<str>>(
        entries: impl IntoIterator<Item = (EntityKind, S)>,
    ) -> Result<Self> {
        Self::build(entries, None)
    }

    /// [`DictionaryDetector::from_entries`], also recording which entries
    /// (by their position in `entries`) produced each pattern, for
    /// [`DictionaryDetector::detect_all_traced`] (Task 7e).
    pub fn from_entries_traced<S: AsRef<str>>(
        entries: impl IntoIterator<Item = (EntityKind, S)>,
    ) -> Result<(Self, PatternOrigins)> {
        let mut origins = PatternOrigins::default();
        let d = Self::build(entries, Some(&mut origins))?;
        Ok((d, origins))
    }

    fn build<S: AsRef<str>>(
        entries: impl IntoIterator<Item = (EntityKind, S)>,
        mut origins: Option<&mut PatternOrigins>,
    ) -> Result<Self> {
        let mut patterns: Vec<Zeroizing<String>> = Vec::new();
        let mut meta: Vec<(EntityKind, f32)> = Vec::new();
        // `Zeroizing<String>` has no `Hash`: key by the hash of the variant
        // and compare by value on a hit (same scheme as `leak_patterns`).
        let hasher = RandomState::new();
        let mut seen: HashMap<u64, Vec<usize>> = HashMap::new();

        let mut add = |pat: &str,
                       kind: &EntityKind,
                       conf: f32,
                       entry: usize,
                       patterns: &mut Vec<Zeroizing<String>>,
                       meta: &mut Vec<(EntityKind, f32)>| {
            let pat = pat.trim();
            if pat.is_empty() {
                return;
            }
            for variant in [
                Zeroizing::new(pat.to_string()),
                Zeroizing::new(pat.to_lowercase()),
                Zeroizing::new(pat.to_uppercase()),
            ] {
                let slot = seen.entry(hasher.hash_one(variant.as_str())).or_default();
                if let Some(&i) = slot
                    .iter()
                    .find(|&&i| patterns[i].as_str() == variant.as_str())
                {
                    // The highest-confidence entry's kind wins. With traced
                    // origins that entry may later be dead (a StoreDict
                    // base): the span is still found through a live one,
                    // under the dead entry's kind.
                    if meta[i].1 < conf {
                        meta[i] = (kind.clone(), conf);
                    }
                    if let Some(o) = origins.as_deref_mut() {
                        o.add(i, entry);
                    }
                    continue;
                }
                slot.push(patterns.len());
                if let Some(o) = origins.as_deref_mut() {
                    o.push(entry);
                }
                patterns.push(variant);
                meta.push((kind.clone(), conf));
            }
        };

        for (n, (kind, entry)) in entries.into_iter().enumerate() {
            // Input text is NFC-normalized by the engine; entries must be too.
            // Internal whitespace is collapsed because the text is searched
            // in its whitespace-collapsed form.
            let nfc = Zeroizing::new(entry.as_ref().nfc().collect::<String>());
            let entry = Zeroizing::new(collapse_pattern(&nfc));
            add(&entry, &kind, 0.97, n, &mut patterns, &mut meta);
            if kind == EntityKind::Person && entry.split_whitespace().count() >= 2 {
                if let Some(surname) = entry.split_whitespace().last() {
                    let surname = surname.trim_matches(|c: char| !c.is_alphanumeric());
                    if surname.chars().count() >= 4 && !is_common_word(surname) {
                        add(surname, &kind, 0.80, n, &mut patterns, &mut meta);
                    }
                }
            }
        }

        if patterns.is_empty() {
            return Ok(DictionaryDetector { ac: None, meta });
        }
        // `Standard` so `find_overlapping_iter` can report every match; a
        // longest match rejected by the word-boundary rule must not hide a
        // shorter bounded one (see `detect`).
        let ac = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(patterns.iter().map(|p| p.as_bytes()))
            .map_err(|_| Error::ConfigInvalid("dictionary".into()))?;
        Ok(DictionaryDetector { ac: Some(ac), meta })
    }

    /// Every word-bounded, char-boundary match in the collapsed view as
    /// `(start, end, pattern index)` offsets into that view.
    fn candidates(&self, view: &Collapsed) -> Vec<(usize, usize, usize)> {
        let Some(ac) = &self.ac else {
            return Vec::new();
        };
        let t = view.text();
        let mut cands = Vec::new();
        for m in ac.find_overlapping_iter(t) {
            let (start, end) = (m.start(), m.end());
            if !t.is_char_boundary(start) || !t.is_char_boundary(end) {
                continue;
            }
            if !word_bounded(t, start, end) {
                continue;
            }
            cands.push((start, end, m.pattern().as_usize()));
        }
        cands
    }

    fn span_of(&self, view: &Collapsed, (start, end, idx): (usize, usize, usize)) -> Span {
        let (kind, conf) = &self.meta[idx];
        Span::new(
            view.to_original(start),
            view.to_original(end),
            kind.clone(),
            *conf,
            DetectorId::Dictionary,
        )
    }

    /// Every word-bounded match, overlapping ones included, sorted by
    /// `(start, end)` and not resolved. [`Detector::detect`] resolves to a
    /// non-overlapping set; a caller that must see each known entity that
    /// occurs (a leak check) uses this.
    pub fn detect_all(&self, text: &str) -> crate::Result<Vec<Span>> {
        if self.ac.is_none() {
            return Ok(Vec::new());
        }
        let view = Collapsed::new(text);
        let mut cands = self.candidates(&view);
        cands.sort_by_key(|c| (c.0, c.1));
        Ok(cands.into_iter().map(|c| self.span_of(&view, c)).collect())
    }

    /// [`DictionaryDetector::detect_all`] with each match's pattern index,
    /// for [`PatternOrigins::of`] (Task 7e).
    pub fn detect_all_traced(&self, text: &str) -> crate::Result<Vec<(Span, usize)>> {
        if self.ac.is_none() {
            return Ok(Vec::new());
        }
        let view = Collapsed::new(text);
        let mut cands = self.candidates(&view);
        cands.sort_by_key(|c| (c.0, c.1));
        Ok(cands
            .into_iter()
            .map(|c| (self.span_of(&view, c), c.2))
            .collect())
    }

    /// Build by reading the configured files. Every name of an alias group
    /// is an entry of the group's kind (M4 spec §16.5).
    pub fn from_config(cfg: &DictionaryConfig) -> Result<Self> {
        let groups = read_groups(cfg)?;
        Self::from_entries(groups.into_iter().flat_map(|g| {
            let kind = g.kind;
            g.names.into_iter().map(move |n| (kind.clone(), n))
        }))
    }
}

impl Detector for DictionaryDetector {
    fn id(&self) -> DetectorId {
        DetectorId::Dictionary
    }

    /// Searches the whitespace-collapsed text (any whitespace run matches a
    /// single space in an entry) for every overlapping match, keeps the
    /// word-bounded ones, and resolves them to a non-overlapping set,
    /// longest first (then earliest, then highest confidence). Offsets are
    /// mapped back to `text`.
    fn detect(&self, text: &str, _ctx: &DetectCtx) -> crate::Result<Vec<Span>> {
        if self.ac.is_none() {
            return Ok(Vec::new());
        }
        let view = Collapsed::new(text);
        let mut cands = self.candidates(&view);
        cands.sort_by(|a, b| {
            (b.1 - b.0)
                .cmp(&(a.1 - a.0))
                .then(a.0.cmp(&b.0))
                .then(self.meta[b.2].1.total_cmp(&self.meta[a.2].1))
        });
        let mut accepted: BTreeMap<usize, usize> = BTreeMap::new();
        let mut picked: Vec<(usize, usize, usize)> = Vec::new();
        for (start, end, idx) in cands {
            if overlaps_accepted(&accepted, start, end) {
                continue;
            }
            accepted.insert(start, end);
            picked.push((start, end, idx));
        }
        picked.sort_by_key(|p| p.0);
        Ok(picked.into_iter().map(|p| self.span_of(&view, p)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::span::EntityKind as K;

    fn det() -> DictionaryDetector {
        DictionaryDetector::from_entries(vec![
            (K::Person, "Sarah Leitner".to_string()),
            (K::Person, "Thomas May".to_string()),
            (K::Person, "Max Berg".to_string()),
            (K::Organization, "Example GmbH".to_string()),
            (K::StreetAddress, "Neubaugasse 22".to_string()),
        ])
        .unwrap()
    }

    fn found(text: &str) -> Vec<(K, String, f32)> {
        det()
            .detect(text, &DetectCtx::for_text(text))
            .unwrap()
            .into_iter()
            .map(|s| (s.kind.clone(), s.slice(text).to_string(), s.confidence))
            .collect()
    }

    #[test]
    fn full_name_case_insensitive_and_umlaut_safe() {
        let v = found("Frau SARAH LEITNER wohnt in der neubaugasse 22.");
        assert!(
            v.iter().any(|(k, t, c)| *k == K::Person
                && t == "SARAH LEITNER"
                && (*c - 0.97).abs() < 1e-6)
        );
        assert!(
            v.iter()
                .any(|(k, t, _)| *k == K::StreetAddress && t == "neubaugasse 22")
        );
    }

    #[test]
    fn surname_alone_has_lower_confidence() {
        let v = found("Frau Leitner hat angerufen.");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].1, "Leitner");
        assert!((v[0].2 - 0.80).abs() < 1e-6);
    }

    #[test]
    fn common_word_surnames_are_not_emitted_alone() {
        assert!(found("In May we go to the Berg.").is_empty());
        assert_eq!(found("Thomas May called.").len(), 1);
    }

    #[test]
    fn word_boundaries_respected() {
        assert!(found("Leitnerstraße 5").is_empty());
        assert!(
            found("sarah@example.at").is_empty(),
            "surname inside token must not match"
        );
        assert_eq!(found("(Leitner)").len(), 1);
    }

    #[test]
    fn leftmost_longest_prefers_full_name() {
        let v = found("Sarah Leitner");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].1, "Sarah Leitner");
    }

    /// I2: a rejected longer match ("Anna Berg" inside "Anna Bergmann")
    /// must not hide a shorter, word-bounded one ("Bergmann").
    #[test]
    fn rejected_longest_match_does_not_hide_bounded_shorter_match() {
        let d = DictionaryDetector::from_entries(vec![
            (K::Person, "Anna Berg".to_string()),
            (K::Person, "Karl Bergmann".to_string()),
        ])
        .unwrap();
        let text = "Termin mit Anna Bergmann";
        let v: Vec<(String, f32)> = d
            .detect(text, &DetectCtx::for_text(text))
            .unwrap()
            .into_iter()
            .map(|s| (s.slice(text).to_string(), s.confidence))
            .collect();
        assert!(
            v.iter()
                .any(|(t, c)| t == "Bergmann" && (*c - 0.80).abs() < 1e-6),
            "{v:?}"
        );
    }

    #[test]
    fn overlapping_matches_resolve_longest_first_without_overlap() {
        let d = DictionaryDetector::from_entries(vec![
            (K::Person, "Sarah Leitner".to_string()),
            (K::Organization, "Leitner Bau".to_string()),
        ])
        .unwrap();
        let text = "Sarah Leitner Bau";
        let spans = d.detect(text, &DetectCtx::for_text(text)).unwrap();
        assert_eq!(spans.len(), 1, "{spans:?}");
        assert_eq!(spans[0].slice(text), "Sarah Leitner");
    }

    /// I9: any whitespace run in the text matches a single space in an entry.
    #[test]
    fn whitespace_runs_match_single_spaces() {
        for (text, want, kind) in [
            ("Sarah\nLeitner", "Sarah\nLeitner", K::Person),
            ("Frau Sarah \t Leitner kam", "Sarah \t Leitner", K::Person),
            ("Neubaugasse\n22, Wien", "Neubaugasse\n22", K::StreetAddress),
            (
                "bei Example\u{00a0}GmbH",
                "Example\u{00a0}GmbH",
                K::Organization,
            ),
        ] {
            let v = found(text);
            assert!(
                v.iter().any(|(k, t, _)| *k == kind && t == want),
                "{text:?}: {v:?}"
            );
            assert_eq!(v.len(), 1, "{text:?}: {v:?}");
        }
        // entries with irregular whitespace are collapsed too
        let d = DictionaryDetector::from_entries(vec![(K::Person, "Max   Gruber".to_string())])
            .unwrap();
        let text = "Max Gruber";
        assert_eq!(d.detect(text, &DetectCtx::for_text(text)).unwrap().len(), 1);
    }

    #[test]
    fn empty_config_matches_nothing() {
        let d = DictionaryDetector::from_config(&DictionaryConfig::default()).unwrap();
        assert!(
            d.detect("Sarah Leitner", &DetectCtx::for_text(""))
                .unwrap()
                .is_empty()
        );
    }

    /// M4 spec §16.5: every variant of an alias line is matched like an entry.
    #[test]
    fn alias_lines_add_every_variant() {
        let dir = tempfile::tempdir().unwrap();
        let persons = dir.path().join("persons.txt");
        std::fs::write(
            &persons,
            "Hans-Peter Gruber | HP Gruber | Hansi\nSarah Leitner\n",
        )
        .unwrap();
        let cfg = DictionaryConfig {
            persons: vec![persons],
            addresses: vec![],
            organizations: vec![],
            aliases: vec![AliasEntry {
                kind: "ORGANIZATION".into(),
                names: vec!["Example GmbH".into(), "Example".into()],
            }],
        };
        let d = DictionaryDetector::from_config(&cfg).unwrap();
        let hits = |text: &str| -> Vec<(K, String, f32)> {
            d.detect(text, &DetectCtx::for_text(text))
                .unwrap()
                .into_iter()
                .map(|s| (s.kind.clone(), s.slice(text).to_string(), s.confidence))
                .collect()
        };
        for variant in ["Hans-Peter Gruber", "HP Gruber", "Hansi", "HANSI"] {
            let v = hits(&format!("Termin mit {variant} morgen"));
            assert!(
                v.iter()
                    .any(|(k, t, c)| *k == K::Person && t == variant && (*c - 0.97).abs() < 1e-6),
                "{variant}: {v:?}"
            );
        }
        let v = hits("Frau Gruber rief an");
        assert!(
            v.iter()
                .any(|(k, t, c)| *k == K::Person && t == "Gruber" && (*c - 0.80).abs() < 1e-6),
            "surname of a variant: {v:?}"
        );
        assert!(
            hits("Hans Peter Gruber")
                .iter()
                .all(|(_, t, _)| t == "Gruber"),
            "never fuzzy: the hyphenless form matches only through the surname rule"
        );
        assert!(
            hits("bei Example seit 2020")
                .iter()
                .any(|(k, t, _)| *k == K::Organization && t == "Example")
        );
        // organization and address files are never split: a `|` is part of the name
        let orgs = dir.path().join("orgs.txt");
        std::fs::write(&orgs, "Bau | Holz GmbH\n").unwrap();
        let cfg2 = DictionaryConfig {
            persons: vec![],
            addresses: vec![],
            organizations: vec![orgs],
            aliases: vec![],
        };
        let d2 = DictionaryDetector::from_config(&cfg2).unwrap();
        let text = "Auftrag an Bau | Holz GmbH heute";
        let v: Vec<String> = d2
            .detect(text, &DetectCtx::for_text(text))
            .unwrap()
            .iter()
            .map(|s| s.slice(text).to_string())
            .collect();
        assert_eq!(v, ["Bau | Holz GmbH"]);
        assert_eq!(split_alias_line("a | b|c ").unwrap(), ["a", "b", "c"]);
        assert_eq!(
            split_alias_line("Sarah Leitner").unwrap(),
            ["Sarah Leitner"]
        );
        assert!(split_alias_line("a | | b").is_err());
        assert!(split_alias_line("a |").is_err());
    }

    #[test]
    fn detect_all_reports_every_overlapping_match() {
        let d = DictionaryDetector::from_entries(vec![
            (K::Person, "Qorvex Brandl".to_string()),
            (K::Organization, "Brandl Holding".to_string()),
        ])
        .unwrap();
        let text = "Gruss an Qorvex Brandl Holding.";
        let ctx = DetectCtx::for_text(text);
        let one = d.detect(text, &ctx).unwrap();
        assert_eq!(one.len(), 1, "detect still resolves to one: {one:?}");
        let all = d.detect_all(text).unwrap();
        assert!(
            all.iter()
                .any(|s| s.kind == K::Person && s.slice(text) == "Qorvex Brandl"),
            "{all:?}"
        );
        assert!(
            all.iter()
                .any(|s| s.kind == K::Organization && s.slice(text) == "Brandl Holding"),
            "{all:?}"
        );
        assert!(
            all.windows(2)
                .all(|w| (w[0].start, w[0].end) <= (w[1].start, w[1].end)),
            "sorted by (start, end)"
        );
    }

    #[test]
    fn debug_output_omits_dictionary_entries() {
        let dbg = format!("{:?}", det());
        for leaked in [
            "Sarah",
            "Leitner",
            "Thomas",
            "May",
            "Berg",
            "Example",
            "Neubaugasse",
        ] {
            assert!(!dbg.contains(leaked), "debug output leaked {leaked}: {dbg}");
        }
        assert!(dbg.contains("patterns"));
    }
}
