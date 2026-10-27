//! Dictionary alias groups (M4 spec §16.5, engine spec §6.1 amendment):
//! variants of one entity that no model would link (`Hans-Peter Gruber |
//! HP Gruber | Hansi`). A variant is an exact phrase after
//! [`normalize`]; nothing here is fuzzy. A variant mints a surface token
//! under the group's first-listed name (plan 4a): same entity suffix, its own
//! text. The store keeps the canonical row unchanged and adds the variant's
//! row next to it, so every variant restores to the text that was replaced.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::{Hash, Hasher};

use crate::detect::dictionary::{DictionaryConfig, read_groups};
use crate::span::EntityKind;
use crate::token::{StoreError, Token, TokenStore, normalize, parse_token};
use crate::{Error, Result, TokenSettings};

/// One entity with its listed spellings; `names[0]` is the canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasGroup {
    /// Kind every name is detected as.
    pub kind: EntityKind,
    /// First-listed name first.
    pub names: Vec<String>,
}

/// Every alias group of a configuration, indexed for lookup.
///
/// The maps below hold configuration names (from `persons.txt` files and
/// `[[dictionary.aliases]]`), not request data: they are plain `String`s,
/// not zeroizing [`crate::token::NormKey`]s, because they never see an
/// original value from a live request.
#[derive(Clone, Default)]
pub struct AliasTable {
    groups: Vec<AliasGroup>,
    /// kind label → normalized name → group index, for every name.
    by_key: HashMap<String, HashMap<String, usize>>,
    /// kind label → canonical as written → group index. Nested maps so a
    /// lookup borrows `&str`s and allocates nothing (the leak check calls
    /// `variants_of` once per working-set entry).
    by_canonical: HashMap<String, HashMap<String, usize>>,
    /// [`AliasTable::fingerprint`]; 0 for no groups.
    fingerprint: u64,
}

impl fmt::Debug for AliasTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AliasTable")
            .field("groups", &self.groups.len())
            .finish()
    }
}

impl AliasTable {
    /// No groups.
    pub fn empty() -> Self {
        AliasTable::default()
    }

    /// Index `groups`. Groups with fewer than two names are plain
    /// dictionary entries: they are not aliases, but they take part in the
    /// collision check. A normalized name that appears in two groups of the
    /// same kind, twice in one group, or both as a plain entry and in a
    /// group, is a configuration error: linking is never a guess.
    pub fn build(groups: impl IntoIterator<Item = AliasGroup>) -> Result<Self> {
        let mut t = AliasTable::default();
        let mut singles: HashMap<String, HashSet<String>> = HashMap::new();
        let mut multi: Vec<AliasGroup> = Vec::new();
        for g in groups {
            if g.names.len() < 2 {
                for name in &g.names {
                    singles
                        .entry(g.kind.label().to_string())
                        .or_default()
                        .insert(normalize(name).as_str().to_string());
                }
            } else {
                multi.push(g);
            }
        }
        for g in multi {
            let label = g.kind.label().to_string();
            let idx = t.groups.len();
            for name in &g.names {
                let key = normalize(name).as_str().to_string();
                if key.is_empty() {
                    return Err(Error::ConfigInvalid(
                        "dictionary.aliases: empty name".into(),
                    ));
                }
                if singles.get(&label).is_some_and(|s| s.contains(&key)) {
                    return Err(Error::ConfigInvalid(format!(
                        "dictionary.aliases: a {label} name is both a plain entry and in a group"
                    )));
                }
                if t.by_key
                    .entry(label.clone())
                    .or_default()
                    .insert(key, idx)
                    .is_some()
                {
                    return Err(Error::ConfigInvalid(format!(
                        "dictionary.aliases: a {label} name is listed in two groups"
                    )));
                }
            }
            t.by_canonical
                .entry(label)
                .or_default()
                .insert(g.names[0].clone(), idx);
            t.groups.push(g);
        }
        if !t.groups.is_empty() {
            // Configuration names, not request data: a plain hash is fine.
            let mut h = std::hash::DefaultHasher::new();
            for g in &t.groups {
                (g.kind.label(), &g.names).hash(&mut h);
            }
            t.fingerprint = h.finish().max(1);
        }
        Ok(t)
    }

    /// Groups from the dictionary files (` | ` lines) and `[[dictionary.aliases]]`.
    pub fn from_config(cfg: &DictionaryConfig) -> Result<Self> {
        Self::build(read_groups(cfg)?)
    }

    /// True when no group is defined.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Number of groups.
    pub fn len(&self) -> usize {
        self.groups.len()
    }

    /// Identifies the groups (Task 7e): equal for equal groups, 0 when
    /// there are none, otherwise nonzero. A store's cached consistency
    /// dictionary is kept only for the alias view it was built through.
    pub fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    /// The group's first-listed name when `text` (normalized) is one of a
    /// group's names of `kind`.
    pub fn canonical(&self, kind: &EntityKind, text: &str) -> Option<&str> {
        let by_name = self.by_key.get(kind.label())?;
        let key = normalize(text);
        by_name
            .get(key.as_str())
            .map(|&i| self.groups[i].names[0].as_str())
    }

    /// The other names of the group whose canonical is exactly `canonical`.
    /// Allocation-free: called once per working-set entry by the leak check.
    pub fn variants_of(&self, kind: &EntityKind, canonical: &str) -> &[String] {
        match self
            .by_canonical
            .get(kind.label())
            .and_then(|m| m.get(canonical))
        {
            Some(&i) => &self.groups[i].names[1..],
            None => &[],
        }
    }

    /// Every `(kind, canonical)` whose group lists `text`, across kinds.
    pub fn canonicals_for(&self, text: &str) -> Vec<(EntityKind, &str)> {
        let norm = normalize(text);
        self.groups
            .iter()
            .filter(|g| g.names.iter().any(|n| normalize(n) == norm))
            .map(|g| (g.kind.clone(), g.names[0].as_str()))
            .collect()
    }
}

/// A [`TokenStore`] that maps alias variants to their canonical before the
/// inner store mints, and reports the variants next to every canonical
/// entry so the leak check sees them.
pub struct Aliased<'a> {
    inner: &'a mut dyn TokenStore,
    table: &'a AliasTable,
}

impl<'a> Aliased<'a> {
    /// Wrap `inner`.
    pub fn new(inner: &'a mut dyn TokenStore, table: &'a AliasTable) -> Self {
        Aliased { inner, table }
    }

    /// The group's first-listed name for a variant, else `original` itself.
    fn resolve(&self, kind: &EntityKind, original: &str) -> String {
        self.table
            .canonical(kind, original)
            .unwrap_or(original)
            .to_string()
    }
}

impl fmt::Debug for Aliased<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aliased")
            .field("groups", &self.table.len())
            .finish()
    }
}

impl TokenStore for Aliased<'_> {
    fn token_for(
        &mut self,
        kind: &EntityKind,
        original: &str,
    ) -> std::result::Result<Token, StoreError> {
        // The canonical entity is minted under its listed spelling; any other
        // spelling of it (a variant, or the canonical in other casing) is a
        // surface form of that entity, so it restores to its own text.
        let table = self.table;
        match table.canonical(kind, original) {
            Some(canonical) if canonical != original => {
                let parent = self.inner.token_for(kind, canonical)?;
                self.inner.surface_token(&parent, original)
            }
            _ => self.inner.token_for(kind, original),
        }
    }

    fn original(&self, token: &str) -> Option<&str> {
        self.inner.original(token)
    }

    fn entries(&self) -> Box<dyn Iterator<Item = (&EntityKind, &str)> + '_> {
        let table = self.table;
        Box::new(self.inner.entries().flat_map(move |(k, o)| {
            std::iter::once((k, o))
                .chain(table.variants_of(k, o).iter().map(move |v| (k, v.as_str())))
        }))
    }

    fn record_removed(
        &mut self,
        kind: &EntityKind,
        original: &str,
    ) -> std::result::Result<(), StoreError> {
        let canonical = self.resolve(kind, original);
        self.inner.record_removed(kind, &canonical)
    }

    fn removed_entries(&self) -> Box<dyn Iterator<Item = (&EntityKind, &str)> + '_> {
        let table = self.table;
        Box::new(self.inner.removed_entries().flat_map(move |(k, o)| {
            std::iter::once((k, o))
                .chain(table.variants_of(k, o).iter().map(move |v| (k, v.as_str())))
        }))
    }

    fn removed_marker(&self, kind: &EntityKind) -> String {
        self.inner.removed_marker(kind)
    }

    fn settings(&self) -> &TokenSettings {
        self.inner.settings()
    }

    fn prepare(&mut self, tokens: &[String]) -> std::result::Result<(), StoreError> {
        self.inner.prepare(tokens)
    }

    /// A parent that is itself a surface token of an alias variant (the
    /// linker chose `HP Gruber` as the document's full name) resolves to the
    /// group's canonical entity: the store answers `UnknownParent` for a
    /// surface parent, the wrapper reads the parent's text back, maps it to
    /// the canonical, and mints the surface under the canonical's token.
    fn surface_token(
        &mut self,
        parent: &Token,
        surface: &str,
    ) -> std::result::Result<Token, StoreError> {
        match self.inner.surface_token(parent, surface) {
            Err(StoreError::UnknownParent) => {
                let parsed = parse_token(self.inner.settings(), parent.as_str())
                    .ok_or(StoreError::UnknownParent)?;
                let kind = EntityKind::from_label(parsed.label);
                // a parent evicted from a lazily loading store
                self.inner.prepare(&[parent.as_str().to_string()])?;
                let variant = self
                    .inner
                    .original(parent.as_str())
                    .ok_or(StoreError::UnknownParent)?
                    .to_string();
                let canonical = self
                    .table
                    .canonical(&kind, &variant)
                    .ok_or(StoreError::UnknownParent)?
                    .to_string();
                let canon = self.inner.token_for(&kind, &canonical)?;
                self.inner.surface_token(&canon, surface)
            }
            r => r,
        }
    }

    /// The inner store's cached dictionary through this table (Task 7e).
    /// A second alias view on top is not cached: the caller builds its own.
    fn store_dict(
        &mut self,
        aliases: Option<&AliasTable>,
    ) -> Option<Result<crate::consistency::StoreDict>> {
        match aliases {
            Some(t) if !t.is_empty() => None,
            _ => self.inner.store_dict(Some(self.table)),
        }
    }

    /// The inner store's cached leak index through this table (Task 5), as
    /// `store_dict`.
    fn leak_index(
        &mut self,
        aliases: Option<&AliasTable>,
    ) -> Option<Result<crate::verify::LeakIndex>> {
        match aliases {
            Some(t) if !t.is_empty() => None,
            _ => self.inner.leak_index(Some(self.table)),
        }
    }

    fn link_candidates(
        &self,
        kind: &EntityKind,
        window: std::time::Duration,
    ) -> Vec<zeroize::Zeroizing<String>> {
        self.inner.link_candidates(kind, window)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::dictionary::AliasEntry;
    use crate::span::EntityKind as K;
    use crate::token::{Context, ContextId};
    use std::time::Duration;

    fn gruber() -> AliasGroup {
        AliasGroup {
            kind: K::Person,
            names: vec![
                "Hans-Peter Gruber".into(),
                "HP Gruber".into(),
                "Hansi".into(),
            ],
        }
    }

    fn ctx() -> Context {
        Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            TokenSettings::default(),
        )
    }

    /// A surface token minted through the alias wrapper hangs off the
    /// canonical entity's token and restores to the exact surface text.
    #[test]
    fn surface_token_forwards_to_the_inner_store() {
        let table = AliasTable::build(vec![gruber()]).unwrap();
        let mut c = ctx();
        let mut store = Aliased::new(&mut c, &table);
        let parent = store.token_for(&K::Person, "Hansi").unwrap();
        let surface = store.surface_token(&parent, "Hansi").unwrap();
        assert_eq!(store.original(surface.as_str()), Some("Hansi"));
    }

    #[test]
    fn canonical_is_the_first_listed_name_after_normalization_only() {
        let t = AliasTable::build(vec![gruber()]).unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(
            t.canonical(&K::Person, "HP Gruber"),
            Some("Hans-Peter Gruber")
        );
        assert_eq!(
            t.canonical(&K::Person, "hp  gruber"),
            Some("Hans-Peter Gruber"),
            "case and whitespace"
        );
        assert_eq!(t.canonical(&K::Person, "HANSI"), Some("Hans-Peter Gruber"));
        assert_eq!(
            t.canonical(&K::Person, "Hans-Peter Gruber"),
            Some("Hans-Peter Gruber"),
            "the canonical maps to itself"
        );
        assert_eq!(
            t.canonical(&K::Person, "Hans Peter Gruber"),
            None,
            "a hyphen is not a space: never fuzzy"
        );
        assert_eq!(t.canonical(&K::Person, "Hans"), None, "no prefix matching");
        assert_eq!(
            t.canonical(&K::Organization, "Hansi"),
            None,
            "kinds do not mix"
        );
        assert_eq!(
            t.variants_of(&K::Person, "Hans-Peter Gruber"),
            ["HP Gruber", "Hansi"]
        );
        assert!(
            t.variants_of(&K::Person, "HP Gruber").is_empty(),
            "variants are listed under the canonical only"
        );
        assert_eq!(
            t.canonicals_for("hansi"),
            vec![(K::Person, "Hans-Peter Gruber")]
        );
        assert!(t.canonicals_for("Sarah Leitner").is_empty());
        assert!(!format!("{t:?}").contains("Gruber"));
    }

    #[test]
    fn variant_in_two_groups_is_a_config_error() {
        let other = AliasGroup {
            kind: K::Person,
            names: vec!["Hans Maier".into(), "Hansi".into()],
        };
        let e = AliasTable::build(vec![gruber(), other]).unwrap_err();
        assert!(format!("{e}").contains("dictionary.aliases"), "{e}");
        assert!(
            !format!("{e}").contains("Hansi"),
            "the name is not in the message: {e}"
        );
        // a variant equal to another group's canonical
        let clash = AliasGroup {
            kind: K::Person,
            names: vec!["Peter Huber".into(), "hans-peter gruber".into()],
        };
        assert!(AliasTable::build(vec![gruber(), clash]).is_err());
        // twice in one group
        let twice = AliasGroup {
            kind: K::Person,
            names: vec!["A B".into(), "a  b".into()],
        };
        assert!(AliasTable::build(vec![twice]).is_err());
        // the same name under another kind is a different entity and is allowed
        let org = AliasGroup {
            kind: K::Organization,
            names: vec!["Gruber Bau".into(), "Hansi".into()],
        };
        assert_eq!(AliasTable::build(vec![gruber(), org]).unwrap().len(), 2);
        // one-name groups are plain entries, not aliases
        let single = AliasGroup {
            kind: K::Person,
            names: vec!["Sarah Leitner".into()],
        };
        assert!(AliasTable::build(vec![single]).unwrap().is_empty());
        let empty = AliasGroup {
            kind: K::Person,
            names: vec!["A B".into(), "   ".into()],
        };
        assert!(AliasTable::build(vec![empty]).is_err());
    }

    /// Review Focus 1, plain lines: a name that is both a plain dictionary
    /// entry and a member of a group would make the plain entry mint its own
    /// token while the group's other variants share another; refuse it.
    #[test]
    fn plain_line_colliding_with_a_group_is_a_config_error() {
        let plain = AliasGroup {
            kind: K::Person,
            names: vec!["hansi".into()],
        };
        let e = AliasTable::build(vec![plain.clone(), gruber()]).unwrap_err();
        assert!(format!("{e}").contains("plain entry"), "{e}");
        assert!(!format!("{e}").contains("hansi"), "{e}");
        assert!(
            AliasTable::build(vec![gruber(), plain]).is_err(),
            "order does not matter"
        );
        let canonical_twice = AliasGroup {
            kind: K::Person,
            names: vec!["Hans-Peter  Gruber".into()],
        };
        assert!(
            AliasTable::build(vec![gruber(), canonical_twice]).is_err(),
            "the canonical as a plain line too"
        );
        let other_kind = AliasGroup {
            kind: K::Organization,
            names: vec!["Hansi".into()],
        };
        assert_eq!(
            AliasTable::build(vec![gruber(), other_kind]).unwrap().len(),
            1,
            "another kind is another entity"
        );
    }

    #[test]
    fn variants_share_the_entity_suffix_and_restore_to_their_own_text() {
        let t = AliasTable::build(vec![gruber()]).unwrap();
        let mut c = ctx();
        let mut a = Aliased::new(&mut c, &t);
        let full = a.token_for(&K::Person, "Hans-Peter Gruber").unwrap();
        let short = a.token_for(&K::Person, "HP Gruber").unwrap();
        let nick = a.token_for(&K::Person, "hansi").unwrap();
        assert_ne!(full, short);
        assert_ne!(full, nick);
        let (pf, ps, pn) = (
            parse_token(a.settings(), full.as_str()).unwrap(),
            parse_token(a.settings(), short.as_str()).unwrap(),
            parse_token(a.settings(), nick.as_str()).unwrap(),
        );
        assert_eq!(ps.suffix, pf.suffix);
        assert_eq!(pn.suffix, pf.suffix);
        assert!(
            pf.variant.is_none()
                && ps.variant.is_some()
                && pn.variant.is_some()
                && ps.variant != pn.variant
        );
        assert_eq!(a.original(full.as_str()), Some("Hans-Peter Gruber"));
        assert_eq!(a.original(short.as_str()), Some("HP Gruber"));
        assert_eq!(
            a.original(nick.as_str()),
            Some("hansi"),
            "the text as written, not the listed spelling"
        );
        // R9: the key is the exact text, so the same text reuses its row and
        // another casing is a row of its own that restores to that casing.
        assert_eq!(a.token_for(&K::Person, "hansi").unwrap(), nick);
        let cap = a.token_for(&K::Person, "Hansi").unwrap();
        assert_ne!(cap, nick);
        assert_eq!(a.original(cap.as_str()), Some("Hansi"));
        // the canonical written with other casing is a surface form too
        let upper = a.token_for(&K::Person, "HANS-PETER GRUBER").unwrap();
        assert!(
            parse_token(a.settings(), upper.as_str())
                .unwrap()
                .variant
                .is_some()
        );
        assert_ne!(upper, short);
        assert_ne!(upper, nick);
        assert_eq!(a.original(upper.as_str()), Some("HANS-PETER GRUBER"));
        // the leak check sees every listed variant next to the canonical
        let entries: Vec<String> = a.entries().map(|(_, o)| o.to_string()).collect();
        for want in ["Hans-Peter Gruber", "HP Gruber", "Hansi"] {
            assert!(entries.iter().any(|e| e == want), "{want} in {entries:?}");
        }
        assert!(!format!("{a:?}").contains("Gruber"));
        assert_eq!(
            c.len(),
            5,
            "one entity and four surface rows in the inner store"
        );
    }

    /// Review Focus 10: a variant full name as link parent.
    #[test]
    fn variant_parents_resolve_to_the_canonical() {
        let t = AliasTable::build(vec![gruber()]).unwrap();
        let mut c = ctx();
        let mut a = Aliased::new(&mut c, &t);
        let hp = a.token_for(&K::Person, "HP Gruber").unwrap();
        let sur = a.surface_token(&hp, "Gruber").unwrap();
        let canon = a.token_for(&K::Person, "Hans-Peter Gruber").unwrap();
        let (pc, ph, ps) = (
            parse_token(a.settings(), canon.as_str()).unwrap(),
            parse_token(a.settings(), hp.as_str()).unwrap(),
            parse_token(a.settings(), sur.as_str()).unwrap(),
        );
        assert_eq!(ph.suffix, pc.suffix);
        assert_eq!(
            ps.suffix, pc.suffix,
            "the surname is a surface form of the canonical entity"
        );
        assert_ne!(sur, hp);
        assert_eq!(a.original(sur.as_str()), Some("Gruber"));
        // a parent that is neither known nor a variant is still refused
        assert_eq!(
            a.surface_token(&Token::from("<PERSON_0000>".to_string()), "x"),
            Err(StoreError::UnknownParent)
        );
    }

    /// Fix round 1: `removed_entries()` must expand through `variants_of`
    /// exactly as `entries()` does, since `TokenStore::removed_entries`
    /// feeds the leak check the same way (a policy can set a `PERSON` kind
    /// to `Remove`); otherwise a variant of a removed canonical that no
    /// detector catches is missing from the leak check's pattern set.
    #[test]
    fn removed_entries_expand_through_variants_too() {
        let t = AliasTable::build(vec![gruber()]).unwrap();
        let mut c = ctx();
        let mut a = Aliased::new(&mut c, &t);
        a.record_removed(&K::Person, "HP Gruber").unwrap();
        let removed: Vec<(String, String)> = a
            .removed_entries()
            .map(|(k, o)| (k.label().to_string(), o.to_string()))
            .collect();
        assert_eq!(
            removed,
            [
                ("PERSON".to_string(), "Hans-Peter Gruber".to_string()),
                ("PERSON".into(), "HP Gruber".into()),
                ("PERSON".into(), "Hansi".into())
            ],
            "a variant of the removed canonical is in the leak check's pattern set"
        );
    }

    #[test]
    fn empty_table_is_transparent() {
        let t = AliasTable::empty();
        let mut c = ctx();
        let mut a = Aliased::new(&mut c, &t);
        let x = a.token_for(&K::Person, "HP Gruber").unwrap();
        assert_eq!(a.original(x.as_str()), Some("HP Gruber"));
        assert_eq!(a.entries().count(), 1);
    }

    #[test]
    fn from_config_reads_alias_lines_and_config_groups() {
        let dir = tempfile::tempdir().unwrap();
        let persons = dir.path().join("persons.txt");
        std::fs::write(
            &persons,
            "Sarah Leitner\n# comment\nHans-Peter Gruber | HP Gruber | Hansi\n\nMax Berg|Maxi\n",
        )
        .unwrap();
        let cfg = DictionaryConfig {
            persons: vec![persons.clone()],
            addresses: vec![],
            organizations: vec![],
            aliases: vec![AliasEntry {
                kind: "ORGANIZATION".into(),
                names: vec!["Example GmbH".into(), "Example".into()],
            }],
        };
        let t = AliasTable::from_config(&cfg).unwrap();
        assert_eq!(
            t.len(),
            3,
            "two alias lines plus one config group; the plain line is not a group"
        );
        assert_eq!(
            t.canonical(&K::Person, "Maxi"),
            Some("Max Berg"),
            "spacing around | is free"
        );
        assert_eq!(
            t.canonical(&K::Organization, "example"),
            Some("Example GmbH")
        );
        std::fs::write(&persons, "Hans-Peter Gruber | | Hansi\n").unwrap();
        let e = AliasTable::from_config(&cfg).unwrap_err();
        assert!(format!("{e}").contains("dictionary"), "{e}");
        let bad_kind = DictionaryConfig {
            persons: vec![],
            addresses: vec![],
            organizations: vec![],
            aliases: vec![AliasEntry {
                kind: "".into(),
                names: vec!["a".into(), "b".into()],
            }],
        };
        assert!(
            AliasTable::from_config(&bad_kind).is_err(),
            "an empty kind label is refused"
        );
        let digit_kind = DictionaryConfig {
            persons: vec![],
            addresses: vec![],
            organizations: vec![],
            aliases: vec![AliasEntry {
                kind: "KUNDEN_NR2".into(),
                names: vec!["a".into(), "b".into()],
            }],
        };
        assert!(
            AliasTable::from_config(&digit_kind).is_err(),
            "a kind label with a digit is refused (M4 spec §16.4)"
        );
    }
}
