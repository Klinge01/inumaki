//! Known-entity detector: the namespace's own originals as a dictionary
//! (spec §7). A main automaton is built at open and rebuilt in the
//! background after [`REBUILD_AFTER`] new mints; a delta automaton covers
//! entries minted since the last build. Pattern bytes inside an automaton
//! cannot be zeroized (engine spec §6.5 caveat); both are dropped on
//! rotation and when the namespace closes.

use std::borrow::Cow;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use inumaki_core::alias::AliasTable;
use inumaki_core::detect::dictionary::DictionaryDetector;
use inumaki_core::detect::{DetectCtx, Detector};
use inumaki_core::span::{DetectorId, EntityKind, Span};
use zeroize::Zeroizing;

use crate::error::VaultError;

/// New mints after which the main automaton is rebuilt.
pub const REBUILD_AFTER: usize = 256;

/// Kinds the automaton is built from.
pub const KNOWN_KINDS: [EntityKind; 7] = [
    EntityKind::Person,
    EntityKind::Organization,
    EntityKind::StreetAddress,
    EntityKind::Email,
    EntityKind::CustomerId,
    EntityKind::ContractId,
    EntityKind::InvoiceId,
];

/// True for kinds in [`KNOWN_KINDS`].
pub fn is_known_kind(kind: &EntityKind) -> bool {
    KNOWN_KINDS.contains(kind)
}

/// True when a minted original belongs in the known-entity automaton (and
/// so in the cache re-check, the release check, and the tripwire): a known
/// kind, and for PERSON at least two name parts. A one-part PERSON entity
/// (an unlinked or ambiguous bare first name or surname) would otherwise be
/// a full-match dictionary hit that outranks NER and splits the next
/// document's `Sarah Gruber`, and M4 spec §16.1 forbids first-name-only
/// tripwire hits.
pub fn is_known_entity(kind: &EntityKind, original: &str) -> bool {
    is_known_kind(kind) && (*kind != EntityKind::Person || original.split_whitespace().count() >= 2)
}

/// SQL list of [`KNOWN_KINDS`] labels.
pub(crate) const KNOWN_KINDS_SQL: &str =
    "('PERSON','ORGANIZATION','STREET_ADDRESS','EMAIL','CUSTOMER_ID','CONTRACT_ID','INVOICE_ID')";

fn build(
    entries: &[(EntityKind, Zeroizing<String>)],
    aliases: &AliasTable,
) -> Result<DictionaryDetector, VaultError> {
    DictionaryDetector::from_entries(entries.iter().flat_map(|(k, s)| {
        std::iter::once((k.clone(), Cow::Borrowed(s.as_str()))).chain(
            aliases
                .variants_of(k, s)
                .iter()
                .map(move |v| (k.clone(), Cow::Owned(v.clone()))),
        )
    }))
    .map_err(|_| VaultError::Automaton)
}

/// Dictionary detector over a namespace's known entities.
pub struct KnownEntityDetector {
    main: RwLock<Arc<DictionaryDetector>>,
    main_size: AtomicUsize,
    delta_entries: Mutex<Vec<(EntityKind, Zeroizing<String>)>>,
    delta: RwLock<Option<Arc<DictionaryDetector>>>,
    generation: AtomicU64,
    /// Alias groups stored originals are expanded through (M4 spec §16.5).
    aliases: Arc<AliasTable>,
}

impl std::fmt::Debug for KnownEntityDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KnownEntityDetector")
            .field("main", &self.main_size.load(Ordering::Relaxed))
            .field("pending", &self.pending())
            .field("generation", &self.generation.load(Ordering::Relaxed))
            .field("alias_groups", &self.aliases.len())
            .finish()
    }
}

impl KnownEntityDetector {
    /// Main automaton from `entries`, expanded through `aliases`.
    pub fn build(
        entries: Vec<(EntityKind, Zeroizing<String>)>,
        aliases: Arc<AliasTable>,
    ) -> Result<Self, VaultError> {
        let main = build(&entries, &aliases)?;
        Ok(KnownEntityDetector {
            main: RwLock::new(Arc::new(main)),
            main_size: AtomicUsize::new(entries.len()),
            delta_entries: Mutex::new(Vec::new()),
            delta: RwLock::new(None),
            generation: AtomicU64::new(0),
            aliases,
        })
        // `entries` drops here; each `Zeroizing<String>` is wiped.
    }

    /// Add a freshly minted entry to the delta automaton. Returns how many
    /// entries the delta holds.
    pub fn push(&self, kind: &EntityKind, original: &str) -> Result<usize, VaultError> {
        let mut pending = self
            .delta_entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        pending.push((kind.clone(), Zeroizing::new(original.to_string())));
        let ac = build(&pending, &self.aliases)?;
        *self.delta.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(ac));
        Ok(pending.len())
    }

    /// Entries in the delta automaton.
    pub fn pending(&self) -> usize {
        self.delta_entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Entries in the main automaton.
    pub fn size(&self) -> usize {
        self.main_size.load(Ordering::Relaxed)
    }

    /// Times the main automaton was replaced.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Swap in a new main automaton built from `entries` and drop the first
    /// `seen` delta entries (the ones the caller's row snapshot already
    /// covers), unless `expected` names a generation that is no longer
    /// current. The check and the swap happen under the delta lock, so they
    /// are one step: a `replace` and a `replace_if` never interleave between
    /// the check and the swap. Shared by [`KnownEntityDetector::replace`]
    /// and [`KnownEntityDetector::replace_if`].
    fn swap(
        &self,
        entries: Vec<(EntityKind, Zeroizing<String>)>,
        seen: usize,
        expected: Option<u64>,
    ) -> Result<bool, VaultError> {
        let main = build(&entries, &self.aliases)?;
        let mut pending = self
            .delta_entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(expected) = expected {
            if self.generation.load(Ordering::Acquire) != expected {
                return Ok(false);
            }
        }
        let at = seen.min(pending.len());
        let keep = pending.split_off(at);
        *pending = keep; // the drained prefix drops here, zeroized
        let delta = if pending.is_empty() {
            None
        } else {
            Some(Arc::new(build(&pending, &self.aliases)?))
        };
        *self.main.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(main);
        self.main_size.store(entries.len(), Ordering::Relaxed);
        *self.delta.write().unwrap_or_else(PoisonError::into_inner) = delta;
        self.generation.fetch_add(1, Ordering::AcqRel);
        Ok(true)
    }

    /// Swap in a new main automaton built from `entries` and drop the first
    /// `seen` delta entries (the ones the caller's row snapshot already
    /// covers). Entries pushed after the snapshot stay in the delta, so an
    /// entity minted during a background rebuild is never undetected
    /// (review I3, spec §4.1).
    pub fn replace(
        &self,
        entries: Vec<(EntityKind, Zeroizing<String>)>,
        seen: usize,
    ) -> Result<(), VaultError> {
        self.swap(entries, seen, None).map(|_| ())
    }

    /// [`KnownEntityDetector::replace`] only when the main automaton's
    /// generation still equals `expected`; `Ok(false)` when another rebuild
    /// (a forget, a rotation) got there first and `entries` may be stale.
    /// The check and the swap happen under the delta lock, so they are one
    /// step.
    pub fn replace_if(
        &self,
        entries: Vec<(EntityKind, Zeroizing<String>)>,
        seen: usize,
        expected: u64,
    ) -> Result<bool, VaultError> {
        self.swap(entries, seen, Some(expected))
    }
}

impl Detector for KnownEntityDetector {
    fn id(&self) -> DetectorId {
        DetectorId::Dictionary
    }

    fn detect(&self, text: &str, ctx: &DetectCtx) -> inumaki_core::Result<Vec<Span>> {
        let main = Arc::clone(&self.main.read().unwrap_or_else(PoisonError::into_inner));
        let delta = self
            .delta
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let mut spans = main.detect(text, ctx)?;
        if let Some(d) = delta {
            spans.extend(d.detect(text, ctx)?);
        }
        Ok(spans)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_prints_counts_only() {
        let d = KnownEntityDetector::build(
            vec![(
                EntityKind::Person,
                Zeroizing::new("Zyxwuria Quolnath".into()),
            )],
            Arc::new(AliasTable::empty()),
        )
        .unwrap();
        let s = format!("{d:?}");
        assert!(!s.contains("Zyxwuria"), "{s}");
        assert!(s.contains("main: 1"));
    }

    #[test]
    fn known_kinds_are_the_identifying_ones() {
        assert!(is_known_kind(&EntityKind::Person));
        assert!(is_known_kind(&EntityKind::InvoiceId));
        assert!(!is_known_kind(&EntityKind::City));
        assert!(!is_known_kind(&EntityKind::Iban));
    }

    /// Review item 2: a background rebuild that read its rows before a
    /// forget must not swap them in after the forget's synchronous rebuild.
    #[test]
    fn stale_rebuild_does_not_resurrect_a_forgotten_entity() {
        use std::sync::Barrier;
        let aliases = Arc::new(AliasTable::empty());
        let canary = || {
            (
                EntityKind::Person,
                Zeroizing::new("Zyxwuria Quolnath".to_string()),
            )
        };
        let d = Arc::new(KnownEntityDetector::build(vec![canary()], Arc::clone(&aliases)).unwrap());
        let before = Arc::new(Barrier::new(2));
        let after = Arc::new(Barrier::new(2));
        let (d2, b1, b2) = (Arc::clone(&d), Arc::clone(&before), Arc::clone(&after));
        let stale = std::thread::spawn(move || {
            let expected = d2.generation(); // snapshot taken before the forget
            let rows = vec![canary()]; // rows read before the DELETE
            b1.wait(); // the forget runs now
            b2.wait();
            d2.replace_if(rows, 0, expected).unwrap()
        });
        before.wait();
        d.replace(Vec::new(), 0).unwrap(); // forget_tokens' synchronous rebuild
        after.wait();
        assert!(!stale.join().unwrap(), "the stale swap was refused");
        let text = "Zyxwuria Quolnath";
        assert!(
            d.detect(text, &DetectCtx::for_text(text))
                .unwrap()
                .is_empty(),
            "still forgotten"
        );
        assert!(
            d.replace_if(vec![canary()], 0, d.generation()).unwrap(),
            "a current snapshot swaps"
        );
        assert_eq!(d.detect(text, &DetectCtx::for_text(text)).unwrap().len(), 1);
    }
}
