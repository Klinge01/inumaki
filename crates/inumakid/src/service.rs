//! Shared sanitize/rehydrate service over dataset namespaces (M4 spec §5.3).
//!
//! One namespace lock per batch; every block is one cache entry; the engine
//! runs for the misses; before anything is released, every non-blocked
//! block is re-checked against what the namespace knows *now*, so a full
//! name a later block (or a concurrent request) taught cannot leave in clear
//! through an earlier block. That release check matches known entities
//! (full values). When a batch of two or more blocks changed the store,
//! `settle_store_changes` also scans every non-blocked block, outside its
//! tokens and protected ranges, for the engine's consistency forms
//! (`StoreDict`: the working set's full values, PERSON name parts,
//! transliterated and folded forms, removed values, every kind),
//! sanitizes an offender once more with the batch's scope, and
//! withholds it if a form is still in clear; so a bare first name or surname
//! detection missed in an earlier block does not leave when a later block
//! mints the full name. "Changed the store" means the epoch or the
//! per-process keyed fingerprint of the working set and removed values
//! differs from the start of the batch. The dictionary is the namespace's
//! own cache (`TokenStore::store_dict`, shared with the engine's passes);
//! cache hits are re-checked with it too (`recheck`). Not covered: forms of
//! values outside the working set, and a single-block batch (not scanned at
//! its end) whose own second engine sanitize mints the full name
//! (residuals, `docs/threat-model.md`). Both re-checks follow the request
//! profile's policy for known entities: a known entity of a kind the
//! profile preserves at that confidence (an ORGANIZATION another profile
//! tokenized) stays in clear, as the engine would have left it; the store
//! forms count for every kind, as in the engine. A store error anywhere
//! discards the whole batch. Session contexts never come through here. Plan
//! 2's gateway wraps these two functions behind its injected trait; plan 2
//! adds field semantics to [`BlockInput`].

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::ops::Range;
use std::sync::{OnceLock, PoisonError};
use std::time::Duration;

use inumaki_core::alias::AliasTable;
use inumaki_core::config::TokenSettings;
use inumaki_core::consistency::StoreDict;
use inumaki_core::detect::DetectCtx;
use inumaki_core::engine::{Engine, Outcome, normalize_input};
use inumaki_core::link::LinkScope;
use inumaki_core::origin::TextOrigin;
use inumaki_core::policy::{Action, Profile};
use inumaki_core::redact::{Redaction, RedactionError, RedactionFile, validate_redactions};
use inumaki_core::rehydrate::RehydrateError;
use inumaki_core::sanitize::Sanitized;
use inumaki_core::span::EntityKind;
use inumaki_core::token::{Context, ContextId, StoreError, Token, TokenStore, parse_token};
use inumaki_core::verify::{CheckId, Reason};
use inumaki_vault::{Namespace, VaultError};
use zeroize::Zeroizing;

use crate::cache::{CacheKey, CachedOutcome, CachedResult};
use crate::engines::EngineError;
use crate::state::AppState;

/// Trusted field semantics of a block (M4 spec §5.3). Untrusted upstream
/// metadata can never set these; the contract walker does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldHint {
    /// Free text: detect, sanitize, verify.
    FreeText,
    /// A typed identifier field: the whole value is tokenized as `kind`
    /// even when no detector would find it. Never cached.
    Identifier(EntityKind),
    /// Discovery metadata: free text under the dataset profile's metadata
    /// profile (plan 2c). Set only by the gateway's listing walker.
    Metadata,
}

/// One text to sanitize or rehydrate.
pub struct BlockInput {
    /// The text. Sanitization NFC-normalizes it first.
    pub text: String,
    /// Field semantics.
    pub hint: FieldHint,
    /// Mandatory transformations (already validated against the NFC text).
    pub redactions: Vec<Redaction>,
}

impl BlockInput {
    /// A free-text block without redactions.
    pub fn text(s: impl Into<String>) -> Self {
        BlockInput {
            text: s.into(),
            hint: FieldHint::FreeText,
            redactions: Vec::new(),
        }
    }
}

impl std::fmt::Debug for BlockInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockInput")
            .field("len", &self.text.len())
            .field("hint", &self.hint)
            .field("redactions", &self.redactions.len())
            .finish()
    }
}

/// How unresolved placeholders are treated during restoration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RehydrateMode {
    /// Unknown tokens stay in the text and are counted (legacy control clients).
    Permissive,
    /// Any unresolved placeholder fails the whole batch (the gateway).
    Strict,
}

/// One applied decision: offsets into the NFC input and the sanitized text,
/// kind, and action. Never the text; the caller slices the sanitized text
/// for the token when it needs it.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplacedSpan {
    /// Span in the input.
    pub start: usize,
    /// One past the last byte in the input.
    pub end: usize,
    /// Range start in the sanitized text.
    pub out_start: usize,
    /// Range end in the sanitized text.
    pub out_end: usize,
    /// Entity kind.
    pub kind: EntityKind,
    /// Action applied.
    pub action: Action,
}

/// One block's sanitization result. `text` is empty for `Blocked`.
#[derive(Clone)]
pub struct BlockResult {
    /// Outcome.
    pub outcome: CachedOutcome,
    /// Sanitized text.
    pub text: String,
    /// Replacement count.
    pub replacements: usize,
    /// Kinds tokenized or removed, or the block's kinds.
    pub kinds: Vec<EntityKind>,
    /// Reasons when uncertain or blocked.
    pub reasons: Vec<Reason>,
    /// Served from the cache.
    pub cached: bool,
    /// The applied decisions, offsets only; empty for `Blocked`.
    pub replaced: Vec<ReplacedSpan>,
}

impl std::fmt::Debug for BlockResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockResult")
            .field("outcome", &self.outcome)
            .field("len", &self.text.len())
            .field("replacements", &self.replacements)
            .field("kinds", &self.kinds.len())
            .field("reasons", &self.reasons.len())
            .field("cached", &self.cached)
            .field("replaced", &self.replaced.len())
            .finish()
    }
}

/// One block's restoration result.
pub struct RehydrateResult {
    /// Restored text.
    pub text: String,
    /// Token-shaped strings left as-is (permissive mode only; strict fails instead).
    pub unknown_tokens: usize,
    /// Removed-value markers left as-is (permissive mode only).
    pub removed_markers: usize,
}

impl std::fmt::Debug for RehydrateResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RehydrateResult")
            .field("len", &self.text.len())
            .field("unknown_tokens", &self.unknown_tokens)
            .field("removed_markers", &self.removed_markers)
            .finish()
    }
}

/// Why a batch produced nothing. Messages carry ids and counts, never text.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// The vault refused (unknown dataset, closed epoch, storage failure).
    #[error(transparent)]
    Vault(#[from] VaultError),
    /// The token store failed mid-request.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The profile's engine is unavailable.
    #[error(transparent)]
    Engine(#[from] EngineError),
    /// Strict restoration found placeholders it cannot resolve.
    #[error("unresolved placeholders: {unknown} unknown tokens, {removed} removed markers")]
    Unresolved {
        /// Unknown, expired, or foreign tokens.
        unknown: usize,
        /// Removed-value markers.
        removed: usize,
    },
    /// A redactions file was refused.
    #[error(transparent)]
    Redaction(#[from] RedactionError),
    /// The request shape is not supported; carries a fixed class.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
}

fn from_sanitized(outcome: CachedOutcome, s: Sanitized, reasons: Vec<Reason>) -> CachedResult {
    let mut kinds = Vec::new();
    // Only tokens this pass minted (M3 review M2): a token pasted in from
    // another dataset is unknown to this namespace and must not be checked
    // against it on every future hit.
    let mut tokens = Vec::new();
    for rep in &s.replacements {
        if matches!(rep.action, Action::Tokenize | Action::Remove)
            && !kinds.contains(&rep.span.kind)
        {
            kinds.push(rep.span.kind.clone());
        }
        if let Some(t) = &rep.token {
            tokens.push(t.as_str().to_string());
        }
    }
    let replaced = s
        .replacements
        .iter()
        .map(|rep| ReplacedSpan {
            start: rep.span.start,
            end: rep.span.end,
            out_start: rep.out_range.start,
            out_end: rep.out_range.end,
            kind: rep.span.kind.clone(),
            action: rep.action,
        })
        .collect();
    CachedResult {
        outcome,
        text: s.text,
        replacements: s.replacements.len(),
        kinds,
        reasons,
        tokens,
        replaced,
        protected: s.protected,
        cross_request: false,
    }
}

/// Engine outcome to the cacheable form.
pub(crate) fn to_result(outcome: Outcome) -> CachedResult {
    match outcome {
        Outcome::Pass { sanitized } => from_sanitized(CachedOutcome::Pass, sanitized, Vec::new()),
        Outcome::PassUncertain { sanitized, reasons } => {
            from_sanitized(CachedOutcome::PassUncertain, sanitized, reasons)
        }
        Outcome::Blocked { reasons, kinds } => CachedResult {
            outcome: CachedOutcome::Blocked,
            text: String::new(),
            replacements: 0,
            kinds,
            reasons,
            tokens: Vec::new(),
            replaced: Vec::new(),
            protected: Vec::new(),
            cross_request: false,
        },
    }
}

/// Cacheable result to the block result.
pub(crate) fn block_result(r: CachedResult, cached: bool) -> BlockResult {
    BlockResult {
        outcome: r.outcome,
        text: r.text,
        replacements: r.replacements,
        kinds: r.kinds,
        reasons: r.reasons,
        cached,
        replaced: r.replaced,
    }
}

/// True when `start..end` in `text` lies inside one of `tokens`'
/// occurrences, or inside one of the `protected` output ranges (tokens that
/// were already in the input and resolved in the store, M8 decision 11: the
/// engine left them alone, so a hit inside one is not a leak).
fn token_covers(
    text: &str,
    tokens: &[String],
    protected: &[Range<usize>],
    start: usize,
    end: usize,
) -> bool {
    protected.iter().any(|r| r.start <= start && end <= r.end)
        || tokens.iter().any(|t| {
            text.match_indices(t.as_str())
                .any(|(i, _)| i <= start && end <= i + t.len())
        })
}

/// A known-entity hit in `text` that no token of this result covers and
/// that `policy` would not preserve: an original the namespace knows now
/// but did not when the text was sanitized. Only `Preserve` exempts a hit;
/// tokenize, remove, block, escalate, and a span the policy would drop all
/// count. A detector failure counts as uncovered (fail closed).
fn uncovered_known_entity(
    n: &Namespace,
    text: &str,
    tokens: &[String],
    protected: &[Range<usize>],
    policy: &Profile,
) -> Option<Reason> {
    let ctx = DetectCtx::for_text(text);
    match n.detector().detect(text, &ctx) {
        Ok(spans) => spans
            .into_iter()
            .find(|sp| {
                !token_covers(text, tokens, protected, sp.start, sp.end)
                    && policy.action_for(sp) != Some(Action::Preserve)
            })
            .map(|sp| Reason {
                kind: sp.kind,
                check: CheckId::Leak,
            }),
        Err(_) => Some(Reason {
            kind: EntityKind::custom("DETECTOR"),
            check: CheckId::DetectorError,
        }),
    }
}

/// What the store-copy checks depend on: every working-set entry and
/// removed value, each hashed with a per-process random key (no stable
/// digest of an original exists), summed so the working set's order does
/// not matter, with the count. Compared before and after a batch.
fn store_fingerprint(n: &Namespace) -> (u64, usize) {
    static KEY: OnceLock<RandomState> = OnceLock::new();
    let key = KEY.get_or_init(RandomState::new);
    let (mut sum, mut count) = (0u64, 0usize);
    for (tag, (kind, value)) in n
        .entries()
        .map(|e| (0u8, e))
        .chain(n.removed_entries().map(|e| (1u8, e)))
    {
        sum = sum.wrapping_add(key.hash_one((tag, kind, value)));
        count += 1;
    }
    (sum, count)
}

/// The engine's referential-consistency dictionary over `n` (its working
/// set and removed values, every kind), through the alias groups as the
/// engine's own pass wraps the store. Task 7e (ruling L62): the namespace's
/// own cache, shared with the engine's passes, its forms living and going
/// with the working set (forget, rotation, deletion, the handle's close);
/// `None` when it cannot be built.
fn current_dict(n: &mut Namespace, aliases: &AliasTable) -> Option<StoreDict> {
    n.store_dict(Some(aliases)).and_then(Result::ok)
}

/// The kind of a clear store form in `r`'s text outside its tokens and
/// protected ranges; an error is fail closed (the caller treats it as a
/// match).
fn store_copy_in_clear(
    d: &StoreDict,
    r: &CachedResult,
) -> inumaki_core::Result<Option<EntityKind>> {
    d.uncovered_match(&r.text, |start, end| {
        token_covers(&r.text, &r.tokens, &r.protected, start, end)
    })
}

/// A withheld block: no text, the reason's kind.
fn withheld_result(reason: Reason) -> CachedResult {
    CachedResult {
        outcome: CachedOutcome::Blocked,
        text: String::new(),
        replacements: 0,
        kinds: vec![reason.kind.clone()],
        reasons: vec![reason],
        tokens: Vec::new(),
        replaced: Vec::new(),
        protected: Vec::new(),
        cross_request: false,
    }
}

/// The indices of `results`' non-blocked blocks that carry a clear copy of
/// a store value (`store_copy_in_clear` against the current store), each
/// with its reason; when the dictionary cannot be built or a scan fails,
/// every such block counts (fail closed, `DetectorError`).
fn store_copy_offenders(
    n: &mut Namespace,
    results: &[(CachedResult, bool)],
    aliases: &AliasTable,
) -> Vec<(usize, Reason)> {
    let detector = || Reason {
        kind: EntityKind::custom("DETECTOR"),
        check: CheckId::DetectorError,
    };
    let d = current_dict(n, aliases);
    results
        .iter()
        .enumerate()
        .filter(|(_, (r, _))| r.outcome != CachedOutcome::Blocked)
        .filter_map(
            |(i, (r, _))| match d.as_ref().map(|d| store_copy_in_clear(d, r)) {
                Some(Ok(None)) => None,
                Some(Ok(Some(kind))) => Some((
                    i,
                    Reason {
                        kind,
                        check: CheckId::Leak,
                    },
                )),
                _ => Some((i, detector())),
            },
        )
        .collect()
}

/// Cache-hit re-check (M3 spec §6, review I2): the cached tokens must still
/// resolve, and nothing the namespace knows now may sit outside them
/// unless `policy` preserves it.
///
/// Task 7c (integrator ruling L54): nor may any form the engine's
/// consistency pass searches (`StoreDict`: full values, name parts,
/// transliterated and folded forms, removed values, every kind, preserved
/// kinds included) sit outside the cached tokens and protected ranges. The
/// known-entity automaton leaves out name parts, one-part names, and
/// non-identifier kinds, so without this a block cached with a bare `Anna`
/// in clear would be replayed after `Anna Berger` was minted, where a fresh
/// pass tokenizes it. The dictionary is the namespace's own (Task 7e,
/// `current_dict`), current after this hit's tokens are prepared; a build
/// error fails the re-check (fail closed: a miss, sanitized fresh).
fn recheck(n: &mut Namespace, r: &CachedResult, policy: &Profile, aliases: &AliasTable) -> bool {
    if n.prepare(&r.tokens).is_err() || !r.tokens.iter().all(|t| n.original(t).is_some()) {
        return false;
    }
    if uncovered_known_entity(n, &r.text, &r.tokens, &r.protected, policy).is_some() {
        return false;
    }
    current_dict(n, aliases).is_some_and(|d| matches!(store_copy_in_clear(&d, r), Ok(None)))
}

/// What [`settle_store_changes`] did: the blocks it ran again (`rerun`),
/// those of them that were cache hits (`dropped_hits`, whose entries must
/// go), and the blocks it withheld.
#[derive(Debug, Default)]
struct Settled {
    rerun: Vec<usize>,
    dropped_hits: Vec<usize>,
    withheld: Vec<usize>,
}

/// Task 7c review I2: when the batch changed the store (`batch_start`, the
/// epoch and fingerprint before its first block, differs from now), an
/// earlier block may carry in clear a form a later block taught (a bare
/// `Quorvik` before `Quorvik Berger` was minted), which a fresh run now
/// tokenizes. Each such block runs once more through `rerun` (the batch's
/// whole store and scope; `None` for a block without a source); whatever
/// still carries a clear store form afterwards, or cannot be checked, is
/// withheld (fail closed). A seam: tests pass a `rerun` that changes
/// nothing, which no real input does.
fn settle_store_changes(
    n: &mut Namespace,
    results: &mut [(CachedResult, bool)],
    aliases: &AliasTable,
    batch_start: Option<(i64, (u64, usize))>,
    mut rerun: impl FnMut(&mut Namespace, usize) -> Result<Option<CachedResult>, ServiceError>,
) -> Result<Settled, ServiceError> {
    let mut out = Settled::default();
    let Some(start) = batch_start else {
        return Ok(out);
    };
    if start == (n.epoch_id(), store_fingerprint(n)) {
        return Ok(out);
    }
    let offenders = store_copy_offenders(n, results, aliases);
    if offenders.is_empty() {
        return Ok(out);
    }
    for (i, _) in offenders {
        let Some(result) = rerun(n, i)? else {
            continue;
        };
        if results[i].1 {
            out.dropped_hits.push(i);
        }
        results[i] = (result, false);
        out.rerun.push(i);
    }
    for (i, reason) in store_copy_offenders(n, results, aliases) {
        tracing::info!(block = i, check = ?reason.check, "block withheld at release");
        results[i].0 = withheld_result(reason);
        out.withheld.push(i);
    }
    Ok(out)
}

/// The final release check (spec §5.3) and the batch's cache writes: what
/// the namespace knows after the whole batch applies to every block,
/// including cached ones, and a block is withheld when a known entity sits
/// outside its tokens unless `policy` preserves it. Then every withheld
/// block's and every re-run hit's entry is dropped, and each fresh (or
/// re-run) block is cached unless withheld, transient, or linked across
/// requests.
fn release_and_cache(
    state: &AppState,
    n: &Namespace,
    policy: &Profile,
    keys: &[CacheKey],
    results: &mut [(CachedResult, bool)],
    mut fresh: Vec<usize>,
    settled: Settled,
) {
    let mut withheld = settled.withheld;
    for (i, (r, _)) in results.iter_mut().enumerate() {
        if r.outcome == CachedOutcome::Blocked {
            continue;
        }
        if let Some(reason) = uncovered_known_entity(n, &r.text, &r.tokens, &r.protected, policy) {
            tracing::info!(block = i, check = ?reason.check, "block withheld at release");
            *r = withheld_result(reason);
            withheld.push(i);
        }
    }
    for &i in withheld.iter().chain(&settled.dropped_hits) {
        state.cache.remove(&keys[i]);
    }
    for i in settled.rerun {
        if !fresh.contains(&i) {
            fresh.push(i);
        }
    }
    for i in fresh {
        if withheld.contains(&i) || transient(&results[i].0) || results[i].0.cross_request {
            // a block linked through the batch or the recency window depends
            // on state the cache key does not carry (plan 4a decision 7)
            continue;
        }
        state.cache.insert(keys[i].clone(), results[i].0.clone());
    }
}

fn transient(r: &CachedResult) -> bool {
    r.reasons.iter().any(|x| x.check == CheckId::DetectorError)
}

/// Sanitize `blocks` in `dataset`'s namespace under one lock. Blocking:
/// call from `spawn_blocking`.
///
/// Nothing is cached, and nothing is returned, until every block passed
/// the final release check; a `Blocked` block has empty text. Any store or
/// vault error discards the whole batch (rows already committed by the
/// engine may remain; no text leaves).
pub fn sanitize_blocks(
    state: &AppState,
    dataset: &str,
    profile: Option<&str>,
    blocks: Vec<BlockInput>,
) -> Result<Vec<BlockResult>, ServiceError> {
    sanitize_blocks_at(state, dataset, profile, blocks, TextOrigin::Free)
}

/// The cache-key variant of a free-text block: `text` without redactions,
/// `redact:<sha256 of the redactions' JSON>` with them, and the suffix
/// `@file-name` for [`TextOrigin::FileName`] (ruling S31). A result
/// computed for a file-name stem, where a rare-surname document word is
/// dropped, must never answer for a content block with the same text (a
/// recall bug); [`TextOrigin::Free`] keeps the strings it always had, so
/// existing cache entries stay valid. Other origins get their label as the
/// suffix.
fn cache_variant(redactions: &[Redaction], origin: TextOrigin) -> Result<String, ServiceError> {
    let base = if redactions.is_empty() {
        "text".to_string()
    } else {
        let json = serde_json::to_string(redactions)
            .map_err(|_| ServiceError::Unsupported("redactions_json"))?;
        format!("redact:{}", inumaki_core::redact::sha256_hex(&json))
    };
    Ok(match origin {
        TextOrigin::Free => base,
        other => format!("{base}@{}", other.label()),
    })
}

/// [`sanitize_blocks`] for texts of known origin ([`TextOrigin`]): the
/// engine runs with `origin`, and the cache variant carries it
/// ([`cache_variant`]). `sanitize_names` passes [`TextOrigin::FileName`]
/// for its phase 2; every other caller goes through [`sanitize_blocks`]
/// ([`TextOrigin::Free`]).
pub fn sanitize_blocks_at(
    state: &AppState,
    dataset: &str,
    profile: Option<&str>,
    blocks: Vec<BlockInput>,
    origin: TextOrigin,
) -> Result<Vec<BlockResult>, ServiceError> {
    // Fix round 1, finding 3: check the whole batch's shape before touching
    // the namespace or running any block, so a later identifier-with-
    // redactions block can never be reached after earlier blocks in the
    // same batch have already minted.
    if blocks
        .iter()
        .any(|b| matches!(b.hint, FieldHint::Identifier(_)) && !b.redactions.is_empty())
    {
        return Err(ServiceError::Unsupported("redactions_on_identifier"));
    }
    // Plan M8-2 Task 6: the hints decide which blocks may be recorded as
    // released (see `releasable`).
    let hints: Vec<FieldHint> = blocks.iter().map(|b| b.hint.clone()).collect();
    let profile = match profile {
        Some(p) => p.to_string(),
        None => state.vault.dataset_profile(dataset)?,
    };
    // Fix round 1, finding 1: the primary profile is never a metadata
    // profile. `datasets::create` refuses one at creation, but a dataset's
    // stored profile can outlive that check (a config edit adds
    // `metadata_of` to a profile already in use, or an explicit override
    // names one directly); without this, its free text and results would
    // silently run under the lighter variant. Fails closed, no dataset
    // slug or text in the error.
    if state.engines.core().is_metadata_profile(&profile) {
        return Err(ServiceError::Unsupported("metadata_profile"));
    }
    // Discovery metadata runs under the profile's metadata variant (plan
    // 2c): never weaker in actions (configuration loading checks it), its
    // own thresholds. Resolved once per batch.
    let meta_profile = if blocks.iter().any(|b| b.hint == FieldHint::Metadata) {
        state.engines.metadata_profile(&profile)?
    } else {
        profile.clone()
    };
    let ns = state.namespace(dataset)?;
    let mut n = ns.lock().unwrap_or_else(PoisonError::into_inner);
    n.refresh()?;
    let epoch = n.epoch_id();
    // Task 7c review I2: the store's state before any block of a batch of
    // several ran (a single block is checked against its own mints by the
    // engine's consistency pass, or by `recheck` on a hit).
    let batch_start = (blocks.len() > 1).then(|| (epoch, store_fingerprint(&n)));
    // The primary profile's policy governs both re-checks. A block settled
    // by the retry profile is judged by it too: what the retry tokenized is
    // covered; anything it preserved that the primary would not is withheld.
    let policy = state.engines.policy(&profile)?;
    // Tier 2 of the name linker (plan 4a decision 3): full names of earlier
    // blocks of this batch. Dropped with the batch.
    let mut scope = LinkScope::empty();
    let aliases = state.vault.aliases();
    let mut keys: Vec<CacheKey> = Vec::with_capacity(blocks.len());
    let mut results: Vec<(CachedResult, bool)> = Vec::with_capacity(blocks.len());
    let mut fresh: Vec<usize> = Vec::new();
    // Each free-text block's NFC text, redactions, and whether it ran as
    // metadata, for a re-run at the end of the batch (review I2).
    let mut sources: Vec<Option<(String, Vec<Redaction>, bool)>> = Vec::new();
    for (i, b) in blocks.into_iter().enumerate() {
        if let FieldHint::Identifier(kind) = &b.hint {
            let text = normalize_input(&b.text).into_owned();
            keys.push(CacheKey::with_variant(
                dataset,
                epoch,
                &profile,
                &state.config_fingerprint,
                "identifier",
                &text,
            ));
            // Fix round 1, finding 4: a whitespace-only value (not just a
            // literally empty one) must stay empty rather than mint a
            // token shared by every blank value of this kind.
            let r = if text.trim().is_empty() {
                CachedResult {
                    outcome: CachedOutcome::Pass,
                    text: String::new(),
                    replacements: 0,
                    kinds: Vec::new(),
                    reasons: Vec::new(),
                    tokens: Vec::new(),
                    replaced: Vec::new(),
                    protected: Vec::new(),
                    cross_request: false,
                }
            } else {
                let canon = state
                    .vault
                    .aliases()
                    .canonical(kind, &text)
                    .map(str::to_owned);
                let token = n.token_for(kind, canon.as_deref().unwrap_or(&text))?;
                CachedResult {
                    outcome: CachedOutcome::Pass,
                    text: token.as_str().to_string(),
                    replacements: 1,
                    kinds: vec![kind.clone()],
                    reasons: Vec::new(),
                    tokens: vec![token.as_str().to_string()],
                    replaced: vec![ReplacedSpan {
                        start: 0,
                        end: text.len(),
                        out_start: 0,
                        out_end: token.as_str().len(),
                        kind: kind.clone(),
                        action: Action::Tokenize,
                    }],
                    protected: Vec::new(),
                    cross_request: false,
                }
            };
            results.push((r, false));
            sources.push(None);
            continue;
        }
        let text = normalize_input(&b.text).into_owned();
        let variant = cache_variant(&b.redactions, origin)?;
        let block_profile = if b.hint == FieldHint::Metadata {
            &meta_profile
        } else {
            &profile
        };
        let key = CacheKey::with_variant(
            dataset,
            epoch,
            block_profile,
            &state.config_fingerprint,
            &variant,
            &text,
        );
        let hit = state
            .cache
            .get_verified(&key, |r| recheck(&mut n, r, &policy, aliases));
        let entry = match hit {
            Some(r) => (r, true),
            None => {
                let engine = state
                    .engines
                    .engine(block_profile, Some((dataset, n.detector())))?;
                let detailed =
                    engine.process_scoped_at(&text, &mut *n, &b.redactions, &scope, origin)?;
                let mut result = to_result(detailed.outcome);
                // Decision 7: a link decided from the batch or the recency
                // window depends on state the cache key does not carry.
                result.cross_request = detailed.links.cross_request();
                fresh.push(i);
                (result, false)
            }
        };
        keys.push(key);
        results.push(entry);
        sources.push(Some((text, b.redactions, b.hint == FieldHint::Metadata)));
        // Tier 2 for the rest of the batch: this block's canonical persons.
        // (A cached hit's tokens were prepared by `recheck`, so `original`
        // answers for them too.)
        for t in &results.last().expect("pushed above").0.tokens {
            if let Some(p) = parse_token(n.settings(), t)
                && p.label == "PERSON"
                && p.variant.is_none()
                && !p.removed
                && let Some(o) = n.original(t)
            {
                scope.push(o);
            }
        }
    }
    let settled = settle_store_changes(&mut n, &mut results, aliases, batch_start, |n, i| {
        let Some((text, redactions, meta)) = &sources[i] else {
            return Ok(None);
        };
        let block_profile = if *meta { &meta_profile } else { &profile };
        let engine = state
            .engines
            .engine(block_profile, Some((dataset, n.detector())))?;
        let detailed = engine.process_scoped_at(text, &mut *n, redactions, &scope, origin)?;
        let mut result = to_result(detailed.outcome);
        result.cross_request = detailed.links.cross_request();
        Ok(Some(result))
    })?;
    release_and_cache(state, &n, &policy, &keys, &mut results, fresh, settled);
    // Plan M8-2 Task 6 (M8 spec §14): after the final release check.
    for ((r, _), hint) in results.iter().zip(&hints) {
        if releasable(dataset, &profile, &state.cfg.proxy.profile, hint, r.outcome) {
            state.released.insert(&r.text);
        }
    }
    Ok(results
        .into_iter()
        .map(|(r, cached)| block_result(r, cached))
        .collect())
}

/// Whether a block's sanitized text is recorded as released (plan M8-2
/// Task 6, M8 spec §14), so the proxy may skip its engine for the same text
/// after a deterministic re-check: free text that passed under the proxy's
/// own profile, outside a check run. Text released under another (possibly
/// weaker) profile, by a check run, as metadata (its own profile variant)
/// or as an identifier, or flagged uncertain, is never recorded.
pub(crate) fn releasable(
    dataset: &str,
    profile: &str,
    proxy_profile: &str,
    hint: &FieldHint,
    outcome: CachedOutcome,
) -> bool {
    !dataset.starts_with(crate::check::CHECK_PREFIX)
        && profile == proxy_profile
        && *hint == FieldHint::FreeText
        && outcome == CachedOutcome::Pass
}

/// The regex tier the tripwire uses: checksum- and parser-validated
/// matches only (IBAN, card, national IDs, email, IP, URL).
pub(crate) fn validated_regex() -> &'static inumaki_core::detect::regex::RegexDetector {
    static R: std::sync::OnceLock<inumaki_core::detect::regex::RegexDetector> =
        std::sync::OnceLock::new();
    R.get_or_init(inumaki_core::detect::regex::RegexDetector::new)
}

/// In a name a listing exposes as it is, a known person, organization, or
/// street counts only when its match spans two or more words: a
/// single-word one (`Max`, `Long`, `Google`) is an ordinary word in API
/// names (`max_results`). Identifier kinds (customer, contract, invoice
/// numbers, emails) count on one word.
fn counts_in_name(kind: &EntityKind, matched: &str) -> bool {
    let word_like = matches!(
        kind,
        EntityKind::Person | EntityKind::Organization | EntityKind::StreetAddress
    );
    !word_like
        || matched
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .count()
            >= 2
}

/// Shared body of [`scan_clear`] and [`scan_names`]: known originals of the
/// dataset at full-match confidence, plus validated identifiers (checksum-
/// or parser-validated: IBAN, card, national IDs, email, IP, URL) — neither
/// tier counts a kind the dataset's profile preserves, and a range both
/// tiers detect is counted once. `in_names` narrows the known-entity tier to
/// [`counts_in_name`] (plan 2c): a single-word known person, organization,
/// or street does not count when the text is an exposed name. `validated`
/// false skips the validated-identifier tier (the hook's trigger, M6 spec
/// §5.2). Counts per kind, no text. A detector error is
/// `Unsupported("clear_scan")` (fail closed).
fn clear_hits(
    state: &AppState,
    dataset: &str,
    texts: &[String],
    in_names: bool,
    validated: bool,
) -> Result<Vec<(EntityKind, u32)>, ServiceError> {
    use inumaki_core::detect::Detector;
    use inumaki_core::span::DetectorId;
    let profile = state.vault.dataset_profile(dataset)?;
    let policy = state.engines.policy(&profile)?;
    let ns = state.namespace(dataset)?;
    let mut n = ns.lock().unwrap_or_else(PoisonError::into_inner);
    n.refresh()?;
    let mut counts: Vec<(EntityKind, u32)> = Vec::new();
    let mut bump = |k: EntityKind| match counts.iter_mut().find(|(x, _)| *x == k) {
        Some((_, c)) => *c += 1,
        None => counts.push((k, 1)),
    };
    for t in texts {
        let text = normalize_input(t);
        let ctx = DetectCtx::for_text(&text);
        let known = n
            .detector()
            .detect(&text, &ctx)
            .map_err(|_| ServiceError::Unsupported("clear_scan"))?;
        // Ranges already counted for this text: a value that is both a
        // known original and a validated identifier (an IBAN also stored
        // as a known entity) is counted once, not by each tier (review M2).
        let mut seen: Vec<(usize, usize)> = Vec::new();
        for sp in known {
            if sp.confidence >= 0.9
                && policy.action_for(&sp) != Some(Action::Preserve)
                && (!in_names
                    || text
                        .get(sp.start..sp.end)
                        .is_none_or(|m| counts_in_name(&sp.kind, m)))
            {
                seen.push((sp.start, sp.end));
                bump(sp.kind);
            }
        }
        if !validated {
            continue;
        }
        let rx = validated_regex()
            .detect(&text, &ctx)
            .map_err(|_| ServiceError::Unsupported("clear_scan"))?;
        for sp in rx
            .into_iter()
            .filter(|s| s.source == DetectorId::RegexValidated)
        {
            // Both tiers skip a kind the profile preserves (review I3): a
            // preserved URL or IBAN is not a clear-value hit, since the
            // profile would have left it in clear anyway.
            let covered = seen.iter().any(|&(a, b)| a == sp.start && b == sp.end);
            if !covered && policy.action_for(&sp) != Some(Action::Preserve) {
                bump(sp.kind);
            }
        }
    }
    Ok(counts)
}

/// Clear values in model-written text (M4 spec §16.1): see [`clear_hits`].
/// The tripwire: a single-word known name still counts here.
pub fn scan_clear(
    state: &AppState,
    dataset: &str,
    texts: &[String],
) -> Result<Vec<(EntityKind, u32)>, ServiceError> {
    clear_hits(state, dataset, texts, false, true)
}

/// [`scan_clear`] for names a listing exposes as they are (M4 spec §5.2,
/// plan 2c): a known entity of a word-like kind counts only when its match
/// spans two or more words ([`counts_in_name`]); the validated-regex tier is
/// unchanged. The number of hits; never text.
pub fn scan_names(state: &AppState, dataset: &str, names: &[String]) -> Result<u32, ServiceError> {
    Ok(clear_hits(state, dataset, names, true, true)?
        .iter()
        .map(|(_, n)| *n)
        .sum())
}

/// The hook's trigger (M6 spec §5.2): [`scan_names`]' known-entity tier
/// alone. Known originals of `dataset` at full-match confidence that its
/// profile does not preserve, a word-like kind only on two or more words
/// (plan 2c). Validated-regex hits (URLs, emails, IPs in code output) do
/// not count. Counts per kind; never text.
pub fn scan_known_names(
    state: &AppState,
    dataset: &str,
    texts: &[String],
) -> Result<Vec<(EntityKind, u32)>, ServiceError> {
    clear_hits(state, dataset, texts, true, false)
}

/// The hook's re-scan after sanitizing (M6 spec §5.2, review C2): one
/// reason per text that still holds a known original of `dataset` its
/// profile would not preserve, at any confidence and single words included
/// (a surname alone scores 0.80), as the release check
/// (`uncovered_known_entity`) judges it with no token exempt. A detector
/// failure is a reason too (fail closed). Never text.
pub fn known_left(
    state: &AppState,
    dataset: &str,
    texts: &[String],
) -> Result<Vec<Reason>, ServiceError> {
    let profile = state.vault.dataset_profile(dataset)?;
    let policy = state.engines.policy(&profile)?;
    let ns = state.namespace(dataset)?;
    let mut n = ns.lock().unwrap_or_else(PoisonError::into_inner);
    n.refresh()?;
    Ok(texts
        .iter()
        .filter_map(|t| uncovered_known_entity(&n, &normalize_input(t), &[], &[], &policy))
        .collect())
}

/// Largest block the mirror's sanitize path accepts (M5 spec §5.1). A block
/// is one engine call under the namespace lock: a JSON string value, a CSV
/// record with an unterminated quote, or an assembled verification block is
/// unbounded by the file format, and the lock hold grows with it. Text
/// chunks are 4 KiB, so only a degenerate file reaches this. The mirror
/// checks the same size before calling (`MirrorConfig::MAX_BLOCK_BYTES`).
pub const MAX_BLOCK_BYTES: usize = 64 * 1024;

/// Largest file-name stem [`sanitize_names`] examines. A name is at most 255
/// bytes on every supported file system; this leaves room for its expansion.
pub const MAX_NAME_STEM_BYTES: usize = 1024;

/// Stems per namespace-lock hold in [`sanitize_names`]: each is two engine
/// runs under the lock, and a batch should stay well inside the mirror's
/// sub-batch time budget even with NER.
const NAME_LOCK_BATCH: usize = 8;

/// The fixed reason for a block withheld for its size: no text, no size.
fn oversize_reason() -> Reason {
    Reason {
        kind: EntityKind::custom("OVERSIZE"),
        check: CheckId::DetectorError,
    }
}

fn blocked_result(reasons: Vec<Reason>) -> BlockResult {
    BlockResult {
        outcome: CachedOutcome::Blocked,
        text: String::new(),
        replacements: 0,
        kinds: reasons.iter().map(|r| r.kind.clone()).collect(),
        reasons,
        cached: false,
        replaced: Vec::new(),
    }
}

/// [`sanitize_blocks`] for the mirror (M5 spec §5.1): free-text blocks under
/// the dataset's profile, with a size cap. When any block exceeds
/// [`MAX_BLOCK_BYTES`] every block comes back `Blocked` with a fixed reason
/// and the engine, the namespace lock, and the vault are not touched: the
/// mirror withholds the whole file (fail closed) and nothing is minted for
/// a file that will not be released. Blocking.
pub fn sanitize_bounded(
    state: &AppState,
    dataset: &str,
    texts: Vec<String>,
) -> Result<Vec<BlockResult>, ServiceError> {
    if texts.iter().any(|t| t.len() > MAX_BLOCK_BYTES) {
        return Ok(texts
            .iter()
            .map(|_| blocked_result(vec![oversize_reason()]))
            .collect());
    }
    sanitize_blocks(
        state,
        dataset,
        None,
        texts.into_iter().map(BlockInput::text).collect(),
    )
}

/// `_ - . +` read as spaces; byte length and char boundaries are kept, so
/// spans found in the variant apply to the original (M5 spec §4.3 rule 2).
pub fn spaced_variant(s: &str) -> String {
    let bytes: Vec<u8> = s
        .bytes()
        .map(|b| {
            if matches!(b, b'_' | b'-' | b'.' | b'+') {
                b' '
            } else {
                b
            }
        })
        .collect();
    String::from_utf8(bytes).expect("an ASCII-only substitution keeps UTF-8")
}

/// The spelling of a stem that `splice_names` scans besides the written one
/// (ruling S5): like [`spaced_variant`], but a separator inside a date or
/// time shape stays (`foto 2025-07-14`, `at 12.34.56`), so dates and times are
/// not read as phone numbers; every other separator becomes a space, so IBAN,
/// social security and card groups still match their regexes. It is scanned
/// under `TextOrigin::FileName` like the written stem, so it inherits the
/// file position (L129, N3). `known_in_clear` keeps [`spaced_variant`].
///
/// A date or time shape is a whole chain of ASCII digit groups joined by
/// single `- _ . :` separators ([`is_date_or_time`]): no digit is glued to
/// it, and no further digit group touches it across one separator, so
/// `0532_2010_12` inside an IBAN is no `YYYY-MM` (L124(b), L129). Byte
/// length and char boundaries are kept: only ASCII separators change.
pub fn name_detection_variant(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = spaced_variant(s).into_bytes();
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        let mut groups: Vec<Range<usize>> = Vec::new();
        let mut seps: Vec<u8> = Vec::new();
        loop {
            let g = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            groups.push(g..i);
            if i + 1 < b.len()
                && matches!(b[i], b'-' | b'_' | b'.' | b':')
                && b[i + 1].is_ascii_digit()
            {
                seps.push(b[i]);
                i += 1;
            } else {
                break;
            }
        }
        if is_date_or_time(s, &groups, &seps) {
            out[start..i].copy_from_slice(&b[start..i]);
        }
    }
    String::from_utf8(out).expect("restoring ASCII separators keeps UTF-8")
}

/// True when the digit-group chain `groups` of `s`, joined by `seps`, is a
/// date or time shape with valid ranges: `YYYY-MM(-DD)` (`- _ .`, year
/// 1900-2099, month 01-12, day 01-31), `DD.MM.YYYY` (one or two digits for
/// day and month), or `HH.MM(.SS)` (`.` or `:`, hours 00-23, minutes and
/// seconds 00-59).
fn is_date_or_time(s: &str, groups: &[Range<usize>], seps: &[u8]) -> bool {
    let len: Vec<usize> = groups.iter().map(|g| g.len()).collect();
    let val = |k: usize| s[groups[k].clone()].parse::<u32>().unwrap_or(u32::MAX);
    let in_range = |k: usize, lo: u32, hi: u32| (lo..=hi).contains(&val(k));
    let n = groups.len();
    if !(2..=3).contains(&n) {
        return false;
    }
    let iso = len[0] == 4
        && len[1..].iter().all(|&l| l == 2)
        && seps.iter().all(|&c| matches!(c, b'-' | b'_' | b'.'))
        && in_range(0, 1900, 2099)
        && in_range(1, 1, 12)
        && (n == 2 || in_range(2, 1, 31));
    let dotted = n == 3
        && (1..=2).contains(&len[0])
        && (1..=2).contains(&len[1])
        && len[2] == 4
        && seps.iter().all(|&c| c == b'.')
        && in_range(0, 1, 31)
        && in_range(1, 1, 12)
        && in_range(2, 1900, 2099);
    let time = (1..=2).contains(&len[0])
        && len[1..].iter().all(|&l| l == 2)
        && seps.iter().all(|&c| matches!(c, b'.' | b':'))
        && in_range(0, 0, 23)
        && in_range(1, 0, 59)
        && (n == 2 || in_range(2, 0, 59));
    iso || dotted || time
}

/// One merged name span: byte offsets into the NFC stem (the spaced variant
/// has the same offsets), the longer span's kind, `Remove` over `Tokenize`.
struct NameSpan {
    start: usize,
    end: usize,
    kind: EntityKind,
    remove: bool,
    /// The span that set the extent and kind was detected in the stem as
    /// written.
    written: bool,
}

/// Kinds whose separators are cosmetic in a name (`Zyxwuria_Quolnath` is
/// `Zyxwuria Quolnath`), so the spaced spelling is the original to mint.
fn word_like(kind: &EntityKind) -> bool {
    matches!(
        kind,
        EntityKind::Person | EntityKind::Organization | EntityKind::StreetAddress
    )
}

fn detector_reason() -> Reason {
    Reason {
        kind: EntityKind::custom("DETECTOR"),
        check: CheckId::DetectorError,
    }
}

/// What detection and policy made of one spelling of a stem.
enum Scan {
    /// The spans to tokenize or remove.
    Spans(Vec<NameSpan>),
    /// The stem is withheld: the reason, never text.
    Blocked(Reason),
}

/// Detect and decide over one spelling of a stem; nothing is minted (the
/// caller passes an overlay). A policy `Block` or `Escalate` or a detector
/// failure (no candidate) withholds the stem: a spelling that could not be
/// examined must not pass on the strength of the other one (fail closed).
/// The verifier's verdict counts for the spaced spelling only: the written
/// spelling of `Angebot_Zyxwuria_Quolnath` still holds the name, so its leak
/// check blocks by design (the spliced stem is verified in phase 2), while
/// in the spaced spelling every detected span is already tokenized.
fn scan_variant(
    engine: &Engine,
    store: &mut dyn TokenStore,
    variant: &str,
    written: bool,
) -> Result<Scan, StoreError> {
    // N3, L129: both spellings are file-name text, so every word of them is
    // a file position, the detection variant's words included.
    let d = engine.process_scoped_at(
        variant,
        store,
        &[],
        &LinkScope::empty(),
        TextOrigin::FileName,
    )?;
    if d.candidate.is_none() {
        return Ok(Scan::Blocked(detector_reason()));
    }
    let mut spans = Vec::new();
    for dec in &d.decisions {
        let remove = match dec.action {
            Action::Tokenize => false,
            Action::Remove => true,
            Action::Preserve => continue,
            Action::Block | Action::Escalate => {
                return Ok(Scan::Blocked(Reason {
                    kind: dec.span.kind.clone(),
                    check: CheckId::Policy,
                }));
            }
        };
        spans.push(NameSpan {
            start: dec.span.start,
            end: dec.span.end,
            kind: dec.span.kind.clone(),
            remove,
            written,
        });
    }
    // The verifier's veto on the spaced spelling is a real finding: every
    // span detected there is already tokenized in the candidate, so a
    // remaining leak or regex/NER hit is something the sanitizer missed, and
    // phase 2 only sees the written spelling, where it may not show.
    if !written && let Outcome::Blocked { reasons, .. } = d.outcome {
        return Ok(Scan::Blocked(
            reasons.into_iter().next().unwrap_or_else(detector_reason),
        ));
    }
    Ok(Scan::Spans(spans))
}

/// Phase 1 of [`sanitize_names`] for one chunk, under one namespace lock:
/// each stem with its spans replaced by tokens or removed markers (empty
/// for a withheld stem), and the reason a stem is withheld.
fn splice_names(
    state: &AppState,
    dataset: &str,
    profile: &str,
    chunk: &[String],
) -> Result<(Vec<String>, Vec<Option<Reason>>), ServiceError> {
    let ns = state.namespace(dataset)?;
    let mut n = ns.lock().unwrap_or_else(PoisonError::into_inner);
    n.refresh()?;
    let engine = state
        .engines
        .engine(profile, Some((dataset, n.detector())))?;
    let mut spliced = Vec::with_capacity(chunk.len());
    let mut withheld: Vec<Option<Reason>> = Vec::with_capacity(chunk.len());
    'stems: for stem in chunk {
        if stem.len() > MAX_NAME_STEM_BYTES {
            spliced.push(String::new());
            withheld.push(Some(oversize_reason()));
            continue;
        }
        let nfc = normalize_input(stem).into_owned();
        let spaced = name_detection_variant(&nfc);
        let mut spans: Vec<NameSpan> = Vec::new();
        for (written, variant) in [(true, &nfc), (false, &spaced)] {
            let mut store = OverlayStore::new(&mut n);
            match scan_variant(&engine, &mut store, variant, written)? {
                Scan::Spans(s) => spans.extend(s),
                Scan::Blocked(reason) => {
                    spliced.push(String::new());
                    withheld.push(Some(reason));
                    continue 'stems;
                }
            }
        }
        let mut out = String::with_capacity(nfc.len());
        let mut at = 0;
        for s in merge_spans(spans) {
            out.push_str(&nfc[at..s.start]);
            let as_written = &nfc[s.start..s.end];
            let as_spaced = &spaced[s.start..s.end];
            if s.remove {
                let original = if s.written && !word_like(&s.kind) {
                    as_written
                } else {
                    as_spaced
                };
                n.record_removed(&s.kind, original)?;
                out.push_str(&n.removed_marker(&s.kind));
            } else {
                // An entity the content (or an earlier name) already holds
                // keeps its token whichever spelling it was minted from
                // (`Karl-Schweighofer-Gasse 12` stays hyphenated in the
                // content); only an unknown one is minted, as the spaced
                // text for word-like kinds and as written otherwise.
                let mut token = None;
                for original in [as_written, as_spaced] {
                    let canon = state
                        .vault
                        .aliases()
                        .canonical(&s.kind, original)
                        .map(str::to_owned);
                    token = n.peek_token(&s.kind, canon.as_deref().unwrap_or(original))?;
                    if token.is_some() {
                        break;
                    }
                }
                let token = match token {
                    Some(t) => t,
                    None => {
                        let original = if s.written && !word_like(&s.kind) {
                            as_written
                        } else {
                            as_spaced
                        };
                        let canon = state
                            .vault
                            .aliases()
                            .canonical(&s.kind, original)
                            .map(str::to_owned);
                        n.token_for(&s.kind, canon.as_deref().unwrap_or(original))?
                    }
                };
                out.push_str(token.as_str());
            }
            at = s.end;
        }
        out.push_str(&nfc[at..]);
        spliced.push(out);
        withheld.push(None);
    }
    Ok((spliced, withheld))
}

/// Sanitize file-name stems (M5 spec §4.3 rule 2). Detection runs on each
/// stem as written and on its detection variant ([`name_detection_variant`])
/// through an overlay (nothing is minted by detection), both under
/// [`TextOrigin::FileName`]; the union of the spans the policy tokenizes or
/// removes is then resolved under the namespace lock: an entity either
/// spelling already has a token for keeps it, so a name shares the token its
/// content got and no junk entry such as `Zyxwuria_Quolnath` enters the
/// namespace (review I1); an unknown one is minted from its **spaced** text
/// (`Zyxwuria Quolnath`, alias-canonicalized), except that a span the
/// written variant found and that is not a word-like kind (an e-mail
/// address, a customer id) is minted as written: its dots and dashes are
/// part of the value. Each token or removed marker is spliced into the
/// written stem, which keeps its separators, and the spliced stems go
/// through [`sanitize_blocks_at`] under [`TextOrigin::FileName`] without
/// redactions for the ordinary detection and release check; only a `Pass` verdict releases a name (a blocked or
/// uncertain one is withheld). A stem is withheld (`Blocked`, a fixed reason) when
/// either variant has a span the policy blocks or escalates, when a
/// detector failed on either, when the verifier vetoes the spaced variant, and when it is over [`MAX_NAME_STEM_BYTES`]
/// (never examined, never minted). Both phases run per [`NAME_LOCK_BATCH`]
/// stems, so no lock hold covers a long list. A rotation between the two
/// locks leaves an old-epoch token in the name; the record carries the old
/// epoch, so the poller re-mirrors it. Blocking.
pub fn sanitize_names(
    state: &AppState,
    dataset: &str,
    stems: Vec<String>,
) -> Result<Vec<BlockResult>, ServiceError> {
    let profile = state.vault.dataset_profile(dataset)?;
    let mut out = Vec::with_capacity(stems.len());
    for chunk in stems.chunks(NAME_LOCK_BATCH) {
        let (spliced, withheld) = splice_names(state, dataset, &profile, chunk)?;
        let inputs = spliced.into_iter().map(BlockInput::text).collect();
        let results =
            sanitize_blocks_at(state, dataset, Some(&profile), inputs, TextOrigin::FileName)?;
        out.extend(withhold_unless_pass(results, withheld));
    }
    Ok(out)
}

/// Phase 2's verdict for a name (fail closed): only `Pass` leaves. A stem
/// withheld in phase 1 keeps its reason; a spliced stem the release check or
/// the verifier blocked or found uncertain is withheld with its reasons and
/// no text. (A store, vault, or engine error never gets here: it fails the
/// whole call, and no name is written.) A released name carries no
/// `replaced` spans: phase 2's offsets point into the spliced stem, not the
/// caller's stem.
fn withhold_unless_pass(
    results: Vec<BlockResult>,
    withheld: Vec<Option<Reason>>,
) -> Vec<BlockResult> {
    assert_eq!(results.len(), withheld.len(), "one verdict per stem");
    results
        .into_iter()
        .zip(withheld)
        .map(|(r, w)| match w {
            Some(reason) => blocked_result(vec![reason]),
            None if r.outcome == CachedOutcome::Pass => BlockResult {
                replaced: Vec::new(),
                ..r
            },
            None => blocked_result(r.reasons),
        })
        .collect()
}

/// Sort, then merge overlapping spans: the union's extent, the longer
/// span's kind and origin, `Remove` over `Tokenize`.
fn merge_spans(mut spans: Vec<NameSpan>) -> Vec<NameSpan> {
    spans.sort_by_key(|s| (s.start, std::cmp::Reverse(s.end)));
    let mut out: Vec<NameSpan> = Vec::new();
    for s in spans {
        match out.last_mut() {
            Some(last) if s.start < last.end => {
                let (len, last_len) = (s.end - s.start, last.end - last.start);
                if len > last_len {
                    last.kind = s.kind.clone();
                    last.written = s.written;
                } else if len == last_len {
                    last.written |= s.written;
                }
                last.end = last.end.max(s.end);
                last.remove |= s.remove;
            }
            _ => out.push(s),
        }
    }
    out
}

/// The spaced variant of `nfc` with every token occurrence in `tokens`
/// restored, so a token in the text still covers what it covers.
fn spaced_keeping_tokens(nfc: &str, tokens: &[String]) -> String {
    let mut bytes = spaced_variant(nfc).into_bytes();
    for t in tokens {
        for (i, _) in nfc.match_indices(t.as_str()) {
            bytes[i..i + t.len()].copy_from_slice(t.as_bytes());
        }
    }
    String::from_utf8(bytes).expect("restoring whole UTF-8 sequences keeps UTF-8")
}

/// Known originals in clear (M5 spec §5.4, §7.4): one entry per text, the
/// kind of a known-entity span that no token in that text covers and that
/// the profile does not preserve, checked as written and spaced; `None`
/// when clean. One lock per call; the mirror calls it per file. A detector
/// failure counts as a hit (fail closed). Texts are not size-capped here:
/// the known-entity detector is a dictionary scan, and the caller bounds a
/// file by `max_file_bytes`.
pub fn known_in_clear(
    state: &AppState,
    dataset: &str,
    texts: &[String],
) -> Result<Vec<Option<EntityKind>>, ServiceError> {
    let profile = state.vault.dataset_profile(dataset)?;
    let policy = state.engines.policy(&profile)?;
    // Normalization, the spaced copy, and the token scan need no namespace.
    let prepared: Vec<(String, String, Vec<String>)> = texts
        .iter()
        .map(|t| {
            let nfc = normalize_input(t).into_owned();
            let tokens = state.namespace_rehydrator.tokens_in(&nfc);
            let spaced = spaced_keeping_tokens(&nfc, &tokens);
            (nfc, spaced, tokens)
        })
        .collect();
    let ns = state.namespace(dataset)?;
    let mut n = ns.lock().unwrap_or_else(PoisonError::into_inner);
    n.refresh()?;
    Ok(prepared
        .iter()
        .map(|(nfc, spaced, tokens)| {
            // Every token-shaped string in the text (surface forms included)
            // is exempt through `tokens`, resolving or not: a token is not
            // clear text. No further protected ranges: anything else that
            // matches a known original counts.
            [nfc, spaced]
                .into_iter()
                .find_map(|v| uncovered_known_entity(&n, v, tokens, &[], &policy))
                .map(|r| r.kind)
        })
        .collect())
}

/// Restore `blocks` in `dataset`'s namespace under one lock. Blocking.
///
/// Strict mode returns text only when every placeholder in every block
/// resolves; otherwise [`ServiceError::Unresolved`] with batch-wide counts.
pub fn rehydrate_blocks(
    state: &AppState,
    dataset: &str,
    blocks: Vec<BlockInput>,
    mode: RehydrateMode,
) -> Result<Vec<RehydrateResult>, ServiceError> {
    let ns = state.namespace(dataset)?;
    let mut n = ns.lock().unwrap_or_else(PoisonError::into_inner);
    n.refresh()?;
    let r = &state.namespace_rehydrator;
    let mut out = Vec::with_capacity(blocks.len());
    match mode {
        RehydrateMode::Strict => {
            let (mut unknown, mut removed) = (0usize, 0usize);
            let mut texts = Vec::with_capacity(blocks.len());
            for b in &blocks {
                match r.rehydrate_strict(&b.text, &mut *n) {
                    Ok(t) => texts.push(t),
                    Err(RehydrateError::Unresolved {
                        unknown: u,
                        removed: m,
                    }) => {
                        unknown += u;
                        removed += m;
                    }
                    Err(RehydrateError::Store(e)) => return Err(e.into()),
                }
            }
            if unknown + removed > 0 {
                return Err(ServiceError::Unresolved { unknown, removed });
            }
            out.extend(texts.into_iter().map(|text| RehydrateResult {
                text,
                unknown_tokens: 0,
                removed_markers: 0,
            }));
        }
        RehydrateMode::Permissive => {
            for b in &blocks {
                let removed = r
                    .tokens_in(&b.text)
                    .iter()
                    .filter(|t| t.contains("_REMOVED"))
                    .count();
                let (text, unknown) = r.rehydrate_mut(&b.text, &mut *n)?;
                out.push(RehydrateResult {
                    text,
                    unknown_tokens: unknown,
                    removed_markers: removed,
                });
            }
        }
    }
    Ok(out)
}

/// A store for previews (M4 spec §9.1): reads the namespace (existing
/// tokens resolve to their real token), mints new ones into an in-memory
/// context that is dropped with the preview. Removed values are recorded
/// in the overlay only.
pub struct OverlayStore<'a> {
    ns: &'a mut Namespace,
    overlay: Context,
}

impl<'a> OverlayStore<'a> {
    /// Overlay over `ns`.
    pub fn new(ns: &'a mut Namespace) -> Self {
        let settings = ns.settings().clone();
        OverlayStore {
            ns,
            overlay: Context::new(
                ContextId("inspect".into()),
                Duration::from_secs(60),
                settings,
            ),
        }
    }
}

impl TokenStore for OverlayStore<'_> {
    fn token_for(&mut self, kind: &EntityKind, original: &str) -> Result<Token, StoreError> {
        if let Some(t) = self.ns.peek_token(kind, original)? {
            return Ok(t);
        }
        self.overlay.token_for(kind, original)
    }
    fn original(&self, token: &str) -> Option<&str> {
        self.overlay
            .original(token)
            .or_else(|| self.ns.original(token))
    }
    fn entries(&self) -> Box<dyn Iterator<Item = (&EntityKind, &str)> + '_> {
        Box::new(self.ns.entries().chain(self.overlay.entries()))
    }
    fn record_removed(&mut self, kind: &EntityKind, original: &str) -> Result<(), StoreError> {
        // `Context::record_removed` is an inherent method returning `()`
        // (deviation from the brief, which returned it directly): the
        // trait's `Result` is built here instead of by the callee.
        self.overlay.record_removed(kind, original);
        Ok(())
    }
    fn removed_entries(&self) -> Box<dyn Iterator<Item = (&EntityKind, &str)> + '_> {
        Box::new(
            self.ns
                .removed_entries()
                .chain(self.overlay.removed_entries()),
        )
    }
    fn removed_marker(&self, kind: &EntityKind) -> String {
        self.ns.removed_marker(kind)
    }
    fn settings(&self) -> &TokenSettings {
        self.ns.settings()
    }
    fn prepare(&mut self, tokens: &[String]) -> Result<(), StoreError> {
        self.ns.prepare(tokens)
    }
    fn surface_token(&mut self, parent: &Token, surface: &str) -> Result<Token, StoreError> {
        if let Some(t) = self.ns.peek_surface_token(parent.as_str(), surface)? {
            return Ok(t);
        }
        // A preview-only surface token, never minted into the namespace. A
        // vault entity is a parent the overlay does not hold, so it goes
        // through the foreign path.
        match self.overlay.surface_token(parent, surface) {
            Err(StoreError::UnknownParent) => self.overlay.surface_token_foreign(parent, surface),
            r => r,
        }
    }
    fn link_candidates(&self, kind: &EntityKind, window: Duration) -> Vec<Zeroizing<String>> {
        let mut v = self.ns.link_candidates(kind, window);
        v.extend(self.overlay.link_candidates(kind, window));
        v
    }
}

/// One span of an inspection.
#[derive(Clone, serde::Serialize)]
pub struct InspectSpan {
    /// Byte offsets into the NFC input.
    pub start: usize,
    /// One past the last byte.
    pub end: usize,
    /// Kind label.
    pub kind: String,
    /// `tokenize`, `remove`, `preserve`, `escalate`, or `block`.
    pub action: String,
    /// Detector name (`Debug` of `DetectorId`).
    pub source: String,
    /// The original excerpt; only with `show_values`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original: Option<String>,
}

impl std::fmt::Debug for InspectSpan {
    /// `original` carries the plaintext excerpt with `show_values`; print
    /// only whether it is set, never its value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InspectSpan")
            .field("start", &self.start)
            .field("end", &self.end)
            .field("kind", &self.kind)
            .field("action", &self.action)
            .field("source", &self.source)
            .field("has_original", &self.original.is_some())
            .finish()
    }
}

/// A local inspection (M4 spec §9.1). Never dispatched, never cached,
/// never minted.
pub struct Inspection {
    /// Outcome.
    pub outcome: CachedOutcome,
    /// Profile that settled it.
    pub profile: String,
    /// Settled by the retry profile.
    pub retried: bool,
    /// Detected and changed regions.
    pub spans: Vec<InspectSpan>,
    /// Verifier and policy reasons (document level).
    pub reasons: Vec<Reason>,
    /// Replacement count.
    pub replacements: usize,
    /// The candidate text; only with `show_values`.
    pub candidate: Option<String>,
    /// Known coverage limitations of the profile, fixed sentences.
    pub limitations: Vec<String>,
    /// Dataset rotation period in days.
    pub rotation_days: u32,
    /// Grace period in days.
    pub grace_days: u32,
    /// Current epoch start, unix seconds.
    pub epoch_started_at: i64,
}

impl std::fmt::Debug for Inspection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inspection")
            .field("outcome", &self.outcome)
            .field("spans", &self.spans.len())
            .field("reasons", &self.reasons.len())
            .field("has_candidate", &self.candidate.is_some())
            .finish()
    }
}

fn limitations(engine: &Engine) -> Vec<String> {
    let p = engine.profile();
    let mut out = Vec::new();
    if p.ner_sanitizer.is_none() {
        out.push(
            "profile has no NER: names and addresses outside dictionaries and address patterns are not detected"
                .to_string(),
        );
    }
    if p.ner_verifier.is_none() {
        out.push("verifier has no independent NER re-scan".to_string());
    }
    out.push(
        "Pass means the configured checks passed; it is not proof that no identifying information remains"
            .to_string(),
    );
    out
}

/// Inspect `text` in `dataset`'s namespace: what would be detected, what
/// would be done, why it would be blocked. Blocking; call from
/// `spawn_blocking`. Nothing is minted or cached.
pub fn inspect(
    state: &AppState,
    dataset: &str,
    profile: Option<&str>,
    text: &str,
    redactions: Option<&RedactionFile>,
    show_values: bool,
) -> Result<Inspection, ServiceError> {
    let ds = state.vault.dataset(dataset)?;
    let profile = profile.map_or_else(|| ds.profile.clone(), str::to_string);
    let nfc = normalize_input(text).into_owned();
    let reds = match redactions {
        Some(f) => validate_redactions(&nfc, f)?,
        None => Vec::new(),
    };
    let ns = state.namespace(dataset)?;
    let mut n = ns.lock().unwrap_or_else(PoisonError::into_inner);
    n.refresh()?;
    let engine = state
        .engines
        .engine(&profile, Some((dataset, n.detector())))?;
    let mut store = OverlayStore::new(&mut n);
    let d = engine.process_detailed(&nfc, &mut store, &reds)?;
    let (outcome, reasons) = match &d.outcome {
        Outcome::Pass { .. } => (CachedOutcome::Pass, Vec::new()),
        Outcome::PassUncertain { reasons, .. } => (CachedOutcome::PassUncertain, reasons.clone()),
        Outcome::Blocked { reasons, .. } => (CachedOutcome::Blocked, reasons.clone()),
    };
    let spans = d
        .decisions
        .iter()
        .map(|dec| InspectSpan {
            start: dec.span.start,
            end: dec.span.end,
            kind: dec.span.kind.label().to_string(),
            action: format!("{:?}", dec.action).to_lowercase(),
            source: format!("{:?}", dec.span.source),
            original: show_values.then(|| nfc[dec.span.start..dec.span.end].to_string()),
        })
        .collect();
    Ok(Inspection {
        outcome,
        profile: d.profile,
        retried: d.retried,
        spans,
        reasons,
        replacements: d.candidate.as_ref().map_or(0, |c| c.replacements.len()),
        candidate: if show_values {
            d.candidate.map(|c| c.text)
        } else {
            None
        },
        limitations: limitations(&engine),
        rotation_days: ds.rotation_days,
        grace_days: ds.grace_days,
        epoch_started_at: ds.epoch_started_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// S5, L124(b), L129: the detection variant keeps separators only inside
    /// date and time shapes; IBAN, social security, and card groups are
    /// spaced so their regexes still match.
    #[test]
    fn detection_variant_keeps_digit_groups_joined() {
        for (s, want) in [
            ("foto-2025-07-14", "foto 2025-07-14"),
            (
                "Screenshot 2026-10-01 at 12.34.56",
                "Screenshot 2026-10-01 at 12.34.56",
            ),
            ("kontakt_0664-1234567", "kontakt 0664 1234567"),
            ("Angebot_Zyxwuria_Quolnath", "Angebot Zyxwuria Quolnath"),
            ("IMG_20261001_123456", "IMG 20261001 123456"),
            ("angebot_2026-03", "angebot 2026-03"),
            (
                "IBAN_AT61_1904_3002_3457_3201",
                "IBAN AT61 1904 3002 3457 3201",
            ),
            (
                "IBAN_DE66_3704_0044_0532_2010_12",
                "IBAN DE66 3704 0044 0532 2010 12",
            ),
            ("AT61.1904.3002.3457.3201", "AT61 1904 3002 3457 3201"),
            ("svnr_1237-010180", "svnr 1237 010180"),
            ("karte_4111_1111_1111_1111", "karte 4111 1111 1111 1111"),
            ("Grüße_2026", "Grüße 2026"),
        ] {
            assert_eq!(name_detection_variant(s), want);
            assert_eq!(name_detection_variant(s).len(), s.len());
        }
    }

    /// L130: on the detection variant of an identifier stem, the regex
    /// detector alone (no model) finds the identifier: the digit groups are
    /// spaced so the IBAN, social security and card patterns match.
    #[test]
    fn detection_variant_lets_the_regexes_find_identifiers() {
        use inumaki_core::detect::Detector;
        use inumaki_core::detect::regex::RegexDetector;
        use inumaki_core::span::EntityKind;
        let regex = RegexDetector::new();
        for (stem, kind, digits) in [
            ("IBAN_AT61_1904_3002_3457_3201", EntityKind::Iban, "3457"),
            ("AT61.1904.3002.3457.3201", EntityKind::Iban, "3457"),
            ("IBAN_DE66_3704_0044_0532_2010_12", EntityKind::Iban, "0532"),
            ("svnr_1237-010180", EntityKind::NationalId, "010180"),
            ("karte_4111_1111_1111_1111", EntityKind::CreditCard, "4111"),
        ] {
            let v = name_detection_variant(stem);
            let spans = regex.detect(&v, &DetectCtx::for_text(&v)).unwrap();
            assert!(
                spans
                    .iter()
                    .any(|s| s.kind == kind && v[s.start..s.end].contains(digits)),
                "{stem}: no {} span over {digits}",
                kind.label()
            );
        }
    }

    /// S31: a file-name result is never reused for a content block with the
    /// same text (a rare-surname document word dropped in a file name would
    /// be dropped in prose: a recall bug); `Free` keeps its strings, so the
    /// existing cache entries stay valid.
    #[test]
    fn cache_variant_differs_by_origin() {
        assert_eq!(cache_variant(&[], TextOrigin::Free).unwrap(), "text");
        assert_eq!(
            cache_variant(&[], TextOrigin::FileName).unwrap(),
            "text@file-name"
        );
        let r = vec![Redaction {
            start: 0,
            end: 4,
            kind: "PERSON".into(),
            action: inumaki_core::redact::RedactionAction::Tokenize,
        }];
        let json = serde_json::to_string(&r).unwrap();
        let free = cache_variant(&r, TextOrigin::Free).unwrap();
        assert_eq!(
            free,
            format!("redact:{}", inumaki_core::redact::sha256_hex(&json))
        );
        let file = cache_variant(&r, TextOrigin::FileName).unwrap();
        assert_ne!(free, file);
        assert_eq!(file, format!("{free}@file-name"));
    }

    /// Final review I5: each of the four conditions of the released-text
    /// gate, alone, keeps a block out of the proxy's skip set.
    #[test]
    fn only_free_text_passed_under_the_proxy_profile_outside_a_check_is_releasable() {
        let check = format!("{}x", crate::check::CHECK_PREFIX);
        let free = FieldHint::FreeText;
        assert!(releasable(
            "crm",
            "default",
            "default",
            &free,
            CachedOutcome::Pass
        ));
        assert!(
            !releasable(&check, "default", "default", &free, CachedOutcome::Pass),
            "a check run"
        );
        assert!(
            !releasable("crm", "fast", "default", &free, CachedOutcome::Pass),
            "another profile"
        );
        for hint in [
            FieldHint::Metadata,
            FieldHint::Identifier(EntityKind::Person),
        ] {
            assert!(
                !releasable("crm", "default", "default", &hint, CachedOutcome::Pass),
                "{hint:?}"
            );
        }
        for outcome in [CachedOutcome::PassUncertain, CachedOutcome::Blocked] {
            assert!(
                !releasable("crm", "default", "default", &free, outcome),
                "{outcome:?}"
            );
        }
    }

    /// An offline daemon state with an empty `mail` dataset.
    fn started() -> (AppState, tempfile::TempDir, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let models = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("inumaki.toml");
        std::fs::write(
            &cfg,
            format!(
                "{}\n[daemon]\ndefault_profile = \"offline\"\n[vault]\nkey_source = \"file\"\n[mirror]\nroot = \"{d}/mirror-root\"\noutbox_root = \"{d}/mirror-outbox\"\n",
                include_str!("../../../configs/default.toml"),
                d = dir.path().display()
            ),
        )
        .unwrap();
        let s = AppState::start(&crate::state::StartOptions {
            config: Some(cfg),
            data_dir: Some(dir.path().join("data")),
            socket: None,
            models_dir: Some(models.path().to_path_buf()),
            clock: None,
        })
        .unwrap();
        s.vault
            .create_dataset(&inumaki_vault::DatasetSpec::new("mail", "x", "offline"))
            .unwrap();
        (s, dir, models)
    }

    /// A passed result with `text` and no tokens.
    fn clear(text: &str) -> CachedResult {
        CachedResult {
            outcome: CachedOutcome::Pass,
            text: text.into(),
            replacements: 0,
            kinds: Vec::new(),
            reasons: Vec::new(),
            tokens: Vec::new(),
            replaced: Vec::new(),
            protected: Vec::new(),
            cross_request: false,
        }
    }

    fn assert_withheld_person_leak(r: &CachedResult) {
        assert_eq!(r.outcome, CachedOutcome::Blocked);
        assert!(r.text.is_empty(), "text withheld");
        assert!(
            r.reasons
                .iter()
                .any(|x| x.check == CheckId::Leak && x.kind == EntityKind::Person),
            "{:?}",
            r.reasons
        );
    }

    /// Task 7c fix round 2 (re-review (a)): the batch-end withhold. The
    /// batch minted `Quorvik Berger`; an earlier block (a cache hit) holds
    /// the bare `Quorvik`, which the known-entity release check does not
    /// see. A re-run that changes nothing (no real input does that) must
    /// leave the block withheld, and neither the old hit nor the re-run
    /// result may stay cached.
    #[test]
    fn a_rerun_that_keeps_a_store_copy_in_clear_is_withheld_and_not_cached() {
        let (s, _dir, _models) = started();
        let ns = s.namespace("mail").unwrap();
        let mut n = ns.lock().unwrap();
        let start = (n.epoch_id(), store_fingerprint(&n));
        n.token_for(&EntityKind::Person, "Quorvik Berger").unwrap();
        let text = "Das Paket für Quorvik liegt bereit.";
        let key = CacheKey::with_variant(
            "mail",
            n.epoch_id(),
            "offline",
            &s.config_fingerprint,
            "text",
            text,
        );
        s.cache.insert(key.clone(), clear(text));
        let mut results = vec![(clear(text), true)];
        let settled = settle_store_changes(
            &mut n,
            &mut results,
            s.vault.aliases(),
            Some(start),
            |_, _| Ok(Some(clear(text))),
        )
        .unwrap();
        assert_eq!(settled.withheld, [0]);
        let policy = s.engines.policy("offline").unwrap();
        release_and_cache(
            &s,
            &n,
            &policy,
            std::slice::from_ref(&key),
            &mut results,
            Vec::new(),
            settled,
        );
        assert_withheld_person_leak(&results[0].0);
        assert!(
            s.cache.get(&key).is_none(),
            "nothing of the block is cached"
        );
    }

    /// Task 7c fix round 2 (re-review (a)): the release-check withhold. A
    /// fresh block holding a known full name in clear (only a broken pass
    /// could produce it) is withheld and not cached.
    #[test]
    fn a_known_full_name_in_clear_is_withheld_at_release_and_not_cached() {
        let (s, _dir, _models) = started();
        let ns = s.namespace("mail").unwrap();
        let mut n = ns.lock().unwrap();
        n.token_for(&EntityKind::Person, "Quorvik Berger").unwrap();
        let text = "Quorvik Berger hat angerufen.";
        let key = CacheKey::with_variant(
            "mail",
            n.epoch_id(),
            "offline",
            &s.config_fingerprint,
            "text",
            text,
        );
        let mut results = vec![(clear(text), false)];
        let settled =
            settle_store_changes(&mut n, &mut results, s.vault.aliases(), None, |_, _| {
                panic!("a single-block batch is never re-run")
            })
            .unwrap();
        let policy = s.engines.policy("offline").unwrap();
        release_and_cache(
            &s,
            &n,
            &policy,
            std::slice::from_ref(&key),
            &mut results,
            vec![0],
            settled,
        );
        assert_withheld_person_leak(&results[0].0);
        assert!(
            s.cache.get(&key).is_none(),
            "a withheld block is not cached"
        );
    }

    /// A detector that always fails.
    struct Failing;
    impl inumaki_core::detect::Detector for Failing {
        fn id(&self) -> inumaki_core::span::DetectorId {
            inumaki_core::span::DetectorId::Ner
        }
        fn detect(
            &self,
            _: &str,
            _: &DetectCtx,
        ) -> inumaki_core::Result<Vec<inumaki_core::span::Span>> {
            Err(inumaki_core::Error::ModelUnavailable("test".into()))
        }
    }

    /// M5 review (Task 4, critical): a detector failure on either spelling
    /// of a name must withhold the stem, not pass it with no spans (the
    /// other spelling's release check would not see a name that is only
    /// detectable spaced), and nothing is minted.
    #[test]
    fn a_detector_failure_withholds_the_name_and_mints_nothing() {
        let core = inumaki_core::config::CoreConfig::from_toml(include_str!(
            "../../../configs/default.toml"
        ))
        .unwrap();
        let engine = Engine::from_config(&core, "offline", None, None)
            .unwrap()
            .with_detector(std::sync::Arc::new(Failing));
        let mut ctx = Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            TokenSettings::default(),
        );
        for (written, text) in [
            (true, "Angebot_Zyxwuria_Quolnath"),
            (false, "Angebot Zyxwuria Quolnath"),
        ] {
            match scan_variant(&engine, &mut ctx, text, written).unwrap() {
                Scan::Blocked(r) => assert_eq!(r.check, CheckId::DetectorError),
                Scan::Spans(_) => panic!("a failing detector must block the stem"),
            }
        }
        assert_eq!(ctx.entries().count(), 0, "nothing minted");
    }

    /// M5 integrator ruling (Task 4): phase 2 is fail closed. A spliced
    /// stem the verifier blocked or found uncertain leaves with no text;
    /// only a pass is released.
    #[test]
    fn a_spliced_stem_the_verifier_does_not_pass_is_withheld() {
        let result = |outcome| BlockResult {
            outcome,
            text: "Angebot_<PERSON_a1b2c3>".into(),
            replacements: 1,
            kinds: vec![EntityKind::Person],
            reasons: vec![Reason {
                kind: EntityKind::Person,
                check: CheckId::Ner,
            }],
            cached: false,
            replaced: vec![ReplacedSpan {
                start: 8,
                end: 23,
                out_start: 8,
                out_end: 23,
                kind: EntityKind::Person,
                action: Action::Tokenize,
            }],
        };
        let out = withhold_unless_pass(
            vec![
                result(CachedOutcome::Pass),
                result(CachedOutcome::PassUncertain),
                result(CachedOutcome::Blocked),
                result(CachedOutcome::Pass),
            ],
            vec![None, None, None, Some(detector_reason())],
        );
        assert_eq!(out[0].outcome, CachedOutcome::Pass);
        assert_eq!(out[0].text, "Angebot_<PERSON_a1b2c3>");
        assert!(out[0].replaced.is_empty(), "no spliced-stem offsets");
        for b in &out[1..] {
            assert_eq!(b.outcome, CachedOutcome::Blocked);
            assert!(b.text.is_empty());
            assert!(b.replaced.is_empty());
        }
        assert_eq!(out[1].reasons[0].check, CheckId::Ner, "reasons kept");
        assert_eq!(out[3].reasons[0].check, CheckId::DetectorError);
    }

    /// M5 re-review (Task 4, N1): the verifier's veto on the spaced
    /// spelling withholds the stem (a value the sanitizer missed there would
    /// otherwise reach the mirror, since phase 2 sees only the written
    /// spelling); the written spelling's verdict is ignored by design.
    ///
    /// The veto comes from the verifier's bare-identifier re-scan, which no
    /// sanitizer detector mirrors: a store name no longer serves, since the
    /// engine's referential-consistency pass (L3 step 2, Task 4) tokenizes a
    /// store value in either spelling before verification (asserted below).
    #[test]
    fn a_spaced_verifier_veto_withholds_the_name_but_the_written_one_does_not() {
        let core = inumaki_core::config::CoreConfig::from_toml(include_str!(
            "../../../configs/default.toml"
        ))
        .unwrap();
        let engine = Engine::from_config(&core, "offline", None, None).unwrap();
        let mut ctx = Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            TokenSettings::default(),
        );
        // No detector finds an unlabelled identifier; only the verifier's
        // bare-identifier re-scan sees it, and only in the spaced spelling.
        let written = scan_variant(&engine, &mut ctx, "Angebot_QX-48291", true).unwrap();
        assert!(matches!(written, Scan::Spans(s) if s.is_empty()));
        // The same spelling flagged as the written one: the verifier's veto
        // on it is ignored (the `!written &&` guard in `scan_variant`).
        let spaced_as_written = scan_variant(&engine, &mut ctx, "Angebot QX-48291", true).unwrap();
        assert!(
            matches!(spaced_as_written, Scan::Spans(_)),
            "the written spelling's verdict must be ignored"
        );
        let spaced = scan_variant(&engine, &mut ctx, "Angebot QX-48291", false).unwrap();
        match spaced {
            Scan::Blocked(r) => assert_eq!(r.check, CheckId::Regex),
            Scan::Spans(_) => panic!("the verifier's veto on the spaced spelling must block"),
        }
        // A store name is tokenized in both spellings, never left in clear.
        ctx.token_for(&EntityKind::Person, "Zyxwuria Quolnath")
            .unwrap();
        for (stem, written) in [
            ("Angebot_Zyxwuria_Quolnath", true),
            ("Angebot Zyxwuria Quolnath", false),
        ] {
            match scan_variant(&engine, &mut ctx, stem, written).unwrap() {
                Scan::Spans(s) => assert!(!s.is_empty(), "{stem:?}: the store name is tokenized"),
                Scan::Blocked(r) => panic!("{stem:?}: blocked by {:?}", r.check),
            }
        }
    }

    /// Fix round 1, finding 1(a): `original` carries the plaintext excerpt
    /// with `show_values`; `Debug` must never print it.
    #[test]
    fn inspect_span_debug_omits_the_original_value() {
        let span = InspectSpan {
            start: 0,
            end: 17,
            kind: "PERSON".to_string(),
            action: "tokenize".to_string(),
            source: "Dictionary".to_string(),
            original: Some("Zyxwuria Quolnath".to_string()),
        };
        let d = format!("{span:?}");
        assert!(!d.contains("Zyxwuria") && !d.contains("Quolnath"), "{d}");
        assert!(d.contains("has_original: true"), "{d}");
    }

    /// L2 review: a hit inside a protected token's output range is covered,
    /// so a release-time check never withholds a block for text the engine
    /// deliberately left alone. A hit outside it still counts.
    #[test]
    fn hits_inside_protected_ranges_are_covered() {
        let text = "ab <PERSON_a7f2> cd";
        let protected = Vec::from_iter([Range { start: 3, end: 16 }]);
        assert!(token_covers(text, &[], &protected, 4, 10));
        assert!(!token_covers(text, &[], &protected, 0, 2));
        assert!(!token_covers(text, &[], &protected, 10, 18), "straddling");
        assert!(!token_covers(text, &[], &[], 4, 10));
    }
}
