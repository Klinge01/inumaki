//! Request sanitization (M8 spec §5): definitions scanned, reasoning
//! scanned, leaves looked up in the session cache, misses through the
//! engine with the session view, tool results withheld by placeholder,
//! everything else fails closed. Blocking: callers use `spawn_blocking`.
//!
//! Fail closed: [`sanitize_request`] returns a body only when every leaf
//! was decided. Any error (engine, store, host, a refused leaf) returns a
//! [`Fail`] and no body, so the caller has nothing it could forward.
//!
//! Nothing here commits: cache entries and memoized verdicts come back in
//! [`Prepared`] and the handler inserts them only after the upstream
//! accepted the request (spec §5 step 7). Session tokens are minted while
//! sanitizing (the view locks the session only inside each mint), which is
//! harmless when the request then fails: the tokens never left.
//!
//! Privacy: `Prepared` and `Shared` print counts only; errors are the fixed
//! classes of spec §7 with entity-kind labels and check ids, never text.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use inumaki_core::detect::dictionary::DictionaryDetector;
use inumaki_core::detect::{DetectCtx, Detector, validate_span};
use inumaki_core::engine::{
    Abandon, Detailed, Engine, Outcome, Projection, ProjectionScratch, normalize_input,
};
use inumaki_core::policy::{Action, Profile};
use inumaki_core::redact::{Redaction, RedactionAction};
use inumaki_core::span::{DetectorId, EntityKind, Span};
use inumaki_core::token::{StoreError, TokenStore};
use inumaki_core::verify::CheckId;
use inumaki_core::{LinkScope, TextOrigin};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cache::{Cached, KeyMaker, LeafKey};
use crate::closure::{ClosureDict, Gen, Keep, SessionDict, outside_real_tokens, real_token};
use crate::config::{BinaryMode, ProxyConfig, UncertainMode};
use crate::error::Fail;
use crate::host::{HostError, ProxyHost};
use crate::json;
use crate::memo::{NerMemo, STATIC_MIN_BYTES};
use crate::routes::Wire;
use crate::session::{ClientMode, SeedStamp, Session, SessionView};
#[cfg(feature = "closure-shadow")]
use crate::shadow;
use crate::timing::{StageGuard, StageTimes, timed};
use crate::walk::{Class, Leaf, Role, Target, Walk};

/// What every request shares: settings, the host, the key maker, the OS
/// identity dictionary, the token matcher, the clean-definitions set, and
/// the static-prompt NER memo. `Debug` prints the profile name, flags, and
/// the memo's counts only.
pub(crate) struct Shared {
    pub cfg: ProxyConfig,
    pub host: Arc<dyn ProxyHost>,
    pub keys: KeyMaker,
    pub identity: Option<Arc<DictionaryDetector>>,
    /// `host.preserved_logins()`, read once.
    pub preserved_logins: Vec<String>,
    pub tokens: regex::Regex,
    pub clean_definitions: Mutex<CleanDefinitions>,
    /// The static-prompt NER memo (M8 spec §20, amendment 2026-10-12):
    /// `host.ner_memo()` when `cfg.static_cache` is on, else `None`. Its
    /// effective state (`static_cache.enabled`) is `memo.is_some()`.
    pub memo: Option<Arc<NerMemo>>,
    /// The leak closure's round budget (step 6b), [`CLOSURE_ROUNDS`]. Not
    /// configurable; tests lower it. `0` re-runs nothing: whatever the
    /// closure would settle fails closed.
    pub closure: usize,
    /// Test hook (step 6b): reopen every leaf projected in a round, as a
    /// dictionary disagreement would, so the full-engine fallback runs.
    #[cfg(test)]
    pub force_reopen_projected: bool,
}

impl fmt::Debug for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shared")
            .field("profile", &self.cfg.profile)
            .field("identity", &self.identity.is_some())
            .field("closure", &self.closure)
            .field("memo", &self.memo)
            .finish_non_exhaustive()
    }
}

impl Shared {
    /// Build from the configuration and the host: a fresh process key, the
    /// identity dictionary from `host.identity()` (none when it is empty),
    /// and the token matcher from `Rehydrator::pattern`.
    ///
    /// Fails closed with [`Fail::Internal`] when the identity dictionary
    /// cannot be built, rather than running without it.
    pub(crate) fn new(cfg: ProxyConfig, host: Arc<dyn ProxyHost>) -> Result<Shared, Fail> {
        let ids = host.identity();
        let preserved_logins = host.preserved_logins();
        let identity = if ids.iter().all(|(_, v)| v.trim().is_empty()) {
            None
        } else {
            Some(Arc::new(
                DictionaryDetector::from_entries(ids.iter().map(|(k, v)| (k.clone(), v.as_str())))
                    .map_err(|_| Fail::Internal)?,
            ))
        };
        let tokens = regex::Regex::new(&inumaki_core::rehydrate::Rehydrator::pattern(
            &cfg.session_tokens,
        ))
        .map_err(|_| Fail::Internal)?;
        let memo = if cfg.static_cache {
            host.ner_memo()
        } else {
            None
        };
        Ok(Shared {
            keys: KeyMaker::new(&cfg.profile, cfg.fingerprint),
            cfg,
            host,
            memo,
            identity,
            preserved_logins,
            tokens,
            clean_definitions: Mutex::new(CleanDefinitions::default()),
            closure: CLOSURE_ROUNDS,
            #[cfg(test)]
            force_reopen_projected: false,
        })
    }
}

/// Definition digests already scanned clean, valid for one dictionary
/// (review minor: keyed on the dictionary in use, bounded). Holding the
/// `Arc` keeps its address from being reused by a newer dictionary.
#[derive(Default)]
pub(crate) struct CleanDefinitions {
    dictionary: Option<Arc<dyn Detector>>,
    digests: HashSet<[u8; 32]>,
}

const CLEAN_DEFINITIONS_CAP: usize = 1024;

/// A sanitized request, not yet committed. `Debug` prints counts only.
pub(crate) struct Prepared {
    /// The body to forward.
    pub body: Vec<u8>,
    /// Cache entries for the leaves that missed and were sent (commit after
    /// the upstream accepted).
    pub inserts: Vec<(LeafKey, Cached)>,
    /// Memoized placeholders for tool results withheld by this request, and
    /// the keys of binary parts it replaced for the first time.
    pub memo: Vec<([u8; 32], String)>,
    /// The sanitized texts of the leaves that missed and were sent (the
    /// journal payload).
    pub missed: Vec<String>,
    /// Entity kinds tokenized in sent leaves, with leaf counts.
    pub kinds: Vec<(EntityKind, u32)>,
    /// One entry per tool result this request withheld (not those the memo
    /// answered): `(uncertain, kinds, checks)`.
    pub withheld: Vec<(bool, Vec<EntityKind>, Vec<String>)>,
    /// Leaves whose text changed.
    pub replacements: usize,
    /// Leaves answered from the cache.
    pub hits: u64,
    /// Leaves that went through the engine.
    pub misses: u64,
    /// A sent leaf passed as uncertain under `uncertain = "pass"`.
    pub uncertain_passed: bool,
    /// Cache hits still sent at the end, with the revision they were read
    /// at: their stamps advance to `claim` on commit (only while the entry
    /// is still that revision).
    pub verified: Vec<(LeafKey, u64)>,
    /// What this request verified its hits against: the session
    /// dictionary's `upto`, read after the view. Never the logs' length at
    /// commit (values minted meanwhile were not checked).
    pub claim: Gen,
    /// The stamp of `inserts`: the view's snapshot.
    pub insert_gen: Gen,
    /// The dataset-token digests every sent leaf was verified against: the
    /// view's dataset tokens at the end of the request (later closure
    /// rounds re-scan every sent leaf against the whole view). Inserts and
    /// `verified` bumps take it; seeds of this request's answer too.
    pub claim_ds: Arc<[u64]>,
    /// Seeded scanned leaves step 2 checked clean, applied on commit after
    /// the cache lock (`Session::seed_bump`).
    pub seed_bumps: Vec<SeedBump>,
    /// Leaves of tool results this request withheld: their cache entries
    /// go on commit (R4).
    pub evict: Vec<LeafKey>,
    /// Step 6b ran (tests and the bench).
    pub closure_ran: bool,
    /// Hit-derived leaves step 6b projected instead of re-running them
    /// (M8 spec §20, amendment 2026-10-12). Each also counts as a miss.
    pub projected: u64,
    /// Projections abandoned (the leaf took the full engine).
    pub projection_abandoned: u64,
    /// Store entries and removed values the projections minted.
    pub projection_mints: u64,
    /// Abandoned projections per fixed reason (the bench).
    pub abandoned_by: Vec<(Abandon, u32)>,
}

impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prepared")
            .field("body_len", &self.body.len())
            .field("inserts", &self.inserts.len())
            .field("memo", &self.memo.len())
            .field("missed", &self.missed.len())
            .field("kinds", &self.kinds.len())
            .field("withheld", &self.withheld.len())
            .field("replacements", &self.replacements)
            .field("hits", &self.hits)
            .field("misses", &self.misses)
            .field("uncertain_passed", &self.uncertain_passed)
            .field("verified", &self.verified.len())
            .field("claim", &self.claim)
            .field("insert_gen", &self.insert_gen)
            .field("claim_ds", &self.claim_ds.len())
            .field("seed_bumps", &self.seed_bumps.len())
            .field("evict", &self.evict.len())
            .field("closure_ran", &self.closure_ran)
            .field("projected", &self.projected)
            .field("projection_abandoned", &self.projection_abandoned)
            .field("projection_mints", &self.projection_mints)
            .field("abandoned_by", &self.abandoned_by.len())
            .finish()
    }
}

impl Prepared {
    pub(crate) fn empty() -> Prepared {
        Prepared {
            body: Vec::new(),
            inserts: Vec::new(),
            memo: Vec::new(),
            missed: Vec::new(),
            kinds: Vec::new(),
            withheld: Vec::new(),
            replacements: 0,
            hits: 0,
            misses: 0,
            uncertain_passed: false,
            verified: Vec::new(),
            claim: Gen::ZERO,
            insert_gen: Gen::ZERO,
            claim_ds: Arc::from([]),
            seed_bumps: Vec::new(),
            evict: Vec::new(),
            closure_ran: false,
            projected: 0,
            projection_abandoned: 0,
            projection_mints: 0,
            abandoned_by: Vec::new(),
        }
    }

    /// The stamp of the scanned leaves seeded from this request's answer
    /// (ruling I1, N1): what this request verified everything it sent
    /// against, so the provider saw those values only as tokens.
    pub(crate) fn seed_stamp(&self) -> SeedStamp {
        SeedStamp {
            generation: self.claim,
            ds: Arc::clone(&self.claim_ds),
        }
    }
}

/// A seeded leaf step 2 checked clean: `(digest, the stamp read at step 2,
/// sd.upto, the request's dataset digests at step 2)`. The bump applies
/// only while the seed's stamp still covers the one read.
pub(crate) type SeedBump = ([u8; 32], SeedStamp, Gen, Arc<[u64]>);

/// Commit a forwarded request's cache and memo changes (spec §5 step 7),
/// once the upstream took it. Under one cache lock, in this order: the
/// withheld leaves' entries go (`evict`), the sent misses are inserted at
/// `(insert_gen, claim_ds)`, and the sent hits' stamps advance to
/// `(claim, claim_ds)`, each only while its entry is still the revision it
/// was read at (a replaced entry is never vouched for). Then the seed
/// stamps step 2 checked, and the memo. Takes no `SessionStore` lock while
/// the cache guard is held.
pub(crate) fn commit_cache(session: &Session, p: &mut Prepared) {
    {
        let mut cache = session.cache();
        for k in std::mem::take(&mut p.evict) {
            cache.remove(&k);
        }
        for (k, v) in std::mem::take(&mut p.inserts) {
            cache.insert(k, v, p.insert_gen, Arc::clone(&p.claim_ds));
        }
        for (k, rev) in std::mem::take(&mut p.verified) {
            cache.bump(&k, rev, p.claim, &p.claim_ds);
        }
    }
    for (d, read, g, ds) in std::mem::take(&mut p.seed_bumps) {
        session.seed_bump(&d, &read, g, &ds);
    }
    for (k, v) in std::mem::take(&mut p.memo) {
        session.memo_put(k, v);
    }
}

/// A dataset token's keyed digest as cache slots and seed stamps store it
/// (ruling I3): the first 8 bytes, big-endian, of the `dataset-token`
/// digest. Never a value (decision 12); keyed per process.
pub(crate) fn ds_digest(sh: &Shared, token: &str) -> u64 {
    let d = sh.keys.digest("dataset-token", token.as_bytes());
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    u64::from_be_bytes(b)
}

/// Dataset tokens with their digests ([`ds_digest`]), sorted by digest and
/// deduplicated on it.
type DsTokens = Vec<(u64, String)>;

/// The view's dataset tokens with their digests.
fn ds_tokens(sh: &Shared, view: &SessionView<'_>) -> DsTokens {
    let mut v: Vec<(u64, String)> = view
        .dataset_tokens()
        .map(|t| (ds_digest(sh, t), t.to_string()))
        .collect();
    v.sort_unstable_by_key(|x| x.0);
    v.dedup_by_key(|x| x.0);
    v
}

/// The digest set of [`ds_tokens`]' output.
fn ds_set(v: &[(u64, String)]) -> Arc<[u64]> {
    v.iter().map(|x| x.0).collect()
}

/// The tokens of `req` whose digest `covered` lacks.
fn ds_missing<'t>(req: &'t [(u64, String)], covered: &[u64]) -> Vec<&'t str> {
    req.iter()
        .filter(|(d, _)| covered.binary_search(d).is_err())
        .map(|(_, t)| t.as_str())
        .collect()
}

/// A closure dictionary over the values the view resolved `tokens` to (a
/// dataset-coverage check). `None` when there are none. A build error is
/// `Fail::Internal` (a per-request dictionary).
fn ds_dict<'t>(
    view: &SessionView<'_>,
    tokens: impl Iterator<Item = &'t str>,
) -> Result<Option<ClosureDict>, Fail> {
    let d = ClosureDict::build(tokens.filter_map(|t| view.resolved(t)), std::iter::empty())
        .map_err(|_| Fail::Internal)?;
    Ok((!d.is_empty()).then_some(d))
}

pub(crate) fn host_fail(e: HostError) -> Fail {
    match e {
        HostError::ModelUnavailable => Fail::ModelUnavailable,
        HostError::VaultUnavailable => Fail::VaultUnavailable,
        HostError::Unsupported => Fail::UnsupportedContent,
        HostError::Internal => Fail::Internal,
    }
}

/// A store error during a request: the host failure behind it when there is
/// one, else `vault_unavailable` (spec §7: vault, namespace, or store error).
fn store_fail(view: &SessionView<'_>, _: StoreError) -> Fail {
    view.fault().map_or(Fail::VaultUnavailable, host_fail)
}

/// The fixed tool-result placeholder (spec decision 18).
pub(crate) fn placeholder(kinds: &[String]) -> String {
    format!(
        "[inumaki: tool result withheld (kinds: {}). Nothing was sent.]",
        kinds.join(", ")
    )
}

/// First-seen order, duplicates dropped.
pub(crate) fn dedup<T: PartialEq>(v: impl IntoIterator<Item = T>) -> Vec<T> {
    let mut out: Vec<T> = Vec::new();
    for x in v {
        if !out.contains(&x) {
            out.push(x);
        }
    }
    out
}

fn labels(kinds: &[EntityKind]) -> Vec<String> {
    dedup(kinds.iter().map(|k| k.label().to_string()))
}

/// The chat dictionary of one request (spec §5.4 as amended): the host's
/// datasets, the OS identity, and the session's closure-form dictionary.
/// Built once per request (review minor), not per leaf. `Debug` prints
/// counts only.
pub(crate) struct ChatDict {
    datasets: Arc<dyn Detector>,
    identity: Option<Arc<DictionaryDetector>>,
    session: Arc<SessionDict>,
}

impl fmt::Debug for ChatDict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChatDict")
            .field("identity", &self.identity.is_some())
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}

impl ChatDict {
    /// Fails closed: a host error is its class, never "no dictionary".
    pub(crate) fn new(sh: &Shared, session: Arc<SessionDict>) -> Result<ChatDict, Fail> {
        Ok(ChatDict {
            datasets: sh.host.dictionary().map_err(host_fail)?,
            identity: sh.identity.clone(),
            session,
        })
    }

    /// The host's dataset dictionary this request uses (the memo adopts it).
    pub(crate) fn datasets(&self) -> &Arc<dyn Detector> {
        &self.datasets
    }

    /// Host spans at full-match confidence (≥ 0.9) in `text` (NFC): the
    /// datasets' (resolved; the host detector is type-erased, plan Note 8)
    /// and the identity's, every overlapping match when `all`, else
    /// resolved. A detector error or a span that is not a valid range of
    /// `text` fails closed.
    pub(crate) fn host_spans(&self, text: &str, all: bool) -> Result<Vec<Span>, Fail> {
        let ctx = DetectCtx::for_text(text);
        let mut raw = self
            .datasets
            .detect(text, &ctx)
            .map_err(|_| Fail::ModelUnavailable)?;
        if let Some(id) = &self.identity {
            let found = if all {
                id.detect_all(text)
            } else {
                id.detect(text, &ctx)
            };
            raw.extend(found.map_err(|_| Fail::ModelUnavailable)?);
        }
        let mut out = Vec::with_capacity(raw.len());
        for s in raw {
            validate_span(text, &s).map_err(|_| Fail::Internal)?;
            if s.confidence >= 0.9 && s.start < s.end {
                out.push(s);
            }
        }
        Ok(out)
    }

    /// The first pass's redactions for `nfc`: host spans the policy does
    /// not preserve (every overlapping identity match, so a longer
    /// preserved match cannot hide a shorter one), tokenized; and every session-dictionary match of any
    /// kind (closure forms included), removed when it is a removed value
    /// or of a kind the policy removes, else tokenized (NEEDS (a)). A
    /// first-pass Tokenize outranks the engine's Preserve, so a store value
    /// of a preserved kind is tokenized too. Overlapping spans are all
    /// kept: the engine folds a redaction into every decision it overlaps
    /// and takes the union (`merge_redaction`), so a shorter match can
    /// never hide the rest of a longer one. Sorted `(start, Reverse(end))`.
    pub(crate) fn redactions(&self, policy: &Profile, nfc: &str) -> Result<Vec<Redaction>, Fail> {
        let mut out: Vec<Redaction> = self
            .host_spans(nfc, true)?
            .into_iter()
            .filter(|s| !preserved(policy, nfc, s))
            .map(|s| Redaction {
                start: s.start,
                end: s.end,
                kind: s.kind.label().to_string(),
                action: RedactionAction::Tokenize,
            })
            .collect();
        for seg in self.session.segments() {
            out.extend(closure_redactions(policy, seg.dict.spans(nfc)?));
        }
        out.sort_by_key(|r| (r.start, std::cmp::Reverse(r.end)));
        Ok(out)
    }
}

/// Whether the policy preserves span `s` of `text`: its kind is preserved,
/// unless it is an identifier-shaped ORGANIZATION (core's rule, I2: a
/// customer number tagged ORGANIZATION is never "preserved").
pub(crate) fn preserved(policy: &Profile, text: &str, s: &Span) -> bool {
    policy.action_for(s) == Some(Action::Preserve)
        && !(s.kind == EntityKind::Organization
            && inumaki_core::policy::identifier_shaped(s.slice(text)))
}

/// Closure-dictionary spans (`(span, removed)`) as redactions of every
/// kind: a removed value, or a kind the policy removes, is removed (never a
/// restorable token); anything else is tokenized. Unsorted.
fn closure_redactions(policy: &Profile, spans: Vec<(Span, bool)>) -> Vec<Redaction> {
    spans
        .into_iter()
        .map(|(s, removed)| Redaction {
            start: s.start,
            end: s.end,
            kind: s.kind.label().to_string(),
            action: if removed || policy.action_for(&s) == Some(Action::Remove) {
                RedactionAction::Remove
            } else {
                RedactionAction::Tokenize
            },
        })
        .collect()
}

/// The values a scanned leaf (`nfc`) holds in clear, as kinds (step 2, the
/// same rule on every turn, R2): host and identity matches (every
/// overlapping identity match) the policy does not preserve, and every
/// closure form of the session dictionary and of the dataset values this
/// request resolved (`datasets`), of any kind. A match lying entirely
/// inside a real token is exempt (`ClosureDict::clear_spans`'s rule).
fn step2_kinds(
    chat: &ChatDict,
    sd: &SessionDict,
    datasets: Option<&ClosureDict>,
    pol: &Profile,
    tokens: &regex::Regex,
    real: &dyn Fn(&str) -> bool,
    nfc: &str,
) -> Result<Vec<EntityKind>, Fail> {
    let host: Vec<Span> = chat
        .host_spans(nfc, true)?
        .into_iter()
        .filter(|s| !preserved(pol, nfc, s))
        .collect();
    let mut spans = outside_real_tokens(host, tokens, real, nfc);
    for d in sd.segments().map(|s| &s.dict).chain(datasets) {
        spans.extend(d.clear_spans(tokens, real, nfc)?);
    }
    Ok(dedup(spans.into_iter().map(|s| s.kind)))
}

/// The values of `extra` a scanned leaf (`nfc`) holds in clear, as kinds
/// (step 6b): the entries a request added since step 2, which already
/// scanned the host part and the session dictionary.
fn extra_kinds(
    extra: &[&ClosureDict],
    tokens: &regex::Regex,
    real: &dyn Fn(&str) -> bool,
    nfc: &str,
) -> Result<Vec<EntityKind>, Fail> {
    let mut kinds = Vec::new();
    for d in extra {
        kinds.extend(
            d.clear_spans(tokens, real, nfc)?
                .into_iter()
                .map(|s| s.kind),
        );
    }
    Ok(dedup(kinds))
}

/// The chat dictionary, built on first use.
fn chat_dict<'d>(
    dict: &'d mut Option<ChatDict>,
    sh: &Shared,
    sd: &Arc<SessionDict>,
) -> Result<&'d ChatDict, Fail> {
    if dict.is_none() {
        *dict = Some(ChatDict::new(sh, Arc::clone(sd))?);
    }
    dict.as_ref().ok_or(Fail::Internal)
}

/// The profile's policy, fetched on first use.
fn policy_of<'p>(policy: &'p mut Option<Arc<Profile>>, sh: &Shared) -> Result<&'p Profile, Fail> {
    if policy.is_none() {
        *policy = Some(sh.host.policy(&sh.cfg.profile).map_err(host_fail)?);
    }
    policy.as_deref().ok_or(Fail::Internal)
}

/// Step 1 (decision 24): definitions scanned with the host's
/// `scan_definitions`; a clean set is remembered for the dictionary in use.
/// Shared with plan M8-3's check routes.
pub(crate) fn check_definitions(sh: &Shared, w: &Walk) -> Result<(), Fail> {
    let defs: Vec<String> = w
        .leaves
        .iter()
        .filter(|l| l.class == Class::Definition)
        .map(|l| l.text.clone())
        .collect();
    if defs.is_empty() {
        return Ok(());
    }
    let dictionary = sh.host.dictionary().map_err(host_fail)?;
    // Length-prefixed, so no two different definition lists share a digest.
    let mut joined = Vec::with_capacity(defs.iter().map(|d| d.len() + 8).sum());
    for d in &defs {
        joined.extend_from_slice(&(d.len() as u64).to_be_bytes());
        joined.extend_from_slice(d.as_bytes());
    }
    let digest = sh.keys.digest("definitions", &joined);
    {
        let mut c = sh
            .clean_definitions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let same = c
            .dictionary
            .as_ref()
            .is_some_and(|d| Arc::ptr_eq(d, &dictionary));
        if !same {
            c.dictionary = Some(Arc::clone(&dictionary));
            c.digests.clear();
        }
        if c.digests.contains(&digest) {
            return Ok(());
        }
    }
    if !sh
        .host
        .scan_definitions(&defs)
        .map_err(host_fail)?
        .is_empty()
    {
        return Err(Fail::UnsupportedContent);
    }
    let mut c = sh
        .clean_definitions
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if c.dictionary
        .as_ref()
        .is_some_and(|d| Arc::ptr_eq(d, &dictionary))
    {
        if c.digests.len() >= CLEAN_DEFINITIONS_CAP {
            c.digests.clear();
        }
        c.digests.insert(digest);
    }
    Ok(())
}

/// One splice: a byte range and its replacement.
type Edit = (std::ops::Range<usize>, Vec<u8>);

/// Step 7: placeholders, replaced binary parts (`Walk::parts`), and changed
/// leaves spliced into the received bytes, and the walk's removed member
/// (`Walk::removed`) cut out. Returns the body and the count of changed
/// leaves. Shared with plan M8-3.
///
/// Arguments carried as JSON text are re-quoted with `json::quote` after
/// their inner strings change, so a provider-escaped `<` elsewhere in
/// that same argument string becomes a literal `<`. That changes the bytes
/// of a changed argument string only (an unchanged one is never re-quoted),
/// which the next turn's seed covers; it is a known, bounded prompt-cache cost.
///
/// Overlapping edits (which a consistent walk never yields) fail closed
/// with [`Fail::Internal`].
pub(crate) fn apply_edits(
    body: &[u8],
    w: &Walk,
    new_text: &[Option<String>],
    group_placeholder: &HashMap<usize, String>,
) -> Result<(Vec<u8>, usize), Fail> {
    let node = |n: usize| w.nodes.get(n).ok_or(Fail::Internal);
    let mut edits: Vec<Edit> = Vec::new();
    // The member the walk dropped (ruling L58): no leaf or group lies in it,
    // so an overlap here is an inconsistent walk and fails closed below.
    if let Some(r) = &w.removed {
        edits.push((r.clone(), Vec::new()));
    }
    for (g, p) in group_placeholder {
        let grp = w.groups.get(*g).ok_or(Fail::Internal)?;
        edits.push((node(grp.node)?.range.clone(), json::quote(p).into_bytes()));
    }
    // A part is replaced whole; no leaf lies in it. A tool result inside one
    // overlaps it and fails closed below (M8 spec §20 amendment 2026-10-11).
    for part in &w.parts {
        edits.push((node(part.node)?.range.clone(), part.replacement.to_vec()));
    }
    let mut inner: HashMap<usize, Vec<Edit>> = HashMap::new();
    let mut changed = 0usize;
    for (i, l) in w.leaves.iter().enumerate() {
        if l.group.is_some_and(|g| group_placeholder.contains_key(&g)) {
            continue;
        }
        let Some(Some(t)) = new_text.get(i) else {
            continue;
        };
        if *t == l.text {
            continue;
        }
        changed += 1;
        match &l.target {
            Target::Node(n) => edits.push((node(*n)?.range.clone(), json::quote(t).into_bytes())),
            Target::Inner { node, range } => inner
                .entry(*node)
                .or_default()
                .push((range.clone(), json::quote(t).into_bytes())),
        }
    }
    for (n, e) in inner {
        let nd = node(n)?;
        let decoded = nd.text.as_deref().ok_or(Fail::Internal)?;
        let spliced = json::splice(decoded.as_bytes(), e).map_err(|_| Fail::Internal)?;
        let s = String::from_utf8(spliced).map_err(|_| Fail::Internal)?;
        edits.push((nd.range.clone(), json::quote(&s).into_bytes()));
    }
    Ok((
        json::splice(body, edits).map_err(|_| Fail::Internal)?,
        changed,
    ))
}

fn replaced_kinds(s: &inumaki_core::sanitize::Sanitized) -> Vec<EntityKind> {
    s.replacements
        .iter()
        .filter(|r| matches!(r.action, Action::Tokenize | Action::Remove))
        .map(|r| r.span.kind.clone())
        .collect()
}

/// The released-block re-check's dataset dictionary, with the number of
/// dataset tokens the view had resolved when it was built.
type ReleasedDs = (usize, Option<ClosureDict>);

/// Spec §14 (I10), review I10: whether a released tool result (`text`, as
/// received) may skip the engine. Only when all of these hold; any doubt
/// is `false` (the full engine runs) and any error propagates (fail
/// closed):
///
/// - the text is already NFC, so the bytes sent, the bytes step 6b scans,
///   and the bytes checked here are the same;
/// - every token-shaped string in it is a real token of the view
///   (`real_token`: resolved or minted, or a removed marker the system
///   emits); a forged or unresolved one is ordinary text;
/// - step 2's rule finds nothing (`step2_kinds`): no host or identity value
///   the policy does not preserve, no closure form of any session value of
///   any kind, no closure form of a dataset value this request resolved
///   (this block's own tokens included: they were just prepared);
/// - the validated-regex tier finds nothing the policy does not preserve
///   on the text with the real tokens' random parts masked.
#[allow(clippy::too_many_arguments)]
fn released_clean(
    sh: &Shared,
    view: &mut SessionView<'_>,
    dict: &mut Option<ChatDict>,
    policy: &mut Option<Arc<Profile>>,
    sd: &Arc<SessionDict>,
    ds: &mut Option<ReleasedDs>,
    text: &str,
) -> Result<bool, Fail> {
    let std::borrow::Cow::Borrowed(nfc) = normalize_input(text) else {
        return Ok(false);
    };
    let found: Vec<std::ops::Range<usize>> = sh.tokens.find_iter(nfc).map(|m| m.range()).collect();
    if !found.is_empty() {
        let names: Vec<String> = dedup(found.iter().map(|r| nfc[r.clone()].to_string()));
        view.prepare(&names).map_err(|e| store_fail(view, e))?;
        if !names.iter().all(|t| real_token(&*view, t)) {
            return Ok(false);
        }
    }
    let n = view.dataset_tokens().count();
    if ds.as_ref().is_none_or(|(m, _)| *m != n) {
        *ds = Some((n, ds_dict(view, view.dataset_tokens())?));
    }
    let datasets = ds.as_ref().and_then(|(_, d)| d.as_ref());
    let chat = chat_dict(dict, sh, sd)?;
    let pol = policy_of(policy, sh)?;
    let real = |x: &str| real_token(&*view, x);
    if !step2_kinds(chat, sd, datasets, pol, &sh.tokens, &real, nfc)?.is_empty() {
        return Ok(false);
    }
    let masked = inumaki_core::protect::mask(nfc, &found, view.settings()).map(Zeroizing::new);
    let probe = masked.as_deref().map_or(nfc, String::as_str);
    let hits = inumaki_core::detect::regex::RegexDetector::new()
        .detect(probe, &DetectCtx::for_text(probe))
        .map_err(|_| Fail::Internal)?;
    for s in &hits {
        validate_span(probe, s).map_err(|_| Fail::Internal)?;
        if s.source == DetectorId::RegexValidated && !preserved(pol, probe, s) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// At most this many closure rounds per request (step 6b).
const CLOSURE_ROUNDS: usize = 4;

/// The text origin of leaf `l` in a request of client mode `mode` (M8
/// spec §20, amendment 2026-10-20; rulings L107, L120, L122):
/// `HarnessStatic` only for a `Class::Text` leaf with `Role::System` under
/// the leading system prompt (`Leaf::leading`: Messages top-level
/// `system`, Responses `instructions`, and the leading run of
/// system/developer items of the Responses `input` or Chat `messages`
/// array) of a trusted request. Every other leaf, a system/developer item
/// after the leading run included, and every leaf of a restricted request,
/// is `Free`. From the position only, never the text (ruling L60).
pub(crate) fn leaf_origin(l: &Leaf, mode: ClientMode) -> TextOrigin {
    match (l.class, l.role, mode) {
        (Class::Text, Role::System, ClientMode::Trusted) if l.leading => TextOrigin::HarnessStatic,
        _ => TextOrigin::Free,
    }
}

/// Whether a leaf of `origin` (NFC text `nfc`) may use the static-prompt
/// NER memo (M8 spec §20, amendment 2026-10-12): a harness-static leaf of
/// at least [`STATIC_MIN_BYTES`]. The caller adds that a memo exists
/// (`static_cache` on and provided by the host).
fn static_eligible(origin: TextOrigin, nfc: &str) -> bool {
    origin == TextOrigin::HarnessStatic && nfc.len() >= STATIC_MIN_BYTES
}

/// The cache key of leaf `l` of text origin `origin`.
fn leaf_key(sh: &Shared, wire: Wire, l: &Leaf, origin: TextOrigin) -> LeafKey {
    sh.keys.leaf(wire, l.class, origin, l.text.as_bytes())
}

/// One miss through the engine with the chat dictionary's redactions plus
/// `extra`, as a verdict. A detector failure is an availability error,
/// never a privacy verdict (review I1): no placeholder, no memo. `memo` is
/// the static-prompt memo for a harness-static leaf, else `None`
/// ([`leaf_detailed`]).
#[allow(clippy::too_many_arguments)]
fn leaf_verdict(
    sh: &Shared,
    eng: &Engine,
    view: &mut SessionView<'_>,
    chat: &ChatDict,
    policy: &Profile,
    nfc: &str,
    extra: Vec<Redaction>,
    origin: TextOrigin,
    memo: Option<&NerMemo>,
) -> Result<Verdict, Fail> {
    leaf_detailed(sh, eng, view, chat, policy, nfc, extra, origin, memo).map(|(_, v)| v)
}

/// [`leaf_verdict`], keeping the engine's [`Detailed`] beside the verdict
/// (the closure's shadow re-run compares it). The same redaction set and
/// the same outcome-to-verdict mapping. The engine reads `origin` in the
/// sanitizer's technical filter and in the verifier of both passes.
///
/// With a `memo` (an eligible leaf of a trusted request), the memo first
/// adopts the request's dataset dictionary (clearing itself when it is new
/// to it), then a memo scope for `nfc` is held across the engine call, so
/// the engine's wrapped NER detectors may answer from the memo. No scope
/// opens, and the models run, when the request's dictionary is no longer
/// the host's current one or the host cannot say which one is.
#[allow(clippy::too_many_arguments)]
fn leaf_detailed(
    sh: &Shared,
    eng: &Engine,
    view: &mut SessionView<'_>,
    chat: &ChatDict,
    policy: &Profile,
    nfc: &str,
    extra: Vec<Redaction>,
    origin: TextOrigin,
    memo: Option<&NerMemo>,
) -> Result<(Detailed, Verdict), Fail> {
    let mut reds = chat.redactions(policy, nfc)?;
    if !extra.is_empty() {
        reds.extend(extra);
        reds.sort_by_key(|r| (r.start, std::cmp::Reverse(r.end)));
    }
    let scope = memo.and_then(|m| {
        let current = sh.host.dictionary().ok()?;
        let is_current = std::ptr::addr_eq(Arc::as_ptr(chat.datasets()), Arc::as_ptr(&current));
        drop(current);
        // A request whose dictionary is no longer the host's (in flight
        // across a change) opens no scope: the models run (S5).
        if !is_current {
            return None;
        }
        m.adopt(chat.datasets(), true);
        Some(m.scope(nfc))
    });
    let detailed = eng
        .process_scoped_at(nfc, view, &reds, &LinkScope::empty(), origin)
        .map_err(|e| store_fail(view, e));
    drop(scope);
    let detailed = detailed?;
    let checks =
        |r: &[inumaki_core::verify::Reason]| dedup(r.iter().map(|r| format!("{:?}", r.check)));
    let verdict = match &detailed.outcome {
        Outcome::Pass { sanitized } => Verdict::Text {
            kinds: replaced_kinds(sanitized),
            text: sanitized.text.clone(),
            uncertain: false,
        },
        Outcome::PassUncertain { sanitized, .. } if sh.cfg.uncertain == UncertainMode::Pass => {
            Verdict::Text {
                kinds: replaced_kinds(sanitized),
                text: sanitized.text.clone(),
                uncertain: true,
            }
        }
        Outcome::PassUncertain { reasons, .. } => Verdict::Blocked {
            uncertain: true,
            kinds: dedup(reasons.iter().map(|r| r.kind.clone())),
            checks: checks(reasons),
        },
        Outcome::Blocked { reasons, .. }
            if reasons.iter().any(|r| r.check == CheckId::DetectorError) =>
        {
            return Err(Fail::ModelUnavailable);
        }
        Outcome::Blocked { reasons, kinds } => Verdict::Blocked {
            uncertain: false,
            kinds: dedup(kinds.iter().cloned()),
            checks: checks(reasons),
        },
    };
    Ok((detailed, verdict))
}

/// Spec §20 (2026-10-12): project a hit-derived leaf's text `t0`. The
/// caller check is the first pass's host and identity part (values the
/// policy does not preserve), outside the given token ranges. A store
/// error is the store's failure class; `Inconsistent` is `Fail::Internal`.
///
/// The projection takes no text origin (M8 spec §20, amendment 2026-10-20):
/// its verifier kit has no NER re-scan and no sanitizer detector runs, so
/// neither effect of the origin can occur; the cached `t0` was produced
/// under the leaf's origin (the cache key holds it), and an abandoned
/// projection falls through to a full re-run with that origin.
fn project_leaf(
    _sh: &Shared,
    eng: &Engine,
    view: &mut SessionView<'_>,
    chat: &ChatDict,
    pol: &Profile,
    t0: &str,
    scratch: &mut ProjectionScratch,
) -> Result<Projection, Fail> {
    let caller = |p: &str, toks: &[std::ops::Range<usize>]| -> Result<bool, ()> {
        let spans = chat.host_spans(p, true).map_err(|_| ())?;
        Ok(!spans.iter().any(|s| {
            !preserved(pol, p, s) && !toks.iter().any(|t| t.start <= s.start && s.end <= t.end)
        }))
    };
    let t0 = Zeroizing::new(t0.to_string());
    match eng.project(&t0, view, &caller, scratch) {
        Ok(Projection::Inconsistent) => {
            #[cfg(feature = "closure-shadow")]
            shadow::invariant_violation();
            Err(Fail::Internal)
        }
        Ok(p) => Ok(p),
        Err(e) => Err(store_fail(view, e)),
    }
}

/// One more abandonment of `reason` (find or push).
fn bump(by: &mut Vec<(Abandon, u32)>, reason: Abandon) {
    match by.iter_mut().find(|(r, _)| *r == reason) {
        Some((_, n)) => *n += 1,
        None => by.push((reason, 1)),
    }
}

/// The shadow mode's comparison of a projection (`text`, from the cached
/// `t0` with the replacements `replaced`) with the full re-run `detailed` /
/// `v` of the same leaf (`nfc`): D1, R1 and D2. Counts only.
#[cfg(feature = "closure-shadow")]
fn shadow_compare(
    sh: &Shared,
    detailed: &Detailed,
    v: &Verdict,
    nfc: &str,
    text: &str,
    t0: &str,
    replaced: &[(std::ops::Range<usize>, EntityKind)],
) {
    if let Some(full) = &detailed.candidate {
        shadow::d1(full, nfc, text, &sh.tokens);
        shadow::r1(replaced, t0, &full.text, &sh.tokens);
    }
    // Blocked, deferred, or settled uncertain by the full re-run while the
    // projection passed the leaf.
    let none = || vec!["-".to_string()];
    let (checks, kinds) = match v {
        Verdict::Blocked { kinds, checks, .. } => (checks.clone(), labels(kinds)),
        Verdict::Text {
            uncertain: true,
            kinds,
            ..
        } => (vec!["Uncertain".to_string()], labels(kinds)),
        Verdict::Text { .. } => return,
    };
    let (checks, kinds) = (
        if checks.is_empty() { none() } else { checks },
        if kinds.is_empty() { none() } else { kinds },
    );
    for c in &checks {
        for k in &kinds {
            shadow::d2(c, k);
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Set while a [`disable_projection_on_this_thread`] guard lives.
    static NO_PROJECTION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// How much the store grew across projections abandoned on this
    /// thread (an abandoned projection must mint nothing).
    static ABANDONED_GROWTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Test probe: the store growth across every projection abandoned on this
/// thread so far (entries plus removed values, measured around each call).
#[cfg(test)]
pub(crate) fn abandoned_growth_on_this_thread() -> usize {
    ABANDONED_GROWTH.with(std::cell::Cell::get)
}

/// Test switch (P7): step 6b projects nothing on this thread while the
/// returned guard lives, so the full-engine path for hits stays pinned.
#[cfg(test)]
pub(crate) fn disable_projection_on_this_thread() -> impl Drop {
    struct Guard(bool);
    impl Drop for Guard {
        fn drop(&mut self) {
            NO_PROJECTION.with(|c| c.set(self.0));
        }
    }
    Guard(NO_PROJECTION.with(|c| c.replace(true)))
}

/// Whether step 6b may project (always, outside tests).
fn projection_enabled() -> bool {
    #[cfg(test)]
    {
        !NO_PROJECTION.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        true
    }
}

/// A leaf step 6b has still to settle: `(leaf, kinds, checks)`.
type Unsettled = (usize, Vec<EntityKind>, Vec<String>);

/// A verdict the closure may still settle: blocked by the leak check alone.
fn leak_only(uncertain: bool, checks: &[String]) -> bool {
    !uncertain && !checks.is_empty() && checks.iter().all(|c| c == "Leak")
}

enum Verdict {
    Text {
        text: String,
        kinds: Vec<EntityKind>,
        uncertain: bool,
    },
    Blocked {
        uncertain: bool,
        kinds: Vec<EntityKind>,
        checks: Vec<String>,
    },
}

/// A miss that passed, kept until the end so the leaves of a group withheld
/// later in the same request are neither cached nor journaled.
struct Passed {
    leaf: usize,
    key: LeafKey,
    text: String,
    tokens: Vec<String>,
    kinds: Vec<EntityKind>,
    uncertain: bool,
}

/// The groups this request replaces by a placeholder, and the memo entries
/// it adds.
struct Withheld<'a> {
    sh: &'a Shared,
    wire: Wire,
    body: &'a [u8],
    w: &'a Walk,
    placeholder: HashMap<usize, String>,
    memo: Vec<([u8; 32], String)>,
    records: Vec<(bool, Vec<EntityKind>, Vec<String>)>,
    /// The cache keys of the withheld groups' leaves (R4).
    evict: Vec<LeafKey>,
    /// The text origin of each leaf of `w`, by leaf index.
    origins: &'a [TextOrigin],
}

impl Withheld<'_> {
    /// The memo key of group `g`: a keyed digest of its value's bytes.
    fn key(&self, g: usize) -> Result<[u8; 32], Fail> {
        let node = self
            .w
            .groups
            .get(g)
            .and_then(|grp| self.w.nodes.get(grp.node))
            .ok_or(Fail::Internal)?;
        let bytes = self.body.get(node.range.clone()).ok_or(Fail::Internal)?;
        Ok(self.sh.keys.digest("group", bytes))
    }

    fn contains(&self, g: Option<usize>) -> bool {
        g.is_some_and(|g| self.placeholder.contains_key(&g))
    }

    /// Withhold group `g` with a new verdict: placeholder, memo, record,
    /// and its leaves' cache keys to evict (a group the memo answered adds
    /// none: its leaves were evicted when the memo entry was made).
    fn add(
        &mut self,
        g: usize,
        labels: &[String],
        record: (bool, Vec<EntityKind>, Vec<String>),
    ) -> Result<(), Fail> {
        if self.placeholder.contains_key(&g) {
            return Ok(());
        }
        let p = placeholder(labels);
        self.memo.push((self.key(g)?, p.clone()));
        self.placeholder.insert(g, p);
        self.records.push(record);
        for (l, &origin) in self.w.leaves.iter().zip(self.origins) {
            if l.group == Some(g)
                && matches!(l.class, Class::Text | Class::ToolResult | Class::ToolInput)
            {
                self.evict.push(leaf_key(self.sh, self.wire, l, origin));
            }
        }
        Ok(())
    }
}

/// Step 3 (M8 spec §20 amendment 2026-10-11): whether binary content
/// outside tool results refuses the request. `forward` sends it; `refuse`
/// refuses any; `placeholder` refuses only binary the walk could not place
/// in a part (its parts are replaced at step 7). A walk made for another
/// mode errs toward refusing or replacing, never toward forwarding.
fn binary_refused(sh: &Shared, w: &Walk) -> bool {
    match sh.cfg.binary {
        BinaryMode::Forward => false,
        BinaryMode::Refuse => w.user_binary || !w.parts.is_empty(),
        BinaryMode::Placeholder => w.user_binary,
    }
}

/// The memo keys of a request's binary parts, distinct: a keyed digest of
/// each part's bytes (M8 spec §20 amendment 2026-10-11). Never logged.
fn part_keys(sh: &Shared, body: &[u8], w: &Walk) -> Result<Vec<[u8; 32]>, Fail> {
    let mut keys = Vec::with_capacity(w.parts.len());
    for part in &w.parts {
        let range = w.nodes.get(part.node).ok_or(Fail::Internal)?.range.clone();
        let bytes = body.get(range).ok_or(Fail::Internal)?;
        keys.push(sh.keys.digest("part", bytes));
    }
    keys.sort_unstable();
    keys.dedup();
    Ok(keys)
}

/// The two engines a request may use, each fetched on first use: the
/// memo-wrapped one (`ProxyHost::engine`) and the unwrapped one
/// (`ProxyHost::engine_unmemoized`).
#[derive(Default)]
struct LeafEngines {
    wrapped: Option<Arc<Engine>>,
    plain: Option<Arc<Engine>>,
    ner_free: Option<Arc<Engine>>,
}

/// Which engine runs a leaf ([`leaf_engine`]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum EngineKind {
    /// The memo-wrapped engine (an eligible harness-static leaf).
    Memoized,
    /// The unwrapped engine.
    Plain,
    /// The engine without either NER model (a harness-static leaf of a
    /// setting that skips them, [`crate::config::StaticNer`]).
    NerFree,
}

/// The engine for one leaf (M8 spec §20, 2026-10-12; rulings L2-40, L2-42):
/// the memo-wrapped engine only when the leaf uses the memo (`memoized`:
/// an eligible leaf of a trusted request with the memo on), else the
/// unwrapped one. A leaf without a scope thus never runs a wrapped
/// detector, so it cannot read or write the memo through another request's
/// open scope on the same bytes.
fn leaf_engine(sh: &Shared, e: &mut LeafEngines, kind: EngineKind) -> Result<Arc<Engine>, Fail> {
    let slot = match kind {
        EngineKind::Memoized => &mut e.wrapped,
        EngineKind::Plain => &mut e.plain,
        EngineKind::NerFree => &mut e.ner_free,
    };
    if let Some(eng) = slot {
        return Ok(Arc::clone(eng));
    }
    let eng = match kind {
        EngineKind::Memoized => sh.host.engine(&sh.cfg.profile),
        EngineKind::Plain => sh.host.engine_unmemoized(&sh.cfg.profile),
        EngineKind::NerFree => sh.host.engine_static(&sh.cfg.profile),
    }
    .map_err(host_fail)?;
    *slot = Some(Arc::clone(&eng));
    Ok(eng)
}

/// Sanitize one request body (spec §5 steps 3–5). Blocking.
///
/// A streamed request (`"stream": true`) is sanitized like any other; its
/// answer is restored by the stream rewriter (plan M8-2).
///
/// Order: definitions, binary user content,
/// groups the session memo already decided, binary tool results, cache
/// lookups, the view (resolving the hits' and the scanned leaves' tokens),
/// the session dictionary, scanned leaves, misses through the engine, the
/// leak closure, then the edits.
///
/// `skip_static_ner` is `[proxy] harness_static_ner = "skip"`
/// ([`crate::config::StaticNer`]): a harness-static leaf then runs on
/// [`ProxyHost::engine_static`], without the NER models.
///
/// `mode` is the request's client mode (decision 23). It also decides the
/// text origin of each leaf ([`leaf_origin`]): only a trusted request has
/// harness-static leaves. Only a trusted request uses the static-prompt NER
/// memo, and only for eligible leaves ([`static_eligible`]): those run on
/// `ProxyHost::engine`, whose NER detectors the memo wraps. Every other
/// leaf, every leaf of a restricted request, and every leaf while the memo
/// is off run on `ProxyHost::engine_unmemoized`, so they never touch the
/// memo, not even through another request's open scope ([`leaf_engine`]).
#[allow(clippy::too_many_arguments)]
pub(crate) fn sanitize_request(
    sh: &Shared,
    session: &Session,
    wire: Wire,
    body: &[u8],
    w: &Walk,
    mode: ClientMode,
    skip_static_ner: bool,
    times: &mut StageTimes,
) -> Result<Prepared, Fail> {
    // Shared from here: the stage guards add their time on every exit.
    let times: &StageTimes = times;
    let host = &*sh.host;
    let origins: Vec<TextOrigin> = w.leaves.iter().map(|l| leaf_origin(l, mode)).collect();
    // A harness-static leaf of a route that skips the NER models runs on
    // the model-free engine, and so never uses the memo (which memoizes
    // model output).
    let ner_free = |origin: TextOrigin| skip_static_ner && origin == TextOrigin::HarnessStatic;
    let engine_kind = |origin: TextOrigin, memo: bool| {
        if ner_free(origin) {
            EngineKind::NerFree
        } else if memo {
            EngineKind::Memoized
        } else {
            EngineKind::Plain
        }
    };
    // The memo for a leaf of `origin` (NFC `nfc`): a harness-static leaf.
    let memo_for = |origin: TextOrigin, nfc: &str| {
        sh.memo
            .as_deref()
            .filter(|_| !ner_free(origin) && static_eligible(origin, nfc))
    };
    // 1. Definitions (decision 24).
    check_definitions(sh, w)?;
    // 3. Binary outside tool results.
    if binary_refused(sh, w) {
        return Err(Fail::UnsupportedContent);
    }
    let mut out = Prepared::empty();
    let mut held = Withheld {
        sh,
        wire,
        body,
        w,
        placeholder: HashMap::new(),
        memo: Vec::new(),
        records: Vec::new(),
        evict: Vec::new(),
        origins: &origins,
    };
    // Replaced parts the session has not sent before: counted as `BINARY`
    // in the released record, and memoized on commit so a resend counts
    // nothing (the value is unused; the key is the record).
    let mut new_parts = 0u32;
    for k in part_keys(sh, body, w)? {
        if session.memo_get(&k).is_none() {
            new_parts += 1;
            held.memo.push((k, String::new()));
        }
    }
    // 4. Groups already decided. The memo first: a resend of a withheld
    // result emits the same bytes and records nothing new (Review Focus 1).
    // An empty memo needs no keys (one HMAC over each tool result saved).
    let memo_empty = session.memo_is_empty();
    for (g, grp) in w.groups.iter().enumerate() {
        let memoized = if memo_empty {
            None
        } else {
            session.memo_get(&held.key(g)?)
        };
        if let Some(p) = memoized {
            held.placeholder.insert(g, p);
        } else if grp.binary && sh.cfg.binary != BinaryMode::Forward {
            // Recorded and counted like any withheld result (review minor).
            held.add(
                g,
                &["BINARY".into()],
                (false, Vec::new(), vec!["Binary".into()]),
            )?;
        }
    }
    let mut dict: Option<ChatDict> = None;
    let mut policy: Option<Arc<Profile>> = None;
    // 5. Cache lookups (one short cache lock); hit tokens must still resolve.
    // Each hit keeps its key, stamps, and revision for step 6b and commit.
    let mut new_text: Vec<Option<String>> = vec![None; w.leaves.len()];
    let mut hits: Vec<(usize, LeafKey, crate::cache::Hit)> = Vec::new();
    let mut misses: Vec<usize> = Vec::new();
    {
        let cache = session.cache();
        for (i, l) in w.leaves.iter().enumerate() {
            if !matches!(l.class, Class::Text | Class::ToolResult | Class::ToolInput)
                || held.contains(l.group)
            {
                continue;
            }
            let key = leaf_key(sh, wire, l, origins[i]);
            match cache.get(&key) {
                Some(h) => hits.push((i, key, h)),
                None => misses.push(i),
            }
        }
    }
    // The scanned leaves step 2 checks (decision 14), NFC, as the
    // dictionaries see them; each with its seed digest and stamp when it is
    // provider-written text seeded from an answer (ruling I1: checked only
    // against what its stamp does not cover; a lost stamp is unseeded).
    type ToScan<'b> = (
        usize,
        std::borrow::Cow<'b, str>,
        Option<([u8; 32], SeedStamp)>,
    );
    let to_scan: Vec<ToScan<'_>> = w
        .leaves
        .iter()
        .enumerate()
        .filter(|(_, l)| l.class == Class::Scan && !held.contains(l.group))
        .map(|(i, l)| {
            let d = sh.keys.digest("scan", l.text.as_bytes());
            let seed = session.seed_stamp(&d).map(|st| (d, st));
            (i, normalize_input(&l.text), seed)
        })
        .collect();
    // The view, then one `prepare`: the hits' tokens, and every
    // token-shaped string in the scanned leaves, so that `real_token`
    // resolves a real one there (a forged one stays unresolved, M4).
    let mut view = SessionView::new(session, host, sh.cfg.session_tokens.clone());
    let hit_tokens: HashSet<&str> = hits
        .iter()
        .flat_map(|(_, _, h)| h.cached.tokens.iter().map(String::as_str))
        .collect();
    let scan_tokens: Vec<String> = dedup(
        to_scan
            .iter()
            .flat_map(|(_, t, _)| sh.tokens.find_iter(t).map(|m| m.as_str().to_string())),
    );
    let to_prepare: Vec<String> = hit_tokens
        .iter()
        .map(|t| t.to_string())
        .chain(
            scan_tokens
                .iter()
                .filter(|t| !hit_tokens.contains(t.as_str()))
                .cloned(),
        )
        .collect();
    if !to_prepare.is_empty() {
        view.prepare(&to_prepare)
            .map_err(|e| store_fail(&view, e))?;
    }
    drop(hit_tokens);
    drop(scan_tokens);
    // Leaves answered from the cache: step 6b scans their cached text too.
    // `stamp[i]`: a hit's key, `Gen`, dataset digests (plan Task 4b), and
    // revision.
    let mut hit = vec![false; w.leaves.len()];
    // `hit_derived[i]`: leaf `i`'s current text is a cache hit's (or, in
    // step 6b, its projection's), so it already crossed on this route under
    // this session key (spec §20, 2026-10-12, the hit premise). Set here
    // only; cleared when the full engine re-runs the leaf.
    let mut hit_derived = vec![false; w.leaves.len()];
    type Stamp = (LeafKey, Gen, Arc<[u64]>, u64);
    let mut stamp: Vec<Option<Stamp>> = vec![None; w.leaves.len()];
    for (i, key, h) in hits {
        if h.cached.tokens.iter().all(|t| view.original(t).is_some()) {
            new_text[i] = Some(h.cached.text);
            stamp[i] = Some((key, h.generation, h.ds, h.rev));
            hit[i] = true;
            hit_derived[i] = true;
            out.hits += 1;
        } else {
            // A forgotten entity or an expired grace period (spec §5.6).
            misses.push(i);
        }
    }
    // The session dictionary, after the view: it covers the snapshot.
    let sd = session.closure_dict().map_err(|_| Fail::VaultUnavailable)?;
    // The stamps this request may claim (Review Focus 2): inserts take the
    // view's snapshot, hits `sd.upto` (read after the view). A saturated
    // snapshot (a log past `u32::MAX`) or one the dictionary does not cover
    // (the logs only grow) is a stamp nothing can vouch for: fail closed.
    let insert_gen = view.snapshot_gen();
    if insert_gen.entries == u32::MAX || insert_gen.removed == u32::MAX {
        return Err(Fail::VaultUnavailable);
    }
    if !sd.upto.covers(insert_gen) {
        return Err(Fail::Internal);
    }
    out.insert_gen = insert_gen;
    out.claim = sd.upto;
    // 2. Scanned leaves (decision 14): never changed. One rule on every
    // turn (R2): a leaf holding in clear, outside real tokens, a closure
    // form of any session value of any kind (preserved kinds included: the
    // store holds a value only because something tokenized or removed it),
    // a closure form of a dataset value this request resolved, or a host or
    // identity value the policy does not preserve, refuses the request, or,
    // inside a tool result, withholds that result. A group withheld here
    // after the lookup drops out of the hits at the end and is skipped by
    // step 6. The scanned leaves sent as they are: step 6b checks them
    // again for the values this request adds.
    //
    // A seeded leaf (provider-written, ruling I1) is checked the same way,
    // but only against what its stamp does not cover: the session
    // dictionary's segments since its `generation`, and the values of this
    // request's dataset tokens missing from its `ds`. The provider saw the
    // producing request's values only as tokens. A clean one advances its
    // stamp on commit (`seed_bumps`).
    let mut scanned: Vec<usize> = Vec::new();
    if !to_scan.is_empty() {
        // Built on first use: a turn whose seeded leaves are covered builds
        // nothing and fetches no host dictionary.
        let mut datasets: Option<Option<ClosureDict>> = None;
        let mut d_step2: Option<(DsTokens, Arc<[u64]>)> = None;
        for (i, nfc, seed) in &to_scan {
            let l = &w.leaves[*i];
            if held.contains(l.group) {
                continue; // an earlier leaf of this tool result withheld it
            }
            let real = |x: &str| real_token(&view, x);
            let kinds = match seed {
                None => {
                    if datasets.is_none() {
                        datasets = Some(ds_dict(&view, view.dataset_tokens())?);
                    }
                    let ds = datasets.as_ref().and_then(Option::as_ref);
                    let chat = chat_dict(&mut dict, sh, &sd)?;
                    let pol = policy_of(&mut policy, sh)?;
                    step2_kinds(chat, &sd, ds, pol, &sh.tokens, &real, nfc)?
                }
                Some((digest, stamp)) => {
                    if d_step2.is_none() {
                        let v = ds_tokens(sh, &view);
                        let set = ds_set(&v);
                        d_step2 = Some((v, set));
                    }
                    let (req, req_set) = d_step2.as_ref().ok_or(Fail::Internal)?;
                    let missing = ds_missing(req, &stamp.ds);
                    let covered = missing.is_empty() && stamp.generation.covers(sd.upto);
                    let mut spans = Vec::new();
                    for seg in sd.since(stamp.generation) {
                        spans.extend(seg.dict.clear_spans(&sh.tokens, &real, nfc)?);
                    }
                    if !missing.is_empty() {
                        if missing.len() == req.len() {
                            if datasets.is_none() {
                                datasets = Some(ds_dict(&view, view.dataset_tokens())?);
                            }
                            if let Some(d) = datasets.as_ref().and_then(Option::as_ref) {
                                spans.extend(d.clear_spans(&sh.tokens, &real, nfc)?);
                            }
                        } else if let Some(d) = ds_dict(&view, missing.into_iter())? {
                            spans.extend(d.clear_spans(&sh.tokens, &real, nfc)?);
                        }
                    }
                    let kinds = dedup(spans.into_iter().map(|s| s.kind));
                    if kinds.is_empty() && !covered {
                        out.seed_bumps
                            .push((*digest, stamp.clone(), sd.upto, Arc::clone(req_set)));
                    }
                    kinds
                }
            };
            if kinds.is_empty() {
                scanned.push(*i);
                continue;
            }
            let checks = vec!["ClearValue".to_string()];
            match l.group {
                Some(g) => held.add(g, &labels(&kinds), (false, kinds, checks))?,
                None => {
                    return Err(Fail::PrivacyBlock {
                        kinds: labels(&kinds),
                        checks,
                        uncertain: false,
                    });
                }
            }
        }
    }
    drop(to_scan);
    misses.sort_unstable();
    // 6. Misses through the engine. Models are fetched on the first miss
    // that needs them: a history answered from the cache needs none.
    let mut engines = LeafEngines::default();
    let mut passed: Vec<Passed> = Vec::new();
    // Only tokens the view resolves (minted or protected): never `_REMOVED`
    // markers or unknown token-shaped text.
    let passed_of = |view: &SessionView<'_>, i: usize, text: String, kinds, uncertain| {
        let l = &w.leaves[i];
        Passed {
            leaf: i,
            key: leaf_key(sh, wire, l, origins[i]),
            tokens: dedup(
                sh.tokens
                    .find_iter(&text)
                    .map(|m| m.as_str())
                    .filter(|x| view.original(x).is_some())
                    .map(str::to_string),
            ),
            text,
            kinds: dedup(kinds),
            uncertain,
        }
    };
    // Leaves the leak check alone blocked, left to the closure (6b):
    // `(leaf, kinds, checks)`.
    let mut deferred: Vec<Unsettled> = Vec::new();
    // The store's entries before step 6, as keyed 64-bit hashes of
    // `(removed, kind, value)` (no copy of any value): step 6b scans sent
    // leaves for the entries added after. The kind is part of the key: a
    // value the session knows as one kind and this request mints as another
    // (a PERSON's name parts are searched, an ORGANIZATION's are not) is a
    // new entry. Only the engine adds entries, so a request without misses
    // or sent hits needs none. With hits and no misses the view does not
    // grow before 6b, so `added` is empty: the hits' own staleness is the
    // stamps' job (round 0), for session entries (`Gen`) and dataset
    // values (digest coverage) alike.
    let hasher = std::hash::RandomState::new();
    let entry_hash = |removed: bool, k: &EntityKind, o: &str| {
        std::hash::BuildHasher::hash_one(&hasher, (removed, k.label(), o))
    };
    let before: HashSet<u64> = if misses.is_empty() && !hit.contains(&true) {
        HashSet::new()
    } else {
        view.entries()
            .map(|(k, o)| entry_hash(false, k, o))
            .chain(view.removed_entries().map(|(k, o)| entry_hash(true, k, o)))
            .collect()
    };
    let count = |v: &SessionView<'_>| v.entries().count() + v.removed_entries().count();
    let minted_before = count(&view);
    // The released-block re-check's dataset dictionary, built on first use.
    let mut released_ds: Option<ReleasedDs> = None;
    for i in misses {
        let l = &w.leaves[i];
        if held.contains(l.group) {
            continue; // an earlier leaf of this tool result withheld it
        }
        out.misses += 1;
        // Spec §14 (I10): a tool result another front door released, whose
        // deterministic re-check is clean, is sent unchanged without the
        // engine. It is a `Passed` like any other: step 6b scans it for the
        // values this request adds (R1), and a withheld group drops it
        // before the cache and the journal (R4).
        if l.class == Class::ToolResult
            && host.released(&Sha256::digest(l.text.as_bytes()).into())
            && released_clean(
                sh,
                &mut view,
                &mut dict,
                &mut policy,
                &sd,
                &mut released_ds,
                &l.text,
            )?
        {
            new_text[i] = Some(l.text.clone());
            passed.push(passed_of(&view, i, l.text.clone(), Vec::new(), false));
            continue;
        }
        let nfc = normalize_input(&l.text);
        let memo = memo_for(origins[i], &nfc);
        let eng = timed(&times.engine, || {
            leaf_engine(sh, &mut engines, engine_kind(origins[i], memo.is_some()))
        })?;
        let chat = chat_dict(&mut dict, sh, &sd)?;
        let pol = policy_of(&mut policy, sh)?;
        let verdict = timed(&times.engine, || {
            leaf_verdict(
                sh,
                &eng,
                &mut view,
                chat,
                pol,
                &nfc,
                Vec::new(),
                origins[i],
                memo,
            )
        })?;
        match verdict {
            Verdict::Text {
                text,
                kinds,
                uncertain,
            } => {
                new_text[i] = Some(text.clone());
                passed.push(passed_of(&view, i, text, kinds, uncertain));
            }
            Verdict::Blocked {
                uncertain,
                kinds,
                checks,
            } if leak_only(uncertain, &checks) => {
                deferred.push((i, kinds, checks));
            }
            Verdict::Blocked {
                uncertain,
                kinds,
                checks,
            } => match l.group {
                // Decision 18: a tool result becomes the placeholder.
                Some(g) => held.add(g, &labels(&kinds), (uncertain, kinds, checks))?,
                None => {
                    return Err(Fail::PrivacyBlock {
                        kinds: labels(&kinds),
                        checks,
                        uncertain,
                    });
                }
            },
        }
    }
    // 6b. The leak closure. One leaf can mint X while another holds X (or a
    // name part of it) in clear: the detectors fire on one mention, not the
    // other. When the clear copy is processed after the mint the leak check
    // blocks it (a refusal every turn); before it, the copy would pass and
    // leak (commit 328f61d shows both without the closure). A cache hit is
    // the same case: its text was verified against the store of an earlier
    // turn, and this request may mint a value it holds in clear. So the
    // leaves left unsettled (deferred, or a passed or cached leaf with a
    // value the request added in clear) are re-run from their original text
    // with every match of the store's values as extra redactions, while the
    // store keeps growing (at most `sh.closure` rounds). Unlike the chat
    // dictionary, preserved kinds are kept: a store value's clear copy is a
    // leak-check block whatever its kind (a retry profile mints kinds the
    // primary preserves). Removed values are redacted as removals, never as
    // restorable tokens. Scanned leaves cannot be rewritten: one holding an
    // added value in clear (of any kind, preserved ones too, as above)
    // refuses the request or withholds its tool result, as in step 2. What
    // is still unsettled then fails closed as in step 6.
    //
    // A cache hit also goes stale without this request (R1): a value minted
    // outside it (a refused request, a subagent on the same session id)
    // after the hit was verified. Each hit carries the `Gen` it was verified
    // up to; one not covering `sd.upto` is scanned in round 0 against the
    // dictionary's segments since its stamp, and re-run like any open leaf
    // when it holds one of their values in clear.
    //
    // Likewise for dataset values (ruling I3): each hit carries the digests
    // of the dataset tokens it was verified against. One lacking a digest
    // of this request's dataset tokens (`d_req`, after step 6) is
    // dataset-stale and is scanned in round 0 against those values.
    //
    // Nothing is needed when nothing was deferred, the store did not grow,
    // and every sent hit is stamped up to `sd.upto` and covers `d_req`:
    // every sent leaf was then verified against the whole store and every
    // dataset value the request resolved, and every scanned one holds no
    // value it did not hold at step 2.
    let d_req = ds_tokens(sh, &view);
    // `(leaf, gen-stale, the d_req tokens its stamp lacks)`.
    let mut stale: Vec<(usize, bool, Vec<&str>)> = Vec::new();
    for i in 0..w.leaves.len() {
        if !hit[i] || held.contains(w.leaves[i].group) {
            continue;
        }
        let (by_gen, missing) = match stamp[i].as_ref() {
            Some(s) => (!s.1.covers(sd.upto), ds_missing(&d_req, &s.2)),
            None => (true, ds_missing(&d_req, &[])),
        };
        if by_gen || !missing.is_empty() {
            stale.push((i, by_gen, missing));
        }
    }
    if count(&view) != minted_before || !deferred.is_empty() || !stale.is_empty() {
        // The whole block is `closure` time, early returns included.
        let _closure = StageGuard::start(&times.closure);
        out.closure_ran = true;
        // A sent, cached or scanned leaf was verified against an earlier
        // store: only an entry added since can be in clear in it (matches
        // inside a token are ignored).
        let added =
            ClosureDict::from_view(&view, &|r, k, o| !before.contains(&entry_hash(r, k, o)))?;
        let unsettled = |d: &ClosureDict,
                         view: &SessionView<'_>,
                         passed: &[Passed],
                         deferred: &[Unsettled],
                         new_text: &[Option<String>],
                         hit: &[bool],
                         held: &Withheld<'_>|
         -> Result<Vec<Unsettled>, Fail> {
            // A deferred leaf whose tool result was withheld meanwhile is
            // settled (the placeholder goes out): it must not stay open.
            let mut out: Vec<Unsettled> = deferred
                .iter()
                .filter(|u| !held.contains(w.leaves[u.0].group))
                .cloned()
                .collect();
            if !d.is_empty() {
                let sent = passed.iter().map(|p| (p.leaf, p.text.as_str())).chain(
                    new_text
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| hit[*i])
                        .filter_map(|(i, t)| t.as_deref().map(|t| (i, t))),
                );
                for (i, text) in sent {
                    if held.contains(w.leaves[i].group) {
                        continue; // replaced by the placeholder
                    }
                    let kinds = dedup(
                        d.clear_spans(&sh.tokens, &|x| real_token(view, x), text)?
                            .into_iter()
                            .map(|s| s.kind),
                    );
                    if !kinds.is_empty() {
                        out.push((i, kinds, vec!["Leak".to_string()]));
                    }
                }
            }
            out.sort_by_key(|u| u.0);
            Ok(out)
        };
        // Step 2 again for the scanned leaves, against `d` only (the
        // entries added since step 2, which already scanned the host part
        // and the session dictionary): a clear value refuses or withholds.
        // Every kind counts, as in step 2.
        let check_scanned = |d: &ClosureDict,
                             view: &SessionView<'_>,
                             held: &mut Withheld<'_>|
         -> Result<(), Fail> {
            for &i in &scanned {
                let l = &w.leaves[i];
                if d.is_empty() || held.contains(l.group) {
                    continue;
                }
                let nfc = normalize_input(&l.text);
                let kinds = extra_kinds(&[d], &sh.tokens, &|x| real_token(view, x), &nfc)?;
                if kinds.is_empty() {
                    continue;
                }
                let checks = vec!["Leak".to_string()];
                match l.group {
                    Some(g) => held.add(g, &labels(&kinds), (false, kinds, checks))?,
                    None => {
                        return Err(Fail::PrivacyBlock {
                            kinds: labels(&kinds),
                            checks,
                            uncertain: false,
                        });
                    }
                }
            }
            Ok(())
        };
        check_scanned(&added, &view, &mut held)?;
        let mut open = unsettled(&added, &view, &passed, &deferred, &new_text, &hit, &held)?;
        drop(added);
        // Round 0, stale hits: each against the segments since its stamp
        // (a superset of what it was not verified against), and a
        // dataset-stale one against the values of the tokens its digest set
        // lacks: one dictionary over the union of those tokens, so a
        // superset per hit (built after step 6, which may have resolved
        // more). A hit missing its stamp is scanned against everything.
        let lacking: HashSet<&str> = stale.iter().flat_map(|s| s.2.iter().copied()).collect();
        let datasets = if lacking.is_empty() {
            None
        } else {
            ds_dict(&view, lacking.into_iter())?
        };
        for (i, by_gen, missing) in &stale {
            let i = *i;
            let (Some(text), false) = (new_text[i].as_deref(), held.contains(w.leaves[i].group))
            else {
                continue;
            };
            let real = |x: &str| real_token(&view, x);
            let mut kinds: Vec<EntityKind> = Vec::new();
            if *by_gen {
                let since = stamp[i].as_ref().map_or(Gen::ZERO, |s| s.1);
                for seg in sd.since(since) {
                    kinds.extend(
                        seg.dict
                            .clear_spans(&sh.tokens, &real, text)?
                            .into_iter()
                            .map(|s| s.kind),
                    );
                }
            }
            if let (false, Some(d)) = (missing.is_empty(), datasets.as_ref()) {
                kinds.extend(
                    d.clear_spans(&sh.tokens, &real, text)?
                        .into_iter()
                        .map(|s| s.kind),
                );
            }
            if kinds.is_empty() {
                continue;
            }
            match open.iter_mut().find(|u| u.0 == i) {
                Some(u) => u.1 = dedup(std::mem::take(&mut u.1).into_iter().chain(kinds)),
                None => open.push((i, dedup(kinds), vec!["Leak".to_string()])),
            }
        }
        open.sort_by_key(|u| u.0);
        let all: &Keep<'_> = &|_, _, _| true;
        // The dictionaries over every known entry, with the store size they
        // were built at: rebuilt only when the store grew (it only grows).
        let mut full: Option<(usize, ClosureDict)> = None;
        let mut last: Option<usize> = None;
        // The leaves the previous round re-ran by the full engine (a
        // projected leaf is not one: projection does not repeat the
        // engine, so it never ends the loop early).
        let mut rerun: Vec<usize> = Vec::new();
        // Projection (spec §20, 2026-10-12): the per-request scratch, and
        // the leaves projected so far: at most one projection per leaf per
        // request (P1); a reopened projected leaf takes the full engine.
        let mut scratch = ProjectionScratch::default();
        let mut projected_once: HashSet<usize> = HashSet::new();
        // Settles leaf `$i` by the engine's verdict `$v`, replacing the
        // leaf's earlier verdict: one `Passed` (one cache insert, which
        // replaces a stale entry; one journal text; one kind count) per
        // leaf. The full re-run and the shadow mode's re-run share it.
        macro_rules! apply_verdict {
            ($i:expr, $v:expr) => {{
                let i: usize = $i;
                passed.retain(|p| p.leaf != i);
                deferred.retain(|d| d.0 != i);
                new_text[i] = None;
                match $v {
                    Verdict::Text {
                        text,
                        kinds,
                        uncertain,
                    } => {
                        new_text[i] = Some(text.clone());
                        passed.push(passed_of(&view, i, text, kinds, uncertain));
                    }
                    Verdict::Blocked {
                        uncertain,
                        kinds,
                        checks,
                    } if leak_only(uncertain, &checks) => deferred.push((i, kinds, checks)),
                    Verdict::Blocked {
                        uncertain,
                        kinds,
                        checks,
                    } => match w.leaves[i].group {
                        Some(g) => held.add(g, &labels(&kinds), (uncertain, kinds, checks))?,
                        None => {
                            return Err(Fail::PrivacyBlock {
                                kinds: labels(&kinds),
                                checks,
                                uncertain,
                            });
                        }
                    },
                }
            }};
        }
        // The leaves projected in the round just finished (test hook).
        #[cfg(test)]
        let mut projected_now: Vec<usize> = Vec::new();
        for _ in 0..sh.closure {
            let n = count(&view);
            // Settled; or the store did not grow and every open leaf was
            // just re-run against it, so a re-run would repeat. A leaf first
            // flagged after the last re-run still gets its own.
            if open.is_empty() || (last == Some(n) && open.iter().all(|u| rerun.contains(&u.0))) {
                break;
            }
            last = Some(n);
            let local = match full.take() {
                Some((m, c)) if m == n => c,
                _ => ClosureDict::from_view(&view, all)?,
            };
            if local.is_empty() {
                break; // nothing to redact: what is open fails closed below
            }
            rerun.clear();
            #[cfg(test)]
            projected_now.clear();
            for (i, _, _) in std::mem::take(&mut open) {
                let l = &w.leaves[i];
                if held.contains(l.group) {
                    continue;
                }
                // The engine, on the first re-run that needs it: a
                // hits-only turn whose round 0 finds nothing fetches no
                // models.
                let nfc = normalize_input(&l.text);
                let memo = memo_for(origins[i], &nfc);
                let eng = leaf_engine(sh, &mut engines, engine_kind(origins[i], memo.is_some()))?;
                // A cached leaf re-run from its original text is a miss.
                if hit[i] {
                    hit[i] = false;
                    out.hits -= 1;
                    out.misses += 1;
                }
                // A hit-derived leaf is projected (its cached text, the
                // store's values replaced, deterministic checks only),
                // once per request; any abandonment falls through to the
                // full engine in this same round. A projection that
                // replaced nothing is an empty one (spec: abandoned).
                // Why this leaf's projection was abandoned, if it was.
                #[cfg(feature = "closure-shadow")]
                let mut abandon: Option<Abandon> = None;
                if hit_derived[i]
                    && !projected_once.contains(&i)
                    && projection_enabled()
                    && let Some(t0) = new_text[i].as_deref()
                {
                    let chat = chat_dict(&mut dict, sh, &sd)?;
                    let pol = policy_of(&mut policy, sh)?;
                    #[cfg(test)]
                    let size0 = count(&view);
                    #[cfg(feature = "closure-shadow")]
                    shadow::attempted();
                    let projection = timed(&times.project, || {
                        project_leaf(sh, &eng, &mut view, chat, pol, t0, &mut scratch)
                    })?;
                    #[cfg(test)]
                    if !matches!(projection, Projection::Projected { .. }) {
                        let grew = count(&view).saturating_sub(size0);
                        ABANDONED_GROWTH.with(|c| c.set(c.get() + grew));
                    }
                    match projection {
                        Projection::Projected {
                            text,
                            replaced,
                            minted,
                        } if !replaced.is_empty() => {
                            projected_once.insert(i);
                            #[cfg(test)]
                            projected_now.push(i);
                            out.projected += 1;
                            out.projection_mints += minted as u64;
                            // The shadow mode (spec §20, 2026-10-12): the
                            // projection's mints stay; the full re-run runs
                            // too, is compared, and is what is forwarded.
                            #[cfg(feature = "closure-shadow")]
                            {
                                shadow::projected();
                                let extra = closure_redactions(pol, local.spans(&nfc)?);
                                let (detailed, v) = leaf_detailed(
                                    sh, &eng, &mut view, chat, pol, &nfc, extra, origins[i], memo,
                                )?;
                                shadow_compare(sh, &detailed, &v, &nfc, &text, t0, &replaced);
                                // Engine-verified from here on: never projected.
                                hit_derived[i] = false;
                                rerun.push(i);
                                apply_verdict!(i, v);
                                continue;
                            }
                            #[cfg(not(feature = "closure-shadow"))]
                            {
                                passed.retain(|p| p.leaf != i);
                                deferred.retain(|d| d.0 != i);
                                new_text[i] = Some(text.clone());
                                let kinds = replaced.into_iter().map(|(_, k)| k).collect();
                                passed.push(passed_of(&view, i, text, kinds, false));
                                continue; // not a full re-run: not in `rerun`
                            }
                        }
                        // Replaced nothing but minted: phase 2 disagreed
                        // with the empty plan, a bug. Fail closed.
                        Projection::Projected { minted, .. } if minted > 0 => {
                            return Err(Fail::Internal);
                        }
                        Projection::Projected { .. } => {
                            out.projection_abandoned += 1;
                            bump(&mut out.abandoned_by, Abandon::Empty);
                            #[cfg(feature = "closure-shadow")]
                            {
                                shadow::abandoned();
                                abandon = Some(Abandon::Empty);
                            }
                        }
                        Projection::Abandoned { reason, .. } => {
                            out.projection_abandoned += 1;
                            bump(&mut out.abandoned_by, reason);
                            #[cfg(feature = "closure-shadow")]
                            {
                                shadow::abandoned();
                                if reason == Abandon::Invariant {
                                    shadow::invariant_violation();
                                }
                                abandon = Some(reason);
                            }
                        }
                        Projection::Inconsistent => return Err(Fail::Internal),
                    }
                }
                // A full re-run: its text is engine-verified from here on.
                hit_derived[i] = false;
                rerun.push(i);
                let chat = chat_dict(&mut dict, sh, &sd)?;
                let pol = policy_of(&mut policy, sh)?;
                let extra = closure_redactions(pol, local.spans(&nfc)?);
                let v = leaf_verdict(
                    sh, &eng, &mut view, chat, pol, &nfc, extra, origins[i], memo,
                )?;
                // The full re-run passed where the projection was abandoned.
                #[cfg(feature = "closure-shadow")]
                if let (Some(reason), Verdict::Text { .. }) = (abandon, &v) {
                    shadow::r2(&format!("{reason:?}"));
                }
                apply_verdict!(i, v);
            }
            // Against every entry now known: a re-run may have added some,
            // which the scanned leaves must not hold in clear either.
            let now = count(&view);
            let local = if now == n {
                local
            } else {
                let c = ClosureDict::from_view(&view, all)?;
                check_scanned(&c, &view, &mut held)?;
                c
            };
            open = unsettled(&local, &view, &passed, &deferred, &new_text, &hit, &held)?;
            // Test hook: reopen what this round projected, as a dictionary
            // disagreement would (it is never projected again).
            #[cfg(test)]
            if sh.force_reopen_projected {
                for &i in &projected_now {
                    if !open.iter().any(|u| u.0 == i) {
                        open.push((i, vec![EntityKind::Person], vec!["Leak".into()]));
                    }
                }
                open.sort_by_key(|u| u.0);
            }
            full = Some((now, local));
        }
        // Fail closed: what is still unsettled is blocked as in step 6.
        for (i, kinds, checks) in open {
            let l = &w.leaves[i];
            passed.retain(|p| p.leaf != i);
            new_text[i] = None;
            match l.group {
                Some(g) => held.add(g, &labels(&kinds), (false, kinds, checks))?,
                None => {
                    return Err(Fail::PrivacyBlock {
                        kinds: labels(&kinds),
                        checks,
                        uncertain: false,
                    });
                }
            }
        }
    }
    // A cached leaf whose tool result was withheld after the lookup is not
    // sent, so it is not a hit (an unsettled one is dropped above too).
    // Those still sent were verified up to `sd.upto`: their stamps advance
    // on commit.
    for (i, h) in hit.iter_mut().enumerate() {
        if *h && (held.contains(w.leaves[i].group) || new_text[i].is_none()) {
            *h = false;
            out.hits -= 1;
        }
        if *h {
            let (key, _, _, rev) = stamp[i].as_ref().ok_or(Fail::Internal)?;
            out.verified.push((*key, *rev));
        }
    }
    // Only what is actually sent is cached, journaled, and counted.
    for p in passed {
        if held.contains(w.leaves[p.leaf].group) {
            continue;
        }
        for k in p.kinds {
            match out.kinds.iter_mut().find(|(x, _)| *x == k) {
                Some((_, n)) => *n += 1,
                None => out.kinds.push((k, 1)),
            }
        }
        out.uncertain_passed |= p.uncertain;
        out.missed.push(p.text.clone());
        out.inserts.push((
            p.key,
            Cached {
                text: p.text,
                tokens: p.tokens,
            },
        ));
    }
    // Belt and braces: a host failure the view swallowed fails the request.
    if let Some(e) = view.fault() {
        return Err(host_fail(e));
    }
    // The dataset coverage every sent leaf now has: the view's dataset
    // tokens at the end (a closure round re-scans every sent leaf against
    // the whole view, so tokens it resolved count too).
    out.claim_ds = ds_set(&ds_tokens(sh, &view));
    if new_parts > 0 {
        let binary = EntityKind::Custom("BINARY".into());
        match out.kinds.iter_mut().find(|(k, _)| *k == binary) {
            Some((_, n)) => *n += new_parts,
            None => out.kinds.push((binary, new_parts)),
        }
    }
    // 7. Edits.
    let (bytes, changed) = apply_edits(body, w, &new_text, &held.placeholder)?;
    out.body = bytes;
    out.replacements = changed;
    out.memo = held.memo;
    out.withheld = held.records;
    out.evict = held.evict;
    Ok(out)
}

/// A check route's request (M8 spec §12.3), blocking: sanitized by the
/// check dataset in one batch through `ProxyHost::sanitize_dataset` (its
/// profile, `offline`; the engine protects the check's tokens through the
/// namespace store). No session, cache, or memo is read or written.
///
/// Definitions are scanned as on normal routes; binary user content is
/// replaced, refused, or forwarded as on normal routes (with no memo and no
/// record); a binary tool result becomes the placeholder. A blocked (or,
/// under `uncertain = "block"`, uncertain) tool result becomes the
/// placeholder; any other blocked leaf refuses the request with `451`.
/// Scanned leaves (reasoning, citations, search sources) go through the same
/// batch: a normal route refuses one holding a clear value, a check route
/// tokenizes it like text, so the registry never records it in clear.
/// A streamed request is sanitized like any other; its answer is restored
/// by the stream rewriter.
pub(crate) fn sanitize_check(
    sh: &Shared,
    dataset: &str,
    body: &[u8],
    w: &Walk,
) -> Result<Prepared, Fail> {
    check_definitions(sh, w)?;
    if binary_refused(sh, w) {
        return Err(Fail::UnsupportedContent);
    }
    let mut group_placeholder: HashMap<usize, String> = HashMap::new();
    for (g, grp) in w.groups.iter().enumerate() {
        if grp.binary && sh.cfg.binary != BinaryMode::Forward {
            group_placeholder.insert(g, placeholder(&["BINARY".into()]));
        }
    }
    let idx: Vec<usize> = w
        .leaves
        .iter()
        .enumerate()
        .filter(|(_, l)| {
            matches!(
                l.class,
                Class::Text | Class::ToolResult | Class::ToolInput | Class::Scan
            )
        })
        .filter(|(_, l)| !l.group.is_some_and(|g| group_placeholder.contains_key(&g)))
        .map(|(i, _)| i)
        .collect();
    let texts: Vec<String> = idx.iter().map(|i| w.leaves[*i].text.clone()).collect();
    let blocks = if texts.is_empty() {
        Vec::new()
    } else {
        sh.host
            .sanitize_dataset(dataset, texts)
            .map_err(host_fail)?
    };
    if blocks.len() != idx.len() {
        return Err(Fail::Internal);
    }
    let mut out = Prepared::empty();
    let mut new_text: Vec<Option<String>> = vec![None; w.leaves.len()];
    for (i, b) in idx.into_iter().zip(blocks) {
        if !(b.blocked || (b.uncertain && sh.cfg.uncertain == UncertainMode::Block)) {
            new_text[i] = Some(b.text);
            continue;
        }
        let labels = dedup(b.kinds.iter().map(|k| k.label().to_string()));
        match w.leaves[i].group {
            Some(g) => {
                group_placeholder
                    .entry(g)
                    .or_insert_with(|| placeholder(&labels));
                out.withheld.push((!b.blocked, b.kinds, b.checks));
            }
            None => {
                return Err(Fail::PrivacyBlock {
                    kinds: labels,
                    checks: b.checks,
                    uncertain: !b.blocked,
                });
            }
        }
    }
    let (bytes, n) = apply_edits(body, w, &new_text, &group_placeholder)?;
    out.body = bytes;
    out.replacements = n;
    Ok(out)
}

/// `Shared` as the unit tests describe it: profile `fast`, `uncertain =
/// "block"`, binary refused, session suffix 4, upstreams never used.
#[cfg(test)]
pub(crate) fn test_shared(host: Arc<dyn ProxyHost>) -> Shared {
    use std::time::Duration;

    use crate::config::{BaseUrls, TripwireMode};

    let unused = "http://127.0.0.1:9".to_string();
    let cfg = ProxyConfig {
        enabled: true,
        listen: "127.0.0.1:0".parse().expect("a valid address"),
        profile: "fast".into(),
        session_ttl: Duration::from_secs(60),
        session_cap: 16,
        cache_bytes: 1 << 20,
        max_request_bytes: 1 << 20,
        max_inflight: 4,
        upstream_timeout: Duration::from_secs(5),
        binary: BinaryMode::Refuse,
        uncertain: UncertainMode::Block,
        tripwire: TripwireMode::Notify,
        allowed_origins: vec![],
        base_urls: BaseUrls {
            anthropic: unused.clone(),
            openai: unused.clone(),
            openai_codex: unused,
        },
        extra_headers: Default::default(),
        session_tokens: inumaki_core::config::TokenSettings::default(),
        static_cache: true,
        static_ner: crate::config::StaticNer::Scan,
        fingerprint: [0; 32],
    };
    Shared::new(cfg, host).expect("the test identity builds")
}
