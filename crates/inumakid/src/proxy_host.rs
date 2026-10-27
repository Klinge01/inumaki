//! `inumaki_proxy::host::ProxyHost` over the daemon (M8 spec §3.1).
//!
//! The proxy reaches the vault, the models, and the activity writer only
//! through this host. The host holds a `Weak<AppState>`: the state owns the
//! proxy, which owns the host.
//!
//! Which datasets count (spec §5.3, §5.4, §9, §12.3): the chat dictionary,
//! the tripwire, dataset-token reuse, and restoration on normal routes use
//! every live dataset except check datasets (`check-…`) and the reserved
//! chat dataset (kind `chat`, ids `inumaki-…`). A check route's scope is its
//! check dataset and that dataset's companions (`<dataset>-…`) only.
//!
//! Nothing here logs a value, a token, or a dataset id; errors are the
//! fixed [`HostError`] classes.

use std::sync::{Arc, Mutex, PoisonError, Weak};

use inumaki_core::detect::dictionary::DictionaryDetector;
use inumaki_core::detect::{DetectCtx, Detector};
use inumaki_core::engine::{Engine, normalize_input};
use inumaki_core::policy::{Action, Profile};
use inumaki_core::span::{DetectorId, EntityKind, Span};
use inumaki_core::token::{StoreError, TokenStore, parse_token};
use inumaki_proxy::host::{HostBlock, HostError, ProxyEvent, ProxyHost, RefusedVerdict, Scope};
use inumaki_proxy::memo::{NerMemo, STATIC_MEMO_BYTES, STATIC_MEMO_ENTRIES};
use inumaki_vault::{
    CHAT_DATASET, CheckLabel, DatasetHead, DatasetKind, Direction, FrontDoor, KindCount, KindLabel,
    Namespace, NewActivity, RESERVED_PREFIX, VaultError, Verdict,
};
use zeroize::Zeroizing;

use crate::cache::CachedOutcome;
use crate::check::CHECK_PREFIX;
use crate::engines::{EngineError, Engines};
use crate::proxy_config::AccountValues;
use crate::service::{self, BlockInput, ServiceError};
use crate::state::AppState;

/// The chat dictionary's identity: per dataset, its id, the address of the
/// namespace's detector (a deleted and recreated dataset gets a new handle
/// whose generation and count can equal the old one's; the cached union
/// keeps the old `Arc` alive, so its address cannot be reused meanwhile),
/// the detector generation, its known-entity count (a mint adds to the
/// delta without a rebuild, so the generation alone would miss it), and its
/// current epoch id (a rotation is a dictionary change, M8 spec §20,
/// amendment 2026-10-12: the static-prompt memo clears on it).
type DictKey = Vec<(String, usize, u64, usize, i64)>;

/// The daemon's side of the proxy. `Debug` prints the type name only.
pub struct DaemonHost {
    state: Weak<AppState>,
    /// The OS identity (spec decision 13), read once at construction.
    identity: Vec<(EntityKind, Zeroizing<String>)>,
    /// The identity's full names and emails, for the definition scan.
    identity_dict: Option<Arc<DictionaryDetector>>,
    /// The identity's account values (login, home-directory name), for the
    /// definition scan under `[proxy] definitions_account_values = "refuse"`.
    accounts_dict: Option<Arc<DictionaryDetector>>,
    /// The last chat dictionary and what it was built from: the `Arc`
    /// changes exactly when the dictionary does.
    dict: Mutex<Option<(DictKey, Arc<dyn Detector>)>>,
    /// The cross-session static-prompt NER memo (M8 spec §20, amendment
    /// 2026-10-12) for the proxy profile under the configuration
    /// fingerprint; `None` for a host built without a state (tests). Memory
    /// only; a restart drops it.
    memo: Option<Arc<NerMemo>>,
}

impl std::fmt::Debug for DaemonHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DaemonHost")
    }
}

/// How a definition-scan dictionary is built from a non-empty value list.
type Build<'b> =
    dyn Fn(&[(EntityKind, Zeroizing<String>)]) -> inumaki_core::Result<DictionaryDetector> + 'b;

/// The dictionary over `v`. `Ok(None)` for no values; a build error is
/// `Err(HostError::Internal)`: it fails closed, so a non-empty identity whose
/// dictionary cannot be built is an error and the proxy is not started.
fn identity_dict(
    v: &[(EntityKind, Zeroizing<String>)],
    build: &Build<'_>,
) -> Result<Option<Arc<DictionaryDetector>>, HostError> {
    if v.is_empty() {
        return Ok(None);
    }
    build(v)
        .map(|d| Some(Arc::new(d)))
        .map_err(|_| HostError::Internal)
}

impl DaemonHost {
    /// A host over `state`; reads the OS identity once. Fails closed: a
    /// non-empty identity whose dictionary cannot be built is an error, so the
    /// proxy is not started.
    pub fn new(state: Weak<AppState>) -> Result<DaemonHost, HostError> {
        DaemonHost::with_identity(state, crate::identity::read_parts())
    }

    /// A host over `state` with a given identity instead of the OS one
    /// (tests; the daemon uses [`DaemonHost::new`]).
    #[doc(hidden)]
    pub fn with_identity(
        state: Weak<AppState>,
        id: crate::identity::Identity,
    ) -> Result<DaemonHost, HostError> {
        DaemonHost::with_identity_using(state, id, &|v| {
            DictionaryDetector::from_entries(v.iter().map(|(k, x)| (k.clone(), x.as_str())))
        })
    }

    fn with_identity_using(
        state: Weak<AppState>,
        id: crate::identity::Identity,
        build: &Build<'_>,
    ) -> Result<DaemonHost, HostError> {
        let memo = state.upgrade().map(|s| {
            NerMemo::new(
                &s.cfg.proxy.profile,
                s.cfg.proxy.fingerprint,
                STATIC_MEMO_ENTRIES,
                STATIC_MEMO_BYTES,
            )
        });
        Ok(DaemonHost {
            state,
            identity: id.all(),
            identity_dict: identity_dict(&id.names, build)?,
            accounts_dict: identity_dict(&id.accounts, build)?,
            dict: Mutex::new(None),
            memo,
        })
    }

    fn state(&self) -> Result<Arc<AppState>, HostError> {
        self.state.upgrade().ok_or(HostError::Internal)
    }
}

/// A detector over several: every span of every part.
struct UnionDetector(Vec<Arc<dyn Detector>>);

impl Detector for UnionDetector {
    fn id(&self) -> DetectorId {
        DetectorId::Dictionary
    }

    fn detect(&self, text: &str, ctx: &DetectCtx) -> inumaki_core::Result<Vec<Span>> {
        let mut out = Vec::new();
        for d in &self.0 {
            out.extend(d.detect(text, ctx)?);
        }
        Ok(out)
    }
}

/// The engine [`ProxyHost::engine`] returns: with a memo, the proxy engine
/// whose NER detectors it wraps ([`Engines::proxy_engine`]); without one,
/// the shared unwrapped engine.
fn memo_engine(
    engines: &Engines,
    memo: Option<&Arc<NerMemo>>,
    profile: &str,
) -> Result<Arc<Engine>, HostError> {
    match memo {
        Some(m) => engines.proxy_engine(profile, m),
        None => engines.engine(profile, None),
    }
    .map_err(|e| engine_err(&e))
}

/// The engine [`ProxyHost::engine_unmemoized`] returns (ruling L2-40): the
/// unwrapped engine the gateway, the mirror and the hook share
/// ([`Engines::engine`] with no dataset). Never a memo-wrapped one.
fn plain_engine(engines: &Engines, profile: &str) -> Result<Arc<Engine>, HostError> {
    engines.engine(profile, None).map_err(|e| engine_err(&e))
}

fn engine_err(e: &EngineError) -> HostError {
    match e {
        EngineError::Unavailable { .. } => HostError::ModelUnavailable,
        EngineError::Config(_) => HostError::Internal,
    }
}

fn service_err(e: &ServiceError) -> HostError {
    match e {
        ServiceError::Engine(e) => engine_err(e),
        ServiceError::Vault(_) | ServiceError::Store(_) => HostError::VaultUnavailable,
        // `clear_scan` is a detector failure: like a model failure, nothing
        // may be judged clean.
        ServiceError::Unsupported("clear_scan") => HostError::ModelUnavailable,
        _ => HostError::Internal,
    }
}

/// A dataset whose entities chat may know and restore: not a check
/// dataset, not the reserved chat dataset or any other `inumaki-` id.
fn user_dataset(d: &DatasetHead) -> bool {
    d.kind != DatasetKind::Chat
        && !d.id.starts_with(CHECK_PREFIX)
        && !d.id.starts_with(RESERVED_PREFIX)
}

/// The user datasets in creation order (ties by id), from the vault's light
/// listing (one SELECT, no entry counts: this runs on every request).
fn user_datasets(state: &AppState) -> Result<Vec<DatasetHead>, HostError> {
    Ok(state
        .vault
        .dataset_heads()
        .map_err(|_| HostError::VaultUnavailable)?
        .into_iter()
        .filter(user_dataset)
        .collect())
}

/// Run `f` on the namespace of `id`, refreshed. `Ok(None)` when the
/// dataset is gone (deleted between listing and opening): it knows
/// nothing any more. Any other failure fails closed.
fn with_namespace<T>(
    state: &AppState,
    id: &str,
    f: impl FnOnce(&mut Namespace) -> Result<T, HostError>,
) -> Result<Option<T>, HostError> {
    let ns = match state.namespace(id) {
        Ok(ns) => ns,
        Err(VaultError::DatasetNotFound(_) | VaultError::Closed) => return Ok(None),
        Err(_) => return Err(HostError::VaultUnavailable),
    };
    let mut n = ns.lock().unwrap_or_else(PoisonError::into_inner);
    match n.refresh() {
        Ok(()) => {}
        Err(VaultError::DatasetNotFound(_) | VaultError::Closed) => return Ok(None),
        Err(_) => return Err(HostError::VaultUnavailable),
    }
    f(&mut n).map(Some)
}

/// Any store failure, a closed store included, fails closed.
fn store_err(_: StoreError) -> HostError {
    HostError::VaultUnavailable
}

/// Dataset tokens among `tokens` that resolve in `scope`: `(token, kind,
/// original)`. Each token's owner is looked up in the vault (live epochs
/// only, spec §5.3); a token owned by a dataset outside the scope is left
/// out, so it stays a token. Shared by the proxy host and the chat journal
/// reveal.
pub(crate) fn resolve_tokens(
    state: &AppState,
    tokens: &[String],
    scope: &Scope,
) -> Result<Vec<(String, EntityKind, Zeroizing<String>)>, HostError> {
    let mut uniq: Vec<&String> = Vec::new();
    for t in tokens {
        if !uniq.contains(&t) {
            uniq.push(t);
        }
    }
    // (owner, its tokens), in first-seen order.
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    let mut allowed: Vec<(String, bool)> = Vec::new();
    for t in uniq {
        let Some(owner) = state
            .vault
            .dataset_of_token(t)
            .map_err(|_| HostError::VaultUnavailable)?
        else {
            continue;
        };
        let ok = match allowed.iter().find(|(o, _)| *o == owner) {
            Some((_, ok)) => *ok,
            None => {
                let ok = match scope {
                    Scope::Datasets => {
                        !owner.starts_with(CHECK_PREFIX)
                            && !owner.starts_with(RESERVED_PREFIX)
                            && match state.vault.dataset_kind(&owner) {
                                Ok(k) => k != DatasetKind::Chat,
                                Err(VaultError::DatasetNotFound(_)) => false,
                                Err(_) => return Err(HostError::VaultUnavailable),
                            }
                    }
                    // Only a check dataset can be a check route's scope.
                    Scope::Check(ds) => {
                        ds.starts_with(CHECK_PREFIX)
                            && (owner == *ds || owner.starts_with(&format!("{ds}-")))
                    }
                };
                allowed.push((owner.clone(), ok));
                ok
            }
        };
        if !ok {
            continue;
        }
        match groups.iter_mut().find(|(o, _)| *o == owner) {
            Some((_, g)) => g.push(t.clone()),
            None => groups.push((owner, vec![t.clone()])),
        }
    }
    let mut out = Vec::new();
    for (owner, group) in groups {
        let found = with_namespace(state, &owner, |n| {
            n.prepare(&group).map_err(store_err)?;
            let settings = n.settings().clone();
            let mut found = Vec::new();
            for t in &group {
                let Some(orig) = n.original(t) else {
                    continue;
                };
                let Some(p) = parse_token(&settings, t).filter(|p| !p.removed) else {
                    continue;
                };
                found.push((
                    t.clone(),
                    EntityKind::from_label(p.label),
                    Zeroizing::new(orig.to_string()),
                ));
            }
            Ok(found)
        })?;
        out.extend(found.unwrap_or_default());
    }
    Ok(out)
}

fn kind_counts(kinds: &[(EntityKind, u32)]) -> Vec<KindCount> {
    let mut out: Vec<KindCount> = Vec::new();
    for (k, n) in kinds {
        let label = KindLabel::of(k);
        match out.iter_mut().find(|c| c.kind == label) {
            Some(c) => c.count = c.count.saturating_add(*n),
            None => out.push(KindCount {
                kind: label,
                count: *n,
            }),
        }
    }
    out
}

fn kind_ones(kinds: &[EntityKind]) -> Vec<KindCount> {
    let mut out: Vec<KindCount> = Vec::new();
    for k in kinds {
        let label = KindLabel::of(k);
        if !out.iter().any(|c| c.kind == label) {
            out.push(KindCount {
                kind: label,
                count: 1,
            });
        }
    }
    out
}

/// Check ids from the fixed set; anything else is dropped.
fn check_labels(checks: &[String]) -> Vec<CheckLabel> {
    let mut out: Vec<CheckLabel> = Vec::new();
    for c in checks.iter().filter_map(|c| CheckLabel::parse(c)) {
        if !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

impl ProxyHost for DaemonHost {
    fn engine(&self, profile: &str) -> Result<Arc<Engine>, HostError> {
        memo_engine(&self.state()?.engines, self.memo.as_ref(), profile)
    }

    fn engine_unmemoized(&self, profile: &str) -> Result<Arc<Engine>, HostError> {
        plain_engine(&self.state()?.engines, profile)
    }

    fn ner_memo(&self) -> Option<Arc<NerMemo>> {
        self.memo.clone()
    }

    fn policy(&self, profile: &str) -> Result<Arc<Profile>, HostError> {
        self.state()?
            .engines
            .policy(profile)
            .map_err(|e| engine_err(&e))
    }

    /// The same `Arc` until a user dataset is added, removed, recreated,
    /// rotated, rebuilt, or learns an entity (the host contract). Per call:
    /// the vault's light dataset listing (one SELECT) and, per user
    /// dataset, its open namespace handle refreshed (an atomic generation
    /// check; SQL only after a vault write), then a key comparison.
    fn dictionary(&self) -> Result<Arc<dyn Detector>, HostError> {
        let state = self.state()?;
        let mut key: DictKey = Vec::new();
        let mut parts: Vec<Arc<dyn Detector>> = Vec::new();
        for d in user_datasets(&state)? {
            if let Some((g, n, e, det)) = with_namespace(&state, &d.id, |n| {
                Ok((
                    n.detector_generation(),
                    n.known_entities(),
                    n.epoch_id(),
                    n.detector(),
                ))
            })? {
                let addr = Arc::as_ptr(&det) as *const () as usize;
                key.push((d.id, addr, g, n, e));
                parts.push(det);
            }
        }
        let mut cached = self.dict.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((k, det)) = cached.as_ref() {
            if *k == key {
                return Ok(Arc::clone(det));
            }
        }
        let det: Arc<dyn Detector> = Arc::new(UnionDetector(parts));
        *cached = Some((key, Arc::clone(&det)));
        Ok(det)
    }

    fn scan_known(&self, texts: &[String]) -> Result<Vec<(String, EntityKind, u32)>, HostError> {
        let state = self.state()?;
        let mut out: Vec<(String, EntityKind, u32)> = Vec::new();
        for d in user_datasets(&state)? {
            let Some(det) = with_namespace(&state, &d.id, |n| Ok(n.detector()))? else {
                continue;
            };
            let mut counts: Vec<(EntityKind, u32)> = Vec::new();
            for t in texts {
                let nfc = normalize_input(t);
                let ctx = DetectCtx::for_text(&nfc);
                for s in det
                    .detect(&nfc, &ctx)
                    .map_err(|_| HostError::ModelUnavailable)?
                {
                    if s.confidence >= 0.9 {
                        match counts.iter_mut().find(|(k, _)| *k == s.kind) {
                            Some((_, c)) => *c += 1,
                            None => counts.push((s.kind, 1)),
                        }
                    }
                }
            }
            out.extend(counts.into_iter().map(|(k, n)| (d.id.clone(), k, n)));
        }
        Ok(out)
    }

    fn identity(&self) -> Vec<(EntityKind, Zeroizing<String>)> {
        self.identity.clone()
    }

    fn dataset_token(
        &self,
        kind: &EntityKind,
        value: &str,
    ) -> Result<Option<(String, Zeroizing<String>)>, HostError> {
        let state = self.state()?;
        for d in user_datasets(&state)? {
            // Current epoch only (`peek_token`); never mints.
            let found = with_namespace(&state, &d.id, |n| {
                let Some(tok) = n.peek_token(kind, value).map_err(store_err)? else {
                    return Ok(None);
                };
                let tok = tok.as_str().to_string();
                if n.original(&tok).is_none() {
                    n.prepare(std::slice::from_ref(&tok)).map_err(store_err)?;
                }
                Ok(n.original(&tok)
                    .map(|o| (tok.clone(), Zeroizing::new(o.to_string()))))
            })?;
            if let Some(Some(hit)) = found {
                return Ok(Some(hit));
            }
        }
        Ok(None)
    }

    fn resolve(
        &self,
        tokens: &[String],
        scope: &Scope,
    ) -> Result<Vec<(String, EntityKind, Zeroizing<String>)>, HostError> {
        let state = self.state()?;
        resolve_tokens(&state, tokens, scope)
    }

    /// Plan M8-2 Task 6: whether `sanitize_blocks` released a block with
    /// this SHA-256 within the TTL. A dropped state answers `false` (the
    /// proxy then runs the full engine).
    fn released(&self, digest: &[u8; 32]) -> bool {
        self.state()
            .map(|s| s.released.contains(digest))
            .unwrap_or(false)
    }

    /// Review C2: the chat namespace is empty by design, so `scan_clear`
    /// over it alone would let a known value through. Known entities of
    /// every user dataset and the identity's names, at full-match
    /// confidence, plus the validated-regex tier; kinds the proxy profile
    /// preserves are skipped.
    fn scan_definitions(&self, texts: &[String]) -> Result<Vec<(EntityKind, u32)>, HostError> {
        let state = self.state()?;
        let policy = self.policy(&state.cfg.proxy.profile)?;
        let keep = |k: &EntityKind| {
            policy.action_for(&Span::new(0, 0, k.clone(), 1.0, DetectorId::Dictionary))
                != Some(Action::Preserve)
        };
        let mut hits: Vec<(EntityKind, u32)> = Vec::new();
        let mut bump = |k: EntityKind, n: u32| match hits.iter_mut().find(|(x, _)| *x == k) {
            Some((_, c)) => *c += n,
            None => hits.push((k, n)),
        };
        // Account values only when the user chose to refuse them (spec §9
        // amendment (d)); full names and the email always.
        let accounts = match state.cfg.proxy_account_values {
            AccountValues::Refuse => self.accounts_dict.clone(),
            AccountValues::Allow => None,
        };
        let dets: Vec<Arc<dyn Detector>> = [
            Some(self.dictionary()?),
            self.identity_dict.clone().map(|d| d as Arc<dyn Detector>),
            accounts.map(|d| d as Arc<dyn Detector>),
        ]
        .into_iter()
        .flatten()
        .collect();
        for t in texts {
            let nfc = normalize_input(t);
            let ctx = DetectCtx::for_text(&nfc);
            // A range both tiers find is counted once.
            let mut seen: Vec<(usize, usize)> = Vec::new();
            for d in &dets {
                for s in d
                    .detect(&nfc, &ctx)
                    .map_err(|_| HostError::ModelUnavailable)?
                {
                    if s.confidence >= 0.9 && keep(&s.kind) {
                        seen.push((s.start, s.end));
                        bump(s.kind, 1);
                    }
                }
            }
            // The validated-regex tier under the CURRENT proxy profile (not
            // the chat dataset's stored one, which a changed `[proxy]
            // profile` leaves behind).
            for s in service::validated_regex()
                .detect(&nfc, &ctx)
                .map_err(|_| HostError::ModelUnavailable)?
            {
                if s.source == DetectorId::RegexValidated
                    && policy.action_for(&s) != Some(Action::Preserve)
                    && !seen.contains(&(s.start, s.end))
                {
                    bump(s.kind, 1);
                }
            }
        }
        Ok(hits)
    }

    /// Check routes (plan M8-3): a check dataset's namespace only.
    fn sanitize_dataset(
        &self,
        dataset: &str,
        blocks: Vec<String>,
    ) -> Result<Vec<HostBlock>, HostError> {
        if !dataset.starts_with(CHECK_PREFIX) {
            return Err(HostError::Unsupported);
        }
        let state = self.state()?;
        let results = service::sanitize_blocks(
            &state,
            dataset,
            None,
            blocks.into_iter().map(BlockInput::text).collect(),
        )
        .map_err(|e| service_err(&e))?;
        Ok(results
            .into_iter()
            .map(|r| {
                let mut checks: Vec<String> = Vec::new();
                for x in &r.reasons {
                    let c = CheckLabel::of(&x.check).as_str().to_string();
                    if !checks.contains(&c) {
                        checks.push(c);
                    }
                }
                HostBlock {
                    blocked: r.outcome == CachedOutcome::Blocked,
                    uncertain: r.outcome == CachedOutcome::PassUncertain,
                    text: r.text,
                    kinds: r.kinds,
                    checks,
                }
            })
            .collect())
    }

    /// Spec §9: one record per event through the gateway's writer (one
    /// chain), under `inumaki-chat` unless a tripwire hit names a dataset.
    /// No original, token, or dataset id goes in: opaque labels, enums,
    /// counts, and the keyed digest of the journal payload.
    fn record(&self, event: ProxyEvent) {
        let Ok(state) = self.state() else {
            return;
        };
        let Some(gateway) = state.gateway.get() else {
            return;
        };
        let vault = &state.vault;
        let upstream_label =
            |up: inumaki_proxy::UpstreamId| Some(vault.opaque_upstream(CHAT_DATASET, up.id()));
        let base = |up, direction, verdict| NewActivity {
            dataset: vault.opaque_ref(CHAT_DATASET),
            front_door: FrontDoor::Proxy,
            upstream: upstream_label(up),
            direction,
            verdict,
            checks: Vec::new(),
            kinds: Vec::new(),
            tripwire: false,
            bytes: 0,
            released: None,
        };
        let sink = gateway.activity();
        match event {
            ProxyEvent::Released {
                upstream,
                kinds,
                payload,
            } => {
                let mut rec = base(upstream, Direction::Request, Verdict::Released);
                rec.kinds = kind_counts(&kinds);
                if payload.is_empty() {
                    sink.emit(rec);
                } else {
                    rec.bytes = payload.len() as u64;
                    rec.released = Some(vault.released_digest(&payload));
                    sink.emit_released(CHAT_DATASET, rec, payload);
                }
            }
            ProxyEvent::Withheld {
                upstream,
                uncertain,
                kinds,
                checks,
            } => {
                let verdict = if uncertain {
                    Verdict::Uncertain
                } else {
                    Verdict::Blocked
                };
                let mut rec = base(upstream, Direction::Result, verdict);
                rec.kinds = kind_ones(&kinds);
                rec.checks = check_labels(&checks);
                sink.emit(rec);
            }
            ProxyEvent::Refused {
                upstream,
                verdict,
                kinds,
                checks,
            } => {
                let verdict = match verdict {
                    RefusedVerdict::Blocked => Verdict::Blocked,
                    RefusedVerdict::Uncertain => Verdict::Uncertain,
                    RefusedVerdict::Unsupported => Verdict::Unsupported,
                };
                let mut rec = base(upstream, Direction::Request, verdict);
                rec.kinds = kind_ones(&kinds);
                rec.checks = check_labels(&checks);
                sink.emit(rec);
            }
            ProxyEvent::ClearValue {
                upstream,
                dataset,
                kinds,
                blocked,
            } => {
                let verdict = if blocked {
                    Verdict::Blocked
                } else {
                    Verdict::Released
                };
                let mut rec = base(upstream, Direction::Response, verdict);
                if let Some(ds) = dataset.as_deref() {
                    rec.dataset = vault.opaque_ref(ds);
                }
                rec.kinds = kind_counts(&kinds);
                rec.checks = vec![CheckLabel::ClearValue];
                rec.tripwire = true;
                sink.emit(rec);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn a_non_empty_identity_whose_dictionary_fails_keeps_the_host_from_building() {
        let fail: &Build<'_> = &|_| Err(inumaki_core::Error::ConfigInvalid("dictionary".into()));
        let names = Identity {
            names: vec![(
                EntityKind::Person,
                Zeroizing::new("Zyxwuria Quolnath".into()),
            )],
            accounts: vec![],
        };
        assert_eq!(
            DaemonHost::with_identity_using(Weak::new(), names, fail).unwrap_err(),
            HostError::Internal
        );
        let accounts = Identity {
            names: vec![],
            accounts: vec![(EntityKind::Person, Zeroizing::new("zquolnath".into()))],
        };
        assert_eq!(
            DaemonHost::with_identity_using(Weak::new(), accounts, fail).unwrap_err(),
            HostError::Internal
        );
        // No values: nothing to build, never an error.
        let called = std::cell::Cell::new(false);
        let spy: &Build<'_> = &|_| {
            called.set(true);
            Err(inumaki_core::Error::ConfigInvalid("x".into()))
        };
        let empty = Identity {
            names: vec![],
            accounts: vec![],
        };
        assert!(DaemonHost::with_identity_using(Weak::new(), empty, spy).is_ok());
        assert!(!called.get());
    }

    /// Ruling L2-40: a host that returns a memo from `ner_memo()` returns
    /// the unwrapped engine from `engine_unmemoized()`: its models run on
    /// every call, even inside an open scope on the same text after the
    /// memo engine stored a result, and the memo is never read or written.
    /// `engine()` returns the memo engine, whose repeat pass is a hit.
    #[test]
    fn engine_unmemoized_never_returns_a_memo_wrapped_engine() {
        use crate::engines::fake::{CountingNer, long_text};
        use inumaki_core::token::{Context, ContextId};
        use inumaki_models::assemble::NerPair;

        let core = inumaki_core::config::CoreConfig::from_toml(include_str!(
            "../../../configs/default.toml"
        ))
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let engines = Engines::new(core, dir.path().to_path_buf());
        let (s, v) = (
            Arc::new(CountingNer::default()),
            Arc::new(CountingNer::default()),
        );
        engines.insert_pair(
            "support-email",
            NerPair {
                sanitizer: Some(s.clone() as Arc<dyn Detector>),
                verifier: Some(v.clone() as Arc<dyn Detector>),
            },
        );
        let memo = NerMemo::new(
            "support-email",
            [0; 32],
            STATIC_MEMO_ENTRIES,
            STATIC_MEMO_BYTES,
        );
        let text = long_text();
        let run = |e: &Engine| {
            let mut ctx = Context::new(
                ContextId("t".into()),
                std::time::Duration::from_secs(60),
                e.token_settings().clone(),
            );
            e.process(&text, &mut ctx).unwrap();
        };
        let _scope = memo.scope(&text);
        let wrapped = memo_engine(&engines, Some(&memo), "support-email").unwrap();
        run(&wrapped);
        run(&wrapped);
        assert_eq!(
            (s.long(), v.long()),
            (1, 1),
            "the memo engine's repeat pass is a hit"
        );
        let before = memo.stats();
        let plain = plain_engine(&engines, "support-email").unwrap();
        assert!(!Arc::ptr_eq(&plain, &wrapped));
        run(&plain);
        run(&plain);
        assert_eq!(
            (s.long(), v.long()),
            (3, 3),
            "both models ran on each unmemoized pass"
        );
        assert_eq!(
            memo.stats(),
            before,
            "the unmemoized engine never touched the memo"
        );
        // Without a memo, `engine()` is that same unwrapped engine.
        assert!(Arc::ptr_eq(
            &memo_engine(&engines, None, "support-email").unwrap(),
            &plain
        ));
    }
}
