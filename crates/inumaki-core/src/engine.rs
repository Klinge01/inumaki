//! Orchestrates detection, policy, tokenization, verification, retry, and block.

use std::borrow::Cow;
use std::ops::Range;
use std::sync::Arc;

use unicode_normalization::{UnicodeNormalization, is_nfc};
use zeroize::Zeroizing;

use crate::alias::{AliasTable, Aliased};
use crate::config::{CoreConfig, TokenSettings};
use crate::consistency::{StoreDict, store_fingerprint};
use crate::detect::anchor::AnchorDetector;
use crate::detect::dictionary::DictionaryDetector;
use crate::detect::domain::DomainDetector;
use crate::detect::path_names::PathNameDetector;
use crate::detect::plausible::{drop_implausible_persons, split_and_drop_greeting_spans};
use crate::detect::regex::RegexDetector;
use crate::detect::secrets::SecretsDetector;
use crate::detect::technical::drop_technical_persons_at;
use crate::detect::{DetectCtx, Detector, run_all};
use crate::link::{self, LinkScope, LinkTier, LinkTiers, LinkingConfig, Links};
use crate::origin::TextOrigin;
use crate::policy::{Action, Decision, OnUncertain, Profile};
use crate::redact::{Redaction, RedactionAction};
use crate::resolve::resolve_overlaps_with;
use crate::sanitize::{Sanitized, sanitize_linked};
use crate::span::{DetectorId, EntityKind, Span};
use crate::token::{StoreError, TokenStore};
use crate::verify::second_pass::detector_failure;
use crate::verify::{CheckId, Reason, SecondPassVerifier, Verdict, Verifier};
use crate::{Error, Result};

mod project;
pub use project::{Abandon, CallerCheck, Projection, ProjectionScratch, real_token};

/// Result of processing one text.
#[derive(Debug)]
pub enum Outcome {
    /// Safe to send.
    Pass {
        /// The candidate.
        sanitized: Sanitized,
    },
    /// Safe to send, flagged.
    PassUncertain {
        /// The candidate.
        sanitized: Sanitized,
        /// Why it was flagged.
        reasons: Vec<Reason>,
    },
    /// Must not be sent.
    Blocked {
        /// Why.
        reasons: Vec<Reason>,
        /// Entity kinds involved, deduplicated.
        kinds: Vec<EntityKind>,
    },
}

/// Everything a local inspection shows (M4 spec §9.1): the outcome, the
/// decisions of the pass that settled it, and the candidate text even when
/// the outcome is `Blocked` (labelled diagnostic output by the caller).
pub struct Detailed {
    /// The outcome.
    pub outcome: Outcome,
    /// Decisions of the settling pass (first pass, or the retry).
    pub decisions: Vec<Decision>,
    /// The settling pass's candidate; `None` after a detector error.
    pub candidate: Option<Sanitized>,
    /// True when the retry profile settled it.
    pub retried: bool,
    /// Name of the profile that settled it.
    pub profile: String,
    /// How many links the name linker decided per tier (zeros after a
    /// detector error). The service never caches a block whose links
    /// depended on state outside the text (plan 4a decision 7).
    pub links: LinkTiers,
    /// How many clear copies of store values the settling pass's
    /// referential-consistency step folded in (`StoreMatch` redactions;
    /// see [`crate::consistency`]). Zero after a detector error.
    pub consistency: usize,
    /// Policy-escalated spans the settling pass tokenized under
    /// `on_uncertain = "tokenize"` (L70); a count, never content. Zero
    /// after a detector error.
    pub band_tokenized: usize,
}

impl std::fmt::Debug for Detailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Detailed")
            .field("outcome", &std::mem::discriminant(&self.outcome))
            .field("decisions", &self.decisions.len())
            .field(
                "candidate_len",
                &self.candidate.as_ref().map(|c| c.text.len()),
            )
            .field("retried", &self.retried)
            .field("profile", &self.profile)
            .field("links", &self.links)
            .field("consistency", &self.consistency)
            .field("band_tokenized", &self.band_tokenized)
            .finish()
    }
}

/// NFC-normalize input text. Borrowed when `text` is already NFC.
///
/// [`Engine::process`] and [`Engine::detect`] apply this at entry, so the
/// sanitized text and every span offset refer to the NFC form. A caller that
/// slices spans must slice the output of this function, not its input.
pub fn normalize_input(text: &str) -> Cow<'_, str> {
    if is_nfc(text) {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(text.nfc().collect())
    }
}

/// [`normalize_input`], with an owned copy held in `Zeroizing` so the
/// plaintext buffer is wiped on drop.
fn nfc_zeroizing(text: &str) -> Option<Zeroizing<String>> {
    match normalize_input(text) {
        Cow::Borrowed(_) => None,
        Cow::Owned(o) => Some(Zeroizing::new(o)),
    }
}

/// The privacy engine for one profile.
pub struct Engine {
    profile: Profile,
    retry_profile: Option<Profile>,
    detectors: Vec<Arc<dyn Detector>>,
    verifier: Arc<dyn Verifier>,
    token_settings: TokenSettings,
    /// Alias groups applied to every token store during a pass (M4 spec §16.5).
    aliases: Arc<AliasTable>,
    /// Name linking (M4 spec §16.2).
    linking: LinkingConfig,
}

/// One call's [`StoreDict`] and the [`store_fingerprint`] of the store it
/// was built from (Task 7d (C), ruling L58), for a store that keeps no
/// cache of its own: shared by the call's primary pass and its retry,
/// dropped when the call returns. Its forms are `Zeroizing` (wiped on
/// drop); `Debug` prints counts only.
#[derive(Debug)]
struct StoreDictSlot {
    fingerprint: (u64, usize),
    dict: StoreDict,
}

/// The dictionary over `store`'s current values. A store that keeps a
/// cache (`TokenStore::store_dict`, Task 7e ruling L62) answers from it:
/// built once, extended by the values minted since, its forms living with
/// the store. Otherwise `slot`'s, rebuilt first when `store`'s
/// [`store_fingerprint`] differs from the one it was built from (a value
/// minted or removed since) or when there is none yet.
fn current_store_dict(
    slot: &mut Option<StoreDictSlot>,
    store: &mut dyn TokenStore,
) -> Result<StoreDict> {
    if let Some(d) = store.store_dict(None) {
        return d;
    }
    let fingerprint = store_fingerprint(store);
    // A stale one is dropped first: one copy of the forms at a time.
    drop(slot.take_if(|s| s.fingerprint != fingerprint));
    let s = match slot {
        Some(s) => s,
        None => slot.insert(StoreDictSlot {
            fingerprint,
            dict: StoreDict::build(store)?,
        }),
    };
    Ok(s.dict.clone())
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("profile", &self.profile.name)
            .field(
                "retry_profile",
                &self.retry_profile.as_ref().map(|p| &p.name),
            )
            .field("detectors", &self.detectors.len())
            .finish()
    }
}

/// The retry profile must keep every `Block` of the primary (review I4,
/// engine spec §6.3/§6.6).
///
/// A profile's `retry_profile` is inherited through `extends`: a profile
/// that extends a shipped profile and adds its own `action = "block"`
/// override picks up the parent's `retry_profile` unchanged, since nothing
/// propagates a per-profile override into a *different* profile's
/// `entities`. Without this check, `Engine::process` would settle a first
/// pass's `Verdict::Fail(Policy)` by retrying into a profile that
/// tokenizes the same kind instead of blocking it, and the block would
/// never surface — silently, since the retry is not itself an error.
///
/// Checked: every kind the primary profile blocks explicitly, and the
/// primary's `default_action` when it is `Block` (kinds with no explicit
/// entry inherit it in both profiles).
fn check_retry_keeps_blocks(primary: &Profile, retry: &Profile, retry_name: &str) -> Result<()> {
    if primary.default.action == Action::Block && retry.default.action != Action::Block {
        return Err(Error::ConfigInvalid(format!(
            "profiles.{retry_name}.default_action"
        )));
    }
    for (kind, policy) in &primary.entities {
        if policy.action != Action::Block {
            continue;
        }
        let retry_action = retry
            .entities
            .get(kind)
            .map_or(retry.default.action, |p| p.action);
        if retry_action != Action::Block {
            return Err(Error::ConfigInvalid(format!(
                "profiles.{retry_name}.entities.{kind}.action"
            )));
        }
    }
    Ok(())
}

fn dedup_kinds(reasons: &[Reason]) -> Vec<EntityKind> {
    let mut out: Vec<EntityKind> = Vec::new();
    for r in reasons {
        if !out.contains(&r.kind) {
            out.push(r.kind.clone());
        }
    }
    out
}

/// Strength order for merging a redaction's forced action with the actions
/// of the decisions it overlaps: `Block` beats everything, `Remove` beats
/// `Tokenize`, and both beat leaving the text in place. While escalations
/// hold, `merge_redaction` lifts an absorbed `Escalate` over `Tokenize` and,
/// since L106, over `Remove`.
fn action_rank(a: Action) -> u8 {
    match a {
        Action::Block => 4,
        Action::Remove => 3,
        Action::Tokenize => 2,
        Action::Escalate => 1,
        Action::Preserve => 0,
    }
}

/// Fold one redaction into `decisions` (M4 spec §9.1, controller fix: a
/// redaction may only add coverage and strengthen an action, never evict a
/// stronger one). Every decision the redaction's range overlaps is removed
/// and replaced by one decision spanning the union of all their ranges (so a
/// redaction that only partially covers a detected entity cannot leave the
/// remainder of that entity in clear text) whose action is the strongest of
/// the redaction's forced action and each removed decision's action — in
/// particular, a `Block` among them survives, and the kind reported is the
/// real detected kind, never the caller's label, so a mislabeled redaction
/// cannot relabel a blocked entity into an unblocked one. The one exception
/// is a regex town ([`crate::detect::regex::is_town_span`]) under a PERSON
/// store copy: the union takes the PERSON kind (ruling L53). A redaction that
/// overlaps nothing is added as its own decision, unchanged from before.
///
/// `escalation_holds` (the pass's profile refuses on uncertainty,
/// `on_uncertain = "block"` or `"tokenize"`): a removed `Escalate` decision
/// keeps the union at `Escalate` where it would otherwise be `Tokenize`
/// (re-review 2, Critical). An escalation there is a refusal or the
/// primary's retry trigger, never a forward in clear, so keeping it fails
/// closed: a store copy or caller redaction cannot turn the retry's guarded
/// multi-line name into a token that leaves the rest of the signature in
/// clear, nor skip the retry. Under `tokenize` the band spans of tokenized
/// or preserved kinds are already `Tokenize` when redactions merge, so an
/// `Escalate` here is one the guard put back or a band span of a `block`
/// kind (L3-13), and it refuses as under `block`. Under `escalate` and `pass`
/// an escalation is forwarded in clear, so there the union tokenizes as
/// before. The union keeps the `crossed_line_break` flag of any decision it
/// absorbed.
///
/// L106: while escalations hold, the absorbed `Escalate` also outranks
/// `Remove` (only `Block` still beats it). A clear copy of a value removed
/// elsewhere in the text (a consistency match, `RedactionAction::Remove`)
/// that lands on the guard's escalated piece would otherwise remove that
/// piece alone and forward the missed surname next to it in clear. Under
/// `escalate` and `pass` the order is unchanged (`Remove` wins).
fn merge_redaction(decisions: &mut Vec<Decision>, r: &Redaction, escalation_holds: bool) {
    let mut start = r.start;
    let mut end = r.end;
    let mut action = match r.action {
        RedactionAction::Tokenize => Action::Tokenize,
        RedactionAction::Remove => Action::Remove,
    };
    let mut kind: Option<EntityKind> = None;
    let mut escalated = false;
    let mut crossed_line_break = false;
    loop {
        let before = decisions.len();
        let mut i = 0;
        while i < decisions.len() {
            if decisions[i].span.start < end && start < decisions[i].span.end {
                let d = decisions.remove(i);
                start = start.min(d.span.start);
                end = end.max(d.span.end);
                // A regex town after a postal code yields its kind to a
                // store name copy (`10234 Gruber` after `Max Gruber`,
                // ruling L53): the copy is the person, not a town.
                let town_yields = crate::detect::regex::is_town_span(&d.span)
                    && r.kind == EntityKind::Person.label();
                if (kind.is_none() && !town_yields) || d.action == Action::Block {
                    kind = Some(d.span.kind.clone());
                }
                if action_rank(d.action) > action_rank(action) {
                    action = d.action;
                }
                escalated |= d.action == Action::Escalate;
                crossed_line_break |= d.span.crossed_line_break;
            } else {
                i += 1;
            }
        }
        if decisions.len() == before {
            break;
        }
    }
    // L106: `Remove` yields to the escalation too, while escalations hold.
    if escalation_holds && escalated && matches!(action, Action::Tokenize | Action::Remove) {
        action = Action::Escalate;
    }
    let kind = kind.unwrap_or_else(|| EntityKind::from_label(&r.kind));
    decisions.push(Decision {
        span: Span {
            crossed_line_break,
            ..Span::new(start, end, kind, 1.0, DetectorId::Redaction)
        },
        action,
    });
}

/// The outcome when the consistency step could not run: blocked with the
/// pass's `DetectorError` reasons.
fn consistency_blocked(verdict: Verdict) -> Outcome {
    let mut reasons = match verdict {
        Verdict::Fail(r) | Verdict::Uncertain(r) => r,
        Verdict::Pass => Vec::new(),
    };
    if reasons.is_empty() {
        reasons.push(Reason {
            kind: EntityKind::custom("DETECTOR"),
            check: CheckId::DetectorError,
        });
    }
    let kinds = dedup_kinds(&reasons);
    Outcome::Blocked { reasons, kinds }
}

/// What one policy-sanitize-verify pass produced.
struct Pass {
    sanitized: Sanitized,
    verdict: Verdict,
    decisions: Vec<Decision>,
    /// Clear copies of store values the consistency step folded in.
    consistency: usize,
    /// Link tiers of the links the pass sanitized with (the linker's,
    /// plus the consistency step's `Window` links).
    links: LinkTiers,
    /// The consistency step could not run: the verdict is a
    /// `DetectorError` failure and the text blocks without a retry.
    detector_error: bool,
    /// Policy-escalated spans this pass tokenized under
    /// `on_uncertain = "tokenize"` (L70); a count, never content.
    band_tokenized: usize,
}

impl Engine {
    /// Assemble from parts.
    pub fn new(
        profile: Profile,
        retry_profile: Option<Profile>,
        detectors: Vec<Arc<dyn Detector>>,
        verifier: Arc<dyn Verifier>,
    ) -> Self {
        Engine {
            profile,
            retry_profile,
            detectors,
            verifier,
            token_settings: TokenSettings::default(),
            aliases: Arc::new(AliasTable::empty()),
            linking: LinkingConfig::default(),
        }
    }

    /// Assemble the standard detector stack from configuration.
    ///
    /// `sanitizer_ner` joins the detector stack; `verifier_ner` is the
    /// independent NER re-scan run by the verifier (spec §6.5). The verifier
    /// must use a *different* NER configuration than the sanitizer, so the
    /// same `Arc` passed for both is rejected with
    /// [`Error::ConfigInvalid`](crate::Error::ConfigInvalid). Without a
    /// `verifier_ner`, the profile must set `verifier.allow_no_ner = true`.
    ///
    /// The verifier is constructed once, from the *primary* profile's
    /// `verifier` settings (`combination_threshold` and `allow_no_ner`). The
    /// retry profile named by `profile.verifier.retry_profile` changes
    /// policy only (actions and thresholds); its own `verifier` table is
    /// read again during [`Engine::process`], but only for `on_uncertain`.
    /// The retry profile's `ner_sanitizer` and `ner_verifier` must resolve
    /// to the same values as the primary profile's, since the detector
    /// stack and verifier are built once from the primary profile and the
    /// retry never rebuilds them; a retry profile that names different NER
    /// sections is rejected with [`Error::ConfigInvalid`](crate::Error::ConfigInvalid).
    pub fn from_config(
        cfg: &CoreConfig,
        profile_name: &str,
        sanitizer_ner: Option<Arc<dyn Detector>>,
        verifier_ner: Option<Arc<dyn Detector>>,
    ) -> Result<Self> {
        if let (Some(a), Some(b)) = (&sanitizer_ner, &verifier_ner) {
            if Arc::ptr_eq(a, b) {
                return Err(Error::ConfigInvalid(
                    "verifier_ner must differ from sanitizer_ner".into(),
                ));
            }
        }
        let profile = cfg.resolve_profile(profile_name)?;
        if profile.ner_sanitizer.is_some() && sanitizer_ner.is_none() {
            return Err(Error::ModelUnavailable("ner_sanitizer".into()));
        }
        if profile.ner_verifier.is_some() && verifier_ner.is_none() {
            return Err(Error::ModelUnavailable("ner_verifier".into()));
        }
        let retry_profile = match &profile.verifier.retry_profile {
            Some(name) if name != profile_name => {
                let retry = cfg.resolve_profile(name)?;
                if retry.ner_sanitizer != profile.ner_sanitizer {
                    return Err(Error::ConfigInvalid(format!(
                        "profiles.{name}.ner_sanitizer"
                    )));
                }
                if retry.ner_verifier != profile.ner_verifier {
                    return Err(Error::ConfigInvalid(format!(
                        "profiles.{name}.ner_verifier"
                    )));
                }
                check_retry_keeps_blocks(&profile, &retry, name)?;
                Some(retry)
            }
            Some(_) => None,
            None => None,
        };
        let aliases = Arc::new(AliasTable::from_config(&cfg.dictionary)?);
        let regex = RegexDetector::new();
        let mut detectors: Vec<Arc<dyn Detector>> = vec![
            Arc::new(regex.clone()),
            Arc::new(SecretsDetector::new()),
            Arc::new(DomainDetector::from_config(&cfg.domain)?),
            Arc::new(DictionaryDetector::from_config(&cfg.dictionary)?),
        ];
        if cfg.linking.anchors {
            detectors.push(Arc::new(AnchorDetector::new()));
        }
        // Names in paths and URLs (ruling S13): every profile and origin, no
        // switch, so outside the `linking.anchors` block.
        detectors.push(Arc::new(PathNameDetector::new()));
        if let Some(n) = sanitizer_ner {
            detectors.push(n);
        }
        let verifier: Arc<dyn Verifier> = Arc::new(SecondPassVerifier::new(
            regex,
            verifier_ner,
            &profile.verifier,
        )?);
        Ok(Engine {
            profile,
            retry_profile,
            detectors,
            verifier,
            token_settings: cfg.tokens.clone(),
            aliases,
            linking: cfg.linking.clone(),
        })
    }

    /// Active profile.
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// The verifier this engine uses; exposed for evaluation tooling.
    pub fn verifier(&self) -> &Arc<dyn Verifier> {
        &self.verifier
    }

    /// Token format the engine expects contexts to use.
    pub fn token_settings(&self) -> &TokenSettings {
        &self.token_settings
    }

    /// Name linking settings this engine applies.
    pub fn linking(&self) -> &LinkingConfig {
        &self.linking
    }

    /// The alias groups this engine applies (empty when none are configured).
    pub fn aliases(&self) -> &Arc<AliasTable> {
        &self.aliases
    }

    /// Add a detector to the stack, e.g. a dataset's known-entity detector.
    /// The retry pass shares the stack, so the detector runs once per request.
    #[must_use]
    pub fn with_detector(mut self, detector: Arc<dyn Detector>) -> Self {
        self.detectors.push(detector);
        self
    }

    /// Run all detectors and resolve overlaps.
    ///
    /// The text is NFC-normalized first (see [`normalize_input`]); span
    /// offsets refer to the NFC form. Fails when any detector fails or
    /// returns an invalid span.
    pub fn detect(&self, text: &str) -> Result<Vec<Span>> {
        self.detect_scoped(text, &LinkScope::empty(), None)
    }

    /// [`Engine::detect`] plus the name linker's emitted mentions, with a
    /// batch scope and a store for the linker's tiers 2 and 3. There are no
    /// store tokens to protect here, so the linker runs unprotected. Free
    /// text ([`TextOrigin::Free`]).
    pub fn detect_scoped(
        &self,
        text: &str,
        scope: &LinkScope,
        store: Option<&dyn TokenStore>,
    ) -> Result<Vec<Span>> {
        self.detect_scoped_at(text, scope, store, TextOrigin::Free)
    }

    /// [`Engine::detect`] for a text of known origin ([`TextOrigin`]).
    pub fn detect_at(&self, text: &str, origin: TextOrigin) -> Result<Vec<Span>> {
        self.detect_scoped_at(text, &LinkScope::empty(), None, origin)
    }

    /// [`Engine::detect_scoped`] for a text of known origin ([`TextOrigin`],
    /// ruling L3-14).
    pub fn detect_scoped_at(
        &self,
        text: &str,
        scope: &LinkScope,
        store: Option<&dyn TokenStore>,
        origin: TextOrigin,
    ) -> Result<Vec<Span>> {
        let owned = nfc_zeroizing(text);
        let text = owned.as_deref().map_or(text, String::as_str);
        let spans = self.detect_nfc(text, &[], origin)?;
        Ok(if self.linking.enabled {
            link::link_mentions(text, spans, scope, store, &self.linking, &[]).0
        } else {
            spans
        })
    }

    /// [`Engine::detect`] on `scan`, text that is already NFC. With
    /// `protected` ranges (see [`crate::protect`]), `scan` is the text with
    /// those tokens masked, and the raw detector output is clipped against
    /// them after the plausibility filter (which judges whole spans) and
    /// *before* overlap resolution: a
    /// high-priority hit inside a token (a dictionary or regex match on its
    /// label) must not win over an overlapping span that reaches into real
    /// text and then be clipped to nothing, leaving that text undetected.
    fn detect_nfc(
        &self,
        scan: &str,
        protected: &[Range<usize>],
        origin: TextOrigin,
    ) -> Result<Vec<Span>> {
        let mut ctx = DetectCtx::for_text(scan);
        if let Some(l) = self.profile.language {
            ctx.language = l;
        }
        let spans = run_all(&self.detectors, scan, &ctx)?;
        // The plausibility filter judges each span as the model found it,
        // before clipping: a short lowercase piece cut from a longer person
        // span (`<PERSON_ab12> wu` → `wu`) must not be dropped as a value.
        let spans = drop_implausible_persons(scan, spans);
        // Harness-static precision (L60): model PERSON spans that are
        // technical text are not names. Judged before clipping, with the
        // protected tokens and the caller's origin (L3-14): a span next to a
        // token is never technical.
        let mut spans = drop_technical_persons_at(scan, spans, protected, origin);
        // Ruling (b): record which PERSON spans, as the detector reported
        // them, crossed a line break, before anything clips or splits them;
        // every piece cut later keeps the flag (`..span.clone()`), and the
        // retry's guard reads it (`escalate_uncertain_multiline_persons`).
        for s in &mut spans {
            if s.kind == EntityKind::Person && scan[s.start..s.end].contains(['\n', '\r']) {
                s.crossed_line_break = true;
            }
        }
        // Task 7, ruling L48: cut model PERSON and ORGANIZATION spans at
        // line breaks (each piece keeps the flag just set) and drop the
        // pieces, and single-line spans, made only of greeting words.
        let spans = split_and_drop_greeting_spans(scan, spans);
        // Ruling L48 (S3): a regex town after a postal code never displaces
        // a PERSON span over the same word; it only adds coverage.
        let spans = crate::detect::regex::yield_towns_to_persons(spans);
        // Ruling S10: a URL span is cut around the path names it strictly
        // contains, or the URL (priority 5, preserved by some profiles)
        // would evict the name and forward it.
        let spans = crate::detect::path_names::cut_urls_around_positions(scan, spans);
        // Outside protected ranges `scan` equals the unmasked text, and the
        // pieces lie outside them, so trimming on `scan` is exact.
        let spans = crate::protect::clip_spans(scan, spans, protected);
        // A known-entity fragment yields to a longer span of the same kind
        // only when every profile that may settle the text (the primary and
        // the retry) tokenizes, removes, or blocks that span: a weak regex
        // or NER span never evicts a known entity (integrator ruling L30).
        let strong = |s: &Span| {
            std::iter::once(&self.profile)
                .chain(self.retry_profile.as_ref())
                .all(|p| {
                    matches!(
                        p.action_for(s),
                        Some(Action::Tokenize | Action::Remove | Action::Block)
                    )
                })
        };
        // Ruling (a): a person span that ends with a known first name takes
        // the surname after it on the same line (see `detect::surname`);
        // a span over that word stops it only if `strong` (re-review 2).
        let spans = crate::detect::surname::extend_over_surnames(scan, spans, protected, &strong);
        Ok(resolve_overlaps_with(spans, &strong))
    }

    /// Policy, sanitize, verify for one profile over already-detected spans,
    /// with alias variants mapped to their canonical before the store sees
    /// them (M4 spec §16.5). With no alias groups the store is used as is.
    /// `protected` are the input ranges of tokens that resolve in the store
    /// (see [`crate::protect`]): decisions are clipped around them and the
    /// result records where they landed, for the verifier.
    ///
    /// Between sanitizing and verifying, the referential-consistency step
    /// (see [`crate::consistency`]) tokenizes every clear copy of a value
    /// the store holds, this pass's own mints included, with that value's
    /// entity: exactly one extra sanitize round, no loop. If it cannot
    /// run, the pass fails with `DetectorError` and the verifier is not
    /// called.
    // The pass's inputs are all distinct and private; a parameter struct
    // would only rename them.
    #[allow(clippy::too_many_arguments)]
    fn run_pass(
        &self,
        text: &str,
        profile: &Profile,
        spans: Vec<Span>,
        links: &Links,
        ctx: &mut dyn TokenStore,
        redactions: &[Redaction],
        protected: &[Range<usize>],
        is_retry: bool,
        dict: &mut Option<StoreDictSlot>,
        origin: TextOrigin,
    ) -> std::result::Result<Pass, StoreError> {
        let mut aliased;
        let ctx: &mut dyn TokenStore = if self.aliases.is_empty() {
            ctx
        } else {
            aliased = Aliased::new(ctx, &self.aliases);
            &mut aliased
        };
        let mut decisions = profile.apply_to_text(text, spans);
        // L70: under `tokenize` an uncertain (policy-escalated) span is
        // tokenized like a detection; it is never forwarded in clear. The
        // multi-line guard then runs in this pass too (not only in the
        // retry): a span it escalates again refuses in `settle`, which
        // triggers the retry, where the guard runs again and blocks.
        // L3-13: only a kind the profile tokenizes or preserves converts to
        // `Tokenize`. A `remove` kind's band span is removed (no token, never
        // restorable, not in the store); a `block` (or `escalate`) kind's
        // band span keeps `Escalate`, which refuses as under `block`. A
        // `remove` kind's span is held at `Tokenize` until the guard below
        // has seen it, so an uncertain multi-line span next to a missed
        // surname refuses for a removed kind too; only then does it become
        // `Remove`. (Since L106 the guard also looks at `Remove` decisions,
        // so the hold is no longer load-bearing; it is kept as is.)
        let tokenize_band = profile.verifier.on_uncertain == OnUncertain::Tokenize;
        let mut converted: Vec<usize> = Vec::new();
        let mut to_remove: Vec<usize> = Vec::new();
        if tokenize_band {
            for (i, d) in decisions.iter_mut().enumerate() {
                if d.action != Action::Escalate {
                    continue;
                }
                match profile.policy_for(&d.span.kind).action {
                    Action::Tokenize | Action::Preserve => {
                        d.action = Action::Tokenize;
                        converted.push(i);
                    }
                    Action::Remove => {
                        d.action = Action::Tokenize;
                        to_remove.push(i);
                    }
                    Action::Block | Action::Escalate => {}
                }
            }
        }
        // An escalation refuses (or triggers the retry) under
        // `on_uncertain = "block"` and `"tokenize"`; only `"escalate"` and
        // `"pass"` forward it in clear.
        let escalation_holds = matches!(
            profile.verifier.on_uncertain,
            OnUncertain::Block | OnUncertain::Tokenize
        );
        // Ruling (b): an uncertain multi-line PERSON span with a name
        // candidate next to it keeps the action escalate (fail closed): in
        // the retry under `block`, in every pass under `tokenize`. Merged
        // redactions and consistency matches keep that escalation
        // (`merge_redaction`), a `Remove` copy included (L106). The guard
        // escalates a tokenized or a removed span (L106: a retry profile
        // that removes PERSON must not skip it). Where an escalation would
        // forward in clear (`escalate`, `pass`), the guard does not run and
        // the span stays tokenized instead.
        if escalation_holds && (is_retry || tokenize_band) {
            crate::policy::escalate_uncertain_multiline_persons(
                text,
                &mut decisions,
                &self.profile,
            );
        }
        // Only conversions the guard left tokenized count. The guard
        // rewrites `decisions[i].action` by index and never reorders or
        // removes, so the indices in `converted` and `to_remove` stay valid
        // here. A `remove` kind's band span the guard left alone is removed
        // now (an escalated one keeps `Escalate` and refuses); it is not
        // counted.
        for &i in &to_remove {
            if decisions[i].action == Action::Tokenize {
                decisions[i].action = Action::Remove;
            }
        }
        let band_tokenized = converted
            .iter()
            .filter(|&&i| decisions[i].action == Action::Tokenize)
            .count();
        // Fold redactions into the detected decisions (see `merge_redaction`):
        // a redaction only adds coverage and strengthens an action, it never
        // evicts a stronger decision made from the real detected span.
        for r in redactions {
            merge_redaction(&mut decisions, r, escalation_holds);
        }
        decisions.sort_by_key(|d| d.span.start);
        // M8 spec decision 11: a redaction merged over a protected token is
        // clipped like a detected span (the pieces stay in order).
        let decisions = crate::protect::clip_decisions(text, decisions, protected);
        let mut sanitized = sanitize_linked(text, &decisions, links, ctx)?;
        sanitized.protected = crate::protect::out_ranges(protected, &sanitized.replacements);
        // Referential consistency (engine spec §6.4, plan ruling C1): the
        // store now holds this pass's own mints too.
        // The call's dictionary (ruling L58): reused from the primary pass
        // when the store is unchanged since.
        let matches =
            current_store_dict(dict, ctx).and_then(|d| d.redactions(text, &decisions, protected));
        let matches = match matches {
            Ok(m) => m,
            Err(e) => {
                return Ok(Pass {
                    sanitized,
                    verdict: detector_failure(&e),
                    decisions,
                    consistency: 0,
                    links: links.tiers(),
                    detector_error: true,
                    band_tokenized: 0,
                });
            }
        };
        let (sanitized, decisions, link_tiers) = if matches.is_empty() {
            (sanitized, decisions, links.tiers())
        } else {
            // Decisions made from this text alone (and the caller's
            // redactions), before any store copy joins them: a store source
            // that one of these tokenizes is a mention in this very text.
            let detected = decisions.clone();
            let mut decisions = decisions;
            for m in &matches {
                merge_redaction(&mut decisions, &m.redaction, escalation_holds);
            }
            decisions.sort_by_key(|d| d.span.start);
            let decisions = crate::protect::clip_decisions(text, decisions, protected);
            // N1: a form of exactly one store original shares its entity,
            // but only when the merged decision is exactly the match (a
            // widened one has another text and kind, so its own token). A
            // link the linker already decided stands. With linking disabled
            // the copy is still tokenized, as its own entity.
            let mut extended = links.clone();
            for m in &matches {
                let Some(source) = &m.source else { continue };
                let r = &m.redaction;
                let exact = decisions.iter().any(|d| {
                    d.span.start == r.start
                        && d.span.end == r.end
                        && d.action == Action::Tokenize
                        && d.span.kind.label() == r.kind
                });
                if exact && self.linking.enabled && extended.parent(r.start).is_none() {
                    // `Document` when the source is tokenized from this
                    // very text (a sign-off `Stefan` after `Stefan Kaiser`):
                    // the link rests on the text alone, so the block may be
                    // cached. `Window` otherwise: the link rests on a value
                    // from outside this text (plan 4a decision 7: never
                    // cache such a block). The snapshot is taken before the
                    // store copies merge, so one store-only copy cannot
                    // vouch for another.
                    let source_key = crate::token::normalize(source);
                    let in_text = detected.iter().any(|d| {
                        d.action == Action::Tokenize
                            && d.span.kind.label() == r.kind
                            && text
                                .get(d.span.start..d.span.end)
                                .is_some_and(|t| crate::token::normalize(t) == source_key)
                    });
                    let tier = if in_text {
                        LinkTier::Document
                    } else {
                        LinkTier::Window
                    };
                    extended.insert(r.start, source, tier);
                }
            }
            let mut s = sanitize_linked(text, &decisions, &extended, ctx)?;
            s.protected = crate::protect::out_ranges(protected, &s.replacements);
            (s, decisions, extended.tiers())
        };
        let verdict = if sanitized.blocked.is_empty() {
            let leak = crate::verify::second_pass::store_leak_index(&mut *ctx);
            self.verifier
                .verify_with_at(&sanitized, &*ctx, leak.as_ref(), origin)
        } else {
            Verdict::Fail(
                sanitized
                    .blocked
                    .iter()
                    .map(|s| Reason {
                        kind: s.kind.clone(),
                        check: CheckId::Policy,
                    })
                    .collect(),
            )
        };
        tracing::debug!(
            profile = %profile.name,
            replacements = sanitized.replacements.len(),
            blocked = sanitized.blocked.len(),
            escalated = sanitized.escalated.len(),
            consistency = matches.len(),
            verdict = ?std::mem::discriminant(&verdict),
            "pipeline pass"
        );
        Ok(Pass {
            sanitized,
            verdict,
            decisions,
            consistency: matches.len(),
            links: link_tiers,
            detector_error: false,
            band_tokenized,
        })
    }

    /// The retry profile, when one is configured and differs from the primary.
    pub fn retry_profile(&self) -> Option<&Profile> {
        self.retry_profile.as_ref()
    }

    /// A detector could not examine the text: block (spec §14).
    fn detector_blocked(e: &Error) -> Outcome {
        tracing::warn!(error = %e, "detector failed; blocking");
        let kind = EntityKind::custom("DETECTOR");
        Outcome::Blocked {
            reasons: vec![Reason {
                kind: kind.clone(),
                check: CheckId::DetectorError,
            }],
            kinds: vec![kind],
        }
    }

    fn settle(
        &self,
        sanitized: Sanitized,
        verdict: Verdict,
        profile: &Profile,
    ) -> std::result::Result<Outcome, Vec<Reason>> {
        let mut reasons: Vec<Reason> = sanitized
            .escalated
            .iter()
            .map(|s| Reason {
                kind: s.kind.clone(),
                check: CheckId::Policy,
            })
            .collect();
        match verdict {
            // The verifier's reasons first, then the pass's escalations: a
            // failed leaf that also held an uncertain span reports both.
            Verdict::Fail(mut r) => {
                r.extend(reasons);
                Err(r)
            }
            Verdict::Uncertain(r) => {
                reasons.extend(r);
                // L70: a verifier `Uncertain` names no span that could be
                // tokenized, so `tokenize` refuses as `block` does.
                match profile.verifier.on_uncertain {
                    OnUncertain::Block | OnUncertain::Tokenize => Err(reasons),
                    OnUncertain::Escalate | OnUncertain::Pass => {
                        Ok(Outcome::PassUncertain { sanitized, reasons })
                    }
                }
            }
            Verdict::Pass => {
                if reasons.is_empty() {
                    return Ok(Outcome::Pass { sanitized });
                }
                // Under `tokenize` an escalation left here is one the
                // multi-line guard put back (L70) or a band span of a
                // `block` kind (L3-13): it refuses as under `block`, never
                // forwarded in clear.
                match profile.verifier.on_uncertain {
                    OnUncertain::Block | OnUncertain::Tokenize => Err(reasons),
                    OnUncertain::Escalate | OnUncertain::Pass => {
                        Ok(Outcome::PassUncertain { sanitized, reasons })
                    }
                }
            }
        }
    }

    /// Detect once, then sanitize and verify; on `Fail`, retry policy,
    /// sanitize, and verify with the retry profile over the same spans
    /// (spec §9.1: the retry profile shares the detector stack, so the raw
    /// spans are identical and detection is not repeated); block otherwise.
    ///
    /// The input is NFC-normalized first (see [`normalize_input`]): the
    /// sanitized text, replacement spans, and stored originals all refer to
    /// the NFC form, so NFD input cannot slip past NFC dictionaries or leak
    /// patterns.
    ///
    /// Tokens already in the text that resolve in the store are protected
    /// (M8 spec decision 11, see [`crate::protect`]): they pass through
    /// byte-identical, detections overlapping them are clipped, and the
    /// verifier treats them like minted tokens. Finding them calls
    /// `ctx.prepare` once; its error is returned like any store error.
    ///
    /// A detector error blocks immediately with [`CheckId::DetectorError`];
    /// there is no retry, since the retry would run the same detectors.
    ///
    /// Returns `Err` only when the token store fails; then nothing was
    /// produced and nothing may be cached.
    ///
    /// [`Engine::process_with`] without redactions.
    pub fn process(
        &self,
        text: &str,
        ctx: &mut dyn TokenStore,
    ) -> std::result::Result<Outcome, StoreError> {
        self.process_with(text, ctx, &[])
    }

    /// Detect once, fold in the caller's redactions (each one strengthens
    /// the decisions it overlaps and never weakens them; see
    /// `merge_redaction`), then sanitize and verify; on `Fail`, retry with
    /// the retry profile over the same spans; block otherwise. See
    /// [`Engine::process_detailed`].
    pub fn process_with(
        &self,
        text: &str,
        ctx: &mut dyn TokenStore,
        redactions: &[Redaction],
    ) -> std::result::Result<Outcome, StoreError> {
        Ok(self.process_detailed(text, ctx, redactions)?.outcome)
    }

    /// [`Engine::process_with`], keeping the settling pass's decisions and
    /// candidate for inspection. Redaction offsets refer to the NFC form of
    /// `text`; validate them with `redact::validate_redactions` first.
    /// [`Engine::process_scoped`] with an empty batch scope.
    pub fn process_detailed(
        &self,
        text: &str,
        ctx: &mut dyn TokenStore,
        redactions: &[Redaction],
    ) -> std::result::Result<Detailed, StoreError> {
        self.process_scoped(text, ctx, redactions, &LinkScope::empty())
    }

    /// [`Engine::process_detailed`] with a batch scope: full names of
    /// earlier blocks of the same batch, which the name linker uses after
    /// the document's own names (plan 4a decision 3). The linker runs once,
    /// after overlap resolution and outside protected tokens; both passes
    /// share its links. Free text ([`TextOrigin::Free`]).
    pub fn process_scoped(
        &self,
        text: &str,
        ctx: &mut dyn TokenStore,
        redactions: &[Redaction],
        scope: &LinkScope,
    ) -> std::result::Result<Detailed, StoreError> {
        self.process_scoped_at(text, ctx, redactions, scope, TextOrigin::Free)
    }

    /// [`Engine::process_with`] for a text of known origin ([`TextOrigin`]).
    /// The proxy's call for a system-prompt leaf (ruling L3-14).
    pub fn process_with_at(
        &self,
        text: &str,
        ctx: &mut dyn TokenStore,
        redactions: &[Redaction],
        origin: TextOrigin,
    ) -> std::result::Result<Outcome, StoreError> {
        Ok(self
            .process_scoped_at(text, ctx, redactions, &LinkScope::empty(), origin)?
            .outcome)
    }

    /// [`Engine::process_scoped`] for a text of known origin ([`TextOrigin`],
    /// ruling L3-14): the proxy passes [`TextOrigin::HarnessStatic`] for a
    /// system-prompt leaf.
    pub fn process_scoped_at(
        &self,
        text: &str,
        ctx: &mut dyn TokenStore,
        redactions: &[Redaction],
        scope: &LinkScope,
        origin: TextOrigin,
    ) -> std::result::Result<Detailed, StoreError> {
        let owned = nfc_zeroizing(text);
        let text = owned.as_deref().map_or(text, String::as_str);
        // M8 spec decision 11: tokens already in the text that resolve in
        // the store are protected. Detection sees them masked (same length,
        // offsets hold); raw spans overlapping them are clipped before
        // overlap resolution, never dropped (see `detect_nfc`).
        let protected = crate::protect::find(text, ctx)?;
        let detected = {
            // A plaintext copy: wiped as soon as detection is done.
            let masked: Option<Zeroizing<String>> =
                crate::protect::mask(text, &protected, ctx.settings()).map(Zeroizing::new);
            self.detect_nfc(
                masked.as_deref().map_or(text, String::as_str),
                &protected,
                origin,
            )
        };
        let spans = match detected {
            Ok(s) => s,
            Err(e) => {
                return Ok(Detailed {
                    outcome: Self::detector_blocked(&e),
                    decisions: Vec::new(),
                    candidate: None,
                    retried: false,
                    profile: self.profile.name.clone(),
                    links: LinkTiers::default(),
                    consistency: 0,
                    band_tokenized: 0,
                });
            }
        };
        // The linker reads the real text (not the masked scan): protected
        // ranges keep it out of tokens that are already minted.
        let (spans, links) = if self.linking.enabled {
            link::link_mentions(text, spans, scope, Some(&*ctx), &self.linking, &protected)
        } else {
            (spans, Links::empty())
        };
        // Redactions are folded into decisions per pass, in `run_pass`, not
        // into the raw spans here: merging them into `spans` and resolving
        // overlaps by source priority would let a redaction evict a
        // detected span outright (kind and all), including the part of it
        // the redaction doesn't cover, instead of only strengthening its
        // decision (see `merge_redaction`).
        let retry_spans = self.retry_profile.as_ref().map(|_| spans.clone());
        // One consistency dictionary per call (ruling L58), dropped on return.
        let mut dict: Option<StoreDictSlot> = None;
        let first = self.run_pass(
            text,
            &self.profile,
            spans,
            &links,
            ctx,
            redactions,
            &protected,
            false,
            &mut dict,
            origin,
        )?;
        if first.detector_error {
            // The consistency step could not examine the text: block, no
            // retry (the retry would build the same dictionary), as for a
            // detector error.
            return Ok(Detailed {
                outcome: consistency_blocked(first.verdict),
                decisions: Vec::new(),
                candidate: None,
                retried: false,
                profile: self.profile.name.clone(),
                links: first.links,
                consistency: 0,
                band_tokenized: 0,
            });
        }
        let Pass {
            sanitized: s,
            verdict: v,
            decisions,
            consistency,
            links: first_tiers,
            band_tokenized,
            ..
        } = first;
        let first = match self.settle(s.clone(), v, &self.profile) {
            Ok(o) => {
                return Ok(Detailed {
                    outcome: o,
                    decisions,
                    candidate: Some(s),
                    retried: false,
                    profile: self.profile.name.clone(),
                    links: first_tiers,
                    consistency,
                    band_tokenized,
                });
            }
            Err(reasons) => reasons,
        };
        if let (Some(rp), Some(spans)) = (&self.retry_profile, retry_spans) {
            let retry = self.run_pass(
                text, rp, spans, &links, ctx, redactions, &protected, true, &mut dict, origin,
            )?;
            // The retry's outcome rests on the first pass failing too, so
            // its cross-request links count (plan 4a decision 7).
            let tiers = LinkTiers {
                document: first_tiers.document.max(retry.links.document),
                batch: first_tiers.batch.max(retry.links.batch),
                window: first_tiers.window.max(retry.links.window),
            };
            if retry.detector_error {
                return Ok(Detailed {
                    outcome: consistency_blocked(retry.verdict),
                    decisions: Vec::new(),
                    candidate: None,
                    retried: true,
                    profile: rp.name.clone(),
                    links: tiers,
                    consistency: 0,
                    band_tokenized: 0,
                });
            }
            let outcome = match self.settle(retry.sanitized.clone(), retry.verdict, rp) {
                Ok(o) => o,
                Err(reasons) => {
                    let kinds = dedup_kinds(&reasons);
                    Outcome::Blocked { reasons, kinds }
                }
            };
            return Ok(Detailed {
                outcome,
                decisions: retry.decisions,
                candidate: Some(retry.sanitized),
                retried: true,
                profile: rp.name.clone(),
                links: tiers,
                consistency: retry.consistency,
                band_tokenized: retry.band_tokenized,
            });
        }
        let kinds = dedup_kinds(&first);
        Ok(Detailed {
            outcome: Outcome::Blocked {
                reasons: first,
                kinds,
            },
            decisions,
            candidate: Some(s),
            retried: false,
            profile: self.profile.name.clone(),
            links: first_tiers,
            consistency,
            band_tokenized,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CoreConfig;
    use crate::policy::{Action, EntityPolicy};
    use crate::redact::{Redaction, RedactionAction};
    use crate::token::StoreError;
    use crate::token::{Context, ContextId};
    use std::time::Duration;

    const CFG: &str = r#"
        [[domain.patterns]]
        regex = "K-[0-9]{6}"
        kind = "CUSTOMER_ID"

        [profiles.fast]
        default_action = "tokenize"
        default_min_confidence = 0.5
        escalate_below = 0.5
        [profiles.fast.entities.CITY]
        action = "preserve"
        min_confidence = 0.0
        [profiles.fast.entities.DATE]
        action = "preserve"
        min_confidence = 0.0
        [profiles.fast.entities.POSTAL_CODE]
        action = "preserve"
        min_confidence = 0.0
        [profiles.fast.entities.SECRET]
        action = "remove"
        min_confidence = 0.0
        [profiles.fast.verifier]
        on_uncertain = "block"
        retry_profile = "strict"
        allow_no_ner = true

        [profiles.strict]
        extends = "fast"
        [profiles.strict.entities.DATE]
        action = "tokenize"
        min_confidence = 0.0
        [profiles.strict.entities.POSTAL_CODE]
        action = "tokenize"
        min_confidence = 0.0
    "#;

    fn engine() -> Engine {
        let cfg = CoreConfig::from_toml(CFG).unwrap();
        Engine::from_config(&cfg, "fast", None, None).unwrap()
    }
    fn ctx() -> Context {
        Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            TokenSettings::default(),
        )
    }

    #[test]
    fn empty_and_whitespace_pass_with_no_replacements() {
        let e = engine();
        for t in ["", "   \n\t"] {
            match e.process(t, &mut ctx()).unwrap() {
                Outcome::Pass { sanitized } => {
                    assert_eq!(sanitized.text, t);
                    assert!(sanitized.replacements.is_empty());
                }
                o => panic!("{o:?}"),
            }
        }
    }

    #[test]
    fn end_to_end_tokenizes_structured_ids_and_removes_secrets() {
        let e = engine();
        let mut c = ctx();
        let text = "Kunde K-928174, IBAN AT61 1904 3002 3457 3201, key AKIAIOSFODNN7EXAMPLE, Termin 24.09.2026.";
        let Outcome::Pass { sanitized } = e.process(text, &mut c).unwrap() else {
            panic!("expected pass")
        };
        assert!(sanitized.text.contains("<CUSTOMER_ID_"));
        assert!(sanitized.text.contains("<IBAN_"));
        assert!(sanitized.text.contains("<SECRET_REMOVED>"));
        assert!(
            sanitized.text.contains("24.09.2026"),
            "date preserved by policy"
        );
        assert!(!sanitized.text.contains("AT61"));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn same_context_reuses_tokens_across_calls() {
        let e = engine();
        let mut c = ctx();
        let a = match e.process("IBAN AT61 1904 3002 3457 3201", &mut c).unwrap() {
            Outcome::Pass { sanitized } => sanitized.text,
            o => panic!("{o:?}"),
        };
        let b = match e
            .process("nochmal AT61 1904 3002 3457 3201", &mut c)
            .unwrap()
        {
            Outcome::Pass { sanitized } => sanitized.text,
            o => panic!("{o:?}"),
        };
        let ta = a.split_whitespace().last().unwrap();
        assert!(b.ends_with(ta));
    }

    /// The shared test engine with a verifier that fails every pass, so the
    /// `strict` retry always runs.
    fn always_retrying_engine() -> Engine {
        struct FailEveryPass;
        impl Verifier for FailEveryPass {
            fn verify(&self, _: &Sanitized, _: &dyn TokenStore) -> Verdict {
                Verdict::Fail(vec![Reason {
                    kind: EntityKind::Person,
                    check: CheckId::Ner,
                }])
            }
        }
        let mut e = engine();
        e.verifier = Arc::new(FailEveryPass);
        e
    }

    /// Builds of the consistency dictionary during `f`.
    fn builds_during(f: impl FnOnce()) -> usize {
        let before = crate::consistency::builds_on_this_thread();
        f();
        crate::consistency::builds_on_this_thread() - before
    }

    /// Task 7d (C, ruling L58): the primary pass and the retry share one
    /// consistency dictionary when the retry mints nothing new.
    #[test]
    fn the_retry_reuses_the_primary_store_dict_when_the_store_is_unchanged() {
        let e = always_retrying_engine();
        let mut c = ctx();
        let n = builds_during(|| {
            let d = e
                .process_detailed("IBAN AT61 1904 3002 3457 3201 bitte.", &mut c, &[])
                .unwrap();
            assert!(d.retried);
        });
        assert_eq!(n, 1);
    }

    /// Task 7d (C, ruling L58): a value the retry mints (the date `strict`
    /// tokenizes and `fast` preserves) changes the store between the
    /// passes, so the retry builds its own dictionary.
    #[test]
    fn a_mint_between_the_passes_rebuilds_the_store_dict() {
        let e = always_retrying_engine();
        let mut c = ctx();
        let n = builds_during(|| {
            let d = e
                .process_detailed("IBAN AT61 1904 3002 3457 3201 am 01.02.2020.", &mut c, &[])
                .unwrap();
            assert!(d.retried);
        });
        assert_eq!(n, 2);
    }

    /// Task 7e (ruling L62): the dictionary lives on the store, not in the
    /// engine: a second call on an unchanged store builds nothing, and a
    /// value minted between calls is found by the next call's consistency
    /// pass (no detector here finds it).
    #[test]
    fn the_store_dict_lives_with_the_store() {
        let e = engine();
        let mut c = ctx();
        let text = "IBAN AT61 1904 3002 3457 3201, Kunde K-928174.";
        assert_eq!(builds_during(|| drop(e.process(text, &mut c).unwrap())), 1);
        assert_eq!(builds_during(|| drop(e.process(text, &mut c).unwrap())), 0);
        c.token_for(&EntityKind::Person, "Zyxwuria Quolnath")
            .unwrap();
        let d = e
            .process_detailed("Gruss an Zyxwuria Quolnath.", &mut c, &[])
            .unwrap();
        assert!(d.consistency >= 1, "{}", d.consistency);
        let Outcome::Pass { sanitized } = d.outcome else {
            panic!("expected pass")
        };
        assert!(!sanitized.text.contains("Zyxwuria"));
        c.record_removed(&EntityKind::custom("SECRET"), "hunter2pw");
        let d = e
            .process_detailed("das Passwort hunter2pw ist alt", &mut c, &[])
            .unwrap();
        assert!(d.consistency >= 1, "{}", d.consistency);
    }

    #[test]
    fn uncertain_combination_blocks_then_retry_profile_passes() {
        // Three preserved quasi-identifier kinds (PROFESSION, DATE, POSTAL_CODE) in one sentence under
        // `fast` → Uncertain → on_uncertain=block → retry with `strict`, which tokenizes dates and postal
        // codes → only PROFESSION remains preserved → Pass.
        let mut cfg = CoreConfig::from_toml(CFG).unwrap();
        cfg.domain
            .patterns
            .push(crate::detect::domain::DomainPattern {
                regex: "Elektriker".into(),
                kind: "PROFESSION".into(),
                confidence: 0.95,
            });
        cfg.profiles.get_mut("fast").unwrap().entities.insert(
            "PROFESSION".into(),
            EntityPolicy {
                action: Action::Preserve,
                min_confidence: 0.0,
            },
        );
        let e = Engine::from_config(&cfg, "fast", None, None).unwrap();
        let text = "Elektriker seit 01.02.2020 in 1010 Wien.";
        match e.process(text, &mut ctx()).unwrap() {
            Outcome::Pass { sanitized } => {
                assert!(
                    sanitized.text.contains("<DATE_"),
                    "retry profile tokenized the date: {}",
                    sanitized.text
                );
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn block_action_blocks_without_sending() {
        let mut cfg = CoreConfig::from_toml(CFG).unwrap();
        cfg.profiles.get_mut("fast").unwrap().entities.insert(
            "IBAN".into(),
            EntityPolicy {
                action: Action::Block,
                min_confidence: 0.0,
            },
        );
        let e = Engine::from_config(&cfg, "fast", None, None).unwrap();
        match e.process("AT61 1904 3002 3457 3201", &mut ctx()).unwrap() {
            Outcome::Blocked { kinds, .. } => assert_eq!(kinds, vec![EntityKind::Iban]),
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn missing_retry_profile_is_config_error() {
        let mut cfg = CoreConfig::from_toml(CFG).unwrap();
        cfg.profiles
            .get_mut("fast")
            .unwrap()
            .verifier
            .as_mut()
            .unwrap()
            .retry_profile = Some("nope".into());
        assert!(Engine::from_config(&cfg, "fast", None, None).is_err());
    }

    struct FailingNer;
    impl Detector for FailingNer {
        fn id(&self) -> crate::span::DetectorId {
            crate::span::DetectorId::Ner
        }
        fn detect(&self, _: &str, _: &DetectCtx) -> Result<Vec<Span>> {
            Err(crate::Error::ModelUnavailable("test backend".into()))
        }
    }

    /// Returns a span past the end of any short text.
    struct BadOffsets;
    impl Detector for BadOffsets {
        fn id(&self) -> crate::span::DetectorId {
            crate::span::DetectorId::Ner
        }
        fn detect(&self, _: &str, _: &DetectCtx) -> Result<Vec<Span>> {
            Ok(vec![Span::new(
                0,
                1000,
                EntityKind::Person,
                0.9,
                crate::span::DetectorId::Ner,
            )])
        }
    }

    /// Finds "Gruber" as a person.
    struct GruberNer;
    impl Detector for GruberNer {
        fn id(&self) -> crate::span::DetectorId {
            crate::span::DetectorId::Ner
        }
        fn detect(&self, text: &str, _: &DetectCtx) -> Result<Vec<Span>> {
            Ok(text
                .find("Gruber")
                .map(|i| {
                    vec![Span::new(
                        i,
                        i + 6,
                        EntityKind::Person,
                        0.9,
                        crate::span::DetectorId::Ner,
                    )]
                })
                .unwrap_or_default())
        }
    }

    /// Finds nothing.
    struct SilentNer;
    impl Detector for SilentNer {
        fn id(&self) -> crate::span::DetectorId {
            crate::span::DetectorId::Ner
        }
        fn detect(&self, _: &str, _: &DetectCtx) -> Result<Vec<Span>> {
            Ok(Vec::new())
        }
    }

    fn detector_error_block(o: Outcome) {
        match o {
            Outcome::Blocked { reasons, kinds } => {
                assert!(
                    reasons.iter().all(|r| r.check == CheckId::DetectorError),
                    "{reasons:?}"
                );
                assert_eq!(kinds, vec![EntityKind::custom("DETECTOR")]);
            }
            o => panic!("expected Blocked, got {o:?}"),
        }
    }

    /// I5: a failing sanitizer backend must block, never pass undetected text.
    #[test]
    fn failing_sanitizer_detector_blocks() {
        let cfg = CoreConfig::from_toml(CFG).unwrap();
        let e = Engine::from_config(&cfg, "fast", Some(Arc::new(FailingNer)), None).unwrap();
        detector_error_block(
            e.process("Herr Gruber, IBAN AT61 1904 3002 3457 3201", &mut ctx())
                .unwrap(),
        );
        assert!(e.detect("Herr Gruber").is_err());
    }

    /// I5: spans outside the text or off a char boundary are a detector error.
    #[test]
    fn detector_span_with_bad_offsets_blocks() {
        let cfg = CoreConfig::from_toml(CFG).unwrap();
        let e = Engine::from_config(&cfg, "fast", Some(Arc::new(BadOffsets)), None).unwrap();
        detector_error_block(e.process("kurz", &mut ctx()).unwrap());
        assert!(matches!(
            e.detect("kurz"),
            Err(crate::Error::InvalidUtf8Boundary)
        ));
    }

    /// I4: the verifier runs its own NER, not the sanitizer's.
    #[test]
    fn verifier_uses_its_own_ner_detector() {
        // Anchors off: the honorific anchor would find `Gruber` itself.
        let cfg = CoreConfig::from_toml(&format!("[linking]\nanchors = false\n{CFG}")).unwrap();
        let e = Engine::from_config(
            &cfg,
            "fast",
            Some(Arc::new(SilentNer)),
            Some(Arc::new(GruberNer)),
        )
        .unwrap();
        match e.process("Herr Gruber kam.", &mut ctx()).unwrap() {
            Outcome::Blocked { reasons, .. } => {
                assert!(
                    reasons.iter().any(|r| r.check == CheckId::Ner),
                    "{reasons:?}"
                )
            }
            o => panic!("expected Blocked, got {o:?}"),
        }
        // the sanitizer's NER is the one used for detection
        let spans = e.detect("Herr Gruber kam.").unwrap();
        assert!(spans.is_empty(), "{spans:?}");
    }

    /// I4: one detector instance cannot serve as both sanitizer and verifier NER.
    #[test]
    fn same_ner_instance_for_sanitizer_and_verifier_is_rejected() {
        let cfg = CoreConfig::from_toml(CFG).unwrap();
        let ner: Arc<dyn Detector> = Arc::new(GruberNer);
        let err = Engine::from_config(&cfg, "fast", Some(Arc::clone(&ner)), Some(ner))
            .expect_err("must be rejected");
        assert!(matches!(err, crate::Error::ConfigInvalid(_)));
    }

    /// M6: without a retry profile, a Fail blocks with the first reasons.
    #[test]
    fn fail_without_retry_profile_blocks_with_first_reasons() {
        struct AlwaysFail;
        impl Verifier for AlwaysFail {
            fn verify(&self, _: &Sanitized, _: &dyn TokenStore) -> Verdict {
                Verdict::Fail(vec![
                    Reason {
                        kind: EntityKind::Person,
                        check: CheckId::Leak,
                    },
                    Reason {
                        kind: EntityKind::Person,
                        check: CheckId::Ner,
                    },
                ])
            }
        }
        let cfg = CoreConfig::from_toml(CFG).unwrap();
        let profile = cfg.resolve_profile("fast").unwrap();
        let e = Engine::new(profile, None, vec![], Arc::new(AlwaysFail));
        match e.process("Hallo", &mut ctx()).unwrap() {
            Outcome::Blocked { reasons, kinds } => {
                assert_eq!(
                    reasons.iter().map(|r| r.check).collect::<Vec<_>>(),
                    vec![CheckId::Leak, CheckId::Ner]
                );
                assert_eq!(kinds, vec![EntityKind::Person]);
            }
            o => panic!("expected Blocked, got {o:?}"),
        }
    }

    /// A failed verdict carries the pass's escalations after the
    /// verifier's reasons (the escalation used to be dropped).
    #[test]
    fn fail_reports_escalations() {
        struct LeakFail;
        impl Verifier for LeakFail {
            fn verify(&self, _: &Sanitized, _: &dyn TokenStore) -> Verdict {
                Verdict::Fail(vec![Reason {
                    kind: EntityKind::Organization,
                    check: CheckId::Leak,
                }])
            }
        }
        struct Uncertain;
        impl Detector for Uncertain {
            fn id(&self) -> crate::span::DetectorId {
                crate::span::DetectorId::Ner
            }
            fn detect(&self, text: &str, _: &DetectCtx) -> Result<Vec<Span>> {
                Ok(text
                    .find("Quolnath")
                    .map(|i| {
                        vec![Span::new(
                            i,
                            i + 8,
                            EntityKind::Person,
                            0.55,
                            crate::span::DetectorId::Ner,
                        )]
                    })
                    .unwrap_or_default())
            }
        }
        let cfg = CoreConfig::from_toml(&format!(
            "{CFG}\n[profiles.fast.entities.PERSON]\naction = \"tokenize\"\nmin_confidence = 0.6\n"
        ))
        .unwrap();
        // escalate_below 0.5 and PERSON min_confidence 0.6: 0.55 escalates.
        let profile = cfg.resolve_profile("fast").unwrap();
        let e = Engine::new(profile, None, vec![Arc::new(Uncertain)], Arc::new(LeakFail));
        match e.process("Bitte Quolnath anrufen.", &mut ctx()).unwrap() {
            Outcome::Blocked { reasons, .. } => {
                assert_eq!(reasons[0].check, CheckId::Leak, "verifier reasons first");
                assert!(
                    reasons
                        .iter()
                        .any(|r| r.check == CheckId::Policy && r.kind == EntityKind::Person)
                );
            }
            o => panic!("expected Blocked, got {o:?}"),
        }
    }

    #[test]
    fn outcome_debug_has_no_text() {
        let e = engine();
        let o = e
            .process("IBAN AT61 1904 3002 3457 3201", &mut ctx())
            .unwrap();
        assert!(!format!("{o:?}").contains("AT61"));
    }

    #[test]
    fn custom_delimiters_flow_through_engine() {
        let toml = format!("[tokens]\nopen = \"{{{{\"\nclose = \"}}}}\"\n{CFG}");
        let cfg = CoreConfig::from_toml(&toml).unwrap();
        let e = Engine::from_config(&cfg, "fast", None, None).unwrap();
        let mut c = Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            e.token_settings().clone(),
        );
        let Outcome::Pass { sanitized } =
            e.process("IBAN AT61 1904 3002 3457 3201", &mut c).unwrap()
        else {
            panic!()
        };
        assert!(sanitized.text.contains("{{IBAN_"));
        let (back, _) =
            crate::rehydrate::Rehydrator::new(e.token_settings()).rehydrate(&sanitized.text, &c);
        assert_eq!(back, "IBAN AT61 1904 3002 3457 3201");
    }

    #[test]
    fn profile_naming_ner_requires_the_detector() {
        let toml = "[ner.gliner]\nmodel = \"m\"\nthreshold = 0.5\nlabels = [ { label = \"person\", kind = \"PERSON\" } ]\n\
                    [ner.token_classifier]\nmodel = \"t\"\nthreshold = 0.5\nlabels = [ { label = \"PER\", kind = \"PERSON\" } ]\n\
                    [profiles.p]\nner_sanitizer = \"gliner\"\nner_verifier = \"token_classifier\"\n\
                    [profiles.p.entities.SECRET]\naction = \"remove\"\nmin_confidence = 0.0\n";
        let cfg = CoreConfig::from_toml(toml).unwrap();
        let err = Engine::from_config(&cfg, "p", None, None).expect_err("must be rejected");
        assert!(
            matches!(err, Error::ModelUnavailable(ref w) if w == "ner_sanitizer"),
            "{err}"
        );
        // A sanitizer alone is not enough either.
        let ner: Arc<dyn Detector> = Arc::new(RegexDetector::new());
        let err = Engine::from_config(&cfg, "p", Some(ner), None).expect_err("must be rejected");
        assert!(
            matches!(err, Error::ModelUnavailable(ref w) if w == "ner_verifier"),
            "{err}"
        );
    }

    /// I1: a retry profile naming different NER sections than the primary is
    /// rejected, since the detector stack and verifier are built once from
    /// the primary profile and never rebuilt for the retry.
    #[test]
    fn retry_profile_must_share_the_primary_ner() {
        // Three distinct NER sections so a retry profile can differ from the
        // primary on exactly one of ner_sanitizer/ner_verifier while staying
        // self-consistent (its own ner_sanitizer != ner_verifier).
        const NER: &str = "[ner.gliner]\nmodel = \"m\"\nthreshold = 0.5\nlabels = [ { label = \"person\", kind = \"PERSON\" } ]\n\
                    [ner.gliner_verifier]\nmodel = \"m\"\nthreshold = 0.3\nlabels = [ { label = \"person\", kind = \"PERSON\" } ]\n\
                    [ner.token_classifier]\nmodel = \"t\"\nthreshold = 0.5\nlabels = [ { label = \"PER\", kind = \"PERSON\" } ]\n";
        let toml = format!(
            "{NER}[profiles.primary]\nner_sanitizer = \"gliner\"\nner_verifier = \"token_classifier\"\n\
             [profiles.primary.entities.SECRET]\naction = \"remove\"\nmin_confidence = 0.0\n[profiles.primary.verifier]\nretry_profile = \"retry\"\nallow_no_ner = true\n\
             [profiles.retry]\nner_sanitizer = \"gliner_verifier\"\nner_verifier = \"token_classifier\"\n\
             [profiles.retry.entities.SECRET]\naction = \"remove\"\nmin_confidence = 0.0\n"
        );
        let cfg = CoreConfig::from_toml(&toml).unwrap();
        let gliner: Arc<dyn Detector> = Arc::new(RegexDetector::new());
        let tc: Arc<dyn Detector> = Arc::new(RegexDetector::new());
        let err = Engine::from_config(&cfg, "primary", Some(gliner), Some(tc))
            .expect_err("must be rejected: retry's ner_sanitizer differs from primary's");
        assert!(
            matches!(err, Error::ConfigInvalid(ref m) if m.contains("profiles.retry.ner_sanitizer")),
            "{err}"
        );

        // A retry that only differs on ner_verifier is rejected too.
        let toml = format!(
            "{NER}[profiles.primary]\nner_sanitizer = \"gliner\"\nner_verifier = \"token_classifier\"\n\
             [profiles.primary.entities.SECRET]\naction = \"remove\"\nmin_confidence = 0.0\n[profiles.primary.verifier]\nretry_profile = \"retry\"\nallow_no_ner = true\n\
             [profiles.retry]\nner_sanitizer = \"gliner\"\nner_verifier = \"gliner_verifier\"\n\
             [profiles.retry.entities.SECRET]\naction = \"remove\"\nmin_confidence = 0.0\n"
        );
        let cfg = CoreConfig::from_toml(&toml).unwrap();
        let gliner: Arc<dyn Detector> = Arc::new(RegexDetector::new());
        let tc: Arc<dyn Detector> = Arc::new(RegexDetector::new());
        let err = Engine::from_config(&cfg, "primary", Some(gliner), Some(tc))
            .expect_err("must be rejected: retry's ner_verifier differs from primary's");
        assert!(
            matches!(err, Error::ConfigInvalid(ref m) if m.contains("profiles.retry.ner_verifier")),
            "{err}"
        );

        // A retry that shares both NER sections with the primary is accepted.
        let toml = "[ner.gliner]\nmodel = \"m\"\nthreshold = 0.5\nlabels = [ { label = \"person\", kind = \"PERSON\" } ]\n\
                    [ner.token_classifier]\nmodel = \"t\"\nthreshold = 0.5\nlabels = [ { label = \"PER\", kind = \"PERSON\" } ]\n\
                    [profiles.primary]\nner_sanitizer = \"gliner\"\nner_verifier = \"token_classifier\"\n\
                    [profiles.primary.entities.SECRET]\naction = \"remove\"\nmin_confidence = 0.0\n[profiles.primary.verifier]\nretry_profile = \"retry\"\nallow_no_ner = true\n\
                    [profiles.retry]\nextends = \"primary\"\ndefault_min_confidence = 0.4\n";
        let cfg = CoreConfig::from_toml(toml).unwrap();
        let gliner: Arc<dyn Detector> = Arc::new(RegexDetector::new());
        let tc: Arc<dyn Detector> = Arc::new(RegexDetector::new());
        Engine::from_config(&cfg, "primary", Some(gliner), Some(tc))
            .expect("retry sharing both NER sections with the primary is accepted");
    }

    /// Review I4: a profile that extends a shipped profile and adds its own
    /// `action = "block"` inherits the parent's `retry_profile`, which does
    /// not carry the override. Without a check, the first pass's
    /// `Verdict::Fail(Policy)` would retry into a profile that tokenizes
    /// the blocked kind instead, and the block would never surface.
    #[test]
    fn retry_profile_must_keep_every_block_of_the_primary() {
        const BASE: &str = "[profiles.base]\ndefault_action = \"tokenize\"\ndefault_min_confidence = 0.5\nescalate_below = 0.5\n\
                            [profiles.base.entities.SECRET]\naction = \"remove\"\nmin_confidence = 0.0\n";

        // The retry does not carry the primary's IBAN block: rejected,
        // naming the entity's key path in the retry profile.
        let toml = format!(
            "{BASE}[profiles.primary]\nextends = \"base\"\n\
             [profiles.primary.entities.IBAN]\naction = \"block\"\nmin_confidence = 0.5\n\
             [profiles.primary.verifier]\nretry_profile = \"retry\"\nallow_no_ner = true\n\
             [profiles.retry]\nextends = \"base\"\n"
        );
        let cfg = CoreConfig::from_toml(&toml).unwrap();
        let err = Engine::from_config(&cfg, "primary", None, None)
            .expect_err("the retry profile drops the IBAN block");
        assert!(
            matches!(err, Error::ConfigInvalid(ref m) if m.contains("profiles.retry.entities.IBAN.action")),
            "{err}"
        );

        // The retry keeps the same block explicitly: accepted.
        let toml = format!(
            "{BASE}[profiles.primary]\nextends = \"base\"\n\
             [profiles.primary.entities.IBAN]\naction = \"block\"\nmin_confidence = 0.5\n\
             [profiles.primary.verifier]\nretry_profile = \"retry\"\nallow_no_ner = true\n\
             [profiles.retry]\nextends = \"base\"\n\
             [profiles.retry.entities.IBAN]\naction = \"block\"\nmin_confidence = 0.5\n"
        );
        let cfg = CoreConfig::from_toml(&toml).unwrap();
        Engine::from_config(&cfg, "primary", None, None)
            .expect("the retry profile keeps the block explicitly");

        // The primary blocks by `default_action`; the retry must inherit a
        // `Block` default too, not just avoid overriding one kind.
        let toml = "[profiles.primary]\ndefault_action = \"block\"\ndefault_min_confidence = 0.5\nescalate_below = 0.5\n\
                     [profiles.primary.verifier]\nretry_profile = \"retry\"\nallow_no_ner = true\n\
                     [profiles.retry]\ndefault_action = \"tokenize\"\ndefault_min_confidence = 0.5\nescalate_below = 0.5\n\
                     [profiles.retry.entities.SECRET]\naction = \"remove\"\nmin_confidence = 0.0\n";
        let cfg = CoreConfig::from_toml(toml).unwrap();
        let err = Engine::from_config(&cfg, "primary", None, None)
            .expect_err("the retry profile's default action does not block");
        assert!(
            matches!(err, Error::ConfigInvalid(ref m) if m.contains("profiles.retry.default_action")),
            "{err}"
        );
    }

    /// §9.1: a failed first pass no longer re-runs the detectors; the retry
    /// reuses the first pass's spans.
    #[test]
    fn retry_runs_detectors_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Counting(AtomicUsize);
        impl Detector for Counting {
            fn id(&self) -> crate::span::DetectorId {
                crate::span::DetectorId::Ner
            }
            fn detect(&self, _: &str, _: &DetectCtx) -> Result<Vec<Span>> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(Vec::new())
            }
        }
        let mut cfg = CoreConfig::from_toml(CFG).unwrap();
        cfg.domain
            .patterns
            .push(crate::detect::domain::DomainPattern {
                regex: "Elektriker".into(),
                kind: "PROFESSION".into(),
                confidence: 0.95,
            });
        cfg.profiles.get_mut("fast").unwrap().entities.insert(
            "PROFESSION".into(),
            EntityPolicy {
                action: Action::Preserve,
                min_confidence: 0.0,
            },
        );
        let counter = Arc::new(Counting(AtomicUsize::new(0)));
        let ner: Arc<dyn Detector> = Arc::clone(&counter) as Arc<dyn Detector>;
        let e = Engine::from_config(&cfg, "fast", Some(ner), None).unwrap();
        // Uncertain under `fast` → block → retry with `strict` → Pass.
        match e
            .process("Elektriker seit 01.02.2020 in 1010 Wien.", &mut ctx())
            .unwrap()
        {
            Outcome::Pass { sanitized } => {
                assert!(sanitized.text.contains("<DATE_"), "{}", sanitized.text)
            }
            o => panic!("{o:?}"),
        }
        assert_eq!(
            counter.0.load(Ordering::SeqCst),
            1,
            "detectors must run once"
        );
        assert_eq!(e.retry_profile().map(|p| p.name.as_str()), Some("strict"));
    }

    /// I1: every shipped profile, including its retry profile, builds an
    /// `Engine` without a `ConfigInvalid`. Stand-in NER detectors are named
    /// after their section so the test also documents which section each
    /// profile expects.
    #[test]
    fn shipped_profiles_build_engines_with_stand_in_ner() {
        struct StandIn;
        impl Detector for StandIn {
            fn id(&self) -> crate::span::DetectorId {
                crate::span::DetectorId::Ner
            }
            fn detect(&self, _: &str, _: &DetectCtx) -> Result<Vec<Span>> {
                Ok(Vec::new())
            }
        }
        let cfg = CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap();
        for name in [
            "offline",
            "offline-strict",
            "fast",
            "fast-strict",
            "support-email",
            "strict",
            "thorough",
            "thorough-strict",
        ] {
            let profile = cfg.resolve_profile(name).unwrap();
            let sanitizer: Option<Arc<dyn Detector>> = profile
                .ner_sanitizer
                .as_ref()
                .map(|_| Arc::new(StandIn) as _);
            let verifier: Option<Arc<dyn Detector>> = profile
                .ner_verifier
                .as_ref()
                .map(|_| Arc::new(StandIn) as _);
            Engine::from_config(&cfg, name, sanitizer, verifier)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    /// Ruling S10: under `offline` (URLs preserved) a URL is cut around the
    /// path name inside it; the name is tokenized, the rest of the URL stays.
    #[test]
    fn a_url_is_cut_around_a_path_name() {
        let cfg = CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap();
        let e = Engine::from_config(&cfg, "offline", None, None).unwrap();
        let text = "Infos: https://example.com/team/gruber ok";
        let Outcome::Pass { sanitized } = e.process(text, &mut ctx()).unwrap() else {
            panic!("not a pass");
        };
        assert!(
            sanitized
                .text
                .starts_with("Infos: https://example.com/team/<PERSON_"),
            "{}",
            sanitized.text
        );
        assert!(!sanitized.text.contains("gruber"));
    }

    /// Review Focus 2: under the shipped config an uncertain PERSON (0.55)
    /// ends tokenized through the strict retry — not forwarded, not refused.
    #[test]
    fn shipped_support_email_tokenizes_an_uncertain_name_through_the_retry() {
        struct Conf(&'static str, f32);
        impl Detector for Conf {
            fn id(&self) -> crate::span::DetectorId {
                crate::span::DetectorId::Ner
            }
            fn detect(&self, text: &str, _: &DetectCtx) -> Result<Vec<Span>> {
                Ok(text
                    .match_indices(self.0)
                    .map(|(i, m)| {
                        Span::new(
                            i,
                            i + m.len(),
                            EntityKind::Person,
                            self.1,
                            crate::span::DetectorId::Ner,
                        )
                    })
                    .collect())
            }
        }
        struct Nothing;
        impl Detector for Nothing {
            fn id(&self) -> crate::span::DetectorId {
                crate::span::DetectorId::Ner
            }
            fn detect(&self, _: &str, _: &DetectCtx) -> Result<Vec<Span>> {
                Ok(Vec::new())
            }
        }
        let cfg = CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap();
        let e = Engine::from_config(
            &cfg,
            "support-email",
            Some(Arc::new(Conf("Quolnath Brandl", 0.55))),
            Some(Arc::new(Nothing)),
        )
        .unwrap();
        let d = e
            .process_detailed(
                "Bitte rufen Sie Quolnath Brandl morgen an.",
                &mut ctx(),
                &[],
            )
            .unwrap();
        let Outcome::Pass { sanitized } = d.outcome else {
            panic!("expected pass, got {:?}", d.outcome)
        };
        assert!(d.retried, "the primary escalates and the retry settles it");
        assert!(
            !sanitized.text.contains("Quolnath") && !sanitized.text.contains("Brandl"),
            "{}",
            sanitized.text
        );
        assert!(
            sanitized.text.contains("<PERSON_"),
            "the name is tokenized, not dropped: {}",
            sanitized.text
        );
    }

    /// Every shipped retry profile has an empty PERSON / STREET_ADDRESS band.
    #[test]
    fn shipped_retry_profiles_have_no_person_or_street_escalation_band() {
        let cfg = CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap();
        for p in ["offline-strict", "fast-strict", "strict", "thorough-strict"] {
            let prof = cfg.resolve_profile(p).unwrap();
            for k in [EntityKind::Person, EntityKind::StreetAddress] {
                let policy = prof.policy_for(&k);
                assert_eq!(policy.action, Action::Tokenize, "{p} {}", k.label());
                assert!(
                    policy.min_confidence <= prof.escalate_below,
                    "{p} {}",
                    k.label()
                );
            }
        }
    }

    /// A stand-in sanitizer NER: every occurrence of each needle is a
    /// PERSON at the given confidence.
    struct PersonNer(Vec<(&'static str, f32)>);
    impl Detector for PersonNer {
        fn id(&self) -> crate::span::DetectorId {
            crate::span::DetectorId::Ner
        }
        fn detect(&self, text: &str, _: &DetectCtx) -> Result<Vec<Span>> {
            Ok(self
                .0
                .iter()
                .flat_map(|(needle, conf)| {
                    text.match_indices(needle).map(|(i, m)| {
                        Span::new(
                            i,
                            i + m.len(),
                            EntityKind::Person,
                            *conf,
                            crate::span::DetectorId::Ner,
                        )
                    })
                })
                .collect())
        }
    }

    /// A stand-in verifier NER that finds nothing.
    struct NoNer;
    impl Detector for NoNer {
        fn id(&self) -> crate::span::DetectorId {
            crate::span::DetectorId::Ner
        }
        fn detect(&self, _: &str, _: &DetectCtx) -> Result<Vec<Span>> {
            Ok(Vec::new())
        }
    }

    /// Rulings L98 and L3-14: the origin reaches the sanitizer's technical
    /// filter, and every entry point without an origin is `Free`.
    #[test]
    fn text_origin_reaches_the_technical_filter_and_defaults_to_free() {
        struct PassAll;
        impl Verifier for PassAll {
            fn verify(&self, _: &Sanitized, _: &dyn TokenStore) -> Verdict {
                Verdict::Pass
            }
        }
        let cfg = CoreConfig::from_toml(CFG).unwrap();
        let profile = cfg.resolve_profile("fast").unwrap();
        let e = Engine::new(
            profile,
            None,
            vec![Arc::new(PersonNer(vec![("rust", 0.6)]))],
            Arc::new(PassAll),
        );
        let persons = |spans: Vec<Span>| {
            spans
                .iter()
                .filter(|s| s.kind == EntityKind::Person)
                .count()
        };
        let text = "danke rust";
        assert_eq!(persons(e.detect(text).unwrap()), 1, "detect is Free");
        assert_eq!(persons(e.detect_at(text, TextOrigin::Free).unwrap()), 1);
        assert_eq!(
            persons(e.detect_at(text, TextOrigin::HarnessStatic).unwrap()),
            0
        );
        let d = e.process_detailed(text, &mut ctx(), &[]).unwrap();
        let Outcome::Pass { sanitized } = &d.outcome else {
            panic!("expected pass, got {:?}", d.outcome)
        };
        assert!(
            !sanitized.text.contains("rust"),
            "free text: tokenized, {}",
            sanitized.text
        );
        let d = e
            .process_scoped_at(
                text,
                &mut ctx(),
                &[],
                &LinkScope::empty(),
                TextOrigin::HarnessStatic,
            )
            .unwrap();
        let Outcome::Pass { sanitized } = &d.outcome else {
            panic!("expected pass, got {:?}", d.outcome)
        };
        assert_eq!(sanitized.text, text, "harness-static: dropped");
        let o = e
            .process_with_at(text, &mut ctx(), &[], TextOrigin::HarnessStatic)
            .unwrap();
        assert!(matches!(o, Outcome::Pass { sanitized } if sanitized.text == text));
    }

    /// Ruling L103 through the engine: the origin reaches the verifier, and
    /// the entry points without an origin are `Free`.
    #[test]
    fn text_origin_reaches_the_verifier_product_cue() {
        let cfg = CoreConfig::from_toml(CFG).unwrap();
        let profile = cfg.resolve_profile("fast").unwrap();
        let verifier = crate::verify::SecondPassVerifier::new(
            crate::detect::regex::RegexDetector::new(),
            Some(Arc::new(PersonNer(vec![("Claude", 0.99)]))),
            &profile.verifier,
        )
        .unwrap();
        let e = Engine::new(profile, None, vec![], Arc::new(verifier));
        let text = "You are Claude Code. Claude never guesses file contents.";
        assert!(matches!(
            e.process(text, &mut ctx()).unwrap(),
            Outcome::Blocked { .. }
        ));
        assert!(matches!(
            e.process_with_at(text, &mut ctx(), &[], TextOrigin::Free)
                .unwrap(),
            Outcome::Blocked { .. }
        ));
        assert!(matches!(
            e.process_with_at(text, &mut ctx(), &[], TextOrigin::HarnessStatic)
                .unwrap(),
            Outcome::Pass { .. }
        ));
    }

    /// Fix round 1 (security review of 6c): the retry pass judges with the
    /// same origin as the primary pass. Ruling L3-18: both passes call
    /// `verify_with_at`, with the store's leak index and the origin at once.
    #[test]
    fn the_retry_pass_gets_the_same_origin_as_the_primary() {
        #[derive(Default)]
        struct Recorder(std::sync::Mutex<Vec<(TextOrigin, bool)>>);
        impl Verifier for Recorder {
            fn verify(&self, s: &Sanitized, c: &dyn TokenStore) -> Verdict {
                self.verify_with_at(s, c, None, TextOrigin::Free)
            }
            fn verify_with_at(
                &self,
                _: &Sanitized,
                _: &dyn TokenStore,
                leak: Option<&crate::verify::LeakIndex>,
                o: TextOrigin,
            ) -> Verdict {
                self.0.lock().unwrap().push((o, leak.is_some()));
                Verdict::Fail(vec![Reason {
                    kind: EntityKind::Person,
                    check: CheckId::Ner,
                }])
            }
        }
        for origin in [TextOrigin::HarnessStatic, TextOrigin::Free] {
            let rec = Arc::new(Recorder::default());
            let mut e = engine();
            e.verifier = rec.clone();
            let d = e
                .process_scoped_at(
                    "Bitte prüfen.",
                    &mut ctx(),
                    &[],
                    &LinkScope::empty(),
                    origin,
                )
                .unwrap();
            assert!(d.retried);
            assert_eq!(
                *rec.0.lock().unwrap(),
                vec![(origin, true), (origin, true)],
                "each pass: the same origin, and the store's leak index"
            );
        }
    }

    fn shipped_support_email(ner: Vec<(&'static str, f32)>) -> Engine {
        let cfg = CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap();
        Engine::from_config(
            &cfg,
            "support-email",
            Some(Arc::new(PersonNer(ner))),
            Some(Arc::new(NoNer)),
        )
        .unwrap()
    }

    /// The shipped configuration with `on_uncertain = "tokenize"` (the
    /// file holds the setting once, in `[profiles.offline.verifier]`, and
    /// every shipped profile inherits it).
    fn tokenize_support_email(ner: Vec<(&'static str, f32)>) -> Engine {
        let src = include_str!("../../../configs/default.toml");
        assert_eq!(src.matches("on_uncertain = \"block\"").count(), 1);
        let cfg = CoreConfig::from_toml(
            &src.replace("on_uncertain = \"block\"", "on_uncertain = \"tokenize\""),
        )
        .unwrap();
        Engine::from_config(
            &cfg,
            "support-email",
            Some(Arc::new(PersonNer(ner))),
            Some(Arc::new(NoNer)),
        )
        .unwrap()
    }

    /// L70: a policy-escalated span is tokenized, the text passes, and the
    /// token restores to exactly the original.
    #[test]
    fn tokenize_mode_tokenizes_band_spans_and_restores_them() {
        let e = tokenize_support_email(vec![("Quolnath", 0.55)]);
        let mut c = ctx();
        let text = "Bitte Quolnath anrufen.";
        let d = e.process_detailed(text, &mut c, &[]).unwrap();
        let Outcome::Pass { sanitized } = &d.outcome else {
            panic!("expected pass, got {:?}", d.outcome)
        };
        assert!(
            !sanitized.text.contains("Quolnath") && sanitized.text.contains("<PERSON_"),
            "{}",
            sanitized.text
        );
        assert_eq!(d.band_tokenized, 1);
        let (back, unknown) =
            crate::rehydrate::Rehydrator::new(e.token_settings()).rehydrate(&sanitized.text, &c);
        assert_eq!((back.as_str(), unknown), (text, 0));
        // the same span under the shipped `block` setting is not forwarded in clear either way
        let d = shipped_support_email(vec![("Quolnath", 0.55)])
            .process_detailed(text, &mut ctx(), &[])
            .unwrap();
        assert_eq!(d.band_tokenized, 0);
    }

    /// L73 (a): a single-line band PERSON span with no name candidate next
    /// to it is tokenized in the first pass and the text passes: the guard
    /// does not over-block. Under the shipped `block` the same text still
    /// goes through the strict retry (block behaviour unchanged).
    #[test]
    fn tokenize_mode_passes_a_single_line_band_span_without_a_neighbour() {
        let text = "Danke, Quolnath.";
        let d = tokenize_support_email(vec![("Quolnath", 0.55)])
            .process_detailed(text, &mut ctx(), &[])
            .unwrap();
        let Outcome::Pass { sanitized } = &d.outcome else {
            panic!("expected pass, got {:?}", d.outcome)
        };
        assert!(!sanitized.text.contains("Quolnath"), "{}", sanitized.text);
        assert!(!d.retried, "settled in the first pass");
        assert_eq!(d.band_tokenized, 1);
        let d = shipped_support_email(vec![("Quolnath", 0.55)])
            .process_detailed(text, &mut ctx(), &[])
            .unwrap();
        let Outcome::Pass { sanitized } = &d.outcome else {
            panic!("expected pass, got {:?}", d.outcome)
        };
        assert!(!sanitized.text.contains("Quolnath"), "{}", sanitized.text);
        assert!(d.retried, "under block the band span goes to the retry");
        assert_eq!(d.band_tokenized, 0);
    }

    /// L70: a verifier `Fail` still blocks (after the retry) under tokenize.
    #[test]
    fn tokenize_mode_still_blocks_on_verifier_fail() {
        struct AlwaysFail;
        impl Verifier for AlwaysFail {
            fn verify(&self, _: &Sanitized, _: &dyn TokenStore) -> Verdict {
                Verdict::Fail(vec![Reason {
                    kind: EntityKind::Person,
                    check: CheckId::Ner,
                }])
            }
        }
        let cfg = CoreConfig::from_toml(CFG).unwrap();
        let mut profile = cfg.resolve_profile("fast").unwrap();
        profile.verifier.on_uncertain = OnUncertain::Tokenize;
        let mut retry = cfg.resolve_profile("strict").unwrap();
        retry.verifier.on_uncertain = OnUncertain::Tokenize;
        let e = Engine::new(profile, Some(retry), vec![], Arc::new(AlwaysFail));
        let d = e
            .process_detailed("Bitte anrufen.", &mut ctx(), &[])
            .unwrap();
        assert!(d.retried, "a Fail retries");
        assert!(
            matches!(d.outcome, Outcome::Blocked { .. }),
            "{:?}",
            d.outcome
        );
    }

    /// L70: a verifier `Uncertain` with no span to tokenize still blocks.
    #[test]
    fn tokenize_mode_still_blocks_on_verifier_uncertain() {
        struct AlwaysUncertain;
        impl Verifier for AlwaysUncertain {
            fn verify(&self, _: &Sanitized, _: &dyn TokenStore) -> Verdict {
                Verdict::Uncertain(vec![Reason {
                    kind: EntityKind::Date,
                    check: CheckId::Combination,
                }])
            }
        }
        let cfg = CoreConfig::from_toml(CFG).unwrap();
        let mut profile = cfg.resolve_profile("fast").unwrap();
        profile.verifier.on_uncertain = OnUncertain::Tokenize;
        let e = Engine::new(profile, None, vec![], Arc::new(AlwaysUncertain));
        assert!(matches!(
            e.process("Bitte anrufen.", &mut ctx()).unwrap(),
            Outcome::Blocked { .. }
        ));
    }

    /// L70 and re-review 2: the multi-line guard runs in every pass under
    /// tokenize. The verifier passes (`NoNer`), so without the guard in the
    /// first pass the missed surname `Ng` next to the uncertain span would be
    /// forwarded in clear. Expect a refusal.
    #[test]
    fn tokenize_mode_keeps_the_retry_guard_fail_closed() {
        let d = tokenize_support_email(vec![("anna\n\n--\nanna", 0.55)])
            .process_detailed("Bitte um Rückruf.\nanna\n\n--\nanna\nNg", &mut ctx(), &[])
            .unwrap();
        assert!(
            matches!(d.outcome, Outcome::Blocked { .. }),
            "got {:?}",
            d.outcome
        );
        assert!(
            d.retried,
            "the guard's escalation fails the first pass, so the retry runs"
        );
    }

    /// Fix round 1 (L3-13): a profile where PERSON has `action` set
    /// (threshold 0.9, band from 0.5), a stand-in NER that finds `Quolnath`
    /// at 0.6 (in the band), a verifier that passes, `on_uncertain =
    /// "tokenize"`, no retry.
    fn tokenize_with_person_action(action: Action) -> Engine {
        tokenize_with_person_action_ner(action, vec![("Quolnath", 0.6)])
    }

    /// [`tokenize_with_person_action`] with the stand-in NER's spans given.
    fn tokenize_with_person_action_ner(action: Action, ner: Vec<(&'static str, f32)>) -> Engine {
        struct AlwaysPass;
        impl Verifier for AlwaysPass {
            fn verify(&self, _: &Sanitized, _: &dyn TokenStore) -> Verdict {
                Verdict::Pass
            }
        }
        let cfg = CoreConfig::from_toml(CFG).unwrap();
        let mut profile = cfg.resolve_profile("fast").unwrap();
        profile.verifier.on_uncertain = OnUncertain::Tokenize;
        profile.escalate_below = 0.5;
        profile.entities.insert(
            EntityKind::Person.label().to_string(),
            EntityPolicy {
                action,
                min_confidence: 0.9,
            },
        );
        Engine::new(
            profile,
            None,
            vec![Arc::new(PersonNer(ner))],
            Arc::new(AlwaysPass),
        )
    }

    /// L3-13: under tokenize a band span of a `block` kind still refuses;
    /// it is neither tokenized nor forwarded.
    #[test]
    fn tokenize_mode_keeps_refusing_a_band_span_of_a_block_kind() {
        let d = tokenize_with_person_action(Action::Block)
            .process_detailed("Bitte Quolnath anrufen.", &mut ctx(), &[])
            .unwrap();
        assert!(
            matches!(d.outcome, Outcome::Blocked { .. }),
            "got {:?}",
            d.outcome
        );
        assert_eq!(d.band_tokenized, 0);
    }

    /// L3-13: under tokenize a band span of a `remove` kind is removed: no
    /// token, nothing restorable, no store entry (only the leak-check record).
    #[test]
    fn tokenize_mode_removes_a_band_span_of_a_remove_kind() {
        let e = tokenize_with_person_action(Action::Remove);
        let mut c = ctx();
        let text = "Bitte Quolnath anrufen.";
        let d = e.process_detailed(text, &mut c, &[]).unwrap();
        let Outcome::Pass { sanitized } = &d.outcome else {
            panic!("expected pass, got {:?}", d.outcome)
        };
        assert!(!sanitized.text.contains("Quolnath"), "{}", sanitized.text);
        let marker = c.removed_marker(&EntityKind::Person);
        assert!(sanitized.text.contains(&marker), "{}", sanitized.text);
        assert!(
            !sanitized.text.replace(&marker, "").contains("<PERSON_"),
            "no token: {}",
            sanitized.text
        );
        assert_eq!(d.band_tokenized, 0);
        assert_eq!(c.entries().count(), 0, "nothing in the store");
        let (back, _) =
            crate::rehydrate::Rehydrator::new(e.token_settings()).rehydrate(&sanitized.text, &c);
        assert!(!back.contains("Quolnath"), "never restorable");
    }

    /// L3-13 with the guard: an uncertain multi-line span of a `remove`
    /// kind next to a name candidate (`Ng`, which no detector finds) is not
    /// removed on its own, which would forward the surname in clear: the
    /// guard escalates it as for a tokenized kind, and the text is refused.
    /// (The pieces carry different values, so this isolates the guard; the
    /// same-value shape, where a removed copy merges onto the escalated
    /// piece, is `tokenize_mode_keeps_the_guard_escalation_over_a_removed_copy`,
    /// L106.)
    #[test]
    fn tokenize_mode_guards_a_multiline_band_span_of_a_remove_kind() {
        let d = tokenize_with_person_action_ner(Action::Remove, vec![("anna\n\n--\nmaria", 0.6)])
            .process_detailed("Bitte um Rückruf.\nanna\n\n--\nmaria\nNg", &mut ctx(), &[])
            .unwrap();
        assert!(
            matches!(d.outcome, Outcome::Blocked { .. }),
            "got {:?}",
            d.outcome
        );
        assert_eq!(d.band_tokenized, 0);
    }

    /// L106: the same shape with one value in both pieces
    /// (`anna\n\n--\nanna`, then `Ng`). The first piece is removed; the
    /// consistency step folds the clear copy of `anna` into the guard's
    /// escalated second piece as `Remove`. While escalations hold, the union
    /// keeps `Escalate`, so the text is refused and `Ng` never crosses.
    #[test]
    fn tokenize_mode_keeps_the_guard_escalation_over_a_removed_copy() {
        let d = tokenize_with_person_action_ner(Action::Remove, vec![("anna\n\n--\nanna", 0.6)])
            .process_detailed("Bitte um Rückruf.\nanna\n\n--\nanna\nNg", &mut ctx(), &[])
            .unwrap();
        if let Outcome::Pass { sanitized } = &d.outcome {
            panic!("expected a refusal, passed: {}", sanitized.text);
        }
        assert!(
            matches!(d.outcome, Outcome::Blocked { .. }),
            "got {:?}",
            d.outcome
        );
        assert_eq!(d.band_tokenized, 0);
    }

    /// L106 end to end, for a caller redaction: a `Remove` redaction over
    /// part of the guard's escalated multi-line name (`maria`) while
    /// escalations hold must not turn the union into a plain removal that
    /// leaves the neighbouring `Ng` in clear. The text is refused, whichever
    /// piece the redaction covers.
    #[test]
    fn a_remove_redaction_over_an_escalated_span_is_refused() {
        let text = "Bitte um Rückruf.\nanna\n\n--\nmaria\nNg";
        let engine =
            tokenize_with_person_action_ner(Action::Remove, vec![("anna\n\n--\nmaria", 0.6)]);
        for needle in ["maria", "anna", "anna\n\n--\nmaria"] {
            let start = text.find(needle).unwrap();
            let red = [Redaction {
                start,
                end: start + needle.len(),
                kind: "PERSON".into(),
                action: RedactionAction::Remove,
            }];
            let d = engine.process_detailed(text, &mut ctx(), &red).unwrap();
            if let Outcome::Pass { sanitized } = &d.outcome {
                panic!("expected a refusal, passed: {}", sanitized.text);
            }
            assert!(
                matches!(d.outcome, Outcome::Blocked { .. }),
                "got {:?}",
                d.outcome
            );
        }
    }

    /// The shipped configuration (`on_uncertain = "block"`) with every
    /// retry profile's PERSON set to `remove` from 0.40 (no shipped profile
    /// does this). `strict-metadata` is cut out: its PERSON must keep its
    /// base's action, and it plays no part here.
    fn block_with_retry_removing_person(ner: Vec<(&'static str, f32)>) -> Engine {
        let src = include_str!("../../../configs/default.toml");
        let line = "PERSON          = { action = \"tokenize\", min_confidence = 0.40 }";
        assert!(src.contains(line));
        let (head, rest) = src.split_once("[profiles.strict-metadata]").unwrap();
        let (_, tail) = rest.split_once("# The model-API proxy").unwrap();
        let src = format!("{head}# The model-API proxy{tail}");
        let cfg = CoreConfig::from_toml(&src.replace(
            line,
            "PERSON          = { action = \"remove\", min_confidence = 0.40 }",
        ))
        .unwrap();
        Engine::from_config(
            &cfg,
            "support-email",
            Some(Arc::new(PersonNer(ner))),
            Some(Arc::new(NoNer)),
        )
        .unwrap()
    }

    /// L106, block variant: the primary escalates the uncertain span and
    /// the retry removes PERSON from 0.40. The retry's multi-line guard
    /// must see the removed piece next to `Ng` (it escalates it), and the
    /// consistency step's `Remove` copy must not outrank that escalation.
    /// Either gap alone forwards `Ng` in clear. Expect a refusal.
    #[test]
    fn a_retry_that_removes_person_keeps_the_guard_fail_closed() {
        let d = block_with_retry_removing_person(vec![("anna\n\n--\nanna", 0.55)])
            .process_detailed("Bitte um Rückruf.\nanna\n\n--\nanna\nNg", &mut ctx(), &[])
            .unwrap();
        assert!(d.retried, "the primary escalates, so the retry runs");
        if let Outcome::Pass { sanitized } = &d.outcome {
            panic!("expected a refusal, passed: {}", sanitized.text);
        }
        assert!(
            matches!(d.outcome, Outcome::Blocked { .. }),
            "got {:?}",
            d.outcome
        );
    }

    /// L106, block variant with distinct values (no consistency copy): the
    /// retry's guard alone must escalate a removed multi-line piece next to
    /// `Ng`.
    #[test]
    fn a_retry_that_removes_person_guards_a_multiline_span() {
        let d = block_with_retry_removing_person(vec![("anna\n\n--\nmaria", 0.55)])
            .process_detailed("Bitte um Rückruf.\nanna\n\n--\nmaria\nNg", &mut ctx(), &[])
            .unwrap();
        assert!(d.retried, "the primary escalates, so the retry runs");
        assert!(
            matches!(d.outcome, Outcome::Blocked { .. }),
            "got {:?}",
            d.outcome
        );
    }

    /// L3-13: a band span of a `tokenize` kind is still tokenized and counted.
    #[test]
    fn tokenize_mode_tokenizes_a_band_span_of_a_tokenize_kind() {
        let d = tokenize_with_person_action(Action::Tokenize)
            .process_detailed("Bitte Quolnath anrufen.", &mut ctx(), &[])
            .unwrap();
        let Outcome::Pass { sanitized } = &d.outcome else {
            panic!("expected pass, got {:?}", d.outcome)
        };
        assert!(sanitized.text.contains("<PERSON_"), "{}", sanitized.text);
        assert_eq!(d.band_tokenized, 1);
    }

    /// L70: an uncertain multi-line span with no name candidate next to it
    /// is tokenized whole in the first pass; nothing refuses and no retry runs.
    #[test]
    fn tokenize_mode_tokenizes_a_multiline_span_without_a_neighbour() {
        let d = tokenize_support_email(vec![("Quolnath\nQuolnath", 0.55)])
            .process_detailed(
                "Bitte um Rückruf.\nDanke!\nQuolnath\nQuolnath",
                &mut ctx(),
                &[],
            )
            .unwrap();
        let Outcome::Pass { sanitized } = &d.outcome else {
            panic!("expected pass, got {:?}", d.outcome)
        };
        assert!(!sanitized.text.contains("Quolnath"), "{}", sanitized.text);
        assert!(!d.retried, "settled in the first pass");
        assert!(d.band_tokenized >= 1);
    }

    /// L41 (ii): `anna\n\n--\nanna müller` with `anna` known: `müller` is
    /// never forwarded in clear, whether rule (a) extends the span over it
    /// or the guard refuses the text.
    #[test]
    fn a_surname_after_a_guarded_span_is_never_forwarded_in_clear() {
        let e = shipped_support_email(vec![("Anna", 0.9), ("anna\n\n--\nanna", 0.55)]);
        let d = e
            .process_detailed(
                "Hallo Anna,\ndanke.\nViele Grüße\nanna\n\n--\nanna müller\nRosenweg 1",
                &mut ctx(),
                &[],
            )
            .unwrap();
        assert!(d.retried, "the primary escalates, so the retry runs");
        match &d.outcome {
            Outcome::Blocked { .. } => {}
            Outcome::Pass { sanitized } => assert!(
                !sanitized.text.contains("müller") && !sanitized.text.contains("anna"),
                "{}",
                sanitized.text
            ),
            other => panic!("unexpected {other:?}"),
        }
    }

    fn guarded(text: &str, needles: Vec<(&'static str, f32)>) -> Detailed {
        shipped_support_email(needles)
            .process_detailed(text, &mut ctx(), &[])
            .unwrap()
    }

    /// L41 (iv): a guarded span made only of known copies, with no name
    /// candidate next to it, is tokenized whole, not refused.
    #[test]
    fn a_guarded_span_of_known_copies_without_a_neighbour_is_tokenized() {
        let d = guarded(
            "Quolnath hat angerufen.\nDanke!\nQuolnath\nQuolnath",
            vec![("Quolnath", 0.9), ("Quolnath\nQuolnath", 0.55)],
        );
        let Outcome::Pass { sanitized } = &d.outcome else {
            panic!("expected pass, got {:?}", d.outcome)
        };
        assert!(!sanitized.text.contains("Quolnath"), "{}", sanitized.text);
    }

    /// L41 (v) and L44 (c): a span that ends at its line end, with nothing
    /// but the line break after it, is followed by the next line's first
    /// word; a short surname there (`Ng`) escalates.
    #[test]
    fn a_surname_on_the_next_line_after_a_guarded_span_escalates() {
        assert!(!crate::stoplist::is_common_word("Ng"));
        let d = guarded(
            "Bitte um Rückruf.\nanna\n\n--\nanna\nNg",
            vec![("anna\n\n--\nanna", 0.55)],
        );
        assert!(
            matches!(d.outcome, Outcome::Blocked { .. }),
            "expected a refusal, got {:?}",
            d.outcome
        );
    }

    /// Task 7 with ruling L37: detection cuts the uncertain multi-line span
    /// into line pieces (the `--` piece is dropped) that carry the
    /// line-break flag, and the retry guard still escalates the piece with
    /// a name candidate (`Ng`) next to it, so the text is refused.
    #[test]
    fn a_split_piece_of_a_guarded_span_still_escalates() {
        let text = "Bitte um Rückruf.\nanna\n\n--\nanna\nNg";
        let needles = vec![("anna\n\n--\nanna", 0.55)];
        let spans = shipped_support_email(needles.clone()).detect(text).unwrap();
        let persons: Vec<&Span> = spans
            .iter()
            .filter(|s| s.kind == EntityKind::Person)
            .collect();
        assert_eq!(
            persons.iter().map(|s| s.slice(text)).collect::<Vec<_>>(),
            ["anna", "anna"],
            "the span is cut at its line breaks"
        );
        assert!(persons.iter().all(|s| s.crossed_line_break));
        let d = guarded(text, needles);
        assert!(d.retried, "the primary escalates, so the retry runs");
        assert!(
            matches!(d.outcome, Outcome::Blocked { .. }),
            "expected a refusal, got {:?}",
            d.outcome
        );
    }

    /// L44 (c): terminal punctuation after the span ends the name, so the
    /// next line's first word is not adjacent, even a name-like one.
    #[test]
    fn a_comma_after_a_guarded_span_ends_its_adjacency() {
        for next in ["we", "Ng"] {
            let text = format!("Grüße\nanna\n\n--\nanna,\n{next} ruft zurück.");
            let d = guarded(&text, vec![("anna\n\n--\nanna", 0.55)]);
            let Outcome::Pass { sanitized } = &d.outcome else {
                panic!("{next}: expected pass, got {:?}", d.outcome)
            };
            assert!(!sanitized.text.contains("anna"), "{}", sanitized.text);
        }
    }

    /// L45: a hyphenated word after a guarded span is a candidate when one
    /// of its parts is (`müller-lang` escalates), and not when every part
    /// is a common or salutation word (`Support-Team` does not). On the
    /// same line, rule (a) takes `müller-lang` whole (final review 2), so
    /// it is tokenized, never clear; on the next line the guard escalates.
    #[test]
    fn a_hyphenated_neighbour_counts_only_with_a_name_like_part() {
        let d = guarded(
            "Bitte um Rückruf.\nanna\n\n--\nanna müller-lang",
            vec![("anna\n\n--\nanna", 0.55)],
        );
        let Outcome::Pass { sanitized } = &d.outcome else {
            panic!("müller-lang: expected pass, got {:?}", d.outcome)
        };
        assert!(
            !sanitized.text.contains("müller") && !sanitized.text.contains("lang"),
            "{}",
            sanitized.text
        );
        let d = guarded(
            "Bitte um Rückruf.\nanna\n\n--\nanna\nmüller-lang",
            vec![("anna\n\n--\nanna", 0.55)],
        );
        assert!(
            matches!(d.outcome, Outcome::Blocked { .. }),
            "müller-lang: expected a refusal, got {:?}",
            d.outcome
        );
        let d = guarded(
            "Bitte um Rückruf.\nanna\n\n--\nanna Support-Team,\nwir melden uns.",
            vec![("anna\n\n--\nanna", 0.55)],
        );
        let Outcome::Pass { sanitized } = &d.outcome else {
            panic!("Support-Team: expected pass, got {:?}", d.outcome)
        };
        assert!(!sanitized.text.contains("anna"), "{}", sanitized.text);
    }

    /// Re-review 3, I1: a surname that is also an ordinary word (`Smith`,
    /// `Lang`) still counts: rule (a) extends over it or the guard
    /// escalates, so it is never forwarded in clear.
    #[test]
    fn a_name_like_common_word_next_to_a_guarded_span_is_never_clear() {
        assert!(crate::stoplist::is_common_word("Smith"));
        let d = guarded(
            "Grüße\nanna\n\n--\nanna Smith",
            vec![("anna\n\n--\nanna", 0.55)],
        );
        match &d.outcome {
            Outcome::Blocked { .. } => {}
            Outcome::Pass { sanitized } => {
                assert!(!sanitized.text.contains("Smith"), "{}", sanitized.text)
            }
            other => panic!("unexpected {other:?}"),
        }
        // a span cut inside a hyphenated surname: the rest (`-lang`) is a
        // candidate, so the span escalates
        let d = guarded(
            "Grüße\nanna\n\n--\nanna müller-lang",
            vec![("anna\n\n--\nanna müller", 0.55)],
        );
        assert!(
            matches!(d.outcome, Outcome::Blocked { .. }),
            "müller|-lang: expected a refusal, got {:?}",
            d.outcome
        );
    }

    /// L44 (a): a sign-off abbreviation before the span is not a name
    /// candidate.
    #[test]
    fn a_sign_off_abbreviation_before_a_guarded_span_is_not_a_candidate() {
        let d = guarded(
            "Bitte um Rückruf.\nLG anna\n\n--\nanna.",
            vec![("anna\n\n--\nanna", 0.55)],
        );
        let Outcome::Pass { sanitized } = &d.outcome else {
            panic!("expected pass, got {:?}", d.outcome)
        };
        assert!(!sanitized.text.contains("anna"), "{}", sanitized.text);
    }

    /// Ruling (a): a tokenized PERSON span that ends with a gazetteer first
    /// name takes the next word on the same line when that word is one
    /// alphabetic word (diacritics, any case) and not a common word.
    #[test]
    fn a_surname_after_a_first_name_on_the_same_line_is_tokenized() {
        assert!(!crate::stoplist::is_common_word("petrović"));
        let e = shipped_support_email(vec![("lukas", 0.9)]);
        let d = e
            .process_detailed("Grüße\nlukas petrović", &mut ctx(), &[])
            .unwrap();
        let Outcome::Pass { sanitized } = d.outcome else {
            panic!("expected pass, got {:?}", d.outcome)
        };
        assert!(
            !sanitized.text.contains("petrović") && !sanitized.text.contains("lukas"),
            "{}",
            sanitized.text
        );
        assert_eq!(sanitized.replacements.len(), 1, "one PERSON token");
    }

    /// Re-review 2, Critical: a consistency match (a lower-case copy of a
    /// confident `Anna`) must not merge a guarded multi-line band span into
    /// a `Tokenize` union; the guard's escalation holds and the text is
    /// refused rather than sending the unguarded rest (`müller-lang`). The
    /// surname is on the next line, where rule (a) does not reach and only
    /// the guard keeps it from going out in clear.
    #[test]
    fn a_consistency_match_does_not_undo_the_retry_guard() {
        let e = shipped_support_email(vec![("Anna", 0.9), ("anna\n\n--\nanna", 0.55)]);
        let d = e
            .process_detailed(
                "Hallo Anna, danke für die Info.\nViele Grüße\nanna\n\n--\nanna\nmüller-lang",
                &mut ctx(),
                &[],
            )
            .unwrap();
        assert!(
            matches!(d.outcome, Outcome::Blocked { .. }),
            "expected a refusal, got {:?}",
            d.outcome
        );
    }

    /// Re-review 2, Critical (primary half): a consistency match inside the
    /// primary's band escalation keeps it an escalation, so the retry (which
    /// also tokenizes cities, organizations and dates) still runs.
    #[test]
    fn a_consistency_match_keeps_the_primary_band_as_the_retry_trigger() {
        let e = shipped_support_email(vec![("Quolnath", 0.9), ("quolnath brandl", 0.55)]);
        let d = e
            .process_detailed(
                "Quolnath schrieb gestern. Später rief quolnath brandl an.",
                &mut ctx(),
                &[],
            )
            .unwrap();
        assert!(
            d.retried,
            "the primary's band escalation still triggers the retry"
        );
        let Outcome::Pass { sanitized } = d.outcome else {
            panic!("expected pass, got {:?}", d.outcome)
        };
        assert!(
            !sanitized.text.contains("brandl") && !sanitized.text.contains("uolnath"),
            "{}",
            sanitized.text
        );
    }

    /// Re-review 2, Important: a surname the model scores as a PERSON
    /// below every threshold does not stop the extension (it would be
    /// dropped by policy and leak).
    #[test]
    fn a_sub_threshold_surname_span_does_not_stop_the_extension() {
        let e = shipped_support_email(vec![("lukas", 0.9), ("petrović", 0.3)]);
        let d = e
            .process_detailed("Grüße\nlukas petrović", &mut ctx(), &[])
            .unwrap();
        let Outcome::Pass { sanitized } = d.outcome else {
            panic!("expected pass, got {:?}", d.outcome)
        };
        assert!(!sanitized.text.contains("petrović"), "{}", sanitized.text);
    }

    /// Ruling (a), negative: a following common word is not swallowed, and
    /// a word on the next line is not taken.
    #[test]
    fn a_common_word_or_a_next_line_word_after_a_first_name_stays() {
        assert!(crate::stoplist::is_common_word("bitte"));
        let e = shipped_support_email(vec![("lukas", 0.9)]);
        let d = e
            .process_detailed(
                "Sag lukas bitte Bescheid.\nRuf lukas\npetrović an.",
                &mut ctx(),
                &[],
            )
            .unwrap();
        let Outcome::Pass { sanitized } = d.outcome else {
            panic!("expected pass, got {:?}", d.outcome)
        };
        assert!(
            sanitized.text.contains("> bitte Bescheid."),
            "{}",
            sanitized.text
        );
        assert!(
            sanitized.text.ends_with(">\npetrović an."),
            "{}",
            sanitized.text
        );
    }

    #[test]
    fn with_detector_adds_to_the_stack() {
        let cfg = CoreConfig::from_toml(CFG).unwrap();
        let e = Engine::from_config(&cfg, "fast", None, None)
            .unwrap()
            .with_detector(Arc::new(GruberNer));
        let spans = e.detect("Herr Gruber kam.").unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].kind, EntityKind::Person);
        let Outcome::Pass { sanitized } = e.process("Herr Gruber kam.", &mut ctx()).unwrap() else {
            panic!("expected pass")
        };
        assert!(sanitized.text.contains("<PERSON_"), "{}", sanitized.text);
    }

    /// Spec §5.3: a store failure discards the whole result; no candidate
    /// text, no placeholder token, no `Blocked` that could be cached.
    struct FailingStore(Context);
    impl TokenStore for FailingStore {
        fn token_for(
            &mut self,
            _: &EntityKind,
            _: &str,
        ) -> std::result::Result<crate::token::Token, StoreError> {
            Err(StoreError::Unavailable)
        }
        fn original(&self, t: &str) -> Option<&str> {
            self.0.original(t)
        }
        fn entries(&self) -> Box<dyn Iterator<Item = (&EntityKind, &str)> + '_> {
            Box::new(self.0.entries())
        }
        fn record_removed(
            &mut self,
            _: &EntityKind,
            _: &str,
        ) -> std::result::Result<(), StoreError> {
            Err(StoreError::Unavailable)
        }
        fn removed_entries(&self) -> Box<dyn Iterator<Item = (&EntityKind, &str)> + '_> {
            Box::new(self.0.removed_entries())
        }
        fn removed_marker(&self, k: &EntityKind) -> String {
            self.0.removed_marker(k)
        }
        fn settings(&self) -> &TokenSettings {
            self.0.settings()
        }
        fn surface_token(
            &mut self,
            parent: &crate::token::Token,
            surface: &str,
        ) -> std::result::Result<crate::token::Token, StoreError> {
            self.0.surface_token(parent, surface)
        }
    }

    /// M4 spec §9.1: a redaction forces a transformation the detectors
    /// missed, keeps a policy block, and never marks anything safe.
    /// Re-review 2: a redaction (caller or consistency match) over an
    /// escalated span keeps the escalation, and the union keeps the
    /// line-break flag, where an escalation refuses; elsewhere (an
    /// escalation would forward in clear) the union tokenizes as before.
    #[test]
    fn merging_a_redaction_keeps_an_escalation_only_where_it_refuses() {
        let escalated = Decision {
            span: Span {
                crossed_line_break: true,
                ..Span::new(
                    0,
                    15,
                    EntityKind::Person,
                    0.55,
                    crate::span::DetectorId::Ner,
                )
            },
            action: Action::Escalate,
        };
        let red = Redaction {
            start: 0,
            end: 4,
            kind: "PERSON".into(),
            action: RedactionAction::Tokenize,
        };
        for (holds, want) in [(true, Action::Escalate), (false, Action::Tokenize)] {
            let mut ds = vec![escalated.clone()];
            merge_redaction(&mut ds, &red, holds);
            assert_eq!(ds.len(), 1);
            assert_eq!(ds[0].action, want, "holds = {holds}");
            assert_eq!((ds[0].span.start, ds[0].span.end), (0, 15));
            assert!(ds[0].span.crossed_line_break);
        }
        // L106: while escalations hold, a union that absorbed an
        // escalation keeps it over `Remove` too; elsewhere `Remove` wins
        for (holds, want) in [(true, Action::Escalate), (false, Action::Remove)] {
            let mut ds = vec![escalated.clone()];
            merge_redaction(
                &mut ds,
                &Redaction {
                    action: RedactionAction::Remove,
                    ..red.clone()
                },
                holds,
            );
            assert_eq!(ds.len(), 1);
            assert_eq!(ds[0].action, want, "remove, holds = {holds}");
        }
        // `Block` still wins over the escalation
        for holds in [true, false] {
            let mut ds = vec![
                escalated.clone(),
                Decision {
                    span: Span::new(
                        10,
                        15,
                        EntityKind::Iban,
                        1.0,
                        crate::span::DetectorId::RegexValidated,
                    ),
                    action: Action::Block,
                },
            ];
            merge_redaction(
                &mut ds,
                &Redaction {
                    end: 15,
                    ..red.clone()
                },
                holds,
            );
            assert_eq!(ds.len(), 1);
            assert_eq!(ds[0].action, Action::Block, "block, holds = {holds}");
        }
    }

    #[test]
    fn redaction_forces_tokenize_and_keeps_policy_blocks() {
        let e = engine();
        let text = "Bitte an Sarah Leitner weiterleiten.";
        let red = [Redaction {
            start: 9,
            end: 22,
            kind: "PERSON".into(),
            action: RedactionAction::Tokenize,
        }];
        let Outcome::Pass { sanitized } = e.process_with(text, &mut ctx(), &red).unwrap() else {
            panic!()
        };
        assert!(
            sanitized.text.starts_with("Bitte an <PERSON_"),
            "{}",
            sanitized.text
        );
        let rem = [Redaction {
            start: 9,
            end: 22,
            kind: "PERSON".into(),
            action: RedactionAction::Remove,
        }];
        let Outcome::Pass { sanitized } = e.process_with(text, &mut ctx(), &rem).unwrap() else {
            panic!()
        };
        assert_eq!(sanitized.text, "Bitte an <PERSON_REMOVED> weiterleiten.");
        // a redaction over a kind the profile blocks does not unblock it
        let mut cfg = CoreConfig::from_toml(CFG).unwrap();
        cfg.profiles.get_mut("fast").unwrap().entities.insert(
            "IBAN".into(),
            EntityPolicy {
                action: Action::Block,
                min_confidence: 0.0,
            },
        );
        cfg.profiles
            .get_mut("fast")
            .unwrap()
            .verifier
            .as_mut()
            .unwrap()
            .retry_profile = Some("fast".into());
        let e = Engine::from_config(&cfg, "fast", None, None).unwrap();
        let text = "AT61 1904 3002 3457 3201";
        let red = [Redaction {
            start: 0,
            end: text.len(),
            kind: "IBAN".into(),
            action: RedactionAction::Tokenize,
        }];
        assert!(matches!(
            e.process_with(text, &mut ctx(), &red).unwrap(),
            Outcome::Blocked { .. }
        ));
    }

    /// Controller fix: a redaction labeled with a harmless kind must not let
    /// a detected, policy-blocked span slip through. The invariant is
    /// "redactions only add coverage and strengthen actions," never weaken
    /// one — so the merge must use the *detected* decision's action (and
    /// report the *detected* kind), not the caller-supplied label.
    #[test]
    fn mislabeled_redaction_does_not_bypass_a_policy_block() {
        let mut cfg = CoreConfig::from_toml(CFG).unwrap();
        cfg.profiles.get_mut("fast").unwrap().entities.insert(
            "IBAN".into(),
            EntityPolicy {
                action: Action::Block,
                min_confidence: 0.0,
            },
        );
        cfg.profiles
            .get_mut("fast")
            .unwrap()
            .verifier
            .as_mut()
            .unwrap()
            .retry_profile = Some("fast".into());
        let e = Engine::from_config(&cfg, "fast", None, None).unwrap();
        let text = "AT61 1904 3002 3457 3201";
        // Exactly the detected IBAN span, but labeled as something harmless.
        let red = [Redaction {
            start: 0,
            end: text.len(),
            kind: "NOTE".into(),
            action: RedactionAction::Tokenize,
        }];
        match e.process_with(text, &mut ctx(), &red).unwrap() {
            Outcome::Blocked { kinds, .. } => assert_eq!(kinds, vec![EntityKind::Iban]),
            o => panic!("mislabeled redaction bypassed the block: {o:?}"),
        }
    }

    /// Controller fix: a redaction that only partially overlaps a detected
    /// entity must not leave the rest of that entity in clear text — the
    /// merged decision must cover the union of both ranges.
    #[test]
    fn partial_overlap_redaction_extends_to_cover_the_whole_detected_span() {
        let e = engine();
        let text = "IBAN AT61 1904 3002 3457 3201";
        // The IBAN occupies bytes 5..29; redact only a slice in the middle
        // under an unrelated label.
        let red = [Redaction {
            start: 10,
            end: 15,
            kind: "NOTE".into(),
            action: RedactionAction::Tokenize,
        }];
        let Outcome::Pass { sanitized } = e.process_with(text, &mut ctx(), &red).unwrap() else {
            panic!()
        };
        assert!(
            !sanitized.text.contains("AT61") && !sanitized.text.contains("3201"),
            "the untouched prefix/suffix of the IBAN leaked: {}",
            sanitized.text
        );
        assert!(
            sanitized.text.contains("<IBAN_"),
            "the real detected kind is reported, not the redaction's label: {}",
            sanitized.text
        );
    }

    /// Controller fix: same invariant, checked against a detected PERSON
    /// under a mismatched label — the whole name must disappear, not just
    /// the bytes the redaction happened to cover.
    #[test]
    fn mismatched_kind_redaction_over_a_detected_person_removes_the_whole_name() {
        let cfg = CoreConfig::from_toml(CFG).unwrap();
        let e = Engine::from_config(&cfg, "fast", None, None)
            .unwrap()
            .with_detector(Arc::new(GruberNer));
        let text = "Herr Gruber kam.";
        // "Gruber" occupies bytes 5..11; redact only its middle two bytes.
        let red = [Redaction {
            start: 7,
            end: 9,
            kind: "MISC".into(),
            action: RedactionAction::Tokenize,
        }];
        let Outcome::Pass { sanitized } = e.process_with(text, &mut ctx(), &red).unwrap() else {
            panic!()
        };
        assert!(!sanitized.text.contains("Gruber"), "{}", sanitized.text);
    }

    #[test]
    fn detailed_returns_candidate_and_decisions_even_when_blocked() {
        let mut cfg = CoreConfig::from_toml(CFG).unwrap();
        cfg.profiles.get_mut("fast").unwrap().entities.insert(
            "IBAN".into(),
            EntityPolicy {
                action: Action::Block,
                min_confidence: 0.0,
            },
        );
        cfg.profiles
            .get_mut("fast")
            .unwrap()
            .verifier
            .as_mut()
            .unwrap()
            .retry_profile = Some("fast".into());
        let e = Engine::from_config(&cfg, "fast", None, None).unwrap();
        let d = e
            .process_detailed("Konto AT61 1904 3002 3457 3201 bitte", &mut ctx(), &[])
            .unwrap();
        assert!(matches!(d.outcome, Outcome::Blocked { .. }));
        let c = d.candidate.expect("candidate kept for inspection");
        assert!(
            c.text.contains("AT61"),
            "a Block action leaves the text in place"
        );
        assert_eq!(d.decisions.len(), 1);
        assert_eq!(d.decisions[0].action, Action::Block);
        assert!(!d.retried);
        assert_eq!(d.profile, "fast");
        let d = engine()
            .process_detailed("IBAN AT61 1904 3002 3457 3201", &mut ctx(), &[])
            .unwrap();
        assert!(matches!(d.outcome, Outcome::Pass { .. }));
        assert!(d.candidate.unwrap().text.contains("<IBAN_"));
    }

    /// M4 spec §16.5 through the whole pipeline: variants share the token,
    /// the text restores to the first-listed name, the leak check sees a
    /// variant left in clear.
    #[test]
    fn alias_variants_share_a_token_through_the_engine() {
        use crate::rehydrate::Rehydrator;
        let dir = tempfile::tempdir().unwrap();
        let persons = dir.path().join("persons.txt");
        std::fs::write(&persons, "Hans-Peter Gruber | HP Gruber | Hansi\n").unwrap();
        let cfg = CoreConfig::from_toml(&format!(
            "[dictionary]\npersons = [\"{}\"]\n[profiles.fast]\ndefault_action = \"tokenize\"\n[profiles.fast.entities.SECRET]\naction = \"remove\"\nmin_confidence = 0.0\n[profiles.fast.verifier]\nallow_no_ner = true\n",
            persons.display()
        ))
        .unwrap();
        let e = Engine::from_config(&cfg, "fast", None, None).unwrap();
        assert_eq!(e.aliases().len(), 1);
        let mut c = ctx();
        let text = "Hans-Peter Gruber kommt. HP Gruber bringt Hansi mit.";
        let Outcome::Pass { sanitized } = e.process(text, &mut c).unwrap() else {
            panic!("expected pass")
        };
        let tokens: Vec<&str> = sanitized
            .text
            .split(|ch: char| ch.is_whitespace() || ch == '.')
            .filter(|w| w.starts_with("<PERSON_"))
            .collect();
        assert_eq!(tokens.len(), 3, "{}", sanitized.text);
        let settings = TokenSettings::default();
        let parsed: Vec<_> = tokens
            .iter()
            .map(|t| crate::token::parse_token(&settings, t).unwrap())
            .collect();
        assert!(
            parsed.iter().all(|p| p.suffix == parsed[0].suffix),
            "variants share the entity suffix: {}",
            sanitized.text
        );
        assert!(parsed[0].variant.is_none(), "the canonical is the entity");
        assert!(parsed[1].variant.is_some() && parsed[2].variant.is_some());
        assert_ne!(parsed[1].variant, parsed[2].variant);
        assert_eq!(c.len(), 3);
        let (back, unknown) =
            Rehydrator::new(&TokenSettings::default()).rehydrate(&sanitized.text, &c);
        assert_eq!(unknown, 0);
        assert_eq!(back, text, "each variant restores to its own surface form");
        // without alias groups the engine behaves exactly as before
        let plain = CoreConfig::from_toml(
            "[profiles.fast]\ndefault_action = \"tokenize\"\n[profiles.fast.entities.SECRET]\naction = \"remove\"\nmin_confidence = 0.0\n[profiles.fast.verifier]\nallow_no_ner = true\n",
        )
        .unwrap();
        let e = Engine::from_config(&plain, "fast", None, None).unwrap();
        assert!(e.aliases().is_empty());
    }

    /// Finds every occurrence of one full name as a PERSON (a stand-in NER).
    struct FindPerson(&'static str);
    impl Detector for FindPerson {
        fn id(&self) -> crate::span::DetectorId {
            crate::span::DetectorId::Ner
        }
        fn detect(&self, text: &str, _: &DetectCtx) -> Result<Vec<Span>> {
            Ok(text
                .match_indices(self.0)
                .map(|(i, m)| {
                    Span::new(
                        i,
                        i + m.len(),
                        EntityKind::Person,
                        0.9,
                        crate::span::DetectorId::Ner,
                    )
                })
                .collect())
        }
    }

    fn linking_engine(extra: &str, ner: &'static str) -> Engine {
        let cfg = CoreConfig::from_toml(&format!("{extra}\n{CFG}")).unwrap();
        Engine::from_config(&cfg, "fast", Some(Arc::new(FindPerson(ner))), None).unwrap()
    }

    /// Plan 4a, Review Focus 1 end to end: the engine links bare mentions,
    /// mints surface tokens, never leaves the ambiguous or bare part in
    /// clear, and rehydration is exact.
    #[test]
    fn engine_links_bare_mentions_and_restores_exactly() {
        use crate::rehydrate::Rehydrator;
        use crate::token::parse_token;
        let e = linking_engine("", "Sarah Leitner");
        assert!(e.linking().enabled && e.linking().anchors);
        let mut c = ctx();
        let text = "Sehr geehrte Damen und Herren,\n\nSarah Leitner hat angerufen. Leitner bittet um Rückruf.\n\nLG Sarah";
        let Outcome::Pass { sanitized } = e.process(text, &mut c).unwrap() else {
            panic!("expected pass")
        };
        let toks: Vec<&str> = sanitized
            .replacements
            .iter()
            .map(|r| r.token.as_ref().unwrap().as_str())
            .collect();
        assert_eq!(toks.len(), 3, "{}", sanitized.text);
        let parsed: Vec<_> = toks
            .iter()
            .map(|t| parse_token(c.settings(), t).unwrap())
            .collect();
        assert!(
            parsed.iter().all(|p| p.suffix == parsed[0].suffix),
            "one entity: {toks:?}"
        );
        assert!(
            parsed[0].variant.is_none()
                && parsed[1].variant.is_some()
                && parsed[2].variant.is_some()
                && parsed[1].variant != parsed[2].variant,
            "{toks:?}"
        );
        assert!(!sanitized.text.contains("Sarah") && !sanitized.text.contains("Leitner"));
        assert!(
            sanitized.text.contains("Damen und Herren"),
            "group greeting stays"
        );
        let (back, unknown) = Rehydrator::new(c.settings()).rehydrate(&sanitized.text, &c);
        assert_eq!((back.as_str(), unknown), (text, 0));
        // detect() reports the linked mentions too (recall counts them)
        let spans = e.detect(text).unwrap();
        assert_eq!(
            spans
                .iter()
                .filter(|s| s.kind == EntityKind::Person)
                .count(),
            3
        );
        assert!(
            spans
                .iter()
                .any(|s| s.source == crate::span::DetectorId::Link)
        );
        // two people share the first name: the sign-off is its own entity,
        // tokenized, never clear and never linked to either
        let text = "Sarah Leitner und Sarah Gruber kommen.\n\nLG Sarah";
        let two = linking_engine("", "Sarah Leitner");
        let two = two.with_detector(Arc::new(FindPerson("Sarah Gruber")));
        let mut c = ctx();
        let Outcome::Pass { sanitized } = two.process(text, &mut c).unwrap() else {
            panic!("expected pass")
        };
        assert!(
            !sanitized.text.contains("Sarah") && !sanitized.text.contains("Gruber"),
            "{}",
            sanitized.text
        );
        let sarah = sanitized
            .replacements
            .last()
            .unwrap()
            .token
            .clone()
            .unwrap();
        let sarah = parse_token(c.settings(), sarah.as_str()).unwrap();
        let others: Vec<String> = sanitized.replacements[..2]
            .iter()
            .map(|r| r.token.clone().unwrap().as_str().to_string())
            .collect();
        for o in &others {
            assert_ne!(parse_token(c.settings(), o).unwrap().suffix, sarah.suffix);
        }
    }

    /// Ruling L53 (1): a town after a postal code yields to a known name
    /// part. With `Max Gruber` in the store, `10234 Gruber.` is the linked
    /// PERSON (a surface token of the same entity), never a CITY.
    #[test]
    fn a_regex_town_yields_to_a_known_name_part() {
        use crate::token::parse_token;
        let e = linking_engine("", "Max Gruber");
        let mut c = ctx();
        let Outcome::Pass { .. } = e.process("Max Gruber hat angerufen.", &mut c).unwrap() else {
            panic!("expected pass")
        };
        let text = "Rückfrage zur Lieferung:\n10234 Gruber.";
        let Outcome::Pass { sanitized } = e.process(text, &mut c).unwrap() else {
            panic!("expected pass")
        };
        assert!(!sanitized.text.contains("Gruber"));
        let g = text.find("Gruber").unwrap();
        let r = sanitized
            .replacements
            .iter()
            .find(|r| r.span.start <= g && g < r.span.end)
            .expect("Gruber is replaced");
        assert_eq!(r.span.kind, EntityKind::Person);
        let tok = parse_token(c.settings(), r.token.as_ref().unwrap().as_str()).unwrap();
        assert!(tok.variant.is_some(), "a surface token of the known entity");
        // In one text the linker takes the word from the town.
        let text = "Max Gruber hat angerufen.\n10234 Gruber.";
        let spans = e.detect(text).unwrap();
        let g = text.rfind("Gruber").unwrap();
        assert!(spans.iter().any(|s| s.kind == EntityKind::Person
            && s.source == crate::span::DetectorId::Link
            && (s.start, s.end) == (g, g + 6)));
        assert!(!spans.iter().any(|s| s.kind == EntityKind::City));
    }

    /// Ruling L53 (3): `detect_nfc` lets a model PERSON win over the regex
    /// town before overlap resolution, where the regex source priority
    /// would otherwise keep the CITY.
    #[test]
    fn a_model_person_wins_over_a_regex_town_in_detection() {
        let cfg = CoreConfig::from_toml(CFG).unwrap();
        let e = Engine::from_config(&cfg, "fast", Some(Arc::new(GruberNer)), None).unwrap();
        let text = "Hauptstraße 5\n10234 Gruber.";
        let spans = e.detect(text).unwrap();
        let g = text.find("Gruber").unwrap();
        assert!(
            spans
                .iter()
                .any(|s| s.kind == EntityKind::Person && (s.start, s.end) == (g, g + 6))
        );
        assert!(!spans.iter().any(|s| s.kind == EntityKind::City));
        // Without the model span the regex town stands.
        let spans = engine().detect(text).unwrap();
        assert!(spans.iter().any(|s| s.kind == EntityKind::City));
    }

    #[test]
    fn linking_can_be_disabled_and_anchors_separately() {
        let text = "Sarah Leitner hat angerufen.\n\nLG Sarah";
        let e = linking_engine("[linking]\nenabled = false\n", "Sarah Leitner");
        let o = e.process(text, &mut ctx()).unwrap();
        let Outcome::Pass { sanitized } = o else {
            panic!("{o:?}")
        };
        assert_eq!(
            sanitized.replacements.len(),
            2,
            "anchor still catches the sign-off; no link"
        );
        let e = linking_engine(
            "[linking]\nenabled = false\nanchors = false\n",
            "Sarah Leitner",
        );
        // no detector finds the bare sign-off: the referential-consistency
        // pass tokenizes it as a copy of a store value (plan L3 step 2,
        // Task 4) rather than leaving it for the leak check to block; with
        // linking disabled it is not linked, so it is its own entity
        let mut c = ctx();
        let o = e.process(text, &mut c).unwrap();
        let Outcome::Pass { sanitized } = o else {
            panic!("{o:?}")
        };
        assert!(!sanitized.text.contains("Sarah"), "{}", sanitized.text);
        let hex: Vec<String> = sanitized
            .replacements
            .iter()
            .filter_map(|r| r.token.as_ref())
            .map(|t| {
                crate::token::parse_token(c.settings(), t.as_str())
                    .unwrap()
                    .suffix
                    .to_string()
            })
            .collect();
        assert_eq!(hex.len(), 2);
        assert_ne!(hex[0], hex[1], "linking disabled: no consistency link");
    }

    /// Review Focus 4 at engine level: case mapping that changes byte
    /// lengths (capital sharp s) and combining marks leave offsets valid and
    /// the round trip exact.
    #[test]
    fn linked_mentions_keep_offsets_through_case_mapping_and_nfd_input() {
        use crate::rehydrate::Rehydrator;
        let e = linking_engine("", "Anna Großmann");
        let mut c = ctx();
        let text = "Anna Großmann schreibt.\nFrau GROẞMANN bittet um Rückruf.\n\nLG Anna";
        let Outcome::Pass { sanitized } = e.process(text, &mut c).unwrap() else {
            panic!("expected pass")
        };
        assert!(
            !sanitized.text.contains("GROẞMANN") && !sanitized.text.contains("Anna"),
            "{}",
            sanitized.text
        );
        let (back, unknown) = Rehydrator::new(c.settings()).rehydrate(&sanitized.text, &c);
        assert_eq!((back.as_str(), unknown), (text, 0));
        // NFD input: offsets refer to the NFC form and the text round-trips
        // to it
        let nfd = "Jo\u{0308}rg Mu\u{0308}ller ruft an.\n\nLG Jo\u{0308}rg";
        let e = linking_engine("", "Jörg Müller");
        let mut c = ctx();
        let Outcome::Pass { sanitized } = e.process(nfd, &mut c).unwrap() else {
            panic!("expected pass")
        };
        assert!(
            !sanitized.text.contains('\u{0308}') && !sanitized.text.contains("rg"),
            "{}",
            sanitized.text
        );
        let (back, unknown) = Rehydrator::new(c.settings()).rehydrate(&sanitized.text, &c);
        assert_eq!((back.as_str(), unknown), (normalize_input(nfd).as_ref(), 0));
    }

    /// Review Focus 10: the linker picks the document's full name, which is
    /// an alias variant; the bare surname becomes a surface of the canonical.
    #[test]
    fn alias_variant_full_name_links_a_bare_surname() {
        use crate::rehydrate::Rehydrator;
        use crate::token::parse_token;
        let dir = tempfile::tempdir().unwrap();
        let persons = dir.path().join("persons.txt");
        std::fs::write(&persons, "Hans-Peter Gruber | HP Gruber | Hansi\n").unwrap();
        let cfg = CoreConfig::from_toml(&format!(
            "[dictionary]\npersons = [\"{}\"]\n[profiles.fast]\ndefault_action = \"tokenize\"\n[profiles.fast.entities.SECRET]\naction = \"remove\"\nmin_confidence = 0.0\n[profiles.fast.verifier]\nallow_no_ner = true\n",
            persons.display()
        ))
        .unwrap();
        let e = Engine::from_config(&cfg, "fast", None, None).unwrap();
        let mut c = ctx();
        let text = "HP Gruber ruft an. Herr Gruber bittet um Rückruf.";
        let Outcome::Pass { sanitized } = e.process(text, &mut c).unwrap() else {
            panic!("expected pass, not a discarded batch")
        };
        let toks: Vec<&str> = sanitized
            .replacements
            .iter()
            .map(|r| r.token.as_ref().unwrap().as_str())
            .collect();
        assert_eq!(toks.len(), 2, "{}", sanitized.text);
        let parsed: Vec<_> = toks
            .iter()
            .map(|t| parse_token(c.settings(), t).unwrap())
            .collect();
        assert_eq!(
            parsed[0].suffix, parsed[1].suffix,
            "both are surface forms of the canonical: {toks:?}"
        );
        assert!(parsed[0].variant.is_some() && parsed[1].variant.is_some());
        let (back, unknown) = Rehydrator::new(c.settings()).rehydrate(&sanitized.text, &c);
        assert_eq!((back.as_str(), unknown), (text, 0));
        assert_eq!(c.original(toks[1]), Some("Gruber"));
    }

    /// Plan 4a: the retry pass reuses the links, so the surface tokens of the
    /// first pass and the retry agree and nothing is minted twice.
    #[test]
    fn retry_pass_reuses_links() {
        struct FailOnce(std::sync::atomic::AtomicBool);
        impl Verifier for FailOnce {
            fn verify(&self, _: &Sanitized, _: &dyn TokenStore) -> Verdict {
                if self.0.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    Verdict::Fail(vec![Reason {
                        kind: EntityKind::Person,
                        check: CheckId::Ner,
                    }])
                } else {
                    Verdict::Pass
                }
            }
        }
        let cfg = CoreConfig::from_toml(CFG).unwrap();
        let profile = cfg.resolve_profile("fast").unwrap();
        let retry = cfg.resolve_profile("strict").unwrap();
        let e = Engine::new(
            profile,
            Some(retry),
            vec![Arc::new(FindPerson("Sarah Leitner"))],
            Arc::new(FailOnce(std::sync::atomic::AtomicBool::new(true))),
        );
        let mut c = ctx();
        let d = e
            .process_detailed("Sarah Leitner kam. Frau Leitner ging.", &mut c, &[])
            .unwrap();
        assert!(d.retried);
        let Outcome::Pass { sanitized } = d.outcome else {
            panic!()
        };
        assert_eq!(sanitized.replacements.len(), 2);
        assert_eq!(
            c.len(),
            2,
            "the retry reused the same entity and surface row"
        );
        assert_eq!(d.links.document, 1);
    }

    /// A bare identifier no detector found fails the verifier's re-scan, so
    /// the retry profile runs (and, finding nothing either, blocks).
    #[test]
    fn surviving_bare_identifier_triggers_the_retry_and_blocks() {
        let e = engine();
        let d = e
            .process_detailed("Bitte Ticket V-482913 bearbeiten.", &mut ctx(), &[])
            .unwrap();
        assert!(d.retried, "the strict retry ran");
        let Outcome::Blocked { reasons, .. } = d.outcome else {
            panic!("{:?}", d.outcome)
        };
        assert!(reasons.iter().all(|r| r.check == CheckId::Regex));
    }

    /// Decision 4 at engine level: with the default config a stale store
    /// candidate is not linked (`window == 0`) and the bare name gets its own
    /// entity token; the first-name flag links it as a surface of the stored
    /// entity.
    #[test]
    fn stale_store_candidates_are_not_linked_by_default() {
        use crate::token::parse_token;
        let text = "Danke für die Antwort.\n\nLG Sarah";
        let run = |extra: &str| {
            let cfg = CoreConfig::from_toml(&format!("{extra}\n{CFG}")).unwrap();
            let e = Engine::from_config(&cfg, "fast", Some(Arc::new(SilentNer)), None).unwrap();
            let mut c = ctx();
            let parent = c
                .token_for(&EntityKind::Person, "Sarah Leitner")
                .unwrap()
                .as_str()
                .to_string();
            let d = e.process_detailed(text, &mut c, &[]).unwrap();
            let Outcome::Pass { sanitized } = d.outcome else {
                panic!("expected pass")
            };
            let tok = sanitized.replacements[0].token.clone().unwrap();
            let same_entity = parse_token(c.settings(), tok.as_str()).unwrap().suffix
                == parse_token(c.settings(), &parent).unwrap().suffix;
            (d.links.window, same_entity, sanitized.text)
        };
        let (window, same, out) = run("");
        assert_eq!((window, same), (0, false), "{out}");
        assert!(!out.contains("Sarah"));
        let (window, same, _) = run("[linking]\nfirst_names_across_requests = true\n");
        assert_eq!((window, same), (1, true));
    }

    /// A store that knows `Thomas Gruber` gives the dictionary a `Gruber`
    /// surname hit; it must not split the NER span `Sarah Gruber`, or the
    /// linker would see one `Sarah X` in the document and link the sign-off
    /// to it. Two candidates share `Sarah`: the sign-off is its own entity.
    #[test]
    fn dictionary_surname_does_not_split_a_longer_name_or_defeat_ambiguity() {
        use crate::token::parse_token;
        let dir = tempfile::tempdir().unwrap();
        let persons = dir.path().join("persons.txt");
        std::fs::write(&persons, "Thomas Gruber\n").unwrap();
        let cfg = CoreConfig::from_toml(&format!(
            "[dictionary]\npersons = [\"{}\"]\n{CFG}",
            persons.display()
        ))
        .unwrap();
        let e = Engine::from_config(
            &cfg,
            "fast",
            Some(Arc::new(FindPerson("Sarah Leitner"))),
            None,
        )
        .unwrap()
        .with_detector(Arc::new(FindPerson("Sarah Gruber")));
        let text = "Sarah Leitner und Sarah Gruber haben beide unterschrieben.\n\nLG Sarah";
        let spans = e.detect(text).unwrap();
        let person: Vec<&str> = spans
            .iter()
            .filter(|s| s.kind == EntityKind::Person)
            .map(|s| s.slice(text))
            .collect();
        assert_eq!(person, ["Sarah Leitner", "Sarah Gruber", "Sarah"]);
        let mut c = ctx();
        let Outcome::Pass { sanitized } = e.process(text, &mut c).unwrap() else {
            panic!("expected pass")
        };
        assert!(!sanitized.text.contains("Sarah") && !sanitized.text.contains("Gruber"));
        let suffixes: Vec<String> = sanitized
            .replacements
            .iter()
            .map(|r| {
                let t = r.token.clone().unwrap();
                parse_token(c.settings(), t.as_str())
                    .unwrap()
                    .suffix
                    .to_string()
            })
            .collect();
        assert_eq!(suffixes.len(), 3, "{}", sanitized.text);
        assert!(
            suffixes[2] != suffixes[0] && suffixes[2] != suffixes[1] && suffixes[0] != suffixes[1],
            "the sign-off is its own entity: {}",
            sanitized.text
        );
    }

    /// The batch scope is tier 2: it links when the document has no
    /// candidate, and `Detailed.links` says so (the service never caches a
    /// block that depended on it).
    #[test]
    fn batch_scope_links_and_is_reported_in_detailed() {
        use crate::link::LinkScope;
        let e = engine();
        let text = "Danke für die Antwort.\n\nLG Sarah";
        let mut scope = LinkScope::empty();
        scope.push("Sarah Leitner");
        let mut c = ctx();
        let d = e.process_scoped(text, &mut c, &[], &scope).unwrap();
        assert_eq!(
            d.links,
            LinkTiers {
                document: 0,
                batch: 1,
                window: 0
            }
        );
        assert!(d.links.cross_request());
        let Outcome::Pass { sanitized } = d.outcome else {
            panic!()
        };
        assert!(!sanitized.text.contains("Sarah"), "{}", sanitized.text);
        // the empty scope: the same sign-off is its own entity, no link
        let d = e.process_detailed(text, &mut ctx(), &[]).unwrap();
        assert_eq!(d.links, LinkTiers::default());
    }

    /// A token already in the text (resolves in the store) stays intact: the
    /// linker neither re-tokenizes inside it nor links through it, while a
    /// bare mention elsewhere links to the token's entity (store tier with
    /// the first-name flag on) and the text round-trips.
    #[test]
    fn linking_leaves_resolvable_tokens_intact_and_links_the_bare_mention() {
        use crate::rehydrate::Rehydrator;
        use crate::token::parse_token;
        let cfg = CoreConfig::from_toml(&format!(
            "[linking]\nfirst_names_across_requests = true\n{CFG}"
        ))
        .unwrap();
        let e = Engine::from_config(&cfg, "fast", Some(Arc::new(SilentNer)), None).unwrap();
        let mut c = ctx();
        let t = c
            .token_for(&EntityKind::Person, "Sarah Leitner")
            .unwrap()
            .as_str()
            .to_string();
        let text = format!("Hallo {t} hat angerufen.\n\nLG Sarah");
        let d = e.process_detailed(&text, &mut c, &[]).unwrap();
        assert_eq!(
            d.links.window, 1,
            "the bare mention links through the store"
        );
        let Outcome::Pass { sanitized } = d.outcome else {
            panic!("expected pass")
        };
        assert_eq!(
            sanitized.text.matches(t.as_str()).count(),
            1,
            "the existing token is intact: {}",
            sanitized.text
        );
        assert!(!sanitized.text.contains("Sarah"), "{}", sanitized.text);
        assert_eq!(sanitized.replacements.len(), 1, "only the bare mention");
        let surface = sanitized.replacements[0].token.clone().unwrap();
        let parent = parse_token(c.settings(), &t).unwrap();
        let surface = parse_token(c.settings(), surface.as_str()).unwrap();
        assert_eq!(surface.suffix, parent.suffix);
        assert!(surface.variant.is_some());
        let (back, unknown) = Rehydrator::new(c.settings()).rehydrate(&sanitized.text, &c);
        assert_eq!(unknown, 0);
        assert_eq!(back, text.replace(&t, "Sarah Leitner"));
    }

    #[test]
    fn store_error_discards_everything() {
        let e = engine();
        let err = e
            .process(
                "IBAN AT61 1904 3002 3457 3201 bitte",
                &mut FailingStore(ctx()),
            )
            .unwrap_err();
        assert_eq!(err, StoreError::Unavailable);
        // text without anything to tokenize never touches the store
        assert!(matches!(
            e.process("nur Text", &mut FailingStore(ctx())),
            Ok(Outcome::Pass { .. })
        ));
    }

    // Task 4: the referential-consistency pass (Review Focus 4).

    /// Reports only the first occurrence of a needle, as a given kind.
    struct FirstOnly(&'static str, EntityKind);
    impl Detector for FirstOnly {
        fn id(&self) -> crate::span::DetectorId {
            crate::span::DetectorId::Ner
        }
        fn detect(&self, text: &str, _: &DetectCtx) -> Result<Vec<Span>> {
            Ok(text
                .find(self.0)
                .map(|i| {
                    vec![Span::new(
                        i,
                        i + self.0.len(),
                        self.1.clone(),
                        0.9,
                        crate::span::DetectorId::Ner,
                    )]
                })
                .unwrap_or_default())
        }
    }

    fn first_only_engine(needle: &'static str, kind: EntityKind) -> Engine {
        let cfg = CoreConfig::from_toml(CFG).unwrap();
        Engine::from_config(&cfg, "fast", Some(Arc::new(FirstOnly(needle, kind))), None).unwrap()
    }

    /// Review Focus 4: a second, differently cased copy of a value the pass
    /// minted is tokenized with the same entity, not left for the leak check.
    #[test]
    fn second_copy_of_a_minted_value_is_tokenized_in_the_same_text() {
        let e = first_only_engine("Zebrafink", EntityKind::custom("PROJECT_NAME"));
        let mut c = ctx();
        let text = "Projekt Zebrafink startet. Rückfragen zu ZEBRAFINK an mich.";
        let Outcome::Pass { sanitized } = e.process(text, &mut c).unwrap() else {
            panic!("expected pass")
        };
        assert!(
            !sanitized.text.to_lowercase().contains("zebrafink"),
            "{}",
            sanitized.text
        );
        let toks: Vec<_> = sanitized
            .replacements
            .iter()
            .filter_map(|r| r.token.as_ref())
            .collect();
        assert_eq!(toks.len(), 2);
        let p: Vec<_> = toks
            .iter()
            .map(|t| {
                crate::token::parse_token(c.settings(), t.as_str())
                    .unwrap()
                    .suffix
                    .to_string()
            })
            .collect();
        assert_eq!(p[0], p[1], "one entity, one suffix");
    }

    /// RED on afa0422 (Blocked [Leak PERSON]); the linker skips a
    /// lower-case word in mixed-case text.
    #[test]
    fn lower_case_name_part_in_mixed_text_is_tokenized() {
        let e = linking_engine("", "Sarah Leitner");
        let mut c = ctx();
        let text = "Sarah Leitner hat angerufen. Bitte leitner morgen zurückrufen.";
        let Outcome::Pass { sanitized } = e.process(text, &mut c).unwrap() else {
            panic!("expected pass")
        };
        assert!(
            !sanitized.text.to_lowercase().contains("leitner"),
            "{}",
            sanitized.text
        );
        // N1: the part is linked to its single store original: same token hex
        let hex = |t: &str| {
            crate::token::parse_token(c.settings(), t)
                .unwrap()
                .suffix
                .to_string()
        };
        let toks: Vec<String> = sanitized
            .replacements
            .iter()
            .filter_map(|r| r.token.as_ref())
            .map(|t| hex(t.as_str()))
            .collect();
        assert_eq!(toks.len(), 2, "{}", sanitized.text);
        assert_eq!(
            toks[0], toks[1],
            "the part shares Sarah Leitner's token hex"
        );
    }

    /// N1: a part two store people share is tokenized as its own entity,
    /// never linked to one of them.
    #[test]
    fn ambiguous_part_is_tokenized_but_not_linked() {
        let e = linking_engine("", "Sarah Leitner");
        let mut c = ctx();
        let max = c.token_for(&EntityKind::Person, "Max Leitner").unwrap();
        let text = "Sarah Leitner hat angerufen. Bitte leitner morgen zurückrufen.";
        let Outcome::Pass { sanitized } = e.process(text, &mut c).unwrap() else {
            panic!("expected pass")
        };
        assert!(
            !sanitized.text.to_lowercase().contains("leitner"),
            "{}",
            sanitized.text
        );
        let hex = |t: &str| {
            crate::token::parse_token(c.settings(), t)
                .unwrap()
                .suffix
                .to_string()
        };
        let sarah = hex(sanitized.replacements[0].token.as_ref().unwrap().as_str());
        let part = sanitized
            .replacements
            .iter()
            .filter_map(|r| r.token.as_ref())
            .next_back()
            .unwrap();
        assert_ne!(hex(part.as_str()), sarah);
        assert_ne!(hex(part.as_str()), hex(max.as_str()));
    }

    /// Review Focus 4: a value the store already holds (an earlier text of
    /// the same context) is tokenized with its existing token in a later
    /// text that no detector flags. RED on afa0422 (Blocked [Leak PERSON]).
    #[test]
    fn store_value_from_an_earlier_text_is_tokenized_with_its_token() {
        let e = linking_engine("", "Sarah Leitner");
        let mut c = ctx();
        let Outcome::Pass { sanitized: first } =
            e.process("Sarah Leitner hat angerufen.", &mut c).unwrap()
        else {
            panic!()
        };
        let tok = first.replacements[0].token.clone().unwrap();
        let Outcome::Pass { sanitized } = e
            .process("Ein Rückruf an Sarah  LEITNER folgt.", &mut c)
            .unwrap()
        else {
            panic!("expected pass")
        };
        assert!(
            !sanitized.text.to_lowercase().contains("leitner"),
            "{}",
            sanitized.text
        );
        let suffix = |t: &str| {
            crate::token::parse_token(c.settings(), t)
                .unwrap()
                .suffix
                .to_string()
        };
        assert!(
            sanitized
                .replacements
                .iter()
                .filter_map(|r| r.token.as_ref())
                .any(|t| suffix(t.as_str()) == suffix(tok.as_str()))
        );
    }

    /// Review Focus 4 (ruling C1): a CITY or ORGANIZATION value already in
    /// the store (a retry profile tokenized it) that appears in clear in a
    /// later text under a profile that preserves the kind ends tokenized
    /// with the existing token. RED on afa0422: Blocked [Leak CITY, Leak
    /// ORGANIZATION].
    #[test]
    fn preserved_kind_store_values_are_tokenized_with_their_existing_token() {
        let cfg = CoreConfig::from_toml(&format!(
            "{CFG}\n[profiles.fast.entities.ORGANIZATION]\naction = \"preserve\"\nmin_confidence = 0.0\n"
        ))
        .unwrap();
        let e = Engine::from_config(&cfg, "fast", None, None).unwrap();
        let mut c = ctx();
        let wien = c.token_for(&EntityKind::City, "Wien").unwrap();
        let muster = c
            .token_for(&EntityKind::Organization, "Muster GmbH")
            .unwrap();
        let text = "Ich wohne in Wien, Kunde bei Muster GmbH.";
        let Outcome::Pass { sanitized } = e.process(text, &mut c).unwrap() else {
            panic!("expected pass")
        };
        assert!(
            !sanitized.text.contains("Wien") && !sanitized.text.contains("Muster GmbH"),
            "{}",
            sanitized.text
        );
        assert!(
            sanitized.text.contains(wien.as_str()) && sanitized.text.contains(muster.as_str()),
            "{}",
            sanitized.text
        );
    }

    /// Text whose lower-casing changes byte length (`İ`). A guard for the
    /// prototype's shortcut: the dictionary must match case variants
    /// without byte arithmetic on lower-cased text.
    #[test]
    fn consistency_pass_handles_text_whose_lower_case_changes_byte_length() {
        let e = first_only_engine("İlker Yılmaz", EntityKind::Person);
        let mut c = ctx();
        let text = "İlker Yılmaz schreibt. Gruß an İLKER und ilker.";
        let Outcome::Pass { sanitized } = e.process(text, &mut c).unwrap() else {
            panic!("expected pass")
        };
        assert!(
            !sanitized.text.contains("İLKER") && !sanitized.text.contains("ilker"),
            "{}",
            sanitized.text
        );
    }

    /// N2: when the store dictionary cannot be built, the engine blocks
    /// with `DetectorError`, without a retry and without a candidate.
    #[test]
    fn store_dictionary_failure_blocks_without_retry() {
        let e = linking_engine("", "Sarah Leitner");
        let mut c = ctx();
        crate::consistency::fail_builds_on_this_thread(true);
        let d = e
            .process_detailed("Sarah Leitner hat angerufen.", &mut c, &[])
            .unwrap();
        crate::consistency::fail_builds_on_this_thread(false);
        assert!(!d.retried, "no retry after a consistency failure");
        assert!(d.candidate.is_none());
        detector_error_block(d.outcome);
    }

    /// N4: the settling pass reports how many clear copies it folded in.
    #[test]
    fn detailed_counts_consistency_redactions() {
        let e = first_only_engine("Zebrafink", EntityKind::custom("PROJECT_NAME"));
        let d = e
            .process_detailed("Zebrafink und ZEBRAFINK und zebrafink.", &mut ctx(), &[])
            .unwrap();
        assert!(matches!(d.outcome, Outcome::Pass { .. }), "{:?}", d.outcome);
        assert_eq!(d.consistency, 2);
        // Task 4 follow-up: the source is tokenized from this very text, so
        // the links rest on the text alone (`Document`) and the result may
        // be cached.
        assert_eq!(d.links.document, 2, "both copies linked to the value");
        assert_eq!(d.links.window, 0);
        assert!(!d.links.cross_request());
    }

    /// Task 4 follow-up: a copy whose source exists only in the store (minted
    /// by an earlier text) is linked at `Window` and marks the result
    /// cross-request, so the service never caches it.
    #[test]
    fn a_consistency_link_to_a_store_only_value_stays_window() {
        let e = first_only_engine("Zebrafink", EntityKind::custom("PROJECT_NAME"));
        let mut c = ctx();
        let first = e
            .process_detailed("Zebrafink startet.", &mut c, &[])
            .unwrap();
        assert!(
            matches!(first.outcome, Outcome::Pass { .. }),
            "{:?}",
            first.outcome
        );
        let d = e
            .process_detailed("Rückfragen zu ZEBRAFINK an mich.", &mut c, &[])
            .unwrap();
        let Outcome::Pass { sanitized } = &d.outcome else {
            panic!("expected pass, got {:?}", d.outcome)
        };
        assert!(!sanitized.text.contains("ZEBRAFINK"), "{}", sanitized.text);
        assert_eq!(d.consistency, 1);
        assert_eq!(d.links.window, 1);
        assert_eq!(d.links.document, 0);
        assert!(d.links.cross_request());
    }

    /// Task 4 fix round 1 (L30): a known-entity fragment (a dataset store's
    /// bare `Hauptstraße`, reported by a dictionary detector) must not cut
    /// the street regex's whole address in two and leave `Wiedner` and the
    /// house number in clear.
    #[test]
    fn known_street_fragment_does_not_split_the_whole_address() {
        let known =
            DictionaryDetector::from_entries([(EntityKind::StreetAddress, "Hauptstraße")]).unwrap();
        let e = engine().with_detector(Arc::new(known));
        let text = "my neighbour from Wiedner Hauptstraße 61 keeps receiving my mail.";
        let mut c = ctx();
        let Outcome::Pass { sanitized } = e.process(text, &mut c).unwrap() else {
            panic!("expected pass")
        };
        let masked = mask_test_token_suffixes(&sanitized.text);
        assert!(
            !masked.contains("Wiedner") && !masked.contains("61"),
            "{}",
            sanitized.text
        );
        let streets: Vec<&str> = sanitized
            .replacements
            .iter()
            .filter(|r| r.span.kind == EntityKind::StreetAddress)
            .map(|r| r.span.slice(text))
            .collect();
        assert_eq!(streets, ["Wiedner Hauptstraße 61"]);
    }

    /// Replace the characters between the last `_` and `>` of every
    /// `<KIND_xxxx>` token with `#`, so assertions on the surrounding text are
    /// not tripped by the random suffix.
    fn mask_test_token_suffixes(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(open) = rest.find('<') {
            out.push_str(&rest[..open]);
            let tail = &rest[open..];
            match tail.find('>') {
                Some(close) => {
                    let token = &tail[..close];
                    match token.rfind('_') {
                        Some(us) => {
                            out.push_str(&token[..=us]);
                            out.push_str(&"#".repeat(token.len() - us - 1));
                        }
                        None => out.push_str(token),
                    }
                    out.push('>');
                    rest = &tail[close + 1..];
                }
                None => {
                    out.push_str(tail);
                    rest = "";
                }
            }
        }
        out.push_str(rest);
        out
    }

    /// Ruling L30 (b): the same known value standing alone elsewhere in the
    /// text still gets its stored token; only the fragment inside the whole
    /// address yields.
    #[test]
    fn known_street_value_standing_alone_keeps_its_stored_token() {
        let known =
            DictionaryDetector::from_entries([(EntityKind::StreetAddress, "Hauptstraße")]).unwrap();
        let e = engine().with_detector(Arc::new(known));
        let mut c = ctx();
        let stored = c
            .token_for(&EntityKind::StreetAddress, "Hauptstraße")
            .unwrap();
        let text = "Ich wohne in der Wiedner Hauptstraße 61. Die Hauptstraße ist gesperrt.";
        let Outcome::Pass { sanitized } = e.process(text, &mut c).unwrap() else {
            panic!("expected pass")
        };
        // Mask the random hex suffix of each `<KIND_xxxx>` token first: it can
        // legitimately contain "61".
        let masked = mask_test_token_suffixes(&sanitized.text);
        assert!(
            !masked.contains("Wiedner") && !masked.contains("61"),
            "{}",
            sanitized.text
        );
        let streets: Vec<(&str, String)> = sanitized
            .replacements
            .iter()
            .filter(|r| r.span.kind == EntityKind::StreetAddress)
            .map(|r| {
                (
                    r.span.slice(text),
                    r.token.clone().unwrap().as_str().to_string(),
                )
            })
            .collect();
        assert_eq!(streets.len(), 2, "{}", sanitized.text);
        assert_eq!(streets[0].0, "Wiedner Hauptstraße 61");
        assert_eq!(streets[1], ("Hauptstraße", stored.as_str().to_string()));
        assert_ne!(streets[0].1, stored.as_str());
    }

    /// Integrator ruling (review risk 6): a known full name inside a longer
    /// PERSON span the policy tokenizes takes the container's token, not
    /// the stored one, and rehydration restores the original text exactly.
    #[test]
    fn known_name_inside_an_accepted_person_span_takes_its_token_and_round_trips() {
        use crate::rehydrate::Rehydrator;
        let known = DictionaryDetector::from_entries([(EntityKind::Person, "Max Berg")]).unwrap();
        let e = linking_engine("", "Max Berg Kundenservice").with_detector(Arc::new(known));
        let mut c = ctx();
        let stored = c.token_for(&EntityKind::Person, "Max Berg").unwrap();
        let text = "Bitte Max Berg Kundenservice morgen anrufen.";
        let Outcome::Pass { sanitized } = e.process(text, &mut c).unwrap() else {
            panic!("expected pass")
        };
        let persons: Vec<_> = sanitized
            .replacements
            .iter()
            .filter(|r| r.span.kind == EntityKind::Person)
            .collect();
        assert_eq!(persons.len(), 1, "{}", sanitized.text);
        assert_eq!(persons[0].span.slice(text), "Max Berg Kundenservice");
        let token = persons[0].token.as_ref().unwrap();
        assert_ne!(token.as_str(), stored.as_str(), "the container's own token");
        assert!(!sanitized.text.contains("Max") && !sanitized.text.contains("Berg"));
        let (back, unknown) = Rehydrator::new(c.settings()).rehydrate(&sanitized.text, &c);
        assert_eq!(unknown, 0);
        assert_eq!(back.as_bytes(), text.as_bytes(), "byte-equal round trip");
    }
}
