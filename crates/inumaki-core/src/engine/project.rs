//! Closure projection (M8 spec §20 and engine spec §6.5, amendments of
//! 2026-10-12): one consistency round over an already forwarded, cached
//! sanitized text, checked deterministically on a dry pass before any mint.
//! Privacy: every working copy of the input is `Zeroizing`; `Debug` prints
//! counts only; `Abandon` carries no payload.

use std::fmt;
use std::ops::{Deref, Range};
use std::time::Duration;

use zeroize::{Zeroize, Zeroizing};

use super::{Engine, current_store_dict, merge_redaction};
use crate::alias::{AliasTable, Aliased};
use crate::consistency::{StoreDict, StoreMatch};
use crate::detect::regex::RegexDetector;
use crate::detect::{DetectCtx, Detector, validate_span};
use crate::link::{LinkTier, Links};
use crate::policy::{Action, Decision, VerifierSettings};
use crate::redact::RedactionAction;
use crate::rehydrate::Rehydrator;
use crate::sanitize::{Replacement, Sanitized, sanitize_linked};
use crate::span::{DetectorId, EntityKind, Span};
use crate::token::{
    StoreError, SurfaceForm, Token, TokenStore, format_token, parse_token, token_label,
};
use crate::verify::{CheckId, LeakIndex, SecondPassVerifier, Verdict, Verifier};

/// Why a projection was abandoned. Fixed, no payload (S7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Abandon {
    /// The linker's recency-window tier is on: it reads the store, so a
    /// full re-run could link a mention the projection cannot see.
    WindowLinking,
    /// The text is not NFC.
    NotNfc,
    /// A token-shaped substring of the text is not a real token.
    ForgedToken,
    /// No store value is in clear in the text.
    Empty,
    /// A replaced slice holds a sentence boundary.
    SentenceMerge,
    /// The dry result holds a clear byte the input lacked.
    Invariant,
    /// The verifier's leak check still sees a store value.
    Leak,
    /// The verifier's regex re-scan found a span not in clear in the input.
    Regex,
    /// The combination heuristic flagged the dry result.
    Combination,
    /// The caller's check said no.
    Caller,
    /// A dictionary, detector, verifier, or caller check could not run.
    Error,
}

/// The result of [`Engine::project`]. `Debug` prints lengths and counts.
pub enum Projection {
    /// Forwardable. `replaced`: input ranges and kinds of the new
    /// replacements (positions, no text). `minted`: store growth.
    Projected {
        /// The projected text.
        text: String,
        /// Input ranges and kinds of the replacements.
        replaced: Vec<(Range<usize>, EntityKind)>,
        /// How many entries and removed values the store gained.
        minted: usize,
    },
    /// Nothing was minted. `absorbed`: mint calls the dry overlay
    /// absorbed (an overcount: a lookup of an existing value counts too).
    Abandoned {
        /// Why.
        reason: Abandon,
        /// Mint calls the dry overlay absorbed.
        absorbed: usize,
    },
    /// Phase 2 disagreed with phase 1: a bug. The caller fails closed.
    Inconsistent,
}

impl fmt::Debug for Projection {
    /// The variant, lengths, and counts; never text, a token, or a kind.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Projection::Projected {
                text,
                replaced,
                minted,
            } => f
                .debug_struct("Projected")
                .field("text_len", &text.len())
                .field("replaced", &replaced.len())
                .field("minted", minted)
                .finish(),
            Projection::Abandoned { reason, absorbed } => f
                .debug_struct("Abandoned")
                .field("reason", reason)
                .field("absorbed", absorbed)
                .finish(),
            Projection::Inconsistent => f.write_str("Inconsistent"),
        }
    }
}

/// The caller's check on the dry result: `(text, token ranges)` →
/// `Ok(true)` clean, `Ok(false)` abandon, `Err(())` abandon (error).
pub type CallerCheck<'a> = dyn Fn(&str, &[Range<usize>]) -> Result<bool, ()> + 'a;

/// The deterministic verifier and regex detector of a projection. Holds no
/// originals.
pub(crate) struct ProjectionKit {
    verifier: SecondPassVerifier,
    regex: RegexDetector,
}

/// Per-request scratch shared by every `project` call of one request:
/// the token regex (`Rehydrator::pattern(store.settings())`, built on
/// first use, P6). Never the leak index: that lives on the store (Task 5,
/// L69). `Debug`: counts.
#[derive(Default)]
pub struct ProjectionScratch {
    /// The token regex and the `(open, close)` delimiters it was built for
    /// (ruling F18: the only inputs of `Rehydrator::pattern`).
    tokens: Option<((String, String), regex::Regex)>,
    /// The deterministic verifier and regex detector (no originals), with
    /// the name of the profile whose verifier settings built it.
    kit: Option<(String, ProjectionKit)>,
    /// Test-only (P3): drop the projector's matches of this kind label so a
    /// value stays in clear for the leak check. Never set outside tests.
    #[cfg(test)]
    pub(crate) drop_kind_for_test: Option<&'static str>,
}

impl fmt::Debug for ProjectionScratch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProjectionScratch")
            .field("tokens", &usize::from(self.tokens.is_some()))
            .field("kit", &usize::from(self.kit.is_some()))
            .finish()
    }
}

/// The one real-token rule (moved from the proxy's `closure.rs`): a token
/// `store` resolves, or a removed marker of a built-in kind, or of a custom
/// kind the store holds a value of.
pub fn real_token<S: TokenStore + ?Sized>(store: &S, text: &str) -> bool {
    if store.original(text).is_some() {
        return true;
    }
    let Some(p) = parse_token(store.settings(), text).filter(|p| p.removed) else {
        return false;
    };
    !matches!(EntityKind::from_label(p.label), EntityKind::Custom(_))
        || store
            .entries()
            .chain(store.removed_entries())
            .any(|(k, _)| token_label(k) == p.label)
}

/// The store overlay of phase 1: reads forward, mints are absorbed.
struct Dry<'s> {
    inner: &'s mut dyn TokenStore,
    absorbed: usize,
}

impl TokenStore for Dry<'_> {
    fn token_for(&mut self, kind: &EntityKind, _o: &str) -> Result<Token, StoreError> {
        self.absorbed += 1;
        let s = self.inner.settings();
        Ok(Token::from(format_token(
            s,
            kind,
            &"x".repeat(s.suffix_len),
        )))
    }
    /// The token's shape under `surface_form` (ruling F20): `Derived` adds
    /// a two-character component to the parent, `Independent` is shaped
    /// like an entity token of the parent's label.
    fn surface_token(&mut self, parent: &Token, _s: &str) -> Result<Token, StoreError> {
        self.absorbed += 1;
        let s = self.inner.settings();
        let p = parent.as_str();
        let head = p.strip_suffix(s.close.as_str()).unwrap_or(p);
        let close = &s.close;
        Ok(Token::from(match s.surface_form {
            SurfaceForm::Derived => format!("{head}_xx{close}"),
            SurfaceForm::Independent => {
                let label = head.rsplit_once('_').map_or(head, |(l, _)| l);
                format!("{label}_{}{close}", "x".repeat(s.suffix_len))
            }
        }))
    }
    fn record_removed(&mut self, _k: &EntityKind, _o: &str) -> Result<(), StoreError> {
        self.absorbed += 1;
        Ok(())
    }
    // P10 (b): every other trait method is forwarded explicitly, defaulted
    // ones included, so the overlay answers as the view does.
    fn original(&self, token: &str) -> Option<&str> {
        self.inner.original(token)
    }
    fn entries(&self) -> Box<dyn Iterator<Item = (&EntityKind, &str)> + '_> {
        self.inner.entries()
    }
    fn removed_entries(&self) -> Box<dyn Iterator<Item = (&EntityKind, &str)> + '_> {
        self.inner.removed_entries()
    }
    fn removed_marker(&self, kind: &EntityKind) -> String {
        self.inner.removed_marker(kind)
    }
    fn settings(&self) -> &crate::config::TokenSettings {
        self.inner.settings()
    }
    fn prepare(&mut self, tokens: &[String]) -> Result<(), StoreError> {
        self.inner.prepare(tokens)
    }
    fn link_candidates(&self, kind: &EntityKind, window: Duration) -> Vec<Zeroizing<String>> {
        self.inner.link_candidates(kind, window)
    }
    fn store_dict(&mut self, aliases: Option<&AliasTable>) -> Option<crate::Result<StoreDict>> {
        self.inner.store_dict(aliases)
    }
    fn leak_index(&mut self, aliases: Option<&AliasTable>) -> Option<crate::Result<LeakIndex>> {
        self.inner.leak_index(aliases)
    }
}

/// A sanitized candidate whose text is wiped on drop (it holds the input's
/// clear bytes).
struct Wiped(Sanitized);

impl Drop for Wiped {
    fn drop(&mut self) {
        self.0.text.zeroize();
    }
}

impl Deref for Wiped {
    type Target = Sanitized;
    fn deref(&self) -> &Sanitized {
        &self.0
    }
}

/// What phase 1 hands to phase 2.
struct Plan {
    decisions: Vec<Decision>,
    links: Links,
    /// The dry result's `(start, end, kind, action)` per replacement.
    shape: Vec<(usize, usize, EntityKind, Action)>,
}

/// Phase 1's outcome: go on to phase 2, or abandon.
enum Dried {
    Go(Plan),
    Stop(Abandon, usize),
}

fn shape(s: &Sanitized) -> Vec<(usize, usize, EntityKind, Action)> {
    s.replacements
        .iter()
        .map(|r| (r.span.start, r.span.end, r.span.kind.clone(), r.action))
        .collect()
}

fn store_size(s: &dyn TokenStore) -> usize {
    s.entries().count() + s.removed_entries().count()
}

/// A replaced slice holds a sentence boundary of the combination
/// heuristic, judged in `text` (S4 (c)): `\n` inside it, or `.`, `!`, `?`
/// inside it or at its end that `text` follows by whitespace or ends with.
/// The rule of the verifier's
/// [`sentence_bounds`](crate::verify::second_pass::SecondPassVerifier), kept
/// here on its own (ruling F28); `\r` also counts, which only abandons more.
fn merges_sentences(text: &str, r: Range<usize>) -> bool {
    text[r.clone()].char_indices().any(|(i, c)| match c {
        '\n' | '\r' => true,
        '.' | '!' | '?' => {
            let end = r.start + i + c.len_utf8();
            text[end..].chars().next().is_none_or(char::is_whitespace)
        }
        _ => false,
    })
}

/// Every byte of `s.text` outside a replacement's output range equals the
/// input byte at the mapped position, in order (S7: always checked).
fn clear_bytes_subset(input: &str, s: &Sanitized) -> bool {
    let (mut i, mut o) = (0usize, 0usize);
    let mut reps: Vec<&Replacement> = s.replacements.iter().collect();
    reps.sort_by_key(|r| r.span.start);
    for r in reps {
        let (a, b) = (r.span.start, r.out_range.start);
        if a < i || b < o || a - i != b - o || input.get(i..a) != s.text.get(o..b) {
            return false;
        }
        i = r.span.end;
        o = r.out_range.end;
    }
    input.len().checked_sub(i) == s.text.len().checked_sub(o) && input.get(i..) == s.text.get(o..)
}

impl Engine {
    /// Project `text`, a sanitized text that was already forwarded and is
    /// cached, onto `store`'s current values (engine spec §6.5, amendment
    /// of 2026-10-12): every clear copy of a store value gets that value's
    /// token or removal marker. Phase 1 sanitizes against a dry overlay
    /// that mints nothing and runs the deterministic checks and `caller`
    /// on its result; only when all pass does phase 2 sanitize for real.
    /// Any doubt abandons with nothing minted. Every error other than a
    /// `StoreError` is an abandonment.
    pub fn project(
        &self,
        text: &str,
        store: &mut dyn TokenStore,
        caller: &CallerCheck<'_>,
        scratch: &mut ProjectionScratch,
    ) -> Result<Projection, StoreError> {
        let abandon = |reason, absorbed| Ok(Projection::Abandoned { reason, absorbed });
        // 1. Engine preconditions.
        if self.linking.enabled
            && (self.linking.surnames_across_requests || self.linking.first_names_across_requests)
        {
            return abandon(Abandon::WindowLinking, 0);
        }
        if scratch
            .kit
            .as_ref()
            .is_none_or(|(name, _)| *name != self.profile.name)
        {
            let settings = VerifierSettings {
                allow_no_ner: true,
                ..self.profile.verifier.clone()
            };
            let Ok(verifier) = SecondPassVerifier::new(RegexDetector::new(), None, &settings)
            else {
                return abandon(Abandon::Error, 0);
            };
            let kit = ProjectionKit {
                verifier,
                regex: RegexDetector::new(),
            };
            scratch.kit = Some((self.profile.name.clone(), kit));
        }
        // 2. NFC.
        if !unicode_normalization::is_nfc(text) {
            return abandon(Abandon::NotNfc, 0);
        }
        // 3. Real tokens.
        let mut protected = crate::protect::find(text, store)?;
        {
            let s = store.settings();
            if scratch
                .tokens
                .as_ref()
                .is_none_or(|((o, c), _)| *o != s.open || *c != s.close)
            {
                let Ok(re) = regex::Regex::new(&Rehydrator::pattern(s)) else {
                    return abandon(Abandon::Error, 0);
                };
                scratch.tokens = Some(((s.open.clone(), s.close.clone()), re));
            }
        }
        let (Some((_, tokens)), Some((_, kit))) = (&scratch.tokens, &scratch.kit) else {
            return abandon(Abandon::Error, 0);
        };
        for m in tokens.find_iter(text) {
            if !real_token(store, m.as_str()) {
                return abandon(Abandon::ForgedToken, 0);
            }
            if parse_token(store.settings(), m.as_str()).is_some_and(|p| p.removed) {
                protected.push(m.range());
            }
        }
        protected.sort_by_key(|r| r.start);
        #[cfg(test)]
        let drop_kind = scratch.drop_kind_for_test;
        #[cfg(not(test))]
        let drop_kind: Option<&str> = None;
        // 4.–8. Through the alias wrapper `run_pass` uses.
        let dried = self.with_aliases(store, |ctx| {
            self.dry(text, ctx, &protected, caller, kit, drop_kind)
        })?;
        let plan = match dried {
            Dried::Go(plan) => plan,
            Dried::Stop(reason, absorbed) => return abandon(reason, absorbed),
        };
        // 9. Phase 2, real.
        let before = store_size(store);
        let s2 = self.with_aliases(store, |ctx| {
            sanitize_linked(text, &plan.decisions, &plan.links, ctx).map(Wiped)
        })?;
        let after = store_size(store);
        let consistent = shape(&s2) == plan.shape
            && clear_bytes_subset(text, &s2)
            && tokens
                .find_iter(&s2.text)
                .all(|m| real_token(store, m.as_str()));
        if !consistent {
            return Ok(Projection::Inconsistent);
        }
        let replaced = s2
            .replacements
            .iter()
            .map(|r| (r.span.start..r.span.end, r.span.kind.clone()))
            .collect();
        let mut s2 = s2;
        Ok(Projection::Projected {
            text: std::mem::take(&mut s2.0.text),
            replaced,
            minted: after.saturating_sub(before),
        })
    }

    /// `f` over `store`, wrapped exactly as `run_pass` wraps it:
    /// `Aliased` when the engine has alias groups.
    fn with_aliases<R>(
        &self,
        store: &mut dyn TokenStore,
        f: impl FnOnce(&mut dyn TokenStore) -> R,
    ) -> R {
        if self.aliases.is_empty() {
            f(store)
        } else {
            f(&mut Aliased::new(store, &self.aliases))
        }
    }

    /// Steps 5 to 8 of [`Engine::project`] over the (alias-wrapped) store:
    /// matches, sentence guard, N1 links, and phase 1 with its checks.
    fn dry(
        &self,
        text: &str,
        ctx: &mut dyn TokenStore,
        protected: &[Range<usize>],
        caller: &CallerCheck<'_>,
        kit: &ProjectionKit,
        drop_kind: Option<&str>,
    ) -> Result<Dried, StoreError> {
        let stop = |reason, absorbed| Ok(Dried::Stop(reason, absorbed));
        // 5. Matches.
        let matches =
            current_store_dict(&mut None, ctx).and_then(|d| d.redactions(text, &[], protected));
        let Ok(mut matches) = matches else {
            return stop(Abandon::Error, 0);
        };
        if matches.is_empty() {
            return stop(Abandon::Empty, 0);
        }
        for m in &mut matches {
            let r = &mut m.redaction;
            if r.action == RedactionAction::Tokenize {
                let span = Span::new(
                    r.start,
                    r.end,
                    EntityKind::from_label(&r.kind),
                    1.0,
                    DetectorId::Redaction,
                );
                if self.profile.action_for(&span) == Some(Action::Remove) {
                    r.action = RedactionAction::Remove;
                }
            }
        }
        // P3 test hook (never set outside tests).
        if let Some(label) = drop_kind {
            matches.retain(|m: &StoreMatch| m.redaction.kind != label);
        }
        let mut decisions = Vec::new();
        for m in &matches {
            merge_redaction(&mut decisions, &m.redaction, false);
        }
        decisions.sort_by_key(|d| d.span.start);
        let decisions = crate::protect::clip_decisions(text, decisions, protected);
        // 6. Sentence guard.
        if decisions
            .iter()
            .any(|d| merges_sentences(text, d.span.start..d.span.end))
        {
            return stop(Abandon::SentenceMerge, 0);
        }
        // 7. N1 links: a form of exactly one store original shares its
        // entity when the decision is exactly the match. There are no
        // detected decisions, so the tier is always `Window`.
        let mut links = Links::empty();
        if self.linking.enabled {
            for m in &matches {
                let Some(src) = &m.source else { continue };
                let r = &m.redaction;
                let exact = decisions.iter().any(|d| {
                    d.span.start == r.start
                        && d.span.end == r.end
                        && d.action == Action::Tokenize
                        && d.span.kind.label() == r.kind
                });
                if exact && links.parent(r.start).is_none() {
                    links.insert(r.start, src, LinkTier::Window);
                }
            }
        }
        drop(matches);
        // 8. Phase 1, dry.
        let mut dry = Dry {
            inner: ctx,
            absorbed: 0,
        };
        let mut s1 = Wiped(sanitize_linked(text, &decisions, &links, &mut dry)?);
        s1.0.protected = crate::protect::out_ranges(protected, &s1.replacements);
        if !clear_bytes_subset(text, &s1) {
            return stop(Abandon::Invariant, dry.absorbed);
        }
        // The input's own clear regex spans are preserve ranges of P's
        // candidate at their mapped offsets (the hit premise).
        let masked0 = Zeroizing::new(
            crate::protect::mask(text, protected, dry.settings())
                .unwrap_or_else(|| text.to_string()),
        );
        let Ok(spans) = kit.regex.detect(&masked0, &DetectCtx::for_text(&masked0)) else {
            return stop(Abandon::Error, dry.absorbed);
        };
        if spans.iter().any(|s| validate_span(&masked0, s).is_err()) {
            return stop(Abandon::Error, dry.absorbed);
        }
        let mut s1v = Wiped(s1.0.clone());
        for r in spans {
            let in_protected = protected
                .iter()
                .any(|p| p.start <= r.start && r.end <= p.end);
            let overlaps = decisions
                .iter()
                .any(|d| d.span.start < r.end && r.start < d.span.end);
            if in_protected || overlaps {
                continue;
            }
            // Signed (P10 (a)): a token can be shorter than its slice.
            let delta: isize = s1
                .replacements
                .iter()
                .filter(|x| x.span.end <= r.start)
                .map(|x| x.out_range.len() as isize - (x.span.end - x.span.start) as isize)
                .sum();
            let (a, b) = (r.start as isize + delta, r.end as isize + delta);
            if a < 0 || b < a || b as usize > s1.text.len() {
                return stop(Abandon::Error, dry.absorbed);
            }
            s1v.0.replacements.push(Replacement {
                span: Span::new(r.start, r.end, r.kind, 1.0, DetectorId::Redaction),
                action: Action::Preserve,
                token: None,
                out_range: a as usize..b as usize,
            });
        }
        s1v.0.replacements.sort_by_key(|r| r.out_range.start);
        // The inner store's leak index through the same wrapper (Task 5);
        // it drops when this call returns.
        let leak = crate::verify::second_pass::store_leak_index(&mut dry);
        match kit.verifier.verify_with(&s1v, &dry, leak.as_ref()) {
            Verdict::Pass => {}
            Verdict::Fail(reasons) => {
                let has = |c| reasons.iter().any(|r| r.check == c);
                let reason = if has(CheckId::Leak) {
                    Abandon::Leak
                } else if has(CheckId::Regex) {
                    Abandon::Regex
                } else {
                    Abandon::Error
                };
                return stop(reason, dry.absorbed);
            }
            Verdict::Uncertain(_) => return stop(Abandon::Combination, dry.absorbed),
        }
        drop(s1v);
        // The caller's check on the dry result and its token ranges.
        let mut ranges: Vec<Range<usize>> = s1
            .replacements
            .iter()
            .filter(|r| matches!(r.action, Action::Tokenize | Action::Remove))
            .map(|r| r.out_range.clone())
            .chain(s1.protected.iter().cloned())
            .collect();
        ranges.sort_by_key(|r| r.start);
        match caller(&s1.text, &ranges) {
            Ok(true) => {}
            Ok(false) => return stop(Abandon::Caller, dry.absorbed),
            Err(()) => return stop(Abandon::Error, dry.absorbed),
        }
        Ok(Dried::Go(Plan {
            shape: shape(&s1),
            decisions,
            links,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CoreConfig, TokenSettings};
    use crate::token::{Context, ContextId, TokenStore};
    use std::time::Duration;

    const CFG: &str = r#"
        [profiles.fast]
        default_action = "tokenize"
        default_min_confidence = 0.5
        escalate_below = 0.5
        [profiles.fast.entities.DATE]
        action = "preserve"
        min_confidence = 0.0
        [profiles.fast.entities.SECRET]
        action = "remove"
        min_confidence = 0.0
        [profiles.fast.verifier]
        on_uncertain = "block"
        allow_no_ner = true
    "#;

    fn engine() -> Engine {
        Engine::from_config(&CoreConfig::from_toml(CFG).unwrap(), "fast", None, None).unwrap()
    }
    fn ctx() -> Context {
        Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            TokenSettings::default(),
        )
    }
    fn size(c: &Context) -> usize {
        c.entries().count() + c.removed_entries().count()
    }
    const OK: &CallerCheck<'static> = &|_, _| Ok(true);

    #[test]
    fn projection_tokenizes_a_name_part_with_the_entity_token() {
        let e = engine();
        let mut c = ctx();
        let full = c.token_for(&EntityKind::Person, "Qorvex Brandl").unwrap();
        let t0 = "Gruss an Brandl, am 12.03.2024.";
        let p = e
            .project(t0, &mut c, OK, &mut ProjectionScratch::default())
            .unwrap();
        let Projection::Projected { text, replaced, .. } = p else {
            panic!("abandoned: {p:?}")
        };
        assert!(!text.contains("Brandl"), "{}", text.len());
        assert!(text.contains("12.03.2024"), "a preserved date stays");
        assert_eq!(replaced.len(), 1);
        // N1: a surface token of the same entity (same hex as `full`).
        let hex = &full.as_str()[8..12];
        assert!(text.contains(hex), "same entity");
    }

    #[test]
    fn projection_removes_removed_values() {
        let e = engine();
        let mut c = ctx();
        TokenStore::record_removed(&mut c, &EntityKind::custom("SECRET"), "hunter2pw").unwrap();
        let p = e
            .project(
                "pw is hunter2pw ok",
                &mut c,
                OK,
                &mut ProjectionScratch::default(),
            )
            .unwrap();
        let Projection::Projected { text, .. } = p else {
            panic!("{p:?}")
        };
        assert!(text.contains("_REMOVED>") && !text.contains("hunter2pw"));
    }

    /// The policy Remove override: a store *entry* (a restorable token) of a
    /// kind the profile removes, matched as `Tokenize`, is projected as the
    /// removal marker, never as a restorable token of that kind.
    #[test]
    fn projection_removes_an_entry_of_a_removed_kind() {
        let e = engine();
        let mut c = ctx();
        c.token_for(&EntityKind::custom("SECRET"), "hunter2pwX")
            .unwrap();
        let p = e
            .project(
                "pw hunter2pwX ok",
                &mut c,
                OK,
                &mut ProjectionScratch::default(),
            )
            .unwrap();
        let Projection::Projected { text, .. } = p else {
            panic!("{p:?}")
        };
        assert!(!text.contains("hunter2pw"), "{}", text.len());
        assert!(text.contains("<SECRET_REMOVED>"), "{}", text.len());
        assert_eq!(
            text.matches("<SECRET_").count(),
            text.matches("<SECRET_REMOVED>").count(),
            "a restorable SECRET token in P"
        );
    }

    #[test]
    fn projection_abandons_on_forged_token_and_non_nfc() {
        let e = engine();
        let mut c = ctx();
        c.token_for(&EntityKind::Person, "Qorvex Brandl").unwrap();
        let s = &mut ProjectionScratch::default();
        for (t0, why) in [
            ("Brandl and <PERSON_abcd> here", Abandon::ForgedToken),
            ("Brandl in Mu\u{0308}nchen", Abandon::NotNfc),
            ("Brandl and <BRANDL_REMOVED>", Abandon::ForgedToken),
        ] {
            match e.project(t0, &mut c, OK, s).unwrap() {
                Projection::Abandoned { reason, .. } => assert_eq!(reason, why),
                p => panic!("{why:?}: {p:?}"),
            }
        }
    }

    #[test]
    fn an_abandoned_projection_mints_nothing() {
        let e = engine();
        let mut c = ctx();
        c.token_for(&EntityKind::Person, "Qorvex Brandl").unwrap();
        let before = size(&c);
        let s = &mut ProjectionScratch::default();
        // caller check abandons; caller check errs
        for (t0, caller, why) in [
            (
                "Gruss an Brandl.",
                &(|_: &str, _: &[std::ops::Range<usize>]| Ok(false)) as &CallerCheck<'_>,
                Abandon::Caller,
            ),
            (
                "Gruss an Brandl.",
                &(|_: &str, _: &[std::ops::Range<usize>]| Err(())) as &CallerCheck<'_>,
                Abandon::Error,
            ),
        ] {
            match e.project(t0, &mut c, caller, s).unwrap() {
                Projection::Abandoned { reason, absorbed } => {
                    assert_eq!(reason, why);
                    assert!(absorbed >= 1, "the surface token was absorbed");
                }
                p => panic!("{p:?}"),
            }
            assert_eq!(size(&c), before, "{why:?} left a mint behind");
        }
        // A value whose form spans a sentence boundary (`Dr. Quill`, with `.`
        // before whitespace).
        c.token_for(&EntityKind::Person, "Dr. Quill").unwrap();
        let before = size(&c);
        match e
            .project("Gruss an Dr. Quill heute", &mut c, OK, s)
            .unwrap()
        {
            Projection::Abandoned { reason, .. } => assert_eq!(reason, Abandon::SentenceMerge),
            p => panic!("{p:?}"),
        }
        assert_eq!(size(&c), before);
    }

    /// P3: the Regex abandon path. `K-482913` is a bare identifier in clear
    /// in T0 and no regex span of T0, so no exemption is synthesized for it
    /// and the dry P fails the regex re-scan. Nothing is minted.
    #[test]
    fn projection_abandons_on_a_regex_span_left_in_clear() {
        let e = engine();
        let mut c = ctx();
        c.token_for(&EntityKind::Person, "Qorvex Brandl").unwrap();
        let before = size(&c);
        match e
            .project(
                "Brandl K-482913 bitte",
                &mut c,
                OK,
                &mut ProjectionScratch::default(),
            )
            .unwrap()
        {
            Projection::Abandoned { reason, .. } => assert_eq!(reason, Abandon::Regex),
            p => panic!("{p:?}"),
        }
        assert_eq!(size(&c), before, "an abandoned projection minted");
    }

    /// P3: the Leak abandon path, through the test hook
    /// (`ProjectionScratch::drop_kind_for_test`): the projector's PERSON
    /// matches are dropped, so the dry P keeps `Brandl` in clear and only
    /// the verifier's leak check (its own automaton) stands between it and
    /// the provider. The SECRET match keeps the projection non-empty.
    #[test]
    fn projection_abandons_when_the_leak_check_still_sees_a_value() {
        let e = engine();
        let mut c = ctx();
        c.token_for(&EntityKind::Person, "Qorvex Brandl").unwrap();
        TokenStore::record_removed(&mut c, &EntityKind::custom("SECRET"), "hunter2pw").unwrap();
        let before = size(&c);
        let mut s = ProjectionScratch {
            drop_kind_for_test: Some("PERSON"),
            ..Default::default()
        };
        match e
            .project("Brandl: pw hunter2pw", &mut c, OK, &mut s)
            .unwrap()
        {
            Projection::Abandoned { reason, .. } => assert_eq!(reason, Abandon::Leak),
            p => panic!("{p:?}"),
        }
        assert_eq!(size(&c), before, "an abandoned projection minted");
    }

    #[test]
    fn every_clear_byte_of_the_result_is_a_clear_byte_of_the_input() {
        let e = engine();
        let mut c = ctx();
        c.token_for(&EntityKind::Person, "Qorvex Brandl").unwrap();
        c.token_for(&EntityKind::Person, "Ilse Brandl").unwrap(); // `Brandl` shared: own entity
        let t0 = "BRANDL, Qorvex Brandl und brandl";
        let p = e
            .project(t0, &mut c, OK, &mut ProjectionScratch::default())
            .unwrap();
        let Projection::Projected { text, .. } = p else {
            panic!("{p:?}")
        };
        let clear: String = regex::Regex::new(r"<[A-Z][A-Z0-9_]*_[0-9a-f]{4}(_[0-9a-z]{2})?>")
            .unwrap()
            .replace_all(&text, "")
            .into_owned();
        for w in clear.split_whitespace() {
            assert!(t0.contains(w.trim_matches(',')), "{} not in input", w.len());
        }
        assert!(!text.to_lowercase().contains("brandl"));
    }

    #[test]
    fn a_projection_rebuilds_no_store_dictionary() {
        let e = engine();
        let mut c = ctx();
        c.token_for(&EntityKind::Person, "Qorvex Brandl").unwrap();
        let _ = c.store_dict(None).unwrap().unwrap(); // warm the context's cache
        let before = crate::consistency::builds_on_this_thread();
        let _ = e
            .project(
                "Gruss an Brandl.",
                &mut c,
                OK,
                &mut ProjectionScratch::default(),
            )
            .unwrap();
        // the delta layer may build once for the surface mint of phase 2; never the base
        assert!(crate::consistency::builds_on_this_thread() - before <= 1);
    }

    /// Task 5 (Q5, F10): `run_pass` asks the store for its leak index, so
    /// two `process` calls on an unchanged context build the leak base once
    /// and never go stale; afterwards the only live leak layers are the
    /// context's own (the engine kept no `Arc` of them).
    #[test]
    fn run_pass_uses_the_stores_leak_index_and_keeps_none() {
        use crate::consistency::{leak_builds_on_this_thread, live_leak_layers_on_this_thread};
        use crate::verify::second_pass::stale_on_this_thread;
        let e = engine();
        let mut c = ctx();
        let live = live_leak_layers_on_this_thread();
        let (b, stale) = (leak_builds_on_this_thread(), stale_on_this_thread());
        let text = "Bitte an anna.berger@example.com und Qorvex Brandl schreiben.";
        assert!(matches!(
            e.process(text, &mut c).unwrap(),
            super::super::Outcome::Pass { .. }
        ));
        let first = leak_builds_on_this_thread() - b;
        assert!((1..=2).contains(&first), "base, and the top layer at most");
        assert!(matches!(
            e.process(text, &mut c).unwrap(),
            super::super::Outcome::Pass { .. }
        ));
        assert_eq!(leak_builds_on_this_thread() - b, first, "reused");
        assert_eq!(stale_on_this_thread(), stale, "never stale");
        let held = live_leak_layers_on_this_thread() - live;
        let idx = c.leak_index(None).unwrap().unwrap();
        assert_eq!(leak_builds_on_this_thread() - b, first);
        assert_eq!(held, idx.layer_count() as isize, "only the context's");
        drop(idx);
        drop(c);
        assert_eq!(live_leak_layers_on_this_thread() - live, 0);
    }

    #[test]
    fn projection_debug_carries_no_text() {
        let e = engine();
        let mut c = ctx();
        c.token_for(&EntityKind::Person, "Qorvex Brandl").unwrap();
        let p = e
            .project(
                "Gruss an Brandl.",
                &mut c,
                OK,
                &mut ProjectionScratch::default(),
            )
            .unwrap();
        let d = format!("{p:?}");
        for s in ["Brandl", "Gruss", "PERSON_"] {
            assert!(!d.contains(s), "{d}");
        }
    }
}
