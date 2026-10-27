//! Apply policy decisions to text, producing the sanitized candidate.

use std::fmt;
use std::ops::Range;

use crate::link::Links;
use crate::policy::{Action, Decision};
use crate::span::{EntityKind, Span};
use crate::token::{StoreError, Token, TokenStore};

/// One applied decision with its position in the output text.
#[derive(Debug, Clone)]
pub struct Replacement {
    /// Span in the original text.
    pub span: Span,
    /// Action applied.
    pub action: Action,
    /// Token inserted, for `Tokenize`.
    pub token: Option<Token>,
    /// Byte range in the sanitized text this decision occupies.
    pub out_range: Range<usize>,
}

/// Result of sanitization. `Debug` omits the text.
#[derive(Clone)]
pub struct Sanitized {
    /// The candidate text.
    pub text: String,
    /// Applied decisions, sorted by `out_range.start`.
    pub replacements: Vec<Replacement>,
    /// Spans whose action was `Block`.
    pub blocked: Vec<Span>,
    /// Spans whose action was `Escalate`.
    pub escalated: Vec<Span>,
    /// Output ranges of tokens that were already in the input and resolve
    /// in the store (M8 spec decision 11, see [`crate::protect`]). Sorted,
    /// non-overlapping; the verifier treats them like minted tokens.
    /// Empty when the caller sanitized without the engine.
    pub protected: Vec<Range<usize>>,
}

impl Sanitized {
    /// True when `start..end` lies inside a protected token's output range.
    ///
    /// Binary search over the sorted ranges: the only candidate is the last
    /// one starting at or before `start`. Unsorted ranges can only miss a
    /// hit, which leaves it unexempt (fail closed).
    fn in_protected(&self, start: usize, end: usize) -> bool {
        let k = self.protected.partition_point(|r| r.start <= start);
        k > 0 && end <= self.protected[k - 1].end
    }

    /// True when `start..end` lies inside any replacement's output range
    /// or a protected token.
    pub fn is_covered(&self, start: usize, end: usize) -> bool {
        self.in_protected(start, end)
            || self
                .replacements
                .iter()
                .any(|r| r.out_range.start <= start && end <= r.out_range.end)
    }

    /// True when a verifier re-scan hit of `kind` at `start..end` is already
    /// handled by the sanitizer: it lies inside a `Tokenize`/`Remove` output
    /// range or a protected token, or inside a `Preserve`/`Escalate` range
    /// of the *same* kind.
    ///
    /// A hit of a different kind inside a preserved range (an email inside a
    /// preserved URL, a person inside a preserved organization) is not
    /// exempt: preserving the outer value never licensed sending the inner
    /// one.
    pub fn is_exempt(&self, start: usize, end: usize, kind: &EntityKind) -> bool {
        self.in_protected(start, end)
            || self.replacements.iter().any(|r| {
                r.out_range.start <= start
                    && end <= r.out_range.end
                    && match r.action {
                        Action::Tokenize | Action::Remove => true,
                        Action::Preserve | Action::Escalate => r.span.kind == *kind,
                        Action::Block => false,
                    }
            })
    }

    /// True when `start..end` lies inside a `Tokenize` or `Remove` output
    /// range or a protected token.
    pub fn is_inside_token(&self, start: usize, end: usize) -> bool {
        self.in_protected(start, end)
            || self.replacements.iter().any(|r| {
                matches!(r.action, Action::Tokenize | Action::Remove)
                    && r.out_range.start <= start
                    && end <= r.out_range.end
            })
    }
}

impl fmt::Debug for Sanitized {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sanitized")
            .field("len", &self.text.len())
            .field("replacements", &self.replacements.len())
            .field("blocked", &self.blocked.len())
            .field("escalated", &self.escalated.len())
            .field("protected", &self.protected.len())
            .finish()
    }
}

/// [`sanitize_linked`] with no links.
pub fn sanitize(
    text: &str,
    decisions: &[Decision],
    ctx: &mut dyn TokenStore,
) -> Result<Sanitized, StoreError> {
    sanitize_linked(text, decisions, &Links::empty(), ctx)
}

/// Apply decisions (sorted, non-overlapping) to `text`. A `Tokenize` span
/// whose start is linked (see [`Links`]) to an earlier entity mints that
/// entity's token, then — if the mention's text differs from the entity's
/// stored original — a surface token of it, so the mention still restores
/// to exactly the text it replaced (M4 plan 4a).
///
/// The result's `protected` is empty: protecting tokens already in the text
/// is the engine's job (see [`crate::protect`]), which clips `decisions`
/// around them before this call and fills `protected` after it.
pub fn sanitize_linked(
    text: &str,
    decisions: &[Decision],
    links: &Links,
    ctx: &mut dyn TokenStore,
) -> Result<Sanitized, StoreError> {
    let mut out = String::with_capacity(text.len());
    let mut replacements = Vec::with_capacity(decisions.len());
    let mut blocked = Vec::new();
    let mut escalated = Vec::new();
    let mut cursor = 0usize;

    for d in decisions {
        let span = &d.span;
        if span.start < cursor {
            continue; // defensive: overlapping input
        }
        out.push_str(&text[cursor..span.start]);
        let original = span.slice(text);
        let out_start = out.len();
        let token = match d.action {
            Action::Tokenize => {
                let t = match links.parent(span.start) {
                    Some(parent) => {
                        let p = ctx.token_for(&span.kind, parent)?;
                        if ctx.original(p.as_str()) == Some(original) {
                            p
                        } else {
                            ctx.surface_token(&p, original)?
                        }
                    }
                    None => {
                        let t = ctx.token_for(&span.kind, original)?;
                        if ctx.original(t.as_str()) == Some(original) {
                            t
                        } else {
                            ctx.surface_token(&t, original)?
                        }
                    }
                };
                out.push_str(t.as_str());
                Some(t)
            }
            Action::Remove => {
                ctx.record_removed(&span.kind, original)?;
                out.push_str(&ctx.removed_marker(&span.kind));
                None
            }
            Action::Preserve => {
                out.push_str(original);
                None
            }
            Action::Escalate => {
                out.push_str(original);
                escalated.push(span.clone());
                None
            }
            Action::Block => {
                out.push_str(original);
                blocked.push(span.clone());
                None
            }
        };
        replacements.push(Replacement {
            span: span.clone(),
            action: d.action,
            token,
            out_range: out_start..out.len(),
        });
        cursor = span.end;
    }
    out.push_str(&text[cursor..]);
    Ok(Sanitized {
        text: out,
        replacements,
        blocked,
        escalated,
        protected: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TokenSettings;
    use crate::policy::{Action, Decision};
    use crate::span::{DetectorId as D, EntityKind as K, SecretKind, Span};
    use crate::token::{Context, ContextId};
    use std::time::Duration;

    fn ctx() -> Context {
        Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            TokenSettings::default(),
        )
    }
    fn d(start: usize, end: usize, k: K, a: Action) -> Decision {
        Decision {
            span: Span::new(start, end, k, 0.9, D::Ner),
            action: a,
        }
    }

    #[test]
    fn applies_each_action() {
        let text = "Sarah in Wien, key AKIA, block ME.";
        //          0123456789012345678901234567890123
        let mut c = ctx();
        let s = sanitize(
            text,
            &[
                d(0, 5, K::Person, Action::Tokenize),
                d(9, 13, K::City, Action::Preserve),
                d(19, 23, K::Secret(SecretKind::Aws), Action::Remove),
                d(31, 33, K::Custom("X".into()), Action::Block),
            ],
            &mut c,
        )
        .unwrap();
        assert!(s.text.starts_with("<PERSON_"));
        assert!(s.text.contains(" in Wien, key <SECRET_REMOVED>, block ME."));
        assert_eq!(s.blocked.len(), 1);
        assert_eq!(s.replacements.len(), 4);
        let tok = s.replacements[0].token.as_ref().unwrap();
        assert_eq!(&s.text[s.replacements[0].out_range.clone()], tok.as_str());
        assert_eq!(&s.text[s.replacements[1].out_range.clone()], "Wien");
        assert!(s.is_inside_token(0, 3));
        assert!(!s.is_inside_token(
            s.replacements[1].out_range.start,
            s.replacements[1].out_range.end
        ));
        assert!(s.is_covered(
            s.replacements[1].out_range.start,
            s.replacements[1].out_range.end
        ));
    }

    #[test]
    fn escalate_preserves_and_records() {
        let mut c = ctx();
        let s = sanitize(
            "Hunter called",
            &[d(0, 6, K::Person, Action::Escalate)],
            &mut c,
        )
        .unwrap();
        assert_eq!(s.text, "Hunter called");
        assert_eq!(s.escalated.len(), 1);
    }

    #[test]
    fn debug_omits_text() {
        let mut c = ctx();
        let s = sanitize(
            "Sarah Leitner",
            &[d(0, 13, K::Person, Action::Preserve)],
            &mut c,
        )
        .unwrap();
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("Sarah"));
    }

    /// Plan 4a: a mention whose text differs from the stored original gets
    /// a surface token; a linked mention gets a surface token of its parent.
    #[test]
    fn sanitize_linked_mints_surface_tokens_and_restores_exactly() {
        use crate::link::{LinkTier, LinkTiers, Links};
        use crate::rehydrate::Rehydrator;
        let text = "Sarah Leitner rief an. SARAH LEITNER nochmal. Frau Leitner, LG Sarah";
        let mut c = ctx();
        let a = 0;
        let b = text.find("SARAH LEITNER").unwrap();
        let l = text.find("Leitner,").unwrap();
        let s2 = text.rfind("Sarah").unwrap();
        let mut links = Links::empty();
        links.insert(l, "Sarah Leitner", LinkTier::Document);
        links.insert(s2, "Sarah Leitner", LinkTier::Document);
        assert_eq!(
            links.tiers(),
            LinkTiers {
                document: 2,
                batch: 0,
                window: 0
            }
        );
        assert!(!links.tiers().cross_request());
        let decisions = [
            d(a, a + 13, K::Person, Action::Tokenize),
            d(b, b + 13, K::Person, Action::Tokenize),
            d(l, l + 7, K::Person, Action::Tokenize),
            d(s2, s2 + 5, K::Person, Action::Tokenize),
        ];
        let s = sanitize_linked(text, &decisions, &links, &mut c).unwrap();
        let toks: Vec<&str> = s
            .replacements
            .iter()
            .map(|r| r.token.as_ref().unwrap().as_str())
            .collect();
        let parsed: Vec<_> = toks
            .iter()
            .map(|t| crate::token::parse_token(c.settings(), t).unwrap())
            .collect();
        assert!(
            parsed.iter().all(|p| p.suffix == parsed[0].suffix),
            "one entity: {toks:?}"
        );
        assert!(
            parsed[0].variant.is_none() && parsed[1..].iter().all(|p| p.variant.is_some()),
            "{toks:?}"
        );
        assert_eq!(
            toks.iter().collect::<std::collections::HashSet<_>>().len(),
            4,
            "distinct surface tokens: {toks:?}"
        );
        let (back, unknown) = Rehydrator::new(c.settings()).rehydrate(&s.text, &c);
        assert_eq!(unknown, 0);
        assert_eq!(
            back, text,
            "every token restores exactly the text it replaced"
        );
        assert_eq!(c.len(), 4);
        // plain sanitize is the empty-links case
        let mut c2 = ctx();
        let plain = sanitize(text, &decisions, &mut c2).unwrap();
        assert_eq!(plain.replacements.len(), 4);
        let (back, _) = Rehydrator::new(c2.settings()).rehydrate(&plain.text, &c2);
        assert_eq!(back, text);
    }

    /// Plan 4a: a link whose parent the store cannot mint fails the pass.
    #[test]
    fn parent_mint_failure_is_a_store_error() {
        use crate::link::{LinkTier, Links};
        let mut links = Links::empty();
        links.insert(0, "Sarah Leitner", LinkTier::Batch);
        assert_eq!(format!("{links:?}"), "Links(1)");
        assert!(links.tiers().cross_request());
        // a store that refuses to mint the parent
        struct NoMint(Context);
        impl TokenStore for NoMint {
            fn token_for(&mut self, _: &EntityKind, _: &str) -> Result<Token, StoreError> {
                Err(StoreError::Unavailable)
            }
            fn original(&self, t: &str) -> Option<&str> {
                self.0.original(t)
            }
            fn entries(&self) -> Box<dyn Iterator<Item = (&EntityKind, &str)> + '_> {
                Box::new(self.0.entries())
            }
            fn record_removed(&mut self, k: &EntityKind, o: &str) -> Result<(), StoreError> {
                self.0.record_removed(k, o);
                Ok(())
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
            fn surface_token(&mut self, p: &Token, s: &str) -> Result<Token, StoreError> {
                self.0.surface_token(p, s)
            }
        }
        let mut nm = NoMint(ctx());
        assert_eq!(
            sanitize_linked(
                "Sarah",
                &[d(0, 5, K::Person, Action::Tokenize)],
                &links,
                &mut nm
            )
            .unwrap_err(),
            StoreError::Unavailable
        );
    }

    /// Plan 4a: the store no longer links surnames. Plain `sanitize` (no
    /// linker) gives a bare surname its own entity; spellings of the full
    /// name still share one, and every token restores the exact text.
    #[test]
    fn plain_sanitize_gives_a_bare_surname_its_own_entity() {
        use crate::rehydrate::Rehydrator;
        let text = "Sarah Leitner. SARAH LEITNER. Leitner.";
        let a = 0;
        let b = text.find("SARAH LEITNER").unwrap();
        let l = text.rfind("Leitner.").unwrap();
        let mut c = ctx();
        let decisions = [
            d(a, a + 13, K::Person, Action::Tokenize),
            d(b, b + 13, K::Person, Action::Tokenize),
            d(l, l + 7, K::Person, Action::Tokenize),
        ];
        let s = sanitize(text, &decisions, &mut c).unwrap();
        let toks: Vec<&str> = s
            .replacements
            .iter()
            .map(|r| r.token.as_ref().unwrap().as_str())
            .collect();
        let parsed: Vec<_> = toks
            .iter()
            .map(|t| crate::token::parse_token(c.settings(), t).unwrap())
            .collect();
        assert_eq!(
            parsed[0].suffix, parsed[1].suffix,
            "one entity, two spellings: {toks:?}"
        );
        assert_ne!(
            parsed[0].suffix, parsed[2].suffix,
            "no store-side surname link: {toks:?}"
        );
        let (back, unknown) = Rehydrator::new(c.settings()).rehydrate(&s.text, &c);
        assert_eq!(unknown, 0);
        assert_eq!(
            back, text,
            "every token restores exactly the text it replaced"
        );
    }

    /// Fix round 1, review Important 1 (B): once a linked mention has
    /// minted a surface row (here: "Sarah" linked to "Sarah Leitner"), a
    /// later *unlinked* one-word mention with the same normalized text
    /// must not anchor to that surface row and then fail `surface_token`
    /// with `UnknownParent` — the whole batch must still succeed.
    #[test]
    fn unlinked_mention_after_a_surface_row_does_not_fail_with_unknown_parent() {
        use crate::link::{LinkTier, Links};
        use crate::rehydrate::Rehydrator;
        let text = "Sarah rief an. SARAH nochmal.";
        let mut c = ctx();
        c.token_for(&K::Person, "Sarah Leitner").unwrap();
        let a = text.find("Sarah").unwrap();
        let b = text.rfind("SARAH").unwrap();
        let mut links = Links::empty();
        links.insert(a, "Sarah Leitner", LinkTier::Document);
        let decisions = [
            d(a, a + 5, K::Person, Action::Tokenize),
            d(b, b + 5, K::Person, Action::Tokenize),
        ];
        let s = sanitize_linked(text, &decisions, &links, &mut c).unwrap();
        let (back, unknown) = Rehydrator::new(c.settings()).rehydrate(&s.text, &c);
        assert_eq!(unknown, 0);
        assert_eq!(back, text);
    }

    /// Fix round 1, review R9: surface rows are keyed on the exact surface
    /// text (spec §16.2), so repeats of the exact canonical spelling reuse
    /// the entity token directly and every other casing gets its own
    /// surface token; the whole document rehydrates byte-identical.
    #[test]
    fn repeated_casings_of_the_full_name_rehydrate_byte_identical() {
        use crate::rehydrate::Rehydrator;
        let text = "Sarah Leitner A. SARAH LEITNER B. Sarah Leitner C. sarah leitner D.";
        let m1 = text.find("Sarah Leitner A").unwrap();
        let m2 = text.find("SARAH LEITNER B").unwrap();
        let m3 = text.find("Sarah Leitner C").unwrap();
        let m4 = text.find("sarah leitner D").unwrap();
        let mut c = ctx();
        let decisions = [
            d(m1, m1 + 13, K::Person, Action::Tokenize),
            d(m2, m2 + 13, K::Person, Action::Tokenize),
            d(m3, m3 + 13, K::Person, Action::Tokenize),
            d(m4, m4 + 13, K::Person, Action::Tokenize),
        ];
        let s = sanitize(text, &decisions, &mut c).unwrap();
        let toks: Vec<&str> = s
            .replacements
            .iter()
            .map(|r| r.token.as_ref().unwrap().as_str())
            .collect();
        assert_eq!(
            toks[0], toks[2],
            "the exact canonical spelling reuses the entity token"
        );
        assert_ne!(toks[0], toks[1]);
        assert_ne!(toks[0], toks[3]);
        assert_ne!(toks[1], toks[3]);
        assert_eq!(c.len(), 3, "canonical entity plus two surface forms");
        let (back, unknown) = Rehydrator::new(c.settings()).rehydrate(&s.text, &c);
        assert_eq!(unknown, 0);
        assert_eq!(back, text, "byte-identical restoration");
    }
}
