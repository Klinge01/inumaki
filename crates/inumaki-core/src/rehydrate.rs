//! Replace tokens in model output with their original values.

use regex::Regex;

use crate::config::TokenSettings;
use crate::token::{StoreError, TokenStore};

/// Why a strict restoration produced nothing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RehydrateError {
    /// Placeholders the store cannot resolve: unknown, expired, or foreign
    /// tokens, and `_REMOVED` markers (removed values are never restored).
    #[error("unresolved placeholders: {unknown} unknown tokens, {removed} removed markers")]
    Unresolved {
        /// Token-shaped strings the store does not know.
        unknown: usize,
        /// Removed-value markers.
        removed: usize,
    },
    /// The store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Compiled token matcher for one delimiter configuration.
pub struct Rehydrator {
    re: Regex,
}

impl Rehydrator {
    /// The regex source every token consumer shares: entity tokens with a
    /// 4–12 hex suffix, their surface forms with a two-hex-character
    /// component, and removed markers, in `settings`' delimiters.
    pub fn pattern(settings: &TokenSettings) -> String {
        format!(
            "{}[A-Z][A-Z0-9_]*_(?:[0-9a-f]{{4,12}}(?:_[0-9a-f]{{2}})?|REMOVED){}",
            regex::escape(&settings.open),
            regex::escape(&settings.close)
        )
    }

    /// Longest token the proxy's streaming holdback waits for (M8 spec §6.3,
    /// §18.3): the open delimiter, a 32-character label, `_`, 12 hex
    /// characters, a 3-byte surface component (`_3e`), the close delimiter.
    /// Longer labels are legal; such a token is left unrestored in a stream,
    /// never exposed.
    pub fn max_token_len(settings: &TokenSettings) -> usize {
        settings.open.len() + 32 + 1 + 12 + 3 + settings.close.len()
    }

    /// Build a matcher for the configured delimiters. Recognizes suffixes of
    /// 4 to 12 hex characters regardless of `suffix_len`, so tokens of the
    /// other format (session vs dataset) are seen as tokens, never as
    /// ordinary text.
    pub fn new(settings: &TokenSettings) -> Self {
        Rehydrator {
            re: Regex::new(&Self::pattern(settings))
                .expect("escaped delimiters form a valid pattern"),
        }
    }

    /// Every token-shaped string in `text`, in order, duplicates kept.
    pub fn tokens_in(&self, text: &str) -> Vec<String> {
        self.re
            .find_iter(text)
            .map(|m| m.as_str().to_string())
            .collect()
    }

    /// Replace every known token. Returns the text and the number of unknown tokens left as-is.
    pub fn rehydrate(&self, text: &str, ctx: &dyn TokenStore) -> (String, usize) {
        let mut unknown = 0usize;
        let out = self.re.replace_all(text, |caps: &regex::Captures<'_>| {
            let tok = &caps[0];
            match ctx.original(tok) {
                Some(orig) => orig.to_string(),
                None => {
                    if !tok.contains("_REMOVED") {
                        unknown += 1;
                    }
                    tok.to_string()
                }
            }
        });
        (out.into_owned(), unknown)
    }

    /// Calls `store.prepare` with the tokens found in `text`, then
    /// [`Rehydrator::rehydrate`]: lets a lazily loading store (a vault
    /// namespace) fetch the originals first. For a `Context` this equals
    /// `rehydrate`.
    pub fn rehydrate_mut(
        &self,
        text: &str,
        store: &mut dyn TokenStore,
    ) -> Result<(String, usize), StoreError> {
        let tokens = self.tokens_in(text);
        store.prepare(&tokens)?;
        Ok(self.rehydrate(text, &*store))
    }

    /// Strict restoration (M4 spec §5.3): every token-shaped placeholder in
    /// `text` must resolve, and a `_REMOVED` marker never does. On failure
    /// nothing is returned, only counts; the caller must not fall back to a
    /// partially restored text.
    pub fn rehydrate_strict(
        &self,
        text: &str,
        store: &mut dyn TokenStore,
    ) -> Result<String, RehydrateError> {
        let tokens = self.tokens_in(text);
        store.prepare(&tokens)?;
        let (mut unknown, mut removed) = (0usize, 0usize);
        for t in &tokens {
            if t.contains("_REMOVED") {
                removed += 1;
            } else if store.original(t).is_none() {
                unknown += 1;
            }
        }
        if unknown + removed > 0 {
            return Err(RehydrateError::Unresolved { unknown, removed });
        }
        Ok(self.rehydrate(text, &*store).0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TokenSettings;
    use crate::span::EntityKind as K;
    use crate::token::{Context, ContextId};
    use std::time::Duration;

    #[test]
    fn restores_known_and_counts_unknown() {
        let settings = TokenSettings::default();
        let mut c = Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            settings.clone(),
        );
        let t = c.token_for(&K::Person, "Sarah Leitner").unwrap();
        let r = Rehydrator::new(&settings);
        let input = format!("Hallo {}, <PERSON_0000> und <SECRET_REMOVED>.", t.as_str());
        let (out, unknown) = r.rehydrate(&input, &c);
        assert_eq!(
            out,
            "Hallo Sarah Leitner, <PERSON_0000> und <SECRET_REMOVED>."
        );
        assert_eq!(unknown, 1);
    }

    #[test]
    fn custom_delimiters() {
        let settings = TokenSettings {
            suffix_len: 4,
            open: "{{".into(),
            close: "}}".into(),
            ..TokenSettings::default()
        };
        let mut c = Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            settings.clone(),
        );
        let t = c.token_for(&K::Email, "a@b.at").unwrap();
        let r = Rehydrator::new(&settings);
        let (out, unknown) = r.rehydrate(&format!("mail {}", t.as_str()), &c);
        assert_eq!(out, "mail a@b.at");
        assert_eq!(unknown, 0);
    }

    #[test]
    fn text_without_tokens_is_unchanged() {
        let settings = TokenSettings::default();
        let c = Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            settings.clone(),
        );
        let (out, n) = Rehydrator::new(&settings).rehydrate("a < b > c <x_1>", &c);
        assert_eq!(out, "a < b > c <x_1>");
        assert_eq!(n, 0);
    }

    #[test]
    fn custom_kind_labels_with_non_ascii_and_digits_rehydrate() {
        let settings = TokenSettings::default();
        let mut c = Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            settings.clone(),
        );
        let buero = c.token_for(&K::custom("büro"), "Büro 5").unwrap();
        let id2 = c.token_for(&K::custom("id2"), "12345").unwrap();
        let r = Rehydrator::new(&settings);
        let input = format!("{} and {}", buero.as_str(), id2.as_str());
        let (out, unknown) = r.rehydrate(&input, &c);
        assert_eq!(out, "Büro 5 and 12345");
        assert_eq!(unknown, 0);
    }

    #[test]
    fn tokens_in_and_rehydrate_mut() {
        let settings = TokenSettings::default();
        let mut c = Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            settings.clone(),
        );
        let t = c.token_for(&K::Person, "Sarah Leitner").unwrap();
        let r = Rehydrator::new(&settings);
        let input = format!("{} und {} und <PERSON_0000>", t.as_str(), t.as_str());
        assert_eq!(
            r.tokens_in(&input),
            vec![t.as_str(), t.as_str(), "<PERSON_0000>"]
        );
        let (out, unknown) = r.rehydrate_mut(&input, &mut c).unwrap();
        assert_eq!(out, "Sarah Leitner und Sarah Leitner und <PERSON_0000>");
        assert_eq!(unknown, 1);
    }

    /// M4 spec §5.3: token shapes of every suffix length are recognized, so a
    /// session token pasted into dataset traffic (or vice versa) is counted
    /// as unresolved instead of passing as ordinary text.
    #[test]
    fn recognizes_every_suffix_length() {
        let six = Rehydrator::new(&TokenSettings {
            suffix_len: 6,
            ..TokenSettings::default()
        });
        assert_eq!(
            six.tokens_in("<PERSON_ab12> <IBAN_ab12cd> <X_abcdefabcdef> <Y_abc> <Z_abcdefabcdefa>"),
            vec!["<PERSON_ab12>", "<IBAN_ab12cd>", "<X_abcdefabcdef>"]
        );
        let c = Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            TokenSettings::default(),
        );
        assert_eq!(six.rehydrate("<PERSON_ab12>", &c).1, 1, "unknown, counted");
    }

    /// Spec §5.3: strict restoration fails on any unresolved placeholder,
    /// including removed-value markers, with counts and no text.
    #[test]
    fn strict_rehydrate_resolves_all_or_nothing() {
        let settings = TokenSettings::default();
        let mut c = Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            settings.clone(),
        );
        let t = c.token_for(&K::Person, "Sarah Leitner").unwrap();
        let r = Rehydrator::new(&settings);
        assert_eq!(
            r.rehydrate_strict(&format!("Hallo {}.", t.as_str()), &mut c)
                .unwrap(),
            "Hallo Sarah Leitner."
        );
        let input = format!("{} <PERSON_0000> <IBAN_1111> <SECRET_REMOVED>", t.as_str());
        assert_eq!(
            r.rehydrate_strict(&input, &mut c),
            Err(RehydrateError::Unresolved {
                unknown: 2,
                removed: 1
            })
        );
        assert_eq!(
            r.rehydrate_strict("kein Token", &mut c).unwrap(),
            "kein Token"
        );
    }

    /// Plan 4a: variant tokens are tokens; the pattern is shared.
    #[test]
    fn variant_tokens_are_recognized_and_restored() {
        let settings = TokenSettings::default();
        let mut c = Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            settings.clone(),
        );
        let full = c.token_for(&K::Person, "Sarah Leitner").unwrap();
        let first = c.surface_token(&full, "Sarah").unwrap();
        let r = Rehydrator::new(&settings);
        let input = format!(
            "Hallo {}, hier ist {}. <PERSON_0000_3e> <PERSON_0000_0>",
            first.as_str(),
            full.as_str()
        );
        assert_eq!(
            r.tokens_in(&input),
            vec![first.as_str(), full.as_str(), "<PERSON_0000_3e>"],
            "a one-character tail is not a token"
        );
        let (out, unknown) = r.rehydrate(&input, &c);
        assert_eq!(
            out,
            "Hallo Sarah, hier ist Sarah Leitner. <PERSON_0000_3e> <PERSON_0000_0>"
        );
        assert_eq!(unknown, 1);
        assert_eq!(
            r.rehydrate_strict(&format!("{} {}", first.as_str(), full.as_str()), &mut c)
                .unwrap(),
            "Sarah Sarah Leitner"
        );
        assert!(Rehydrator::pattern(&settings).contains("[0-9a-f]{2}"));
    }
}
