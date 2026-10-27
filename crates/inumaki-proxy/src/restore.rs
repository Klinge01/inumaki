//! Response-side restoration (M8 spec §6.1, decisions 12 and 23).
//!
//! Every token is classified by where it resolves:
//!
//! | Column | Session tokens | Dataset tokens |
//! |---|---|---|
//! | [`Column::Text`] (model text) | restored | restored only for [`ClientMode::Trusted`] (or on a check route) |
//! | [`Column::Args`] (tool-call arguments) | restored | left as tokens |
//! | [`Column::Error`] (upstream error bodies) | restored | left as tokens |
//!
//! Removed markers (`<SECRET_REMOVED>`) and unknown token-shaped text are
//! never restored. On a check route ([`Scope::Check`], spec §12.3) only the
//! check's dataset tokens are restored, and session tokens stay tokens.
//!
//! Privacy: the restorer caches resolved dataset originals for one answer in
//! `Zeroizing` buffers; `Debug` prints counts only. Errors are the fixed
//! classes of spec §7.

use std::collections::HashMap;
use std::fmt;

use inumaki_core::config::TokenSettings;
use inumaki_core::token::parse_token;
use regex::Regex;
use zeroize::Zeroizing;

use crate::error::Fail;
use crate::host::{ProxyHost, Scope};
use crate::pipeline::host_fail;
use crate::session::{ClientMode, Session};

/// Which part of an answer a string comes from (spec §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Column {
    /// Model text: `text` blocks, `output_text`, Chat `content`, `refusal`.
    Text,
    /// Tool-call arguments: session tokens only (decision 12).
    Args,
    /// Upstream error bodies: session tokens only (decision 23).
    Error,
}

/// Restores the tokens of one answer. Not `Clone`; `Debug` prints counts.
pub struct Restorer<'a> {
    session: &'a Session,
    host: &'a dyn ProxyHost,
    tokens: &'a Regex,
    scope: Scope,
    mode: ClientMode,
    settings: TokenSettings,
    /// Dataset lookups of this answer: `None` when the scope does not know the token.
    datasets: HashMap<String, Option<Zeroizing<String>>>,
}

impl fmt::Debug for Restorer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Restorer")
            .field("scope", &self.scope)
            .field("mode", &self.mode)
            .field("datasets", &self.datasets.len())
            .finish()
    }
}

impl<'a> Restorer<'a> {
    /// A restorer over `session` (its token settings decide which matches
    /// are removed markers) with `host` resolving dataset tokens in `scope`.
    pub fn new(
        session: &'a Session,
        host: &'a dyn ProxyHost,
        tokens: &'a Regex,
        scope: Scope,
        mode: ClientMode,
    ) -> Restorer<'a> {
        let settings = session.with_context(|c| c.settings().clone());
        Restorer {
            session,
            host,
            tokens,
            scope,
            mode,
            settings,
            datasets: HashMap::new(),
        }
    }

    /// `text` with every token restored that `col` allows; unknown tokens
    /// and removed markers stay. A host failure fails closed: the caller
    /// relays nothing of the answer.
    pub fn restore(&mut self, text: &str, col: Column) -> Result<String, Fail> {
        if !self.tokens.is_match(text) {
            return Ok(text.to_string());
        }
        let check = matches!(self.scope, Scope::Check(_));
        let datasets_allowed = col == Column::Text && (self.mode == ClientMode::Trusted || check);
        let settings = &self.settings;
        let found: Vec<&str> = self
            .tokens
            .find_iter(text)
            .map(|m| m.as_str())
            .filter(|t| parse_token(settings, t).is_some_and(|p| !p.removed))
            .collect();
        // Session originals, under one short lock; none on a check route.
        let session: HashMap<&str, Zeroizing<String>> = if check {
            HashMap::new()
        } else {
            self.session.with_context(|c| {
                found
                    .iter()
                    .filter_map(|t| c.original(t).map(|o| (*t, Zeroizing::new(o.to_string()))))
                    .collect()
            })
        };
        if datasets_allowed {
            let mut ask: Vec<String> = Vec::new();
            for t in &found {
                if !session.contains_key(t)
                    && !self.datasets.contains_key(*t)
                    && !ask.iter().any(|a| a == t)
                {
                    ask.push((*t).to_string());
                }
            }
            if !ask.is_empty() {
                let got = self.host.resolve(&ask, &self.scope).map_err(host_fail)?;
                for t in &ask {
                    self.datasets.insert(t.clone(), None);
                }
                // Only tokens that were asked for.
                for (t, _, o) in got {
                    if let Some(slot) = self.datasets.get_mut(&t) {
                        *slot = Some(o);
                    }
                }
            }
        }
        let mut out = String::with_capacity(text.len());
        let mut cur = 0;
        for m in self.tokens.find_iter(text) {
            out.push_str(&text[cur..m.start()]);
            let t = m.as_str();
            match session.get(t) {
                Some(o) => out.push_str(o),
                None => match self.datasets.get(t) {
                    Some(Some(o)) if datasets_allowed => out.push_str(o),
                    _ => out.push_str(t),
                },
            }
            cur = m.end();
        }
        out.push_str(&text[cur..]);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use inumaki_core::span::EntityKind;
    use inumaki_core::token::TokenStore;

    use super::*;
    use crate::session::{SessionKey, SessionStore, SessionView};
    use crate::testing::{CHECK_DS, CHECK_NAME, CHECK_TOKEN, DS_TOKEN, EMAIL, FakeHost, NAME};

    /// Decisions 12 and 23, spec §6.1 and §12.3, per column, mode, and scope.
    #[test]
    fn provenance_mode_and_scope_decide_each_column() {
        let host = FakeHost::new();
        let store = SessionStore::new(
            Duration::from_secs(60),
            4,
            TokenSettings::default(),
            1 << 20,
        );
        let s = store.get(SessionKey([1; 32]));
        let e = SessionView::new(&s, &*host, TokenSettings::default())
            .token_for(&EntityKind::Email, EMAIL)
            .unwrap();
        let e = e.as_str();
        let re = Regex::new(&inumaki_core::rehydrate::Rehydrator::pattern(
            &TokenSettings::default(),
        ))
        .unwrap();
        let text = format!("{e} {DS_TOKEN} <PERSON_ffffff> <SECRET_REMOVED>");
        let run = |scope: Scope, mode: ClientMode, col: Column| {
            Restorer::new(&s, &*host, &re, scope, mode)
                .restore(&text, col)
                .unwrap()
        };
        let tail = "<PERSON_ffffff> <SECRET_REMOVED>";
        let t = ClientMode::Trusted;
        let r = ClientMode::Restricted;
        assert_eq!(
            run(Scope::Datasets, t, Column::Text),
            format!("{EMAIL} {NAME} {tail}")
        );
        assert_eq!(
            run(Scope::Datasets, r, Column::Text),
            format!("{EMAIL} {DS_TOKEN} {tail}")
        );
        for col in [Column::Args, Column::Error] {
            for mode in [t, r] {
                assert_eq!(
                    run(Scope::Datasets, mode, col),
                    format!("{EMAIL} {DS_TOKEN} {tail}"),
                    "{col:?} {mode:?}"
                );
            }
        }
        // A check route restores its own dataset's tokens in text whatever
        // the header, and never a session token or another dataset's token.
        let ctext = format!("{e} {DS_TOKEN} {CHECK_TOKEN} {tail}");
        let check = |mode: ClientMode, col: Column| {
            Restorer::new(&s, &*host, &re, Scope::Check(CHECK_DS.into()), mode)
                .restore(&ctext, col)
                .unwrap()
        };
        for mode in [t, r] {
            assert_eq!(
                check(mode, Column::Text),
                format!("{e} {DS_TOKEN} {CHECK_NAME} {tail}"),
                "{mode:?}"
            );
            for col in [Column::Args, Column::Error] {
                assert_eq!(check(mode, col), ctext, "{col:?} {mode:?}");
            }
        }
        // Forget applies at once; a vault failure fails closed.
        host.forget(DS_TOKEN);
        assert_eq!(
            run(Scope::Datasets, t, Column::Text),
            format!("{EMAIL} {DS_TOKEN} {tail}")
        );
        *host.fail_vault.lock().unwrap() = true;
        let err = Restorer::new(&s, &*host, &re, Scope::Datasets, t).restore(&text, Column::Text);
        assert_eq!(err, Err(Fail::VaultUnavailable));
        assert_eq!(
            Restorer::new(&s, &*host, &re, Scope::Datasets, t)
                .restore(&text, Column::Args)
                .unwrap(),
            format!("{EMAIL} {DS_TOKEN} {tail}"),
            "arguments never ask the vault"
        );
    }
}
