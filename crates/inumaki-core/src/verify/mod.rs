//! Independent verification of the sanitized candidate.

use crate::origin::TextOrigin;
use crate::sanitize::Sanitized;
use crate::span::EntityKind;
use crate::token::TokenStore;

mod home_login;
pub mod onnx_classifier;
pub mod second_pass;

pub use second_pass::{LeakIndex, SecondPassVerifier};

/// Which check produced a reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckId {
    /// An original value survived in the candidate.
    Leak,
    /// A structured identifier the sanitizer never saw.
    Regex,
    /// A name or address the independent NER pass found.
    Ner,
    /// Too many preserved quasi-identifiers in one sentence.
    Combination,
    /// A policy `Escalate` decision.
    Policy,
    /// A detector failed or returned invalid spans, so the text could not
    /// be examined. Always blocks.
    DetectorError,
}

/// One reason for a non-pass verdict. Carries kind and check, never text.
#[derive(Debug, Clone, PartialEq)]
pub struct Reason {
    /// Entity kind involved.
    pub kind: EntityKind,
    /// Check that fired.
    pub check: CheckId,
}

/// Outcome of verification.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Safe to transmit.
    Pass,
    /// Must not transmit.
    Fail(Vec<Reason>),
    /// Policy decides.
    Uncertain(Vec<Reason>),
}

/// Gate before transmission. Receives only the candidate and the mapping, never the original text.
///
/// Implementing: the engine's process path calls only
/// [`Verifier::verify_with_at`] (and [`Engine::project`](crate::Engine::project)
/// only [`Verifier::verify_with`]); it never calls [`Verifier::verify_at`]. A
/// verifier that should see the leak index or the origin overrides
/// `verify_with_at` (and `verify_with`). Its `verify` must not call the
/// provided defaults: they end at `verify`, so that would recurse forever.
pub trait Verifier: Send + Sync {
    /// Evaluate the candidate.
    fn verify(&self, sanitized: &Sanitized, ctx: &dyn TokenStore) -> Verdict;

    /// [`Verifier::verify`] with the store's leak-check index
    /// ([`TokenStore::leak_index`]), which a verifier may use instead of
    /// building its own patterns from `ctx`. The default ignores it.
    fn verify_with(
        &self,
        sanitized: &Sanitized,
        ctx: &dyn TokenStore,
        leak: Option<&LeakIndex>,
    ) -> Verdict {
        let _ = leak;
        self.verify(sanitized, ctx)
    }

    /// [`Verifier::verify_with`] for a text of known origin ([`TextOrigin`],
    /// rulings L103, L3-14 and L3-18): the store's leak-check index and the
    /// origin at once, as the engine's process path calls it. The default
    /// ignores the origin and calls [`Verifier::verify_with`], so a verifier
    /// that does not override it judges every text as [`TextOrigin::Free`]
    /// (fail-closed). The origin is not text.
    fn verify_with_at(
        &self,
        sanitized: &Sanitized,
        ctx: &dyn TokenStore,
        leak: Option<&LeakIndex>,
        origin: TextOrigin,
    ) -> Verdict {
        let _ = origin;
        self.verify_with(sanitized, ctx, leak)
    }

    /// Evaluate the candidate of a text of known origin ([`TextOrigin`],
    /// rulings L103 and L3-14), without a store leak-check index. The default
    /// calls [`Verifier::verify_with_at`] with no index, so it reads as
    /// [`TextOrigin::Free`] exactly when that method's default does.
    fn verify_at(
        &self,
        sanitized: &Sanitized,
        ctx: &dyn TokenStore,
        origin: TextOrigin,
    ) -> Verdict {
        self.verify_with_at(sanitized, ctx, None, origin)
    }
}

#[cfg(test)]
mod tests {
    /// Ruling L127: the verifier's generic logins stay equal to the
    /// sanitizer's list as sets, so a drift fails the build. A test, not
    /// shared runtime code: `home_login` itself never names `crate::detect`.
    #[test]
    fn verifier_generic_logins_equal_the_detector_list() {
        use std::collections::BTreeSet;
        let a: BTreeSet<_> = super::home_login::VERIFIER_GENERIC_LOGINS.iter().collect();
        let b: BTreeSet<_> = crate::detect::path_names::GENERIC_ACCOUNTS.iter().collect();
        assert_eq!(a, b);
    }

    /// Ruling L3-30: the slashless `~word` rule reads the same word lists on
    /// both sides, each side its own copy: the code keywords and operators
    /// that make `~` code, and the stoplist's common words that are not
    /// name-like.
    #[test]
    fn verifier_tilde_lists_equal_the_detector_lists() {
        use super::home_login::{
            VERIFIER_TILDE_COMMON_WORDS, VERIFIER_TILDE_KEYWORDS, VERIFIER_TILDE_OPERATORS,
        };
        use crate::detect::path_names::{TILDE_CODE_KEYWORDS, TILDE_OPERATORS};
        use std::collections::BTreeSet;
        let set = |l: &[&'static str]| l.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(set(VERIFIER_TILDE_KEYWORDS), set(TILDE_CODE_KEYWORDS));
        assert_eq!(VERIFIER_TILDE_OPERATORS, TILDE_OPERATORS);
        let ours: BTreeSet<String> = VERIFIER_TILDE_COMMON_WORDS
            .iter()
            .map(|w| w.to_string())
            .collect();
        assert_eq!(ours, crate::stoplist::common_non_name_like_words());
    }

    proptest::proptest! {
        /// Neither side panics on any text (a detector panic stops the
        /// engine; fix round 1 found a char-boundary slice in R5), and on
        /// short path-like texts the two sides agree as in
        /// `sanitized_paths_never_fail_the_home_login_check`.
        #[test]
        fn no_panic_and_agreement_on_path_like_text(
            text in "([a-zA-Z0-9äöüÄ.~/=@\\\\:()$%<>{}_\\- \"',;|`]|Users|home|homes|C:|-Users-){0,24}"
        ) {
            use crate::config::TokenSettings;
            use crate::detect::path_names::PathNameDetector;
            use crate::detect::{DetectCtx, Detector};
            use crate::policy::{Action, Decision};
            use crate::sanitize::sanitize;
            use crate::token::{Context, ContextId};
            let spans = PathNameDetector::new()
                .detect(&text, &DetectCtx::for_text(&text))
                .unwrap();
            let mut c = Context::new(
                ContextId("p".into()),
                std::time::Duration::from_secs(60),
                TokenSettings::default(),
            );
            let decisions: Vec<Decision> = spans
                .into_iter()
                .map(|span| Decision { span, action: Action::Tokenize })
                .collect();
            let s = sanitize(&text, &decisions, &mut c).unwrap();
            proptest::prop_assert!(
                super::home_login::check_home_logins(&s).is_empty(),
                "{} -> {}",
                text,
                s.text
            );
        }
    }

    /// Ruling L134 (b): the two sides agree. For every row, the text with
    /// the path detector's spans tokenized never fails the home-login check:
    /// whatever the verifier would refuse after a home root, the sanitizer
    /// tokenizes. Rows: the must-fail and must-pass rows of both modules,
    /// short logins, extensions, code and markup.
    #[test]
    fn sanitized_paths_never_fail_the_home_login_check() {
        use crate::config::TokenSettings;
        use crate::detect::path_names::PathNameDetector;
        use crate::detect::{DetectCtx, Detector};
        use crate::policy::{Action, Decision};
        use crate::sanitize::sanitize;
        use crate::token::{Context, ContextId};
        let rows = [
            "cwd /Users/mhuber/app",
            "in /home/agruber/x",
            r"C:\Users\sleitner\Desktop",
            "siehe ~mhuber/notes",
            "Pfad //home//huber prüfen",
            r#"{"cwd":"\/home\/huber\/x"}"#,
            r#"{"cwd":"C:\\Users\\mhuber\\x"}"#,
            "C:/Users/mhuber/x",
            "/Users/anna%20gruber/Desktop",
            "Ende: /home/mhuber.",
            "mhuber:x:1000:1000::/home/mhuber:/bin/bash",
            "~mhuber",
            "~mhuber/",
            r#""~mhuber""#,
            "(~mhuber)",
            "~mhuber.",
            "~flags",
            "cd ~mhuber && ls",
            "export P=/Users/mhuber${SUFFIX}/bin",
            "cp a /home/mhuber$EXT",
            "/Users/mhuber%",
            r"C:\Users\mhuber%TEMP%",
            "<td>/home/mhuber</td>",
            "/homes/mhuber/x",
            "/Users/kl/x",
            "/home/a/x",
            "/Users/mhuber.txt",
            "/home/runner.txt",
            "/home/data/x",
            "https://example.com/home/about",
            "`/Users/mhuber`",
            "| /home/mhuber |",
            "/home/mhuber(1)/x",
            "[/home/mhuber]",
            r"C:\Users\Anna Gruber\Documents",
            "/Users/runner/work",
            "x & ~flags",
            "if (~idx)",
            "MyClass::~MyClass()",
            "/home/steuer/",
            r"C:\Users\Preis\x",
            "https://example.com/~leitner/urlaub.jpg",
            "scp f user@host:~mhuber/notes",
            "scp f user@srv.example.com:~mhuber/notes",
            "rsync -a srv:~mhuber/ .",
            "--dir=~mhuber/x",
            "PATH=$PATH:~mhuber/bin",
            "export HOME_DIR=~mhuber/x",
            "Pfad:~mhuber/notes",
            "x=~mask/2",
            "a.b=~c/d",
            "x&~flags/2",
            "--dir=~mhuber",
            "HOME_DIR=~mhuber",
            "x=~mhuber",
            "mode:~fast",
            r"/Users\-Users-homes",
            r"C:~ä\",
            r"C:\Users\C:~Users",
            "/Users/C:~mhuber/x",
            "/Users/~mhuber/x",
            "C://Users/home",
            "C://users/home",
            "http://home/mhuber",
            "/Users/mhuber.txt:12",
            "/Users/mhuber.txt/x",
        ];
        let det = PathNameDetector::new();
        for text in rows {
            let mut c = Context::new(
                ContextId("a".into()),
                std::time::Duration::from_secs(60),
                TokenSettings::default(),
            );
            let decisions: Vec<Decision> = det
                .detect(text, &DetectCtx::for_text(text))
                .unwrap()
                .into_iter()
                .map(|span| Decision {
                    span,
                    action: Action::Tokenize,
                })
                .collect();
            let s = sanitize(text, &decisions, &mut c).unwrap();
            assert!(
                super::home_login::check_home_logins(&s).is_empty(),
                "{text} -> {}",
                s.text
            );
        }
    }
}
