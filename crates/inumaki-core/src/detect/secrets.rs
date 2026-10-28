//! Credential and secret patterns. Policy default for these is `Remove`.

use std::sync::LazyLock;

use regex::{Regex, RegexSet};

use super::{DetectCtx, Detector};
use crate::span::{DetectorId, EntityKind, SecretKind, Span};

/// The confidence of every span this detector reports. A profile's SECRET
/// `min_confidence` may not exceed it (`CoreConfig::check_secret_removed`),
/// or a detected secret would escalate or be dropped instead of removed.
/// Any change to this value must keep `CoreConfig::check_secret_removed`
/// meaningful: no profile's SECRET `min_confidence` may exceed it.
pub(crate) const SECRET_CONFIDENCE: f32 = 0.95;

struct Rule {
    pattern: &'static str,
    kind: SecretKind,
    group: usize,
}

const RULES: &[Rule] = &[
    Rule {
        pattern: r"\bAKIA[0-9A-Z]{16}\b",
        kind: SecretKind::Aws,
        group: 0,
    },
    Rule {
        pattern: r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
        kind: SecretKind::GitHub,
        group: 0,
    },
    Rule {
        pattern: r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b",
        kind: SecretKind::Slack,
        group: 0,
    },
    Rule {
        pattern: r"\bAIza[0-9A-Za-z_\-]{35}\b",
        kind: SecretKind::Google,
        group: 0,
    },
    Rule {
        pattern: r"\b[sr]k_(?:live|test)_[0-9a-zA-Z]{20,}\b",
        kind: SecretKind::Stripe,
        group: 0,
    },
    // OpenAI and Anthropic keys and the gateways that copy their shape:
    // `sk-...`, `sk-proj-...`, `sk-svcacct-...`, `sk-ant-api03-...`,
    // `sk-or-v1-...`. 20+ characters after `sk-` keep a short kebab-case
    // word (`sk-fading-circle`) out.
    Rule {
        pattern: r"\bsk-[A-Za-z0-9][A-Za-z0-9_\-]{18,}[A-Za-z0-9_]",
        kind: SecretKind::Generic,
        group: 0,
    },
    Rule {
        pattern: r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
        kind: SecretKind::Jwt,
        group: 0,
    },
    Rule {
        pattern: r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
        kind: SecretKind::PrivateKey,
        group: 0,
    },
    Rule {
        pattern: r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s@/]+@[^\s]*[^\s.,;:!?)]",
        kind: SecretKind::ConnectionString,
        group: 0,
    },
    Rule {
        pattern: r"(?i)\bbearer\s+([A-Za-z0-9._~+/=\-]{19,}[A-Za-z0-9_~+/=\-])",
        kind: SecretKind::Bearer,
        group: 1,
    },
    // Double-quoted value after a key/token/password label: everything inside
    // the quotes, spaces and apostrophes included (`password="Sommer 2024"`).
    Rule {
        pattern: r#"(?i)\b(?:api[_\-]?key|secret|token|password|passwd|pwd|passwort|paßwort|kennwort)\b\s*[:=]\s*"([^"\n]{4,})""#,
        kind: SecretKind::Generic,
        group: 1,
    },
    // Single-quoted value, same labels.
    Rule {
        pattern: r#"(?i)\b(?:api[_\-]?key|secret|token|password|passwd|pwd|passwort|paßwort|kennwort)\b\s*[:=]\s*'([^'\n]{4,})'"#,
        kind: SecretKind::Generic,
        group: 1,
    },
    // Key/token labels: value of 8+ non-space characters. The value never
    // ends in sentence punctuation (`.,;:)`), which would otherwise be
    // removed with it and hide a second copy from the leak check.
    Rule {
        pattern: r#"(?i)\b(?:api[_\-]?key|secret|token)\b\s*[:=]\s*["']?([^\s"'`]{7,}[^\s"'`.,;:)])"#,
        kind: SecretKind::Generic,
        group: 1,
    },
    // Environment-variable style labels (`OPENAI_API_KEY=...`,
    // `AWS_SECRET_ACCESS_KEY=...`, `DB_PASSWORD=...`): the label word is
    // the tail of an upper-case name, so `\b` finds no boundary before it in
    // the rules above.
    Rule {
        pattern: r#"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_(?:API_?KEY|SECRET_ACCESS_KEY|SECRET_KEY|ACCESS_KEY|PRIVATE_KEY|SECRET|TOKEN|PASSWORD|PASSWD)\b\s*[:=]\s*["']?([^\s"'`]{7,}[^\s"'`.,;:)])"#,
        kind: SecretKind::Generic,
        group: 1,
    },
    // Password labels (EN + DE): any value of 4+ non-space characters.
    Rule {
        pattern: r#"(?i)\b(?:password|passwd|pwd|passwort|paßwort|kennwort)\b\s*[:=]\s*["']?([^\s"'`]{3,}[^\s"'`.,;:)])"#,
        kind: SecretKind::Generic,
        group: 1,
    },
];

static SET: LazyLock<RegexSet> =
    LazyLock::new(|| RegexSet::new(RULES.iter().map(|r| r.pattern)).expect("static set"));
static REGEXES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    RULES
        .iter()
        .map(|r| Regex::new(r.pattern).expect("static pattern"))
        .collect()
});

/// Detects credentials that must never reach a cloud provider.
#[derive(Clone, Default)]
pub struct SecretsDetector;

impl SecretsDetector {
    /// Construct. Patterns are compiled once per process.
    pub fn new() -> Self {
        LazyLock::force(&SET);
        LazyLock::force(&REGEXES);
        SecretsDetector
    }
}

impl Detector for SecretsDetector {
    fn id(&self) -> DetectorId {
        DetectorId::Secrets
    }

    fn detect(&self, text: &str, _ctx: &DetectCtx) -> crate::Result<Vec<Span>> {
        let mut out = Vec::new();
        for idx in SET.matches(text).iter() {
            let rule = &RULES[idx];
            for caps in REGEXES[idx].captures_iter(text) {
                if let Some(m) = caps.get(rule.group) {
                    out.push(Span::new(
                        m.start(),
                        m.end(),
                        EntityKind::Secret(rule.kind),
                        SECRET_CONFIDENCE,
                        DetectorId::Secrets,
                    ));
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::resolve_overlaps;
    use crate::span::{EntityKind, SecretKind};

    fn secrets(text: &str) -> Vec<(SecretKind, String)> {
        let spans = SecretsDetector::new()
            .detect(text, &DetectCtx::for_text(text))
            .unwrap();
        // Runs the same overlap resolution the engine applies to every detector's output, so
        // these tests see the engine's tie-breaking, not just this detector's raw spans.
        let resolved = resolve_overlaps(spans);
        resolved
            .into_iter()
            .map(|s| match s.kind {
                EntityKind::Secret(k) => (k, s.slice(text).to_string()),
                _ => panic!("non-secret kind"),
            })
            .collect()
    }

    #[test]
    fn aws_and_github() {
        let v = secrets("key AKIAIOSFODNN7EXAMPLE and ghp_abcdefghijklmnopqrstuvwxyz0123456789AB");
        assert!(v.contains(&(SecretKind::Aws, "AKIAIOSFODNN7EXAMPLE".into())));
        assert!(v.iter().any(|(k, _)| *k == SecretKind::GitHub));
    }

    #[test]
    fn jwt() {
        let t = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let v = secrets(&format!("token {t} ok"));
        assert_eq!(v, vec![(SecretKind::Jwt, t.to_string())]);
    }

    #[test]
    fn private_key_block() {
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----";
        let v = secrets(text);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].0, SecretKind::PrivateKey);
        assert_eq!(v[0].1, text);
    }

    #[test]
    fn connection_string_and_bearer() {
        let v = secrets(
            "postgres://app:s3cret@db.internal:5432/prod\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz012345",
        );
        assert!(v.iter().any(|(k, _)| *k == SecretKind::ConnectionString));
        assert!(v.iter().any(|(k, _)| *k == SecretKind::Bearer));
    }

    #[test]
    fn generic_key_value_captures_value_only() {
        let v = secrets("api_key = \"abcdEFGH1234-xyz\"");
        assert_eq!(v, vec![(SecretKind::Generic, "abcdEFGH1234-xyz".into())]);
    }

    /// C3: a value ending a sentence must not swallow the full stop, or the
    /// leak check would look for the wrong string.
    #[test]
    fn values_do_not_capture_sentence_final_period() {
        let v = secrets("api_key: 9f8e7d6c5b4a3210ffee. Bitte teste.");
        assert_eq!(
            v,
            vec![(SecretKind::Generic, "9f8e7d6c5b4a3210ffee".into())]
        );
        let v = secrets("Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345.");
        assert_eq!(
            v,
            vec![(
                SecretKind::Bearer,
                "abcdefghijklmnopqrstuvwxyz012345".into()
            )]
        );
        let v = secrets("Nutze postgres://app:s3cret@db.internal:5432/prod.");
        assert_eq!(v[0].1, "postgres://app:s3cret@db.internal:5432/prod");
    }

    /// I6: German password labels, and values with punctuation.
    #[test]
    fn german_password_labels() {
        for (text, want) in [
            ("Passwort: Sommer2024!x", "Sommer2024!x"),
            ("Kennwort = geheim123", "geheim123"),
            ("Paßwort: Winter#23", "Winter#23"),
            ("password: abc1234", "abc1234"),
        ] {
            let v = secrets(text);
            assert_eq!(v, vec![(SecretKind::Generic, want.into())], "{text}");
        }
    }

    /// OpenAI and Anthropic keys (`sk-proj-...` was sent in clear before
    /// this rule) are found whole, wherever they stand.
    #[test]
    fn openai_and_anthropic_keys_are_found_whole() {
        for key in [
            "sk-proj-cF4GqOdO3hXj4h6Qr0AAskg263tHfjIYscNPnQp97T1dFUE3",
            "sk-svcacct-Kz8Qw3mR7vT2nX9pL4bY6hJ1cD5fG0aS",
            "sk-ant-api03-Zk3mQ8vR1nT6xP2LbY9hJ4cD7fG0aS5w",
            "sk-9f8e7d6c5b4a3f2e1d0c1234567890abcdef",
            "sk-test-9f8e7d6c5b4a3f2e1d0c",
            "sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef",
        ] {
            for text in [
                format!("the key {key} is bad"),
                format!("key=\"{key}\"."),
                format!("({key})"),
            ] {
                let v = secrets(&text);
                assert!(
                    v.iter().any(|(_, t)| t == key),
                    "{key} not found whole in {text:?}: {v:?}"
                );
            }
        }
    }

    /// Environment-variable names ending in a key word label a value even
    /// though the word has no `\b` before it.
    #[test]
    fn env_var_style_labels_take_the_value() {
        for (text, want) in [
            ("export OPENAI_API_KEY=abcd1234efgh5678", "abcd1234efgh5678"),
            (
                "AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG",
                "wJalrXUtnFEMI/K7MDENG",
            ),
            ("DB_PASSWORD: hunter2hunter2", "hunter2hunter2"),
            ("GITHUB_TOKEN=\"ghx_somevalue1234\"", "ghx_somevalue1234"),
        ] {
            let v = secrets(text);
            assert!(v.iter().any(|(_, t)| t == want), "{text}: {v:?}");
        }
    }

    /// Words that merely look like the shapes above stay clean.
    #[test]
    fn short_kebab_words_and_prose_are_not_keys() {
        for text in [
            "use the sk-fading-circle spinner",
            "pip install scikit-learn, not sk-learn",
            "the task-force-meeting-notes file",
            "set MAX_TOKENS to a small number",
            "the TOKEN: is empty",
        ] {
            assert!(secrets(text).is_empty(), "{text}: {:?}", secrets(text));
        }
    }

    #[test]
    fn plain_prose_is_clean() {
        assert!(secrets("Bitte senden Sie mir das Passwort zurücksetzen Formular.").is_empty());
    }

    #[test]
    fn quoted_secret_values_are_taken_whole() {
        let v = secrets("password=\"Sommer 2024\" ok");
        assert!(v.iter().any(|(_, t)| t == "Sommer 2024"), "{v:?}");
        let v = secrets("api_key: 'abc def ghi' ok");
        assert!(v.iter().any(|(_, t)| t == "abc def ghi"), "{v:?}");
        let v = secrets("password=\"my dog's name123\" ok");
        assert!(v.iter().any(|(_, t)| t == "my dog's name123"), "{v:?}");
        let v = secrets("token: 'say \"hi\" 2024' ok");
        assert!(v.iter().any(|(_, t)| t == "say \"hi\" 2024"), "{v:?}");
    }
}
