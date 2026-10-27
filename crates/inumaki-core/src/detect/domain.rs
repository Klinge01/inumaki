//! Business-specific recognizers loaded from configuration.

use std::fmt;

use regex::Regex;
use serde::Deserialize;
use unicode_normalization::UnicodeNormalization;

use super::{DetectCtx, Detector};
use crate::span::{DetectorId, EntityKind, Span};
use crate::{Error, Result};

fn default_pattern_conf() -> f32 {
    0.95
}
fn default_label_conf() -> f32 {
    0.92
}
fn default_window() -> usize {
    40
}

/// A regex that is itself the identifier, e.g. `K-[0-9]{6}`.
#[derive(Debug, Clone, Deserialize)]
pub struct DomainPattern {
    /// Regex without anchors; word boundaries are added.
    pub regex: String,
    /// Entity label, e.g. `CUSTOMER_ID` or a custom name.
    pub kind: String,
    /// Confidence assigned to matches.
    #[serde(default = "default_pattern_conf")]
    pub confidence: f32,
}

/// A label such as `Kundennummer:` followed by a value starting within
/// `window` characters.
#[derive(Debug, Clone, Deserialize)]
pub struct DomainLabel {
    /// Case-insensitive label texts.
    pub labels: Vec<String>,
    /// Entity label for the value.
    pub kind: String,
    /// Regex the value must match.
    pub value: String,
    /// Characters after the label in which the value must start. The value
    /// itself may extend past the window.
    #[serde(default = "default_window")]
    pub window: usize,
    /// Confidence assigned to matches.
    #[serde(default = "default_label_conf")]
    pub confidence: f32,
    /// Take only a value holding at least one ASCII digit: the first such
    /// match whose start lies in the window (`V-12345678`, not `HTTP`).
    #[serde(default)]
    pub require_digit: bool,
}

/// `[domain]` configuration table.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DomainConfig {
    /// Pattern rules.
    #[serde(default)]
    pub patterns: Vec<DomainPattern>,
    /// Label-triggered rules.
    #[serde(default)]
    pub labels: Vec<DomainLabel>,
}

struct PatternRule {
    re: Regex,
    kind: EntityKind,
    confidence: f32,
}

struct LabelRule {
    label_re: Regex,
    value_re: Regex,
    kind: EntityKind,
    window: usize,
    confidence: f32,
    require_digit: bool,
}

/// Detector for configured domain identifiers.
pub struct DomainDetector {
    patterns: Vec<PatternRule>,
    labels: Vec<LabelRule>,
}

impl fmt::Debug for DomainDetector {
    /// Prints rule counts only; never the configured pattern or label text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DomainDetector")
            .field("patterns", &self.patterns.len())
            .field("labels", &self.labels.len())
            .finish()
    }
}

impl DomainDetector {
    /// Compile rules. Errors name the config key, never the pattern text.
    /// Confidences outside `0.0..=1.0` are rejected.
    pub fn from_config(cfg: &DomainConfig) -> Result<Self> {
        let mut patterns = Vec::new();
        let unit = |v: f32, key: String| -> Result<()> {
            if (0.0..=1.0).contains(&v) {
                Ok(())
            } else {
                Err(Error::ConfigInvalid(key))
            }
        };
        for (i, p) in cfg.patterns.iter().enumerate() {
            unit(p.confidence, format!("domain.patterns[{i}].confidence"))?;
            let re = Regex::new(&format!(r"\b(?:{})\b", p.regex))
                .map_err(|_| Error::InvalidPattern(format!("domain.patterns[{i}].regex")))?;
            patterns.push(PatternRule {
                re,
                kind: EntityKind::from_label(&p.kind),
                confidence: p.confidence,
            });
        }
        let mut labels = Vec::new();
        for (i, l) in cfg.labels.iter().enumerate() {
            unit(l.confidence, format!("domain.labels[{i}].confidence"))?;
            // Input text is NFC-normalized by the engine; labels must be too. Matching is
            // already case-insensitive (the `(?i)` flag below is Unicode-aware by default,
            // since the `regex` crate's `unicode-case` feature is on), so a config never
            // needs to list both "Invoice" and "invoice" — only genuinely different
            // wordings or punctuation.
            //
            // A trailing `\b` is added per label, not once after the whole group: `\b` only
            // fires at a transition between a word and a non-word character, so a label
            // ending in punctuation (an abbreviation like "Inv." or "Cust. no.") followed by
            // the whitespace that separates it from its value — the overwhelmingly common
            // case — would otherwise never match (both the label's trailing '.' and the
            // following space are non-word, so no transition exists there). A label ending
            // in a word character (a letter or digit, e.g. "Invoice") still gets its `\b` to
            // avoid matching a prefix of a longer word (so "Invoice" doesn't fire inside
            // "Invoicing").
            let alts: Vec<String> = l
                .labels
                .iter()
                .map(|s| {
                    let nfc = s.nfc().collect::<String>();
                    let escaped = regex::escape(&nfc);
                    if nfc.chars().next_back().is_some_and(char::is_alphanumeric) {
                        format!(r"{escaped}\b")
                    } else {
                        escaped
                    }
                })
                .collect();
            let label_re = Regex::new(&format!(r"(?i)\b(?:{})\s*[:=\-]?\s*", alts.join("|")))
                .map_err(|_| Error::InvalidPattern(format!("domain.labels[{i}].labels")))?;
            let value_re = Regex::new(&l.value)
                .map_err(|_| Error::InvalidPattern(format!("domain.labels[{i}].value")))?;
            labels.push(LabelRule {
                label_re,
                value_re,
                kind: EntityKind::from_label(&l.kind),
                window: l.window,
                confidence: l.confidence,
                require_digit: l.require_digit,
            });
        }
        Ok(DomainDetector { patterns, labels })
    }
}

/// Upper bound on how far past the window end a label value may extend.
const MAX_VALUE_BYTES: usize = 1024;

fn floor_char_boundary(text: &str, mut i: usize) -> usize {
    i = i.min(text.len());
    while !text.is_char_boundary(i) {
        i -= 1;
    }
    i
}

impl Detector for DomainDetector {
    fn id(&self) -> DetectorId {
        DetectorId::Domain
    }

    fn detect(&self, text: &str, _ctx: &DetectCtx) -> crate::Result<Vec<Span>> {
        let mut out = Vec::new();
        for r in &self.patterns {
            for m in r.re.find_iter(text) {
                out.push(Span::new(
                    m.start(),
                    m.end(),
                    r.kind.clone(),
                    r.confidence,
                    DetectorId::Domain,
                ));
            }
        }
        for r in &self.labels {
            for m in r.label_re.find_iter(text) {
                let win_start = m.end();
                let rest = &text[win_start..];
                // `window` counts characters. The value must *start* inside
                // the window but may run past its end, so the search covers
                // the rest of the text up to a generous bound (values longer
                // than `MAX_VALUE_BYTES` are cut there).
                let win_bytes = rest
                    .char_indices()
                    .nth(r.window)
                    .map_or(rest.len(), |(i, _)| i);
                let search_end = floor_char_boundary(rest, win_bytes + MAX_VALUE_BYTES);
                let Some(v) = r
                    .value_re
                    .find_iter(&rest[..search_end])
                    .find(|v| !r.require_digit || v.as_str().bytes().any(|b| b.is_ascii_digit()))
                else {
                    continue;
                };
                if v.start() >= win_bytes {
                    continue;
                }
                out.push(Span::new(
                    win_start + v.start(),
                    win_start + v.end(),
                    r.kind.clone(),
                    r.confidence,
                    DetectorId::Domain,
                ));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::span::EntityKind;

    fn cfg() -> DomainConfig {
        toml::from_str(
            r#"
            [[patterns]]
            regex = "K-[0-9]{6}"
            kind = "CUSTOMER_ID"

            [[labels]]
            labels = ["Kundennummer", "Customer ID", "Vertragsnummer"]
            kind = "CONTRACT_ID"
            value = "[A-Z0-9-]{4,20}"

            [[labels]]
            labels = ["Zählpunkt"]
            kind = "METER_POINT"
            value = "AT[0-9]{10,40}"
            window = 60
            "#,
        )
        .unwrap()
    }

    fn found(text: &str) -> Vec<(EntityKind, String)> {
        let d = DomainDetector::from_config(&cfg()).unwrap();
        d.detect(text, &DetectCtx::for_text(text))
            .unwrap()
            .into_iter()
            .map(|s| (s.kind.clone(), s.slice(text).to_string()))
            .collect()
    }

    #[test]
    fn pattern_rule_is_word_bounded() {
        let v = found("Kunde K-928174 und XK-928174Y");
        assert_eq!(v, vec![(EntityKind::CustomerId, "K-928174".into())]);
    }

    #[test]
    fn label_trigger_finds_value_in_window() {
        let v = found("Ihre Kundennummer: 8439271 wurde aktualisiert. customer id = AB-12345");
        assert!(v.contains(&(EntityKind::ContractId, "8439271".into())));
        assert!(v.contains(&(EntityKind::ContractId, "AB-12345".into())));
    }

    #[test]
    fn label_outside_window_is_ignored() {
        let filler = "x".repeat(50);
        let v = found(&format!("Vertragsnummer {filler} 12345678"));
        assert!(v.is_empty());
    }

    /// M5: the window counts characters, and a value that starts inside
    /// the window is taken whole even when it runs past the window end.
    #[test]
    fn window_counts_characters_and_takes_the_whole_value() {
        let mut c = cfg();
        c.labels[1].window = 10;
        let d = DomainDetector::from_config(&c).unwrap();
        // 8 two-byte chars + space: the value starts at char 9 (< 10) but
        // byte 17 (> 10).
        let text = "Zählpunkt: ääääääää AT0010000000000000001000004392265 ok";
        let v: Vec<String> = d
            .detect(text, &DetectCtx::for_text(text))
            .unwrap()
            .into_iter()
            .map(|s| s.slice(text).to_string())
            .collect();
        assert_eq!(v, vec!["AT0010000000000000001000004392265".to_string()]);
        // a value starting after `window` characters is still ignored
        let text = "Zählpunkt: äääääääääää AT0010000000000000001000004392265";
        assert!(
            d.detect(text, &DetectCtx::for_text(text))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn custom_kind_and_confidence() {
        let d = DomainDetector::from_config(&cfg()).unwrap();
        let text = "Zählpunkt: AT0010000000000000001000004392265";
        let s = &d.detect(text, &DetectCtx::for_text(text)).unwrap()[0];
        assert_eq!(s.kind, EntityKind::custom("meter_point"));
        assert!((s.confidence - 0.92).abs() < 1e-6);
        assert_eq!(s.source, DetectorId::Domain);
    }

    #[test]
    fn debug_output_omits_configured_patterns_and_labels() {
        let d = DomainDetector::from_config(&cfg()).unwrap();
        let dbg = format!("{d:?}");
        assert!(!dbg.contains("K-[0-9]{6}"));
        assert!(!dbg.contains("Kundennummer"));
        assert!(dbg.contains("patterns"));
        assert!(dbg.contains("labels"));
    }

    /// I7: configured confidences must lie in 0.0..=1.0.
    #[test]
    fn out_of_range_confidence_is_rejected_with_key_path() {
        let mut c = cfg();
        c.patterns[0].confidence = 1.2;
        let msg = format!("{}", DomainDetector::from_config(&c).unwrap_err());
        assert!(msg.contains("domain.patterns[0].confidence"), "{msg}");
        let mut c = cfg();
        c.labels[1].confidence = -0.5;
        let msg = format!("{}", DomainDetector::from_config(&c).unwrap_err());
        assert!(msg.contains("domain.labels[1].confidence"), "{msg}");
    }

    #[test]
    fn bad_regex_reports_key_path_not_pattern() {
        let mut c = cfg();
        c.patterns[0].regex = "(".into();
        let err = DomainDetector::from_config(&c).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("domain.patterns[0].regex"));
        assert!(!msg.contains('('));
    }

    fn invoice_cfg() -> DomainConfig {
        toml::from_str(
            r#"
            [[labels]]
            labels = ["Rechnung", "Invoice"]
            kind = "INVOICE_ID"
            value = "[A-Z0-9][A-Z0-9/-]{3,19}"
            "#,
        )
        .unwrap()
    }

    fn found_with(cfg: &DomainConfig, text: &str) -> Vec<(EntityKind, String)> {
        let d = DomainDetector::from_config(cfg).unwrap();
        d.detect(text, &DetectCtx::for_text(text))
            .unwrap()
            .into_iter()
            .map(|s| (s.kind.clone(), s.slice(text).to_string()))
            .collect()
    }

    /// Label matching is case-insensitive (Unicode simple fold via the regex crate's `(?i)`
    /// flag), so a mention of a label in any case still triggers the rule; a config does not
    /// need to list both cases.
    #[test]
    fn label_matching_is_case_insensitive() {
        let cfg = invoice_cfg();
        for text in [
            "invoice RE-2026-12345",
            "Rechnung RE-2026-12345",
            "INVOICE RE-2026-12345",
        ] {
            assert_eq!(
                found_with(&cfg, text),
                vec![(EntityKind::InvoiceId, "RE-2026-12345".to_string())],
                "{text}"
            );
        }
    }

    /// A label ending in punctuation (an abbreviation like "Rechnungsnr.") must still match
    /// when followed by the whitespace that normally separates it from its value: the
    /// trailing `\b` is per-label, not applied once after the whole alternation, since `\b`
    /// cannot fire between two non-word characters (the label's '.' and the following
    /// space).
    #[test]
    fn label_ending_in_a_period_matches_before_whitespace() {
        let cfg: DomainConfig = toml::from_str(
            r#"
            [[labels]]
            labels = ["Rechnungsnr."]
            kind = "INVOICE_ID"
            value = "[A-Z0-9][A-Z0-9/-]{3,19}"
            "#,
        )
        .unwrap();
        assert_eq!(
            found_with(&cfg, "Rechnungsnr. RE-2026-04711 vom 12.03.2026"),
            vec![(EntityKind::InvoiceId, "RE-2026-04711".to_string())]
        );
    }

    /// Plan 2026-10-12 Task 5: with `require_digit`, a label takes the first
    /// value in its window that holds a digit; a word of capitals (`HTTP`)
    /// is not a contract number.
    #[test]
    fn require_digit_skips_capital_words() {
        let cfg: DomainConfig = toml::from_str(
            r#"
            [[labels]]
            labels = ["Contract", "Vertrag"]
            kind = "CONTRACT_ID"
            value = "[A-Z0-9][A-Z0-9-]{3,19}"
            require_digit = true
            "#,
        )
        .unwrap();
        let hits =
            |t: &str| -> Vec<String> { found_with(&cfg, t).into_iter().map(|(_, s)| s).collect() };
        assert!(hits("Keep the API contract stable: the HTTP handler returns JSON.").is_empty());
        assert_eq!(hits("Contract: AB-12345"), vec!["AB-12345"]);
        assert_eq!(hits("Vertrag HTTP V-12345678"), vec!["V-12345678"]);
        assert_eq!(
            hits("I would like to cancel my contract V-48213977."),
            vec!["V-48213977"]
        );
    }
}
