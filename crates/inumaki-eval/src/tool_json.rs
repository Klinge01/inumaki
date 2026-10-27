//! `tool_json` track (M4 spec §16.6): MCP-shaped tool results with nested
//! objects and arrays, typed identifier fields (numeric customer ids among
//! them), free-text fields, and `structuredContent` duplicated in a text
//! block; gold spans from the generator families. Recall, accepted leak, and
//! block rate are reported per track and per kind; gates are set after the
//! first measurement by spec revision.

use inumaki_core::config::TokenSettings;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::corpus::{GoldSpan, default_sensitive};
use crate::generate::{GenFamily, Lists, Values, values_with};
use crate::metrics::{EvalOutcome, Report};
use crate::residue::{Residue, find_residue};
use crate::rng::Rng;

/// Field semantics the contract would assign (plan 2's `FieldHint` shape, as labels).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum BlockHint {
    /// Detect, sanitize, verify.
    FreeText,
    /// The whole value is this kind.
    Identifier(String),
}

/// One block of a tool result.
#[derive(Clone, PartialEq, Serialize)]
pub struct ToolBlock {
    /// JSON pointer inside the result (`content/0/text`, `structuredContent/messages/0/from`).
    pub path: String,
    /// The block text.
    pub text: String,
    /// Field semantics.
    pub hint: BlockHint,
    /// Gold spans into `text`.
    pub spans: Vec<GoldSpan>,
}

impl std::fmt::Debug for ToolBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolBlock")
            .field("path", &self.path)
            .field("hint", &self.hint)
            .field("len", &self.text.len())
            .field("spans", &self.spans.len())
            .finish()
    }
}

/// One tool result.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ToolDoc {
    /// `tj-NNNNN` (tuning) or `tjho-NNNNN` (held-out).
    pub id: String,
    /// `de` or `en`.
    pub lang: String,
    /// `blocks[0]` is the serialized structured content as a text block.
    pub blocks: Vec<ToolBlock>,
}

/// Generator options.
#[derive(Debug, Clone)]
pub struct ToolOptions {
    /// Seed (default 4243).
    pub seed: u64,
    /// Documents (default 300).
    pub count: usize,
    /// Identity family.
    pub family: GenFamily,
}

impl Default for ToolOptions {
    fn default() -> Self {
        ToolOptions {
            seed: 4243,
            count: 300,
            family: GenFamily::Tuning,
        }
    }
}

const DE_SNIPPETS: &[&str] = &[
    "ich bin umgezogen und wohne jetzt in der {STREET}, {ZIP_CITY}. Kundennummer {CUSTOMER_ID}.",
    "bitte rufen Sie mich unter {PHONE} zurück, es geht um Rechnung {INVOICE_ID}.",
    "meine IBAN lautet {IBAN}, Kontoinhaber ist {PERSON}.",
    "Frau {LAST} hat mich gebeten, Ihnen das weiterzuleiten.",
];
const EN_SNIPPETS: &[&str] = &[
    "I have moved and now live at {STREET}, {ZIP_CITY}. Customer number {CUSTOMER_ID}.",
    "please call me back on {PHONE} regarding invoice {INVOICE_ID}.",
    "my IBAN is {IBAN}, account holder {PERSON}.",
    "Mr {LAST} asked me to forward this to you.",
];
const SUBJECTS: &[&str] = &[
    "Adressänderung {CUSTOMER_ID}",
    "Rechnung {INVOICE_ID}",
    "Vertrag {CONTRACT_ID}",
    "Rückruf {PERSON}",
    "Re: your request",
    "Invoice {INVOICE_ID} question",
];

struct Slot {
    path: String,
    text: String,
    hint: BlockHint,
    spans: Vec<GoldSpan>,
}

/// One free-text field, filled from `template` against `v`. `entity` (a
/// gold entity id such as `"p"` or `"p2"`) is stamped onto this field's
/// `PERSON` spans only: a subject or snippet naming the second person in
/// the thread must not be linked to the first.
fn field(path: &str, template: &str, v: &Values, entity: Option<&str>) -> Slot {
    let mut b = crate::generate::Builder::new(false);
    b.fill(template, v);
    let (text, mut spans) = b.into_parts();
    for g in spans.iter_mut().filter(|g| g.kind == "PERSON") {
        g.entity = entity.map(str::to_string);
    }
    Slot {
        path: path.to_string(),
        text,
        hint: BlockHint::FreeText,
        spans,
    }
}

/// One typed identifier field: the whole value is the gold span.
fn identifier(path: &str, value: &str, kind: &str) -> Slot {
    Slot {
        path: path.to_string(),
        text: value.to_string(),
        hint: BlockHint::Identifier(kind.to_string()),
        spans: vec![GoldSpan {
            start: 0,
            end: value.len(),
            kind: kind.to_string(),
            sensitive: default_sensitive(kind),
            entity: None,
        }],
    }
}

/// Locate every field value in the serialized JSON and produce the text
/// block's gold spans. Values are looked up by their JSON-escaped form and
/// must be word-bounded (a bare id inside a longer digit run is not a
/// match); a value that occurs more than once is marked at every
/// occurrence.
///
/// Ordering invariant: `fields` is scanned in order, and once a range is
/// claimed by an earlier field's span, a later field's overlapping match is
/// skipped (`spans.iter().any(|x| x.start < e && s < x.end)`). A longer
/// value that contains a shorter one as a literal substring (a full
/// `PERSON` name containing its own bare surname, e.g. `"Sarah Gruber"` and
/// `"Gruber"`) must therefore have its field placed *before* the shorter
/// one in `fields`, or the shorter value's match inside the longer one's
/// own occurrence claims that range first, and the longer value's own
/// match is then skipped as an overlap — silently losing the full-name gold
/// span rather than raising an error. `generate_tool_docs` currently
/// satisfies this by construction: each message's `from` field (the full
/// name) is always pushed before that message's `subject`/`snippet`
/// fields, and a `{LAST}`-only mention always names the same identity
/// (`entity: Some("p")`) whose full name was established by an earlier
/// message's `from` (message 0's, at the latest) — but this is an implicit
/// property of the generator's draw order, not something this function
/// enforces or can check; a future template change (e.g. a bare `{LAST2}`
/// slot before `{PERSON2}` is ever used) could violate it without any test
/// failing except by chance. See
/// `tests::a_shorter_value_that_is_a_substring_of_an_earlier_longer_value_does_not_lose_the_longer_spans_gold_span`
/// for the shape of failure this would cause.
fn text_block(json: &str, fields: &[Slot]) -> ToolBlock {
    let mut spans: Vec<GoldSpan> = Vec::new();
    for f in fields {
        for g in &f.spans {
            let raw = &f.text[g.start..g.end];
            let escaped = serde_json::to_string(raw).expect("a string serializes");
            let needle = &escaped[1..escaped.len() - 1];
            for (i, _) in json.match_indices(needle) {
                let (s, e) = (i, i + needle.len());
                // a value must stand alone inside its JSON string or number:
                // no digit or letter directly before or after it, so a customer
                // id cannot be marked inside a phone number or a date
                if !inumaki_core::detect::dictionary::word_bounded(json, s, e) {
                    continue;
                }
                if spans.iter().any(|x| x.start < e && s < x.end) {
                    continue;
                }
                spans.push(GoldSpan {
                    start: s,
                    end: e,
                    kind: g.kind.clone(),
                    sensitive: g.sensitive,
                    entity: g.entity.clone(),
                });
            }
        }
    }
    spans.sort_by_key(|s| s.start);
    ToolBlock {
        path: "content/0/text".into(),
        text: json.to_string(),
        hint: BlockHint::FreeText,
        spans,
    }
}

/// Deterministic tool results from `o.family`'s lists.
pub fn generate_tool_docs(o: &ToolOptions) -> Vec<ToolDoc> {
    let mut rng = Rng::new(o.seed);
    let l = match o.family {
        GenFamily::Tuning => Lists::tuning(),
        GenFamily::HeldOut => Lists::held_out(),
    };
    let prefix = match o.family {
        GenFamily::Tuning => "tj",
        GenFamily::HeldOut => "tjho",
    };
    (0..o.count)
        .map(|idx| {
            let de = rng.chance(0.6);
            // `values_with` draws both persons (`v.p`, `v.p2`) and every
            // other value (street, phone, ids, ...) from `l` in one shot;
            // the brief's `values_for(rng, l, p, p2)` over externally built
            // `Person`s is not needed since this landed function already
            // does exactly that internally.
            let v = values_with(&mut rng, &l);
            let n = 1 + rng.below(3);
            let mut fields: Vec<Slot> = Vec::new();
            let mut messages: Vec<Value> = Vec::new();
            for m in 0..n {
                let base = format!("structuredContent/messages/{m}");
                let from = field(
                    &format!("{base}/from"),
                    if m == 0 {
                        "{PERSON} <{EMAIL}>"
                    } else {
                        "{PERSON2} <{EMAIL2}>"
                    },
                    &v,
                    Some(if m == 0 { "p" } else { "p2" }),
                );
                let subject = field(
                    &format!("{base}/subject"),
                    rng.pick::<&str>(SUBJECTS),
                    &v,
                    Some("p"),
                );
                let snippet = field(
                    &format!("{base}/snippet"),
                    if de {
                        rng.pick::<&str>(DE_SNIPPETS)
                    } else {
                        rng.pick::<&str>(EN_SNIPPETS)
                    },
                    &v,
                    Some("p"),
                );
                let customer = v.customer_digits();
                let cid = identifier(&format!("{base}/customer_id"), &customer, "CUSTOMER_ID");
                let contract = identifier(&format!("{base}/contract"), v.contract(), "CONTRACT_ID");
                messages.push(json!({
                    "id": format!("mm_{:016x}", rng.next_u64()),
                    "from": from.text.clone(),
                    "subject": subject.text.clone(),
                    "snippet": snippet.text.clone(),
                    "customer_id": customer.parse::<u64>().expect("digits"),
                    "contract": contract.text.clone(),
                    "date": v.date(),
                    "flags": { "unread": m == 0, "attachments": rng.below(3) }
                }));
                fields.extend([from, subject, snippet, cid, contract]);
            }
            let structured = json!({ "messages": messages, "total": n, "folder": "INBOX" });
            let json_text = serde_json::to_string(&structured).expect("serializes");
            let mut blocks = vec![text_block(&json_text, &fields)];
            blocks.extend(fields.into_iter().map(|f| ToolBlock {
                path: f.path,
                text: f.text,
                hint: f.hint,
                spans: f.spans,
            }));
            ToolDoc {
                id: format!("{prefix}-{idx:05}"),
                lang: if de { "de" } else { "en" }.into(),
                blocks,
            }
        })
        .collect()
}

/// SHA-256 over every block's id, path, text, hint, and spans, in order.
pub fn digest_tool_docs(docs: &[ToolDoc]) -> String {
    let mut h = Sha256::new();
    for d in docs {
        h.update(serde_json::to_string(d).expect("serializes").as_bytes());
        h.update(b"\n");
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Evaluate `docs`: `sanitize` returns one outcome per block (in order). A
/// document is accepted when every block is `Pass`, uncertain when none is
/// blocked and one is `PassUncertain`, blocked otherwise; residue is
/// checked per block against its own gold spans; recall is not measured
/// (blocks carry no separate detection pass; the sanitized output is the
/// evidence).
pub fn evaluate_tool_docs(
    docs: &[ToolDoc],
    sanitize: &mut dyn FnMut(&ToolDoc) -> Vec<EvalOutcome>,
    settings: &TokenSettings,
) -> Report {
    let _ = settings;
    let mut r = Report {
        profile: String::new(),
        docs: docs.len(),
        ..Default::default()
    };
    for d in docs {
        for b in &d.blocks {
            for g in &b.spans {
                r.per_kind.entry(g.kind.clone()).or_default().gold += 1;
            }
        }
        let outs = sanitize(d);
        if outs.len() != d.blocks.len() || outs.iter().any(|o| matches!(o, EvalOutcome::StoreError))
        {
            r.store_errors += 1;
            continue;
        }
        let lang = r.per_lang.entry(d.lang.clone()).or_default();
        lang.docs += 1;
        if outs.iter().any(|o| matches!(o, EvalOutcome::Blocked)) {
            r.blocked_docs += 1;
            lang.blocked += 1;
            continue;
        }
        let uncertain = outs
            .iter()
            .any(|o| matches!(o, EvalOutcome::PassUncertain { .. }));
        let mut leaked = false;
        for (b, o) in d.blocks.iter().zip(&outs) {
            let (EvalOutcome::Pass { text, .. } | EvalOutcome::PassUncertain { text, .. }) = o
            else {
                continue;
            };
            for g in b.spans.iter().filter(|g| g.sensitive) {
                match find_residue(&g.kind, &b.text[g.start..g.end], text) {
                    Some(Residue::Full) => {
                        r.per_kind.entry(g.kind.clone()).or_default().leaked += 1;
                        leaked = true;
                    }
                    Some(Residue::Partial) => {
                        r.per_kind.entry(g.kind.clone()).or_default().partial_leaked += 1;
                        leaked = true;
                    }
                    None => {}
                }
            }
        }
        r.docs_with_leak += usize::from(leaked);
        if uncertain {
            r.uncertain_docs += 1;
            lang.uncertain += 1;
            r.uncertain_leak_docs += usize::from(leaked);
        } else {
            r.pass_docs += 1;
            lang.accepted += 1;
            r.accepted_leak_docs += usize::from(leaked);
            lang.accepted_leak += usize::from(leaked);
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review finding (minor): `text_block`'s de-duplication depends on the
    /// order `fields` is scanned in — a longer value (a full `PERSON` name)
    /// must be located before a shorter value that is its literal substring
    /// (the bare surname), or the surname's own match inside the full
    /// name's occurrence claims that range first and the full name's own,
    /// larger match is then skipped as an overlap. Exercises `text_block`
    /// directly (not the generator) with a hand-built `fields` order,
    /// matching the doc comment's example.
    #[test]
    fn a_shorter_value_that_is_a_substring_of_an_earlier_longer_value_does_not_lose_the_longer_spans_gold_span()
     {
        let full_name = Slot {
            path: "structuredContent/messages/0/from".into(),
            text: "Sarah Gruber".into(),
            hint: BlockHint::FreeText,
            spans: vec![GoldSpan {
                start: 0,
                end: "Sarah Gruber".len(),
                kind: "PERSON".into(),
                sensitive: true,
                entity: Some("p".into()),
            }],
        };
        let surname_only = Slot {
            path: "structuredContent/messages/0/subject".into(),
            text: "Gruber".into(),
            hint: BlockHint::FreeText,
            spans: vec![GoldSpan {
                start: 0,
                end: "Gruber".len(),
                kind: "PERSON".into(),
                sensitive: true,
                entity: Some("p".into()),
            }],
        };
        let structured = json!({ "from": "Sarah Gruber <sarah@example.at>", "subject": "Gruber" });
        let json_text = serde_json::to_string(&structured).expect("serializes");

        // Correct order (as `generate_tool_docs` builds it): the full name's
        // field precedes the bare-surname field.
        let block = text_block(&json_text, &[full_name, surname_only]);
        let full_span = block
            .spans
            .iter()
            .find(|s| &block.text[s.start..s.end] == "Sarah Gruber")
            .expect("the full name is a gold span at its own position");
        assert_eq!(full_span.kind, "PERSON");
        let surname_span = block
            .spans
            .iter()
            .find(|s| &block.text[s.start..s.end] == "Gruber" && s.start != full_span.start)
            .expect("the standalone surname (in \"subject\") is a separate gold span");
        assert!(
            surname_span.start >= full_span.end || surname_span.end <= full_span.start,
            "the standalone surname's span must not overlap the full name's span"
        );
        // No spurious third span: "Gruber" inside "Sarah Gruber" is not
        // separately marked (it is covered by the full name's span).
        assert_eq!(block.spans.len(), 2, "{:?}", block.spans);
    }

    #[test]
    fn tool_docs_are_deterministic_shaped_and_pinned() {
        let a = generate_tool_docs(&ToolOptions::default());
        let b = generate_tool_docs(&ToolOptions::default());
        assert_eq!(digest_tool_docs(&a), digest_tool_docs(&b));
        assert_eq!(a.len(), 300);
        let d = &a[0];
        assert_eq!(d.blocks[0].path, "content/0/text");
        assert_eq!(d.blocks[0].hint, BlockHint::FreeText);
        let json: serde_json::Value = serde_json::from_str(&d.blocks[0].text)
            .expect("the text block is the serialized structuredContent");
        assert!(json["messages"].is_array());
        assert!(
            d.blocks
                .iter()
                .any(|b| b.hint == BlockHint::Identifier("CUSTOMER_ID".into())
                    && b.text.chars().all(|c| c.is_ascii_digit())),
            "a numeric customer id is a typed identifier block: {:?}",
            d.blocks
                .iter()
                .map(|b| (&b.path, &b.hint))
                .collect::<Vec<_>>()
        );
        assert!(
            d.blocks
                .iter()
                .any(|b| b.path.ends_with("/from") && b.hint == BlockHint::FreeText)
        );
        for b in &d.blocks {
            let doc = crate::corpus::Doc {
                id: format!("{}:{}", d.id, b.path),
                lang: d.lang.clone(),
                text: b.text.clone(),
                spans: b.spans.clone(),
                why: None,
            };
            doc.validate().unwrap_or_else(|e| panic!("{e}"));
        }
        // the text block's gold spans point at the same values as the field blocks
        let text = &d.blocks[0];
        for b in &d.blocks[1..] {
            for g in &b.spans {
                let value = &b.text[g.start..g.end];
                assert!(
                    text.spans
                        .iter()
                        .any(|t| &text.text[t.start..t.end] == value && t.kind == g.kind),
                    "{value} of {} missing in the text block",
                    b.path
                );
            }
        }
        let ho = generate_tool_docs(&ToolOptions {
            family: crate::generate::GenFamily::HeldOut,
            ..ToolOptions::default()
        });
        assert_ne!(digest_tool_docs(&ho), digest_tool_docs(&a));
    }

    #[test]
    fn evaluation_counts_per_block_and_per_document() {
        use crate::metrics::{EvalOutcome, Replaced};
        let docs = generate_tool_docs(&ToolOptions {
            count: 5,
            ..ToolOptions::default()
        });
        // a sanitizer that tokenizes every gold span of every block except the first document's text block, which it leaves in clear
        let mut sanitize = |d: &ToolDoc| -> Vec<EvalOutcome> {
            d.blocks
                .iter()
                .enumerate()
                .map(|(i, b)| {
                    if d.id.ends_with("00000") && i == 0 {
                        return EvalOutcome::Pass {
                            text: b.text.clone(),
                            replaced: Vec::new(),
                        };
                    }
                    let mut text = String::new();
                    let mut replaced = Vec::new();
                    let mut cur = 0;
                    for (n, g) in b.spans.iter().enumerate() {
                        text.push_str(&b.text[cur..g.start]);
                        let s = text.len();
                        text.push_str(&format!("<{}_{:04x}>", g.kind, n));
                        replaced.push(Replaced {
                            start: g.start,
                            end: g.end,
                            out_start: s,
                            out_end: text.len(),
                            kind: g.kind.clone(),
                            tokenized: true,
                        });
                        cur = g.end;
                    }
                    text.push_str(&b.text[cur..]);
                    EvalOutcome::Pass { text, replaced }
                })
                .collect()
        };
        let r = evaluate_tool_docs(
            &docs,
            &mut sanitize,
            &inumaki_core::config::TokenSettings::default(),
        );
        assert_eq!(r.docs, 5);
        assert_eq!(r.pass_docs, 5);
        assert_eq!(r.accepted_leak_docs, 1, "the clear text block leaks");
        assert!(r.per_kind["PERSON"].gold > 0 && r.per_kind["CUSTOMER_ID"].gold > 0);
        assert_eq!(
            r.per_kind["CUSTOMER_ID"].leaked,
            r.per_kind["CUSTOMER_ID"].leaked.min(2),
            "at most the first document's ids"
        );
        assert_eq!(r.provenance.family, "");
    }
}
