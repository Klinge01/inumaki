//! A deterministic fixture mailbox for the scripted mail tasks (M4 spec
//! §13.1): one synthetic DACH/English mail per day from the eval generator,
//! with gold spans, a gold sender, a fixed non-identifying subject, its own
//! Message-ID, every fourth mail also as HTML, every fifth with a PDF
//! attachment. The runner seeds these into a test mailbox and drives the
//! gateway; `dictionary_lists` lets an offline-profile test detect them.
//!
//! The same options always give byte-identical messages: `mail-builder`
//! draws its MIME boundaries from the clock, so they are replaced by fixed
//! ones before the digest is taken.

use mail_builder::MessageBuilder;
use mail_builder::headers::address::Address;
use mail_builder::headers::date::Date;
use mail_builder::headers::message_id::MessageId;
use sha2::{Digest, Sha256};

use crate::corpus::Doc;
use crate::generate::{GenFamily, GenOptions, generate};

/// Default seed (distinct from the tuning and held-out seeds).
pub const DEFAULT_FIXTURE_SEED: u64 = 4711;
/// Default mailbox size.
pub const DEFAULT_FIXTURE_COUNT: usize = 50;
/// Unix day of the first mail (2026-01-05).
const FIRST_DAY: i64 = 20_458;
/// Recipient of every fixture mail.
const TO: &str = "support@musterfirma.example";
/// A tiny PDF header, enough for a parser to call it a PDF.
const PDF_STUB: &[u8] = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<</Type/Catalog>>\nendobj\n";

const DE_SUBJECTS: [&str; 5] = [
    "R\u{fc}ckfrage zur Rechnung",
    "Z\u{e4}hlerstand",
    "Terminvereinbarung",
    "K\u{fc}ndigung",
    "Frage zum Vertrag",
];
const EN_SUBJECTS: [&str; 5] = [
    "Question about my invoice",
    "Meter reading",
    "Appointment",
    "Cancellation",
    "Contract question",
];

/// Generator options.
#[derive(Debug, Clone)]
pub struct FixtureOptions {
    /// Seed.
    pub seed: u64,
    /// Number of mails (one per day from 2026-01-05).
    pub count: usize,
    /// Eval generator family.
    pub family: GenFamily,
    /// Every n-th mail also carries an HTML alternative.
    pub html_every: usize,
    /// Every n-th mail carries a PDF attachment.
    pub attachment_every: usize,
}

impl Default for FixtureOptions {
    fn default() -> Self {
        FixtureOptions {
            seed: DEFAULT_FIXTURE_SEED,
            count: DEFAULT_FIXTURE_COUNT,
            family: GenFamily::Tuning,
            html_every: 4,
            attachment_every: 5,
        }
    }
}

/// One fixture mail with its gold data.
#[derive(Clone, PartialEq)]
pub struct FixtureMail {
    /// Position in the mailbox.
    pub index: usize,
    /// The eval document (text and gold spans) that is the body.
    pub doc: Doc,
    /// Folder to seed into.
    pub folder: String,
    /// Sender display name (a gold PERSON), when the document has one.
    pub from_name: Option<String>,
    /// Sender address (a gold EMAIL, else a synthetic non-identifying one).
    pub from_address: String,
    /// `Reply-To` address on every third mail (the connector must reply there).
    pub reply_to: Option<String>,
    /// Subject (fixed, non-identifying).
    pub subject: String,
    /// Message-ID without brackets.
    pub message_id: String,
    /// `YYYY-MM-DD` of the Date header.
    pub day: String,
    /// The day after (for `before`).
    pub next_day: String,
    /// Unix seconds of the Date header.
    pub date_unix: i64,
    /// The quoted IMAP date-time for `APPEND` (`"\" 5-Jan-2026 09:00:00 +0000\""`),
    /// so the message's INTERNALDATE, which `SINCE`/`BEFORE` search on, is
    /// this day and not the day it was seeded.
    pub internal_date: String,
    /// The RFC 5322 bytes.
    pub eml: Vec<u8>,
}

impl FixtureMail {
    /// Where a correct reply goes: `Reply-To` when set, else the sender.
    pub fn expected_recipient(&self) -> &str {
        self.reply_to.as_deref().unwrap_or(&self.from_address)
    }
}

impl std::fmt::Debug for FixtureMail {
    // the document, the addresses, and the bytes are fixture PII look-alikes: counts only
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FixtureMail")
            .field("index", &self.index)
            .field("folder", &self.folder)
            .field("day", &self.day)
            .field("eml_len", &self.eml.len())
            .field("spans", &self.doc.spans.len())
            .finish()
    }
}

/// Days since 1970-01-01 → (year, month, day) (proleptic Gregorian).
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn iso(days: i64) -> String {
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// The quoted IMAP `date-time` (RFC 3501 §9: `DQUOTE date-day-fixed "-" date-month "-"
/// date-year SP time SP zone DQUOTE`, day space-padded) of a UTC unix time.
pub fn imap_datetime(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "\"{d:>2}-{}-{y:04} {:02}:{:02}:{:02} +0000\"",
        MONTHS[(m - 1) as usize],
        secs / 3_600,
        (secs % 3_600) / 60,
        secs % 60
    )
}

/// The first gold span of `kind` that is safe in a header: the generator's
/// transforms can break a name across lines, which a display name cannot
/// carry.
fn span_text<'a>(doc: &'a Doc, kind: &str) -> Option<&'a str> {
    doc.spans
        .iter()
        .filter(|s| s.kind == kind)
        .map(|s| &doc.text[s.start..s.end])
        .find(|v| !v.chars().any(char::is_control))
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn replace_all(hay: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hay.len());
    let mut at = 0;
    while let Some(p) = find(hay, needle, at) {
        out.extend_from_slice(&hay[at..p]);
        out.extend_from_slice(with);
        at = p + needle.len();
    }
    out.extend_from_slice(&hay[at..]);
    out
}

/// Replace every MIME boundary the builder drew (from the clock) with a
/// fixed one, in order of first appearance, so the same options give the
/// same bytes.
fn pin_boundaries(eml: Vec<u8>, seed: u64, index: usize) -> Vec<u8> {
    const KEY: &[u8] = b"boundary=\"";
    let mut found: Vec<Vec<u8>> = Vec::new();
    let mut at = 0;
    while let Some(p) = find(&eml, KEY, at) {
        let start = p + KEY.len();
        let Some(len) = eml[start..].iter().position(|&b| b == b'"') else {
            break;
        };
        let value = eml[start..start + len].to_vec();
        if !value.is_empty() && !found.contains(&value) {
            found.push(value);
        }
        at = start + len;
    }
    let mut out = eml;
    for (k, value) in found.iter().enumerate() {
        out = replace_all(
            &out,
            value,
            format!("=_fixture-{seed}-{index:05}-{k}").as_bytes(),
        );
    }
    out
}

/// Build the mailbox.
pub fn generate_mailbox(opts: &FixtureOptions) -> Vec<FixtureMail> {
    let docs = generate(&GenOptions {
        seed: opts.seed,
        count: opts.count,
        transforms: true,
        family: opts.family,
    });
    docs.into_iter()
        .enumerate()
        .map(|(index, doc)| {
            let day_num = FIRST_DAY + index as i64;
            let date_unix = day_num * 86_400 + 9 * 3_600;
            let from_name = span_text(&doc, "PERSON").map(str::to_string);
            // an obfuscated gold EMAIL (`name [at] host`) is no address: use the synthetic one
            let from_address = span_text(&doc, "EMAIL")
                .filter(|a| {
                    a.contains('@')
                        && !a
                            .chars()
                            .any(|c| c.is_whitespace() || matches!(c, '<' | '>' | '"' | ','))
                })
                .map(str::to_string)
                .unwrap_or_else(|| format!("absender-{index:04}@fixture.example"));
            let subjects = if doc.lang == "en" {
                &EN_SUBJECTS
            } else {
                &DE_SUBJECTS
            };
            let subject = subjects[index % subjects.len()].to_string();
            let message_id = format!("fx-{}-{index:05}@fixture.example", opts.seed);
            // every third mail asks for replies elsewhere: the connector must honour Reply-To
            let reply_to = (index % 3 == 2).then(|| format!("reply-{index:04}@fixture.example"));
            let mut b = MessageBuilder::new()
                .from(Address::new_address(
                    from_name.clone(),
                    from_address.clone(),
                ))
                .to(Address::new_address(Some("Support"), TO))
                .subject(subject.clone())
                .message_id(MessageId::new(message_id.clone()))
                .date(Date::new(date_unix))
                .text_body(doc.text.clone());
            if let Some(r) = &reply_to {
                b = b.reply_to(Address::new_address(None::<String>, r.clone()));
            }
            if opts.html_every > 0 && index % opts.html_every == opts.html_every - 1 {
                let paragraphs: Vec<String> = doc
                    .text
                    .split("\n\n")
                    .map(|p| format!("<p>{}</p>", escape_html(p).replace('\n', "<br>")))
                    .collect();
                b = b.html_body(format!(
                    "<html><body>{}</body></html>",
                    paragraphs.join("\n")
                ));
            }
            if opts.attachment_every > 0
                && index % opts.attachment_every == opts.attachment_every - 1
            {
                b = b.attachment("application/pdf", "Rechnung.pdf", PDF_STUB.to_vec());
            }
            let eml = b
                .write_to_vec()
                .expect("in-memory serialization cannot fail");
            let eml = pin_boundaries(eml, opts.seed, index);
            FixtureMail {
                index,
                doc,
                folder: "INBOX".into(),
                from_name,
                from_address,
                reply_to,
                subject,
                message_id,
                day: iso(day_num),
                next_day: iso(day_num + 1),
                date_unix,
                internal_date: imap_datetime(date_unix),
                eml,
            }
        })
        .collect()
}

/// SHA-256 over every `eml` in order, hex.
pub fn fixture_digest(mails: &[FixtureMail]) -> String {
    let mut h = Sha256::new();
    for m in mails {
        h.update((m.eml.len() as u64).to_be_bytes());
        h.update(&m.eml);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Dictionary lists for an offline-profile run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DictionaryLists {
    /// Gold PERSON values.
    pub persons: Vec<String>,
    /// Gold STREET_ADDRESS values.
    pub addresses: Vec<String>,
    /// Gold ORGANIZATION values.
    pub organizations: Vec<String>,
}

/// Gold values by kind, sorted and deduplicated.
pub fn dictionary_lists(mails: &[FixtureMail]) -> DictionaryLists {
    let mut d = DictionaryLists::default();
    for m in mails {
        for s in &m.doc.spans {
            let v = m.doc.text[s.start..s.end].to_string();
            match s.kind.as_str() {
                "PERSON" => d.persons.push(v),
                "STREET_ADDRESS" => d.addresses.push(v),
                "ORGANIZATION" => d.organizations.push(v),
                _ => {}
            }
        }
    }
    for l in [&mut d.persons, &mut d.addresses, &mut d.organizations] {
        l.sort();
        l.dedup();
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_parser::MessageParser;

    #[test]
    fn fixtures_are_deterministic_and_parse() {
        let a = generate_mailbox(&FixtureOptions {
            count: 12,
            ..FixtureOptions::default()
        });
        let b = generate_mailbox(&FixtureOptions {
            count: 12,
            ..FixtureOptions::default()
        });
        assert_eq!(
            a, b,
            "same seed, byte-identical mailbox (boundaries pinned)"
        );
        assert_eq!(fixture_digest(&a), fixture_digest(&b));
        assert_ne!(
            fixture_digest(&a),
            fixture_digest(&generate_mailbox(&FixtureOptions {
                count: 12,
                seed: 1,
                ..FixtureOptions::default()
            }))
        );
        assert_eq!(a.len(), 12);
        let mut days = std::collections::BTreeSet::new();
        for (i, m) in a.iter().enumerate() {
            assert_eq!(m.index, i);
            assert_eq!(m.folder, "INBOX");
            assert!(days.insert(m.day.clone()), "one mail per day: {}", m.day);
            let parsed = MessageParser::default().parse(&m.eml).expect("eml parses");
            assert_eq!(parsed.message_id(), Some(m.message_id.as_str()));
            assert_eq!(parsed.subject(), Some(m.subject.as_str()));
            assert_eq!(
                parsed.from().unwrap().first().unwrap().address(),
                Some(m.from_address.as_str())
            );
            assert_eq!(
                parsed
                    .from()
                    .unwrap()
                    .first()
                    .unwrap()
                    .name()
                    .map(str::to_string),
                m.from_name
            );
            assert_eq!(parsed.date().map(|d| d.to_timestamp()), Some(m.date_unix));
            let body = parsed.body_text(0).unwrap();
            assert!(
                body.contains(m.doc.text.lines().next().unwrap().trim()),
                "body is the doc text"
            );
            assert!(
                m.from_name.as_deref().is_none_or(|n| m
                    .doc
                    .spans
                    .iter()
                    .any(|s| s.kind == "PERSON" && &m.doc.text[s.start..s.end] == n)),
                "the sender is a gold PERSON"
            );
            m.doc.validate().unwrap();
        }
        assert_eq!(
            a.iter()
                .filter(|m| m.eml.windows(9).any(|w| w == b"text/html"))
                .count(),
            3,
            "every 4th is HTML too"
        );
        assert_eq!(
            a.iter()
                .filter(|m| m.eml.windows(15).any(|w| w == b"application/pdf"))
                .count(),
            2,
            "every 5th has an attachment"
        );
        assert_eq!(a[0].day, "2026-01-05");
        assert_eq!(a[0].next_day, "2026-01-06");
        assert_eq!(a[11].day, "2026-01-16");
        assert_eq!(
            a[0].internal_date, "\" 5-Jan-2026 09:00:00 +0000\"",
            "IMAP date-time, day space-padded, quoted"
        );
        assert_eq!(a[11].internal_date, "\"16-Jan-2026 09:00:00 +0000\"");
        assert_eq!(imap_datetime(0), "\" 1-Jan-1970 00:00:00 +0000\"");
        let with_reply_to: Vec<usize> = a
            .iter()
            .filter(|m| m.reply_to.is_some())
            .map(|m| m.index)
            .collect();
        assert_eq!(
            with_reply_to,
            [2, 5, 8, 11],
            "every third mail carries Reply-To"
        );
        for m in &a {
            let parsed = MessageParser::default().parse(&m.eml).unwrap();
            assert_eq!(
                parsed
                    .reply_to()
                    .and_then(|r| r.first())
                    .and_then(|x| x.address())
                    .map(str::to_string),
                m.reply_to
            );
            assert_eq!(
                m.expected_recipient(),
                m.reply_to.as_deref().unwrap_or(&m.from_address)
            );
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_454), (2026, 1, 1));
        let d = dictionary_lists(&a);
        assert!(!d.persons.is_empty() && d.persons.windows(2).all(|w| w[0] < w[1]));
        assert!(
            d.persons
                .iter()
                .all(|p| a.iter().any(|m| m.doc.text.contains(p.as_str())))
        );
        let dbg = format!("{:?}", a[0]);
        assert!(!dbg.contains(&a[0].from_address) && dbg.contains("eml_len"));
    }

    #[test]
    fn every_default_fixture_parses_back_in_both_families() {
        for family in [GenFamily::Tuning, GenFamily::HeldOut] {
            for m in generate_mailbox(&FixtureOptions {
                family,
                ..FixtureOptions::default()
            }) {
                let parsed = MessageParser::default().parse(&m.eml).expect("eml parses");
                let from = parsed.from().unwrap().first().unwrap();
                assert_eq!(
                    from.address(),
                    Some(m.from_address.as_str()),
                    "mail {}",
                    m.index
                );
                assert_eq!(
                    from.name().map(str::to_string),
                    m.from_name,
                    "mail {}",
                    m.index
                );
            }
        }
    }

    #[test]
    fn multipart_boundaries_are_pinned() {
        let a = generate_mailbox(&FixtureOptions {
            count: 6,
            ..FixtureOptions::default()
        });
        // index 3 is HTML too, index 4 has the attachment: both multipart
        for i in [3usize, 4] {
            let s = String::from_utf8_lossy(&a[i].eml);
            assert!(
                s.contains(&format!("boundary=\"=_fixture-4711-{i:05}-0\"")),
                "mail {i} has a pinned boundary"
            );
        }
    }
}
