//! MIME → text (M4 spec §6.3): the text body is preferred, else HTML through
//! html2text at 100 columns (script and style dropped); quoted history and
//! signatures are kept; a nested message/rfc822 is rendered inline once;
//! attachments are listed by name and MIME type only; everything is NFC.
//! `Debug` for every type here prints counts and lengths, never content.

use mail_parser::{Address, HeaderValue, Message, MessageParser, MimeHeaders, PartType};
use unicode_normalization::UnicodeNormalization;

/// Render width for HTML.
pub const HTML_WIDTH: usize = 100;

/// One address as parsed.
#[derive(Clone, PartialEq, Eq)]
pub struct MailAddress {
    /// Display name.
    pub name: Option<String>,
    /// `local@domain`.
    pub address: Option<String>,
}

impl std::fmt::Debug for MailAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailAddress")
            .field("name_len", &self.name.as_ref().map(String::len))
            .field("address_len", &self.address.as_ref().map(String::len))
            .finish()
    }
}

impl MailAddress {
    /// `Name <addr>`, `addr`, or `Name`.
    pub fn display(&self) -> String {
        match (&self.name, &self.address) {
            (Some(n), Some(a)) => format!("{n} <{a}>"),
            (None, Some(a)) => a.clone(),
            (Some(n), None) => n.clone(),
            (None, None) => String::new(),
        }
    }
}

/// An attachment: name and type only; bytes are never fetched or rendered.
#[derive(Clone, PartialEq, Eq)]
pub struct Attachment {
    /// File name from Content-Disposition or Content-Type.
    pub name: Option<String>,
    /// `type/subtype`.
    pub mime: String,
}

impl std::fmt::Debug for Attachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attachment")
            .field("name_len", &self.name.as_ref().map(String::len))
            // the type comes from the sender's headers: its length only
            .field("mime_len", &self.mime.len())
            .finish()
    }
}

/// A parsed message.
#[derive(Clone, PartialEq, Eq)]
pub struct Parsed {
    /// From.
    pub from: Vec<MailAddress>,
    /// To.
    pub to: Vec<MailAddress>,
    /// Cc.
    pub cc: Vec<MailAddress>,
    /// Reply-To.
    pub reply_to: Vec<MailAddress>,
    /// RFC 3339 date.
    pub date: Option<String>,
    /// Subject.
    pub subject: Option<String>,
    /// Message-ID without angle brackets.
    pub message_id: Option<String>,
    /// In-Reply-To (first id).
    pub in_reply_to: Option<String>,
    /// References ids.
    pub references: Vec<String>,
    /// Body text (NFC).
    pub body: String,
    /// Attachments listed only.
    pub attachments: Vec<Attachment>,
    /// Nested message/rfc822 parts rendered inline (depth one).
    pub nested: Vec<Parsed>,
}

impl std::fmt::Debug for Parsed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Parsed")
            .field("from", &self.from.len())
            .field("to", &self.to.len())
            .field("cc", &self.cc.len())
            .field("has_subject", &self.subject.is_some())
            .field("body_len", &self.body.len())
            .field("attachments", &self.attachments.len())
            .field("nested", &self.nested.len())
            .finish()
    }
}

/// NFC-normalize.
pub fn nfc(s: &str) -> String {
    s.nfc().collect()
}

/// One header value on one line: every control character (CR, LF, ESC,
/// NUL, …) becomes a space, so nothing sender-controlled can break the
/// Markdown structure or reach a terminal as an escape sequence.
fn one_line(s: &str) -> String {
    let flat: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    nfc(&flat)
}

fn addresses(a: Option<&Address<'_>>) -> Vec<MailAddress> {
    a.map(|a| {
        a.iter()
            .map(|x| MailAddress {
                name: x.name().map(one_line),
                address: x.address().map(one_line),
            })
            .collect()
    })
    .unwrap_or_default()
}

fn ids(v: &HeaderValue<'_>) -> Vec<String> {
    match v {
        HeaderValue::Text(t) => vec![one_line(t)],
        HeaderValue::TextList(l) => l.iter().map(|t| one_line(t)).collect(),
        _ => Vec::new(),
    }
}

fn strip_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let lower = html.to_ascii_lowercase();
    // drop script and style blocks wholesale
    let mut cleaned = String::with_capacity(html.len());
    let mut pos = 0;
    while let Some(start) = match (lower[pos..].find("<script"), lower[pos..].find("<style")) {
        (Some(a), Some(b)) => Some(a.min(b) + pos),
        (Some(a), None) | (None, Some(a)) => Some(a + pos),
        (None, None) => None,
    } {
        let tag_end = if lower[start..].starts_with("<script") {
            "</script>"
        } else {
            "</style>"
        };
        cleaned.push_str(&html[pos..start]);
        match lower[start..].find(tag_end) {
            Some(e) => pos = start + e + tag_end.len(),
            None => {
                pos = html.len();
                break;
            }
        }
    }
    cleaned.push_str(&html[pos..]);
    let rest = &cleaned;
    let mut in_tag = false;
    for c in rest.chars() {
        match c {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    let out = out
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"");
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// HTML → plain text at [`HTML_WIDTH`] columns; script and style content is
/// dropped; on a renderer error, tags are stripped and whitespace collapsed.
pub fn html_to_text(html: &str) -> String {
    match html2text::config::plain_no_decorate().string_from_read(html.as_bytes(), HTML_WIDTH) {
        Ok(t) => t,
        Err(_) => strip_tags(html),
    }
}

fn body_of(msg: &Message<'_>) -> String {
    if let Some(part) = msg.text_part(0) {
        match &part.body {
            PartType::Text(t) => return t.to_string(),
            PartType::Html(h) => return html_to_text(h),
            _ => {}
        }
    }
    if let Some(h) = msg.body_html(0) {
        return html_to_text(&h);
    }
    String::new()
}

fn mime_of(part: &mail_parser::MessagePart<'_>) -> String {
    match part.content_type() {
        Some(ct) => one_line(&format!(
            "{}/{}",
            ct.ctype().to_ascii_lowercase(),
            ct.subtype().unwrap_or("octet-stream").to_ascii_lowercase()
        )),
        None => "application/octet-stream".to_string(),
    }
}

fn parse_inner(msg: &Message<'_>, depth: u8) -> Parsed {
    let mut attachments = Vec::new();
    let mut nested = Vec::new();
    for part in msg.attachments() {
        match &part.body {
            PartType::Message(inner) if depth == 0 => nested.push(parse_inner(inner, 1)),
            PartType::Message(_) => attachments.push(Attachment {
                name: part.attachment_name().map(one_line),
                mime: "message/rfc822".into(),
            }),
            _ => attachments.push(Attachment {
                name: part.attachment_name().map(one_line),
                mime: mime_of(part),
            }),
        }
    }
    Parsed {
        from: addresses(msg.from()),
        to: addresses(msg.to()),
        cc: addresses(msg.cc()),
        reply_to: addresses(msg.reply_to()),
        date: msg.date().map(|d| d.to_rfc3339()),
        subject: msg.subject().map(one_line),
        message_id: msg.message_id().map(one_line),
        in_reply_to: ids(msg.in_reply_to()).into_iter().next(),
        references: ids(msg.references()),
        body: nfc(&body_of(msg)),
        attachments,
        nested,
    }
}

/// Parse a raw RFC 5322 message. `None` when nothing parses at all.
pub fn parse_message(raw: &[u8]) -> Option<Parsed> {
    let msg = MessageParser::default().parse(raw)?;
    Some(parse_inner(&msg, 0))
}

fn list(v: &[MailAddress]) -> String {
    v.iter()
        .map(MailAddress::display)
        .collect::<Vec<_>>()
        .join(", ")
}

fn headers_block(p: &Parsed, out: &mut String) {
    out.push_str(&format!("**From:** {}\n", list(&p.from)));
    if !p.to.is_empty() {
        out.push_str(&format!("**To:** {}\n", list(&p.to)));
    }
    if !p.cc.is_empty() {
        out.push_str(&format!("**Cc:** {}\n", list(&p.cc)));
    }
    if !p.reply_to.is_empty() {
        out.push_str(&format!("**Reply-To:** {}\n", list(&p.reply_to)));
    }
    if let Some(d) = &p.date {
        out.push_str(&format!("**Date:** {d}\n"));
    }
    out.push_str(&format!(
        "**Subject:** {}\n",
        p.subject.as_deref().unwrap_or("")
    ));
}

/// The Markdown `mail_read` returns: headers, blank line, body, forwarded
/// messages once, attachment list.
pub fn render_markdown(p: &Parsed) -> String {
    let mut out = String::with_capacity(p.body.len() + 256);
    headers_block(p, &mut out);
    out.push('\n');
    out.push_str(p.body.trim_end());
    out.push('\n');
    for n in &p.nested {
        out.push_str("\n--- Forwarded message ---\n");
        headers_block(n, &mut out);
        out.push('\n');
        out.push_str(n.body.trim_end());
        out.push('\n');
        if !n.attachments.is_empty() {
            out.push_str("\n**Attachments (forwarded message):**\n");
            for a in &n.attachments {
                out.push_str(&format!(
                    "- {} ({})\n",
                    a.name.as_deref().unwrap_or("(unnamed)"),
                    a.mime
                ));
            }
        }
    }
    if !p.attachments.is_empty() {
        out.push_str("\n**Attachments:**\n");
        for a in &p.attachments {
            out.push_str(&format!(
                "- {} ({})\n",
                a.name.as_deref().unwrap_or("(unnamed)"),
                a.mime
            ));
        }
    }
    nfc(&out)
}

/// A search-result row.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Summary {
    /// First From address as `Name <addr>`.
    pub from: String,
    /// Subject.
    pub subject: String,
    /// RFC 3339 date, or empty.
    pub date: String,
    /// Body prefix, whitespace collapsed, `…` when cut.
    pub snippet: String,
    /// Message-ID without brackets.
    pub message_id: Option<String>,
}

impl std::fmt::Debug for Summary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Summary")
            .field("from_len", &self.from.len())
            .field("subject_len", &self.subject.len())
            .field("snippet_len", &self.snippet.len())
            .field("has_message_id", &self.message_id.is_some())
            .finish()
    }
}

/// Build a row from `BODY[HEADER]` and a prefix of `BODY[TEXT]`.
pub fn parse_summary(header: &[u8], text_head: &[u8], snippet_chars: usize) -> Summary {
    let mut raw = Vec::with_capacity(header.len() + 2 + text_head.len());
    raw.extend_from_slice(header);
    if !header.ends_with(b"\r\n\r\n") && !header.ends_with(b"\n\n") {
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(text_head);
    let Some(p) = parse_message(&raw) else {
        return Summary::default();
    };
    let words: Vec<&str> = p.body.split_whitespace().collect();
    let joined = words.join(" ");
    let mut snippet: String = joined.chars().take(snippet_chars).collect();
    if joined.chars().count() > snippet_chars {
        snippet.push('…');
    }
    Summary {
        from: p.from.first().map(MailAddress::display).unwrap_or_default(),
        subject: p.subject.clone().unwrap_or_default(),
        date: p.date.clone().unwrap_or_default(),
        snippet,
        message_id: p.message_id.clone(),
    }
}
