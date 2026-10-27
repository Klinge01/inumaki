//! Reply-draft serialization (M4 spec §6.2): `To` = the original sender,
//! `Re:` subject, `In-Reply-To`/`References`, our own `Message-ID` and
//! `Date`, a text body. Every header value is validated before the builder
//! runs, so no agent-supplied text can inject a header.

use mail_builder::MessageBuilder;
use mail_builder::headers::address::Address;
use mail_builder::headers::date::Date;
use mail_builder::headers::message_id::MessageId;

use crate::error::MailError;
use crate::render::MailAddress;

/// Longest accepted draft body.
pub const MAX_BODY_BYTES: usize = 256 * 1024;
/// Most Cc recipients.
pub const MAX_CC: usize = 20;

/// Refuse control characters (CR, LF, NUL, …) and over-long values.
pub fn validate_header_text(s: &str, field: &'static str) -> Result<(), MailError> {
    if s.len() > 998 || s.chars().any(char::is_control) {
        return Err(MailError::InvalidArgument(field));
    }
    Ok(())
}

/// True for a plain `local@domain` with no whitespace, control characters,
/// or address-list punctuation (`<`, `>`, `,`, `;`, `"`).
pub fn valid_addr_spec(a: &str) -> bool {
    let Some((local, domain)) = a.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !a.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | ',' | ';' | '"')
        })
        && a.matches('@').count() == 1
}

/// True for one msg-id body (no angle brackets): non-empty, at most 998
/// bytes, no whitespace, no control characters, no `<` or `>`. Anything
/// else could write two ids, or a second header, into one header line.
pub fn valid_msgid(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 998
        && !id
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>'))
}

/// Parse a comma-separated Cc list: `Name <a@b>`, `<a@b>`, or `a@b`.
pub fn parse_cc(cc: &str) -> Result<Vec<MailAddress>, MailError> {
    validate_header_text(cc, "cc")?;
    let mut out = Vec::new();
    for item in cc.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let parsed = if let Some(open) = item.find('<') {
            let Some(close) = item[open..].find('>').map(|i| i + open) else {
                return Err(MailError::InvalidArgument("cc"));
            };
            if close != item.len() - 1 {
                return Err(MailError::InvalidArgument("cc"));
            }
            let addr = item[open + 1..close].trim();
            let name = item[..open].trim().trim_matches('"').trim();
            if !valid_addr_spec(addr) {
                return Err(MailError::InvalidArgument("cc"));
            }
            MailAddress {
                name: (!name.is_empty()).then(|| name.to_string()),
                address: Some(addr.to_string()),
            }
        } else {
            if !valid_addr_spec(item) {
                return Err(MailError::InvalidArgument("cc"));
            }
            MailAddress {
                name: None,
                address: Some(item.to_string()),
            }
        };
        out.push(parsed);
        if out.len() > MAX_CC {
            return Err(MailError::InvalidArgument("cc_count"));
        }
    }
    Ok(out)
}

/// `Re: <subject>` unless the subject already starts with `Re:` or `AW:`.
pub fn reply_subject(orig: Option<&str>) -> String {
    let s = orig.map(str::trim).unwrap_or("");
    let lower = s.to_lowercase();
    if lower.starts_with("re:") || lower.starts_with("aw:") {
        return s.to_string();
    }
    if s.is_empty() {
        return "Re:".to_string();
    }
    format!("Re: {s}")
}

/// A fresh `Message-ID`: 40 random hex characters at `domain`.
pub fn new_message_id(domain: &str) -> Result<String, MailError> {
    let mut raw = [0u8; 20];
    getrandom::fill(&mut raw).map_err(|_| MailError::DraftRejected("random"))?;
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{hex}@{domain}"))
}

/// What a reply draft is built from.
#[derive(Clone, Copy)]
pub struct ReplyDraft<'a> {
    /// Our address.
    pub from: &'a str,
    /// The original sender.
    pub to: &'a MailAddress,
    /// Extra recipients.
    pub cc: &'a [MailAddress],
    /// Already `Re:`-prefixed subject.
    pub subject: &'a str,
    /// The original Message-ID (no brackets).
    pub in_reply_to: Option<&'a str>,
    /// The original References (no brackets).
    pub references: &'a [String],
    /// Body text (rehydrated by the gateway before it gets here).
    pub body: &'a str,
    /// Our Message-ID (no brackets).
    pub message_id: &'a str,
    /// Unix seconds for `Date`.
    pub date_unix: i64,
}

impl std::fmt::Debug for ReplyDraft<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplyDraft")
            .field("cc", &self.cc.len())
            .field("subject_len", &self.subject.len())
            .field("references", &self.references.len())
            .field("body_len", &self.body.len())
            .finish()
    }
}

fn address(a: &MailAddress, field: &'static str) -> Result<Address<'static>, MailError> {
    let Some(addr) = a.address.as_deref() else {
        return Err(if field == "to" {
            MailError::DraftRejected("recipient")
        } else {
            MailError::InvalidArgument(field)
        });
    };
    validate_header_text(addr, field)?;
    if !valid_addr_spec(addr) {
        return Err(if field == "to" {
            MailError::DraftRejected("recipient")
        } else {
            MailError::InvalidArgument(field)
        });
    }
    // Display names lose the characters that could open a second address or
    // close the quoted phrase (`<`, `>`, `"`, `\`); mail-builder's own quoting
    // is not relied on for injection safety.
    let name = match &a.name {
        Some(n) => {
            validate_header_text(n, field)?;
            let clean = n.replace(['<', '>', '"', '\\'], "").trim().to_string();
            (!clean.is_empty()).then_some(clean)
        }
        None => None,
    };
    Ok(Address::new_address(name, addr.to_string()))
}

/// Serialize the draft. Validates every header value and the body first;
/// nothing is produced on any failure.
pub fn build_reply(d: &ReplyDraft<'_>) -> Result<Vec<u8>, MailError> {
    if !valid_addr_spec(d.from) || d.from.chars().any(char::is_control) {
        return Err(MailError::DraftRejected("from_address"));
    }
    let to = address(d.to, "to")?;
    let mut cc = Vec::with_capacity(d.cc.len());
    for c in d.cc {
        cc.push(address(c, "cc")?);
    }
    validate_header_text(d.subject, "subject")?;
    if !valid_msgid(d.message_id) {
        return Err(MailError::InvalidArgument("message_id"));
    }
    if d.body.trim().is_empty() || d.body.len() > MAX_BODY_BYTES || d.body.contains('\u{0}') {
        return Err(MailError::InvalidArgument("body"));
    }
    // The thread ids come from the (possibly hostile) original mail: an
    // invalid one is dropped rather than refusing the reply, so
    // In-Reply-To is omitted when the original's Message-ID is invalid.
    let in_reply_to = d.in_reply_to.filter(|i| valid_msgid(i));
    let mut refs: Vec<String> = d
        .references
        .iter()
        .filter(|r| valid_msgid(r))
        .cloned()
        .collect();
    if let Some(i) = in_reply_to {
        if !refs.iter().any(|r| r == i) {
            refs.push(i.to_string());
        }
    }
    let mut b = MessageBuilder::new()
        .from(Address::new_address(None::<String>, d.from.to_string()))
        .to(to)
        .subject(d.subject.to_string())
        .message_id(MessageId::new(d.message_id.to_string()))
        .date(Date::new(d.date_unix))
        .text_body(d.body.to_string());
    if !cc.is_empty() {
        b = b.cc(Address::new_list(cc));
    }
    if let Some(i) = in_reply_to {
        b = b.in_reply_to(MessageId::new(i.to_string()));
    }
    if !refs.is_empty() {
        b = b.references(MessageId::from(refs));
    }
    b.write_to_vec()
        .map_err(|_| MailError::DraftRejected("serialize"))
}
