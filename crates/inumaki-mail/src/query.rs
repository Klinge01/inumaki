//! IMAP search criteria built from a plain query and ISO dates (M4 spec
//! §6.2), quoting that cannot become a second command, and the modified
//! UTF-7 decoding of folder names (RFC 3501 §5.1.3) for display.

use crate::error::MailError;

/// Longest accepted query.
pub const MAX_QUERY_CHARS: usize = 256;

/// A quoted IMAP string. Refuses empty input, control characters (so no
/// CR/LF can end the command), and over-long input.
pub fn quote_search(s: &str) -> Result<String, MailError> {
    if s.is_empty() || s.chars().count() > MAX_QUERY_CHARS || s.chars().any(char::is_control) {
        return Err(MailError::InvalidArgument("query"));
    }
    Ok(format!(
        "\"{}\"",
        s.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn days_in_month(y: u32, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        _ => 0,
    }
}

/// `YYYY-MM-DD` → IMAP `D-Mon-YYYY`.
pub fn imap_date(iso: &str) -> Result<String, MailError> {
    let b = iso.as_bytes();
    if b.len() != 10
        || b[4] != b'-'
        || b[7] != b'-'
        || !b
            .iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
    {
        return Err(MailError::InvalidArgument("date"));
    }
    let y: u32 = iso[0..4]
        .parse()
        .map_err(|_| MailError::InvalidArgument("date"))?;
    let m: u32 = iso[5..7]
        .parse()
        .map_err(|_| MailError::InvalidArgument("date"))?;
    let d: u32 = iso[8..10]
        .parse()
        .map_err(|_| MailError::InvalidArgument("date"))?;
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || d == 0 || d > days_in_month(y, m) {
        return Err(MailError::InvalidArgument("date"));
    }
    Ok(format!("{d}-{}-{y}", MONTHS[(m - 1) as usize]))
}

/// A LITERAL+ (RFC 7888) non-synchronizing literal: `{n+}` CRLF bytes. The
/// server does not send a continuation, so `async-imap`'s `uid_search`
/// (which writes the whole string and then reads responses) can carry it.
/// Only for servers that advertise `LITERAL+`.
pub fn literal_plus(s: &str) -> Result<String, MailError> {
    if s.is_empty() || s.chars().count() > MAX_QUERY_CHARS || s.chars().any(char::is_control) {
        return Err(MailError::InvalidArgument("query"));
    }
    Ok(format!("{{{}+}}\r\n{s}", s.len()))
}

/// `UID SEARCH` criteria: `OR OR FROM q SUBJECT q TEXT q` for the query,
/// `SINCE`/`BEFORE` for the dates. `SINCE`/`BEFORE` compare the server's
/// INTERNALDATE (the date the message was received or appended, RFC 3501
/// §6.4.4), not the `Date` header. A non-ASCII query needs `CHARSET UTF-8`
/// and cannot travel in a quoted string (7-bit only): it is sent as a
/// LITERAL+ literal when `literal_plus` is true, else refused with
/// `invalid_argument("query_charset")`. At least one criterion is required.
pub fn build_search(
    query: Option<&str>,
    since: Option<&str>,
    before: Option<&str>,
    literal_plus_ok: bool,
) -> Result<String, MailError> {
    // A query that was given but is blank is a bad query, not a missing one.
    let query = match query.map(str::trim) {
        Some("") => return Err(MailError::InvalidArgument("query")),
        other => other,
    };
    if query.is_none() && since.is_none() && before.is_none() {
        return Err(MailError::InvalidArgument("search_criteria"));
    }
    let mut parts: Vec<String> = Vec::new();
    if let Some(q) = query {
        let term = if q.is_ascii() {
            quote_search(q)?
        } else if literal_plus_ok {
            parts.push("CHARSET UTF-8".into());
            literal_plus(q)?
        } else {
            quote_search(q)?; // report control characters first
            return Err(MailError::InvalidArgument("query_charset"));
        };
        parts.push(format!("OR OR FROM {term} SUBJECT {term} TEXT {term}"));
    }
    if let Some(s) = since {
        parts.push(format!("SINCE {}", imap_date(s)?));
    }
    if let Some(b) = before {
        parts.push(format!("BEFORE {}", imap_date(b)?));
    }
    Ok(parts.join(" "))
}

/// A `UID FETCH` set (`3,1,2`).
pub fn fetch_set(uids: &[u32]) -> String {
    uids.iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn b64_value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b',' => Some(63),
        _ => None,
    }
}

fn decode_shift(seg: &str) -> Option<String> {
    let mut bits: u32 = 0;
    let mut nbits = 0;
    let mut bytes: Vec<u8> = Vec::new();
    for c in seg.bytes() {
        bits = (bits << 6) | b64_value(c)?;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            bytes.push(((bits >> nbits) & 0xff) as u8);
        }
    }
    if bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks(2)
        .map(|p| u16::from_be_bytes([p[0], p[1]]))
        .collect();
    char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .ok()
}

/// Decode a modified UTF-7 mailbox name for display. `&-` is `&`;
/// `&<base64>-` is UTF-16BE; anything malformed is left as written.
pub fn decode_utf7(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut rest = name;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        match after.find('-') {
            None => {
                out.push_str(&rest[i..]);
                return out;
            }
            Some(0) => {
                out.push('&');
                rest = &after[1..];
            }
            Some(j) => match decode_shift(&after[..j]) {
                Some(s) => {
                    out.push_str(&s);
                    rest = &after[j + 1..];
                }
                None => {
                    out.push_str(&rest[i..=i + j + 1]);
                    rest = &after[j + 1..];
                }
            },
        }
    }
    out.push_str(rest);
    out
}
