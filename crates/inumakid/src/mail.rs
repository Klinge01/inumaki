//! `[mail]` (M4 spec §6.1, §10): the mail connector's settings, validated
//! once at load. Errors name the key, never the value.

use std::time::Duration;

use inumaki_core::Error;
use inumaki_mail::MailConfig;
use serde::Deserialize;

use crate::config::{DaemonConfig, parse_bytes, parse_duration};

/// `[mail]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MailSection {
    /// IMAP NOOP interval while idle, e.g. `5m` (at least 30 s).
    pub keepalive: String,
    /// Timeout per IMAP command, e.g. `30s`.
    pub command_timeout: String,
    /// Largest message `mail_read` fetches, e.g. `4MiB` (at least 64 KiB).
    pub max_message_bytes: String,
    /// Search snippet length in characters (40 to 2000).
    pub snippet_chars: usize,
    /// Days an unused mail handle is kept (1 to 365).
    pub handle_retention_days: u32,
    /// How long a refused login is remembered before the server is asked
    /// again, e.g. `60s`.
    pub auth_retry_after: String,
}

impl Default for MailSection {
    fn default() -> Self {
        MailSection {
            keepalive: "5m".into(),
            command_timeout: "30s".into(),
            max_message_bytes: "4MiB".into(),
            snippet_chars: 200,
            handle_retention_days: 30,
            auth_retry_after: "60s".into(),
        }
    }
}

/// Validate `[mail]` into the connector's settings (the fields `[mail]`
/// does not cover keep their defaults).
pub fn parse(m: &MailSection) -> Result<MailConfig, Error> {
    let invalid = |key: &str| Error::ConfigInvalid(format!("mail.{key}"));
    let keepalive = parse_duration(&m.keepalive)
        .filter(|d| *d >= Duration::from_secs(30))
        .ok_or_else(|| invalid("keepalive"))?;
    let command_timeout = parse_duration(&m.command_timeout)
        .filter(|d| !d.is_zero())
        .ok_or_else(|| invalid("command_timeout"))?;
    let max_message_bytes = parse_bytes(&m.max_message_bytes)
        .filter(|b| *b >= 64 * 1024)
        .ok_or_else(|| invalid("max_message_bytes"))?;
    if !(40..=2000).contains(&m.snippet_chars) {
        return Err(invalid("snippet_chars"));
    }
    if !(1..=365).contains(&m.handle_retention_days) {
        return Err(invalid("handle_retention_days"));
    }
    let auth_retry_after = parse_duration(&m.auth_retry_after)
        .filter(|d| !d.is_zero())
        .ok_or_else(|| invalid("auth_retry_after"))?;
    Ok(MailConfig {
        keepalive,
        command_timeout,
        max_message_bytes,
        snippet_chars: m.snippet_chars,
        auth_retry_after,
        ..MailConfig::default()
    })
}

impl DaemonConfig {
    /// The mail connector's settings (validated `[mail]`).
    pub fn mail_config(&self) -> MailConfig {
        self.mail_parsed.clone()
    }
}
