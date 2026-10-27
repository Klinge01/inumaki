//! Presets (connection settings only, M4 spec §4.4) and the account a
//! mailbox dataset logs in with. The daemon implements [`MailCredentials`]
//! over the vault; the connector calls it at every (re)connect so a
//! replaced password is picked up without a restart.

use zeroize::Zeroizing;

use crate::error::MailError;

/// A provider preset: IMAP host and port, and a fixed authentication hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    /// `imap.gmail.com:993`.
    Gmail,
    /// `outlook.office365.com:993`.
    Outlook,
    /// Host and port supplied by the user.
    Generic,
}

impl Preset {
    /// Parse the stored or API string (exact, lower case).
    pub fn parse(s: &str) -> Option<Preset> {
        match s {
            "gmail" => Some(Preset::Gmail),
            "outlook" => Some(Preset::Outlook),
            "generic" => Some(Preset::Generic),
            _ => None,
        }
    }

    /// The stored string.
    pub fn as_str(self) -> &'static str {
        match self {
            Preset::Gmail => "gmail",
            Preset::Outlook => "outlook",
            Preset::Generic => "generic",
        }
    }

    /// Default IMAP host and port; `None` for `generic`.
    pub fn imap_defaults(self) -> Option<(&'static str, u16)> {
        match self {
            Preset::Gmail => Some(("imap.gmail.com", 993)),
            Preset::Outlook => Some(("outlook.office365.com", 993)),
            Preset::Generic => None,
        }
    }

    /// What to tell the user after `mail_auth_failed`. Verified support is
    /// documented in `docs/mail-providers.md`; the hint promises nothing.
    pub fn auth_hint(self) -> &'static str {
        match self {
            Preset::Gmail => {
                "Gmail IMAP accepts an app password only on an account with 2-step verification (Google account, Security, App passwords); the account password is refused. IMAP access must be enabled in Gmail settings. See docs/mail-providers.md for what was verified."
            }
            Preset::Outlook => {
                "Microsoft 365 and outlook.com require OAuth for IMAP; basic authentication with a password or app password was retired, so this preset is unsupported in milestone 4 (OAuth is deferred). See docs/mail-providers.md."
            }
            Preset::Generic => {
                "check the IMAP host, port, user name, and password; TLS is required unless the host is loopback. See docs/mail-providers.md."
            }
        }
    }
}

/// True for the loopback names a plaintext IMAP connection is allowed to.
pub fn is_loopback_host(host: &str) -> bool {
    host == "127.0.0.1" || host == "::1" || host.eq_ignore_ascii_case("localhost")
}

/// One mailbox login. `Debug` prints the host, port, TLS, and preset only.
#[derive(Clone)]
pub struct MailAccount {
    /// Preset (for hints).
    pub preset: Preset,
    /// IMAP host.
    pub host: String,
    /// IMAP port.
    pub port: u16,
    /// Implicit TLS; `false` only for loopback hosts.
    pub tls: bool,
    /// Login name.
    pub username: Zeroizing<String>,
    /// App password.
    pub password: Zeroizing<String>,
    /// Drafts folder; `None` = discover.
    pub drafts_folder: Option<String>,
    /// `From` of drafts when the login name is not an address.
    pub from_address: Option<String>,
}

impl std::fmt::Debug for MailAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailAccount")
            .field("preset", &self.preset)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("has_drafts_folder", &self.drafts_folder.is_some())
            .field("has_from_address", &self.from_address.is_some())
            .finish()
    }
}

impl MailAccount {
    /// The `From` address of a draft: the configured one, else the login
    /// name when it is an address.
    pub fn draft_from(&self) -> Result<String, MailError> {
        if let Some(a) = &self.from_address {
            return Ok(a.clone());
        }
        if self.username.contains('@') && !self.username.chars().any(char::is_control) {
            return Ok(self.username.to_string());
        }
        Err(MailError::DraftRejected("from_address"))
    }
}

/// Where the connector gets its login from (the daemon: the vault).
pub trait MailCredentials: Send + Sync + 'static {
    /// The account to log in with, read fresh.
    fn account(&self) -> Result<MailAccount, MailError>;
}

/// A fixed account (tests and the `mail-tasks` runner).
pub struct StaticCredentials(pub MailAccount);

impl MailCredentials for StaticCredentials {
    fn account(&self) -> Result<MailAccount, MailError> {
        Ok(self.0.clone())
    }
}
