//! Failure classes (M4 spec §6.2, §11). Every variant carries a class or an
//! `io::ErrorKind`, never a server message, an address, or a folder name.
//! [`MailError::hint`] is the fixed sentence the agent sees in a tool error.

use std::io;

/// Why a mail operation failed. Classes only.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MailError {
    /// TCP connect or IO failed.
    #[error("mail_unreachable: {0:?}")]
    Unreachable(io::ErrorKind),
    /// A command did not complete in time.
    #[error("mail_timeout")]
    Timeout,
    /// TLS setup or handshake failed; carries a class.
    #[error("mail_tls_failed: {0}")]
    Tls(&'static str),
    /// The server refused the login.
    #[error("mail_auth_failed")]
    AuthFailed,
    /// The server answered something unexpected; carries a class.
    #[error("mail_protocol: {0}")]
    Protocol(&'static str),
    /// A folder or message handle is unknown, stale, or mismatched.
    #[error("context_unavailable")]
    ContextUnavailable,
    /// A tool argument is missing or malformed; carries the argument name.
    #[error("invalid_argument: {0}")]
    InvalidArgument(&'static str),
    /// The draft could not be built or the server refused to store it; carries a class.
    #[error("draft_rejected: {0}")]
    DraftRejected(&'static str),
    /// The connection dropped after the draft literal was sent.
    #[error("draft_status_unknown")]
    DraftStatusUnknown,
    /// The configured drafts folder does not exist.
    #[error("drafts_folder_missing")]
    DraftsFolderMissing,
    /// A message is larger than the configured limit.
    #[error("resource_limit")]
    TooLarge,
    /// The handle store failed; carries a class.
    #[error("mail_handles: {0}")]
    Handles(&'static str),
    /// Credentials could not be read; carries a class.
    #[error("mail_credentials: {0}")]
    Credentials(&'static str),
}

impl MailError {
    /// The fixed class name (the first word of the tool-error text).
    pub fn class(&self) -> &'static str {
        match self {
            MailError::Unreachable(_) => "mail_unreachable",
            MailError::Timeout => "mail_timeout",
            MailError::Tls(_) => "mail_tls_failed",
            MailError::AuthFailed => "mail_auth_failed",
            MailError::Protocol(_) => "mail_protocol",
            MailError::ContextUnavailable => "context_unavailable",
            MailError::InvalidArgument(_) => "invalid_argument",
            MailError::DraftRejected(_) => "draft_rejected",
            MailError::DraftStatusUnknown => "draft_status_unknown",
            MailError::DraftsFolderMissing => "drafts_folder_missing",
            MailError::TooLarge => "resource_limit",
            MailError::Handles(_) => "mail_handles",
            MailError::Credentials(_) => "mail_credentials",
        }
    }

    /// The fixed sentence shown to the agent. No data, ever.
    pub fn hint(&self) -> &'static str {
        match self {
            MailError::Unreachable(_) => "the mail server could not be reached",
            MailError::Timeout => "the mail server did not answer in time",
            MailError::Tls(_) => "the TLS connection to the mail server failed",
            MailError::AuthFailed => {
                "the mailbox refused the login; check the app password with `inumaki dataset check-mailbox`"
            }
            MailError::Protocol(_) => "the mail server answered unexpectedly",
            MailError::ContextUnavailable => {
                "the folder or message handle is unknown or stale; run mail_search again"
            }
            MailError::InvalidArgument(_) => "an argument is missing or malformed",
            MailError::DraftRejected(_) => {
                "the draft could not be built or the mail server refused to store it"
            }
            MailError::DraftStatusUnknown => {
                "the connection dropped while saving the draft; check the Drafts folder in your mail client before trying again"
            }
            MailError::DraftsFolderMissing => "the configured Drafts folder does not exist",
            MailError::TooLarge => "the message is larger than the configured limit",
            MailError::Handles(_) => "the local handle store failed",
            MailError::Credentials(_) => "the mailbox credentials could not be read",
        }
    }

    /// True when the IMAP session must be dropped and reconnected.
    pub fn is_connection(&self) -> bool {
        matches!(
            self,
            MailError::Unreachable(_)
                | MailError::Timeout
                | MailError::Tls(_)
                | MailError::Protocol(_)
                | MailError::DraftStatusUnknown
        )
    }

    /// Map an `async-imap` error after `during_append` (the literal may have
    /// been sent) or any other command. Server strings are dropped.
    pub(crate) fn from_imap(e: &async_imap::error::Error, during_append: bool) -> MailError {
        use async_imap::error::Error as E;
        match e {
            E::Io(_) | E::ConnectionLost if during_append => MailError::DraftStatusUnknown,
            E::Io(io) => MailError::Unreachable(io.kind()),
            E::ConnectionLost => MailError::Unreachable(io::ErrorKind::ConnectionReset),
            // BAD = the server could not parse our command (malformed criteria);
            // the session is still in sync, so this is not a connection class.
            E::Bad(_) => MailError::InvalidArgument("imap_command"),
            E::No(_) if during_append => MailError::DraftRejected("refused"),
            E::No(_) => MailError::Protocol("no"),
            // after an APPEND the literal may already be stored: a reply we
            // cannot read is as ambiguous as a dropped connection
            E::Parse(_) if during_append => MailError::DraftStatusUnknown,
            E::Parse(_) => MailError::Protocol("parse"),
            E::Validate(_) => MailError::InvalidArgument("imap_string"),
            // async-imap read one line that was not the `+` continuation (an
            // unsolicited `* n EXISTS`, or a refusal) and did not send the
            // literal; the server may still be waiting for it, so the session
            // is desynchronised and must be dropped before anything else is sent.
            E::Append => MailError::Protocol("append_desync"),
            // `Error` is #[non_exhaustive]: any future variant is a protocol
            // class, or ambiguous during an APPEND (never retried)
            _ if during_append => MailError::DraftStatusUnknown,
            _ => MailError::Protocol("imap_other"),
        }
    }

    /// Map a login failure: `NO` is a wrong password (or an unsupported
    /// authentication method); `BAD` is a protocol problem, not a wrong
    /// password (it must not be memoized as one); the rest are connection classes.
    pub(crate) fn from_login(e: &async_imap::error::Error) -> MailError {
        use async_imap::error::Error as E;
        match e {
            E::No(_) => MailError::AuthFailed,
            E::Bad(_) => MailError::Protocol("login"),
            other => MailError::from_imap(other, false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MailError;
    use async_imap::error::{Error as E, ParseError};

    #[test]
    fn an_unreadable_append_reply_is_ambiguous_but_a_pre_literal_refusal_is_not() {
        let parse = E::Parse(ParseError::Invalid(b"%%%".to_vec()));
        assert_eq!(
            MailError::from_imap(&parse, true),
            MailError::DraftStatusUnknown
        );
        assert_eq!(
            MailError::from_imap(&parse, false),
            MailError::Protocol("parse")
        );
        assert_eq!(
            MailError::from_imap(&E::Append, true),
            MailError::Protocol("append_desync")
        );
    }
}
