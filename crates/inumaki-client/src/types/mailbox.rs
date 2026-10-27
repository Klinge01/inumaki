//! Mailboxes (M6 spec §9.4, plan 3).

use serde::{Deserialize, Serialize};

/// Mailbox preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MailboxPreset {
    /// Gmail.
    Gmail,
    /// Outlook.
    Outlook,
    /// Any IMAP server.
    Generic,
}

/// One mailbox in `GET /v1/status` `mailboxes` (plan 3).
#[derive(Clone, Serialize, Deserialize)]
pub struct MailboxStatus {
    /// Dataset slug.
    pub dataset: String,
    /// Preset.
    pub preset: MailboxPreset,
    /// IMAP host.
    pub imap_host: String,
    /// IMAP port.
    pub imap_port: u16,
    /// TLS.
    pub imap_tls: bool,
    /// Live handles.
    pub handles: u64,
}

debug_fields!(MailboxStatus {
    preset,
    imap_port,
    imap_tls,
    handles
});

use crate::secret::Secret;

/// `POST /v1/datasets/{id}/mailbox` body (also replaces). No `smtp*`,
/// `send_mode`, `send`, or `mail_send` field exists: mailboxes are draft-only.
#[derive(Clone, Serialize, Deserialize)]
pub struct MailboxCreate {
    /// Preset.
    pub preset: MailboxPreset,
    /// Host (required for `generic`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imap_host: Option<String>,
    /// Port (required for `generic`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imap_port: Option<u16>,
    /// TLS (must be true for a non-loopback host).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imap_tls: Option<bool>,
    /// Username.
    pub username: String,
    /// App password, 1 to 512 printable characters.
    pub password: Secret,
    /// Drafts folder; auto-discovered when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drafts_folder: Option<String>,
    /// `From` of drafts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_address: Option<String>,
}

impl MailboxCreate {
    /// A preset mailbox with the preset's host, port, and TLS.
    pub fn preset(preset: MailboxPreset, username: impl Into<String>, password: Secret) -> Self {
        MailboxCreate {
            preset,
            imap_host: None,
            imap_port: None,
            imap_tls: None,
            username: username.into(),
            password,
            drafts_folder: None,
            from_address: None,
        }
    }
}

debug_fields!(MailboxCreate {
    preset,
    imap_port,
    imap_tls
});

/// `MailboxBody`.
#[derive(Clone, Serialize, Deserialize)]
pub struct MailboxBody {
    /// Preset.
    pub preset: MailboxPreset,
    /// Host.
    pub imap_host: String,
    /// Port.
    pub imap_port: u16,
    /// TLS.
    pub imap_tls: bool,
    /// Username.
    pub username: String,
    /// Configured drafts folder.
    pub drafts_folder: Option<String>,
    /// `From` of drafts.
    pub from_address: Option<String>,
    /// Secret name of the password.
    pub password_secret: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Live handles.
    pub handles: u64,
}

debug_fields!(MailboxBody {
    preset,
    imap_port,
    imap_tls,
    created_at,
    handles
});

/// `POST /v1/datasets/{id}/mailbox/check` answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxCheck {
    /// Folders listed.
    pub folders: u64,
    /// A drafts folder was found.
    pub drafts_folder_resolved: bool,
    /// It will be created on the first draft.
    pub drafts_folder_will_be_created: bool,
    /// It was configured by name.
    pub drafts_folder_configured: bool,
}
