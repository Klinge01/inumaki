//! Email view (spec §6.4, §6.5): one card per mailbox dataset (`mail-1`, …).
//! The app password is sent once and never kept: it travels as a `Secret`
//! (zeroized on drop, `Debug` prints a length) from the form to the daemon.
//! Datasets are named `mail-N`, never after the mailbox: the slug appears
//! in gateway URLs, and the model-visible entry name is `inumaki-mail…`.

use std::collections::BTreeSet;

use inumaki_client::{
    CreateDataset, DatasetKind, MailboxBody, MailboxCheck, MailboxCreate, MailboxPreset, Secret,
};
use serde::{Deserialize, Serialize};

use crate::ctx::Ctx;
use crate::error::CmdError;
use crate::harness::connect::{DataChange, refresh_after_removing, refresh_connected};
use crate::harness::naming::mail_entry_name;

/// Serializes the choice of the next `mail-N`: two quick Adds must not pick
/// one id.
static NAMING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The Add form. `Debug` prints the preset only.
#[derive(Deserialize)]
pub struct MailboxForm {
    /// Preset.
    pub preset: MailboxPreset,
    /// Username.
    pub username: String,
    /// App password.
    pub password: Secret,
    /// Generic preset: host.
    #[serde(default)]
    pub imap_host: Option<String>,
    /// Generic preset: port.
    #[serde(default)]
    pub imap_port: Option<u16>,
    /// Local display name.
    pub display_name: String,
}

impl std::fmt::Debug for MailboxForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailboxForm")
            .field("preset", &self.preset)
            .finish_non_exhaustive()
    }
}

/// What the card shows of a configured mailbox. No password, and not the
/// vault secret's name. Shown to the local user only (no `Debug`).
#[derive(Serialize)]
pub struct MailboxView {
    /// Preset.
    pub preset: MailboxPreset,
    /// IMAP host.
    pub imap_host: String,
    /// IMAP port.
    pub imap_port: u16,
    /// TLS.
    pub imap_tls: bool,
    /// Username.
    pub username: String,
    /// Configured drafts folder.
    pub drafts_folder: Option<String>,
    /// `From` of drafts.
    pub from_address: Option<String>,
    /// Live handles.
    pub handles: u64,
}

impl From<MailboxBody> for MailboxView {
    fn from(m: MailboxBody) -> MailboxView {
        MailboxView {
            preset: m.preset,
            imap_host: m.imap_host.clone(),
            imap_port: m.imap_port,
            imap_tls: m.imap_tls,
            username: m.username.clone(),
            drafts_folder: m.drafts_folder.clone(),
            from_address: m.from_address.clone(),
            handles: m.handles,
        }
    }
}

/// One mailbox card. `Debug` prints whether the mailbox was read (the rest
/// is a username, a host, and a display name).
#[derive(Serialize)]
pub struct MailboxCard {
    /// Dataset id (`mail-N`).
    pub dataset: String,
    /// Local display name.
    pub display_name: String,
    /// Model-visible entry name (`inumaki-mail…`).
    pub entry_name: String,
    /// The mailbox, when it could be read.
    pub mailbox: Option<MailboxView>,
}

impl std::fmt::Debug for MailboxCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailboxCard")
            .field("read", &self.mailbox.is_some())
            .finish_non_exhaustive()
    }
}

fn mail_n(id: &str) -> Option<u64> {
    id.strip_prefix("mail-").and_then(|n| n.parse().ok())
}

/// Mailbox cards; `not_available` before plan 3 is on the daemon.
pub async fn mailboxes(ctx: &Ctx) -> Result<Vec<MailboxCard>, CmdError> {
    let st = ctx.client.status().await?;
    if st.mailboxes.is_none() {
        return Err(CmdError::not_available());
    }
    let mut ds: Vec<_> = st
        .datasets
        .into_iter()
        .filter(|d| d.kind == DatasetKind::Mailbox && !d.id.starts_with("check-"))
        .collect();
    ds.sort_by(|a, b| {
        (mail_n(&a.id).unwrap_or(u64::MAX), &a.id).cmp(&(mail_n(&b.id).unwrap_or(u64::MAX), &b.id))
    });
    let mut out = Vec::new();
    for (i, d) in ds.into_iter().enumerate() {
        let mailbox = ctx.client.mailbox(&d.id).await.ok().map(MailboxView::from);
        out.push(MailboxCard {
            entry_name: mail_entry_name(i, &BTreeSet::new()),
            display_name: d.name,
            dataset: d.id,
            mailbox,
        });
    }
    Ok(out)
}

/// Answer of Add: the card, and the connected harnesses that could not be
/// updated (review C2c: the UI says so).
#[derive(Debug, Serialize)]
pub struct MailboxAdded {
    /// The new card.
    pub card: MailboxCard,
    /// Connected harnesses whose Reconnect failed.
    pub reconnect_failures: usize,
    /// Which ones (fixed harness keys).
    pub failed_harnesses: Vec<&'static str>,
}

/// Create `mail-N` and its mailbox; connected harnesses get `inumaki-mail…` by Reconnect.
pub async fn add_mailbox(ctx: &Ctx, mut form: MailboxForm) -> Result<MailboxAdded, CmdError> {
    let (id, index, mailbox) = {
        let _naming = NAMING.lock().await;
        let taken = ctx.client.datasets().await?;
        let n = taken
            .iter()
            .filter_map(|d| mail_n(&d.id))
            .max()
            .unwrap_or(0)
            + 1;
        let index = taken
            .iter()
            .filter(|d| d.kind == DatasetKind::Mailbox)
            .filter_map(|d| mail_n(&d.id))
            .filter(|m| *m < n)
            .count();
        let id = format!("mail-{n}");
        let mut create = CreateDataset::new(id.clone(), form.display_name.clone());
        create.kind = Some(DatasetKind::Mailbox);
        ctx.client.create_dataset(&create).await?;
        let mut body = MailboxCreate::preset(
            form.preset,
            form.username.clone(),
            std::mem::take(&mut form.password),
        );
        body.imap_host = form.imap_host.clone();
        body.imap_port = form.imap_port;
        let sent = ctx.client.set_mailbox(&id, &body).await;
        // The password is zeroized with the body, whatever the answer.
        drop(body);
        match sent {
            Ok(m) => (id, index, m),
            Err(e) => {
                // No half-made mailbox: the dataset goes again.
                let _ = ctx.client.delete_dataset(&id).await;
                return Err(e.into());
            }
        }
    };
    let failed = refresh_connected(ctx).await;
    let card = MailboxCard {
        dataset: id,
        display_name: form.display_name.clone(),
        entry_name: mail_entry_name(index, &BTreeSet::new()),
        mailbox: Some(mailbox.into()),
    };
    Ok(MailboxAdded {
        card,
        reconnect_failures: failed.len(),
        failed_harnesses: failed,
    })
}

/// `POST …/mailbox/check`.
pub async fn check_mailbox(ctx: &Ctx, id: &str) -> Result<MailboxCheck, CmdError> {
    Ok(ctx.client.check_mailbox(id).await?)
}

/// Replace the app password, keeping every other setting.
pub async fn replace_password(ctx: &Ctx, id: &str, password: Secret) -> Result<(), CmdError> {
    let cur = ctx.client.mailbox(id).await?;
    let mut body = MailboxCreate::preset(cur.preset, cur.username.clone(), password);
    body.imap_host = Some(cur.imap_host.clone());
    body.imap_port = Some(cur.imap_port);
    body.imap_tls = Some(cur.imap_tls);
    body.drafts_folder = cur.drafts_folder.clone();
    body.from_address = cur.from_address.clone();
    ctx.client.set_mailbox(id, &body).await?;
    Ok(())
}

/// Remove the mailbox and its dataset, then update the connected harnesses.
pub async fn remove_mailbox(ctx: &Ctx, id: &str) -> Result<DataChange, CmdError> {
    // Only a mailbox dataset: never a wrapped server's or a folder's.
    if !is_mailbox(ctx, id).await? {
        return Err(CmdError::new("not_a_mailbox"));
    }
    let _ = ctx.client.delete_mailbox(id).await;
    ctx.client.delete_dataset(id).await?;
    Ok(DataChange::from_failed(
        refresh_after_removing(ctx, id).await,
    ))
}

async fn is_mailbox(ctx: &Ctx, id: &str) -> Result<bool, CmdError> {
    Ok(ctx
        .client
        .datasets()
        .await?
        .iter()
        .any(|d| d.id == id && d.kind == DatasetKind::Mailbox))
}

/// The provider's app-password page (spec §6.3 step 3); allowlisted.
pub fn help_url(p: MailboxPreset) -> Option<&'static str> {
    match p {
        MailboxPreset::Gmail => Some("https://support.google.com/accounts/answer/185833"),
        MailboxPreset::Outlook => Some(
            "https://support.microsoft.com/en-us/account-billing/how-to-get-and-use-app-passwords-5896ed9b-4263-e681-128a-a6f2979a7944",
        ),
        MailboxPreset::Generic => None,
    }
}
