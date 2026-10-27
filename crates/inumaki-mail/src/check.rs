//! `POST /v1/datasets/{id}/mailbox/check` (M4 spec §8): connect, count the
//! folders, see whether drafts have a home, log out. Counts and booleans
//! only; a failure is a class.

use std::time::Duration;

use crate::account::MailAccount;
use crate::error::MailError;
use crate::imap::{DraftsFolder, Imap};

/// What a check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct CheckReport {
    /// Folders the account can list.
    pub folders: usize,
    /// A drafts folder exists or can be created.
    pub drafts_folder_resolved: bool,
    /// No drafts folder exists yet; `Drafts` will be created on the first draft.
    pub drafts_folder_will_be_created: bool,
}

/// Connect, list, resolve the drafts folder, log out.
pub async fn check_mailbox(
    account: &MailAccount,
    timeout: Duration,
) -> Result<CheckReport, MailError> {
    let mut imap = Imap::connect(account, timeout).await?;
    let folders = imap.folders().await?;
    let (resolved, create) = match imap
        .resolve_drafts_folder(account.drafts_folder.as_deref())
        .await
    {
        Ok(DraftsFolder::Existing(_)) => (true, false),
        Ok(DraftsFolder::Create(_)) => (true, true),
        Err(MailError::DraftsFolderMissing) => (false, false),
        Err(e) => return Err(e),
    };
    imap.logout().await;
    Ok(CheckReport {
        folders: folders.len(),
        drafts_folder_resolved: resolved,
        drafts_folder_will_be_created: create,
    })
}
