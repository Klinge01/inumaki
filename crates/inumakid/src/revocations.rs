//! Apply pending gateway token revocations (offline Revert spec D6, D7).
//!
//! The app's offline Revert leaves a label-only record in
//! `<data dir>/revocations/` (format owned by
//! [`inumaki_client::revocations`]). The server applies every record after
//! binding its control socket and before binding the gateway's TCP
//! listener, and again on every sweep. It fails closed: a record that
//! cannot be trusted revokes every `app:` token, and a directory that
//! cannot be listed, a vault call that fails, or an entry that cannot be
//! removed is an error the caller turns into a refused start or a shutdown.
//! No log line here names a label, a path, or a token id.

use std::path::Path;

pub use inumaki_client::revocations::RevocationError;
use inumaki_client::revocations::{self, Pending};
use inumaki_vault::{Vault, VaultError};

/// Apply and remove every pending record under `data_dir`: a
/// [`Pending::Label`] revokes every gateway token with that label, a
/// [`Pending::Unreadable`] revokes every token whose label starts with
/// `app:` (check tokens are kept). A token already gone counts as done.
/// Returns how many tokens this call revoked.
pub fn apply_pending(vault: &Vault, data_dir: &Path) -> Result<usize, RevocationError> {
    let entries = revocations::scan(data_dir)?;
    let mut revoked = 0usize;
    for (path, pending) in &entries {
        let tokens = vault
            .gateway_tokens()
            .map_err(|_| RevocationError::Io("vault"))?;
        let targets = tokens.iter().filter(|t| match pending {
            Pending::Label(l) => t.label == *l,
            Pending::Unreadable => t.label.starts_with("app:"),
        });
        for t in targets {
            match vault.revoke_gateway_token(t.id) {
                Ok(()) => revoked += 1,
                Err(VaultError::GatewayTokenNotFound(_)) => {}
                Err(_) => return Err(RevocationError::Io("vault")),
            }
        }
        if *pending == Pending::Unreadable {
            tracing::warn!("a pending revocation could not be read; every app token was revoked");
        }
        revocations::remove(path)?;
    }
    if !entries.is_empty() {
        tracing::info!(
            revoked,
            records = entries.len(),
            "pending revocations applied"
        );
    }
    Ok(revoked)
}
