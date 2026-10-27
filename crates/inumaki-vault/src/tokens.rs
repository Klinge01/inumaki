//! Gateway bearer tokens (M4 spec §4.3): `inumaki-gw-` plus 32 random bytes
//! in base64url, stored only as `HMAC-SHA256(index_key, "gw-token:" ||
//! token)`, compared in constant time over every row. The prefix keeps the
//! token MAC apart from the other uses of the index key (entry lookup over
//! normalized originals, log labels, released digests).

use base64::Engine;
use rusqlite::params;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::crypto::Indexer;
use crate::error::VaultError;
use crate::vault::Vault;

/// Prefix of every gateway token.
pub const TOKEN_PREFIX: &str = "inumaki-gw-";

/// A `gateway_tokens` row as read back for verification.
type TokenRow = (i64, String, Vec<u8>, i64, Option<i64>);

/// A token's metadata; the token itself is never stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayToken {
    /// Row id, used by `revoke`.
    pub id: i64,
    /// Human label given at creation.
    pub label: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds of the last successful verification.
    pub last_used: Option<i64>,
}

/// Domain-separation prefix of the token MAC input.
const MAC_DOMAIN: &str = "gw-token:";

/// The stored form of a token.
fn token_mac(indexer: &Indexer, token: &str) -> [u8; 32] {
    let input = Zeroizing::new(format!("{MAC_DOMAIN}{token}"));
    indexer.mac(input.as_bytes())
}

fn valid_label(label: &str) -> bool {
    !label.is_empty() && label.chars().count() <= 64 && !label.chars().any(char::is_control)
}

impl Vault {
    /// Mint a token: returns its metadata and the token text, which is
    /// shown once and then forgotten by everyone but the caller.
    pub fn create_gateway_token(
        &self,
        label: &str,
    ) -> Result<(GatewayToken, Zeroizing<String>), VaultError> {
        if !valid_label(label) {
            return Err(VaultError::InvalidLabel);
        }
        let mut raw = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *raw).map_err(|_| VaultError::Random)?;
        let token = Zeroizing::new(format!(
            "{TOKEN_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(*raw)
        ));
        let hash = token_mac(&self.inner.indexer, &token);
        let now = self.inner.now();
        let id = {
            let conn = self.inner.lock();
            conn.execute(
                "INSERT INTO gateway_tokens (label, token_hash, created_at) VALUES (?1, ?2, ?3)",
                params![label, hash.as_slice(), now],
            )?;
            conn.last_insert_rowid()
        };
        tracing::info!("gateway token created");
        Ok((
            GatewayToken {
                id,
                label: label.to_string(),
                created_at: now,
                last_used: None,
            },
            token,
        ))
    }

    /// Every token's metadata, oldest first.
    pub fn gateway_tokens(&self) -> Result<Vec<GatewayToken>, VaultError> {
        let conn = self.inner.lock();
        let mut stmt = conn
            .prepare("SELECT id, label, created_at, last_used FROM gateway_tokens ORDER BY id")?;
        let rows = stmt
            .query_map([], |r| {
                Ok(GatewayToken {
                    id: r.get(0)?,
                    label: r.get(1)?,
                    created_at: r.get(2)?,
                    last_used: r.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Delete a token by id.
    pub fn revoke_gateway_token(&self, id: i64) -> Result<(), VaultError> {
        let n = {
            let conn = self.inner.lock();
            conn.execute("DELETE FROM gateway_tokens WHERE id = ?1", params![id])?
        };
        if n == 0 {
            return Err(VaultError::GatewayTokenNotFound(id));
        }
        tracing::info!("gateway token revoked");
        Ok(())
    }

    /// The token's metadata when `token` matches a stored hash. Every row is
    /// compared in constant time; the prefix check only rejects strings
    /// that cannot be tokens. Records `last_used` on a hit.
    pub fn verify_gateway_token(&self, token: &str) -> Result<Option<GatewayToken>, VaultError> {
        if !token.starts_with(TOKEN_PREFIX) {
            return Ok(None);
        }
        let mac = token_mac(&self.inner.indexer, token);
        let rows: Vec<TokenRow> = {
            let conn = self.inner.lock();
            let mut stmt = conn.prepare(
                "SELECT id, label, token_hash, created_at, last_used FROM gateway_tokens",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?;
            rows.collect::<Result<_, _>>()?
        };
        let mut hit: Option<GatewayToken> = None;
        for (id, label, hash, created_at, last_used) in rows {
            let equal: bool = hash.as_slice().ct_eq(mac.as_slice()).into();
            if equal && hit.is_none() {
                hit = Some(GatewayToken {
                    id,
                    label,
                    created_at,
                    last_used,
                });
            }
        }
        if let Some(t) = &mut hit {
            let now = self.inner.now();
            let conn = self.inner.lock();
            conn.execute(
                "UPDATE gateway_tokens SET last_used = ?1 WHERE id = ?2",
                params![now, t.id],
            )?;
            t.last_used = Some(now);
        }
        Ok(hit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_mac_is_domain_separated_from_entry_lookup() {
        let indexer = Indexer::new(&[7u8; 32]);
        let token = "inumaki-gw-abc";
        let stored = token_mac(&indexer, token);
        // Entry lookup MACs the normalized original with no prefix: a token
        // stored as an entry key must not produce the same MAC.
        assert_ne!(stored, indexer.mac(token.as_bytes()));
        assert_eq!(stored, indexer.mac(b"gw-token:inumaki-gw-abc"));
    }
}
