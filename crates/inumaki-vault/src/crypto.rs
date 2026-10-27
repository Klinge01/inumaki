//! XChaCha20-Poly1305 for stored values (token as associated data) and
//! HMAC-SHA256 for the lookup index.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::VaultError;

/// Nonce length of XChaCha20-Poly1305 in bytes.
pub const NONCE_LEN: usize = 24;

/// An encrypted value with its nonce.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed {
    /// 24 random bytes.
    pub nonce: Vec<u8>,
    /// Ciphertext plus tag.
    pub value: Vec<u8>,
}

impl std::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealed")
            .field("value_len", &self.value.len())
            .finish()
    }
}

/// Value encryption. The associated data binds a ciphertext to its token
/// (or another identifier), so a row cannot be re-pointed to another token.
pub struct Cipher {
    aead: XChaCha20Poly1305,
}

impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cipher")
    }
}

impl Cipher {
    /// Cipher over a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        Cipher {
            aead: XChaCha20Poly1305::new(Key::from_slice(key)),
        }
    }

    /// Encrypt `plain` under a fresh random nonce with `aad` authenticated.
    pub fn seal(&self, aad: &[u8], plain: &[u8]) -> Result<Sealed, VaultError> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| VaultError::Random)?;
        let value = self
            .aead
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plain, aad })
            .map_err(|_| VaultError::Encrypt)?;
        Ok(Sealed {
            nonce: nonce.to_vec(),
            value,
        })
    }

    /// Decrypt into a zeroized buffer. Any mismatch (key, nonce, aad, tag) is
    /// [`VaultError::Decrypt`].
    pub fn open(
        &self,
        aad: &[u8],
        nonce: &[u8],
        value: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if nonce.len() != NONCE_LEN {
            return Err(VaultError::Decrypt);
        }
        self.aead
            .decrypt(XNonce::from_slice(nonce), Payload { msg: value, aad })
            .map(Zeroizing::new)
            .map_err(|_| VaultError::Decrypt)
    }

    /// [`Cipher::open`] for UTF-8 text.
    pub fn open_str(
        &self,
        aad: &[u8],
        nonce: &[u8],
        value: &[u8],
    ) -> Result<Zeroizing<String>, VaultError> {
        let bytes = self.open(aad, nonce, value)?;
        let s = std::str::from_utf8(&bytes).map_err(|_| VaultError::Decrypt)?;
        Ok(Zeroizing::new(s.to_owned()))
    }
}

/// HMAC-SHA256 over normalized keys for the lookup index.
pub struct Indexer {
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Indexer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Indexer")
    }
}

impl Indexer {
    /// Indexer over a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        Indexer {
            key: Zeroizing::new(*key),
        }
    }

    /// `HMAC-SHA256(index_key, data)`.
    pub fn mac(&self, data: &[u8]) -> [u8; 32] {
        let mut m: Hmac<Sha256> =
            Mac::new_from_slice(&*self.key).expect("HMAC accepts any key length");
        m.update(data);
        m.finalize().into_bytes().into()
    }
}

/// Lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Inverse of [`hex`]; `None` on odd length or non-hex input.
pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn seal_open_round_trip_with_fresh_nonces() {
        let c = Cipher::new(&key(1));
        let a = c
            .seal(b"<PERSON_a1b2c3>", "Sarah Leitner".as_bytes())
            .unwrap();
        let b = c
            .seal(b"<PERSON_a1b2c3>", "Sarah Leitner".as_bytes())
            .unwrap();
        assert_eq!(a.nonce.len(), 24);
        assert_ne!(a.nonce, b.nonce, "every value gets a fresh nonce");
        assert_ne!(a.value, b.value);
        let back = c.open_str(b"<PERSON_a1b2c3>", &a.nonce, &a.value).unwrap();
        assert_eq!(back.as_str(), "Sarah Leitner");
    }

    #[test]
    fn value_cannot_be_repointed_to_another_token() {
        let c = Cipher::new(&key(1));
        let s = c.seal(b"<PERSON_a1b2c3>", b"Sarah Leitner").unwrap();
        assert!(matches!(
            c.open_str(b"<PERSON_ffffff>", &s.nonce, &s.value),
            Err(VaultError::Decrypt)
        ));
        assert!(matches!(
            Cipher::new(&key(2)).open_str(b"<PERSON_a1b2c3>", &s.nonce, &s.value),
            Err(VaultError::Decrypt)
        ));
        assert!(matches!(
            c.open_str(b"<PERSON_a1b2c3>", &s.nonce[..23], &s.value),
            Err(VaultError::Decrypt)
        ));
    }

    #[test]
    fn hmac_is_deterministic_and_key_dependent() {
        let a = Indexer::new(&key(1));
        let b = Indexer::new(&key(2));
        assert_eq!(a.mac(b"sarah leitner"), a.mac(b"sarah leitner"));
        assert_ne!(a.mac(b"sarah leitner"), b.mac(b"sarah leitner"));
        assert_ne!(a.mac(b"sarah leitner"), a.mac(b"sarah leitne"));
    }

    #[test]
    fn debug_impls_print_nothing_secret() {
        let c = Cipher::new(&key(1));
        let s = c.seal(b"aad", b"Sarah Leitner").unwrap();
        let d = format!("{c:?} {s:?} {:?}", Indexer::new(&key(1)));
        assert!(!d.contains("Sarah"));
        assert!(!d.contains("1, 1, 1"));
    }
}
