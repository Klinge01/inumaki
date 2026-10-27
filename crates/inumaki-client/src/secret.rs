//! Secret values in bodies: zeroized on drop, never printed.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A secret string: an app password, a bearer token, a value to forget.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    /// Wrap `s`.
    pub fn new(s: impl Into<String>) -> Self {
        Secret(s.into())
    }

    /// The value, for the one place that must send or write it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret({} bytes)", self.0.len())
    }
}

/// Secret environment variables or headers, by name.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretMap(BTreeMap<String, String>);

impl SecretMap {
    /// Empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace `name`.
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        if let Some(mut old) = self.0.insert(name.into(), value.into()) {
            old.zeroize();
        }
    }

    /// The names, sorted.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }

    /// Entries.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// No entries.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretMap {
    fn drop(&mut self) {
        for v in self.0.values_mut() {
            v.zeroize();
        }
    }
}

impl std::fmt::Debug for SecretMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretMap({} entries)", self.0.len())
    }
}
