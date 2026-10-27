//! Per-context opaque tokens and the in-memory context store.
//! Originals and their normalized keys are held in `Zeroizing<String>` and
//! wiped on drop.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry as MapEntry;
use dashmap::mapref::one::RefMut;
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;
use zeroize::Zeroizing;

use crate::alias::AliasTable;
use crate::config::TokenSettings;
use crate::consistency::{StoreDict, StoreDictCache};
use crate::span::EntityKind;
use crate::verify::LeakIndex;
use crate::{Error, Result};

/// An opaque token such as `<PERSON_a7f2>`.
///
/// `Debug` prints only the length (`Token(13)`): token values never reach
/// logs (spec §10), and anything deriving `Debug` over a `Token` (such as
/// [`crate::Replacement`]) inherits that.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Token(String);

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Token({})", self.0.len())
    }
}

impl Token {
    /// The token text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for Token {
    /// Wrap an already formatted token string. Stores outside this crate
    /// (the vault's namespace) build tokens with [`format_token`].
    fn from(s: String) -> Self {
        Token(s)
    }
}

/// Why a token store could not complete an operation. Carries a kind label
/// at most, never a value (spec §5.3: a value-free storage error the core
/// defines without depending on the vault).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The store is not reachable or its data could not be read or written
    /// (a database, decryption, or automaton failure). Retry later.
    #[error("token store unavailable")]
    Unavailable,
    /// The store's dataset or epoch is gone; nothing more can be minted or resolved.
    #[error("token store closed: its dataset or epoch is gone")]
    Closed,
    /// Every suffix for this kind label is taken.
    #[error("token space exhausted for kind {0}")]
    Exhausted(String),
    /// `surface_token` was given a parent token this store does not hold as
    /// a current entity (a linker bug or a token from another epoch). The
    /// batch is discarded.
    #[error("surface token parent unknown")]
    UnknownParent,
}

/// How surface forms of an entity are tokenized (`[tokens] surface_form`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SurfaceForm {
    /// `<PERSON_a7f2c9_3e>`: the entity's suffix plus a random two-character
    /// component, so the model sees that the mentions are one entity.
    #[default]
    Derived,
    /// A fresh random suffix per surface form; no visible link.
    Independent,
}

/// Surface forms one entity can have in `Derived` mode: 16² two-character components.
pub const MAX_SURFACE_FORMS: usize = 256;

/// A token taken apart: `<LABEL_suffix>`, `<LABEL_suffix_xx>`, or `<LABEL_REMOVED>`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ParsedToken<'a> {
    /// Kind label as written in the token (`PERSON`, `K2FA_CODE`).
    pub label: &'a str,
    /// The random hex suffix (empty for a removed marker).
    pub suffix: &'a str,
    /// The two-character surface component of a surface-form token; `None`
    /// for the entity itself.
    pub variant: Option<&'a str>,
    /// True for `<LABEL_REMOVED>`.
    pub removed: bool,
}

impl fmt::Debug for ParsedToken<'_> {
    /// Prints the label (a kind name, not identifying), the suffix's
    /// length, whether a surface component is present, and `removed` —
    /// never the suffix or component characters themselves.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedToken")
            .field("label", &self.label)
            .field("suffix_len", &self.suffix.len())
            .field("has_variant", &self.variant.is_some())
            .field("removed", &self.removed)
            .finish()
    }
}

fn is_hex_suffix(s: &str) -> bool {
    (4..=12).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_label(s: &str) -> bool {
    let mut b = s.bytes();
    matches!(b.next(), Some(c) if c.is_ascii_uppercase())
        && b.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
}

/// Parse `token` against `settings`' delimiters. `None` when it is not a
/// well-formed token: wrong delimiters, a label not matching
/// `[A-Z][A-Z0-9_]*`, a suffix outside 4–12 lowercase hex characters, or a
/// surface component that is not exactly two lowercase hex characters.
pub fn parse_token<'a>(settings: &TokenSettings, token: &'a str) -> Option<ParsedToken<'a>> {
    let body = token
        .strip_prefix(settings.open.as_str())?
        .strip_suffix(settings.close.as_str())?;
    let (head, tail) = body.rsplit_once('_')?;
    if tail == "REMOVED" {
        return is_label(head).then_some(ParsedToken {
            label: head,
            suffix: "",
            variant: None,
            removed: true,
        });
    }
    // A two-character hex tail is a surface component when what precedes it
    // is itself `LABEL_hex`; a suffix is at least 4 characters, so the two
    // shapes cannot be confused.
    let component_tail = tail.len() == 2
        && tail
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if component_tail {
        let (label, suffix) = head.rsplit_once('_')?;
        if !is_label(label) || !is_hex_suffix(suffix) {
            return None;
        }
        return Some(ParsedToken {
            label,
            suffix,
            variant: Some(tail),
            removed: false,
        });
    }
    (is_label(head) && is_hex_suffix(tail)).then_some(ParsedToken {
        label: head,
        suffix: tail,
        variant: None,
        removed: false,
    })
}

/// `parent` (`<PERSON_a7f2c9>`) with `_component` inserted before the
/// closing delimiter: `<PERSON_a7f2c9_3e>`. The caller passes a well-formed
/// entity token and a two-character component.
pub fn derive_surface_token(settings: &TokenSettings, parent: &str, component: &str) -> String {
    let body = parent
        .strip_suffix(settings.close.as_str())
        .unwrap_or(parent);
    format!("{body}_{component}{}", settings.close)
}

/// Two lowercase hex characters from the OS CSPRNG (a surface component).
pub fn random_surface_component() -> String {
    let mut b = [0u8; 1];
    getrandom::fill(&mut b).expect("OS randomness available");
    format!("{:02x}", b[0])
}

/// Normalized form of an original value used for referential consistency.
/// Holds near-plaintext (folded, lower-cased) data, so the inner buffer is
/// zeroized on drop and `Debug` never prints it.
#[derive(Clone)]
pub struct NormKey(Zeroizing<String>);

impl PartialEq for NormKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_str() == other.0.as_str()
    }
}

impl Eq for NormKey {}

impl std::hash::Hash for NormKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_str().hash(state);
    }
}

impl fmt::Debug for NormKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NormKey(<redacted>)")
    }
}

impl NormKey {
    /// The normalized key text. Near-plaintext: callers hash or compare it
    /// and never store or log it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// NFKC, diacritics folded, lower-cased, whitespace collapsed, `ß` → `ss`.
/// Every intermediate buffer (and the final key) is held in `Zeroizing` and
/// wiped on drop.
pub fn normalize(s: &str) -> NormKey {
    let nfkc: Zeroizing<String> = Zeroizing::new(s.nfkc().collect::<String>());
    let stripped: Zeroizing<String> = Zeroizing::new(
        nfkc.nfd()
            .filter(|c| !is_combining_mark(*c))
            .collect::<String>(),
    );
    let lowered: Zeroizing<String> = Zeroizing::new(stripped.to_lowercase());
    let replaced: Zeroizing<String> = Zeroizing::new(lowered.replace('ß', "ss"));
    let collapsed: Zeroizing<String> =
        Zeroizing::new(replaced.split_whitespace().collect::<Vec<_>>().join(" "));
    NormKey(collapsed)
}

/// Identifier of a context (a request or a session).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContextId(pub String);

struct Entry {
    token: String,
    kind: EntityKind,
    original: Zeroizing<String>,
    /// Parent entity token when this is a surface form.
    surface_of: Option<String>,
    used: Instant,
}

/// Token mapping for one processing context.
pub struct Context {
    id: ContextId,
    entries: Vec<Entry>,
    /// Values replaced by a `Remove` action. Leak-check only: never mapped
    /// to a token, never returned by [`Context::original`], never rehydrated.
    removed: Vec<(EntityKind, Zeroizing<String>)>,
    by_token: HashMap<String, usize>,
    by_key: HashMap<String, HashMap<NormKey, usize>>,
    /// `(parent token, exact surface text)` → entry (R9: keyed on the
    /// surface exactly as given, not its normalized form, so restoration
    /// always returns the exact text replaced).
    by_surface: HashMap<(String, String), usize>,
    /// Number of surface-form children per parent token (R9/minor-6: O(1)
    /// `MAX_SURFACE_FORMS` check instead of scanning every entry).
    surface_children: HashMap<String, usize>,
    created: Instant,
    last_used: Instant,
    ttl: Duration,
    settings: TokenSettings,
    /// The consistency dictionary over this context's values (Task 7e):
    /// dropped with the context.
    dict: StoreDictCache,
}

fn kind_class(kind: &EntityKind) -> String {
    kind.label().to_string()
}

/// Map a kind's label to the `[A-Z0-9_]` alphabet used inside a token.
/// German umlauts and eszett get spelled out (`Ä`→`AE`, `Ö`→`OE`, `Ü`→`UE`,
/// `ß`→`SS`, lowercase equivalents too); any other character outside
/// `A-Z0-9_` becomes `_`. If the result would not start with a letter, it is
/// prefixed with `K`. Built-in labels (already `[A-Z_]+`) pass through
/// unchanged.
pub fn token_label(kind: &EntityKind) -> String {
    let raw = kind.label();
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            'Ä' | 'ä' => out.push_str("AE"),
            'Ö' | 'ö' => out.push_str("OE"),
            'Ü' | 'ü' => out.push_str("UE"),
            'ß' => out.push_str("SS"),
            'A'..='Z' | '0'..='9' | '_' => out.push(ch),
            'a'..='z' => out.push(ch.to_ascii_uppercase()),
            _ => out.push('_'),
        }
    }
    if !matches!(out.chars().next(), Some('A'..='Z')) {
        out.insert(0, 'K');
    }
    out
}

/// `{open}{LABEL}_{suffix}{close}`, the one token format every store uses.
pub fn format_token(settings: &TokenSettings, kind: &EntityKind, suffix: &str) -> String {
    format!(
        "{}{}_{}{}",
        settings.open,
        token_label(kind),
        suffix,
        settings.close
    )
}

/// `settings.suffix_len` (clamped to `1..=12`) lowercase hex characters from
/// the OS CSPRNG.
pub fn random_suffix(settings: &TokenSettings) -> String {
    let n = settings.suffix_len.clamp(1, 12);
    let mut bytes = vec![0u8; n.div_ceil(2)];
    getrandom::fill(&mut bytes).expect("OS randomness available");
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    hex[..n].to_string()
}

impl Context {
    /// Create an empty context.
    pub fn new(id: ContextId, ttl: Duration, settings: TokenSettings) -> Self {
        let now = Instant::now();
        Context {
            id,
            entries: Vec::new(),
            removed: Vec::new(),
            by_token: HashMap::new(),
            by_key: HashMap::new(),
            by_surface: HashMap::new(),
            surface_children: HashMap::new(),
            created: now,
            last_used: now,
            ttl,
            settings,
            dict: StoreDictCache::default(),
        }
    }

    /// Context identifier.
    pub fn id(&self) -> &ContextId {
        &self.id
    }

    /// Token format settings.
    pub fn settings(&self) -> &TokenSettings {
        &self.settings
    }

    /// Number of distinct mapped values.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when nothing is mapped.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// True once `ttl` has elapsed since last use.
    pub fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.last_used) >= self.ttl
    }

    /// Mark as used now.
    pub fn touch(&mut self) {
        self.last_used = Instant::now();
    }

    /// Mint a token for `kind` that isn't already used in this context.
    ///
    /// Tries up to 64 random suffixes first; if the configured suffix space
    /// is nearly full, falls back to an exhaustive scan of that space (all
    /// `16^n` values, `n` hex digits, starting from a random offset and
    /// wrapping) and returns the first free one. `None` when every possible
    /// suffix for `kind`'s label is already in use in this context.
    fn fresh_token(&self, kind: &EntityKind) -> Option<String> {
        for _ in 0..64 {
            let t = format_token(&self.settings, kind, &random_suffix(&self.settings));
            if !self.by_token.contains_key(&t) {
                return Some(t);
            }
        }
        let n = self.settings.suffix_len.clamp(1, 12) as u32;
        let space: u64 = 16u64.pow(n);
        let mut offset_bytes = [0u8; 8];
        getrandom::fill(&mut offset_bytes).expect("OS randomness available");
        let start = u64::from_le_bytes(offset_bytes) % space;
        for step in 0..space {
            let idx = (start + step) % space;
            let suffix = format!("{:0width$x}", idx, width = n as usize);
            let t = format_token(&self.settings, kind, &suffix);
            if !self.by_token.contains_key(&t) {
                return Some(t);
            }
        }
        None
    }

    /// Marker used for `Remove` actions, e.g. `<SECRET_REMOVED>`.
    pub fn removed_marker(&self, kind: &EntityKind) -> String {
        format!(
            "{}{}_REMOVED{}",
            self.settings.open,
            token_label(kind),
            self.settings.close
        )
    }

    /// Token for `original`, reusing an existing one when the normalized value
    /// already maps. A bare surname is its own entity here; linking it to a
    /// full name is the engine's job (`crate::link`), never the store's.
    ///
    /// `Err(StoreError::Exhausted(_))` when every possible token suffix for
    /// `kind`'s label is already in use in this context; nothing is stored.
    pub fn token_for(
        &mut self,
        kind: &EntityKind,
        original: &str,
    ) -> std::result::Result<Token, StoreError> {
        self.touch();
        let key = normalize(original);
        let class = kind_class(kind);
        if let Some(&i) = self.by_key.get(&class).and_then(|m| m.get(&key)) {
            self.entries[i].used = Instant::now();
            return Ok(Token(self.entries[i].token.clone()));
        }
        let token = self
            .fresh_token(kind)
            .ok_or_else(|| StoreError::Exhausted(token_label(kind)))?;
        let idx = self.entries.len();
        self.entries.push(Entry {
            token: token.clone(),
            kind: kind.clone(),
            original: Zeroizing::new(original.to_string()),
            surface_of: None,
            used: Instant::now(),
        });
        self.by_token.insert(token.clone(), idx);
        self.by_key.entry(class).or_default().insert(key, idx);
        self.dict.note_entry(kind, original);
        Ok(Token(token))
    }

    /// The token [`Context::token_for`] would reuse for `original` of
    /// `kind`, without minting one or touching use times (M8 spec §5.3: a
    /// session's existing token wins over a dataset token for the same
    /// value). Mirrors `token_for`'s reuse branch exactly: the normalized
    /// value (surnames are linked by the name linker, not by the store).
    pub fn peek_token(&self, kind: &EntityKind, original: &str) -> Option<Token> {
        let key = normalize(original);
        if let Some(&i) = self.by_key.get(&kind_class(kind)).and_then(|m| m.get(&key)) {
            return Some(Token(self.entries[i].token.clone()));
        }
        None
    }

    /// The kind of a token this context minted (entity or surface form).
    pub fn kind_of(&self, token: &str) -> Option<EntityKind> {
        self.by_token
            .get(token)
            .map(|&i| self.entries[i].kind.clone())
    }

    /// See [`TokenStore::surface_token`]: `parent` must be an entity token
    /// this context minted.
    pub fn surface_token(
        &mut self,
        parent: &Token,
        surface: &str,
    ) -> std::result::Result<Token, StoreError> {
        let kind = match self.by_token.get(parent.as_str()) {
            Some(&i) if self.entries[i].surface_of.is_none() => self.entries[i].kind.clone(),
            _ => return Err(StoreError::UnknownParent),
        };
        self.surface_with_kind(parent, surface, kind)
    }

    /// [`Context::surface_token`] for a parent this context does not hold:
    /// the inspection overlay previews surface forms of vault entities, so
    /// the parent only has to parse as an entity token; its kind is read
    /// from the label. Never used on a release path.
    pub fn surface_token_foreign(
        &mut self,
        parent: &Token,
        surface: &str,
    ) -> std::result::Result<Token, StoreError> {
        if let Some(&i) = self.by_token.get(parent.as_str()) {
            if self.entries[i].surface_of.is_none() {
                return self.surface_token(parent, surface);
            }
            return Err(StoreError::UnknownParent);
        }
        match parse_token(&self.settings, parent.as_str()) {
            Some(p) if p.variant.is_none() && !p.removed => {
                let kind = EntityKind::from_label(p.label);
                self.surface_with_kind(parent, surface, kind)
            }
            _ => Err(StoreError::UnknownParent),
        }
    }

    fn surface_with_kind(
        &mut self,
        parent: &Token,
        surface: &str,
        kind: EntityKind,
    ) -> std::result::Result<Token, StoreError> {
        self.touch();
        // R9: keyed on the exact surface text, not its normalized form, so
        // rehydration always restores exactly the text that was replaced.
        let skey = (parent.as_str().to_string(), surface.to_string());
        if let Some(&i) = self.by_surface.get(&skey) {
            self.entries[i].used = Instant::now();
            return Ok(Token(self.entries[i].token.clone()));
        }
        let existing = self
            .surface_children
            .get(parent.as_str())
            .copied()
            .unwrap_or(0);
        let token = match self.settings.surface_form {
            SurfaceForm::Derived => {
                if existing >= MAX_SURFACE_FORMS {
                    return Err(StoreError::Exhausted(token_label(&kind)));
                }
                // random component, collision-checked against this parent's tokens
                let mut candidate = None;
                for _ in 0..64 {
                    let t = derive_surface_token(
                        &self.settings,
                        parent.as_str(),
                        &random_surface_component(),
                    );
                    if !self.by_token.contains_key(&t) {
                        candidate = Some(t);
                        break;
                    }
                }
                match candidate {
                    Some(t) => t,
                    None => {
                        // the space is nearly full: take the first free component
                        (0u8..=255)
                            .map(|n| {
                                derive_surface_token(
                                    &self.settings,
                                    parent.as_str(),
                                    &format!("{n:02x}"),
                                )
                            })
                            .find(|t| !self.by_token.contains_key(t))
                            .ok_or_else(|| StoreError::Exhausted(token_label(&kind)))?
                    }
                }
            }
            SurfaceForm::Independent => self
                .fresh_token(&kind)
                .ok_or_else(|| StoreError::Exhausted(token_label(&kind)))?,
        };
        let idx = self.entries.len();
        self.dict.note_entry(&kind, surface);
        self.entries.push(Entry {
            token: token.clone(),
            kind,
            original: Zeroizing::new(surface.to_string()),
            surface_of: Some(parent.as_str().to_string()),
            used: Instant::now(),
        });
        self.by_token.insert(token.clone(), idx);
        self.by_surface.insert(skey, idx);
        *self
            .surface_children
            .entry(parent.as_str().to_string())
            .or_default() += 1;
        Ok(Token(token))
    }

    /// See [`TokenStore::link_candidates`].
    pub fn link_candidates(&self, kind: &EntityKind, window: Duration) -> Vec<Zeroizing<String>> {
        let now = Instant::now();
        self.entries
            .iter()
            .filter(|e| {
                e.kind == *kind && e.surface_of.is_none() && now.duration_since(e.used) < window
            })
            .map(|e| Zeroizing::new(e.original.to_string()))
            .collect()
    }

    /// Original value for a token text, if known.
    pub fn original(&self, token: &str) -> Option<&str> {
        self.by_token
            .get(token)
            .map(|&i| self.entries[i].original.as_str())
    }

    /// All (kind, original) pairs. Used by the verifier's leak check.
    pub fn entries(&self) -> impl Iterator<Item = (&EntityKind, &str)> {
        self.entries.iter().map(|e| (&e.kind, e.original.as_str()))
    }

    /// Remember a value that a `Remove` action took out of the text, so the
    /// verifier can check that no other copy of it is sent. Deduplicated by
    /// value. Removed values never get a token and are never rehydrated.
    pub fn record_removed(&mut self, kind: &EntityKind, original: &str) {
        self.touch();
        if !self.removed.iter().any(|(_, v)| v.as_str() == original) {
            self.removed
                .push((kind.clone(), Zeroizing::new(original.to_string())));
            self.dict.note_removed(kind, original);
        }
    }

    /// All removed (kind, value) pairs. Used by the verifier's leak check only.
    pub fn removed_entries(&self) -> impl Iterator<Item = (&EntityKind, &str)> {
        self.removed.iter().map(|(k, v)| (k, v.as_str()))
    }

    /// Test hook (Task 5, Q1): append an entry without telling the cache
    /// (`note_entry`), as a write path that forgot to would.
    #[cfg(test)]
    pub(crate) fn push_entry_unnoted_for_test(&mut self, kind: &EntityKind, original: &str) {
        let token = self.fresh_token(kind).expect("token space left");
        self.by_token.insert(token.clone(), self.entries.len());
        self.entries.push(Entry {
            token,
            kind: kind.clone(),
            original: Zeroizing::new(original.to_string()),
            surface_of: None,
            used: Instant::now(),
        });
    }
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("id", &self.id)
            .field("entries", &self.entries.len())
            .field("removed", &self.removed.len())
            .field("surface_forms", &self.by_surface.len())
            .field("age_ms", &self.created.elapsed().as_millis())
            .finish()
    }
}

/// What the engine needs from a token mapping: minting, lookup, the leak
/// check's pattern sources, and the token format.
///
/// [`Context`] is the in-memory, per-session store; a vault namespace
/// (crate `inumaki-vault`) is the persistent one. The engine, the verifier,
/// and the rehydrator only ever see `dyn TokenStore`.
///
/// A store that cannot answer returns a [`StoreError`]; the caller discards
/// every result produced since the last successful call.
pub trait TokenStore {
    /// Token for `original` of `kind`; reuses an existing one for the same
    /// normalized value and a compatible kind.
    fn token_for(
        &mut self,
        kind: &EntityKind,
        original: &str,
    ) -> std::result::Result<Token, StoreError>;
    /// Original for a token string, if this store knows it.
    fn original(&self, token: &str) -> Option<&str>;
    /// Tokenized `(kind, original)` pairs the verifier may leak-check: for a
    /// `Context` the whole context, for a namespace its working set.
    fn entries(&self) -> Box<dyn Iterator<Item = (&EntityKind, &str)> + '_>;
    /// Record a value a `Remove` action took out (leak-checked, never rehydrated).
    fn record_removed(
        &mut self,
        kind: &EntityKind,
        original: &str,
    ) -> std::result::Result<(), StoreError>;
    /// Removed `(kind, value)` pairs for the leak check.
    fn removed_entries(&self) -> Box<dyn Iterator<Item = (&EntityKind, &str)> + '_>;
    /// Marker used in place of a removed value, e.g. `<SECRET_REMOVED>`.
    fn removed_marker(&self, kind: &EntityKind) -> String;
    /// Token format settings.
    fn settings(&self) -> &TokenSettings;
    /// Make `original` able to answer for `tokens`. A store that decrypts
    /// lazily loads them here; the default does nothing.
    fn prepare(&mut self, _tokens: &[String]) -> std::result::Result<(), StoreError> {
        Ok(())
    }

    /// Token for `surface`, a different spelling or a part of the entity
    /// behind `parent` (an entity token this store holds). The same exact
    /// surface text of the same parent gets the same token; the token
    /// restores to `surface` exactly (M4 spec §16.2: rehydration returns
    /// exactly the text replaced, so the key is the surface as given, not
    /// its normalized form). `Err(StoreError::UnknownParent)` when `parent`
    /// is not a current entity token here.
    fn surface_token(
        &mut self,
        parent: &Token,
        surface: &str,
    ) -> std::result::Result<Token, StoreError>;

    /// Originals of `kind` entities (never surface forms) minted or used
    /// within `window`, for the linker's store tier. The default links
    /// nothing across requests.
    fn link_candidates(&self, _kind: &EntityKind, _window: Duration) -> Vec<Zeroizing<String>> {
        Vec::new()
    }

    /// The referential-consistency dictionary over this store's values
    /// (`entries` and `removed_entries`, each with its alias variants when
    /// `aliases` is given), from a [`StoreDictCache`] the store owns (Task
    /// 7e, ruling L62): its forms never outlive the store, and go when
    /// their values are forgotten, rotated out, or expire. `None` (the
    /// default): the store keeps no cache, and the caller builds a
    /// dictionary of its own per call.
    fn store_dict(&mut self, _aliases: Option<&AliasTable>) -> Option<crate::Result<StoreDict>> {
        None
    }

    /// The store's leak-check index from its own cache (the one behind
    /// [`TokenStore::store_dict`]; Task 5, Phase B). The caller holds it
    /// only for the current call: it keeps `Arc`s of the cache's layers,
    /// which must not outlive a `clear()` (Q5). The verifier checks it
    /// against the store before use (`LeakIndex::covers`). `None` (the
    /// default): no cache, the verifier builds its patterns per call.
    fn leak_index(&mut self, _aliases: Option<&AliasTable>) -> Option<crate::Result<LeakIndex>> {
        None
    }
}

impl TokenStore for Context {
    fn token_for(
        &mut self,
        kind: &EntityKind,
        original: &str,
    ) -> std::result::Result<Token, StoreError> {
        Context::token_for(self, kind, original)
    }
    fn original(&self, token: &str) -> Option<&str> {
        Context::original(self, token)
    }
    fn entries(&self) -> Box<dyn Iterator<Item = (&EntityKind, &str)> + '_> {
        Box::new(Context::entries(self))
    }
    fn record_removed(
        &mut self,
        kind: &EntityKind,
        original: &str,
    ) -> std::result::Result<(), StoreError> {
        Context::record_removed(self, kind, original);
        Ok(())
    }
    fn removed_entries(&self) -> Box<dyn Iterator<Item = (&EntityKind, &str)> + '_> {
        Box::new(Context::removed_entries(self))
    }
    fn removed_marker(&self, kind: &EntityKind) -> String {
        Context::removed_marker(self, kind)
    }
    fn settings(&self) -> &TokenSettings {
        Context::settings(self)
    }
    fn surface_token(
        &mut self,
        parent: &Token,
        surface: &str,
    ) -> std::result::Result<Token, StoreError> {
        Context::surface_token(self, parent, surface)
    }
    fn link_candidates(&self, kind: &EntityKind, window: Duration) -> Vec<Zeroizing<String>> {
        Context::link_candidates(self, kind, window)
    }
    /// The context only grows (no entry or removed value ever leaves it),
    /// so its cache never needs an eviction.
    fn store_dict(&mut self, aliases: Option<&AliasTable>) -> Option<crate::Result<StoreDict>> {
        let mut cache = std::mem::take(&mut self.dict);
        let d = cache.get(&*self, aliases);
        self.dict = cache;
        Some(d)
    }
    /// The leak index from the same cache (Task 5), as `store_dict`.
    fn leak_index(&mut self, aliases: Option<&AliasTable>) -> Option<crate::Result<LeakIndex>> {
        let mut cache = std::mem::take(&mut self.dict);
        let d = cache.leak(&*self, aliases);
        self.dict = cache;
        Some(d)
    }
}

/// In-memory store of live contexts keyed by id.
pub struct ContextStore {
    map: DashMap<ContextId, Context>,
    ttl: Duration,
    cap: usize,
    settings: TokenSettings,
}

impl ContextStore {
    /// Create a store.
    pub fn new(ttl: Duration, cap: usize, settings: TokenSettings) -> Self {
        ContextStore {
            map: DashMap::new(),
            ttl,
            cap,
            settings,
        }
    }

    /// A context that is not stored; dropped by the caller after one request.
    pub fn ephemeral(&self) -> Context {
        Context::new(ContextId(String::new()), self.ttl, self.settings.clone())
    }

    /// Fetch or create a stored context and mark it used. Evicts the least
    /// recently used context when at capacity.
    ///
    /// An existing context whose TTL has elapsed is never returned: it is
    /// replaced by a fresh, empty one (the old mappings are dropped and
    /// zeroized), so an expired context cannot be revived by access alone.
    pub fn get_or_create(&self, id: &ContextId) -> Result<RefMut<'_, ContextId, Context>> {
        if !self.map.contains_key(id) && self.map.len() >= self.cap {
            let oldest = self
                .map
                .iter()
                .min_by_key(|e| e.value().last_used)
                .map(|e| e.key().clone());
            match oldest {
                Some(k) => {
                    self.map.remove(&k);
                }
                None => return Err(Error::ContextCapReached),
            }
        }
        let fresh = || Context::new(id.clone(), self.ttl, self.settings.clone());
        let mut r = match self.map.entry(id.clone()) {
            MapEntry::Occupied(mut o) => {
                if o.get().is_expired(Instant::now()) {
                    // The replaced context drops here; its originals are zeroized.
                    o.insert(fresh());
                }
                o.into_ref()
            }
            MapEntry::Vacant(v) => v.insert(fresh()),
        };
        r.touch();
        Ok(r)
    }

    /// The stored context for `id`, marked used, or `None` when there is
    /// none or it has expired (an expired context is dropped, never
    /// revived). Restoration uses this: it must not create a session.
    pub fn get(&self, id: &ContextId) -> Option<RefMut<'_, ContextId, Context>> {
        let mut r = self.map.get_mut(id)?;
        if r.is_expired(Instant::now()) {
            drop(r);
            self.map.remove(id);
            return None;
        }
        r.touch();
        Some(r)
    }

    /// Remove a context now.
    pub fn remove(&self, id: &ContextId) {
        self.map.remove(id);
    }

    /// Drop expired contexts; returns how many were removed.
    pub fn sweep_expired(&self) -> usize {
        let now = Instant::now();
        let mut removed = 0usize;
        self.map.retain(|_, c| {
            if c.is_expired(now) {
                removed += 1;
                false
            } else {
                true
            }
        });
        removed
    }

    /// Number of live contexts.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True when no contexts are live.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::span::EntityKind as K;
    use std::time::Duration;

    fn ctx() -> Context {
        Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            TokenSettings::default(),
        )
    }

    #[test]
    fn token_shape_and_lookup() {
        let mut c = ctx();
        let t = c.token_for(&K::Person, "Sarah Leitner").unwrap();
        assert!(t.as_str().starts_with("<PERSON_"), "{}", t.as_str());
        assert!(t.as_str().ends_with('>'));
        assert_eq!(t.as_str().len(), "<PERSON_".len() + 4 + 1);
        assert_eq!(c.original(t.as_str()), Some("Sarah Leitner"));
        assert_eq!(c.len(), 1);
    }

    /// M4: token values never reach logs through `Debug`.
    #[test]
    fn token_debug_omits_the_value() {
        let mut c = ctx();
        let t = c.token_for(&K::Person, "Sarah Leitner").unwrap();
        let d = format!("{t:?}");
        assert!(!d.contains("PERSON"), "{d}");
        assert!(!d.contains(&t.as_str()[8..12]), "{d}");
        assert_eq!(d, format!("Token({})", t.as_str().len()));
    }

    #[test]
    fn same_entity_same_token_across_case_and_whitespace() {
        let mut c = ctx();
        let a = c.token_for(&K::Person, "Sarah Leitner").unwrap();
        let b = c.token_for(&K::Person, "SARAH  LEITNER").unwrap();
        let d = c.token_for(&K::Person, "sarah leitner").unwrap();
        assert_eq!(a, b);
        assert_eq!(a, d);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn diacritics_fold_into_same_key() {
        assert_eq!(normalize("Müller"), normalize("Muller"));
        assert_eq!(normalize("Straße 1"), normalize("strasse   1"));
    }

    #[test]
    fn normkey_debug_never_prints_plaintext() {
        let d = format!("{:?}", normalize("Sarah Leitner"));
        assert!(!d.contains("sarah"));
        assert!(!d.contains("leitner"));
    }

    #[test]
    fn different_kinds_get_different_tokens() {
        let mut c = ctx();
        let a = c.token_for(&K::City, "Wien").unwrap();
        let b = c.token_for(&K::Organization, "Wien").unwrap();
        assert_ne!(a, b);
    }

    /// Plan 4a: linking moved to `crate::link`; a bare surname is its own
    /// entity in the store, whatever full names it holds.
    #[test]
    fn store_no_longer_links_surnames_itself() {
        let mut c = ctx();
        let full = c.token_for(&K::Person, "Sarah Leitner").unwrap();
        let sur = c.token_for(&K::Person, "Leitner").unwrap();
        assert_ne!(full, sur);
        assert_eq!(c.original(sur.as_str()), Some("Leitner"));
        assert_eq!(c.token_for(&K::Person, "Leitner").unwrap(), sur);
        assert_eq!(c.len(), 2);
    }

    /// Plan 4a: the token grammar carries an optional surface component;
    /// every consumer parses tokens through one function.
    #[test]
    fn parse_token_reads_entity_variant_and_removed_shapes() {
        let s = TokenSettings::default();
        let p = parse_token(&s, "<PERSON_a7f2>").unwrap();
        assert_eq!(
            (p.label, p.suffix, p.variant, p.removed),
            ("PERSON", "a7f2", None, false)
        );
        let p = parse_token(&s, "<PERSON_a7f2c9_3e>").unwrap();
        assert_eq!(
            (p.label, p.suffix, p.variant, p.removed),
            ("PERSON", "a7f2c9", Some("3e"), false)
        );
        let p = parse_token(&s, "<K2FA_CODE_0123_00>").unwrap();
        assert_eq!(
            (p.label, p.suffix, p.variant),
            ("K2FA_CODE", "0123", Some("00"))
        );
        let p = parse_token(&s, "<SECRET_REMOVED>").unwrap();
        assert!(p.removed && p.variant.is_none() && p.label == "SECRET");
        // a four-hex tail is a suffix, not a component; the label absorbs the earlier part
        let p = parse_token(&s, "<LABEL_1234_5678>").unwrap();
        assert_eq!((p.label, p.suffix, p.variant), ("LABEL_1234", "5678", None));
        for bad in [
            "<PERSON_abc>",
            "<PERSON_a7f2_0>",
            "<PERSON_a7f2_012>",
            "<PERSON_a7f2_3E>",
            "<PERSON_a7f2_3e_4f>",
            "<person_a7f2>",
            "PERSON_a7f2",
            "<PERSON_a7f2",
            "<PERSON_A7F2>",
            "<_a7f2>",
            "<PERSON_abcdefabcdefa>",
            "<PERSON_a7f2_x>",
            "<PERSON_a7f2_xx>",
        ] {
            assert!(parse_token(&s, bad).is_none(), "{bad}");
        }
        let braces = TokenSettings {
            open: "{{".into(),
            close: "}}".into(),
            ..TokenSettings::default()
        };
        assert_eq!(
            parse_token(&braces, "{{IBAN_ab12cd_07}}").unwrap().variant,
            Some("07")
        );
        assert!(parse_token(&braces, "<IBAN_ab12cd>").is_none());
        assert_eq!(
            derive_surface_token(&s, "<PERSON_a7f2c9>", "3e"),
            "<PERSON_a7f2c9_3e>"
        );
        assert_eq!(
            derive_surface_token(&braces, "{{PERSON_a7f2c9}}", "0c"),
            "{{PERSON_a7f2c9_0c}}"
        );
        let c = random_surface_component();
        assert_eq!(c.len(), 2);
        assert!(
            c.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
    }

    /// Plan 4a: a surface form of an entity gets a derived token that shares
    /// the entity's suffix, restores to its own text, and is reused for the
    /// same surface; `Independent` hides the link.
    #[test]
    fn context_surface_tokens_are_derived_reused_and_restore_their_text() {
        let mut c = ctx();
        let full = c.token_for(&K::Person, "Sarah Leitner").unwrap();
        let first = c.surface_token(&full, "Sarah").unwrap();
        let (pf, p1) = (
            parse_token(c.settings(), full.as_str()).unwrap(),
            parse_token(c.settings(), first.as_str()).unwrap(),
        );
        assert_eq!(
            (p1.label, p1.suffix),
            (pf.label, pf.suffix),
            "derived from the parent"
        );
        assert_eq!(p1.variant.map(str::len), Some(2));
        // R9: the same exact surface text reuses the token; a different
        // exact text (even a mere case variant) is a distinct surface form
        // that restores to itself, not to the first-seen spelling.
        assert_eq!(
            c.surface_token(&full, "Sarah").unwrap(),
            first,
            "same exact surface, same token"
        );
        let shout = c.surface_token(&full, "SARAH").unwrap();
        assert_ne!(
            shout, first,
            "different exact text, different surface token"
        );
        assert_eq!(c.original(shout.as_str()), Some("SARAH"));
        let last = c.surface_token(&full, "Leitner").unwrap();
        assert_ne!(last, first);
        assert_eq!(
            parse_token(c.settings(), last.as_str()).unwrap().suffix,
            pf.suffix
        );
        assert_eq!(c.original(first.as_str()), Some("Sarah"));
        assert_eq!(c.original(last.as_str()), Some("Leitner"));
        assert_eq!(c.original(full.as_str()), Some("Sarah Leitner"));
        assert_eq!(c.len(), 4);
        // entries lists the surface forms too (the leak check sees them)
        let e: Vec<String> = c.entries().map(|(_, o)| o.to_string()).collect();
        assert!(e.contains(&"Sarah".to_string()) && e.contains(&"Leitner".to_string()));
        // an unknown parent is refused
        assert_eq!(
            c.surface_token(&Token::from("<PERSON_0000>".to_string()), "X"),
            Err(StoreError::UnknownParent)
        );
        // independent mode: a fresh suffix, still a surface row
        let mut i = Context::new(
            ContextId("i".into()),
            Duration::from_secs(60),
            TokenSettings {
                surface_form: SurfaceForm::Independent,
                ..TokenSettings::default()
            },
        );
        let full = i.token_for(&K::Person, "Sarah Leitner").unwrap();
        let first = i.surface_token(&full, "Sarah").unwrap();
        let pf = parse_token(i.settings(), full.as_str()).unwrap();
        let ps = parse_token(i.settings(), first.as_str()).unwrap();
        assert_ne!(pf.suffix, ps.suffix);
        assert_eq!(ps.variant, None);
        assert_eq!(i.original(first.as_str()), Some("Sarah"));
        assert_eq!(
            i.surface_token(&full, "Sarah").unwrap(),
            first,
            "exact reuse"
        );
        let lower = i.surface_token(&full, "sarah").unwrap();
        assert_ne!(
            lower, first,
            "different exact text, different surface token"
        );
        assert_eq!(i.original(lower.as_str()), Some("sarah"));
    }

    /// Plan 4a: `link_candidates` returns recent canonical persons only.
    #[test]
    fn context_link_candidates_are_recent_canonical_persons() {
        let mut c = ctx();
        let full = c.token_for(&K::Person, "Sarah Leitner").unwrap();
        c.surface_token(&full, "Sarah").unwrap();
        c.token_for(&K::City, "Wien").unwrap();
        let v: Vec<String> = c
            .link_candidates(&K::Person, Duration::from_secs(60))
            .into_iter()
            .map(|z| z.to_string())
            .collect();
        assert_eq!(
            v,
            vec!["Sarah Leitner".to_string()],
            "no surface rows, no other kinds"
        );
        assert!(
            c.link_candidates(&K::Person, Duration::ZERO).is_empty(),
            "outside the window"
        );
    }

    #[test]
    fn tokens_are_unique_under_collision_pressure() {
        let mut c = Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            TokenSettings {
                suffix_len: 1,
                ..Default::default()
            },
        );
        // 16 possible suffixes; ask for 16 distinct persons; all must be distinct.
        let mut seen = std::collections::HashSet::new();
        for i in 0..16 {
            assert!(seen.insert(c.token_for(&K::Person, &format!("Person Nr{i}")).unwrap()));
        }
    }

    /// Spec §5.3: exhaustion is an error, never a panic and never an unstored token.
    #[test]
    fn context_reports_exhaustion_instead_of_panicking() {
        let mut c = Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            TokenSettings {
                suffix_len: 1,
                ..Default::default()
            },
        );
        for i in 0..16 {
            c.token_for(&K::Person, &format!("Person Nr{i}")).unwrap();
        }
        assert_eq!(
            c.token_for(&K::Person, "Person Nr16"),
            Err(StoreError::Exhausted("PERSON".into()))
        );
        assert_eq!(c.len(), 16, "nothing was stored for the failed mint");
    }

    #[test]
    fn custom_delimiters_and_removed_marker() {
        let mut c = Context::new(
            ContextId("t".into()),
            Duration::from_secs(60),
            TokenSettings {
                suffix_len: 4,
                open: "{{".into(),
                close: "}}".into(),
                ..Default::default()
            },
        );
        let t = c.token_for(&K::Email, "a@b.c").unwrap();
        assert!(t.as_str().starts_with("{{EMAIL_") && t.as_str().ends_with("}}"));
        assert_eq!(
            c.removed_marker(&K::Secret(crate::span::SecretKind::Aws)),
            "{{SECRET_REMOVED}}"
        );
    }

    #[test]
    fn custom_label_spells_out_umlauts() {
        let mut c = ctx();
        let t = c.token_for(&K::custom("büro"), "Büro 5").unwrap();
        assert!(t.as_str().starts_with("<BUERO_"), "{}", t.as_str());
    }

    #[test]
    fn custom_label_not_starting_with_letter_gets_prefixed() {
        let mut c = ctx();
        let t = c.token_for(&K::custom("2fa code"), "123456").unwrap();
        assert!(t.as_str().starts_with("<K2FA_CODE_"), "{}", t.as_str());
    }

    #[test]
    fn builtin_labels_are_unchanged() {
        let mut c = ctx();
        let t = c.token_for(&K::Person, "Sarah Leitner").unwrap();
        assert!(t.as_str().starts_with("<PERSON_"));
        assert_eq!(
            c.removed_marker(&K::Secret(crate::span::SecretKind::Aws)),
            "<SECRET_REMOVED>"
        );
    }

    #[test]
    fn removed_values_are_leak_only_and_deduplicated() {
        let mut c = ctx();
        let k = K::Secret(crate::span::SecretKind::Generic);
        c.record_removed(&k, "9f8e7d6c5b4a3210ffee");
        c.record_removed(&k, "9f8e7d6c5b4a3210ffee");
        assert_eq!(c.removed_entries().count(), 1);
        assert!(c.is_empty(), "removed values are not token mappings");
        assert_eq!(c.entries().count(), 0);
        assert!(!format!("{c:?}").contains("9f8e"));
    }

    #[test]
    fn debug_never_prints_originals() {
        let mut c = ctx();
        c.token_for(&K::Person, "Sarah Leitner").unwrap();
        let d = format!("{c:?}");
        assert!(!d.contains("Sarah"));
        assert!(d.contains("entries"));
    }

    /// I8: an expired context must never come back; access replaces it.
    #[test]
    fn expired_context_is_replaced_on_access() {
        let store = ContextStore::new(Duration::from_millis(40), 10, TokenSettings::default());
        let id = ContextId("a".into());
        store
            .get_or_create(&id)
            .unwrap()
            .token_for(&K::Person, "Sarah Leitner")
            .unwrap();
        std::thread::sleep(Duration::from_millis(80));
        let c = store.get_or_create(&id).unwrap();
        assert!(!c.is_expired(Instant::now()), "revived an expired context");
        assert_eq!(c.len(), 0, "expired mappings must not be reused");
        assert!(c.original("<PERSON_0000>").is_none());
    }

    /// I8: access counts as use, so an active context does not expire.
    #[test]
    fn access_refreshes_ttl() {
        let store = ContextStore::new(Duration::from_millis(300), 10, TokenSettings::default());
        let id = ContextId("a".into());
        store
            .get_or_create(&id)
            .unwrap()
            .token_for(&K::Person, "Sarah Leitner")
            .unwrap();
        std::thread::sleep(Duration::from_millis(180));
        assert_eq!(store.get_or_create(&id).unwrap().len(), 1);
        std::thread::sleep(Duration::from_millis(180));
        assert_eq!(
            store.get_or_create(&id).unwrap().len(),
            1,
            "the access at 180 ms must have refreshed the TTL"
        );
    }

    /// M4 spec §5.3: restoration never creates a session and never revives an expired one.
    #[test]
    fn get_never_creates_and_drops_expired() {
        let store = ContextStore::new(Duration::from_millis(40), 10, TokenSettings::default());
        let id = ContextId("a".into());
        assert!(store.get(&id).is_none());
        assert_eq!(store.len(), 0, "get must not create");
        store
            .get_or_create(&id)
            .unwrap()
            .token_for(&K::Person, "Sarah Leitner")
            .unwrap();
        assert_eq!(store.get(&id).unwrap().len(), 1);
        std::thread::sleep(Duration::from_millis(80));
        assert!(store.get(&id).is_none(), "expired");
        assert_eq!(store.len(), 0, "expired context dropped on access");
    }

    #[test]
    fn store_ttl_and_cap() {
        let store = ContextStore::new(Duration::from_millis(0), 2, TokenSettings::default());
        store
            .get_or_create(&ContextId("a".into()))
            .unwrap()
            .token_for(&K::Person, "A B")
            .unwrap();
        store.get_or_create(&ContextId("b".into())).unwrap();
        assert_eq!(store.len(), 2);
        store.get_or_create(&ContextId("c".into())).unwrap(); // evicts oldest
        assert_eq!(store.len(), 2);
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(store.sweep_expired(), 2);
        assert_eq!(store.len(), 0);
        let e = store.ephemeral();
        assert!(e.is_empty());
    }

    /// A minimal in-memory `TokenStore` unrelated to `Context`, used to show
    /// the engine works through the trait alone.
    struct MapStore {
        settings: TokenSettings,
        entries: Vec<(EntityKind, String, String, Option<String>)>, // kind, original, token, surface_of
        removed: Vec<(EntityKind, String)>,
    }

    impl MapStore {
        fn new() -> Self {
            MapStore {
                settings: TokenSettings::default(),
                entries: Vec::new(),
                removed: Vec::new(),
            }
        }
    }

    impl TokenStore for MapStore {
        fn token_for(
            &mut self,
            kind: &EntityKind,
            original: &str,
        ) -> std::result::Result<Token, StoreError> {
            let key = normalize(original);
            if let Some((_, _, t, _)) = self.entries.iter().find(|(k, o, _, p)| {
                p.is_none() && k.label() == kind.label() && normalize(o) == key
            }) {
                return Ok(Token(t.clone()));
            }
            let mut t = format_token(&self.settings, kind, &random_suffix(&self.settings));
            while self.entries.iter().any(|(_, _, e, _)| *e == t) {
                t = format_token(&self.settings, kind, &random_suffix(&self.settings));
            }
            self.entries
                .push((kind.clone(), original.to_string(), t.clone(), None));
            Ok(Token(t))
        }
        fn original(&self, token: &str) -> Option<&str> {
            self.entries
                .iter()
                .find(|(_, _, t, _)| t == token)
                .map(|(_, o, _, _)| o.as_str())
        }
        fn entries(&self) -> Box<dyn Iterator<Item = (&EntityKind, &str)> + '_> {
            Box::new(self.entries.iter().map(|(k, o, _, _)| (k, o.as_str())))
        }
        fn record_removed(
            &mut self,
            kind: &EntityKind,
            original: &str,
        ) -> std::result::Result<(), StoreError> {
            if !self.removed.iter().any(|(_, v)| v == original) {
                self.removed.push((kind.clone(), original.to_string()));
            }
            Ok(())
        }
        fn removed_entries(&self) -> Box<dyn Iterator<Item = (&EntityKind, &str)> + '_> {
            Box::new(self.removed.iter().map(|(k, v)| (k, v.as_str())))
        }
        fn removed_marker(&self, kind: &EntityKind) -> String {
            format!(
                "{}{}_REMOVED{}",
                self.settings.open,
                token_label(kind),
                self.settings.close
            )
        }
        fn settings(&self) -> &TokenSettings {
            &self.settings
        }
        fn surface_token(
            &mut self,
            parent: &Token,
            surface: &str,
        ) -> std::result::Result<Token, StoreError> {
            let kind = match self
                .entries
                .iter()
                .find(|(_, _, t, p)| p.is_none() && t == parent.as_str())
            {
                Some((k, _, _, _)) => k.clone(),
                None => return Err(StoreError::UnknownParent),
            };
            // R9: keyed on the exact surface text, not its normalized form.
            if let Some((_, _, t, _)) = self
                .entries
                .iter()
                .find(|(_, o, _, p)| p.as_deref() == Some(parent.as_str()) && o.as_str() == surface)
            {
                return Ok(Token(t.clone()));
            }
            let existing = self
                .entries
                .iter()
                .filter(|(_, _, _, p)| p.as_deref() == Some(parent.as_str()))
                .count();
            let mut component = (existing % 256) as u8;
            let mut token =
                derive_surface_token(&self.settings, parent.as_str(), &format!("{component:02x}"));
            while self.entries.iter().any(|(_, _, t, _)| *t == token) {
                component = component.wrapping_add(1);
                token = derive_surface_token(
                    &self.settings,
                    parent.as_str(),
                    &format!("{component:02x}"),
                );
            }
            self.entries.push((
                kind,
                surface.to_string(),
                token.clone(),
                Some(parent.as_str().to_string()),
            ));
            Ok(Token(token))
        }
    }

    /// Behaviour every `TokenStore` must show. Lives inside `#[cfg(test)]`,
    /// so other crates cannot import it: `inumaki-vault`'s `tests/namespace.rs`
    /// carries a copy. Keep both in sync when changing either.
    /// A `<PERSON_...>` token this store cannot possibly have minted, for
    /// conformance's unknown-token checks. `token_for`/`fresh_token` always
    /// mint a suffix of exactly `settings.suffix_len` hex characters, so a
    /// suffix one character longer can never collide (review Minor 5: the
    /// literal `"0".repeat(n)` used here previously could coincide with one
    /// of the 200 randomly minted suffixes later in this function, about
    /// 0.3% of runs). When `n` is already the 12-character maximum, fall
    /// back to drawing suffixes until one is confirmed unminted.
    fn unminted_person_token(store: &dyn TokenStore, open: &str, close: &str, n: usize) -> String {
        if n < 12 {
            return format!("{open}PERSON_{}{close}", "0".repeat(n + 1));
        }
        loop {
            let candidate = format!("{open}PERSON_{}{close}", random_suffix(store.settings()));
            if store.original(&candidate).is_none() {
                return candidate;
            }
        }
    }

    pub(crate) fn conformance(store: &mut dyn TokenStore) {
        let n = store.settings().suffix_len;
        let (open, close) = (
            store.settings().open.clone(),
            store.settings().close.clone(),
        );
        let t = store.token_for(&K::Person, "Sarah Leitner").unwrap();
        assert!(
            t.as_str().starts_with(&format!("{open}PERSON_")),
            "{}",
            t.as_str()
        );
        assert!(t.as_str().ends_with(&close));
        let suffix = &t.as_str()[open.len() + "PERSON_".len()..t.as_str().len() - close.len()];
        assert_eq!(suffix.len(), n);
        assert!(
            suffix
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        // same entity, same token, across case and whitespace
        assert_eq!(store.token_for(&K::Person, "SARAH  LEITNER").unwrap(), t);
        assert_eq!(store.token_for(&K::Person, "sarah leitner").unwrap(), t);
        // original() returns the first-seen spelling; unknown tokens are None
        assert_eq!(store.original(t.as_str()), Some("Sarah Leitner"));
        let unminted = unminted_person_token(&*store, &open, &close, n);
        assert_eq!(store.original(&unminted), None);
        // different kinds, different tokens
        let city = store.token_for(&K::City, "Wien").unwrap();
        let org = store.token_for(&K::Organization, "Wien").unwrap();
        assert_ne!(city, org);
        // entries lists tokenized pairs
        let entries: Vec<(String, String)> = store
            .entries()
            .map(|(k, o)| (k.label().to_string(), o.to_string()))
            .collect();
        assert!(
            entries.contains(&("PERSON".into(), "Sarah Leitner".into())),
            "{entries:?}"
        );
        assert!(entries.contains(&("CITY".into(), "Wien".into())));
        // removed values: leak-only, deduplicated, never a token, never an original
        let secret = K::Secret(crate::span::SecretKind::Generic);
        store
            .record_removed(&secret, "9f8e7d6c5b4a3210ffee")
            .unwrap();
        store
            .record_removed(&secret, "9f8e7d6c5b4a3210ffee")
            .unwrap();
        assert_eq!(store.removed_entries().count(), 1);
        assert!(store.entries().all(|(_, o)| o != "9f8e7d6c5b4a3210ffee"));
        assert_eq!(
            store.removed_marker(&secret),
            format!("{open}SECRET_REMOVED{close}")
        );
        // uniqueness under many mints
        let mut seen = std::collections::HashSet::new();
        for i in 0..200 {
            assert!(
                seen.insert(
                    store
                        .token_for(&K::Person, &format!("Person Nr{i}"))
                        .unwrap()
                )
            );
        }
        // prepare is at least a no-op
        store.prepare(&[t.as_str().to_string()]).unwrap();
        assert_eq!(store.original(t.as_str()), Some("Sarah Leitner"));
        // surface forms (plan 4a): derived from the parent, restore their own text
        let sur = store.surface_token(&t, "Leitner").unwrap();
        let (pt, ps) = (
            crate::token::parse_token(store.settings(), t.as_str()).unwrap(),
            crate::token::parse_token(store.settings(), sur.as_str()).unwrap(),
        );
        assert_eq!((ps.label, ps.suffix), (pt.label, pt.suffix));
        assert_eq!(ps.variant.map(str::len), Some(2));
        assert_eq!(store.original(sur.as_str()), Some("Leitner"));
        // R9: the exact same surface text reuses the token; a different
        // (case-variant) surface text is a distinct token restoring itself.
        assert_eq!(store.surface_token(&t, "Leitner").unwrap(), sur);
        let sur_upper = store.surface_token(&t, "LEITNER").unwrap();
        assert_ne!(
            sur_upper, sur,
            "different exact text, different surface token"
        );
        assert_eq!(store.original(sur_upper.as_str()), Some("LEITNER"));
        assert_eq!(
            store.surface_token(&Token::from(unminted), "x"),
            Err(StoreError::UnknownParent)
        );
    }

    #[test]
    fn context_conforms_to_token_store() {
        let mut c = ctx();
        conformance(&mut c);
    }

    #[test]
    fn map_store_conforms_to_token_store() {
        let mut s = MapStore::new();
        conformance(&mut s);
    }

    #[test]
    fn engine_works_through_the_trait_object() {
        use crate::config::CoreConfig;
        use crate::engine::{Engine, Outcome};
        use crate::rehydrate::Rehydrator;
        let cfg = CoreConfig::from_toml(
            "[profiles.fast]\ndefault_action = \"tokenize\"\n[profiles.fast.entities.SECRET]\naction = \"remove\"\nmin_confidence = 0.0\n[profiles.fast.verifier]\nallow_no_ner = true\n",
        )
        .unwrap();
        let e = Engine::from_config(&cfg, "fast", None, None).unwrap();
        let mut s = MapStore::new();
        let text = "IBAN AT61 1904 3002 3457 3201 bitte";
        let Outcome::Pass { sanitized } = e.process(text, &mut s).unwrap() else {
            panic!("expected pass")
        };
        assert!(sanitized.text.contains("<IBAN_"));
        let (back, unknown) =
            Rehydrator::new(&TokenSettings::default()).rehydrate(&sanitized.text, &s);
        assert_eq!(back, text);
        assert_eq!(unknown, 0);
    }

    #[test]
    fn public_token_helpers_match_context_format() {
        let s = TokenSettings::default();
        let suffix = random_suffix(&s);
        assert_eq!(suffix.len(), 4);
        assert_eq!(format_token(&s, &K::Person, "a7f2"), "<PERSON_a7f2>");
        assert_eq!(token_label(&K::custom("büro")), "BUERO");
        let key = normalize("Sarah  Leitner");
        assert_eq!(key.as_str(), "sarah leitner");
    }
}
