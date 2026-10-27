//! TOML configuration for the core engine.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::detect::dictionary::DictionaryConfig;
use crate::detect::domain::DomainConfig;
use crate::lang::Language;
use crate::policy::{Action, EntityPolicy, OnUncertain, Profile, VerifierSettings};
use crate::{Error, Result};

fn d_suffix() -> usize {
    4
}
fn d_open() -> String {
    "<".into()
}
fn d_close() -> String {
    ">".into()
}
fn d_sessions() -> usize {
    1
}

/// `[tokens]` table.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenSettings {
    /// Hex characters after the kind label.
    #[serde(default = "d_suffix")]
    pub suffix_len: usize,
    /// Opening delimiter.
    #[serde(default = "d_open")]
    pub open: String,
    /// Closing delimiter.
    #[serde(default = "d_close")]
    pub close: String,
    /// How a mention whose text differs from the entity's stored original
    /// is tokenized (plan 4a): `derived` shares the entity's suffix with a
    /// surface component, `independent` mints an unrelated suffix.
    #[serde(default)]
    pub surface_form: crate::token::SurfaceForm,
}

impl Default for TokenSettings {
    fn default() -> Self {
        TokenSettings {
            suffix_len: d_suffix(),
            open: d_open(),
            close: d_close(),
            surface_form: crate::token::SurfaceForm::Derived,
        }
    }
}

/// One `[ner.<section>]` table.
#[derive(Debug, Clone, Deserialize)]
pub struct NerSectionConfig {
    /// Model name from the model manifest.
    pub model: String,
    /// Default minimum score for labels without their own threshold.
    pub threshold: f32,
    /// Labels given to the model and the entity kinds they map to.
    pub labels: Vec<NerLabelConfig>,
}

/// One label of an NER section.
#[derive(Debug, Clone, Deserialize)]
pub struct NerLabelConfig {
    /// Label text for the model (GLiNER) or the model's type name (`PER`…).
    pub label: String,
    /// Entity kind label, e.g. `PERSON`.
    pub kind: String,
    /// Per-label minimum score; defaults to the section threshold.
    pub threshold: Option<f32>,
}

/// `[ner]` table. Model loading lives in `inumaki-models`; core only carries the data.
#[derive(Debug, Clone, Deserialize)]
pub struct NerConfig {
    /// Models directory; see `inumaki_models::resolve_models_dir` for precedence.
    pub models_dir: Option<PathBuf>,
    /// Intra-op threads per model; 0 selects min(4, CPU cores).
    #[serde(default)]
    pub threads: usize,
    /// Independently loaded ONNX sessions per model (a pool); 1 means one
    /// request at a time per model. Memory grows linearly with this value.
    #[serde(default = "d_sessions")]
    pub sessions: usize,
    /// Sanitizer-side GLiNER settings.
    pub gliner: Option<NerSectionConfig>,
    /// Verifier-side GLiNER settings (lower threshold, broader labels).
    pub gliner_verifier: Option<NerSectionConfig>,
    /// Token-classifier settings.
    pub token_classifier: Option<NerSectionConfig>,
    /// Kiji PII model settings (plan 4a evaluation).
    pub kiji: Option<NerSectionConfig>,
}

impl Default for NerConfig {
    fn default() -> Self {
        NerConfig {
            models_dir: None,
            threads: 0,
            sessions: 1,
            gliner: None,
            gliner_verifier: None,
            token_classifier: None,
            kiji: None,
        }
    }
}

impl NerConfig {
    /// Section by profile value (`gliner`, `gliner_verifier`, `token_classifier`, `kiji`).
    pub fn section(&self, which: &str) -> Option<&NerSectionConfig> {
        match which {
            "gliner" => self.gliner.as_ref(),
            "gliner_verifier" => self.gliner_verifier.as_ref(),
            "token_classifier" => self.token_classifier.as_ref(),
            "kiji" => self.kiji.as_ref(),
            _ => None,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.sessions == 0 {
            return Err(Error::ConfigInvalid("ner.sessions".into()));
        }
        let in_range = |v: f32| (0.0..=1.0).contains(&v);
        for (name, sec) in [
            ("gliner", &self.gliner),
            ("gliner_verifier", &self.gliner_verifier),
            ("token_classifier", &self.token_classifier),
            ("kiji", &self.kiji),
        ] {
            let Some(sec) = sec else { continue };
            if sec.model.trim().is_empty() {
                return Err(Error::ConfigInvalid(format!("ner.{name}.model")));
            }
            if !in_range(sec.threshold) {
                return Err(Error::ConfigInvalid(format!("ner.{name}.threshold")));
            }
            if sec.labels.is_empty() {
                return Err(Error::ConfigInvalid(format!("ner.{name}.labels")));
            }
            // The model is asked for each label text once and a label's
            // spans take the kind of the last entry that names it, so two
            // entries for one label with different kinds or thresholds would
            // leave one of them dead. Refuse instead of picking one. (The
            // overlay replaces a shipped label that the file restates, so
            // this fires for a label twice in one list.)
            let mut seen: HashMap<&str, (String, f32)> = HashMap::new();
            for (i, l) in sec.labels.iter().enumerate() {
                let effective = (
                    l.kind.to_ascii_uppercase(),
                    l.threshold.unwrap_or(sec.threshold),
                );
                if seen
                    .insert(l.label.as_str(), effective.clone())
                    .is_some_and(|p| p != effective)
                {
                    return Err(Error::ConfigInvalid(format!(
                        "ner.{name}.labels[{i}].label"
                    )));
                }
                if l.threshold.is_some_and(|t| !in_range(t)) {
                    return Err(Error::ConfigInvalid(format!(
                        "ner.{name}.labels[{i}].threshold"
                    )));
                }
                if !kind_ok(&l.kind) {
                    return Err(Error::ConfigInvalid(format!("ner.{name}.labels[{i}].kind")));
                }
            }
        }
        Ok(())
    }
}

/// `[profiles.<name>.verifier]` table before defaults are applied.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct VerifierSettingsConfig {
    /// See [`VerifierSettings::on_uncertain`].
    pub on_uncertain: Option<OnUncertain>,
    /// See [`VerifierSettings::retry_profile`].
    pub retry_profile: Option<String>,
    /// See [`VerifierSettings::allow_no_ner`].
    pub allow_no_ner: Option<bool>,
    /// See [`VerifierSettings::combination_threshold`].
    pub combination_threshold: Option<usize>,
}

/// `[profiles.<name>]` table before inheritance is resolved.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProfileConfig {
    /// Parent profile name.
    pub extends: Option<String>,
    /// `"auto"`, `"de"`, or `"en"`.
    pub language: Option<String>,
    /// Action for kinds without an explicit entry.
    pub default_action: Option<Action>,
    /// Threshold for kinds without an explicit entry.
    pub default_min_confidence: Option<f32>,
    /// See [`Profile::escalate_below`].
    pub escalate_below: Option<f32>,
    /// Per-kind entries.
    #[serde(default)]
    pub entities: HashMap<String, EntityPolicy>,
    /// Verifier settings.
    pub verifier: Option<VerifierSettingsConfig>,
    /// NER section for detection: `gliner`, `gliner_verifier`, `token_classifier`, `kiji`, or `none`.
    pub ner_sanitizer: Option<String>,
    /// NER section for the verifier's independent re-scan (must differ from `ner_sanitizer`).
    pub ner_verifier: Option<String>,
    /// Marks this profile as the discovery-metadata variant of the named
    /// profile (plan 2c): a dataset with that profile sanitizes its listing
    /// prose (tool, prompt, and template prose, schema prose, enum values)
    /// under this one. Read from this profile's own table only, never
    /// through `extends`. See [`CoreConfig::metadata_profile_for`].
    pub metadata_of: Option<String>,
}

/// Whole core configuration. Unknown tables (`[server]`, `[providers]`) are ignored.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CoreConfig {
    /// Token format.
    #[serde(default)]
    pub tokens: TokenSettings,
    /// Dictionary files.
    #[serde(default)]
    pub dictionary: DictionaryConfig,
    /// Domain recognizers.
    #[serde(default)]
    pub domain: DomainConfig,
    /// Named profiles.
    #[serde(default)]
    pub profiles: HashMap<String, ProfileConfig>,
    /// NER model sections available to profiles.
    #[serde(default)]
    pub ner: NerConfig,
    /// Name linking (M4 spec §16.2).
    #[serde(default)]
    pub linking: crate::link::LinkingConfig,
}

/// A configured kind name, upper-cased (`meter_point` → `METER_POINT`, as
/// [`crate::span::EntityKind::from_label`] does), has the one kind-label
/// shape ([`crate::span::valid_kind_label`]).
fn kind_ok(kind: &str) -> bool {
    crate::span::valid_kind_label(&kind.to_ascii_uppercase())
}

/// 1-based (line, column) of a byte offset into `s`. Never returns any text
/// from `s` itself, only its position.
fn line_col(s: &str, offset: usize) -> (usize, usize) {
    let mut offset = offset.min(s.len());
    while offset > 0 && !s.is_char_boundary(offset) {
        offset -= 1;
    }
    let mut line = 1usize;
    let mut col = 1usize;
    for ch in s[..offset].chars() {
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

/// The shipped default configuration, compiled in.
const EMBEDDED_DEFAULT: &str = include_str!("../../../configs/default.toml");

/// The position-only message for a TOML error in `s`. Never carries any
/// value from `s`, per the `ConfigInvalid` contract.
fn toml_error(s: &str, e: &toml::de::Error) -> Error {
    match e.span() {
        Some(span) => {
            let (line, col) = line_col(s, span.start);
            Error::ConfigInvalid(format!("toml parse error at line {line}, column {col}"))
        }
        None => Error::ConfigInvalid("toml parse error".into()),
    }
}

/// The arrays of tables whose entries have an identity key, as (path, key).
/// An entry of the file with the same key value as a shipped entry replaces
/// that entry in place. Only the NER label lists have one: a `label` text
/// names one entry for the model. Every other array of tables
/// (`domain.labels`, `domain.patterns`) is a set of independent rules.
const IDENTITY_KEYS: &[(&str, &str)] = &[
    ("ner.gliner.labels", "label"),
    ("ner.gliner_verifier.labels", "label"),
    ("ner.token_classifier.labels", "label"),
    ("ner.kiji.labels", "label"),
];

/// Merge `user` into `base`: a table present in both merges key by key,
/// recursively. An array of tables that `base` also has and fills is
/// extended, so a file can add a detector but never drop a shipped one:
/// where the array has an identity key ([`IDENTITY_KEYS`]) an entry of
/// `user` with the same key value replaces the shipped entry in place and an
/// entry with a new value is appended; otherwise the shipped entries stay
/// first and the entries of `user` that are not exact duplicates follow. A
/// second entry of `user` with a key value its own list already used is
/// appended, not merged, so the duplicate is still seen by validation. Every
/// other value (a scalar, an array of scalars, an array the base has empty)
/// replaces the base's value as a whole.
fn merge_tables(base: &mut toml::Table, user: toml::Table) {
    merge_at(base, user, "");
}

fn merge_at(base: &mut toml::Table, user: toml::Table, path: &str) {
    use toml::Value;
    let tables = |a: &[Value]| a.iter().all(Value::is_table);
    for (key, value) in user {
        let here = if path.is_empty() {
            key.clone()
        } else {
            format!("{path}.{key}")
        };
        match (base.get_mut(&key), value) {
            (Some(Value::Table(b)), Value::Table(u)) => merge_at(b, u, &here),
            (Some(Value::Array(b)), Value::Array(u))
                if !b.is_empty() && tables(b) && tables(&u) =>
            {
                let identity = IDENTITY_KEYS
                    .iter()
                    .find(|(p, _)| *p == here)
                    .map(|(_, k)| *k);
                let shipped = b.len();
                let mut replaced = HashSet::new();
                for entry in u {
                    let named = identity.and_then(|k| entry.get(k)).filter(|v| v.is_str());
                    let slot = named.and_then(|n| {
                        let k = identity?;
                        (0..shipped).find(|i| b[*i].get(k) == Some(n) && !replaced.contains(i))
                    });
                    match slot {
                        Some(i) => {
                            replaced.insert(i);
                            b[i] = entry;
                        }
                        None if identity.is_none() && b.contains(&entry) => {}
                        None => b.push(entry),
                    }
                }
            }
            (_, value) => {
                base.insert(key, value);
            }
        }
    }
}

/// The user's configuration file laid over the embedded default
/// (`configs/default.toml`), as one table. A partial file is enough.
///
/// One rule applies everywhere, profiles included: a table in `user` that
/// the default also has merges key by key, recursively. So `[tokens]
/// suffix_len` changes one key and keeps the rest, and `[profiles.offline]
/// escalate_below` changes one setting of the shipped `offline` and keeps its
/// entity rules and verifier settings, which the profiles extending it rely
/// on. A scalar, an array of scalars, or an array the default has empty
/// (`dictionary.persons`, ...) replaces the default's value as a whole. An
/// array of tables the default fills (`[[domain.labels]]`,
/// `[[domain.patterns]]`, `[ner.*] labels`) is extended: the shipped entries
/// stay, the file's entries follow, an exact duplicate of a shipped entry is
/// not doubled, and a NER label restated in the file (same `label` text)
/// replaces the shipped label in place, so its threshold or kind can be
/// tuned. To loosen a shipped profile rule the file states it explicitly,
/// except SECRET, which every profile must remove or block (see
/// `CoreConfig::check_secret_removed`); a shipped detector or NER label
/// cannot be removed. Tables the default does
/// not have (`[daemon]`, `[vault]`, ...) pass through.
///
/// `user` is first read on its own against the engine's tables, so a wrong
/// type is reported at the user's own line and column. A section the file
/// only partly names (`[ner.gliner] threshold`) lacks keys its typed form
/// requires and the merged table supplies them, so a "missing field" there is
/// not an error; if the merged table still fails to load, that first error is
/// reported with its line. The error never carries a value.
pub fn overlay_on_default(user: &str) -> Result<toml::Table> {
    let user_table: toml::Table = toml::from_str(user).map_err(|e| toml_error(user, &e))?;
    let mut pending = None;
    if let Err(e) = toml::from_str::<CoreConfig>(user) {
        if !e.message().starts_with("missing field") {
            return Err(toml_error(user, &e));
        }
        pending = Some(toml_error(user, &e));
    }
    let mut user_table = user_table;
    uppercase_entity_keys(&mut user_table);
    let mut merged: toml::Table =
        toml::from_str(EMBEDDED_DEFAULT).expect("embedded default config is valid TOML");
    merge_tables(&mut merged, user_table);
    if let Err(e) = toml::Value::Table(merged.clone()).try_into::<CoreConfig>() {
        // The user-line error is the right one only when the merge failed
        // for the same reason; a different failure has no line to point at.
        return Err(match pending {
            Some(p) if e.message().starts_with("missing field") => p,
            _ => missing_or_invalid(),
        });
    }
    Ok(merged)
}

/// Upper-case the keys of every `profiles.<p>.entities` table in the user's
/// file, as [`CoreConfig::resolve_profile`] does, so `person` overrides the
/// shipped `PERSON` instead of sitting next to it. A table whose keys collide
/// after upper-casing is left as written; [`CoreConfig::validated`] refuses it.
fn uppercase_entity_keys(user: &mut toml::Table) {
    let Some(toml::Value::Table(profiles)) = user.get_mut("profiles") else {
        return;
    };
    for (_, profile) in profiles.iter_mut() {
        let Some(toml::Value::Table(entities)) = profile.get_mut("entities") else {
            continue;
        };
        let upper: HashSet<String> = entities.keys().map(|k| k.to_uppercase()).collect();
        if upper.len() != entities.len() {
            continue;
        }
        *entities = std::mem::take(entities)
            .into_iter()
            .map(|(k, v)| (k.to_uppercase(), v))
            .collect();
    }
}

fn missing_or_invalid() -> Error {
    Error::ConfigInvalid("missing or invalid value in the merged configuration".into())
}

impl CoreConfig {
    /// Parse a whole configuration from a TOML string. Nothing is layered
    /// under it: a table the text leaves out takes the type's own default,
    /// not the shipped one (use [`CoreConfig::from_toml_at`] or
    /// [`overlay_on_default`] for a partial file). The error never carries
    /// any value from `s`, only a line/column position, per the
    /// `ConfigInvalid` contract.
    pub fn from_toml(s: &str) -> Result<Self> {
        let cfg: CoreConfig = toml::from_str(s).map_err(|e| toml_error(s, &e))?;
        cfg.validated()
    }

    /// The cross-table checks every route into a [`CoreConfig`] shares.
    fn validated(self) -> Result<Self> {
        let cfg = self;
        if !(4..=12).contains(&cfg.tokens.suffix_len) {
            return Err(Error::ConfigInvalid("tokens.suffix_len".into()));
        }
        if cfg.linking.window_minutes == 0 {
            return Err(Error::ConfigInvalid("linking.window_minutes".into()));
        }
        cfg.ner.validate()?;
        for (name, pc) in &cfg.profiles {
            let mut seen = HashSet::new();
            for k in pc.entities.keys() {
                let up = k.to_uppercase();
                if !seen.insert(up.clone()) {
                    // Which entry wins would depend on map order.
                    return Err(Error::ConfigInvalid(
                        if crate::span::valid_kind_label(&up) {
                            format!("profiles.{name}.entities.{up}")
                        } else {
                            format!("profiles.{name}.entities")
                        },
                    ));
                }
            }
        }
        for (i, p) in cfg.domain.patterns.iter().enumerate() {
            if !kind_ok(&p.kind) {
                return Err(Error::ConfigInvalid(format!("domain.patterns[{i}].kind")));
            }
        }
        for (i, l) in cfg.domain.labels.iter().enumerate() {
            if !kind_ok(&l.kind) {
                return Err(Error::ConfigInvalid(format!("domain.labels[{i}].kind")));
            }
        }
        for (meta, pc) in &cfg.profiles {
            if let Some(base) = &pc.metadata_of {
                if !cfg.profiles.contains_key(base) {
                    return Err(Error::ConfigInvalid(format!("profiles.{meta}.metadata_of")));
                }
                cfg.metadata_profile_for(base)?;
            }
        }
        cfg.check_secret_removed()?;
        Ok(cfg)
    }

    /// Every effective profile removes or blocks the SECRET kind (rulings
    /// L90, L5-11): a credential is removed and never restored, so no
    /// profile, shipped or new, may `tokenize` or `preserve` it, whether it
    /// says so itself, inherits it through `extends`, or leaves SECRET
    /// unlisted with such a `default_action`. Its effective `min_confidence`
    /// may not exceed the secret scanner's fixed confidence
    /// ([`crate::detect::secrets::SECRET_CONFIDENCE`]), or a detected secret
    /// would escalate (text unchanged) or be dropped (ruling L5-12). The
    /// error names
    /// `profiles.<p>.entities.SECRET`, where `<p>` is the nearest profile in
    /// the chain that lists SECRET, or the checked profile when none does.
    /// A profile whose chain does not resolve is left to
    /// [`CoreConfig::resolve_profile`], which refuses it on use.
    fn check_secret_removed(&self) -> Result<()> {
        let secret = crate::span::EntityKind::Secret(crate::span::SecretKind::Generic);
        let mut names: Vec<&String> = self.profiles.keys().collect();
        names.sort();
        for name in names {
            let Ok(p) = self.resolve_profile(name) else {
                continue;
            };
            let sp = p.policy_for(&secret);
            if matches!(sp.action, Action::Remove | Action::Block)
                && sp.min_confidence <= crate::detect::secrets::SECRET_CONFIDENCE
            {
                continue;
            }
            let lists =
                |pc: &ProfileConfig| pc.entities.keys().any(|k| k.to_uppercase() == "SECRET");
            let mut at = name.as_str();
            let mut seen = HashSet::new();
            let source = loop {
                let Some(pc) = self.profiles.get(at) else {
                    break name.as_str();
                };
                if lists(pc) {
                    break at;
                }
                match &pc.extends {
                    Some(parent) if seen.insert(at) => at = parent,
                    _ => break name.as_str(),
                }
            };
            return Err(Error::ConfigInvalid(format!(
                "profiles.{source}.entities.SECRET"
            )));
        }
        Ok(())
    }

    /// Read a file, lay it over the embedded default ([`overlay_on_default`]),
    /// and resolve dictionary and `ner.models_dir` paths relative to it.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|_| Error::ConfigInvalid(format!("cannot read {}", path.display())))?;
        Self::from_toml_at(&text, path)
    }

    /// [`CoreConfig::load`] on text already read from `path`: overlay `text`
    /// on the embedded default and resolve dictionary and `ner.models_dir`
    /// paths relative to `path`. For callers that parse the same text for
    /// more than the engine, so both see one version of the file.
    pub fn from_toml_at(text: &str, path: &Path) -> Result<Self> {
        Self::from_table_at(overlay_on_default(text)?, path)
    }

    /// [`CoreConfig::from_toml_at`] on an already merged table (see
    /// [`overlay_on_default`]), for a caller that also needs the table.
    pub fn from_table_at(table: toml::Table, path: &Path) -> Result<Self> {
        let cfg: CoreConfig = toml::Value::Table(table)
            .try_into()
            .map_err(|_| missing_or_invalid())?;
        let mut cfg = cfg.validated()?;
        let base = path.parent().unwrap_or(Path::new("."));
        let fix = |v: &mut Vec<PathBuf>| {
            for p in v.iter_mut() {
                if p.is_relative() {
                    *p = base.join(&*p);
                }
            }
        };
        fix(&mut cfg.dictionary.persons);
        fix(&mut cfg.dictionary.addresses);
        fix(&mut cfg.dictionary.organizations);
        if let Some(p) = &mut cfg.ner.models_dir {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        }
        Ok(cfg)
    }

    /// Resolve a profile including its `extends` chain.
    ///
    /// Rejects, with [`Error::ConfigInvalid`] naming the key path in the
    /// profile that sets it: a confidence or threshold
    /// (`default_min_confidence`, `escalate_below`,
    /// `entities.<KIND>.min_confidence`) outside `0.0..=1.0`, and a
    /// `verifier.combination_threshold` below 2.
    pub fn resolve_profile(&self, name: &str) -> Result<Profile> {
        let mut chain: Vec<(&str, &ProfileConfig)> = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();
        let mut cur = name;
        loop {
            if !seen.insert(cur) {
                return Err(Error::ConfigInvalid(format!(
                    "profiles.{name}: extends cycle"
                )));
            }
            let pc = self
                .profiles
                .get(cur)
                .ok_or_else(|| Error::ConfigInvalid(format!("profiles.{cur}")))?;
            chain.push((cur, pc));
            match &pc.extends {
                Some(parent) => cur = parent.as_str(),
                None => break,
            }
        }
        chain.reverse(); // root first, child last

        let mut language: Option<Language> = None;
        let mut default = EntityPolicy {
            action: Action::Tokenize,
            min_confidence: 0.5,
        };
        let mut escalate_below = 0.5f32;
        let mut entities: HashMap<String, EntityPolicy> = HashMap::new();
        let mut verifier = VerifierSettings::default();
        let mut ner_sanitizer: Option<String> = None;
        let mut ner_verifier: Option<String> = None;

        for (pname, pc) in chain {
            let unit = |v: f32, key: &str| -> Result<()> {
                if (0.0..=1.0).contains(&v) {
                    Ok(())
                } else {
                    Err(Error::ConfigInvalid(format!("profiles.{pname}.{key}")))
                }
            };
            if let Some(c) = pc.default_min_confidence {
                unit(c, "default_min_confidence")?;
            }
            if let Some(e) = pc.escalate_below {
                unit(e, "escalate_below")?;
            }
            for (k, v) in &pc.entities {
                unit(v.min_confidence, &format!("entities.{k}.min_confidence"))?;
            }
            if let Some(t) = pc.verifier.as_ref().and_then(|v| v.combination_threshold) {
                if t < 2 {
                    return Err(Error::ConfigInvalid(format!(
                        "profiles.{pname}.verifier.combination_threshold"
                    )));
                }
            }
            if let Some(l) = &pc.language {
                language = match l.as_str() {
                    "de" => Some(Language::De),
                    "en" => Some(Language::En),
                    "auto" => None,
                    _ => return Err(Error::ConfigInvalid(format!("profiles.{name}.language"))),
                };
            }
            if let Some(a) = pc.default_action {
                default.action = a;
            }
            if let Some(c) = pc.default_min_confidence {
                default.min_confidence = c;
            }
            if let Some(e) = pc.escalate_below {
                escalate_below = e;
            }
            for (k, v) in &pc.entities {
                entities.insert(k.to_uppercase(), *v);
            }
            if let Some(v) = &pc.verifier {
                if let Some(x) = v.on_uncertain {
                    verifier.on_uncertain = x;
                }
                if let Some(x) = &v.retry_profile {
                    verifier.retry_profile = Some(x.clone());
                }
                if let Some(x) = v.allow_no_ner {
                    verifier.allow_no_ner = x;
                }
                if let Some(x) = v.combination_threshold {
                    verifier.combination_threshold = x;
                }
            }
            if let Some(x) = &pc.ner_sanitizer {
                ner_sanitizer = Some(x.clone());
            }
            if let Some(x) = &pc.ner_verifier {
                ner_verifier = Some(x.clone());
            }
        }

        let check = |key: &str, v: Option<String>| -> Result<Option<String>> {
            match v.as_deref() {
                None | Some("none") => Ok(None),
                Some(s @ ("gliner" | "gliner_verifier" | "token_classifier" | "kiji")) => {
                    if self.ner.section(s).is_some() {
                        Ok(Some(s.to_string()))
                    } else {
                        Err(Error::ConfigInvalid(format!("profiles.{name}.{key}")))
                    }
                }
                Some(_) => Err(Error::ConfigInvalid(format!("profiles.{name}.{key}"))),
            }
        };
        let ner_sanitizer = check("ner_sanitizer", ner_sanitizer)?;
        let ner_verifier = check("ner_verifier", ner_verifier)?;
        // The `is_some()` guard matters: without it, two profiles that both leave NER off
        // (`ner_sanitizer = ner_verifier = None`) would trip this check and be rejected as
        // "using the same NER section", even though neither uses one at all.
        if ner_sanitizer.is_some() && ner_sanitizer == ner_verifier {
            return Err(Error::ConfigInvalid(format!(
                "profiles.{name}.ner_verifier"
            )));
        }

        Ok(Profile {
            name: name.to_string(),
            language,
            entities,
            default,
            escalate_below,
            verifier,
            ner_sanitizer,
            ner_verifier,
        })
    }

    /// True when `name` is a metadata profile (it sets `metadata_of`).
    pub fn is_metadata_profile(&self, name: &str) -> bool {
        self.profiles
            .get(name)
            .is_some_and(|p| p.metadata_of.is_some())
    }

    /// [`CoreConfig::resolve_profile`] for the profile of a dataset or the
    /// daemon's default: a metadata profile is refused, since it is only
    /// ever a variant for listing prose.
    pub fn resolve_dataset_profile(&self, name: &str) -> Result<Profile> {
        if self.is_metadata_profile(name) {
            return Err(Error::ConfigInvalid(format!("profiles.{name}.metadata_of")));
        }
        self.resolve_profile(name)
    }

    /// The profile a `name` dataset's discovery metadata is sanitized
    /// under: the one profile whose `metadata_of` names `name`, or `name`
    /// itself. See [`CoreConfig::check_metadata_profile`] for what the
    /// metadata profile may change.
    pub fn metadata_profile_for(&self, name: &str) -> Result<String> {
        let mut found = self
            .profiles
            .iter()
            .filter(|(_, p)| p.metadata_of.as_deref() == Some(name))
            .map(|(m, _)| m);
        let Some(meta) = found.next() else {
            return Ok(name.to_string());
        };
        if found.next().is_some() {
            return Err(Error::ConfigInvalid(format!(
                "profiles.{name}: two metadata profiles"
            )));
        }
        self.check_metadata_profile(name, meta)?;
        Ok(meta.clone())
    }

    /// A metadata profile never weakens its base `name`: it extends it
    /// directly; takes the same action for the default and every kind;
    /// raises no threshold where the action is `block` or `remove`; keeps
    /// the escalation band of such a kind; keeps the verifier NER,
    /// `on_uncertain`, and `allow_no_ner` off when the base has it off;
    /// raises no combination threshold; and keeps the sanitizer NER or
    /// drops it (the lighter description profile). Thresholds and
    /// escalation of other kinds may change: that is what it is for.
    fn check_metadata_profile(&self, name: &str, meta: &str) -> Result<()> {
        let bad = |key: &str| Error::ConfigInvalid(format!("profiles.{meta}.{key}"));
        let mc = &self.profiles[meta];
        if mc.extends.as_deref() != Some(name) || self.is_metadata_profile(name) {
            return Err(bad("metadata_of"));
        }
        let base = self.resolve_profile(name)?;
        let v = self.resolve_profile(meta)?;
        let strong = |a: Action| matches!(a, Action::Block | Action::Remove);
        let policy = |p: &Profile, kind: &str| p.entities.get(kind).copied().unwrap_or(p.default);
        // Fix round 1, finding 2: a forced language change could weaken
        // language-dependent detectors (a German-tuned detector run as
        // English, say), so the metadata profile keeps the base's language
        // exactly, `auto` included.
        if v.language != base.language {
            return Err(bad("language"));
        }
        if v.default.action != base.default.action {
            return Err(bad("default_action"));
        }
        if strong(base.default.action) && v.default.min_confidence > base.default.min_confidence {
            return Err(bad("default_min_confidence"));
        }
        for kind in base.entities.keys().chain(v.entities.keys()) {
            let (b, x) = (policy(&base, kind), policy(&v, kind));
            if x.action != b.action {
                return Err(bad(&format!("entities.{kind}.action")));
            }
            if strong(b.action) && x.min_confidence > b.min_confidence {
                return Err(bad(&format!("entities.{kind}.min_confidence")));
            }
        }
        // A block/remove kind above the base's floor escalates (so blocks)
        // between the floor and its threshold; a raised floor drops that.
        let banded = std::iter::once(base.default)
            .chain(base.entities.values().copied())
            .any(|p| strong(p.action) && p.min_confidence > base.escalate_below);
        if banded && v.escalate_below > base.escalate_below {
            return Err(bad("escalate_below"));
        }
        if v.ner_verifier != base.ner_verifier {
            return Err(bad("ner_verifier"));
        }
        if v.ner_sanitizer.is_some() && v.ner_sanitizer != base.ner_sanitizer {
            return Err(bad("ner_sanitizer"));
        }
        if v.verifier.on_uncertain != base.verifier.on_uncertain {
            return Err(bad("verifier.on_uncertain"));
        }
        if v.verifier.allow_no_ner && !base.verifier.allow_no_ner {
            return Err(bad("verifier.allow_no_ner"));
        }
        if v.verifier.combination_threshold > base.verifier.combination_threshold {
            return Err(bad("verifier.combination_threshold"));
        }
        // A metadata profile may not retry into some third, weaker profile:
        // only into itself (fails closed the same way it fails) or into
        // whatever the base already retries into.
        let retry_ok = v.verifier.retry_profile.as_deref() == Some(meta)
            || v.verifier.retry_profile == base.verifier.retry_profile;
        if !retry_ok {
            return Err(bad("verifier.retry_profile"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Action;

    #[test]
    fn linking_defaults_and_validation() {
        let c = CoreConfig::from_toml("").unwrap();
        assert!(c.linking.enabled && c.linking.anchors);
        assert!(!c.linking.surnames_across_requests && !c.linking.first_names_across_requests);
        assert_eq!(c.linking.window_minutes, 30);
        let err = CoreConfig::from_toml("[linking]\nwindow_minutes = 0\n").unwrap_err();
        assert!(err.to_string().contains("linking.window_minutes"));
    }

    const TOML: &str = r#"
        [tokens]
        suffix_len = 6
        open = "{{"
        close = "}}"

        [profiles.base]
        default_action = "tokenize"
        default_min_confidence = 0.6
        escalate_below = 0.6
        [profiles.base.entities.PERSON]
        action = "tokenize"
        min_confidence = 0.6
        [profiles.base.entities.CITY]
        action = "preserve"
        min_confidence = 0.0
        [profiles.base.entities.SECRET]
        action = "remove"
        min_confidence = 0.0
        [profiles.base.verifier]
        on_uncertain = "block"
        allow_no_ner = true

        [profiles.strict]
        extends = "base"
        escalate_below = 0.4
        [profiles.strict.entities.CITY]
        action = "tokenize"
        min_confidence = 0.4
        [profiles.strict.verifier]
        retry_profile = "strict"

        [profiles.loop_a]
        extends = "loop_b"
        [profiles.loop_b]
        extends = "loop_a"
    "#;

    #[test]
    fn parses_tokens_and_base_profile() {
        let c = CoreConfig::from_toml(TOML).unwrap();
        assert_eq!(c.tokens.suffix_len, 6);
        assert_eq!(c.tokens.open, "{{");
        let p = c.resolve_profile("base").unwrap();
        assert_eq!(p.entities["CITY"].action, Action::Preserve);
        assert!(p.verifier.allow_no_ner);
        assert_eq!(p.verifier.combination_threshold, 3);
    }

    #[test]
    fn extends_overrides_per_key_and_inherits_the_rest() {
        let c = CoreConfig::from_toml(TOML).unwrap();
        let p = c.resolve_profile("strict").unwrap();
        assert_eq!(p.entities["CITY"].action, Action::Tokenize);
        assert_eq!(p.entities["PERSON"].action, Action::Tokenize);
        assert!((p.escalate_below - 0.4).abs() < 1e-6);
        assert!(p.verifier.allow_no_ner, "inherited");
        assert_eq!(p.verifier.retry_profile.as_deref(), Some("strict"));
    }

    #[test]
    fn cycle_is_an_error_naming_the_profile() {
        let c = CoreConfig::from_toml(TOML).unwrap();
        let e = c.resolve_profile("loop_a").unwrap_err();
        assert!(format!("{e}").contains("profiles.loop_a"));
    }

    #[test]
    fn missing_profile_is_an_error() {
        let c = CoreConfig::from_toml(TOML).unwrap();
        assert!(c.resolve_profile("nope").is_err());
    }

    #[test]
    fn unknown_tables_are_ignored() {
        let c = CoreConfig::from_toml(&format!("[server]\nlisten = \"127.0.0.1:1\"\n{SECRET_X}"))
            .unwrap();
        assert!(c.resolve_profile("x").is_ok());
    }

    #[test]
    fn defaults_when_empty() {
        let t = TokenSettings::default();
        assert_eq!(
            (t.suffix_len, t.open.as_str(), t.close.as_str()),
            (4, "<", ">")
        );
    }

    #[test]
    fn parse_error_omits_offending_value_for_bad_type() {
        let e = CoreConfig::from_toml(
            "[profiles.x]\ndefault_min_confidence = \"supersecretvalue12345\"\n",
        )
        .unwrap_err();
        let msg = format!("{e}");
        assert!(!msg.contains("supersecretvalue12345"));
        assert!(msg.contains("line"));
    }

    #[test]
    fn suffix_len_below_minimum_is_rejected() {
        let e = CoreConfig::from_toml("[tokens]\nsuffix_len = 2\n").unwrap_err();
        assert!(format!("{e}").contains("tokens.suffix_len"));
    }

    #[test]
    fn suffix_len_above_maximum_is_rejected() {
        let e = CoreConfig::from_toml("[tokens]\nsuffix_len = 13\n").unwrap_err();
        assert!(format!("{e}").contains("tokens.suffix_len"));
    }

    #[test]
    fn suffix_len_default_still_parses() {
        let c = CoreConfig::from_toml("").unwrap();
        assert_eq!(c.tokens.suffix_len, 4);
    }

    #[test]
    fn shipped_default_config_resolves() {
        let c = CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap();
        for p in [
            "offline",
            "offline-strict",
            "fast",
            "fast-strict",
            "support-email",
            "strict",
            "thorough",
            "thorough-strict",
        ] {
            c.resolve_profile(p).unwrap_or_else(|e| panic!("{p}: {e}"));
        }
        let se = c.resolve_profile("support-email").unwrap();
        assert_eq!(se.ner_sanitizer.as_deref(), Some("gliner"));
        assert_eq!(se.ner_verifier.as_deref(), Some("token_classifier"));
        assert_eq!(se.verifier.retry_profile.as_deref(), Some("strict"));
        let th = c.resolve_profile("thorough").unwrap();
        assert_eq!(th.ner_sanitizer.as_deref(), Some("gliner"));
        assert_eq!(th.ner_verifier.as_deref(), Some("gliner_verifier"));
        let off = c.resolve_profile("offline").unwrap();
        assert!(off.ner_sanitizer.is_none() && off.ner_verifier.is_none());
        assert!(off.verifier.allow_no_ner);
        assert_eq!(
            c.resolve_profile("strict").unwrap().entities["CITY"].action,
            Action::Tokenize
        );
    }

    const NER_TOML: &str = r#"
        [ner]
        threads = 2
        [ner.gliner]
        model = "gliner-x-small"
        threshold = 0.5
        labels = [ { label = "person", kind = "PERSON" }, { label = "city", kind = "CITY", threshold = 0.7 } ]
        [ner.token_classifier]
        model = "mbert-ner-hrl"
        threshold = 0.5
        labels = [ { label = "PER", kind = "PERSON" } ]

        [profiles.base]
        ner_sanitizer = "gliner"
        ner_verifier = "token_classifier"
        [profiles.base.entities]
        SECRET = { action = "remove", min_confidence = 0.0 }
        [profiles.child]
        extends = "base"
        ner_verifier = "none"
        [profiles.child.verifier]
        allow_no_ner = true
        [profiles.same]
        ner_sanitizer = "gliner"
        ner_verifier = "gliner"
        [profiles.missing]
        ner_sanitizer = "gliner_verifier"
        [profiles.bogus]
        ner_sanitizer = "spacy"
    "#;

    #[test]
    fn ner_sections_parse_and_profiles_inherit() {
        let c = CoreConfig::from_toml(NER_TOML).unwrap();
        assert_eq!(c.ner.threads, 2);
        assert_eq!(
            c.ner.section("gliner").unwrap().labels[1].threshold,
            Some(0.7)
        );
        let base = c.resolve_profile("base").unwrap();
        assert_eq!(base.ner_sanitizer.as_deref(), Some("gliner"));
        assert_eq!(base.ner_verifier.as_deref(), Some("token_classifier"));
        let child = c.resolve_profile("child").unwrap();
        assert_eq!(child.ner_sanitizer.as_deref(), Some("gliner"), "inherited");
        assert_eq!(child.ner_verifier, None, "\"none\" clears it");
    }

    #[test]
    fn ner_profile_values_are_validated_with_key_paths() {
        let c = CoreConfig::from_toml(NER_TOML).unwrap();
        for (p, key) in [
            ("same", "profiles.same.ner_verifier"),
            ("missing", "profiles.missing.ner_sanitizer"),
            ("bogus", "profiles.bogus.ner_sanitizer"),
        ] {
            let e = c.resolve_profile(p).unwrap_err();
            assert!(format!("{e}").contains(key), "{p}: {e}");
        }
    }

    #[test]
    fn ner_sessions_defaults_to_one_and_rejects_zero() {
        let c = CoreConfig::from_toml("").unwrap();
        assert_eq!(c.ner.sessions, 1);
        let c = CoreConfig::from_toml("[ner]\nsessions = 3\n").unwrap();
        assert_eq!(c.ner.sessions, 3);
        let e = CoreConfig::from_toml("[ner]\nsessions = 0\n").unwrap_err();
        assert!(format!("{e}").contains("ner.sessions"), "{e}");
    }

    #[test]
    fn custom_kinds_must_have_the_kind_label_shape() {
        let ok = "[[domain.patterns]]\nregex = \"x\"\nkind = \"meter_point\"\n";
        assert!(CoreConfig::from_toml(ok).is_ok());
        for (toml, key) in [
            (
                "[[domain.patterns]]\nregex = \"x\"\nkind = \"ZAEHLER2\"\n",
                "domain.patterns[0].kind",
            ),
            (
                "[[domain.labels]]\nlabels = [\"Nr\"]\nvalue = \"x\"\nkind = \"Kunden Nr\"\n",
                "domain.labels[0].kind",
            ),
            (
                "[ner.gliner]\nmodel = \"m\"\nthreshold = 0.5\nlabels = [ { label = \"person\", kind = \"PERSON_1\" } ]\n",
                "ner.gliner.labels[0].kind",
            ),
        ] {
            let e = CoreConfig::from_toml(toml).unwrap_err();
            assert!(format!("{e}").contains(key), "{toml}: {e}");
        }
    }

    #[test]
    fn ner_thresholds_are_range_checked() {
        let bad = "[ner.gliner]\nmodel = \"m\"\nthreshold = 1.5\nlabels = [ { label = \"person\", kind = \"PERSON\" } ]\n";
        let e = CoreConfig::from_toml(bad).unwrap_err();
        assert!(format!("{e}").contains("ner.gliner.threshold"), "{e}");
        let bad = "[ner.gliner]\nmodel = \"m\"\nthreshold = 0.5\nlabels = [ { label = \"person\", kind = \"PERSON\", threshold = -0.1 } ]\n";
        let e = CoreConfig::from_toml(bad).unwrap_err();
        assert!(
            format!("{e}").contains("ner.gliner.labels[0].threshold"),
            "{e}"
        );
        let bad = "[ner.gliner]\nmodel = \"m\"\nthreshold = 0.5\nlabels = []\n";
        let e = CoreConfig::from_toml(bad).unwrap_err();
        assert!(format!("{e}").contains("ner.gliner.labels"), "{e}");
    }

    /// Profile `x`'s SECRET entry: every loadable profile removes secrets.
    const SECRET_X: &str =
        "[profiles.x.entities.SECRET]\naction = \"remove\"\nmin_confidence = 0.0\n";

    fn resolve_err(toml: &str, profile: &str) -> String {
        let c = CoreConfig::from_toml(toml).unwrap();
        format!("{}", c.resolve_profile(profile).unwrap_err())
    }

    /// I7: a threshold below 2 makes every sentence "uncertain" (or panics).
    #[test]
    fn combination_threshold_below_two_is_rejected() {
        for t in [0, 1] {
            let msg = resolve_err(
                &format!("[profiles.x.verifier]\ncombination_threshold = {t}\n"),
                "x",
            );
            assert!(
                msg.contains("profiles.x.verifier.combination_threshold"),
                "{msg}"
            );
        }
        let c = CoreConfig::from_toml(&format!(
            "[profiles.x.verifier]\ncombination_threshold = 2\n{SECRET_X}"
        ))
        .unwrap();
        assert!(c.resolve_profile("x").is_ok());
    }

    /// I7: confidences and thresholds must lie in 0.0..=1.0 (NaN included).
    #[test]
    fn out_of_range_confidences_are_rejected_with_key_path() {
        for (toml, key) in [
            (
                "[profiles.x]\ndefault_min_confidence = 1.5\n",
                "profiles.x.default_min_confidence",
            ),
            (
                "[profiles.x]\nescalate_below = -0.1\n",
                "profiles.x.escalate_below",
            ),
            (
                "[profiles.x]\nescalate_below = nan\n",
                "profiles.x.escalate_below",
            ),
            (
                "[profiles.x.entities.PERSON]\naction = \"tokenize\"\nmin_confidence = 2.0\n",
                "profiles.x.entities.PERSON.min_confidence",
            ),
        ] {
            let msg = resolve_err(toml, "x");
            assert!(msg.contains(key), "{toml}: {msg}");
        }
        // the key path names the profile that sets the value
        let msg = resolve_err(
            "[profiles.base]\nescalate_below = 7.0\n[profiles.child]\nextends = \"base\"\n",
            "child",
        );
        assert!(msg.contains("profiles.base.escalate_below"), "{msg}");
        // bounds are inclusive
        let c = CoreConfig::from_toml(&format!(
            "[profiles.x]\ndefault_min_confidence = 1.0\nescalate_below = 0.0\n{SECRET_X}"
        ))
        .unwrap();
        assert!(c.resolve_profile("x").is_ok());
    }

    #[test]
    fn parse_error_omits_offending_value_for_bad_enum_variant() {
        let e = CoreConfig::from_toml(
            "[profiles.x.entities.PERSON]\naction = \"john.doe@example.com\"\nmin_confidence = 0.5\n",
        )
        .unwrap_err();
        let msg = format!("{e}");
        assert!(!msg.contains("john.doe@example.com"));
        assert!(msg.contains("line"));
    }

    /// A profile `p` (GLiNER sanitizer, token-classifier verifier, IBAN
    /// blocked) with `p_entities` added to its entities, followed by `md`.
    fn md_config(p_entities: &str, md: &str) -> Result<CoreConfig> {
        CoreConfig::from_toml(&format!(
            "[ner.gliner]\nmodel = \"g\"\nthreshold = 0.5\nlabels = [{{ label = \"person\", kind = \"PERSON\" }}]\n\
             [ner.gliner_verifier]\nmodel = \"g\"\nthreshold = 0.3\nlabels = [{{ label = \"person\", kind = \"PERSON\" }}]\n\
             [ner.token_classifier]\nmodel = \"t\"\nthreshold = 0.5\nlabels = [{{ label = \"PER\", kind = \"PERSON\" }}]\n\
             [profiles.p]\ndefault_action = \"tokenize\"\nner_sanitizer = \"gliner\"\nner_verifier = \"token_classifier\"\n\
             [profiles.p.entities]\nIBAN = {{ action = \"block\", min_confidence = 0.5 }}\n\
             SECRET = {{ action = \"remove\", min_confidence = 0.0 }}\n{p_entities}\n\
             [profiles.p.verifier]\non_uncertain = \"block\"\ncombination_threshold = 3\n\
             {md}\n"
        ))
    }

    /// Plan 2c, Review Focus 2: a metadata profile is a variant of exactly
    /// one profile and never weakens it.
    #[test]
    fn metadata_profiles_never_weaken_their_base() {
        const MD: &str = "[profiles.p-md]\nextends = \"p\"\nmetadata_of = \"p\"\n";
        // path A shape: no escalation band, PERSON from 0.7
        let ok = md_config(
            "",
            &format!(
                "{MD}escalate_below = 1.0\n[profiles.p-md.entities]\nPERSON = {{ action = \"tokenize\", min_confidence = 0.7 }}\n\
                 [profiles.p-md.verifier]\nretry_profile = \"p-md\"\n"
            ),
        )
        .unwrap();
        assert_eq!(ok.metadata_profile_for("p").unwrap(), "p-md");
        assert_eq!(
            ok.metadata_profile_for("p-md").unwrap(),
            "p-md",
            "none: itself"
        );
        assert!(ok.is_metadata_profile("p-md") && !ok.is_metadata_profile("p"));
        ok.resolve_dataset_profile("p").unwrap();
        let e = ok.resolve_dataset_profile("p-md").unwrap_err();
        assert!(e.to_string().contains("profiles.p-md.metadata_of"), "{e}");
        // path B shape: no sanitizer NER
        md_config(
            "",
            &format!("{MD}ner_sanitizer = \"none\"\nescalate_below = 1.0\n"),
        )
        .unwrap();
        for (p_entities, md, key) in [
            ("", format!("{MD}language = \"en\"\n"), "profiles.p-md.language"),
            ("", format!("{MD}[profiles.p-md.entities]\nIBAN = {{ action = \"tokenize\", min_confidence = 0.5 }}\n"), "profiles.p-md.entities.IBAN.action"),
            ("", format!("{MD}default_action = \"preserve\"\n"), "profiles.p-md.default_action"),
            ("", format!("{MD}[profiles.p-md.entities]\nIBAN = {{ action = \"block\", min_confidence = 0.9 }}\n"), "profiles.p-md.entities.IBAN.min_confidence"),
            ("TAX_ID = { action = \"remove\", min_confidence = 0.8 }", format!("{MD}escalate_below = 1.0\n"), "profiles.p-md.escalate_below"),
            ("", format!("{MD}ner_verifier = \"gliner_verifier\"\n"), "profiles.p-md.ner_verifier"),
            ("", format!("{MD}ner_sanitizer = \"gliner_verifier\"\n"), "profiles.p-md.ner_sanitizer"),
            ("", format!("{MD}[profiles.p-md.verifier]\non_uncertain = \"pass\"\n"), "profiles.p-md.verifier.on_uncertain"),
            ("", format!("{MD}[profiles.p-md.verifier]\nallow_no_ner = true\n"), "profiles.p-md.verifier.allow_no_ner"),
            ("", format!("{MD}[profiles.p-md.verifier]\ncombination_threshold = 5\n"), "profiles.p-md.verifier.combination_threshold"),
            ("", format!("{MD}[profiles.w]\nextends = \"p\"\n[profiles.p-md.verifier]\nretry_profile = \"w\"\n"), "profiles.p-md.verifier.retry_profile"),
            ("", "[profiles.q]\ndefault_action = \"tokenize\"\n[profiles.p-md]\nextends = \"q\"\nmetadata_of = \"p\"\n".to_string(), "profiles.p-md.metadata_of"),
            ("", "[profiles.p-md]\nmetadata_of = \"nope\"\n".to_string(), "profiles.p-md.metadata_of"),
            ("", format!("{MD}[profiles.p-md2]\nextends = \"p\"\nmetadata_of = \"p\"\n"), "two metadata profiles"),
        ] {
            let e = md_config(p_entities, &md).unwrap_err();
            assert!(e.to_string().contains(key), "{key}: {e}");
        }
    }

    /// Plan 2c Task 3: the shipped metadata profiles cover exactly the
    /// `support-email` family (`support-email`, `strict`); the `thorough`
    /// family and the `fast`/`offline` families have none and map to
    /// themselves.
    #[test]
    fn shipped_metadata_profiles_cover_the_support_email_family() {
        let cfg = CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap();
        for p in ["support-email", "strict"] {
            assert_eq!(
                cfg.metadata_profile_for(p).unwrap(),
                format!("{p}-metadata")
            );
        }
        for p in [
            "offline",
            "offline-strict",
            "fast",
            "fast-strict",
            "thorough",
            "thorough-strict",
        ] {
            assert_eq!(cfg.metadata_profile_for(p).unwrap(), p);
        }
    }

    /// The overlay is read through a file path so relative-path handling and
    /// the whole `from_toml_at` route run.
    fn overlaid(user: &str) -> Result<CoreConfig> {
        CoreConfig::from_toml_at(user, Path::new("/etc/inumaki/inumaki.toml"))
    }

    fn shipped() -> CoreConfig {
        CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap()
    }

    /// Critical (B2): a file that names only daemon tables keeps every
    /// shipped profile, so `daemon.default_profile` stays valid.
    #[test]
    fn a_partial_file_keeps_the_shipped_profiles() {
        let want: HashSet<String> = shipped().profiles.keys().cloned().collect();
        assert!(!want.is_empty());
        for user in [
            "[mirror]\nworkers = 2\n",
            "[proxy]\nlisten = \"127.0.0.1:1\"\n",
        ] {
            let c = overlaid(user).unwrap();
            let got: HashSet<String> = c.profiles.keys().cloned().collect();
            assert_eq!(got, want, "{user}");
            c.resolve_dataset_profile("support-email").unwrap();
            assert_eq!(c.tokens.suffix_len, 4, "{user}");
        }
    }

    /// Critical (B2, ruling L5-08): tables merge key by key everywhere,
    /// profiles included.
    #[test]
    fn the_overlay_merges_tables_key_wise() {
        let c = overlaid(
            "[tokens]\nsuffix_len = 6\n\
             [ner.gliner]\nthreshold = 0.3\n\
             [ner.gliner_verifier]\nlabels = [{ label = \"person\", kind = \"PERSON\" }]\n\
             [profiles.strict]\ndefault_min_confidence = 0.9\n",
        )
        .unwrap();
        let base = shipped();
        // One key changed, the rest of the table kept.
        assert_eq!(c.tokens.suffix_len, 6);
        assert_eq!(c.tokens.open, "<");
        let g = c.ner.gliner.as_ref().unwrap();
        assert!((g.threshold - 0.3).abs() < 1e-6);
        assert_eq!(g.model, "gliner-x-small");
        assert_eq!(
            g.labels.len(),
            base.ner.gliner.as_ref().unwrap().labels.len()
        );
        // A list of tables extends the shipped one (see the next test).
        assert!(c.ner.gliner_verifier.as_ref().unwrap().labels.len() > 1);
        // A profile merges too: its other keys stay.
        let strict = &c.profiles["strict"];
        assert_eq!(strict.default_min_confidence, Some(0.9));
        assert_eq!(strict.extends, base.profiles["strict"].extends);
        assert_eq!(
            strict.entities.len(),
            base.profiles["strict"].entities.len()
        );
    }

    /// Critical (ruling L5-08): changing one setting of a shipped profile
    /// keeps its entity rules and verifier settings, so the profiles that
    /// extend it still remove secrets.
    #[test]
    fn a_one_key_profile_edit_keeps_the_rules_the_extending_profiles_rely_on() {
        let base = shipped();
        let c = overlaid("[profiles.offline]\nescalate_below = 0.4\n").unwrap();
        let off = c.resolve_profile("offline").unwrap();
        assert!((off.escalate_below - 0.4).abs() < 1e-6);
        let before = base.resolve_profile("offline").unwrap();
        assert_eq!(off.verifier.retry_profile, before.verifier.retry_profile);
        assert_eq!(off.verifier.allow_no_ner, before.verifier.allow_no_ner);
        for name in ["offline", "support-email", "strict"] {
            let p = c.resolve_profile(name).unwrap();
            assert_eq!(
                p.entities.get("SECRET").map(|e| e.action),
                Some(Action::Remove),
                "{name}"
            );
        }
        // An entity entry merges key by key as well.
        let c =
            overlaid("[profiles.offline.entities]\nPERSON = { action = \"tokenize\" }\n").unwrap();
        let p = c.resolve_profile("offline").unwrap();
        assert_eq!(
            p.entities["PERSON"].min_confidence,
            before.entities["PERSON"].min_confidence
        );
    }

    /// Critical: an error the merge cannot fix keeps the line of the key
    /// that caused it.
    #[test]
    fn a_missing_key_in_a_new_entry_is_reported_at_the_files_line() {
        let e = overlaid(
            "[mirror]\nworkers = 2\n[profiles.mine.entities]\nPERSON = { action = \"tokenize\" }\n",
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("line 4"), "{e}");
    }

    /// Critical (L5-09, L5-09b): an array of tables the shipped default fills
    /// is extended, not replaced; arrays the default has empty are replaced;
    /// a restated NER label replaces the shipped one.
    #[test]
    fn arrays_of_tables_extend_the_shipped_lists() {
        let base = shipped();
        let c = overlaid(
            "[[domain.labels]]\nlabels = [\"Ticket:\"]\nkind = \"TICKET_ID\"\nvalue = \"T-[0-9]+\"\n",
        )
        .unwrap();
        assert_eq!(c.domain.labels.len(), base.domain.labels.len() + 1);
        for (a, b) in base.domain.labels.iter().zip(&c.domain.labels) {
            assert_eq!(a.kind, b.kind);
        }
        let c = overlaid("[ner.gliner]\nlabels = [{ label = \"ticket\", kind = \"TICKET_ID\" }]\n")
            .unwrap();
        let labels = &c.ner.gliner.as_ref().unwrap().labels;
        let shipped_labels = &base.ner.gliner.as_ref().unwrap().labels;
        assert_eq!(labels.len(), shipped_labels.len() + 1);
        assert!(labels.iter().any(|l| l.kind == "PERSON"));
        // An exact duplicate of a shipped entry is not doubled.
        let c = overlaid("[ner.gliner]\nlabels = [{ label = \"person\", kind = \"PERSON\" }]\n")
            .unwrap();
        assert_eq!(
            c.ner.gliner.as_ref().unwrap().labels.len(),
            shipped_labels.len()
        );
        // A list the default has empty is replaced.
        let c = overlaid("[dictionary]\npersons = [\"a.txt\", \"b.txt\"]\n").unwrap();
        assert_eq!(c.dictionary.persons.len(), 2);
        let c = overlaid("[dictionary]\npersons = [\"c.txt\"]\n").unwrap();
        assert_eq!(c.dictionary.persons.len(), 1);
        // A restated shipped label replaces it in place; the length stays.
        let c = overlaid(
            "[ner.gliner]\nlabels = [{ label = \"person\", kind = \"PERSON\", threshold = 0.99 }]\n",
        )
        .unwrap();
        let labels = &c.ner.gliner.as_ref().unwrap().labels;
        assert_eq!(labels.len(), shipped_labels.len());
        let at = shipped_labels
            .iter()
            .position(|l| l.label == "person")
            .unwrap();
        assert_eq!(labels[at].label, "person");
        assert_eq!(labels[at].threshold, Some(0.99));
        // The same label twice inside the file is still refused by key path.
        let e = overlaid(
            "[ner.gliner]\nlabels = [{ label = \"ticket\", kind = \"TICKET_ID\" }, { label = \"ticket\", kind = \"OTHER_ID\" }]\n",
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("ner.gliner.labels[") && e.contains("].label"),
            "{e}"
        );
        assert!(!e.contains("OTHER_ID"), "{e}");
    }

    /// Critical (L5-09b): a whole copy of the shipped file with one shipped
    /// NER label's threshold raised loads, with the new value and the same
    /// number of labels.
    #[test]
    fn an_edited_whole_copy_of_the_shipped_file_loads() {
        let text = include_str!("../../../configs/default.toml");
        let old = "{ label = \"organization\", kind = \"ORGANIZATION\", threshold = 0.6 }";
        assert!(text.contains(old));
        let edited = text.replace(
            old,
            "{ label = \"organization\", kind = \"ORGANIZATION\", threshold = 0.8 }",
        );
        let c = overlaid(&edited).unwrap();
        let labels = &c.ner.gliner.as_ref().unwrap().labels;
        let base = shipped();
        assert_eq!(labels.len(), base.ner.gliner.as_ref().unwrap().labels.len());
        let org = labels.iter().find(|l| l.label == "organization").unwrap();
        assert_eq!(org.threshold, Some(0.8));
    }

    /// Critical (N1): a user entity key in another case overrides the
    /// shipped kind instead of sitting next to it, and keys that collide
    /// after upper-casing are refused by key path, never by value.
    #[test]
    fn entity_keys_fold_to_upper_case_and_colliding_kinds_are_refused() {
        let c =
            overlaid("[profiles.offline.entities]\nperson = { min_confidence = 0.9 }\n").unwrap();
        assert!(!c.profiles["offline"].entities.contains_key("person"));
        let p = c.resolve_profile("offline").unwrap();
        assert!((p.entities["PERSON"].min_confidence - 0.9).abs() < 1e-6);
        assert_eq!(p.entities["PERSON"].action, Action::Tokenize);
        let text = "[profiles.x.entities]\nperson = { action = \"block\", min_confidence = 0.1 }\nPERSON = { action = \"tokenize\", min_confidence = 0.1 }\n";
        let e = overlaid(text).unwrap_err().to_string();
        assert!(e.contains("profiles.x.entities.PERSON"), "{e}");
        let e = CoreConfig::from_toml(text).unwrap_err().to_string();
        assert!(e.contains("profiles.x.entities.PERSON"), "{e}");
    }

    /// A failure after the merge that is not a missing key must not point at
    /// the line of an unrelated partial section.
    #[test]
    fn a_later_wrong_type_does_not_borrow_a_partial_sections_line() {
        let e = overlaid("[ner.gliner]\nthreshold = 0.3\n[tokens]\nsuffix_len = \"qwxzvk\"\n")
            .unwrap_err()
            .to_string();
        assert!(!e.contains("line 1") && !e.contains("line 2"), "{e}");
        assert!(!e.contains("qwxzvk"), "{e}");
    }

    /// The shipped default has no relative path, so rebasing paths against
    /// the user file's directory can only move the user's own paths.
    #[test]
    fn the_shipped_default_has_no_relative_paths() {
        let c = shipped();
        for list in [
            &c.dictionary.persons,
            &c.dictionary.addresses,
            &c.dictionary.organizations,
        ] {
            assert!(list.iter().all(|p| p.is_absolute()));
        }
        assert!(c.ner.models_dir.as_ref().is_none_or(|p| p.is_absolute()));
    }

    /// Critical (B2): a wrong type in the file is reported at the file's own
    /// line and never echoes the value; a missing key a section only partly
    /// names is not an error.
    #[test]
    fn overlay_errors_name_the_files_own_line_and_no_value() {
        let e = overlaid("[mirror]\nworkers = 2\n[tokens]\nsuffix_len = \"qwxzvk\"\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains("line 4"), "{e}");
        assert!(!e.contains("qwxzvk"), "{e}");
        let e = overlaid("[tokens]\nsuffix_len = 2\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains("tokens.suffix_len"), "{e}");
        let e = overlaid("[tokens\nx").unwrap_err().to_string();
        assert!(e.contains("line 1"), "{e}");
        overlaid("[ner.gliner]\nthreshold = 0.3\n").unwrap();
    }

    /// Critical (B2): the shipped text, loaded as a file, overlays to
    /// itself, and `from_toml` stays exact (no overlay).
    #[test]
    fn a_whole_config_overlays_to_itself_and_from_toml_stays_exact() {
        let text = include_str!("../../../configs/default.toml");
        let own: toml::Table = toml::from_str(text).unwrap();
        assert_eq!(overlay_on_default(text).unwrap(), own);
        // A whole config that leaves a shipped profile out is not completed
        // by `from_toml`.
        let whole = "[profiles.only]\ndefault_action = \"tokenize\"\n\
                     [profiles.only.entities]\nSECRET = { action = \"remove\", min_confidence = 0.0 }\n";
        let c = CoreConfig::from_toml(whole).unwrap();
        assert_eq!(c.profiles.len(), 1);
        assert!(overlaid(whole).unwrap().profiles.len() > 1);
    }

    /// The kind a profile applies to a SECRET span.
    fn secret_action(c: &CoreConfig, name: &str) -> Action {
        let k = crate::span::EntityKind::Secret(crate::span::SecretKind::Generic);
        c.resolve_profile(name).unwrap().policy_for(&k).action
    }

    /// Critical (L90, L5-11): a user file cannot make a shipped profile
    /// tokenize secrets, even by stating the rule explicitly.
    #[test]
    fn secret_tokenize_in_a_shipped_profile_is_refused() {
        let e = overlaid(
            "[profiles.offline.entities]\nSECRET = { action = \"tokenize\", min_confidence = 0.0 }\n",
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("profiles.offline.entities.SECRET"), "{e}");
        assert!(!e.contains("tokenize"), "{e}");
    }

    /// Critical (L90, L91): a lower-case `secret` key is the same kind and is
    /// refused the same way.
    #[test]
    fn lower_case_secret_tokenize_is_refused() {
        let e = overlaid("[profiles.offline.entities]\nsecret = { action = \"tokenize\" }\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains("profiles.offline.entities.SECRET"), "{e}");
        let e = CoreConfig::from_toml(
            "[profiles.p]\n[profiles.p.entities]\nsecret = { action = \"preserve\", min_confidence = 0.0 }\n",
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("profiles.p.entities.SECRET"), "{e}");
    }

    /// Critical (L90, L5-11): a new profile may not tokenize secrets, nor
    /// leave SECRET to a `tokenize` default; `remove` and `block` load.
    #[test]
    fn a_new_profile_that_does_not_remove_secret_is_refused() {
        for (text, path) in [
            (
                "[profiles.mine.entities]\nSECRET = { action = \"tokenize\", min_confidence = 0.0 }\n",
                "profiles.mine.entities.SECRET",
            ),
            (
                "[profiles.mine]\ndefault_action = \"tokenize\"\n",
                "profiles.mine.entities.SECRET",
            ),
            (
                "[profiles.mine]\nextends = \"offline\"\ndefault_action = \"preserve\"\n\
                 [profiles.kid]\nextends = \"mine\"\n\
                 [profiles.kid.entities]\nSECRET = { action = \"preserve\", min_confidence = 0.0 }\n",
                "profiles.kid.entities.SECRET",
            ),
        ] {
            let e = overlaid(text).unwrap_err().to_string();
            assert!(e.contains(path), "{text}: {e}");
            if !text.contains("offline") {
                let e = CoreConfig::from_toml(text).unwrap_err().to_string();
                assert!(e.contains(path), "{text}: {e}");
            }
        }
        for action in ["remove", "block"] {
            let c = CoreConfig::from_toml(&format!(
                "[profiles.mine.entities]\nSECRET = {{ action = \"{action}\", min_confidence = 0.0 }}\n"
            ))
            .unwrap();
            assert!(matches!(
                secret_action(&c, "mine"),
                Action::Remove | Action::Block
            ));
        }
        let c = CoreConfig::from_toml("[profiles.mine]\ndefault_action = \"block\"\n").unwrap();
        assert_eq!(secret_action(&c, "mine"), Action::Block);
    }

    /// Critical (L5-12): a SECRET threshold above the scanner's confidence
    /// would let a detected secret escalate or drop, so it is refused; up to
    /// that confidence it loads.
    #[test]
    fn secret_min_confidence_above_the_scanner_confidence_is_refused() {
        for key in ["SECRET", "secret"] {
            let text = format!(
                "[profiles.mine]\nextends = \"offline\"\n\
                 [profiles.mine.entities]\n{key} = {{ action = \"remove\", min_confidence = 1.0 }}\n"
            );
            let e = overlaid(&text).unwrap_err().to_string();
            assert!(e.contains("profiles.mine.entities.SECRET"), "{key}: {e}");
            assert!(!e.contains("1.0"), "{e}");
            // On the shipped `offline` it is refused as well; the metadata
            // invariant (checked first) names the escalation band it drops.
            let text = format!(
                "[profiles.offline.entities]\n{key} = {{ action = \"remove\", min_confidence = 1.0 }}\n"
            );
            assert!(overlaid(&text).is_err(), "{key}");
        }
        let e = CoreConfig::from_toml(
            "[profiles.p]\ndefault_action = \"block\"\ndefault_min_confidence = 0.99\n",
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("profiles.p.entities.SECRET"), "{e}");
        for c in ["0.95", "0.0"] {
            let cfg = overlaid(&format!(
                "[profiles.mine]\nextends = \"offline\"\n\
                 [profiles.mine.entities]\nSECRET = {{ action = \"remove\", min_confidence = {c} }}\n"
            ))
            .unwrap();
            assert_eq!(secret_action(&cfg, "mine"), Action::Remove, "{c}");
        }
    }

    /// Critical (L90): a new profile extending `offline` with no SECRET
    /// entry inherits the removal and loads.
    #[test]
    fn a_new_profile_extending_offline_inherits_secret_removal() {
        let c = overlaid("[profiles.mine]\nextends = \"offline\"\ndefault_action = \"preserve\"\n")
            .unwrap();
        assert!(!c.profiles["mine"].entities.contains_key("SECRET"));
        assert_eq!(secret_action(&c, "mine"), Action::Remove);
    }

    /// Critical (L90): every shipped profile removes secrets, through both
    /// load routes.
    #[test]
    fn the_shipped_default_removes_secret_in_every_profile() {
        let text = include_str!("../../../configs/default.toml");
        for c in [shipped(), overlaid(text).unwrap(), overlaid("").unwrap()] {
            assert!(!c.profiles.is_empty());
            for name in c.profiles.keys() {
                assert_eq!(secret_action(&c, name), Action::Remove, "{name}");
            }
        }
    }

    /// Critical (L90, reviewer repro): a one-key edit of `offline` still
    /// loads and the profiles extending it keep SECRET removal.
    #[test]
    fn a_one_key_offline_edit_loads_and_keeps_secret_removal() {
        let c = overlaid("[profiles.offline]\nescalate_below = 0.4\n").unwrap();
        for name in ["offline", "support-email", "strict"] {
            assert_eq!(secret_action(&c, name), Action::Remove, "{name}");
        }
    }
}
