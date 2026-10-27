//! Test doubles: a deterministic engine that tokenizes a fixed list of
//! synthetic originals (and learns new ones on request), and an in-memory
//! manifest. Tokens are `<KIND_nnnnnn>`, one per original, stable.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;

use inumaki_core::span::EntityKind;
use inumaki_mirror::{
    Activity, Block, DatasetState, EngineError, ManifestStore, MirrorEngine, Outcome, Side,
};

pub struct FakeEngine {
    /// (original, kind) the engine detects; longest first.
    pub known: Mutex<Vec<(String, EntityKind)>>,
    /// Original to token, per epoch.
    pub tokens: Mutex<HashMap<String, String>>,
    pub epoch: Mutex<i64>,
    pub generation: Mutex<u64>,
    pub fingerprint: Mutex<[u8; 32]>,
    pub uncertain_marker: Mutex<Option<String>>,
    pub records: Mutex<Vec<Activity>>,
    pub fail: Mutex<Option<EngineError>>,
    /// Originals `known_in_clear` reports but `sanitize` never replaces (a
    /// missed name).
    pub clear_only: Mutex<Vec<String>>,
    /// Originals taught by `learn` (the vault's per-epoch known entities).
    pub learned: Mutex<Vec<(String, EntityKind)>>,
    /// What `rotate` took out of `known`; `carry_known` puts it back.
    pub previous: Mutex<Vec<(String, EntityKind)>>,
    /// `carry_known` calls.
    pub carried: Mutex<u32>,
    /// Largest block `sanitize` or `sanitize_names` received, in bytes.
    pub largest_block: Mutex<usize>,
    /// Largest text `known_in_clear` received, in bytes.
    pub largest_clear_text: Mutex<usize>,
}

impl FakeEngine {
    pub fn new(known: &[(&str, EntityKind)]) -> Self {
        let mut k: Vec<(String, EntityKind)> = known
            .iter()
            .map(|(s, k)| (s.to_string(), k.clone()))
            .collect();
        k.sort_by_key(|(s, _)| std::cmp::Reverse(s.len()));
        FakeEngine {
            known: Mutex::new(k),
            tokens: Mutex::new(HashMap::new()),
            epoch: Mutex::new(1),
            generation: Mutex::new(0),
            fingerprint: Mutex::new([0; 32]),
            uncertain_marker: Mutex::new(None),
            records: Mutex::new(Vec::new()),
            fail: Mutex::new(None),
            clear_only: Mutex::new(Vec::new()),
            learned: Mutex::new(Vec::new()),
            previous: Mutex::new(Vec::new()),
            carried: Mutex::new(0),
            largest_block: Mutex::new(0),
            largest_clear_text: Mutex::new(0),
        }
    }

    /// `known_in_clear` sees `original`; `sanitize` does not replace it.
    pub fn learn_clear_only(&self, original: &str) {
        self.clear_only.lock().unwrap().push(original.to_string());
    }

    /// Start detecting `original` (as if another front door taught it).
    pub fn learn(&self, original: &str, kind: EntityKind) {
        self.learned
            .lock()
            .unwrap()
            .push((original.to_string(), kind.clone()));
        let mut k = self.known.lock().unwrap();
        k.push((original.to_string(), kind));
        k.sort_by_key(|(s, _)| std::cmp::Reverse(s.len()));
        *self.generation.lock().unwrap() += 1;
    }

    /// A new epoch: fresh tokens, and the learned originals leave the
    /// detector (they were known per epoch) until `carry_known`.
    pub fn rotate(&self) {
        *self.epoch.lock().unwrap() += 1;
        self.tokens.lock().unwrap().clear();
        let learned = std::mem::take(&mut *self.learned.lock().unwrap());
        self.known.lock().unwrap().retain(|x| !learned.contains(x));
        *self.previous.lock().unwrap() = learned;
    }

    fn token(&self, original: &str, kind: &EntityKind) -> String {
        let epoch = *self.epoch.lock().unwrap();
        let mut t = self.tokens.lock().unwrap();
        let n = t.len();
        t.entry(original.to_string())
            .or_insert_with(|| format!("<{}_{:04}{:02}>", kind.label(), n, epoch % 100))
            .clone()
    }

    fn replace(&self, text: &str) -> (String, Vec<EntityKind>) {
        let known = self.known.lock().unwrap().clone();
        let mut out = text.to_string();
        let mut kinds = Vec::new();
        for (orig, kind) in &known {
            for variant in [orig.clone(), orig.replace(' ', "_")] {
                if out.contains(&variant) {
                    let tok = self.token(orig, kind);
                    out = out.replace(&variant, &tok);
                    if !kinds.contains(kind) {
                        kinds.push(kind.clone());
                    }
                }
            }
        }
        (out, kinds)
    }
}

impl MirrorEngine for FakeEngine {
    fn sanitize(&self, _d: &str, blocks: Vec<String>) -> Result<Vec<Block>, EngineError> {
        if let Some(e) = self.fail.lock().unwrap().clone() {
            return Err(e);
        }
        {
            let mut largest = self.largest_block.lock().unwrap();
            *largest = blocks.iter().map(String::len).fold(*largest, usize::max);
        }
        let marker = self.uncertain_marker.lock().unwrap().clone();
        Ok(blocks
            .into_iter()
            .map(|b| {
                if marker.as_deref().is_some_and(|m| b.contains(m)) {
                    return Block {
                        outcome: Outcome::Uncertain,
                        text: String::new(),
                        kinds: vec![],
                    };
                }
                let (text, kinds) = self.replace(&b);
                Block {
                    outcome: Outcome::Pass,
                    text,
                    kinds,
                }
            })
            .collect())
    }

    fn sanitize_names(&self, d: &str, stems: Vec<String>) -> Result<Vec<Block>, EngineError> {
        self.sanitize(d, stems)
    }

    fn rehydrate_strict(&self, _d: &str, blocks: Vec<String>) -> Result<Vec<String>, EngineError> {
        let t = self.tokens.lock().unwrap().clone();
        let mut unknown = 0;
        let mut removed = 0;
        let out: Vec<String> = blocks
            .into_iter()
            .map(|b| {
                let mut s = b.clone();
                for (orig, tok) in &t {
                    s = s.replace(tok.as_str(), orig);
                }
                unknown += s.matches("<PERSON_").count()
                    + s.matches("<IBAN_").count()
                    + s.matches("<ORGANIZATION_").count();
                removed += s.matches("_REMOVED>").count();
                s
            })
            .collect();
        if unknown + removed > 0 {
            return Err(EngineError::Unresolved { unknown, removed });
        }
        Ok(out)
    }

    fn known_in_clear(
        &self,
        _d: &str,
        texts: &[String],
    ) -> Result<Vec<Option<EntityKind>>, EngineError> {
        {
            let mut largest = self.largest_clear_text.lock().unwrap();
            *largest = texts.iter().map(String::len).fold(*largest, usize::max);
        }
        let mut known = self.known.lock().unwrap().clone();
        known.extend(
            self.clear_only
                .lock()
                .unwrap()
                .iter()
                .map(|s| (s.clone(), EntityKind::Person)),
        );
        Ok(texts
            .iter()
            .map(|t| {
                let spaced: String = t
                    .chars()
                    .map(|c| {
                        if matches!(c, '_' | '-' | '.' | '+') {
                            ' '
                        } else {
                            c
                        }
                    })
                    .collect();
                known
                    .iter()
                    .find(|(o, _)| t.contains(o.as_str()) || spaced.contains(o.as_str()))
                    .map(|(_, k)| k.clone())
            })
            .collect())
    }

    fn scan_clear(&self, d: &str, texts: &[String]) -> Result<Vec<(String, u32)>, EngineError> {
        Ok(self
            .known_in_clear(d, texts)?
            .into_iter()
            .flatten()
            .map(|k| (k.label().to_string(), 1))
            .collect())
    }

    fn state(&self, _d: &str) -> Result<DatasetState, EngineError> {
        Ok(DatasetState {
            epoch_id: *self.epoch.lock().unwrap(),
            entries_generation: *self.generation.lock().unwrap(),
            fingerprint: *self.fingerprint.lock().unwrap(),
        })
    }

    fn carry_known(&self, _d: &str) -> Result<u64, EngineError> {
        *self.carried.lock().unwrap() += 1;
        let previous = std::mem::take(&mut *self.previous.lock().unwrap());
        let n = previous.len() as u64;
        for (o, k) in previous {
            self.learn(&o, k);
        }
        Ok(n)
    }

    fn record(&self, a: Activity) {
        self.records.lock().unwrap().push(a);
    }
}

/// (dataset, side, relative path) to sealed record.
type Rows = HashMap<(String, Side, Vec<u8>), Vec<u8>>;

#[derive(Default)]
pub struct MemManifest {
    pub rows: Mutex<Rows>,
    /// Persisted root ids, per dataset.
    pub root_ids: Mutex<HashMap<String, (u64, u64)>>,
    /// `put_root_id` fails (a vault error).
    pub fail_root_id: Mutex<bool>,
    /// `put` fails (a vault error).
    pub fail_put: Mutex<bool>,
}

impl ManifestStore for MemManifest {
    fn put(&self, d: &str, s: Side, rel: &[u8], rec: &[u8]) -> Result<(), EngineError> {
        if *self.fail_put.lock().unwrap() {
            return Err(EngineError::VaultUnavailable);
        }
        self.rows
            .lock()
            .unwrap()
            .insert((d.into(), s, rel.to_vec()), rec.to_vec());
        Ok(())
    }

    fn delete(&self, d: &str, s: Side, rel: &[u8]) -> Result<(), EngineError> {
        self.rows
            .lock()
            .unwrap()
            .remove(&(d.into(), s, rel.to_vec()));
        Ok(())
    }

    fn list(&self, d: &str, s: Side) -> Result<Vec<Vec<u8>>, EngineError> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|((dd, ss, _), _)| dd == d && *ss == s)
            .map(|(_, v)| v.clone())
            .collect())
    }

    fn clear(&self, d: &str) -> Result<(), EngineError> {
        self.rows.lock().unwrap().retain(|(dd, _, _), _| dd != d);
        Ok(())
    }

    fn put_root_id(&self, d: &str, root_id: (u64, u64)) -> Result<(), EngineError> {
        if *self.fail_root_id.lock().unwrap() {
            return Err(EngineError::VaultUnavailable);
        }
        self.root_ids.lock().unwrap().insert(d.into(), root_id);
        Ok(())
    }

    fn mac(&self, domain: &str, data: &[u8]) -> [u8; 32] {
        // Deterministic stand-in (tests only): FNV-1a spread over 32 bytes.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in domain.as_bytes().iter().chain([0u8].iter()).chain(data) {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        let mut out = [0u8; 32];
        for (i, c) in out.chunks_mut(8).enumerate() {
            c.copy_from_slice(&(h.rotate_left(i as u32 * 13)).to_le_bytes());
        }
        out
    }
}
