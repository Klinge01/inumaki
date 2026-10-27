//! Activity records (M4 spec §16.4). A record says what happened at a
//! front door (verdict, checks, kinds with counts, byte count) and cannot
//! say anything else: every field is an enum, an integer, a bool, or a
//! newtype that accepts one fixed format, checked again when a row is
//! loaded (an unknown key fails the load too). Rows are chained with
//! SHA-256 for cheap tamper evidence.
//!
//! What bounds each field:
//! - ids and digests are lower-case hex of a fixed length;
//! - [`CheckLabel`] is a closed enum: the verifier's [`CheckId`]s plus
//!   the gateway's `ClearValue`; any other string fails to load;
//! - [`KindLabel`] is bounded by format and by provenance, not by an
//!   alphabet that excludes names. The format is `[A-Z][A-Z_]{0,31}`
//!   ([`inumaki_core::span::valid_kind_label`]: no digits, so no account
//!   or record number fits). A label is built only from an
//!   [`EntityKind`] ([`KindLabel::of`]), and every kind comes from the
//!   engine or from operator configuration (domain recognizers, NER label
//!   maps, contracts, redaction files), which is validated to the same
//!   format and trusted like a contract. An upper-case name such as
//!   `ZYXWURIA_QUOLNATH` has the format; nothing an agent or an upstream
//!   sends can make it a kind.

use std::fmt;

use inumaki_core::span::{EntityKind, valid_kind_label};
use inumaki_core::verify::CheckId;
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};

use crate::crypto::Indexer;
use crate::error::VaultError;
use crate::vault::Vault;

macro_rules! fixed_hex {
    ($name:ident, $doc:literal, $len:literal) => {
        #[doc = $doc]
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// The validated text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = &'static str;
            fn try_from(s: String) -> Result<Self, Self::Error> {
                if lower_hex(&s, $len) {
                    Ok($name(s))
                } else {
                    Err(concat!("invalid ", stringify!($name)))
                }
            }
        }

        impl From<$name> for String {
            fn from(v: $name) -> String {
                v.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }
    };
}

fn lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fixed_hex!(
    RecordId,
    "Random record id: 32 lowercase hex characters.",
    32
);
fixed_hex!(
    OpaqueId,
    "HMAC label of a dataset or upstream: 16 lowercase hex characters.",
    16
);
fixed_hex!(
    Digest,
    "Keyed digest of released bytes: 64 lowercase hex characters.",
    64
);

/// Entity kind label, `[A-Z][A-Z_]{0,31}`. Built only from an
/// [`EntityKind`]; a stored label is checked again on load. There is no
/// constructor from a string (see the module docs for what bounds it).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct KindLabel(String);

impl KindLabel {
    /// The label of an entity kind (`PERSON`, `CUSTOMER_ID`); `CUSTOM` for
    /// a custom kind whose label does not have the format (configuration
    /// validation refuses those, so this is a backstop).
    pub fn of(kind: &EntityKind) -> KindLabel {
        let l = kind.label();
        KindLabel(if valid_kind_label(l) { l } else { "CUSTOM" }.to_string())
    }

    /// The validated text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for KindLabel {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if valid_kind_label(&s) {
            Ok(KindLabel(s))
        } else {
            Err(serde::de::Error::custom("invalid KindLabel"))
        }
    }
}

impl fmt::Debug for KindLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KindLabel({})", self.0)
    }
}

/// A check that fired: the verifier's [`CheckId`]s plus the gateway's
/// clear-value tripwire. Serialized as the variant name (`Leak`,
/// `DetectorError`, `ClearValue`); any other string fails to load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CheckLabel {
    /// [`CheckId::Leak`].
    Leak,
    /// [`CheckId::Regex`].
    Regex,
    /// [`CheckId::Ner`].
    Ner,
    /// [`CheckId::Combination`].
    Combination,
    /// [`CheckId::Policy`].
    Policy,
    /// [`CheckId::DetectorError`].
    DetectorError,
    /// A known original in clear in model-authored arguments (M4 spec §16.1).
    ClearValue,
}

impl CheckLabel {
    /// Every label, in declaration order.
    pub const ALL: [CheckLabel; 7] = [
        CheckLabel::Leak,
        CheckLabel::Regex,
        CheckLabel::Ner,
        CheckLabel::Combination,
        CheckLabel::Policy,
        CheckLabel::DetectorError,
        CheckLabel::ClearValue,
    ];

    /// The label of a verifier check.
    pub fn of(check: &CheckId) -> CheckLabel {
        match check {
            CheckId::Leak => CheckLabel::Leak,
            CheckId::Regex => CheckLabel::Regex,
            CheckId::Ner => CheckLabel::Ner,
            CheckId::Combination => CheckLabel::Combination,
            CheckId::Policy => CheckLabel::Policy,
            CheckId::DetectorError => CheckLabel::DetectorError,
        }
    }

    /// The label as text (`Leak`, `ClearValue`).
    pub fn as_str(self) -> &'static str {
        match self {
            CheckLabel::Leak => "Leak",
            CheckLabel::Regex => "Regex",
            CheckLabel::Ner => "Ner",
            CheckLabel::Combination => "Combination",
            CheckLabel::Policy => "Policy",
            CheckLabel::DetectorError => "DetectorError",
            CheckLabel::ClearValue => "ClearValue",
        }
    }

    /// One of the fixed names, else `None`.
    pub fn parse(s: &str) -> Option<CheckLabel> {
        CheckLabel::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

/// Where the event happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrontDoor {
    /// The MCP gateway.
    Gateway,
    /// The control API.
    Control,
    /// The model-API proxy (M8).
    Proxy,
    /// The folder mirror (M5).
    Mirror,
    /// A harness hook (M6).
    Hook,
}

/// Which way the data moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// A result travelling to the model.
    Result,
    /// Arguments the model wrote, travelling to a tool.
    Arguments,
    /// A request to a provider (M8).
    Request,
    /// A provider response (M8).
    Response,
}

/// What inumaki did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Passed and released.
    Released,
    /// Withheld by a verifier or policy block (or the tripwire in block mode).
    Blocked,
    /// Withheld as uncertain.
    Uncertain,
    /// Failed strict restoration.
    Unresolved,
    /// Failed the field contract.
    Unsupported,
}

/// A kind with the number of blocks it appeared in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KindCount {
    /// Kind label.
    pub kind: KindLabel,
    /// Blocks carrying it.
    pub count: u32,
}

/// A record to append; the vault assigns `id` and `at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewActivity {
    /// Opaque dataset label ([`Vault::opaque_ref`]).
    pub dataset: OpaqueId,
    /// Front door.
    pub front_door: FrontDoor,
    /// Opaque upstream label ([`Vault::opaque_upstream`]).
    pub upstream: Option<OpaqueId>,
    /// Direction.
    pub direction: Direction,
    /// Verdict.
    pub verdict: Verdict,
    /// Checks that fired.
    pub checks: Vec<CheckLabel>,
    /// Kinds replaced, withheld, or found in clear.
    pub kinds: Vec<KindCount>,
    /// The clear-value tripwire fired (M4 spec §16.1).
    pub tripwire: bool,
    /// Bytes of the released or inspected payload.
    pub bytes: u64,
    /// Keyed digest of the released bytes (links a journal entry, plan 2b).
    pub released: Option<Digest>,
}

/// A stored record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivityRecord {
    /// Random id.
    pub id: RecordId,
    /// Unix seconds, from the vault clock.
    pub at: i64,
    /// Opaque dataset label.
    pub dataset: OpaqueId,
    /// Front door.
    pub front_door: FrontDoor,
    /// Opaque upstream label.
    pub upstream: Option<OpaqueId>,
    /// Direction.
    pub direction: Direction,
    /// Verdict.
    pub verdict: Verdict,
    /// Checks that fired.
    pub checks: Vec<CheckLabel>,
    /// Kinds with counts.
    pub kinds: Vec<KindCount>,
    /// Tripwire fired.
    pub tripwire: bool,
    /// Payload bytes.
    pub bytes: u64,
    /// Keyed digest of the released bytes.
    pub released: Option<Digest>,
}

/// The stored JSON body: everything but `id` and `at`, which have columns.
/// An extra key (text added on disk) fails the load like a bad value does.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    front_door: FrontDoor,
    upstream: Option<OpaqueId>,
    direction: Direction,
    verdict: Verdict,
    checks: Vec<CheckLabel>,
    kinds: Vec<KindCount>,
    tripwire: bool,
    bytes: u64,
    released: Option<Digest>,
}

/// Query for [`Vault::activity`].
#[derive(Debug, Clone, Default)]
pub struct ActivityFilter {
    /// Only this dataset.
    pub dataset: Option<OpaqueId>,
    /// Only records at or after this time.
    pub since: Option<i64>,
    /// At most this many (newest first); 0 means 100.
    pub limit: usize,
}

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Rows per sweep or verification step; the vault connection is released
/// between steps, so tokenization never waits behind a whole table scan.
pub const CHUNK: usize = 1000;

/// Keyed digest of released bytes (index-key HMAC over `released:` +
/// bytes), from a raw [`Indexer`]. Shared by [`Vault::released_digest`] and
/// the journal writer (plan 2b), which appends through its own connection
/// and has no `Vault` handle to call a method on.
pub(crate) fn released_digest_with(indexer: &Indexer, bytes: &[u8]) -> Digest {
    let mut input = b"released:".to_vec();
    input.extend_from_slice(bytes);
    Digest(crate::crypto::hex(&indexer.mac(&input)))
}

fn chain(prev: &str, id: &str, at: i64, dataset: &str, body: &str) -> String {
    let mut h = Sha256::new();
    for part in [prev, id, &at.to_string(), dataset, body] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part.as_bytes());
    }
    crate::crypto::hex(&h.finalize())
}

impl Vault {
    /// Opaque label of a dataset, as an [`OpaqueId`].
    pub fn opaque_ref(&self, dataset_id: &str) -> OpaqueId {
        OpaqueId(self.opaque_id(dataset_id))
    }

    /// Opaque label of an upstream within a dataset. Dataset ids never
    /// contain `/`, so this input never collides with a dataset label.
    pub fn opaque_upstream(&self, dataset_id: &str, upstream: &str) -> OpaqueId {
        OpaqueId(self.opaque_id(&format!("{dataset_id}/upstream/{upstream}")))
    }

    /// Keyed digest of released bytes (index-key HMAC over `released:` + bytes).
    pub fn released_digest(&self, bytes: &[u8]) -> Digest {
        released_digest_with(&self.inner.indexer, bytes)
    }

    /// Append a record: random id, vault time, chained to the last row.
    pub fn append_activity(&self, rec: NewActivity) -> Result<ActivityRecord, VaultError> {
        self.append_activities(vec![rec])?
            .pop()
            .ok_or(VaultError::ActivityRecord)
    }

    /// Append records in one transaction, in order, each chained to the
    /// one before (the activity writer drains its queue into one call).
    pub fn append_activities(
        &self,
        recs: Vec<NewActivity>,
    ) -> Result<Vec<ActivityRecord>, VaultError> {
        if recs.is_empty() {
            return Ok(Vec::new());
        }
        let mut rows = Vec::with_capacity(recs.len());
        for rec in recs {
            let mut raw = [0u8; 16];
            getrandom::fill(&mut raw).map_err(|_| VaultError::Random)?;
            let body = Body {
                front_door: rec.front_door,
                upstream: rec.upstream.clone(),
                direction: rec.direction,
                verdict: rec.verdict,
                checks: rec.checks.clone(),
                kinds: rec.kinds.clone(),
                tripwire: rec.tripwire,
                bytes: rec.bytes,
                released: rec.released.clone(),
            };
            let body = serde_json::to_string(&body).map_err(|_| VaultError::ActivityRecord)?;
            rows.push((crate::crypto::hex(&raw), body, rec));
        }
        let at = self.inner.now();
        {
            let mut conn = self.inner.lock();
            // IMMEDIATE: take the write lock up front, so another writer on
            // the file means waiting (busy timeout), not an instant
            // SQLITE_BUSY on the read-to-write upgrade.
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut prev: String = tx
                .query_row(
                    "SELECT hash FROM activity ORDER BY seq DESC LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .optional()?
                .unwrap_or_else(|| GENESIS.to_string());
            for (id, body, rec) in &rows {
                let hash = chain(&prev, id, at, rec.dataset.as_str(), body);
                tx.execute(
                    "INSERT INTO activity (id, at, dataset, record, prev, hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![id, at, rec.dataset.as_str(), body, prev, hash],
                )?;
                prev = hash;
            }
            tx.commit()?;
        }
        Ok(rows
            .into_iter()
            .map(|(id, _, rec)| ActivityRecord {
                id: RecordId(id),
                at,
                dataset: rec.dataset,
                front_door: rec.front_door,
                upstream: rec.upstream,
                direction: rec.direction,
                verdict: rec.verdict,
                checks: rec.checks,
                kinds: rec.kinds,
                tripwire: rec.tripwire,
                bytes: rec.bytes,
                released: rec.released,
            })
            .collect())
    }

    /// Records matching `filter`, newest first. A row that fails validation
    /// fails the whole query ([`VaultError::ActivityRecord`]).
    pub fn activity(&self, filter: &ActivityFilter) -> Result<Vec<ActivityRecord>, VaultError> {
        let limit = if filter.limit == 0 {
            100
        } else {
            filter.limit.min(10_000)
        } as i64;
        let rows: Vec<(String, i64, String, String)> = {
            let conn = self.inner.lock();
            let mut stmt = conn.prepare(
                "SELECT id, at, dataset, record FROM activity \
                 WHERE (?1 IS NULL OR dataset = ?1) AND (?2 IS NULL OR at >= ?2) \
                 ORDER BY seq DESC LIMIT ?3",
            )?;
            let rows = stmt.query_map(
                params![
                    filter.dataset.as_ref().map(OpaqueId::as_str),
                    filter.since,
                    limit
                ],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
            rows.collect::<Result<_, _>>()?
        };
        rows.into_iter()
            .map(|(id, at, dataset, record)| {
                let b: Body =
                    serde_json::from_str(&record).map_err(|_| VaultError::ActivityRecord)?;
                Ok(ActivityRecord {
                    id: RecordId::try_from(id).map_err(|_| VaultError::ActivityRecord)?,
                    at,
                    dataset: OpaqueId::try_from(dataset).map_err(|_| VaultError::ActivityRecord)?,
                    front_door: b.front_door,
                    upstream: b.upstream,
                    direction: b.direction,
                    verdict: b.verdict,
                    checks: b.checks,
                    kinds: b.kinds,
                    tripwire: b.tripwire,
                    bytes: b.bytes,
                    released: b.released,
                })
            })
            .collect()
    }

    /// Delete expired records; returns how many. The chain only verifies
    /// over a contiguous tail, so this deletes a prefix: every row up to
    /// the newest one older than `retention_days`. A wall-clock step back
    /// can leave a younger row inside that prefix; it goes too, rather
    /// than leaving a hole that `verify` would report as tampering. Runs in
    /// chunks of [`CHUNK`] rows, releasing the vault connection between.
    pub fn sweep_activity(&self, retention_days: u32) -> Result<usize, VaultError> {
        let cutoff = self.inner.now() - i64::from(retention_days) * 86_400;
        let bound: Option<i64> = {
            let conn = self.inner.lock();
            conn.query_row(
                "SELECT max(seq) FROM activity WHERE at < ?1",
                params![cutoff],
                |r| r.get(0),
            )?
        };
        let Some(bound) = bound else {
            return Ok(0);
        };
        let mut deleted = 0;
        loop {
            let n = {
                let conn = self.inner.lock();
                conn.execute(
                    "DELETE FROM activity WHERE seq IN \
                     (SELECT seq FROM activity WHERE seq <= ?1 ORDER BY seq LIMIT ?2)",
                    params![bound, CHUNK as i64],
                )?
            };
            deleted += n;
            if n < CHUNK {
                return Ok(deleted);
            }
        }
    }

    /// Recompute the chain from the oldest kept row (its stored `prev` is
    /// trusted, since sweeps delete the rows before it); returns the number
    /// of rows verified. Reads [`CHUNK`] rows at a time and hashes them
    /// with the vault connection released. A sweep between two chunks
    /// deletes a prefix; when it took the last verified row, the next
    /// chunk starts over as the oldest kept rows.
    pub fn verify_activity_chain(&self) -> Result<usize, VaultError> {
        type Row = (i64, String, i64, String, String, String, String);
        let mut last: Option<(i64, String)> = None;
        let mut verified = 0usize;
        loop {
            let (rows, last_kept): (Vec<Row>, bool) = {
                let conn = self.inner.lock();
                let mut stmt = conn.prepare(
                    "SELECT seq, id, at, dataset, record, prev, hash FROM activity \
                     WHERE seq > ?1 ORDER BY seq LIMIT ?2",
                )?;
                let after = last.as_ref().map_or(i64::MIN, |l| l.0);
                let rows = stmt
                    .query_map(params![after, CHUNK as i64], |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                            r.get(6)?,
                        ))
                    })?
                    .collect::<Result<_, _>>()?;
                let kept = match &last {
                    None => true,
                    Some((seq, _)) => conn
                        .query_row(
                            "SELECT 1 FROM activity WHERE seq = ?1",
                            params![seq],
                            |_| Ok(()),
                        )
                        .optional()?
                        .is_some(),
                };
                (rows, kept)
            };
            if rows.is_empty() {
                return Ok(verified);
            }
            if !last_kept {
                last = None;
                verified = 0;
            }
            for (seq, id, at, dataset, record, prev, hash) in rows {
                if last.as_ref().is_some_and(|(_, h)| *h != prev) {
                    return Err(VaultError::ActivityChain(seq));
                }
                if chain(&prev, &id, at, &dataset, &record) != hash {
                    return Err(VaultError::ActivityChain(seq));
                }
                last = Some((seq, hash));
                verified += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stored body is closed too: a field added here must be added to
    /// this destructuring, with a type that cannot carry text.
    #[test]
    fn body_fields_are_closed_and_typed() {
        fn check(b: Body) {
            let Body {
                front_door,
                upstream,
                direction,
                verdict,
                checks,
                kinds,
                tripwire,
                bytes,
                released,
            } = b;
            let _: (FrontDoor, Option<OpaqueId>, Direction, Verdict) =
                (front_door, upstream, direction, verdict);
            let _: (Vec<CheckLabel>, Vec<KindCount>, bool, u64, Option<Digest>) =
                (checks, kinds, tripwire, bytes, released);
        }
        check(Body {
            front_door: FrontDoor::Gateway,
            upstream: None,
            direction: Direction::Result,
            verdict: Verdict::Released,
            checks: vec![CheckLabel::Leak],
            kinds: vec![KindCount {
                kind: KindLabel::of(&EntityKind::Person),
                count: 1,
            }],
            tripwire: false,
            bytes: 0,
            released: None,
        });
    }
}
