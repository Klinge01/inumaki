//! What the gateway needs from the engine (M4 spec §5.3): batch
//! sanitization with trusted field semantics and strict restoration over a
//! dataset namespace. The daemon implements [`Blocks`]; the gateway never
//! touches the vault's entries or the models.

use std::sync::Arc;

use inumaki_core::policy::Profile;
use inumaki_core::span::EntityKind;
use inumaki_core::verify::Reason;

/// Field semantics the contract walker attaches to a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldHint {
    /// Free text: detect, sanitize, verify.
    FreeText,
    /// A typed identifier: the whole value becomes a token of this kind.
    Identifier(EntityKind),
    /// Discovery metadata a listing sends (tool, prompt, and template
    /// prose, schema prose, examples, defaults, enum and const values,
    /// patterns): free text under the dataset profile's metadata profile
    /// (plan 2c). Never a listed resource or a result.
    Metadata,
    /// A locally minted handle under a `handle` rule: the daemon checks
    /// provenance (it minted this value for this dataset) and returns the
    /// text unchanged, or fails the whole batch with
    /// `Unsupported("handle_provenance")`. Never sent to the engine.
    Handle,
}

/// One block to sanitize.
#[derive(Clone, PartialEq, Eq)]
pub struct TextBlock {
    /// The text.
    pub text: String,
    /// Field semantics.
    pub hint: FieldHint,
}

impl TextBlock {
    /// A free-text block.
    pub fn text(s: impl Into<String>) -> Self {
        TextBlock {
            text: s.into(),
            hint: FieldHint::FreeText,
        }
    }
}

impl std::fmt::Debug for TextBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TextBlock")
            .field("len", &self.text.len())
            .field("hint", &self.hint)
            .finish()
    }
}

/// Which outcome the engine produced for one block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockOutcome {
    /// Safe to send.
    Pass,
    /// Flagged; the gateway withholds it (M4 spec §5.3).
    PassUncertain,
    /// Must not be sent; `text` is empty.
    Blocked,
}

/// One sanitized block. `Debug` prints lengths and counts.
#[derive(Clone)]
pub struct BlockResult {
    /// Outcome.
    pub outcome: BlockOutcome,
    /// Sanitized text (empty when blocked).
    pub text: String,
    /// Replacement count.
    pub replacements: usize,
    /// Kinds tokenized or removed, or the block's kinds.
    pub kinds: Vec<EntityKind>,
    /// Reasons when uncertain or blocked.
    pub reasons: Vec<Reason>,
    /// Served from the cache.
    pub cached: bool,
}

impl std::fmt::Debug for BlockResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockResult")
            .field("outcome", &self.outcome)
            .field("len", &self.text.len())
            .field("replacements", &self.replacements)
            .field("kinds", &self.kinds.len())
            .field("reasons", &self.reasons.len())
            .field("cached", &self.cached)
            .finish()
    }
}

impl BlockResult {
    /// Kind labels, deduplicated, first-seen order.
    pub fn kind_labels(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for k in &self.kinds {
            let l = k.label().to_string();
            if !out.contains(&l) {
                out.push(l);
            }
        }
        out
    }

    /// Check ids of the reasons, deduplicated, first-seen order.
    pub fn check_ids(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for r in &self.reasons {
            let c = format!("{:?}", r.check);
            if !out.contains(&c) {
                out.push(c);
            }
        }
        out
    }
}

/// Why a batch could not be served. Classes and counts only.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlocksError {
    /// No such dataset (or its epoch is gone).
    #[error("dataset not found")]
    DatasetNotFound,
    /// The dataset's profile has no models loaded.
    #[error("model unavailable")]
    ModelUnavailable,
    /// The vault or token store failed.
    #[error("vault unavailable")]
    VaultUnavailable,
    /// Strict restoration found placeholders it cannot resolve.
    #[error("unresolved placeholders: {unknown} unknown, {removed} removed")]
    Unresolved {
        /// Unknown, expired, or foreign tokens.
        unknown: usize,
        /// Removed-value markers.
        removed: usize,
    },
    /// The request shape is not supported; fixed class.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    /// A fixed-message internal failure.
    #[error("internal: {0}")]
    Internal(&'static str),
}

/// Batch sanitization and strict restoration over a dataset namespace.
/// Both calls block (engine work); async callers use `spawn_blocking`.
pub trait Blocks: Send + Sync + 'static {
    /// Sanitize every block under the dataset's profile, holding the
    /// namespace once for the whole batch; one result per block, in order.
    /// Nothing is released unless every block passed the final check.
    fn sanitize_blocks(
        &self,
        dataset: &str,
        blocks: Vec<TextBlock>,
    ) -> Result<Vec<BlockResult>, BlocksError>;

    /// Restore every placeholder in every block or fail the whole batch.
    fn rehydrate_strict(
        &self,
        dataset: &str,
        blocks: Vec<String>,
    ) -> Result<Vec<String>, BlocksError>;

    /// The dataset's resolved profile (its policy only, no models), so the
    /// gateway can refuse a contract whose identifier kinds the profile
    /// blocks or removes ([`crate::contract::Contract::check_profile`]).
    /// Blocks (vault read).
    fn profile(&self, dataset: &str) -> Result<Arc<Profile>, BlocksError>;

    /// Known originals (full matches) and validated identifiers that appear
    /// in clear in model-written text (M4 spec §16.1). Returns kind labels
    /// with occurrence counts; empty when clean. Never returns text. No
    /// default body: an implementation that forgets it must not compile,
    /// since a default "nothing found" would fail open.
    fn scan_clear(
        &self,
        dataset: &str,
        texts: &[String],
    ) -> Result<Vec<(String, u32)>, BlocksError>;

    /// [`Blocks::scan_clear`] for names a listing exposes as they are (M4
    /// spec §5.2): a known person, organization, or street counts only when
    /// its match spans two or more words, so a known `Max` does not fail
    /// `max_results`; identifier kinds and validated identifiers count as
    /// in `scan_clear`. The number of hits; never text. The default counts
    /// every `scan_clear` hit: stricter, never fails open.
    fn scan_names(&self, dataset: &str, names: &[String]) -> Result<u32, BlocksError> {
        Ok(self
            .scan_clear(dataset, names)?
            .iter()
            .map(|(_, n)| *n)
            .sum())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use inumaki_core::verify::CheckId;

    #[test]
    fn labels_and_checks_are_deduplicated_in_order() {
        let r = BlockResult {
            outcome: BlockOutcome::Blocked,
            text: String::new(),
            replacements: 0,
            kinds: vec![EntityKind::Person, EntityKind::Iban, EntityKind::Person],
            reasons: vec![
                Reason {
                    kind: EntityKind::Person,
                    check: CheckId::Leak,
                },
                Reason {
                    kind: EntityKind::Iban,
                    check: CheckId::Leak,
                },
                Reason {
                    kind: EntityKind::Person,
                    check: CheckId::Ner,
                },
            ],
            cached: false,
        };
        assert_eq!(r.kind_labels(), ["PERSON", "IBAN"]);
        assert_eq!(r.check_ids(), ["Leak", "Ner"]);
    }

    #[test]
    fn debug_prints_no_text() {
        let r = BlockResult {
            outcome: BlockOutcome::Pass,
            text: "Zyxwuria Quolnath".into(),
            replacements: 0,
            kinds: vec![],
            reasons: vec![],
            cached: true,
        };
        let b = TextBlock::text("Zyxwuria Quolnath");
        let d = format!("{r:?} {b:?}");
        assert!(!d.contains("Zyxwuria"), "{d}");
        assert!(d.contains("len: 17"));
        assert_eq!(
            serde_json::to_string(&BlockOutcome::PassUncertain).unwrap(),
            "\"pass_uncertain\""
        );
    }
}
