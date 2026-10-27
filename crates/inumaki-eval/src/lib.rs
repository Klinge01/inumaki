//! Evaluation for inumaki: hand-written cases, a deterministic synthetic
//! generator, metrics (recall, precision, leak rate, verifier error rates,
//! latency), and a baseline regression gate.
#![deny(missing_docs)]

pub mod cases;
pub mod corpus;
pub mod data;
pub mod data_held_out;
pub mod generate;
pub mod mail_fixture;
pub mod metrics;
pub mod report;
pub mod residue;
pub mod rng;
pub mod sequence;
pub mod tool_json;

pub use corpus::{Doc, EvalError, GoldSpan};
pub use generate::{GenFamily, GenOptions, HELD_OUT_COUNT, HELD_OUT_SEED, generate, held_out};
pub use mail_fixture::{
    DictionaryLists, FixtureMail, FixtureOptions, dictionary_lists, fixture_digest,
    generate_mailbox,
};
pub use metrics::{
    DetectFailed, DocOutcome, EngineSanitizer, EvalOptions, EvalOutcome, LinkStats, Replaced,
    Report, Sanitizer, evaluate, evaluate_with,
};
pub use report::{Baseline, Targets, render_text};
pub use residue::{Residue, find_residue};
