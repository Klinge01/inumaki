//! Names and keys the app chooses (spec §4.5). MCP server names reach the
//! model, and a dataset slug is a customer name as often as not: data
//! sources get fixed names, never the dataset's. The rules are M6-1's
//! (`inumaki_adapters::protect`, reached through `adapt.rs`), so the app and
//! `inumaki connect` name things identically; `server_key` is the app's
//! keyed hash for `state.json`.

pub use super::adapt::{
    credential_like, dataset_id, definition_id, mail_entry_name, upstream_name,
};
pub use super::server_key;
