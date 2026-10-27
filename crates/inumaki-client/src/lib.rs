//! Typed client for the `inumakid` control API (M6 spec §9): the contract
//! types for every endpoint, one JSON fixture per response shape, a
//! Unix-socket client, and (feature `mock`) a mock daemon serving the
//! fixtures. It depends on no inumaki crate, so the app and the hook link
//! it without the engine, the vault, or ONNX Runtime.

// `ClientError::Status` carries the parsed error detail by value. A control
// API error ends the call, so its size on the stack does not matter, and
// boxing it would change every match on the public type.
#![allow(clippy::result_large_err)]

#[macro_use]
mod macros;

pub mod client;
pub mod contract;
mod endpoints;
#[cfg(feature = "mock")]
pub mod mock;
pub mod revocations;
pub mod secret;
pub mod socket;
pub mod types;

pub use client::{Client, ClientError, RawReply};
pub use hyper::Method;
pub use secret::{Secret, SecretMap};
pub use socket::{DAEMON_KEYS, SocketError, default_data_dir, resolve_socket};
pub use types::*;
