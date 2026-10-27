//! Command bodies: plain async functions over `&Ctx` (or `&Arc<Ctx>` where
//! they move work to a blocking thread), wrapped by `ipc.rs`.

pub mod activity;
pub mod check;
pub mod email;
pub mod folders;
pub mod inspect;
pub mod mcp;
pub mod overview;
pub mod service;
pub mod settings;
