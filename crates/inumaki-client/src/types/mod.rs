//! Contract types, one module per endpoint group of M6 spec §9. Field
//! order follows the daemon's structs, so struct-serialized bodies
//! round-trip byte for byte. `Debug` never prints a name, slug, path, text,
//! token, or secret (`debug_fields!` allowlists).

mod activity;
mod check;
mod datasets;
mod doctor;
mod engine;
mod error;
mod folders;
mod hook;
mod journal;
mod mailbox;
mod proxy;
mod service;
mod status;
mod tokens;
mod upstreams;

pub use activity::*;
pub use check::*;
pub use datasets::*;
pub use doctor::*;
pub use engine::*;
pub use error::*;
pub use folders::*;
pub use hook::*;
pub use journal::*;
pub use mailbox::*;
pub use proxy::*;
pub use service::*;
pub use status::*;
pub use tokens::*;
pub use upstreams::*;
