//! The app side of the end-to-end check (M6 spec §8.2): temporary
//! directories, one harness run per connected harness with a
//! `check_invocation`, results into `state.json` (booleans and reason
//! codes only). Harness output goes to the daemon and nowhere else.

pub mod run;
pub mod tmp;
