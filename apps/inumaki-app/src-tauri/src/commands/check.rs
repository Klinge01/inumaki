//! `run_check`: the end-to-end check from Overview or the tray.

use crate::check::run::CheckRun;
use crate::ctx::Ctx;
use crate::error::CmdError;

/// Run the check; the reports carry booleans and reason codes only, the
/// warning fixed text.
pub async fn run_check(ctx: &Ctx) -> Result<CheckRun, CmdError> {
    crate::check::run::run_check(ctx).await
}
