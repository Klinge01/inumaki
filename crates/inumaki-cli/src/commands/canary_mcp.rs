//! Hidden `inumaki canary-mcp`: the check's canary server when the daemon
//! runs in-process as `inumaki daemon` (its executable is `inumaki`).

use std::path::Path;
use std::process::ExitCode;

/// Serve the canary MCP server on stdio.
pub fn run(fixture: &Path) -> ExitCode {
    ExitCode::from(inumakid::check::canary_mcp::run(fixture))
}
