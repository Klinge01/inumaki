//! `inumaki-test-upstream`: the gateway tests' scripted MCP server as a
//! child process on stdio. Not a user-facing binary; built only with the
//! `test-fixtures` feature, so integration tests can spawn it by
//! `CARGO_BIN_EXE_inumaki-test-upstream`; default builds and installs do
//! not contain it. Settings from the environment
//! (`INUMAKI_TEST_UPSTREAM_*`, see `inumaki_gateway::scripted`). Writes one
//! line to stderr at start so the gateway's stderr discard is observable.

use std::io::Write;

use inumaki_gateway::scripted::ScriptedUpstream;

#[tokio::main]
async fn main() {
    let _ = std::io::stderr()
        .write_all(b"scripted upstream starting; this line must never reach a log\n");
    let handler = ScriptedUpstream::from_env();
    let running = match rmcp::serve_server(handler, rmcp::transport::stdio()).await {
        Ok(r) => r,
        Err(_) => std::process::exit(2),
    };
    let _ = running.waiting().await;
}
