//! Socket resolution and error mapping for the daemon commands.

use std::path::Path;

use anyhow::{Result, anyhow};
use hyper::Method;
use inumakid::client::{Client, ClientError, Reply};
use inumakid::config::DaemonConfig;
use inumakid::dirs::{resolve_data_dir, resolve_in};

/// Socket path exactly as the daemon resolves it: `--socket`, else
/// `[daemon] socket` inside the data directory (`--data-dir`,
/// `INUMAKI_DATA_DIR`, platform default).
pub fn resolve_socket(
    socket: Option<&Path>,
    data_dir: Option<&Path>,
    config: Option<&Path>,
) -> Result<std::path::PathBuf> {
    if let Some(s) = socket {
        return Ok(s.to_path_buf());
    }
    let cfg = match config {
        // The error names the file; never its content.
        Some(p) => DaemonConfig::load(p)?,
        None => DaemonConfig::embedded(),
    };
    Ok(resolve_in(&resolve_data_dir(data_dir), &cfg.daemon.socket))
}

/// A client for the resolved socket.
pub fn connect(
    socket: Option<&Path>,
    data_dir: Option<&Path>,
    config: Option<&Path>,
) -> Result<Client> {
    Ok(Client::new(resolve_socket(socket, data_dir, config)?))
}

/// One call; connection failures name the socket and how to start the daemon.
pub fn call(
    client: &Client,
    method: Method,
    path: &str,
    body: Option<&serde_json::Value>,
) -> Result<Reply> {
    client.call_blocking(method, path, body).map_err(|e| match e {
        ClientError::Connect { path, kind } => anyhow!(
            "cannot connect to {path} ({kind:?}); is the daemon running? start it with `inumaki daemon`"
        ),
        other => anyhow!("{other}"),
    })
}

/// `type: message` from an error body (plus kinds and checks when present).
pub fn error_line(reply: &Reply) -> String {
    let e = &reply.body["error"];
    let mut line = format!(
        "{}: {}",
        e["type"].as_str().unwrap_or("error"),
        e["message"].as_str().unwrap_or("")
    );
    let list = |v: &serde_json::Value| -> String {
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default()
    };
    let (kinds, checks) = (list(&e["kinds"]), list(&e["checks"]));
    if !kinds.is_empty() || !checks.is_empty() {
        line.push_str(&format!(" kinds={kinds} checks={checks}"));
    }
    line
}
