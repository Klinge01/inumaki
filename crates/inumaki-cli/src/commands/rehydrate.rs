//! `inumaki rehydrate`: put originals back through the daemon.

use std::path::Path;

use anyhow::{Result, bail};
use hyper::Method;
use serde_json::json;

use super::read_input;
use crate::client::{call, connect, error_line};
use crate::exit;

pub fn run(
    socket: Option<&Path>,
    data_dir: Option<&Path>,
    config: Option<&Path>,
    dataset: Option<&str>,
    session: Option<&str>,
    strict: bool,
    input: &Path,
) -> Result<u8> {
    if dataset.is_some() == session.is_some() {
        bail!("exactly one of --dataset or --session is required");
    }
    let c = connect(socket, data_dir, config)?;
    let text = read_input(input)?;
    let mut body = json!({ "text": text, "strict": strict });
    if let Some(d) = dataset {
        body["dataset"] = json!(d);
    }
    if let Some(s) = session {
        body["session"] = json!(s);
    }
    let r = call(&c, Method::POST, "/v1/rehydrate", Some(&body))?;
    match r.status.as_u16() {
        200 => {
            print!("{}", r.body["text"].as_str().unwrap_or(""));
            let unknown = r.body["unknown_tokens"].as_u64().unwrap_or(0);
            let removed = r.body["removed_markers"].as_u64().unwrap_or(0);
            if unknown > 0 {
                eprintln!("unknown tokens: {unknown}");
            }
            if removed > 0 {
                eprintln!("removed markers left in place: {removed}");
            }
            Ok(exit::OK)
        }
        422 => {
            let e = &r.body["error"];
            eprintln!(
                "unresolved tokens: unknown={} removed={}",
                e["unknown_tokens"].as_u64().unwrap_or(0),
                e["removed_markers"].as_u64().unwrap_or(0)
            );
            Ok(exit::BLOCKED)
        }
        _ => bail!("{}", error_line(&r)),
    }
}
