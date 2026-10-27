//! `inumaki sanitize`: send text through the daemon; print the sanitized text.

use std::path::Path;

use anyhow::{Result, bail};
use hyper::Method;
use serde_json::json;

use super::{read_input, read_redactions};
use crate::client::{call, connect, error_line};
use crate::exit;

#[allow(clippy::too_many_arguments)]
pub fn run(
    socket: Option<&Path>,
    data_dir: Option<&Path>,
    config: Option<&Path>,
    dataset: Option<&str>,
    session: Option<&str>,
    profile: Option<&str>,
    redactions: Option<&Path>,
    input: &Path,
) -> Result<u8> {
    if dataset.is_some() == session.is_some() {
        bail!("exactly one of --dataset or --session is required");
    }
    let c = connect(socket, data_dir, config)?;
    let text = read_input(input)?;
    let mut body = json!({ "text": text });
    if let Some(d) = dataset {
        body["dataset"] = json!(d);
    }
    if let Some(s) = session {
        body["session"] = json!(s);
    }
    if let Some(p) = profile {
        body["profile"] = json!(p);
    }
    if let Some(p) = redactions {
        body["redactions"] = read_redactions(p)?;
    }
    let r = call(&c, Method::POST, "/v1/sanitize", Some(&body))?;
    match r.status.as_u16() {
        200 => {
            print!("{}", r.body["text"].as_str().unwrap_or(""));
            if r.body["outcome"] == "pass_uncertain" {
                // Kinds and check ids only, never values (as `tokenize` does).
                let kinds: Vec<&str> = r.body["kinds"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|k| k.as_str())
                    .collect();
                let checks: Vec<String> = r.body["reasons"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|x| x["check"].as_str().map(str::to_string))
                    .collect();
                eprintln!(
                    "uncertain: kinds={} checks={}",
                    kinds.join(","),
                    checks.join(",")
                );
            }
            Ok(exit::OK)
        }
        451 => {
            let e = &r.body["error"];
            let list = |v: &serde_json::Value| {
                v.as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default()
            };
            eprintln!(
                "blocked: kinds={} checks={}",
                list(&e["kinds"]),
                list(&e["checks"])
            );
            Ok(exit::BLOCKED)
        }
        _ => bail!("{}", error_line(&r)),
    }
}
