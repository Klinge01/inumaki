//! `inumaki inspect`: local diagnostic inspection through the daemon.
//! Prints metadata; values only with `--show-values` on a terminal.

use std::io::IsTerminal;
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
    dataset: &str,
    profile: Option<&str>,
    show_values: bool,
    redactions: Option<&Path>,
    input: &Path,
) -> Result<u8> {
    if show_values && !std::io::stdout().is_terminal() {
        bail!(
            "--show-values prints plaintext and is only allowed on a terminal (stdout is not a TTY)"
        );
    }
    let c = connect(socket, data_dir, config)?;
    let text = read_input(input)?;
    let mut body = json!({ "dataset": dataset, "text": text, "show_values": show_values });
    if let Some(p) = profile {
        body["profile"] = json!(p);
    }
    if let Some(p) = redactions {
        body["redactions"] = read_redactions(p)?;
    }
    let r = call(&c, Method::POST, "/v1/inspect", Some(&body))?;
    if !r.status.is_success() {
        bail!("{}", error_line(&r));
    }
    let b = &r.body;
    println!("{}", b["label"].as_str().unwrap_or(""));
    println!(
        "outcome {}  profile {}{}  replacements {}",
        b["outcome"].as_str().unwrap_or("?"),
        b["profile"].as_str().unwrap_or("?"),
        if b["retried"] == true {
            " (retry profile)"
        } else {
            ""
        },
        b["replacements"]
    );
    println!(
        "{:<8} {:<8} {:<16} {:<10} SOURCE",
        "START", "END", "KIND", "ACTION"
    );
    for s in b["spans"].as_array().into_iter().flatten() {
        print!(
            "{:<8} {:<8} {:<16} {:<10} {}",
            s["start"],
            s["end"],
            s["kind"].as_str().unwrap_or(""),
            s["action"].as_str().unwrap_or(""),
            s["source"].as_str().unwrap_or("")
        );
        if let Some(o) = s["original"].as_str() {
            print!("  {o}");
        }
        println!();
    }
    for reason in b["reasons"].as_array().into_iter().flatten() {
        println!(
            "reason: kind={} check={}",
            reason["kind"].as_str().unwrap_or(""),
            reason["check"].as_str().unwrap_or("")
        );
    }
    for l in b["limitations"].as_array().into_iter().flatten() {
        println!("limitation: {}", l.as_str().unwrap_or(""));
    }
    let e = &b["expiry"];
    println!(
        "expiry: rotation every {} days, grace {} days, current epoch since {}",
        e["rotation_days"], e["grace_days"], e["epoch_started_at"]
    );
    if let Some(c) = b["candidate"].as_str() {
        println!("--- candidate ({}) ---", b["label"].as_str().unwrap_or(""));
        println!("{c}");
    }
    Ok(if b["outcome"] == "blocked" {
        exit::BLOCKED
    } else {
        exit::OK
    })
}
