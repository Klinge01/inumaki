//! `inumaki dataset entities|forget`: what a dataset knows, and removing
//! one entity without deleting the dataset (M4 spec §16.3).

use std::io::IsTerminal;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use hyper::Method;
use serde_json::json;
use zeroize::Zeroizing;

use super::{ago, encode_path_segment, now_secs, valid_dataset};
use crate::client::{call, connect, error_line};
use crate::exit;

/// `inumaki dataset entities ID [--show-values] [--limit N] [--json]`.
pub fn entities(
    socket: Option<&Path>,
    data_dir: Option<&Path>,
    config: Option<&Path>,
    id: &str,
    show_values: bool,
    limit: usize,
    json: bool,
) -> Result<u8> {
    if !valid_dataset(id) {
        bail!("dataset ids contain a-z, 0-9 and '-' only");
    }
    // Refused before the daemon is contacted (Review Focus 6).
    if show_values && !std::io::stdout().is_terminal() {
        bail!(
            "--show-values prints plaintext and is only allowed on a terminal (stdout is not a TTY)"
        );
    }
    let c = connect(socket, data_dir, config)?;
    let r = call(
        &c,
        Method::GET,
        &format!("/v1/datasets/{id}/entities?show_values={show_values}&limit={limit}"),
        None,
    )?;
    if !r.status.is_success() {
        bail!("{}", error_line(&r));
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&r.body)?);
        return Ok(exit::OK);
    }
    let list = r.body["entities"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        println!("no entities in {id}");
        return Ok(exit::OK);
    }
    let now = now_secs();
    println!(
        "{:<26} {:<16} {:>10} {:>10} {:>12} {:>6} {:>5}{}",
        "TOKEN",
        "KIND",
        "FIRST",
        "LAST",
        "USES (store)",
        "FORMS",
        "EPOCH",
        if show_values { "  ORIGINAL" } else { "" }
    );
    for e in &list {
        print!(
            "{:<26} {:<16} {:>10} {:>10} {:>12} {:>6} {:>4}{}",
            e["token"].as_str().unwrap_or("?"),
            e["kind"].as_str().unwrap_or("?"),
            ago(now - e["first_use"].as_i64().unwrap_or(now)),
            ago(now - e["last_use"].as_i64().unwrap_or(now)),
            e["uses"],
            e["surface_forms"],
            e["epoch_id"],
            if e["current_epoch"] == true { " " } else { "*" }
        );
        if let Some(o) = e["original"].as_str() {
            print!("  {o}");
        }
        println!();
    }
    println!(
        "{} entities; * = closed epoch (grace period). Forget one with: inumaki dataset forget {id} --token TOKEN",
        list.len()
    );
    Ok(exit::OK)
}

/// `inumaki dataset forget ID (--token TOKEN | --value)`. The value is read
/// from a no-echo prompt, never from the command line.
pub fn forget(
    socket: Option<&Path>,
    data_dir: Option<&Path>,
    config: Option<&Path>,
    id: &str,
    token: Option<String>,
    value: bool,
) -> Result<u8> {
    if !valid_dataset(id) {
        bail!("dataset ids contain a-z, 0-9 and '-' only");
    }
    if token.is_some() == value {
        bail!("exactly one of --token TOKEN or --value is required");
    }
    let c = connect(socket, data_dir, config)?;
    let r = match token {
        Some(t) => call(
            &c,
            Method::DELETE,
            &format!("/v1/datasets/{id}/entities/{}", encode_path_segment(&t)),
            None,
        )?,
        None => {
            // The prompt buffer is zeroized on drop; the request body the
            // client serializes is not (documented plaintext exception,
            // docs/cli.md, next to `--map` and `inspect --show-values`).
            let v = Zeroizing::new(
                rpassword::prompt_password("value to forget (not echoed): ")
                    .context("reading the value")?,
            );
            if v.trim().is_empty() {
                bail!("empty value");
            }
            call(
                &c,
                Method::POST,
                &format!("/v1/datasets/{id}/entities/forget"),
                Some(&json!({ "value": v.as_str() })),
            )?
        }
    };
    if !r.status.is_success() {
        bail!("{}", error_line(&r));
    }
    let kinds: Vec<&str> = r.body["kinds"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|k| k.as_str())
        .collect();
    println!(
        "forgot 1 entity in {id}: kinds {}, {} token(s) across epochs, {} row(s); cached results dropped; the next mention mints a fresh token",
        kinds.join(","),
        r.body["tokens"],
        r.body["rows"]
    );
    Ok(exit::OK)
}

#[cfg(test)]
mod tests {
    use super::super::encode_path_segment;

    #[test]
    fn path_segments_encode_token_delimiters() {
        assert_eq!(encode_path_segment("<IBAN_a1b2c3>"), "%3CIBAN_a1b2c3%3E");
        assert_eq!(encode_path_segment("a/b?c#d"), "a%2Fb%3Fc%23d");
        assert_eq!(encode_path_segment("A-z.0_9~"), "A-z.0_9~");
    }
}
