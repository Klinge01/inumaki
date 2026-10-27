//! `inumaki journal list|show`: what an agent actually received, in
//! tokenized form; originals only with `--show-values` on a terminal.

use std::io::IsTerminal;
use std::path::Path;

use anyhow::{Result, bail};
use clap::Subcommand;
use hyper::Method;

use super::{ago, now_secs, valid_dataset};
use crate::client::{call, connect, error_line};
use crate::exit;

/// Actions for `inumaki journal`.
#[derive(Subcommand)]
pub(crate) enum JournalAction {
    /// List journal entries of a dataset, newest first.
    List {
        /// Dataset id.
        #[arg(long)]
        dataset: String,
        /// Only the last N seconds.
        #[arg(long)]
        since: Option<i64>,
        /// At most N entries.
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Print the raw JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show one entry: the payload as sent, or rehydrated locally with --show-values.
    Show {
        /// Dataset id.
        #[arg(long)]
        dataset: String,
        /// Record id from `list`.
        record: String,
        /// Rehydrate the payload locally (requires a terminal).
        #[arg(long)]
        show_values: bool,
        /// Print the raw JSON.
        #[arg(long)]
        json: bool,
    },
}

fn valid_record(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn run(
    socket: Option<&Path>,
    data_dir: Option<&Path>,
    config: Option<&Path>,
    action: JournalAction,
) -> Result<u8> {
    match action {
        JournalAction::List {
            dataset,
            since,
            limit,
            json,
        } => {
            if !valid_dataset(&dataset) {
                bail!("dataset ids contain a-z, 0-9 and '-' only");
            }
            if since.is_some_and(|s| s < 0) {
                bail!("--since takes a number of seconds");
            }
            let c = connect(socket, data_dir, config)?;
            let now = now_secs();
            let mut q = vec![format!("limit={limit}")];
            if let Some(s) = since {
                q.push(format!("since={}", now.saturating_sub(s)));
            }
            let r = call(
                &c,
                Method::GET,
                &format!("/v1/datasets/{dataset}/journal?{}", q.join("&")),
                None,
            )?;
            if !r.status.is_success() {
                bail!("{}", error_line(&r));
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&r.body)?);
                return Ok(exit::OK);
            }
            let entries = r.body["entries"].as_array().cloned().unwrap_or_default();
            if entries.is_empty() {
                println!("no journal entries for {dataset}");
                return Ok(exit::OK);
            }
            println!("{:<34} {:>9} {:>9}  RELEASED", "RECORD", "AGE", "BYTES");
            for e in &entries {
                println!(
                    "{:<34} {:>9} {:>9}  {}",
                    e["id"].as_str().unwrap_or("?"),
                    ago(now - e["at"].as_i64().unwrap_or(now)),
                    e["bytes"],
                    e["released"]
                        .as_str()
                        .and_then(|d| d.get(..16))
                        .unwrap_or("?")
                );
            }
            println!(
                "show one with: inumaki journal show --dataset {dataset} RECORD [--show-values]"
            );
            Ok(exit::OK)
        }
        JournalAction::Show {
            dataset,
            record,
            show_values,
            json,
        } => {
            if !valid_dataset(&dataset) {
                bail!("dataset ids contain a-z, 0-9 and '-' only");
            }
            if !valid_record(&record) {
                bail!("record ids are 32 lowercase hex characters (see `inumaki journal list`)");
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
                &format!("/v1/datasets/{dataset}/journal/{record}?show_values={show_values}"),
                None,
            )?;
            if !r.status.is_success() {
                bail!("{}", error_line(&r));
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&r.body)?);
                return Ok(exit::OK);
            }
            let b = &r.body;
            println!("--- {} ---", b["label"].as_str().unwrap_or(""));
            println!(
                "record {}  at {}  bytes {}",
                b["id"].as_str().unwrap_or("?"),
                b["at"],
                b["bytes"]
            );
            let payload = b["payload"].as_str().unwrap_or("");
            // A rehydrated payload may not be valid JSON (an original can
            // contain `"`); it is printed as text.
            match serde_json::from_str::<serde_json::Value>(payload) {
                Ok(v) if !show_values => println!("{}", serde_json::to_string_pretty(&v)?),
                _ => println!("{payload}"),
            }
            if let Some(n) = b["unresolved"].as_u64().filter(|n| *n > 0) {
                println!(
                    "unresolved placeholders: {n} (forgotten, expired, or removed values are left in place)"
                );
            }
            Ok(exit::OK)
        }
    }
}
