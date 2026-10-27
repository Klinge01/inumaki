//! `inumaki activity`: what happened at the front doors, newest first.

use std::path::Path;

use anyhow::{Result, bail};
use hyper::Method;
use serde_json::Value;

use super::{ago, now_secs, valid_dataset};
use crate::client::{call, connect, error_line};
use crate::exit;

/// One record as a line: age, dataset, front door, direction, verdict,
/// the tripwire marker, kinds with counts, checks.
pub fn line(r: &Value, now: i64) -> String {
    let kinds: Vec<String> = r["kinds"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|k| format!("{}×{}", k["kind"].as_str().unwrap_or("?"), k["count"]))
        .collect();
    let checks: Vec<&str> = r["checks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    format!(
        "{:>8}  {:<14} {:<9} {:<10} {:<11}{}{}{}",
        ago(now - r["at"].as_i64().unwrap_or(now)),
        r["dataset"].as_str().unwrap_or("?"),
        r["front_door"].as_str().unwrap_or("?"),
        r["direction"].as_str().unwrap_or("?"),
        r["verdict"].as_str().unwrap_or("?"),
        if r["tripwire"] == true {
            "  CLEAR VALUE"
        } else {
            ""
        },
        if kinds.is_empty() {
            String::new()
        } else {
            format!("  {}", kinds.join(" "))
        },
        if checks.is_empty() {
            String::new()
        } else {
            format!("  checks: {}", checks.join(", "))
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    socket: Option<&Path>,
    data_dir: Option<&Path>,
    config: Option<&Path>,
    dataset: Option<String>,
    since: Option<i64>,
    limit: usize,
    json: bool,
    verify: bool,
) -> Result<u8> {
    let c = connect(socket, data_dir, config)?;
    if verify {
        let r = call(&c, Method::GET, "/v1/activity/verify", None)?;
        if !r.status.is_success() {
            bail!("{}", error_line(&r));
        }
        println!("activity chain ok: {} records", r.body["records"]);
        return Ok(exit::OK);
    }
    let now = now_secs();
    let mut q = vec![format!("limit={limit}")];
    if let Some(d) = &dataset {
        if !valid_dataset(d) {
            bail!("dataset ids contain a-z, 0-9 and '-' only");
        }
        q.push(format!("dataset={d}"));
    }
    if let Some(s) = since {
        if s < 0 {
            bail!("--since takes a number of seconds");
        }
        q.push(format!("since={}", now.saturating_sub(s)));
    }
    let r = call(
        &c,
        Method::GET,
        &format!("/v1/activity?{}", q.join("&")),
        None,
    )?;
    if !r.status.is_success() {
        bail!("{}", error_line(&r));
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&r.body)?);
        return Ok(exit::OK);
    }
    for rec in r.body["records"].as_array().into_iter().flatten() {
        println!("{}", line(rec, now));
    }
    Ok(exit::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_shows_kinds_checks_and_the_tripwire() {
        let r = serde_json::json!({ "at": 940, "dataset": "crm", "front_door": "gateway", "direction": "arguments", "verdict": "released", "tripwire": true, "kinds": [{ "kind": "PERSON", "count": 1 }], "checks": ["ClearValue"] });
        let l = line(&r, 1_000);
        assert!(
            l.contains("60s ago")
                && l.contains("crm")
                && l.contains("CLEAR VALUE")
                && l.contains("PERSON×1")
                && l.contains("ClearValue"),
            "{l}"
        );
    }
}
