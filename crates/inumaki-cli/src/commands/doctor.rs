//! `inumaki doctor`: print the daemon's diagnostics.

use std::path::Path;

use anyhow::{Result, bail};
use hyper::Method;

use crate::client::{call, connect, error_line};
use crate::exit;

/// Run.
pub fn run(
    socket: Option<&Path>,
    data_dir: Option<&Path>,
    config: Option<&Path>,
    dataset: Option<&str>,
) -> Result<u8> {
    let c = connect(socket, data_dir, config)?;
    let r = call(&c, Method::GET, "/v1/doctor", None)?;
    if !r.status.is_success() {
        bail!("{}", error_line(&r));
    }
    let b = &r.body;
    println!("socket: ok ({})", c.socket().display());
    // Where the daemon's configuration came from: `embedded` or a path,
    // never the content. Older daemons do not report it; a failed status
    // call only skips this line, never the rest of the diagnostics.
    if let Ok(s) = call(&c, Method::GET, "/v1/status", None) {
        if let Some(src) = s.body["config_source"]
            .as_str()
            .filter(|_| s.status.is_success())
        {
            println!("config: {src}");
        }
    }
    println!(
        "vault: keys from {}, integrity {}",
        b["vault"]["key_source"].as_str().unwrap_or("?"),
        if b["vault"]["integrity_ok"] == true {
            "ok"
        } else {
            "FAILED"
        }
    );
    for m in b["models"].as_array().into_iter().flatten() {
        println!(
            "model {:<16} {}",
            m["name"].as_str().unwrap_or(""),
            m["status"].as_str().unwrap_or("")
        );
    }
    for p in b["profiles"].as_array().into_iter().flatten() {
        println!(
            "profile {:<16} {:<12} {}",
            p["name"].as_str().unwrap_or(""),
            if p["available"] == true {
                "available"
            } else {
                "unavailable"
            },
            p["qualification"].as_str().unwrap_or("")
        );
    }
    for d in b["datasets"].as_array().into_iter().flatten() {
        if dataset.is_some_and(|want| d["id"] != want) {
            continue;
        }
        println!(
            "dataset {} profile {} rotation {}d grace {}d",
            d["id"].as_str().unwrap_or(""),
            d["profile"].as_str().unwrap_or(""),
            d["rotation_days"],
            d["grace_days"]
        );
        for u in d["upstreams"].as_array().into_iter().flatten() {
            println!(
                "  upstream {:<20} {:<6} contract {:<8} secrets {}",
                u["name"].as_str().unwrap_or(""),
                u["kind"].as_str().unwrap_or(""),
                u["contract"].as_str().unwrap_or(""),
                if u["has_secrets"] == true {
                    "yes"
                } else {
                    "no"
                }
            );
        }
    }
    println!(
        "gateway: {} tokens at {}",
        b["gateway"]["tokens"],
        b["gateway"]["listen"].as_str().unwrap_or("")
    );
    for s in b["next_steps"].as_array().into_iter().flatten() {
        println!("next: {}", s.as_str().unwrap_or(""));
    }
    Ok(exit::OK)
}
