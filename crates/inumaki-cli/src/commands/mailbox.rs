//! `inumaki dataset add-mailbox|check-mailbox|remove-mailbox`.
//!
//! Everything the daemon would refuse with a fixed 400 is checked here first,
//! before the dataset is created, so a bad flag never leaves an empty mailbox
//! dataset behind. The app password comes from a 0600 file or a no-echo
//! prompt, lives in a `Zeroizing` buffer, and is never printed or put in an
//! error message; the daemon's replies carry no password either.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use clap::ValueEnum;
use hyper::Method;
use inumakid::client::{Client, Reply};
use serde_json::json;
use zeroize::Zeroizing;

use crate::client::{call, error_line};
use crate::commands::upstream::refuse_loose_secret_file_permissions;
use crate::commands::valid_dataset;
use crate::exit;

/// Exit code when the mailbox check fails (unreachable, refused login, not configured).
pub(crate) const MAIL_CHECK_FAILED: u8 = 6;

/// A provider preset (connection settings only).
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum PresetArg {
    /// `imap.gmail.com:993`; needs an app password.
    Gmail,
    /// `outlook.office365.com:993`; basic authentication is retired, so logins fail today.
    Outlook,
    /// Any IMAP server; needs --imap-host and --imap-port.
    Generic,
}

impl PresetArg {
    fn as_str(self) -> &'static str {
        match self {
            PresetArg::Gmail => "gmail",
            PresetArg::Outlook => "outlook",
            PresetArg::Generic => "generic",
        }
    }

    fn default_host(self) -> Option<&'static str> {
        match self {
            PresetArg::Gmail => Some("imap.gmail.com"),
            PresetArg::Outlook => Some("outlook.office365.com"),
            PresetArg::Generic => None,
        }
    }
}

/// Arguments of `add-mailbox`.
#[derive(clap::Args)]
pub struct AddArgs {
    /// Dataset id, [a-z0-9-]{1,64}.
    id: String,
    /// Provider preset.
    #[arg(long, value_enum)]
    preset: PresetArg,
    /// IMAP login name (usually the address).
    #[arg(long)]
    user: String,
    /// IMAP host (required for generic; overrides the preset otherwise).
    #[arg(long)]
    imap_host: Option<String>,
    /// IMAP port (required for generic; overrides the preset otherwise).
    #[arg(long)]
    imap_port: Option<u16>,
    /// Plaintext IMAP to 127.0.0.1, ::1, or localhost only (tests and local relays); refused for other hosts.
    #[arg(long)]
    imap_plaintext_loopback: bool,
    /// Drafts folder (default: discovered by its \Drafts attribute, or created as "Drafts").
    #[arg(long)]
    drafts_folder: Option<String>,
    /// From address of drafts when the login name is not an address.
    #[arg(long)]
    from_address: Option<String>,
    /// Display name for a newly created dataset (default: the id).
    #[arg(long)]
    name: Option<String>,
    /// Profile for a newly created dataset (default: the daemon's default profile).
    #[arg(long)]
    profile: Option<String>,
    /// File holding the app password (mode 0600); prompted without echo when absent.
    #[arg(long, value_name = "FILE")]
    password_file: Option<PathBuf>,
}

fn loopback(host: &str) -> bool {
    host == "127.0.0.1" || host == "::1" || host.eq_ignore_ascii_case("localhost")
}

/// Same rule as the daemon's header-like fields: 1 to 320 bytes, no control characters.
fn header_safe(s: &str) -> bool {
    !s.is_empty() && s.len() <= 320 && !s.chars().any(char::is_control)
}

/// Every refusal the daemon would answer with a 400, before anything is created.
/// Messages name flags, never values.
fn validate(a: &AddArgs) -> Result<()> {
    if !valid_dataset(&a.id) {
        bail!("dataset id must be 1 to 64 characters of a-z, 0-9, and -");
    }
    let (host, port) = match (&a.imap_host, a.imap_port, a.preset.default_host()) {
        (Some(h), Some(p), _) => (h.as_str(), p),
        (_, _, None) => bail!("imap_host and imap_port are required for the generic preset"),
        (h, p, Some(d)) => (h.as_deref().unwrap_or(d), p.unwrap_or(993)),
    };
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'));
    if !host_ok || port == 0 {
        bail!("invalid --imap-host or --imap-port");
    }
    if a.imap_plaintext_loopback && !loopback(host) {
        bail!(
            "imap_tls must be true for a non-loopback host; --imap-plaintext-loopback is for 127.0.0.1, ::1, and localhost only"
        );
    }
    if !header_safe(&a.user) {
        bail!("invalid --user");
    }
    if a.drafts_folder.as_deref().is_some_and(|d| !header_safe(d)) {
        bail!("invalid --drafts-folder");
    }
    if a.from_address
        .as_deref()
        .is_some_and(|f| !header_safe(f) || !f.contains('@'))
    {
        bail!("invalid --from-address");
    }
    Ok(())
}

/// The app password: from a file (refused when group or others can read it)
/// or a no-echo prompt. One trailing line break is dropped.
pub(crate) fn read_password(file: Option<&Path>, user_prompt: &str) -> Result<Zeroizing<String>> {
    let mut pw = match file {
        Some(p) => {
            refuse_loose_secret_file_permissions(p)?;
            Zeroizing::new(
                std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
            )
        }
        None => Zeroizing::new(
            rpassword::prompt_password(user_prompt).context("reading the app password")?,
        ),
    };
    while pw.ends_with(['\r', '\n']) {
        pw.pop();
    }
    let n = pw.chars().count();
    if n == 0 {
        bail!("empty app password");
    }
    if n > 512 || pw.chars().any(char::is_control) {
        bail!("password must be 1 to 512 printable characters");
    }
    Ok(pw)
}

/// Print a check reply; `true` when the mailbox answered. A failure prints the
/// daemon's fixed `type: message` (the preset's hint on `mail_auth_failed`).
fn report_check(r: &Reply) -> bool {
    if !r.status.is_success() {
        eprintln!("mailbox check failed: {}", error_line(r));
        return false;
    }
    let b = &r.body;
    let drafts = if b["drafts_folder_will_be_created"] == true {
        "will be created (Drafts)".to_string()
    } else if b["drafts_folder_resolved"] == true {
        if b["drafts_folder_configured"] == true {
            "configured folder found".to_string()
        } else {
            "found".to_string()
        }
    } else {
        "MISSING: the configured drafts folder does not exist".to_string()
    };
    println!(
        "mailbox ok: {} folders; drafts folder {drafts}",
        b["folders"]
    );
    true
}

fn check_code(ok: bool) -> u8 {
    if ok { exit::OK } else { MAIL_CHECK_FAILED }
}

/// `add-mailbox`: validate, create the dataset when needed, store the mailbox, check it.
pub fn add(c: &Client, a: AddArgs) -> Result<u8> {
    validate(&a)?;
    let pw = read_password(
        a.password_file.as_deref(),
        &format!("app password for {}: ", a.user),
    )?;
    let existing = call(c, Method::GET, "/v1/datasets", None)?;
    if !existing.status.is_success() {
        bail!("{}", error_line(&existing));
    }
    match existing
        .body
        .as_array()
        .into_iter()
        .flatten()
        .find(|d| d["id"] == a.id.as_str())
    {
        Some(d) if d["kind"] != "mailbox" => {
            bail!(
                "dataset {} is not a mailbox dataset; remove it or choose another id",
                a.id
            )
        }
        Some(_) => {}
        None => {
            let mut body = json!({
                "id": a.id,
                "name": a.name.clone().unwrap_or_else(|| a.id.clone()),
                "kind": "mailbox",
            });
            if let Some(p) = &a.profile {
                body["profile"] = json!(p);
            }
            let r = call(c, Method::POST, "/v1/datasets", Some(&body))?;
            if r.status.as_u16() != 201 {
                bail!("creating dataset {}: {}", a.id, error_line(&r));
            }
            println!(
                "dataset {} created (kind mailbox, profile {})",
                a.id,
                r.body["profile"].as_str().unwrap_or("?")
            );
        }
    }
    let mut body = json!({
        "preset": a.preset.as_str(),
        "username": a.user,
        "password": pw.as_str(),
        "imap_tls": !a.imap_plaintext_loopback,
    });
    if let Some(h) = &a.imap_host {
        body["imap_host"] = json!(h);
    }
    if let Some(p) = a.imap_port {
        body["imap_port"] = json!(p);
    }
    if let Some(d) = &a.drafts_folder {
        body["drafts_folder"] = json!(d);
    }
    if let Some(f) = &a.from_address {
        body["from_address"] = json!(f);
    }
    let r = call(
        c,
        Method::POST,
        &format!("/v1/datasets/{}/mailbox", a.id),
        Some(&body),
    )?;
    drop(body);
    if r.status.as_u16() != 201 {
        bail!("{}", error_line(&r));
    }
    println!(
        "mailbox configured for {} ({}, {}:{}, tls {}); drafts only, nothing is ever sent",
        a.id,
        r.body["preset"].as_str().unwrap_or("?"),
        r.body["imap_host"].as_str().unwrap_or("?"),
        r.body["imap_port"],
        r.body["imap_tls"]
    );
    let r = call(
        c,
        Method::POST,
        &format!("/v1/datasets/{}/mailbox/check", a.id),
        None,
    )?;
    Ok(check_code(report_check(&r)))
}

/// `check-mailbox`.
pub fn check(c: &Client, id: &str) -> Result<u8> {
    if !valid_dataset(id) {
        bail!("dataset id must be 1 to 64 characters of a-z, 0-9, and -");
    }
    let r = call(
        c,
        Method::POST,
        &format!("/v1/datasets/{id}/mailbox/check"),
        None,
    )?;
    Ok(check_code(report_check(&r)))
}

/// `remove-mailbox`.
pub fn remove(c: &Client, id: &str) -> Result<u8> {
    if !valid_dataset(id) {
        bail!("dataset id must be 1 to 64 characters of a-z, 0-9, and -");
    }
    let r = call(
        c,
        Method::DELETE,
        &format!("/v1/datasets/{id}/mailbox"),
        None,
    )?;
    if r.status.as_u16() != 204 {
        bail!("{}", error_line(&r));
    }
    println!("mailbox removed from {id}");
    Ok(exit::OK)
}
