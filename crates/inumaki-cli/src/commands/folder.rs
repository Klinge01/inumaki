//! `inumaki folder add|list|status|rescan|remove` (M5 spec §14).
//!
//! Everything goes through the control API and prints what the API answers:
//! paths appear on the user's own terminal only, and an error line is the
//! daemon's fixed message plus what the user typed, never a path the daemon
//! resolved.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use clap::Subcommand;
use hyper::Method;
use serde_json::json;

use crate::client::{call, connect, error_line};
use crate::commands::valid_dataset;
use crate::exit;

/// Actions for `inumaki folder`.
#[derive(Subcommand)]
pub(crate) enum FolderAction {
    /// Create a folder dataset and connect a source directory to it.
    Add {
        /// Dataset id, [a-z0-9-]{1,64}.
        id: String,
        /// Display name.
        #[arg(long)]
        name: String,
        /// Source directory (made absolute against the current directory).
        #[arg(long)]
        source: PathBuf,
        /// Where restored outbox files are written (default: under the daemon's outbox root).
        #[arg(long)]
        outbox_destination: Option<PathBuf>,
        /// Profile (default: the daemon's default profile).
        #[arg(long)]
        profile: Option<String>,
    },
    /// List connected folders with their state and counts.
    List,
    /// One folder's connection details.
    Status {
        /// Dataset id.
        id: String,
    },
    /// Re-check every file of a folder now, retrying blocked and pending ones.
    Rescan {
        /// Dataset id.
        id: String,
    },
    /// Disconnect a folder and delete its mirror; the source and the outbox destination are never touched.
    Remove {
        /// Dataset id.
        id: String,
        /// Also delete the dataset with all its tokens.
        #[arg(long)]
        dataset: bool,
    },
}

/// The path as the daemon needs it: absolute, otherwise as typed. Not
/// canonicalized: the daemon resolves symlinks itself. A path that is not
/// UTF-8 cannot travel in the JSON body unchanged, so it is refused here
/// rather than sent as a different path.
fn absolute(p: &Path) -> Result<String> {
    let abs =
        std::path::absolute(p).map_err(|_| anyhow::anyhow!("cannot make the path absolute"))?;
    match abs.to_str() {
        Some(s) => Ok(s.to_string()),
        None => bail!("path must be UTF-8"),
    }
}

fn check_id(id: &str) -> Result<()> {
    if !valid_dataset(id) {
        bail!("dataset id must match [a-z0-9-]{{1,64}}");
    }
    Ok(())
}

pub fn run(
    socket: Option<&Path>,
    data_dir: Option<&Path>,
    config: Option<&Path>,
    action: FolderAction,
) -> Result<u8> {
    match &action {
        FolderAction::Add { id, .. }
        | FolderAction::Status { id }
        | FolderAction::Rescan { id }
        | FolderAction::Remove { id, .. } => check_id(id)?,
        FolderAction::List => {}
    }
    let c = connect(socket, data_dir, config)?;
    match action {
        FolderAction::Add {
            id,
            name,
            source,
            outbox_destination,
            profile,
        } => {
            let mut folder = json!({ "source": absolute(&source)? });
            if let Some(d) = outbox_destination {
                folder["outbox_destination"] = json!(absolute(&d)?);
            }
            let mut body = json!({ "id": id, "name": name, "kind": "folder" });
            if let Some(p) = profile {
                body["profile"] = json!(p);
            }
            let r = call(&c, Method::POST, "/v1/datasets", Some(&body))?;
            if r.status.as_u16() != 201 {
                bail!("{}", error_line(&r));
            }
            let reply = call(
                &c,
                Method::POST,
                &format!("/v1/datasets/{id}/folder"),
                Some(&folder),
            );
            let line = match &reply {
                Ok(r) if r.status.as_u16() == 201 => None,
                Ok(r) => Some(error_line(r)),
                Err(e) => Some(e.to_string()),
            };
            if let Some(line) = line {
                // A refused or failed connect does not leave its new, empty
                // dataset behind: the corrected command can be run again.
                let undone = call(&c, Method::DELETE, &format!("/v1/datasets/{id}"), None)
                    .is_ok_and(|d| d.status.as_u16() == 204);
                if undone {
                    bail!("{line} (the dataset was not kept)");
                }
                bail!("{line}");
            }
            let r = reply?;
            println!(
                "connected {id}: mirror {} (outbox {})",
                r.body["mirror"].as_str().unwrap_or("?"),
                r.body["outbox"].as_str().unwrap_or("?")
            );
        }
        FolderAction::List => {
            let r = call(&c, Method::GET, "/v1/folders", None)?;
            if !r.status.is_success() {
                bail!("{}", error_line(&r));
            }
            println!(
                "mirror root {}",
                r.body["mirror_root"].as_str().unwrap_or("?")
            );
            println!(
                "{:<18} {:<10} {:<22} {:>8} {:>8} {:>8} {:>8}",
                "DATASET", "STATE", "ERROR", "MIRRORED", "BLOCKED", "UNSUPP", "PENDING"
            );
            for f in r.body["folders"].as_array().into_iter().flatten() {
                println!(
                    "{:<18} {:<10} {:<22} {:>8} {:>8} {:>8} {:>8}",
                    f["dataset"].as_str().unwrap_or("?"),
                    f["state"].as_str().unwrap_or("?"),
                    f["error"].as_str().unwrap_or("-"),
                    f["files"]["mirrored"],
                    f["files"]["blocked"],
                    f["files"]["unsupported"],
                    f["files"]["pending"]
                );
            }
        }
        FolderAction::Status { id } => {
            let r = call(&c, Method::GET, &format!("/v1/datasets/{id}/folder"), None)?;
            if !r.status.is_success() {
                bail!("{}", error_line(&r));
            }
            println!("{}", serde_json::to_string_pretty(&r.body)?);
        }
        FolderAction::Rescan { id } => {
            let r = call(
                &c,
                Method::POST,
                &format!("/v1/datasets/{id}/folder/rescan"),
                None,
            )?;
            if r.status.as_u16() != 202 {
                bail!("{}", error_line(&r));
            }
            println!("queued {} files", r.body["queued"]);
        }
        FolderAction::Remove { id, dataset } => {
            let r = call(
                &c,
                Method::DELETE,
                &format!("/v1/datasets/{id}/folder"),
                None,
            )?;
            // With --dataset, a dataset that has no folder is still deleted.
            let no_folder =
                r.status.as_u16() == 404 && r.body["error"]["message"] == "folder not configured";
            if r.status.as_u16() != 204 && !(dataset && no_folder) {
                bail!("{}", error_line(&r));
            }
            if r.status.as_u16() == 204 {
                println!("removed the folder of {id}");
            }
            if dataset {
                let r = call(&c, Method::DELETE, &format!("/v1/datasets/{id}"), None)?;
                if r.status.as_u16() != 204 {
                    bail!("{}", error_line(&r));
                }
                println!("removed {id}");
            }
        }
    }
    Ok(exit::OK)
}
