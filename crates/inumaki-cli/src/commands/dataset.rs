//! `inumaki dataset add|list|remove|rotate` (`entities`/`forget` in
//! `commands::entities`, `upstream` in `commands::upstream`).

use std::path::Path;

use anyhow::{Result, bail};
use hyper::Method;
use serde_json::json;

use crate::DatasetAction;
use crate::client::{call, connect, error_line};
use crate::exit;

pub fn run(
    socket: Option<&Path>,
    data_dir: Option<&Path>,
    config: Option<&Path>,
    action: DatasetAction,
) -> Result<u8> {
    let action = match action {
        DatasetAction::Upstream { action } => {
            return crate::commands::upstream::run(socket, data_dir, config, action);
        }
        DatasetAction::Entities {
            id,
            show_values,
            limit,
            json,
        } => {
            return crate::commands::entities::entities(
                socket,
                data_dir,
                config,
                &id,
                show_values,
                limit,
                json,
            );
        }
        DatasetAction::Forget { id, token, value } => {
            return crate::commands::entities::forget(socket, data_dir, config, &id, token, value);
        }
        DatasetAction::AddMailbox(args) => {
            let c = connect(socket, data_dir, config)?;
            return crate::commands::mailbox::add(&c, args);
        }
        DatasetAction::CheckMailbox { id } => {
            let c = connect(socket, data_dir, config)?;
            return crate::commands::mailbox::check(&c, &id);
        }
        DatasetAction::RemoveMailbox { id } => {
            let c = connect(socket, data_dir, config)?;
            return crate::commands::mailbox::remove(&c, &id);
        }
        other => other,
    };
    let c = connect(socket, data_dir, config)?;
    match action {
        DatasetAction::Add {
            id,
            name,
            profile,
            rotation_days,
            grace_days,
        } => {
            let mut body = json!({ "id": id, "name": name });
            if let Some(p) = profile {
                body["profile"] = json!(p);
            }
            if let Some(r) = rotation_days {
                body["rotation_days"] = json!(r);
            }
            if let Some(g) = grace_days {
                body["grace_days"] = json!(g);
            }
            let r = call(&c, Method::POST, "/v1/datasets", Some(&body))?;
            if r.status.as_u16() != 201 {
                bail!("{}", error_line(&r));
            }
            println!(
                "created {} ({}, rotation {} d, grace {} d, epoch {})",
                r.body["id"].as_str().unwrap_or("?"),
                r.body["profile"].as_str().unwrap_or("?"),
                r.body["rotation_days"],
                r.body["grace_days"],
                r.body["epoch_id"]
            );
        }
        DatasetAction::List => {
            let r = call(&c, Method::GET, "/v1/datasets", None)?;
            if !r.status.is_success() {
                bail!("{}", error_line(&r));
            }
            println!(
                "{:<18} {:<14} {:>8} {:>12} {:>8}",
                "ID", "PROFILE", "EPOCH", "SINCE", "ENTRIES"
            );
            for d in r.body.as_array().into_iter().flatten() {
                println!(
                    "{:<18} {:<14} {:>8} {:>12} {:>8}",
                    d["id"].as_str().unwrap_or("?"),
                    d["profile"].as_str().unwrap_or("?"),
                    d["epoch_id"],
                    d["epoch_started_at"],
                    d["entries"]
                );
            }
        }
        DatasetAction::Remove { id } => {
            let r = call(&c, Method::DELETE, &format!("/v1/datasets/{id}"), None)?;
            if r.status.as_u16() != 204 {
                bail!("{}", error_line(&r));
            }
            println!("removed {id}");
        }
        DatasetAction::Rotate { id } => {
            let r = call(&c, Method::POST, &format!("/v1/datasets/{id}/rotate"), None)?;
            if !r.status.is_success() {
                bail!("{}", error_line(&r));
            }
            println!(
                "rotated {}: epoch {} closed, epoch {} started",
                id, r.body["old_epoch"], r.body["new_epoch"]
            );
        }
        DatasetAction::Upstream { .. }
        | DatasetAction::Entities { .. }
        | DatasetAction::Forget { .. }
        | DatasetAction::AddMailbox(_)
        | DatasetAction::CheckMailbox { .. }
        | DatasetAction::RemoveMailbox { .. } => unreachable!("handled above"),
    }
    Ok(exit::OK)
}
