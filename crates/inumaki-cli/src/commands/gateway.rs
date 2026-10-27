//! `inumaki gateway token new|list|revoke`.

use std::path::Path;

use anyhow::{Result, bail};
use hyper::Method;
use serde_json::json;

use crate::client::{call, connect, error_line};
use crate::exit;
use crate::{GatewayAction, TokenAction};

/// Run.
pub fn run(
    socket: Option<&Path>,
    data_dir: Option<&Path>,
    config: Option<&Path>,
    action: GatewayAction,
) -> Result<u8> {
    let c = connect(socket, data_dir, config)?;
    let GatewayAction::Token { action } = action;
    match action {
        TokenAction::New { label } => {
            let r = call(
                &c,
                Method::POST,
                "/v1/gateway/tokens",
                Some(&json!({ "label": label })),
            )?;
            if r.status.as_u16() != 201 {
                bail!("{}", error_line(&r));
            }
            println!("{}", r.body["token"].as_str().unwrap_or(""));
            eprintln!(
                "token {} ({label}) created; it is shown once and never stored in clear",
                r.body["id"]
            );
            Ok(exit::OK)
        }
        TokenAction::List => {
            let r = call(&c, Method::GET, "/v1/gateway/tokens", None)?;
            if !r.status.is_success() {
                bail!("{}", error_line(&r));
            }
            println!("{:<6} {:<24} {:<12} LAST USED", "ID", "LABEL", "CREATED");
            for t in r.body.as_array().into_iter().flatten() {
                println!(
                    "{:<6} {:<24} {:<12} {}",
                    t["id"],
                    t["label"].as_str().unwrap_or(""),
                    t["created_at"],
                    t["last_used"]
                        .as_i64()
                        .map_or("never".to_string(), |v| v.to_string())
                );
            }
            Ok(exit::OK)
        }
        TokenAction::Revoke { id } => {
            let r = call(
                &c,
                Method::DELETE,
                &format!("/v1/gateway/tokens/{id}"),
                None,
            )?;
            if r.status.as_u16() != 204 {
                bail!("{}", error_line(&r));
            }
            println!("token {id} revoked");
            Ok(exit::OK)
        }
    }
}
