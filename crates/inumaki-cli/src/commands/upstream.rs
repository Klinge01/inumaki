//! `inumaki dataset upstream add|list|remove|accept-schema`.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context as _, Result, anyhow, bail};
use hyper::Method;
use inumaki_adapters::protect::credential_like;
use serde_json::json;

use crate::UpstreamAction;
use crate::client::{call, connect, error_line};
use crate::exit;

fn kv(list: &[String], what: &str) -> Result<BTreeMap<String, String>> {
    let mut m = BTreeMap::new();
    for item in list {
        let (k, v) = item
            .split_once('=')
            .with_context(|| format!("{what} must be KEY=VALUE"))?;
        m.insert(k.to_string(), v.to_string());
    }
    Ok(m)
}

/// Refuse a `--header` or `--env` whose name reads like a credential
/// (review M6): the value would sit in plain shell history / process
/// listings, in the non-secret `headers`/`env` column, and in the
/// upstreams API listing, when `--secret-header` / `--secret-env` exist
/// for exactly this case. `what` is the kind of name, `flag` the flag it
/// came from, and `secret_flag` the one to use instead.
fn refuse_credential_like(
    names: &BTreeMap<String, String>,
    what: &str,
    flag: &str,
    secret_flag: &str,
) -> Result<()> {
    for k in names.keys() {
        if credential_like(k) {
            bail!(
                "{what} {k} looks like a credential; pass it with {secret_flag} instead of {flag}"
            );
        }
    }
    Ok(())
}

/// Refuse a secret file that group or others can read or write (review I4);
/// a no-op on non-unix platforms, which have no equivalent permission bits.
#[cfg(unix)]
pub(crate) fn refuse_loose_secret_file_permissions(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(p)
        .with_context(|| format!("reading {}", p.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        bail!(
            "{} is readable or writable by group or others; chmod 600 it before use",
            p.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn refuse_loose_secret_file_permissions(_p: &Path) -> Result<()> {
    Ok(())
}

fn secrets(names: &[String], file: Option<&Path>, what: &str) -> Result<BTreeMap<String, String>> {
    let mut m: BTreeMap<String, String> = match file {
        Some(p) => {
            refuse_loose_secret_file_permissions(p)?;
            let s =
                std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
            // A fixed message, not `.with_context` (review I5): serde's own
            // error text can quote the offending JSON value, and a mistyped
            // secrets file (e.g. a bare number instead of a string) would
            // then put the secret itself into the process's stderr and, via
            // `main`'s `{e:#}`, the full source chain.
            serde_json::from_str(&s)
                .map_err(|_| anyhow!("{} must be a JSON object of strings", p.display()))?
        }
        None => BTreeMap::new(),
    };
    for n in names {
        let v = rpassword::prompt_password(format!("value for {what} {n}: "))
            .context("reading the secret value")?;
        if v.is_empty() {
            bail!("empty value for {n}");
        }
        m.insert(n.clone(), v);
    }
    Ok(m)
}

/// Run.
pub fn run(
    socket: Option<&Path>,
    data_dir: Option<&Path>,
    config: Option<&Path>,
    action: UpstreamAction,
) -> Result<u8> {
    let c = connect(socket, data_dir, config)?;
    match action {
        UpstreamAction::Add {
            dataset,
            name,
            stdio,
            http,
            env,
            header,
            cwd,
            content_policy,
            secret_env,
            secret_env_file,
            secret_header,
            secret_headers_file,
        } => {
            let (kind, command, args, url) = match (stdio.is_empty(), http) {
                (false, None) => ("stdio", Some(stdio[0].clone()), stdio[1..].to_vec(), None),
                (true, Some(u)) => ("http", None, Vec::new(), Some(u)),
                _ => bail!("exactly one of --stdio or --http is required"),
            };
            // Checked before anything is sent: a refused name leaves no
            // dataset or upstream behind.
            let headers = kv(&header, "--header")?;
            refuse_credential_like(&headers, "header", "--header", "--secret-header")?;
            let env = kv(&env, "--env")?;
            refuse_credential_like(&env, "environment variable", "--env", "--secret-env")?;
            let existing = call(&c, Method::GET, "/v1/datasets", None)?;
            let exists = existing
                .body
                .as_array()
                .into_iter()
                .flatten()
                .any(|d| d["id"] == dataset.as_str());
            if !exists {
                let r = call(
                    &c,
                    Method::POST,
                    "/v1/datasets",
                    Some(&json!({ "id": dataset, "name": dataset, "profile": "strict" })),
                )?;
                if r.status.as_u16() != 201 {
                    bail!("creating dataset {dataset}: {}", error_line(&r));
                }
                println!("dataset {dataset} created with profile strict");
            }
            let policy: serde_json::Value = match content_policy {
                Some(p) => serde_json::from_str(
                    &std::fs::read_to_string(&p)
                        .with_context(|| format!("reading {}", p.display()))?,
                )
                .with_context(|| format!("parsing {}", p.display()))?,
                None => json!({}),
            };
            let body = json!({
                "name": name, "kind": kind, "command": command, "args": args, "cwd": cwd, "url": url,
                "env": env, "headers": headers,
                "secret_env": secrets(&secret_env, secret_env_file.as_deref(), "env")?,
                "secret_headers": secrets(&secret_header, secret_headers_file.as_deref(), "header")?,
                "content_policy": policy,
            });
            let r = call(
                &c,
                Method::POST,
                &format!("/v1/datasets/{dataset}/upstreams"),
                Some(&body),
            )?;
            if r.status.as_u16() != 201 {
                bail!("{}", error_line(&r));
            }
            println!(
                "upstream {name} added to {dataset} (kind {kind}, policy {})",
                if policy.as_object().is_some_and(|o| o.is_empty()) {
                    "none: text-only tools; structured content will be rejected"
                } else {
                    "reviewed"
                }
            );
            Ok(exit::OK)
        }
        UpstreamAction::List { dataset } => {
            let r = call(
                &c,
                Method::GET,
                &format!("/v1/datasets/{dataset}/upstreams"),
                None,
            )?;
            if !r.status.is_success() {
                bail!("{}", error_line(&r));
            }
            println!(
                "{:<20} {:<6} {:<8} {:<10} FINGERPRINT",
                "NAME", "KIND", "ENABLED", "POLICY"
            );
            for u in r.body.as_array().into_iter().flatten() {
                let policy = if u["content_policy"]
                    .as_object()
                    .is_some_and(|o| o.is_empty())
                {
                    "none"
                } else {
                    "reviewed"
                };
                println!(
                    "{:<20} {:<6} {:<8} {:<10} {}",
                    u["name"].as_str().unwrap_or(""),
                    u["kind"].as_str().unwrap_or(""),
                    u["enabled"],
                    policy,
                    u["schema_fingerprint"].as_str().unwrap_or("-")
                );
            }
            Ok(exit::OK)
        }
        UpstreamAction::Remove { dataset, name } => {
            let r = call(
                &c,
                Method::DELETE,
                &format!("/v1/datasets/{dataset}/upstreams/{name}"),
                None,
            )?;
            if r.status.as_u16() != 204 {
                bail!("{}", error_line(&r));
            }
            println!("upstream {name} removed");
            Ok(exit::OK)
        }
        UpstreamAction::AcceptSchema {
            dataset,
            name,
            fingerprint,
        } => {
            let fp = match fingerprint {
                Some(f) => f,
                None => {
                    let st = call(&c, Method::GET, "/v1/status", None)?;
                    st.body["gateway"]["datasets"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .find(|d| d["id"] == dataset.as_str())
                        .and_then(|d| d["upstreams"].as_array())
                        .into_iter()
                        .flatten()
                        .find(|u| u["name"] == name.as_str())
                        .and_then(|u| u["schema_fingerprint"].as_str())
                        .map(str::to_string)
                        .context("the upstream is not running or has no fingerprint yet; pass --fingerprint")?
                }
            };
            let r = call(
                &c,
                Method::POST,
                &format!("/v1/datasets/{dataset}/upstreams/{name}/accept-schema"),
                Some(&json!({ "fingerprint": fp })),
            )?;
            if r.status.as_u16() != 204 {
                bail!("{}", error_line(&r));
            }
            println!("schema {fp} accepted for {name}");
            Ok(exit::OK)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(ns: &[&str]) -> BTreeMap<String, String> {
        ns.iter()
            .map(|n| (n.to_string(), "v".to_string()))
            .collect()
    }

    #[test]
    fn credential_like_env_names_are_refused_with_the_secret_flag() {
        for n in [
            "GITHUB_TOKEN",
            "OPENAI_API_KEY",
            "DB_PASSWORD",
            "AWS_SECRET_ACCESS_KEY",
        ] {
            let e = refuse_credential_like(
                &names(&[n]),
                "environment variable",
                "--env",
                "--secret-env",
            )
            .unwrap_err()
            .to_string();
            assert!(e.contains("--secret-env"), "{e}");
            assert!(!e.contains("=v"), "{e}");
        }
        refuse_credential_like(
            &names(&["PATH", "HOME", "LOG_LEVEL", "NODE_ENV"]),
            "environment variable",
            "--env",
            "--secret-env",
        )
        .unwrap();
    }

    #[test]
    fn credential_like_headers_are_refused() {
        for n in ["Authorization", "Cookie", "X-Api-Key"] {
            assert!(
                refuse_credential_like(&names(&[n]), "header", "--header", "--secret-header")
                    .is_err()
            );
        }
        refuse_credential_like(
            &names(&["Accept", "X-Tenant"]),
            "header",
            "--header",
            "--secret-header",
        )
        .unwrap();
    }
}
