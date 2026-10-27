//! `inumaki connect status|apply|revert` (M6 spec §3): the terminal front of
//! `inumaki-adapters`. The daemon supplies datasets, tokens, folder and
//! proxy facts; this command writes the harness files.
//!
//! Output prints counts and fixed sentences only. It never prints a server
//! name, a path, the gateway token, or the proxy client header's value. The
//! exceptions are the manual snippet of a refused edit, which the user must
//! copy into the file by hand, and a `--protect` name the user typed.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow, bail};
use clap::Subcommand;
use inumaki_adapters::protect::{
    DefinitionIndex, dataset_id_for, mail_entry_name, split, upstream_name,
};
use inumaki_adapters::*;
use inumaki_client::{Client, ClientError, CreateDataset, DatasetKind, SecretMap, UpstreamCreate};
use zeroize::Zeroizing;

use crate::exit;

/// `inumaki connect` actions.
#[derive(Subcommand)]
pub enum ConnectAction {
    /// Show the MCP, Files, and Chat paths of each detected harness.
    Status {
        /// claude-code, codex, hermes, or openclaw; all when omitted.
        harness: Option<String>,
    },
    /// Connect a harness: back up and rewrite its configuration.
    Apply {
        /// claude-code, codex, hermes, or openclaw.
        harness: String,
        /// Put this MCP server behind the gateway (repeatable).
        #[arg(long)]
        protect: Vec<String>,
        /// Do not install the tool-result hook.
        #[arg(long)]
        no_hook: bool,
        /// Route chat through the proxy (the default).
        #[arg(long, conflicts_with = "no_chat")]
        chat: bool,
        /// Do not route chat through the proxy.
        #[arg(long)]
        no_chat: bool,
        /// Do not add the mirror.
        #[arg(long)]
        no_files: bool,
        /// Route Codex's ChatGPT-login chat through the proxy (unverified
        /// until the proxy's own verification). It refines the chat route, so
        /// it conflicts with `--no-chat`.
        #[arg(long, conflicts_with = "no_chat")]
        chatgpt: bool,
    },
    /// Restore a harness's configuration from before inumaki.
    Revert {
        /// claude-code, codex, hermes, or openclaw.
        harness: String,
        /// Keep the backup after reverting.
        #[arg(long)]
        keep_backup: bool,
    },
}

fn harness(s: &str) -> Result<HarnessId> {
    HarnessId::parse(s)
        .ok_or_else(|| anyhow!("unknown harness {s}: use claude-code, codex, hermes, or openclaw"))
}

fn rt() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("runtime")
}

fn missing(e: &ClientError) -> bool {
    e.status() == Some(404)
}

fn describe(s: &PathState) -> String {
    match s {
        PathState::NotConnected { reason } => format!(
            "not connected{}",
            reason
                .map(|r| format!(" ({})", r.sentence()))
                .unwrap_or_default()
        ),
        PathState::Connected { detail } if detail.total > 0 => {
            format!(
                "connected ({} of {} protected)",
                detail.protected, detail.total
            )
        }
        PathState::Connected { detail } => format!(
            "connected{}",
            detail
                .note
                .map(|r| format!(" ({})", r.sentence()))
                .unwrap_or_default()
        ),
        PathState::Unverified { reason } => format!("unverified: {}", reason.sentence()),
        PathState::Unsupported { reason } => format!("not supported: {}", reason.sentence()),
        PathState::Broken { reason } => format!("broken: {}", reason.sentence()),
    }
}

/// One harness in `connect status`: its paths, the hook, and, when a path
/// needs lines added by hand, those lines and the fixed note. Printed to the
/// user's own terminal, never to a log; no token or client-header value is in it.
fn render_status(ad: &dyn HarnessAdapter, inst: &Installation, sys: &SystemState) -> String {
    let st = ad.status(inst, sys);
    let mut out = format!(
        "{}{}\n",
        ad.id().as_str(),
        if inst.tested {
            ""
        } else {
            " (untested version)"
        }
    );
    for (path, state) in &st.paths {
        out.push_str(&format!("  {path:?}: {}\n", describe(state)));
    }
    out.push_str(&format!("  hook: {}\n", describe_hook(&st.hook)));
    if let Some(m) = ad.manual_setup(&st, sys) {
        out.push_str("  add by hand:\n");
        for line in m.lines.lines() {
            out.push_str(&format!("    {line}\n"));
        }
        out.push_str(&format!("  note: {}\n", m.note));
    }
    out
}

fn describe_hook(h: &HookState) -> String {
    match h {
        HookState::NotInstalled => "not installed".to_string(),
        HookState::Installed => "installed".to_string(),
        HookState::Pending { reason } => format!("pending: {}", reason.sentence()),
        HookState::NotSupported { reason } => format!("not supported: {}", reason.sentence()),
        HookState::Broken { reason } => format!("broken: {}", reason.sentence()),
    }
}

/// What `connect revert` does after revoking the harness's tokens.
#[derive(Debug, PartialEq, Eq)]
enum RevertStep {
    /// A backup exists: restore the files from it.
    RestoreFiles,
    /// No backup (a refused first connect): nothing to restore.
    NothingToRestore,
    /// No active backup loads, but a backup manifest exists that does not:
    /// the files may still hold inumaki's edits, so this is an error, never
    /// "no backup".
    Unreadable,
}

fn revert_step(has_backup: bool, unreadable_manifest: bool) -> RevertStep {
    match (has_backup, unreadable_manifest) {
        (true, _) => RevertStep::RestoreFiles,
        (false, true) => RevertStep::Unreadable,
        (false, false) => RevertStep::NothingToRestore,
    }
}

/// Some backup of `h` has a manifest that does not load.
fn has_unreadable_backup(store: &BackupStore, h: HarnessId) -> bool {
    store.list(h).iter().any(|id| store.load(h, id).is_err())
}

/// Whether a failed apply that showed no snippet should revoke the token
/// it minted. A refusal with a snippet never does: the user pastes that token.
fn revoke_minted_after(e: &AdapterError) -> bool {
    e.snippet().is_none()
}

/// Facts from the daemon for status (spec §4.1 `SystemState`).
async fn system_state(
    c: &Client,
    socket: &Path,
    store: &BackupStore,
    h: HarnessId,
    bin: Option<PathBuf>,
) -> SystemState {
    let mut sys = SystemState {
        applied: store.active(h),
        hook_binary: bin.map(|b| b.join("inumaki-hook")),
        hook_socket: Some(socket.to_path_buf()),
        ..Default::default()
    };
    if let Ok(st) = c.status().await {
        sys.service_up = true;
        sys.gateway_base = format!("http://{}", st.gateway.listen);
        for d in &st.gateway.datasets {
            if d.upstreams.iter().any(|u| u.state == "running") {
                sys.datasets_running.insert(d.id.clone());
            }
        }
    }
    if let Ok(f) = c.folders().await {
        let watching: Vec<_> = f
            .folders
            .iter()
            .filter(|x| x.state == inumaki_client::FolderState::Watching)
            .collect();
        sys.folders = Some(FolderInfo {
            mirror_root: f.mirror_root.clone().into(),
            watching: watching.len() as u32,
            outboxes: watching.iter().map(|x| PathBuf::from(&x.outbox)).collect(),
        });
    }
    if let Ok(p) = c.proxy().await {
        use inumaki_client::{ClientKind, RoutePrefix, RouteState};
        sys.proxy = Some(ProxyInfo {
            routes: p
                .routes
                .iter()
                .map(|r| RouteInfo {
                    route: match r.prefix {
                        RoutePrefix::Anthropic => Route::Anthropic,
                        RoutePrefix::Openai => Route::Openai,
                        RoutePrefix::Codex => Route::Codex,
                    },
                    base_url: r.base_url.clone(),
                    failing: r.state == RouteState::Failing,
                })
                .collect(),
            clients_seen: p
                .clients
                .iter()
                .filter_map(|x| match x.client {
                    ClientKind::ClaudeCode => Some(HarnessId::ClaudeCode),
                    ClientKind::Codex => Some(HarnessId::Codex),
                    ClientKind::Hermes => Some(HarnessId::Hermes),
                    ClientKind::Openclaw => Some(HarnessId::Openclaw),
                    ClientKind::Other => None,
                })
                .collect(),
            codex_chatgpt_verified: p.oauth.codex_chatgpt.verified_in_build,
            client_header: Some(ClientHeader::new(Zeroizing::new(p.client_header.value))),
        });
    }
    sys
}

/// The helper-binary directory: `GET /v1/service` `bin_dir` (M6-3), else
/// the directory of this executable.
async fn bin_dir(c: &Client) -> Option<PathBuf> {
    match c.service().await {
        Ok(s) => Some(PathBuf::from(s.bin_dir)),
        Err(_) => std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(Path::to_path_buf)),
    }
}

/// Run.
pub fn run(
    socket: Option<&Path>,
    data_dir: Option<&Path>,
    config: Option<&Path>,
    action: ConnectAction,
) -> Result<u8> {
    // Absolute (final review m1): the socket is written into the hook
    // command, which runs in the session's directory, and status compares
    // it with the registered one.
    let socket = std::path::absolute(crate::client::resolve_socket(socket, data_dir, config)?)
        .context("resolving the socket path")?;
    let data = std::path::absolute(inumakid::dirs::resolve_data_dir(data_dir))
        .context("resolving the data directory")?;
    let c = Client::new(&socket);
    let store = BackupStore::new(&data);
    let env = ProbeEnv::from_process().ok_or_else(|| anyhow!("HOME is not set"))?;
    let rt = rt()?;
    match action {
        ConnectAction::Status { harness: h } => {
            let wanted = h.as_deref().map(harness).transpose()?;
            let bin = rt.block_on(bin_dir(&c));
            for ad in all_adapters() {
                if wanted.is_some_and(|w| w != ad.id()) {
                    continue;
                }
                let Some(inst) = ad.detect(&env) else {
                    continue;
                };
                let sys = rt.block_on(system_state(&c, &socket, &store, ad.id(), bin.clone()));
                print!("{}", render_status(ad.as_ref(), &inst, &sys));
            }
            Ok(exit::OK)
        }
        ConnectAction::Apply {
            harness: h,
            protect,
            no_hook,
            chat,
            no_chat,
            no_files,
            chatgpt,
        } => {
            let h = harness(&h)?;
            let ad = adapter(h);
            let inst = ad
                .detect(&env)
                .ok_or_else(|| anyhow!("{} is not installed or configured", h.as_str()))?;
            let want = Want {
                hook: !no_hook,
                chat: chat_wanted(chat, no_chat),
                chat_explicit: chat,
                files: !no_files,
                chatgpt,
            };
            let (plan, minted) = rt.block_on(build_plan(
                &c,
                &socket,
                &data,
                ad.as_ref(),
                &inst,
                &protect,
                want,
            ))?;
            // Read before the write (the apply never changes what they read).
            let warnings = warning_lines(ad.as_ref(), &inst, &plan);
            match ad.apply(&inst, &plan) {
                Ok(b) => {
                    println!(
                        "connected {} (backup {}); the change takes effect in the next session",
                        h.as_str(),
                        b.id
                    );
                    for w in &warnings {
                        eprintln!("{w}");
                    }
                    if let Some(id) = minted {
                        rt.block_on(revoke_old_tokens(&c, h, id))?;
                    }
                    Ok(exit::OK)
                }
                Err(e) => {
                    let revoke = revoke_minted_after(&e);
                    if let Some(snippet) = e.snippet() {
                        println!("{snippet}");
                    }
                    match minted {
                        Some(id) if revoke => {
                            let _ = rt.block_on(c.revoke_token(id));
                        }
                        Some(_) => eprintln!(
                            "note: the token in the lines above stays valid until `inumaki connect revert {}` (which revokes it) or a new `connect apply`",
                            h.as_str()
                        ),
                        None => {}
                    }
                    if e.snippet().is_some() {
                        bail!("{e}; add the lines above by hand, or fix the file and run again")
                    }
                    bail!("{e}; fix the problem and run again")
                }
            }
        }
        ConnectAction::Revert {
            harness: h,
            keep_backup,
        } => {
            let h = harness(&h)?;
            let ad = adapter(h);
            let active = store.active(h);
            // Revoke first: the revert may delete the backup, and a token
            // left in a drifted file must stop working either way.
            rt.block_on(revoke_all_tokens(&c, h)).map_err(|e| {
                anyhow!("{e}; is the service running? Start it and run revert again")
            })?;
            let unreadable = active.is_none() && has_unreadable_backup(&store, h);
            let (inst, mut b) = match (revert_step(active.is_some(), unreadable), active) {
                (RevertStep::RestoreFiles, Some(b)) => {
                    let inst = ad
                        .detect(&env)
                        .ok_or_else(|| anyhow!("{} is not installed or configured", h.as_str()))?;
                    (inst, b)
                }
                (RevertStep::Unreadable, _) => {
                    // Not "no backup": the files may still route through
                    // inumaki and hold the client header.
                    bail!(
                        "{}'s inumaki backup cannot be read, so no files were restored; its inumaki gateway tokens are revoked. Its files may still hold inumaki's entries and client header: check the backups under the inumaki data directory, or remove inumaki's entries by hand",
                        h.as_str()
                    );
                }
                _ => {
                    // A refused first connect leaves no backup but may have
                    // minted a token the user pasted: it is revoked now.
                    println!(
                        "{} has no inumaki backup, so no files were changed; its inumaki gateway tokens are revoked",
                        h.as_str()
                    );
                    return Ok(exit::OK);
                }
            };
            b.keep_after_revert = keep_backup;
            let r = ad.revert_final(&inst, &b)?;
            println!(
                "reverted {}: {} file(s) restored exactly, {} key by key, {} key(s) left as you changed them",
                h.as_str(),
                r.byte_exact.len(),
                r.key_level.len(),
                r.conflicts.len()
            );
            if r.codex_trust_left {
                // The revert stands (its files are restored): a warning, not a failure.
                eprintln!("warning: {CODEX_TRUST_LEFT_NOTE}");
            }
            if r.client_header_left {
                // The secret is still in the file and goes to the model
                // provider: do not report success.
                bail!(
                    "the inumaki client header could not be removed from {}'s settings; it will be sent to your model provider until removed: delete the {} line by hand",
                    h.as_str(),
                    CLIENT_HEADER_NAME
                );
            }
            Ok(exit::OK)
        }
    }
}

/// The adapter's fixed connect warnings as `warning: <sentence>` lines (the
/// same closed set the app shows): no value from the file, no path.
fn warning_lines(ad: &dyn HarnessAdapter, inst: &Installation, plan: &ConnectPlan) -> Vec<String> {
    ad.connect_warnings(inst, plan)
        .into_iter()
        .map(|w| format!("warning: {}", w.sentence()))
        .collect()
}

/// Whether this apply writes the chat route: an explicit flag wins, else
/// [`CHAT_ROUTE_DEFAULT`]. clap rejects both flags together.
fn chat_wanted(chat: bool, no_chat: bool) -> bool {
    if no_chat {
        false
    } else {
        chat || CHAT_ROUTE_DEFAULT
    }
}

/// Whether the chat route is written for a proxy in `state` (final review
/// I4). Only a running proxy owns its address: a base URL written for one
/// that is disabled or not listening (bind failed or serve ended) sends the
/// conversation and the harness's credentials to whatever holds the address,
/// or breaks the harness, and the client header of a disabled proxy is not valid. The
/// default apply skips the route with a warning; `--chat` fails.
fn chat_route(state: inumaki_client::ProxyState, explicit: bool) -> Result<bool> {
    let Some(why) = state.chat_route_blocker() else {
        return Ok(true);
    };
    if explicit {
        bail!(
            "the proxy is {why}; the chat route was not written. Start the proxy (see `inumaki status`) or apply without --chat"
        );
    }
    if let Some(w) = state.chat_route_skipped() {
        eprintln!("warning: {w}");
    }
    Ok(false)
}

/// What the user asked to connect.
#[derive(Clone, Copy)]
struct Want {
    hook: bool,
    chat: bool,
    /// `--chat` was given (not only the default).
    chat_explicit: bool,
    files: bool,
    chatgpt: bool,
}

async fn build_plan(
    c: &Client,
    socket: &Path,
    data: &Path,
    ad: &dyn HarnessAdapter,
    inst: &Installation,
    protect: &[String],
    want: Want,
) -> Result<(ConnectPlan, Option<i64>)> {
    let st = c
        .status()
        .await
        .map_err(|e| anyhow!("{e}; is the service running? start it with `inumaki daemon`"))?;
    let gateway_base = format!("http://{}", st.gateway.listen);
    let servers = ad.mcp_servers(inst, &gateway_base)?;
    let mut entries: Vec<GatewayEntry> = Vec::new();
    // Entries already behind the gateway get the new token (spec §4.5, Reconnect).
    for s in servers.iter().filter(|s| s.gateway) {
        if let Transport::Http { url } = &s.transport {
            entries.push(GatewayEntry {
                name: s.name.clone(),
                scope: s.scope.clone(),
                url: url.clone(),
                // Inumaki's own entry (it points at the gateway): the user's
                // approval setting on it is theirs and is kept.
                approval_mode: s.approval_mode.clone(),
            });
        }
    }
    // Protect: one dataset per definition.
    let datasets = c.datasets().await?;
    let mut taken: BTreeSet<String> = datasets.iter().map(|d| d.id.clone()).collect();
    // Only `--protect` needs the index: a corrupt one must not block a
    // plain connect.
    let mut index = if protect.is_empty() {
        None
    } else {
        Some(DefinitionIndex::load(data).context("loading the definition index")?)
    };
    let login_path = std::env::var("PATH").ok();
    // Validate every name before anything is created: a typo in the second
    // `--protect` must not leave the first one's dataset behind.
    let mut chosen = Vec::new();
    for name in protect {
        let s = servers
            .iter()
            .find(|s| &s.name == name && !s.gateway)
            .ok_or_else(|| anyhow!("no unprotected MCP server named {name}"))?;
        if s.needs_oauth {
            bail!("{name} needs the MCP OAuth flow; it cannot be protected yet");
        }
        chosen.push(s);
    }
    for s in chosen {
        let index = index
            .as_mut()
            .ok_or_else(|| anyhow!("the definition index is not loaded"))?;
        let def = index.id_for(s);
        let id = match index.get(&def) {
            Some(id) if taken.contains(id) => id.to_string(),
            _ => {
                let id = dataset_id_for(&s.name, &taken);
                c.create_dataset(&CreateDataset::new(&id, &s.name)).await?;
                let parts = split(s, login_path.as_deref());
                let mut up = match parts.kind {
                    "http" => UpstreamCreate::http(
                        upstream_name(&s.name),
                        parts.url.clone().unwrap_or_default(),
                    ),
                    _ => UpstreamCreate::stdio(
                        upstream_name(&s.name),
                        parts.command.clone().unwrap_or_default(),
                    ),
                };
                up.args = parts.args.clone();
                up.cwd = parts.cwd.clone();
                up.env = parts.env.clone();
                up.headers = parts.headers.clone();
                let mut se = SecretMap::new();
                for (k, v) in &parts.secret_env {
                    se.insert(k, v.as_str());
                }
                let mut sh = SecretMap::new();
                for (k, v) in &parts.secret_headers {
                    sh.insert(k, v.as_str());
                }
                up.secret_env = se;
                up.secret_headers = sh;
                if let Err(e) = c.create_upstream(&id, &up).await {
                    // Do not leave an empty dataset behind: the next run
                    // would create a second one.
                    let _ = c.delete_dataset(&id).await;
                    return Err(e.into());
                }
                taken.insert(id.clone());
                index.insert(def, id.clone());
                // Save now: a later failure leaves a reusable mapping, not
                // an upstream with secrets that no index entry points to.
                index.save().context("saving the definition index")?;
                id
            }
        };
        entries.push(GatewayEntry {
            name: s.name.clone(),
            scope: s.scope.clone(),
            url: format!("{gateway_base}/mcp/{id}"),
            // The user's own server entry: its approval setting is not
            // carried onto inumaki's entry (only inumaki-owned entries are).
            approval_mode: None,
        });
    }
    // Mailboxes: `inumaki-mail`, `inumaki-mail-2`, … (spec §4.5).
    let names: BTreeSet<String> = servers
        .iter()
        .filter(|s| !s.gateway)
        .map(|s| s.name.clone())
        .collect();
    for (i, d) in datasets
        .iter()
        .filter(|d| d.kind == DatasetKind::Mailbox)
        .enumerate()
    {
        let url = format!("{gateway_base}/mcp/{}", d.id);
        if !entries.iter().any(|e| e.url == url) {
            entries.push(GatewayEntry {
                name: mail_entry_name(i, &names),
                scope: Scope::User,
                url,
                approval_mode: None,
            });
        }
    }
    let files = if want.files {
        match c.folders().await {
            Ok(f) => Some(FilesPlan {
                mirror_root: f.mirror_root.into(),
                outboxes: f
                    .folders
                    .iter()
                    .filter(|x| x.state == inumaki_client::FolderState::Watching)
                    .map(|x| PathBuf::from(&x.outbox))
                    .collect(),
            }),
            Err(e) if missing(&e) => None,
            Err(e) => return Err(e.into()),
        }
    } else {
        None
    };
    // The client header goes wherever a Chat base URL is written.
    let (chat, proxy_client_header) = if want.chat {
        match c.proxy().await {
            Ok(p) if !chat_route(p.state, want.chat_explicit)? => (None, None),
            Ok(p) => {
                use inumaki_client::RoutePrefix;
                let url = |x: RoutePrefix| {
                    p.routes
                        .iter()
                        .find(|r| r.prefix == x)
                        .map(|r| r.base_url.clone())
                };
                (
                    Some(ChatPlan {
                        anthropic: url(RoutePrefix::Anthropic),
                        openai: url(RoutePrefix::Openai),
                        codex: url(RoutePrefix::Codex),
                        codex_chatgpt: want.chatgpt || p.oauth.codex_chatgpt.verified_in_build,
                    }),
                    Some(ClientHeader::new(Zeroizing::new(p.client_header.value))),
                )
            }
            Err(e) if missing(&e) => (None, None),
            Err(e) => return Err(e.into()),
        }
    } else {
        (None, None)
    };
    let hook = if want.hook && matches!(ad.id(), HarnessId::ClaudeCode | HarnessId::Codex) {
        let bin = bin_dir(c)
            .await
            .ok_or_else(|| anyhow!("cannot find the inumaki binaries"))?;
        Some(HookPlan {
            command: bin.join("inumaki-hook"),
            socket: socket.to_path_buf(),
        })
    } else {
        None
    };
    // Mint the token last: every earlier failure leaves nothing to revoke.
    let (gateway, minted) = if entries.is_empty() {
        (None, None)
    } else {
        let t = c.create_token(&ad.id().token_label()).await?;
        (
            Some(GatewayPlan {
                token: Zeroizing::new(t.token.expose().to_string()),
                entries,
            }),
            Some(t.id),
        )
    };
    Ok((
        ConnectPlan {
            data_dir: data.to_path_buf(),
            gateway_base,
            gateway,
            files,
            chat,
            hook,
            proxy_client_header,
        },
        minted,
    ))
}

/// Keep only `keep`, the token this apply wrote, of `app:<harness>`
/// (Reconnect after drift, spec §4.5).
async fn revoke_old_tokens(c: &Client, h: HarnessId, keep: i64) -> Result<()> {
    for t in c
        .tokens()
        .await?
        .into_iter()
        .filter(|t| t.label == h.token_label() && t.id != keep)
    {
        c.revoke_token(t.id).await?;
    }
    Ok(())
}

/// Revert revokes the harness's tokens (spec §4.2).
async fn revoke_all_tokens(c: &Client, h: HarnessId) -> Result<()> {
    for t in c
        .tokens()
        .await?
        .into_iter()
        .filter(|t| t.label == h.token_label())
    {
        c.revoke_token(t.id).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The chat route is on by default now that the proxy streams
    /// (`CHAT_ROUTE_DEFAULT`): the default apply has it, `--no-chat` skips it,
    /// and contradicting flags are rejected before anything is written.
    #[test]
    fn the_chat_route_is_on_by_default_and_the_flags_conflict() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct T {
            #[command(subcommand)]
            action: ConnectAction,
        }
        let flags = |args: &[&str]| -> Result<(bool, bool), clap::Error> {
            let mut v = vec!["t", "apply", "claude-code"];
            v.extend_from_slice(args);
            match T::try_parse_from(v)?.action {
                ConnectAction::Apply { chat, no_chat, .. } => Ok((chat, no_chat)),
                _ => unreachable!(),
            }
        };
        let want = |args: &[&str]| {
            let (c, n) = flags(args).unwrap();
            chat_wanted(c, n)
        };
        assert_eq!(want(&[]), CHAT_ROUTE_DEFAULT);
        const { assert!(CHAT_ROUTE_DEFAULT, "the proxy streams (M8-2)") };
        assert!(want(&["--chat"]));
        assert!(!want(&["--no-chat"]));
        assert!(flags(&["--chat", "--no-chat"]).is_err());
        // `--chatgpt` refines the chat route: fine alone (chat is the default)
        // or with `--chat`, an error with `--no-chat`.
        assert!(flags(&["--chatgpt"]).is_ok());
        assert!(flags(&["--chat", "--chatgpt"]).is_ok());
        assert!(flags(&["--chatgpt", "--no-chat"]).is_err());
    }

    /// Final review I4: the chat route (base URLs and the client header)
    /// is written only while the proxy runs. For a disabled or unbound
    /// proxy the default apply skips it; an explicit `--chat` fails.
    #[test]
    fn the_chat_route_is_written_only_while_the_proxy_runs() {
        use inumaki_client::ProxyState as S;
        assert!(chat_route(S::Running, false).unwrap());
        assert!(chat_route(S::Running, true).unwrap());
        for s in [S::Disabled, S::BindFailed] {
            assert!(!chat_route(s, false).unwrap(), "{s:?}: skipped by default");
            let e = chat_route(s, true).expect_err("an explicit --chat fails");
            // Fixed text: the state's name and the next step, nothing else.
            let why = s.chat_route_blocker().unwrap();
            assert_eq!(
                e.to_string(),
                format!(
                    "the proxy is {why}; the chat route was not written. Start the proxy (see `inumaki status`) or apply without --chat"
                )
            );
            assert_eq!(
                s.chat_route_skipped().unwrap(),
                format!("the proxy is {why}; the chat route is skipped")
            );
        }
    }

    /// Integrator ruling 2026-10-10: `connect apply codex` with
    /// `approval_policy = "never"` in Codex's config prints the adapter's one
    /// fixed warning line, never a value or path from the file; without the
    /// setting, or without a gateway entry, it prints none.
    #[test]
    fn codex_approval_never_prints_one_fixed_warning_line() {
        let home = tempfile::tempdir().unwrap();
        let codex = home.path().join(".codex");
        std::fs::create_dir_all(&codex).unwrap();
        let cfg = codex.join("config.toml");
        let ad = adapter(HarnessId::Codex);
        let inst = ad.detect(&ProbeEnv::for_tests(home.path())).unwrap();
        let mut plan = ConnectPlan {
            data_dir: home.path().join("data"),
            gateway_base: "http://127.0.0.1:8789".into(),
            gateway: Some(GatewayPlan {
                token: Zeroizing::new("tok-qwxzvk".into()),
                entries: vec![GatewayEntry {
                    name: "crm".into(),
                    scope: Scope::User,
                    url: "http://127.0.0.1:8789/mcp/crm".into(),
                    approval_mode: None,
                }],
            }),
            files: None,
            chat: None,
            hook: None,
            proxy_client_header: None,
        };
        std::fs::write(&cfg, "approval_policy = \"on-request\"\n").unwrap();
        assert!(warning_lines(ad.as_ref(), &inst, &plan).is_empty());
        std::fs::write(
            &cfg,
            "approval_policy = \"never\"\nmodel = \"qwxzvk-model\"\n[mcp_servers.crm]\ncommand = \"/opt/qwxzvk\"\n",
        )
        .unwrap();
        let lines = warning_lines(ad.as_ref(), &inst, &plan);
        assert_eq!(
            lines,
            vec![format!(
                "warning: {}",
                ConnectWarning::CodexApprovalNever.sentence()
            )]
        );
        for leak in ["qwxzvk", "crm", "/opt", &*home.path().to_string_lossy()] {
            assert!(!lines[0].contains(leak), "{leak}");
        }
        plan.gateway = None;
        assert!(warning_lines(ad.as_ref(), &inst, &plan).is_empty());
        // Ruling L97: an apply that installs the hook prints its fixed line.
        plan.hook = Some(HookPlan {
            command: home.path().join("bin/inumaki-hook"),
            socket: home.path().join("data/inumakid.sock"),
        });
        assert_eq!(
            warning_lines(ad.as_ref(), &inst, &plan),
            vec![format!(
                "warning: {}",
                ConnectWarning::HookBlocksWhenStopped.sentence()
            )]
        );
    }

    #[test]
    fn revert_without_a_backup_still_revokes_and_restores_nothing() {
        assert_eq!(revert_step(false, false), RevertStep::NothingToRestore);
        assert_eq!(revert_step(true, false), RevertStep::RestoreFiles);
        assert_eq!(revert_step(true, true), RevertStep::RestoreFiles);
    }

    /// Docs review I5: a backup whose manifest does not load is an error,
    /// never "no backup, exit 0".
    #[test]
    fn an_unreadable_backup_is_not_reported_as_no_backup() {
        let d = tempfile::tempdir().unwrap();
        let store = BackupStore::new(d.path());
        let h = HarnessId::ClaudeCode;
        assert!(!has_unreadable_backup(&store, h));
        let dir = store.dir(h).join("000000000001-000000000");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("manifest.json"), b"{not json").unwrap();
        assert!(store.active(h).is_none());
        assert!(has_unreadable_backup(&store, h));
        assert_eq!(revert_step(false, true), RevertStep::Unreadable);
    }

    #[test]
    fn a_snippets_token_is_never_revoked() {
        // The snippet holds the minted token and the user pastes it: it must
        // stay valid. Errors that print no snippet do revoke it.
        let with_snippet = AdapterError::cannot(FileRole::ClaudeJson, Refusal::Syntax, &[]);
        assert!(with_snippet.snippet().is_some());
        assert!(!revoke_minted_after(&with_snippet));
        for e in [
            AdapterError::Changed {
                role: FileRole::ClaudeJson,
            },
            AdapterError::Backup,
            AdapterError::NotOurGateway,
        ] {
            assert!(revoke_minted_after(&e));
        }
    }

    const HEADER_VALUE: &str = "inumaki_client_status_test";

    /// `connect status` prints the Hermes subscription-login lines and the
    /// fixed note, and no client-header value.
    #[test]
    fn status_prints_the_hermes_oauth_lines() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".hermes");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("config.yaml"),
            "model:\n  provider: openai-codex\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("auth.json"),
            "{\"active_provider\": \"openai-codex\"}",
        )
        .unwrap();
        let ad = adapter(HarnessId::Hermes);
        let inst = ad.detect(&ProbeEnv::for_tests(home.path())).unwrap();
        let sys = SystemState {
            service_up: true,
            proxy: Some(ProxyInfo {
                routes: vec![RouteInfo {
                    route: Route::Codex,
                    base_url: "http://127.0.0.1:8787/codex".into(),
                    failing: false,
                }],
                client_header: Some(ClientHeader::new(Zeroizing::new(HEADER_VALUE.into()))),
                ..Default::default()
            }),
            ..Default::default()
        };
        let out = render_status(ad.as_ref(), &inst, &sys);
        assert!(out.contains("add by hand:"), "{out}");
        assert!(
            out.contains("HERMES_CODEX_BASE_URL=http://127.0.0.1:8787/codex"),
            "{out}"
        );
        assert!(
            out.contains(
                "Hermes OAuth sends no client header, so only session tokens are restored."
            ),
            "{out}"
        );
        assert!(!out.contains(HEADER_VALUE), "{out}");
    }

    /// An OpenClaw Docker sandbox with the mirror outside the workspace roots
    /// gets the bind line and the note about the flag it also needs.
    #[test]
    fn status_prints_the_openclaw_bind_line() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".openclaw");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("openclaw.json"),
            r#"{ agents: { defaults: { workspace: "/work/agents", sandbox: { docker: {} } } } }"#,
        )
        .unwrap();
        let ad = adapter(HarnessId::Openclaw);
        let inst = ad.detect(&ProbeEnv::for_tests(home.path())).unwrap();
        let sys = SystemState {
            service_up: true,
            folders: Some(FolderInfo {
                mirror_root: PathBuf::from("/mirror/root"),
                watching: 1,
                outboxes: Vec::new(),
            }),
            ..Default::default()
        };
        let out = render_status(ad.as_ref(), &inst, &sys);
        assert!(out.contains("add by hand:"), "{out}");
        assert!(out.contains("/mirror/root:/mirror/root:ro"), "{out}");
        assert!(
            out.contains("dangerouslyAllowExternalBindSources is true"),
            "{out}"
        );
        // A mirror inside a workspace root needs nothing by hand.
        let inside = SystemState {
            folders: Some(FolderInfo {
                mirror_root: PathBuf::from("/work/agents/mirror"),
                watching: 1,
                outboxes: Vec::new(),
            }),
            ..sys
        };
        assert!(!render_status(ad.as_ref(), &inst, &inside).contains("add by hand"));
    }
}
