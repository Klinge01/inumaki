//! Every command the UI can call: one-line wrappers around `commands::*`
//! that log the command name, duration, and outcome (never an argument or
//! a result). This is the only place with `#[tauri::command]`.

use std::sync::Arc;

use inumaki_client::HarnessId;
use tauri::State;

use crate::applog::logged;
use crate::commands;
use crate::ctx::Ctx;
use crate::error::CmdError;
use crate::harness::connect::{self as hc, ConnectOutcome, OtherClient};
use crate::harness::ops::{FileChange, PathKind, RevertSummary};
use crate::harness::protect::{ProtectOutcome, ServerRow, UnprotectOutcome};

#[tauri::command]
async fn overview(ctx: State<'_, Arc<Ctx>>) -> Result<commands::overview::OverviewView, CmdError> {
    logged("overview", commands::overview::overview(&ctx)).await
}

#[tauri::command]
async fn refresh(ctx: State<'_, Arc<Ctx>>) -> Result<commands::overview::OverviewView, CmdError> {
    logged("refresh", commands::overview::refresh(&ctx)).await
}

#[tauri::command]
async fn acknowledge(
    ctx: State<'_, Arc<Ctx>>,
    harness: HarnessId,
    path: PathKind,
) -> Result<(), CmdError> {
    logged(
        "acknowledge",
        commands::overview::acknowledge(&ctx, harness, path),
    )
    .await
}

#[tauri::command]
async fn manual_setup(
    ctx: State<'_, Arc<Ctx>>,
    harness: HarnessId,
) -> Result<Option<crate::harness::ops::ManualSetupView>, CmdError> {
    logged(
        "manual_setup",
        commands::overview::manual_setup(&ctx, harness),
    )
    .await
}

#[tauri::command]
async fn connect(ctx: State<'_, Arc<Ctx>>, harness: HarnessId) -> Result<ConnectOutcome, CmdError> {
    logged("connect", hc::connect(&ctx, harness)).await
}

#[tauri::command]
async fn revert(ctx: State<'_, Arc<Ctx>>, harness: HarnessId) -> Result<RevertSummary, CmdError> {
    logged("revert", hc::revert(&ctx, harness)).await
}

#[tauri::command]
async fn reconnect(
    ctx: State<'_, Arc<Ctx>>,
    harness: HarnessId,
) -> Result<ConnectOutcome, CmdError> {
    logged("reconnect", hc::reconnect(&ctx, harness)).await
}

#[tauri::command]
async fn preview_connect(
    ctx: State<'_, Arc<Ctx>>,
    harness: HarnessId,
) -> Result<Vec<FileChange>, CmdError> {
    logged("preview_connect", hc::preview(&ctx, harness)).await
}

#[tauri::command]
async fn other_client(ctx: State<'_, Arc<Ctx>>) -> Result<OtherClient, CmdError> {
    logged("other_client", hc::other_client(&ctx)).await
}

#[tauri::command]
async fn revoke_other_client(ctx: State<'_, Arc<Ctx>>) -> Result<(), CmdError> {
    logged("revoke_other_client", hc::revoke_other_client(&ctx)).await
}

#[tauri::command]
async fn mcp_servers(ctx: State<'_, Arc<Ctx>>) -> Result<Vec<ServerRow>, CmdError> {
    logged("mcp_servers", commands::mcp::servers(&ctx)).await
}

#[tauri::command]
async fn protect(
    ctx: State<'_, Arc<Ctx>>,
    harness: HarnessId,
    id: String,
) -> Result<ProtectOutcome, CmdError> {
    logged("protect", commands::mcp::protect(&ctx, harness, &id)).await
}

#[tauri::command]
async fn unprotect(
    ctx: State<'_, Arc<Ctx>>,
    harness: HarnessId,
    id: String,
) -> Result<UnprotectOutcome, CmdError> {
    logged("unprotect", commands::mcp::unprotect(&ctx, harness, &id)).await
}

#[tauri::command]
async fn remove_protected_dataset(
    ctx: State<'_, Arc<Ctx>>,
    dataset: String,
) -> Result<(), CmdError> {
    logged(
        "remove_protected_dataset",
        commands::mcp::remove_dataset(&ctx, &dataset),
    )
    .await
}

#[tauri::command]
async fn leave_unprotected(
    ctx: State<'_, Arc<Ctx>>,
    harness: HarnessId,
    id: String,
    on: bool,
) -> Result<(), CmdError> {
    logged(
        "leave_unprotected",
        commands::mcp::leave_unprotected(&ctx, harness, &id, on),
    )
    .await
}

#[tauri::command]
async fn accept_schema(
    ctx: State<'_, Arc<Ctx>>,
    dataset: String,
    upstream: String,
) -> Result<(), CmdError> {
    logged(
        "accept_schema",
        commands::mcp::accept_schema(&ctx, &dataset, &upstream),
    )
    .await
}

#[tauri::command]
async fn mailboxes(
    ctx: State<'_, Arc<Ctx>>,
) -> Result<Vec<commands::email::MailboxCard>, CmdError> {
    logged("mailboxes", commands::email::mailboxes(&ctx)).await
}

#[tauri::command]
async fn add_mailbox(
    ctx: State<'_, Arc<Ctx>>,
    form: commands::email::MailboxForm,
) -> Result<commands::email::MailboxAdded, CmdError> {
    logged("add_mailbox", commands::email::add_mailbox(&ctx, form)).await
}

#[tauri::command]
async fn check_mailbox(
    ctx: State<'_, Arc<Ctx>>,
    dataset: String,
) -> Result<inumaki_client::MailboxCheck, CmdError> {
    logged(
        "check_mailbox",
        commands::email::check_mailbox(&ctx, &dataset),
    )
    .await
}

#[tauri::command]
async fn replace_mailbox_password(
    ctx: State<'_, Arc<Ctx>>,
    dataset: String,
    password: inumaki_client::Secret,
) -> Result<(), CmdError> {
    logged(
        "replace_mailbox_password",
        commands::email::replace_password(&ctx, &dataset, password),
    )
    .await
}

#[tauri::command]
async fn remove_mailbox(
    ctx: State<'_, Arc<Ctx>>,
    dataset: String,
) -> Result<commands::folders::DataChange, CmdError> {
    logged(
        "remove_mailbox",
        commands::email::remove_mailbox(&ctx, &dataset),
    )
    .await
}

/// Opens the provider's app-password page (a fixed allowlist), from Rust:
/// the UI has no opener permission.
#[tauri::command]
async fn open_mail_help(preset: inumaki_client::MailboxPreset) -> Result<(), CmdError> {
    logged("open_mail_help", async {
        let url = commands::email::help_url(preset).ok_or_else(|| CmdError::new("no_help_page"))?;
        tauri_plugin_opener::open_url(url, None::<&str>).map_err(|_| CmdError::new("open_failed"))
    })
    .await
}

#[tauri::command]
async fn folders(ctx: State<'_, Arc<Ctx>>) -> Result<commands::folders::FoldersView, CmdError> {
    logged("folders", commands::folders::folders(&ctx)).await
}

/// Opens the folder picker (from Rust: the UI has no dialog permission);
/// `None` when the user cancels.
#[tauri::command]
async fn add_folder(
    app: tauri::AppHandle,
    ctx: State<'_, Arc<Ctx>>,
) -> Result<Option<commands::folders::DataChange>, CmdError> {
    use tauri_plugin_dialog::DialogExt;
    // Logged whole: a cancel, a join error, and a bad path get a line too.
    logged("add_folder", async {
        // The picker blocks until the user answers: not on an async worker.
        let picker = app.clone();
        let picked =
            tokio::task::spawn_blocking(move || picker.dialog().file().blocking_pick_folder())
                .await
                .map_err(|_| CmdError::new("internal"))?;
        let Some(p) = picked else {
            return Ok(None);
        };
        let path = p.into_path().map_err(|_| CmdError::new("bad_request"))?;
        commands::folders::add_folder(&ctx, path).await.map(Some)
    })
    .await
}

#[tauri::command]
async fn rescan_folder(
    ctx: State<'_, Arc<Ctx>>,
    dataset: String,
) -> Result<inumaki_client::RescanBody, CmdError> {
    logged("rescan_folder", commands::folders::rescan(&ctx, &dataset)).await
}

#[tauri::command]
async fn remove_folder(
    ctx: State<'_, Arc<Ctx>>,
    dataset: String,
) -> Result<commands::folders::DataChange, CmdError> {
    logged(
        "remove_folder",
        commands::folders::remove_folder(&ctx, &dataset),
    )
    .await
}

/// Reveals a folder's mirror in the file manager: only a path under the
/// mirror root, never one the UI supplies.
#[tauri::command]
async fn reveal_mirror(ctx: State<'_, Arc<Ctx>>, dataset: String) -> Result<(), CmdError> {
    logged("reveal_mirror", async {
        let p = commands::folders::reveal_target(&ctx, &dataset).await?;
        tauri_plugin_opener::reveal_item_in_dir(p).map_err(|_| CmdError::new("reveal_failed"))
    })
    .await
}

/// Reveals a folder's outbox destination (where restored files go) in the
/// file manager: only the destination the daemon reports, never a path the
/// UI supplies.
#[tauri::command]
async fn reveal_outbox(ctx: State<'_, Arc<Ctx>>, dataset: String) -> Result<(), CmdError> {
    logged("reveal_outbox", async {
        let p = commands::folders::outbox_target(&ctx, &dataset).await?;
        tauri_plugin_opener::reveal_item_in_dir(p).map_err(|_| CmdError::new("reveal_failed"))
    })
    .await
}

#[tauri::command]
async fn activity(
    ctx: State<'_, Arc<Ctx>>,
    dataset: Option<String>,
    limit: Option<u64>,
) -> Result<inumaki_client::ActivityList, CmdError> {
    logged(
        "activity",
        commands::activity::activity(&ctx, dataset, limit),
    )
    .await
}

#[tauri::command]
async fn verify_activity(
    ctx: State<'_, Arc<Ctx>>,
) -> Result<inumaki_client::ActivityVerify, CmdError> {
    logged("verify_activity", commands::activity::verify(&ctx)).await
}

#[tauri::command]
async fn journal(
    ctx: State<'_, Arc<Ctx>>,
    dataset: String,
    since: Option<i64>,
) -> Result<inumaki_client::JournalList, CmdError> {
    logged(
        "journal",
        commands::activity::journal(&ctx, &dataset, since),
    )
    .await
}

#[tauri::command]
async fn journal_record(
    ctx: State<'_, Arc<Ctx>>,
    dataset: String,
    record: String,
    reveal: bool,
) -> Result<inumaki_client::JournalRecord, CmdError> {
    logged(
        "journal_record",
        commands::activity::journal_record(&ctx, &dataset, &record, reveal),
    )
    .await
}

#[tauri::command]
async fn entities(
    ctx: State<'_, Arc<Ctx>>,
    dataset: String,
    reveal: bool,
) -> Result<inumaki_client::EntityList, CmdError> {
    logged(
        "entities",
        commands::activity::entities(&ctx, &dataset, reveal),
    )
    .await
}

#[tauri::command]
async fn forget_token(
    ctx: State<'_, Arc<Ctx>>,
    dataset: String,
    token: String,
) -> Result<commands::activity::ForgetOutcome, CmdError> {
    logged(
        "forget_token",
        commands::activity::forget_token(&ctx, &dataset, &token),
    )
    .await
}

#[tauri::command]
async fn forget_value(
    ctx: State<'_, Arc<Ctx>>,
    dataset: String,
    value: String,
) -> Result<commands::activity::ForgetOutcome, CmdError> {
    logged(
        "forget_value",
        commands::activity::forget_value(&ctx, &dataset, value),
    )
    .await
}

#[tauri::command]
async fn inspect_text(
    ctx: State<'_, Arc<Ctx>>,
    dataset: String,
    text: String,
    show_values: bool,
) -> Result<commands::inspect::InspectView, CmdError> {
    logged(
        "inspect_text",
        commands::inspect::inspect(&ctx, &dataset, text, show_values),
    )
    .await
}

/// Opens the file picker (from Rust: the UI has no dialog permission and
/// never names a path); `None` when the user cancels.
#[tauri::command]
async fn open_text_file(app: tauri::AppHandle) -> Result<Option<String>, CmdError> {
    use tauri_plugin_dialog::DialogExt;
    // Logged whole: a cancel, a join error, and a bad path get a line too.
    logged("open_text_file", async {
        // The picker blocks until the user answers: not on an async worker.
        let picker = app.clone();
        let picked =
            tokio::task::spawn_blocking(move || picker.dialog().file().blocking_pick_file())
                .await
                .map_err(|_| CmdError::new("internal"))?;
        let Some(p) = picked else {
            return Ok(None);
        };
        let path = p.into_path().map_err(|_| CmdError::new("bad_request"))?;
        commands::inspect::read_text_file(&path).map(Some)
    })
    .await
}

#[tauri::command]
async fn sanitize_with(
    ctx: State<'_, Arc<Ctx>>,
    dataset: String,
    text: String,
    spans: Vec<inumaki_client::Redaction>,
) -> Result<inumaki_client::SanitizeResponse, CmdError> {
    logged(
        "sanitize_with",
        commands::inspect::sanitize_with(&ctx, &dataset, text, spans),
    )
    .await
}

#[tauri::command]
async fn service_info(
    ctx: State<'_, Arc<Ctx>>,
) -> Result<commands::settings::ServiceView, CmdError> {
    logged("service_info", commands::settings::service_info(&ctx)).await
}

#[tauri::command]
async fn models_status(ctx: State<'_, Arc<Ctx>>) -> Result<inumaki_client::ModelsJob, CmdError> {
    logged("models_status", commands::settings::models_status(&ctx)).await
}

#[tauri::command]
async fn service_install(ctx: State<'_, Arc<Ctx>>) -> Result<(), CmdError> {
    logged("service_install", commands::service::service_install(&ctx)).await
}

#[tauri::command]
async fn service_remove(ctx: State<'_, Arc<Ctx>>) -> Result<(), CmdError> {
    logged("service_remove", commands::service::service_remove(&ctx)).await
}

#[tauri::command]
async fn service_restart(ctx: State<'_, Arc<Ctx>>) -> Result<(), CmdError> {
    logged("service_restart", commands::service::service_restart(&ctx)).await
}

#[tauri::command]
async fn models_pull_start(
    ctx: State<'_, Arc<Ctx>>,
) -> Result<inumaki_client::ModelsJob, CmdError> {
    logged(
        "models_pull_start",
        commands::service::models_pull_start(&ctx),
    )
    .await
}

#[tauri::command]
async fn models_pull_poll(
    ctx: State<'_, Arc<Ctx>>,
) -> Result<commands::service::ModelsPoll, CmdError> {
    logged(
        "models_pull_poll",
        commands::service::models_pull_poll(&ctx),
    )
    .await
}

#[tauri::command]
async fn run_check(ctx: State<'_, Arc<Ctx>>) -> Result<crate::check::run::CheckRun, CmdError> {
    logged("run_check", commands::check::run_check(&ctx)).await
}

#[tauri::command]
async fn settings(ctx: State<'_, Arc<Ctx>>) -> Result<commands::settings::SettingsView, CmdError> {
    logged("settings", commands::settings::settings(&ctx)).await
}

#[tauri::command]
async fn delete_backup(
    ctx: State<'_, Arc<Ctx>>,
    harness: HarnessId,
    id: String,
) -> Result<(), CmdError> {
    logged(
        "delete_backup",
        commands::settings::delete_backup(&ctx, harness, &id),
    )
    .await
}

#[tauri::command]
async fn set_first_run_done(ctx: State<'_, Arc<Ctx>>) -> Result<(), CmdError> {
    logged("set_first_run_done", async {
        commands::settings::set_first_run_done(&ctx)
    })
    .await
}

#[tauri::command]
async fn set_chat_opt_in(
    ctx: State<'_, Arc<Ctx>>,
    harness: HarnessId,
    on: bool,
) -> Result<commands::folders::DataChange, CmdError> {
    logged(
        "set_chat_opt_in",
        commands::settings::set_chat_opt_in(&ctx, harness, on),
    )
    .await
}

#[tauri::command]
async fn prefs(ctx: State<'_, Arc<Ctx>>) -> Result<commands::settings::PrefsView, CmdError> {
    logged("prefs", commands::settings::prefs(&ctx)).await
}

#[tauri::command]
async fn datasets(
    ctx: State<'_, Arc<Ctx>>,
) -> Result<Vec<commands::settings::DatasetRow>, CmdError> {
    logged("datasets", commands::settings::datasets(&ctx)).await
}

/// The handler list for `invoke_handler`.
pub fn handlers() -> impl Fn(tauri::ipc::Invoke) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        overview,
        refresh,
        acknowledge,
        manual_setup,
        connect,
        revert,
        reconnect,
        preview_connect,
        other_client,
        revoke_other_client,
        mcp_servers,
        protect,
        unprotect,
        remove_protected_dataset,
        leave_unprotected,
        accept_schema,
        mailboxes,
        add_mailbox,
        check_mailbox,
        replace_mailbox_password,
        remove_mailbox,
        open_mail_help,
        folders,
        add_folder,
        rescan_folder,
        remove_folder,
        reveal_mirror,
        reveal_outbox,
        activity,
        verify_activity,
        journal,
        journal_record,
        entities,
        forget_token,
        forget_value,
        inspect_text,
        open_text_file,
        sanitize_with,
        service_info,
        models_status,
        service_install,
        service_remove,
        service_restart,
        models_pull_start,
        models_pull_poll,
        run_check,
        settings,
        delete_backup,
        set_first_run_done,
        set_chat_opt_in,
        prefs,
        datasets
    ]
}
