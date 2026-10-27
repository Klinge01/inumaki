//! The inumaki app (M6 spec §6): a tray icon and one settings window. The
//! Rust side talks to `inumakid` only through `inumaki-client` over the
//! control socket; the UI reaches it only through the commands in `ipc`.

pub mod applog;
pub mod appstate;
pub mod check;
pub mod commands;
pub mod ctx;
pub mod error;
pub mod harness;
mod ipc;
pub mod measured;
pub mod notify;
pub mod paths;
pub mod poll;
pub mod service;
pub mod tray;

/// Show and focus the settings window.
pub(crate) fn show_window(app: &tauri::AppHandle) {
    use tauri::Manager;
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.set_focus();
        if let Some(ctx) = app.try_state::<std::sync::Arc<ctx::Ctx>>() {
            ctx.visible
                .store(true, std::sync::atomic::Ordering::Relaxed);
            ctx.wake.notify_one();
        }
    }
}

/// Build and run the app.
pub fn run() {
    let paths = paths::AppPaths::system();
    applog::init(&paths.log_file);
    applog::install_panic_hook();
    error::note_config_error(paths.config_error.is_some());
    let client = inumaki_client::Client::new(&paths.socket);
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(move |app| {
            use tauri::Manager;
            // Temporary directories of a check the app did not finish (a crash).
            check::tmp::sweep(&paths);
            let notifier = std::sync::Arc::new(ctx::TauriNotifier(app.handle().clone()));
            // Detection (which spawns `--version` and the login shell) runs
            // in the poller: on its first round and whenever showing the
            // window wakes it, never on an ordinary tick (`poll::spawn`).
            let ctx = std::sync::Arc::new(
                ctx::Ctx::new(paths.clone(), client.clone(), notifier)
                    .with_harnesses(harness::adapt::all(&paths)),
            );
            app.manage(ctx.clone());
            tray::build(app.handle())?;
            poll::spawn(app.handle().clone(), ctx.clone());
            // An app update brings new helpers: refresh the copies in
            // `<data dir>/bin` and restart the app's own service (M6-3).
            tauri::async_runtime::spawn(async move { service::refresh_on_start(&ctx).await });
            Ok(())
        })
        .on_window_event(|window, event| {
            use tauri::{Emitter, Manager};
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Closing the window keeps the tray (spec §6.2); reveals clear on hide (§6.5).
                api.prevent_close();
                let _ = window.hide();
                let _ = window.emit("window-hidden", ());
                if let Some(ctx) = window.app_handle().try_state::<std::sync::Arc<ctx::Ctx>>() {
                    ctx.visible
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                }
            }
        })
        .invoke_handler(ipc::handlers())
        .run(tauri::generate_context!())
        .unwrap_or_else(|_| std::process::exit(1));
}
