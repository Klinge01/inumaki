//! The daemon and `inumaki_client::resolve_socket` (used by the app, the MCP
//! shim, and the hook) must pick the same socket for the same data directory
//! and `inumaki.toml`, and must both refuse the same unusable file.

use std::path::{Path, PathBuf};

use inumakid::{AppState, StartOptions};

fn start(data: &Path, models: &Path) -> Result<AppState, inumakid::StartError> {
    AppState::start(&StartOptions {
        config: None,
        data_dir: Some(data.to_path_buf()),
        socket: None,
        models_dir: Some(models.to_path_buf()),
        clock: None,
    })
}

/// The shipped config plus the tables a test daemon needs, with `socket`
/// (a TOML line, or nothing) in `[daemon]`.
fn config(root: &Path, socket_line: &str) -> String {
    format!(
        "{}\n[daemon]\n{socket_line}default_profile = \"offline\"\n[vault]\nkey_source = \"file\"\n[mirror]\nroot = \"{d}/mirror-root\"\noutbox_root = \"{d}/mirror-outbox\"\n",
        include_str!("../../../configs/default.toml"),
        d = root.display()
    )
}

#[test]
fn client_and_daemon_resolve_the_same_socket() {
    let cases: [(&str, String, PathBuf); 3] = [
        ("", String::new(), PathBuf::from("inumakid.sock")),
        (
            "absolute",
            "socket = \"/tmp/inumaki-agreement/x.sock\"\n".into(),
            PathBuf::from("/tmp/inumaki-agreement/x.sock"),
        ),
        (
            "relative",
            "socket = \"run/x.sock\"\n".into(),
            PathBuf::from("run/x.sock"),
        ),
    ];
    for (name, line, expect) in cases {
        let root = tempfile::tempdir().unwrap();
        let models = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("inumaki.toml"), config(root.path(), &line)).unwrap();
        let daemon = start(&data, models.path()).unwrap().socket_path;
        let client = inumaki_client::resolve_socket(None, &data).unwrap();
        assert_eq!(client, daemon, "{name}");
        assert_eq!(client, data.join(&expect), "{name}");
    }
}

#[test]
fn both_refuse_an_unusable_file_and_agree_when_there_is_none() {
    let root = tempfile::tempdir().unwrap();
    let models = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    // No file: the client gives the default the daemon derives from the
    // embedded config.
    let embedded = inumakid::DaemonConfig::embedded().daemon.socket;
    assert_eq!(
        inumaki_client::resolve_socket(None, &data).unwrap(),
        inumakid::dirs::resolve_in(&data, &embedded)
    );
    // A dangling symlink is an error for both, never the default.
    std::os::unix::fs::symlink(data.join("missing"), data.join("inumaki.toml")).unwrap();
    assert!(inumaki_client::resolve_socket(None, &data).is_err());
    assert!(start(&data, models.path()).is_err());
}
