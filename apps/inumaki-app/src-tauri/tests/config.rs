//! The locked-down Tauri surface (M6 spec §6.1): three plugins called from
//! Rust, a window capability of event listening only, a strict CSP, no
//! devtools feature, and no daemon-side crate in the dependency list.

use std::path::Path;

fn read(rel: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)).unwrap()
}

#[test]
fn csp_allows_nothing_remote_and_nothing_inline() {
    let conf: serde_json::Value = serde_json::from_str(&read("tauri.conf.json")).unwrap();
    let csp = conf["app"]["security"]["csp"].as_str().unwrap();
    assert!(csp.contains("default-src 'self'"), "{csp}");
    let sources: Vec<&str> = csp
        .split(';')
        .flat_map(|d| d.split_whitespace().skip(1))
        .collect();
    for v in &sources {
        let remote =
            (v.starts_with("http:") || v.starts_with("https:")) && *v != "http://ipc.localhost";
        let loose = ["'unsafe-eval'", "'unsafe-inline'", "*", "data:"].contains(v)
            && !csp.contains(&format!("img-src 'self' {v}"));
        assert!(!remote && !loose, "CSP allows {v}: {csp}");
        assert!(
            !v.starts_with("ws:") && !v.starts_with("wss:"),
            "CSP allows a websocket origin {v}: {csp}"
        );
    }
    for need in [
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
    ] {
        assert!(
            csp.split(';').any(|d| d.trim() == need),
            "CSP lacks {need}: {csp}"
        );
    }
    assert!(conf["plugins"].as_object().is_none_or(|p| {
        p.keys()
            .all(|k| ["notification", "dialog", "opener"].contains(&k.as_str()))
    }));
}

#[test]
fn the_window_may_only_listen_to_events() {
    let caps: Vec<_> =
        std::fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
    assert_eq!(caps, ["main.json"], "capabilities/ holds exactly one file");
    let cap: serde_json::Value = serde_json::from_str(&read("capabilities/main.json")).unwrap();
    assert_eq!(cap["windows"], serde_json::json!(["main"]));
    // App commands need no permission entry; the UI only listens to "snapshot" and "window-hidden".
    assert_eq!(
        cap["permissions"],
        serde_json::json!(["core:event:allow-listen", "core:event:allow-unlisten"])
    );
    assert!(
        cap.get("remote").is_none(),
        "no remote URL may call commands"
    );
}

#[test]
fn only_the_three_plugins_and_no_daemon_crates_are_dependencies() {
    let toml: toml::Value = toml::from_str(&read("Cargo.toml")).unwrap();
    let deps = toml["dependencies"].as_table().unwrap();
    for bad in [
        "tauri-plugin-shell",
        "tauri-plugin-fs",
        "tauri-plugin-http",
        "tauri-plugin-updater",
        "tauri-plugin-store",
        "tauri-plugin-process",
        "inumakid",
        "inumaki-models",
        "inumaki-core",
        "inumaki-vault",
        "ort",
    ] {
        assert!(!deps.contains_key(bad), "{bad} must not be a dependency");
    }
    for need in [
        "tauri-plugin-notification",
        "tauri-plugin-dialog",
        "tauri-plugin-opener",
        "inumaki-client",
        "inumaki-adapters",
    ] {
        assert!(deps.contains_key(need), "{need}");
    }
    let features: Vec<&str> = deps["tauri"]["features"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        !features.contains(&"devtools"),
        "devtools stay off in release"
    );
    assert!(
        toml.get("workspace").is_some(),
        "own workspace, excluded from the root"
    );
}
