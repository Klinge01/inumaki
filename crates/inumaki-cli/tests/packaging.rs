//! Packaging files (M4 spec §16.10, M6 spec §7.3) name the right binaries,
//! paths, and service settings. The install itself is exercised by
//! scripts/package.sh --brew-test, scripts/package-deb.sh (Docker) and
//! scripts/package-app.sh, not here.

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

#[test]
fn systemd_user_unit_runs_inumakid_without_dynamic_user() {
    let unit = read("packaging/systemd/inumakid.service");
    assert!(unit.contains("[Unit]") && unit.contains("[Service]") && unit.contains("[Install]"));
    assert!(unit.contains("ExecStart=/usr/bin/inumakid"));
    assert!(
        unit.contains("WantedBy=default.target"),
        "a user unit installs into default.target"
    );
    assert!(
        !unit
            .lines()
            .any(|l| l.trim_start().starts_with("After=default.target")),
        "WantedBy= plus After= the same target is an ordering cycle"
    );
    assert!(unit.contains("Restart=on-failure"));
    assert!(unit.contains("NoNewPrivileges=yes"));
    assert!(unit.contains("UMask=0077"));
    assert!(unit.contains("Environment=INUMAKI_MANAGED_BY=deb"));
    // DynamicUser belongs to the M7 *system* unit (Kiji's unit is the reference); a
    // user unit cannot use it, and the data lives in the user's home.
    assert!(
        !unit
            .lines()
            .any(|l| l.trim_start().starts_with("DynamicUser="))
    );
    assert!(
        unit.contains("DynamicUser=yes") && unit.contains("M7"),
        "the M7 note is in a comment"
    );
}

#[test]
fn homebrew_formula_template_installs_the_binaries_and_a_service() {
    let f = read("packaging/homebrew/inumaki.rb.in");
    assert!(f.contains("class Inumaki < Formula"));
    assert!(f.contains("@URL@") && f.contains("@SHA256@") && f.contains("@VERSION@"));
    assert!(f.contains("license \"Apache-2.0\""));
    for b in ["inumaki", "inumakid", "inumaki-mcp", "inumaki-hook"] {
        assert!(
            f.contains(&format!("\"target/release/{b}\"")),
            "formula installs {b}"
        );
    }
    assert!(f.contains("INUMAKI_MANAGED_BY: \"homebrew\""));
    assert!(f.contains("service do") && f.contains("opt_bin/\"inumakid\""));
    assert!(f.contains("test do") && f.contains("--profile offline"));
    assert!(
        f.contains("experimental"),
        "the description says so until the gates pass"
    );
}

#[test]
fn deb_metadata_ships_both_binaries_the_unit_and_the_docs() {
    let t = read("crates/inumaki-cli/Cargo.toml");
    assert!(t.contains("[package.metadata.deb]"));
    assert!(t.contains("name = \"inumaki\""));
    for asset in [
        "\"target/release/inumaki\", \"usr/bin/\", \"755\"",
        "\"target/release/inumakid\", \"usr/bin/\", \"755\"",
        "\"target/release/inumaki-mcp\", \"usr/bin/\", \"755\"",
        "\"target/release/inumaki-hook\", \"usr/bin/\", \"755\"",
        "\"../../packaging/systemd/inumakid.service\", \"usr/lib/systemd/user/inumakid.service\", \"644\"",
        "\"../../configs/default.toml\", \"usr/share/inumaki/default.toml\", \"644\"",
        "\"../../docs/runbook.md\", \"usr/share/doc/inumaki/runbook.md\", \"644\"",
    ] {
        assert!(t.contains(asset), "missing asset {asset}");
    }
    assert!(t.contains("license-file = [\"../../LICENSE\""));
    assert!(
        t.contains("maintainers@inumaki.invalid"),
        "placeholder until release; never a personal address"
    );
    for script in [
        "scripts/package.sh",
        "scripts/package-deb.sh",
        "scripts/package-app.sh",
    ] {
        let s = read(script);
        assert!(s.starts_with("#!/usr/bin/env bash"), "{script}");
        assert!(s.contains("set -euo pipefail"), "{script}");
    }
    assert!(read(".gitignore").lines().any(|l| l.trim() == "/dist/"));
}

#[test]
fn app_bundle_ships_the_helpers_and_is_signed_ad_hoc() {
    let conf: serde_json::Value =
        serde_json::from_str(&read("apps/inumaki-app/src-tauri/tauri.bundle.conf.json")).unwrap();
    let bins: Vec<&str> = conf["bundle"]["externalBin"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        bins,
        [
            "binaries/inumakid",
            "binaries/inumaki",
            "binaries/inumaki-mcp",
            "binaries/inumaki-hook"
        ]
    );
    assert_eq!(conf["bundle"]["macOS"]["signingIdentity"], "-");
    let s = read("scripts/package-app.sh");
    assert!(
        s.contains("codesign --force --deep -s -"),
        "ad hoc signature (spec §7.3)"
    );
    assert!(s.contains("codesign --verify --deep --strict"));
    assert!(
        read(".gitignore")
            .lines()
            .any(|l| l.trim() == "/apps/inumaki-app/src-tauri/binaries/")
    );
}

#[test]
fn app_version_matches_the_workspace_version() {
    let conf: serde_json::Value =
        serde_json::from_str(&read("apps/inumaki-app/src-tauri/tauri.conf.json")).unwrap();
    let cargo = read("Cargo.toml");
    let section = cargo
        .split("[workspace.package]")
        .nth(1)
        .expect("[workspace.package]");
    let workspace = section
        .lines()
        .take_while(|l| !l.trim_start().starts_with('['))
        .find_map(|l| l.trim().strip_prefix("version = "))
        .map(|v| v.trim_matches('"'))
        .expect("workspace version");
    assert_eq!(
        conf["version"], workspace,
        "tauri.conf.json drifted from [workspace.package]"
    );
}
