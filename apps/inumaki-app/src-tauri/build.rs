//! Embed the measured quality and latency numbers of each profile's own
//! primary-corpus report (M6 spec §2 decision 19): docs/quality/*.json.
//! Which report counts as primary is defined in `report_select.rs`. A report
//! that cannot be read, or lacks a field, is skipped with a build warning,
//! never silently: the `measured_is_not_empty` test fails when no report is
//! embedded at all.

use std::path::Path;

#[path = "report_select.rs"]
mod report_select;

fn main() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../docs/quality");
    println!("cargo:rerun-if-changed={}", dir.display());
    println!("cargo:rerun-if-changed=report_select.rs");
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    // A fixed order, so two reports of the same second always resolve the same way.
    paths.sort();
    let mut reports: Vec<(String, serde_json::Value)> = Vec::new();
    for p in paths {
        if p.extension().and_then(|x| x.to_str()) != Some("json") {
            continue;
        }
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        match std::fs::read(&p)
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        {
            Some(v) => reports.push((name, v)),
            None => println!("cargo:warning=docs/quality/{name}: not readable JSON, not embedded"),
        }
    }
    let mut skipped = Vec::new();
    let chosen = report_select::select(&reports, &mut skipped);
    // Fail closed: a primary report that cannot be embedded must not let an
    // older report stand in for its profile without anyone noticing.
    if let Some((name, field)) = skipped.first() {
        panic!("docs/quality/{name} is a primary report but has no `{field}`: fix or remove it");
    }
    let rows: Vec<serde_json::Value> = chosen.into_values().map(|(_, _, r)| r).collect();
    if rows.is_empty() {
        println!(
            "cargo:warning=no primary report in docs/quality: the Settings view shows no measured numbers"
        );
    }
    let out = Path::new(&std::env::var("OUT_DIR").unwrap()).join("measured.json");
    std::fs::write(out, serde_json::to_vec(&rows).unwrap()).unwrap();
    tauri_build::build();
}
