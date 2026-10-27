//! The measured numbers shown in Settings with the "experimental" badge.

use serde::{Deserialize, Serialize};

/// One profile's latest committed primary-corpus report (`report_select.rs`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Measured {
    /// Profile.
    pub profile: String,
    /// Documents.
    pub docs: u64,
    /// Documents with a leak.
    pub leak_docs: u64,
    /// Accepted documents with a leak.
    pub accepted_leak_docs: u64,
    /// Latency p50, ms.
    pub p50_ms: f64,
    /// Latency p95, ms.
    pub p95_ms: f64,
    /// Platform.
    pub platform: String,
    /// Commit.
    pub commit: String,
    /// Time of the run, unix seconds.
    pub evaluated_at: i64,
}

const RAW: &str = include_str!(concat!(env!("OUT_DIR"), "/measured.json"));

/// Parsed at each call (a handful of rows); an unreadable embed yields an
/// empty list, which `measured_is_not_empty` catches at test time.
pub fn measured() -> Vec<Measured> {
    serde_json::from_str(RAW).unwrap_or_default()
}

#[cfg(test)]
#[path = "../report_select.rs"]
mod report_select;

#[cfg(test)]
mod tests {
    use super::report_select::{is_primary, select};
    use serde_json::{Value, json};

    /// A report with every field `row` reads; `family`, `cases`, `generated`
    /// and `at` are the ones the selection looks at.
    fn report(profile: &str, family: &str, cases: u64, generated: u64, at: i64) -> Value {
        json!({
            "profile": profile, "docs": cases + generated,
            "docs_with_leak": 1, "accepted_leak_docs": 1,
            "latency_ms": {"p50": 1.0, "p95": 2.0},
            "provenance": {
                "family": family, "cases": cases, "generated": generated,
                "platform": "test", "git_commit": "c", "evaluated_at": at,
                "seed": 42,
                "config_sha256": "default",
            },
        })
    }

    fn chosen(reports: Vec<(&str, Value)>) -> Vec<(String, String)> {
        let reports: Vec<(String, Value)> = reports
            .into_iter()
            .map(|(n, v)| (n.to_string(), v))
            .collect();
        select(&reports, &mut Vec::new())
            .into_iter()
            .map(|(profile, (name, _, _))| (profile, name))
            .collect()
    }

    #[test]
    fn a_newer_held_out_or_other_run_loses_to_the_older_primary_run() {
        let got = chosen(vec![
            ("primary", report("strict", "tuning", 67, 2000, 100)),
            ("held-out", report("strict", "held-out", 0, 200, 900)),
            (
                "tool-json",
                report("strict", "tool-json+held-out", 0, 300, 901),
            ),
            (
                "tool-json-tuning",
                report("strict", "tool-json+tuning", 0, 300, 902),
            ),
            ("service", report("strict", "tuning+service", 67, 2000, 903)),
            (
                "sequence",
                report("strict", "sequence+service", 0, 300, 904),
            ),
            ("generated-only", report("strict", "tuning", 0, 2000, 905)),
            ("cases-only", report("strict", "cases", 67, 0, 906)),
            ("file", report("strict", "file", 0, 0, 907)),
        ]);
        assert_eq!(got, vec![("strict".into(), "primary".into())]);
    }

    #[test]
    fn the_latest_primary_run_of_each_profile_wins_and_unknown_never_does() {
        let mut unknown = report("strict", "tuning", 67, 2000, 999);
        unknown["provenance"]
            .as_object_mut()
            .unwrap()
            .remove("family");
        let got = chosen(vec![
            ("old", report("strict", "tuning", 58, 2000, 100)),
            ("new", report("strict", "tuning", 67, 2000, 200)),
            ("unknown", unknown),
            ("other", report("offline", "tuning", 67, 2000, 50)),
        ]);
        assert_eq!(
            got,
            vec![
                ("offline".into(), "other".into()),
                ("strict".into(), "new".into())
            ]
        );
        assert!(chosen(vec![("held", report("strict", "held-out", 0, 200, 1))]).is_empty());
    }

    #[test]
    fn a_config_override_run_is_not_primary() {
        let mut file = report("strict", "tuning", 67, 2000, 300);
        file["provenance"]["config_source"] = json!("file");
        assert!(!is_primary(&file));
        let mut legacy = report("strict", "tuning", 67, 2000, 300);
        legacy["provenance"]["config_sha256"] =
            json!(super::report_select::KNOWN_OVERRIDE_CONFIGS[0]);
        assert!(!is_primary(&legacy));
        let mut embedded = report("strict", "tuning", 67, 2000, 300);
        embedded["provenance"]["config_source"] = json!("embedded");
        assert!(is_primary(&embedded));
    }

    #[test]
    fn a_non_default_corpus_run_is_not_primary() {
        // legacy reports (no `canonical`): seed and generated count must be the old defaults
        let mut seeded = report("strict", "tuning", 67, 2000, 300);
        seeded["provenance"]["seed"] = json!(7);
        assert!(!is_primary(&seeded));
        assert!(!is_primary(&report("strict", "tuning", 67, 300, 300)));
        // reports with `canonical`: the writer's word decides, whatever the counts
        let mut no = report("strict", "tuning", 67, 2000, 300);
        no["provenance"]["canonical"] = json!(false);
        assert!(!is_primary(&no));
        let mut yes = report("strict", "tuning", 67, 5000, 300);
        yes["provenance"]["seed"] = json!(43);
        yes["provenance"]["canonical"] = json!(true);
        assert!(
            is_primary(&yes),
            "a changed default corpus size stays primary"
        );
        // canonical does not rescue another family
        let mut held = report("strict", "held-out", 0, 200, 300);
        held["provenance"]["canonical"] = json!(true);
        assert!(!is_primary(&held));
    }

    #[test]
    fn a_primary_report_without_a_row_field_is_reported_not_skipped_silently() {
        let mut broken = report("strict", "tuning", 67, 2000, 500);
        broken["latency_ms"] = json!({});
        let reports = vec![
            ("old".to_string(), report("strict", "tuning", 67, 2000, 100)),
            ("broken".to_string(), broken),
        ];
        let mut skipped = Vec::new();
        let got = select(&reports, &mut skipped);
        assert_eq!(skipped, vec![("broken".to_string(), "latency_ms.p50")]);
        assert!(!skipped.is_empty(), "build.rs fails the build on this");
        assert_eq!(got["strict"].0, "old");
    }

    /// The committed reports: each embedded profile's row is its newest
    /// primary report, and none of them is a held-out, generated-only,
    /// tool-JSON, service or sequence run.
    #[test]
    fn the_committed_reports_embed_a_primary_run_per_profile() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../docs/quality");
        let mut paths: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
            .collect();
        paths.sort();
        let reports: Vec<(String, Value)> = paths
            .iter()
            .filter_map(|p| {
                let v = serde_json::from_slice(&std::fs::read(p).ok()?).ok()?;
                Some((p.file_name()?.to_string_lossy().into_owned(), v))
            })
            .collect();
        let by_name: std::collections::BTreeMap<_, _> =
            reports.iter().map(|(n, v)| (n.as_str(), v)).collect();
        let mut skipped = Vec::new();
        let selected = select(&reports, &mut skipped);
        assert!(
            skipped.is_empty(),
            "primary reports missing fields: {skipped:?}"
        );
        for profile in ["support-email", "strict", "offline", "thorough"] {
            assert!(
                selected.contains_key(profile),
                "no primary report for {profile}"
            );
        }
        for (profile, (name, at, _)) in &selected {
            let p = &by_name[name.as_str()]["provenance"];
            assert_eq!(p["family"], "tuning", "{profile}: {name}");
            assert!(
                p["cases"].as_u64() > Some(0),
                "{profile}: {name} has no cases"
            );
            let cfg = p["config_sha256"].as_str().unwrap();
            assert!(
                !super::report_select::KNOWN_OVERRIDE_CONFIGS.contains(&cfg),
                "{profile}: {name} is a config-override run"
            );
            assert_ne!(p["config_source"], "file", "{profile}: {name}");
            // nothing primary of the profile is newer
            for (n2, v2) in &reports {
                if v2["profile"] == json!(profile) && is_primary(v2) {
                    assert!(
                        v2["provenance"]["evaluated_at"].as_i64() <= Some(*at),
                        "{n2}"
                    );
                }
            }
        }
        // the embedded rows are these rows
        let embedded = super::measured();
        assert_eq!(embedded.len(), selected.len());
        for m in &embedded {
            assert_eq!(m.evaluated_at, selected[&m.profile].1, "{}", m.profile);
            assert_eq!(m.docs, selected[&m.profile].2["docs"], "{}", m.profile);
        }
    }
}
