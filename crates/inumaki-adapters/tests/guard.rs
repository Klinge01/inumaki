//! Spec §4.2: an edit changes exactly its owned keys, or nothing is written.

use inumaki_adapters::edit::{edit_text, parse_standard, verify};
use inumaki_adapters::{Edit, Format, Node, Refusal};

fn p(keys: &[&str]) -> Vec<String> {
    keys.iter().map(|k| k.to_string()).collect()
}

const CLAUDE_JSON: &str = "{\n  \"numStartups\": 3,\n  \"mcpServers\": {\n    \"crm\": {\"command\": \"/bin/crm\"}\n  }\n}\n";

#[test]
fn an_edit_changes_exactly_its_keys_and_claude_json_stays_strict() {
    let edits = vec![Edit::Set {
        path: p(&["mcpServers", "crm"]),
        value: Node::obj([
            ("type", Node::s("http")),
            ("url", Node::s("http://127.0.0.1:8789/mcp/mcp-crm")),
        ]),
    }];
    let out = edit_text(Format::Json, CLAUDE_JSON, &edits).unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).expect("strict JSON");
    assert_eq!(v["numStartups"], 3);
    assert_eq!(v["mcpServers"]["crm"]["type"], "http");
}

#[test]
fn every_format_refuses_what_it_cannot_keep() {
    let set = vec![Edit::Set {
        path: p(&["a"]),
        value: Node::s("x"),
    }];
    // JSON with a comment is not strict JSON.
    assert_eq!(
        edit_text(Format::Json, "{ // c\n}\n", &set),
        Err(Refusal::Syntax)
    );
    // YAML flow style and anchors refuse.
    let flow = "mcp_servers: {a: {url: x}}\n";
    let e = vec![Edit::Set {
        path: p(&["mcp_servers", "b"]),
        value: Node::obj([("url", Node::s("y"))]),
    }];
    assert_eq!(edit_text(Format::Yaml, flow, &e), Err(Refusal::FlowStyle));
    let anchored = "base: &b {x: 1}\nother: *b\n";
    assert_eq!(
        edit_text(Format::Yaml, anchored, &set),
        Err(Refusal::Anchor)
    );
    // TOML cannot hold null.
    let null = vec![Edit::Set {
        path: p(&["a"]),
        value: Node::Null,
    }];
    assert_eq!(
        edit_text(Format::Toml, "x = 1\n", &null),
        Err(Refusal::Unrepresentable)
    );
    // A key of the wrong type on the path.
    let deep = vec![Edit::Set {
        path: p(&["numStartups", "x"]),
        value: Node::Int(1),
    }];
    assert_eq!(
        edit_text(Format::Json, CLAUDE_JSON, &deep),
        Err(Refusal::TypeConflict)
    );
}

#[test]
fn a_result_that_differs_outside_the_owned_keys_is_refused() {
    let edits = vec![Edit::Set {
        path: p(&["mcpServers", "crm"]),
        value: Node::s("x"),
    }];
    let old = parse_standard(Format::Json, CLAUDE_JSON).unwrap();
    // What a correct editor prints passes.
    let good = edit_text(Format::Json, CLAUDE_JSON, &edits).unwrap();
    assert_eq!(verify(Format::Json, &old, &edits, &good), Ok(()));
    // An editor that also dropped `numStartups`, changed a foreign value, or
    // printed something unparsable is refused.
    for tampered in [
        "{\"mcpServers\": {\"crm\": \"x\"}}",
        "{\"numStartups\": 4, \"mcpServers\": {\"crm\": \"x\"}}",
        "{\"numStartups\": 3, \"mcpServers\": {\"crm\": \"x\"}, \"extra\": 1}",
        "{\"numStartups\": 3, \"mcpServers\": {\"crm\": \"x\"",
    ] {
        assert_eq!(
            verify(Format::Json, &old, &edits, tampered),
            Err(Refusal::SemanticDiff),
            "{tampered}"
        );
    }
}

/// Review minor item: comments and formatting outside the owned subtree
/// survive a set, a replace, and a removal. If an editor drops a
/// neighbour's comment, fix the editor (TOML: keep the replaced item's
/// position and decor; JSON: keep same-line trivia of other nodes) until
/// this passes; never weaken the test.
#[test]
fn comments_outside_owned_keys_survive() {
    let json5 = "{\n  // keep: servers\n  mcp: { servers: {\n    a: { command: 'x' }, // keep: a\n    b: { command: 'y' }, // keep: b\n  } },\n}\n";
    let edits = vec![
        Edit::Set {
            path: p(&["mcp", "servers", "a"]),
            value: Node::obj([("url", Node::s("u"))]),
        },
        Edit::Remove {
            path: p(&["mcp", "servers", "b"]),
        },
    ];
    let out = edit_text(Format::Json5, json5, &edits).unwrap();
    for c in ["// keep: servers", "// keep: a"] {
        assert!(out.contains(c), "{c} lost:\n{out}");
    }
    let toml = "# keep: top\nmodel = \"m\"\n\n# keep: docs\n[mcp_servers.docs]\ncommand = \"d\"\n\n# keep: fast\n[profiles.fast]\nmodel = \"f\"\n";
    let edits = vec![Edit::Set {
        path: p(&["mcp_servers", "docs"]),
        value: Node::obj([("url", Node::s("u"))]),
    }];
    let out = edit_text(Format::Toml, toml, &edits).unwrap();
    for c in ["# keep: top", "# keep: docs", "# keep: fast"] {
        assert!(out.contains(c), "{c} lost:\n{out}");
    }
    assert!(
        out.find("[mcp_servers.docs]") < out.find("[profiles.fast]"),
        "the replaced table keeps its position:\n{out}"
    );
}

#[test]
fn array_edits_are_idempotent_and_marker_pulls_only_ours() {
    let text = "{\"hooks\": {\"PostToolUse\": [{\"hooks\": [{\"command\": \"/x/inumaki-hook claude-code\"}]}, {\"hooks\": [{\"command\": \"lint\"}]}]}}\n";
    let entry = Node::obj([
        ("matcher", Node::s("Bash")),
        (
            "hooks",
            Node::Arr(vec![Node::obj([(
                "command",
                Node::s("/y/inumaki-hook claude-code"),
            )])]),
        ),
    ]);
    let edits = vec![
        Edit::PullMatching {
            path: p(&["hooks", "PostToolUse"]),
            marker: "inumaki-hook".into(),
        },
        Edit::Push {
            path: p(&["hooks", "PostToolUse"]),
            value: entry.clone(),
        },
    ];
    let once = edit_text(Format::Json, text, &edits).unwrap();
    let twice = edit_text(Format::Json, &once, &edits).unwrap();
    let v: serde_json::Value = serde_json::from_str(&twice).unwrap();
    let arr = v["hooks"]["PostToolUse"].as_array().unwrap();
    assert_eq!(
        arr.len(),
        2,
        "the foreign entry stays, ours appears once: {v}"
    );
    assert!(arr.iter().any(|e| e.to_string().contains("lint")));
}

#[test]
fn node_and_error_debug_print_no_values() {
    let n = Node::obj([("Authorization", Node::s("Bearer inumaki_gw_qwxzvk"))]);
    assert!(!format!("{n:?}").contains("qwxzvk"));
    let e = inumaki_adapters::AdapterError::cannot(
        inumaki_adapters::FileRole::ClaudeJson,
        Refusal::RoundTrip,
        &[Edit::Set {
            path: p(&["mcpServers", "qwxzvk-crm"]),
            value: n,
        }],
    );
    let shown = format!("{e} {e:?}");
    assert!(!shown.contains("qwxzvk"), "{shown}");
    assert!(
        e.snippet().unwrap().contains("qwxzvk"),
        "the snippet itself carries the value for the user"
    );
}

/// Ruling F1 (privacy): `Edit`'s manual `Debug` prints the variant and the
/// key-path depth only. A path can hold a server name or a project
/// directory (Claude Code local scope keys are `projects.<dir>.mcpServers`),
/// so neither may appear, not even one segment of it.
#[test]
fn edit_debug_never_prints_a_server_name_or_a_project_path() {
    let e = Edit::Set {
        path: p(&[
            "projects",
            "/Users/jdoe/secret-project",
            "mcpServers",
            "acme-crm",
        ]),
        value: Node::s("x"),
    };
    let shown = format!("{e:?}");
    assert!(!shown.contains("acme-crm"), "{shown}");
    assert!(!shown.contains("/Users/"), "{shown}");
    assert!(!shown.contains("secret-project"), "{shown}");
}

/// Review I1: TOML `nan`/`inf`/`-inf` must not collapse to `null` the way
/// `serde_json::to_value(toml::Table)` would, or the guard could not see a
/// change to them (the same hole `Finite` already closes for JSON5).
#[test]
fn toml_non_finite_numbers_refuse() {
    let set = vec![Edit::Set {
        path: p(&["a"]),
        value: Node::s("x"),
    }];
    assert_eq!(
        edit_text(Format::Toml, "a = inf\n", &set),
        Err(Refusal::Syntax)
    );
    assert_eq!(
        edit_text(Format::Toml, "a = -inf\n", &set),
        Err(Refusal::Syntax)
    );
    assert_eq!(
        edit_text(Format::Toml, "a = nan\n", &set),
        Err(Refusal::Syntax)
    );
}

/// Review I2: a TOML file whose last line has no final newline (common with
/// "insert final newline" turned off) round-trips through `toml_edit`
/// apart from that one byte and must not be refused; the output keeps the
/// same shape (no trailing newline either).
#[test]
fn toml_without_a_final_newline_edits_successfully() {
    let edits = vec![Edit::Set {
        path: p(&["b"]),
        value: Node::Int(2),
    }];
    let out = edit_text(Format::Toml, "a = 1", &edits).unwrap();
    assert!(!out.ends_with('\n'), "{out:?}");
    let v = parse_standard(Format::Toml, &out).unwrap();
    assert_eq!(v["a"], 1);
    assert_eq!(v["b"], 2);
}
