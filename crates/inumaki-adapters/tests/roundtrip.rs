//! Every corpus file prints back byte-identical through its concrete-syntax
//! editor, and parses under its standard parser (spec §4.2 precondition).
//! Refusal samples are checked in Task 2 once `edit_text` exists.

use std::str::FromStr;

fn corpus(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/corpus/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn json_and_json5_round_trip_through_the_cst() {
    for name in [
        "claude.json",
        "settings.json",
        "codex-hooks.json",
        "openclaw.json5",
    ] {
        let text = corpus(name);
        let root =
            jsonc_parser::cst::CstRootNode::parse(&text, &jsonc_parser::ParseOptions::default())
                .unwrap();
        assert_eq!(root.to_string(), text, "{name}");
    }
    for name in ["claude.json", "settings.json", "codex-hooks.json"] {
        serde_json::from_str::<serde_json::Value>(&corpus(name)).unwrap();
    }
    json5::from_str::<serde_json::Value>(&corpus("openclaw.json5")).unwrap();
}

#[test]
fn toml_round_trips_through_toml_edit() {
    let text = corpus("codex-config.toml");
    let doc: toml_edit::DocumentMut = text.parse().unwrap();
    assert_eq!(doc.to_string(), text);
    toml::from_str::<toml::Table>(&text).unwrap();
}

/// `yaml_edit::YamlFile`, not `yaml_edit::Document`: `Document::from_str` rejects
/// comments before the first key ("stream-level comments"), which every real
/// Hermes `config.yaml` has (docs/harness-adapters.md, editor decision).
#[test]
fn yaml_round_trips_through_yaml_edit() {
    let text = corpus("hermes-config.yaml");
    let file = yaml_edit::YamlFile::from_str(&text).unwrap();
    assert_eq!(file.to_string(), text);
    serde_yaml_ng::from_str::<serde_json::Value>(&text).unwrap();
}

#[test]
fn refusal_samples_are_refused() {
    use inumaki_adapters::edit::edit_text;
    use inumaki_adapters::{Edit, Format, Node};
    let set = vec![Edit::Set {
        path: vec!["x".into()],
        value: Node::s("y"),
    }];
    let flow = [Edit::Set {
        path: vec!["mcp_servers".into(), "b".into()],
        value: Node::obj([("url", Node::s("u"))]),
    }];
    assert_eq!(
        edit_text(Format::Yaml, &corpus("hermes-flow.yaml"), &flow),
        Err(inumaki_adapters::Refusal::FlowStyle)
    );
    assert_eq!(
        edit_text(Format::Yaml, &corpus("hermes-anchor.yaml"), &set),
        Err(inumaki_adapters::Refusal::Anchor)
    );
    assert_eq!(
        edit_text(Format::Json5, &corpus("openclaw-edge.json5"), &set),
        Err(inumaki_adapters::Refusal::Syntax)
    );
    assert_eq!(
        edit_text(Format::Json5, &corpus("openclaw-infinity.json5"), &set),
        Err(inumaki_adapters::Refusal::Syntax)
    );
}

/// The lossless YAML editor (docs/harness-adapters.md, editor decision):
/// comments survive, a mapping value is a block, missing parents are built,
/// and the result parses to exactly the old value plus the edits.
#[test]
fn yaml_edits_keep_comments_and_print_valid_blocks() {
    use inumaki_adapters::edit::edit_text;
    use inumaki_adapters::edit::parse_standard;
    use inumaki_adapters::{Edit, Format, Node};
    let text = corpus("hermes-config.yaml");
    let p = |k: &[&str]| k.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let edits = vec![
        Edit::Set {
            path: p(&["mcp_servers", "crm"]),
            value: Node::obj([
                ("url", Node::s("http://127.0.0.1:8789/mcp/mcp-crm")),
                (
                    "headers",
                    Node::obj([("Authorization", Node::s("Bearer inumaki_gw_x"))]),
                ),
            ]),
        },
        Edit::Set {
            path: p(&["model", "provider"]),
            value: Node::s("inumaki"),
        },
        Edit::Set {
            path: p(&["providers", "inumaki"]),
            value: Node::obj([
                ("base_url", Node::s("http://127.0.0.1:8787/openai/v1")),
                ("key_env", Node::s("OPENAI_API_KEY")),
            ]),
        },
        Edit::Set {
            path: p(&["a", "b", "c"]),
            value: Node::Bool(true),
        },
        Edit::Push {
            path: p(&["mcp_servers", "filesystem", "args"]),
            value: Node::s("/extra dir"),
        },
        Edit::Pull {
            path: p(&["mcp_servers", "filesystem", "args"]),
            value: Node::s("-y"),
        },
        Edit::Remove {
            path: p(&["display", "skin"]),
        },
    ];
    let out = edit_text(Format::Yaml, &text, &edits).unwrap();
    for keep in [
        "# Hermes Agent configuration (synthetic corpus sample).",
        "# Default model to use.",
        "# inline comment",
    ] {
        assert!(out.contains(keep), "{keep} lost:\n{out}");
    }
    let v = parse_standard(Format::Yaml, &out).unwrap();
    assert_eq!(
        v["mcp_servers"]["crm"]["headers"]["Authorization"],
        "Bearer inumaki_gw_x"
    );
    assert_eq!(v["a"]["b"]["c"], true);
    assert_eq!(v["model"]["provider"], "inumaki");
    assert_eq!(
        v["providers"]["office-proxy"]["key_env"],
        "OFFICE_PROXY_KEY"
    );
}

/// A replaced entry loses its old keys, a second apply changes nothing, and
/// strings YAML would read as something else are quoted (the semantic guard
/// inside `edit_text` refuses otherwise).
#[test]
fn yaml_replace_is_idempotent_and_quotes_special_strings() {
    use inumaki_adapters::edit::{edit_text, parse_standard};
    use inumaki_adapters::{Edit, Format, Node};
    let text = corpus("hermes-config.yaml");
    let p = |k: &[&str]| k.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let replace = vec![Edit::Set {
        path: p(&["mcp_servers", "filesystem"]),
        value: Node::obj([
            ("url", Node::s("http://127.0.0.1:8789/mcp/mcp-fs")),
            (
                "headers",
                Node::obj([("Authorization", Node::s("Bearer inumaki_gw_x"))]),
            ),
        ]),
    }];
    let once = edit_text(Format::Yaml, &text, &replace).unwrap();
    let v = parse_standard(Format::Yaml, &once).unwrap();
    assert!(v["mcp_servers"]["filesystem"].get("command").is_none());
    assert_eq!(edit_text(Format::Yaml, &once, &replace).unwrap(), once);
    for s in [
        "yes",
        "null",
        "123",
        "1.5",
        "@a",
        "*x y",
        "- x",
        "a: b # c",
        "Bearer t: x",
        "",
        "  padded ",
        "multi\nline",
        "'q'",
        "\"dq\"",
        "%d",
        "!tag",
        "&a",
    ] {
        let e = vec![Edit::Set {
            path: p(&["model", "provider"]),
            value: Node::s(s),
        }];
        match edit_text(Format::Yaml, &text, &e) {
            Ok(out) => assert_eq!(
                parse_standard(Format::Yaml, &out).unwrap()["model"]["provider"],
                s,
                "{s:?}"
            ),
            Err(r) => assert_eq!(
                r,
                inumaki_adapters::Refusal::SemanticDiff,
                "{s:?} must be quoted or refused"
            ),
        }
    }
}
