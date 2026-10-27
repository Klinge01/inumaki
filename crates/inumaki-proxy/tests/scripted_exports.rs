//! The scripted upstream's types are reachable at the crate root, as
//! inumakid's tests and plan M8-3 import them.

use inumaki_proxy::{Script, ScriptedUpstream, Step, ToolCall};

#[test]
fn scripted_types_are_exported_at_the_crate_root() {
    let script = Script(vec![
        Step::CallTools(vec![ToolCall {
            name_suffix: "lookup".into(),
            arguments: serde_json::json!({}),
        }]),
        Step::EchoUserText,
    ]);
    let up = ScriptedUpstream::new(script);
    assert!(up.recorded().is_empty());
    let _ = inumaki_proxy::scripted::spawn_http;
}
