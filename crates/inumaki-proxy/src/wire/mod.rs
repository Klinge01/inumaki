//! Per-wire descent for the string-leaf rule (M8 spec §5.2 table).
//!
//! The rule is evaluated one step at a time: the state of a node is the state
//! of its parent container plus one step for the node's own path segment.
//! That keeps the whole walk linear in the number of nodes, whatever the
//! nesting depth (the brief's version re-walked the full path for every node).
//!
//! Each node gets two states. `me` is the state of the node itself and
//! includes the rules that apply to the value at the end of the path (a
//! structural key, a payload field). `down` is the state its children start
//! from: the same step with those end-of-path rules left out, because a
//! structural key makes only its own value structural, not what lies below it.

pub(crate) mod anthropic;
pub(crate) mod chat;
pub(crate) mod responses;
pub(crate) mod shape;

use crate::json::{Node, NodeKind, Seg};
use crate::routes::Wire;
use crate::walk::{self, Class, Ctx, Info, List, Role, Top};
use shape::Shape;

fn role_of(s: &str) -> Role {
    match s {
        "system" | "developer" => Role::System,
        "user" => Role::User,
        "assistant" => Role::Assistant,
        "tool" | "function" => Role::Tool,
        _ => Role::Other,
    }
}

/// Content types whose object is a binary container. `container_upload`
/// (Messages) references an uploaded file; `video_url`, `audio_url`, and
/// `input_video` are accepted by OpenAI-compatible upstreams, which fetch
/// the URL themselves (M8 spec §20 amendment 2026-10-11, Task 2b).
const BINARY_TYPES: &[&str] = &[
    "image",
    "input_image",
    "input_file",
    "input_audio",
    "image_url",
    "file",
    "computer_screenshot",
    "container_upload",
    "video_url",
    "audio_url",
    "input_video",
];

/// Whether an object whose own `type` is `t` is a binary container. A
/// `document` is one only by its source (see `apply_parent`).
pub(crate) fn is_binary_type(t: &str) -> bool {
    BINARY_TYPES.contains(&t)
}

/// Where a step happens: the parent container and the segment below it.
pub(crate) struct At<'a> {
    pub wire: Wire,
    /// The state the parent's children start from (its `down`).
    pub parent: &'a Ctx,
    /// What the parent container is (its `type`, its `role`).
    pub info: &'a Info<'a>,
    /// The parent's own segment (`None` for the root).
    pub parent_seg: Option<&'a Seg>,
    /// The number of segments of the parent: 0 when the parent is the root.
    pub k: usize,
    pub seg: &'a Seg,
    /// Index of the value node this step leads to (for a key node, the value after it).
    pub value: usize,
    /// The step reaches an item of the leading run ([`leading_run`]).
    pub leading_item: bool,
}

/// Whether an item of the Responses `input` or Chat `messages` array is a
/// system or developer message: an object (checked by the caller) with a
/// string `role` that reads as `Role::System` and no `type` other than
/// `message`. A typed item (`function_call`, `reasoning`,
/// `item_reference`, ...) is not, whatever its `role`.
fn system_item(info: &Info<'_>) -> bool {
    matches!(info.ty, None | Some("message" | "additional_tools"))
        && info.role.is_some_and(|r| role_of(r) == Role::System)
}

/// The leading system prompt's run of items (ruling L122): the node of the
/// Responses top-level `input` array or the Chat top-level `messages`
/// array, and how many of its first items are system/developer messages
/// ([`system_item`]) before the first item that is not one. Any other item
/// ends the run: a user, assistant, or tool message, an unknown role, a
/// role-less item, and an item that is not an object (fail closed: a later
/// system/developer item stays `Free`). `None` on Messages (its leading
/// prompt is the top-level `system`, see [`step`]) and when there is no
/// such array (a plain-string Responses `input` is a user message).
///
/// Linear: one pass to find the array (duplicate keys are refused by
/// `json::scan`), then the array's nodes up to the end of the run.
pub(crate) fn leading_run(wire: Wire, nodes: &[Node], info: &[Info<'_>]) -> Option<(usize, usize)> {
    let list = match wire {
        Wire::Responses => "input",
        Wire::Chat => "messages",
        Wire::Messages => return None,
    };
    let arr = nodes.iter().position(|n| {
        n.parent == Some(0)
            && n.kind == NodeKind::Array
            && matches!(&n.seg, Some(Seg::Key(k)) if k == list)
    })?;
    let end = nodes[arr].range.end;
    let mut run = 0;
    for (i, n) in nodes
        .iter()
        .enumerate()
        .skip(arr + 1)
        .take_while(|(_, n)| n.range.start < end)
    {
        if n.parent != Some(arr) {
            continue;
        }
        if n.kind == NodeKind::Object && system_item(&info[i]) {
            run += 1;
        } else {
            break;
        }
    }
    Some((arr, run))
}

/// The state of the node reached by one step. `last` selects `me` (true) or
/// `down` (false), see the module docs.
pub(crate) fn step(at: &At<'_>, last: bool) -> Ctx {
    let p = at.parent;
    let mut c = *p;
    c.list = List::None;
    if c.frozen {
        // Definitions and structural parameters end the descent: the rest of
        // the subtree is handled as the top-level parameter was. An MCP
        // server's credential is opaque, not data and not scanned (ruling I5).
        if c.class == Some(Class::Definition)
            && matches!(at.seg, Seg::Key(n) if n == "authorization_token")
        {
            c.class = None;
            c.structural = true;
            c.shape = Shape::Any;
            c.opaque = true;
        }
        return c;
    }
    if at.k == 0 {
        // Top-level parameters. `walk` refuses roots that are not objects, so
        // every top-level segment is a key.
        let Seg::Key(top) = at.seg else { return c };
        let top = top.as_str();
        let definition = match at.wire {
            Wire::Messages => top == "tools" || top == "mcp_servers",
            Wire::Responses => top == "tools",
            Wire::Chat => matches!(top, "tools" | "functions" | "response_format"),
        };
        if definition {
            c.class = Some(Class::Definition);
            c.frozen = true;
            return c;
        }
        if walk::structural_top(top) {
            c.structural = true;
            c.shape = shape::top_shape(top);
            c.frozen = true;
            return c;
        }
        match (at.wire, top) {
            // The leading system prompt (ruling L122), with its items below.
            (Wire::Messages, "system") | (Wire::Responses, "instructions") => {
                c.role = Some(Role::System);
                c.leading = true;
            }
            // A plain-string `input` is a user message; an array's items bring their own roles.
            (Wire::Responses, "input") if last => c.role = Some(Role::User),
            _ => {}
        }
        c.top = match (at.wire, top) {
            (_, "prompt") => Top::Prompt,
            (Wire::Responses, "text") => Top::Text,
            _ => Top::Other,
        };
    } else if at.k == 1
        && at.wire == Wire::Responses
        && p.top == Top::Text
        && matches!(at.seg, Seg::Key(n) if n == "format")
    {
        c.class = Some(Class::Definition);
        c.frozen = true;
        return c;
    }
    // An item of the leading run (ruling L122): it and everything below it.
    if at.leading_item {
        c.leading = true;
    }
    apply_parent(&mut c, at);
    c.list = list_of(at);
    let Seg::Key(name) = at.seg else { return c };
    let name = name.as_str();
    let ty = at.info.ty;

    // Codex responses-lite (0.162) sends its tool definitions as an
    // `additional_tools` item of the top-level `input`: they are
    // definitions like the top-level `tools` (namespaced ones included).
    if at.wire == Wire::Responses && at.k == 2 && ty == Some("additional_tools") && name == "tools"
    {
        c.class = Some(Class::Definition);
        c.frozen = true;
        return c;
    }

    // Tool results: the content (or output) value is one group.
    let tool_result = match (ty, name) {
        (Some("tool_result"), "content") => true,
        (
            Some(
                "function_call_output"
                | "custom_tool_call_output"
                | "local_shell_call_output"
                | "computer_call_output",
            ),
            "output",
        ) => true,
        (None, "content")
            if at.wire == Wire::Chat && matches!(at.info.role, Some("tool" | "function")) =>
        {
            true
        }
        _ => false,
    };
    if tool_result && c.class.is_none() {
        c.class = Some(Class::ToolResult);
        c.group_root = Some(at.value);
        return c;
    }
    // Tool inputs: every key and string below is data.
    let prev_is_call = matches!(
        at.parent_seg,
        Some(Seg::Key(k)) if k == "function" || k == "function_call"
    );
    let (tool_input, inner_json) = match (ty, name) {
        (Some("tool_use" | "server_tool_use" | "mcp_tool_use" | "custom_tool_call"), "input") => {
            (true, false)
        }
        (Some("local_shell_call"), "action") => (true, false),
        (Some("function_call"), "arguments") => (true, true),
        // A Codex MCP call's `namespace` (M8 spec §20 amendment 2026-10-10):
        // model-written like the arguments, and seeded as such from answers.
        (Some("function_call"), "namespace") => (true, false),
        (_, "arguments") if prev_is_call => (true, true),
        _ => (false, false),
    };
    if tool_input && c.class.is_none() {
        c.class = Some(Class::ToolInput);
        c.inner_json = inner_json;
        return c;
    }
    if c.class == Some(Class::ToolInput) {
        return c; // no structural keys inside tool inputs
    }
    // Caller-keyed maps (review C3): below `metadata` (any wire, any depth) and
    // `prompt.variables`, every key and string is data, `id`, `*_id`, `type`, and
    // `status` included. Only the children are data, not the map's own key.
    if !last && (name == "metadata" || (at.k == 1 && c.top == Top::Prompt && name == "variables")) {
        c.data = true;
        c.structural = false;
        return c;
    }
    if c.data {
        return c;
    }
    // Scanned, never changed: only at the positions spec §5.2 names. The
    // same keys anywhere else (an unknown parameter) are ordinary data
    // (decision 17), so a validated identifier there is still tokenized.
    let scan = match at.wire {
        Wire::Messages => {
            (p.list == List::ContentItem
                && matches!(
                    (ty, name),
                    (Some("thinking"), "thinking") | (Some("search_result"), "source")
                ))
                || (p.list == List::CitationItem && name == "cited_text")
        }
        Wire::Responses => {
            p.list == List::SummaryItem && ty == Some("summary_text") && name == "text"
        }
        Wire::Chat => false,
    };
    if scan {
        c.class = Some(Class::Scan);
        return c;
    }
    // The value itself only: below a non-string value at that position
    // (an object or array), every string is data.
    if last && opaque_signed(at, ty, name) {
        c.structural = true;
        c.shape = Shape::Any;
    }
    if walk::structural_subtree(name, at.k == 0) {
        c.structural = true;
        c.shape = if name == "cache_control" {
            Shape::CacheControl
        } else {
            Shape::Token
        };
    }
    // A call object (legacy Chat `function_call`, `tool_calls[].function`): its `name` is structural.
    if name == "function" || name == "function_call" {
        c.tool_call = true;
    }
    if last {
        // A structural key is trusted only when its value has the key's
        // shape (spec §5.2 note of 2026-10-05); inside a structural subtree
        // the subtree's shape applies.
        if !p.structural {
            if let Some(s) = shape::key_shape(name) {
                c.structural = true;
                c.shape = s;
            }
        } else if p.shape == Shape::CacheControl && name != "cache_control" {
            c.shape = match name {
                "type" => Shape::OneOf(&["ephemeral"]),
                "ttl" => Shape::OneOf(&["5m", "1h"]),
                _ => Shape::OneOf(&[]),
            };
        }
        // A tool call's name, and the name of a legacy `function` message, is the
        // function's name, not a person's (spec §5.2; a `user` message's `name` stays data).
        if name == "name" && (c.tool_call || at.info.role == Some("function")) {
            c.structural = true;
            c.shape = Shape::Any;
        }
        if c.binary && matches!(name, "data" | "file_data") {
            c.payload = true;
        }
    }
    c
}

/// An opaque signed field at its real position (spec §5.2): forwarded as
/// received, never scanned. The same keys anywhere else are data
/// (decision 17), so `{"unknown_param": {"type": "redacted_thinking",
/// "data": ...}}` is sanitized like any text.
///
/// - Messages, in a content item (`messages[i].content[j]`, or a content
///   item's `tool_result.content[j]`): `thinking.signature`,
///   `redacted_thinking.data`.
/// - Messages, in a `web_search_tool_result`'s `content[k]`:
///   `web_search_result.encrypted_content`.
/// - Messages, in a text item's `citations[k]`:
///   `web_search_result_location.encrypted_index`.
/// - Responses, in `input[i]`: `reasoning.encrypted_content`.
fn opaque_signed(at: &At<'_>, ty: Option<&str>, name: &str) -> bool {
    let p = at.parent.list;
    match at.wire {
        Wire::Messages => {
            (p == List::ContentItem
                && matches!(
                    (ty, name),
                    (Some("thinking"), "signature") | (Some("redacted_thinking"), "data")
                ))
                || (p == List::WebResultItem
                    && ty == Some("web_search_result")
                    && name == "encrypted_content")
                || (p == List::CitationItem
                    && ty == Some("web_search_result_location")
                    && name == "encrypted_index")
        }
        Wire::Responses => {
            p == List::InputItem && ty == Some("reasoning") && name == "encrypted_content"
        }
        Wire::Chat => false,
    }
}

/// The known list (or list item) one step reaches (see [`List`]): Messages
/// `messages[i].content[j]` (and a content item's `tool_result.content[j]`),
/// a text item's `citations[k]`, a `web_search_tool_result`'s `content[k]`;
/// Responses `input[i]` and a reasoning
/// item's `summary[k]`. Everything else is `List::None`.
fn list_of(at: &At<'_>) -> List {
    let p = at.parent.list;
    match at.seg {
        Seg::Index(_) => match p {
            List::Messages => List::MessageItem,
            List::Content => List::ContentItem,
            List::Citations => List::CitationItem,
            List::Input => List::InputItem,
            List::Summary => List::SummaryItem,
            List::WebResults => List::WebResultItem,
            _ => List::None,
        },
        Seg::Key(k) => match (at.wire, k.as_str(), at.info.ty) {
            (Wire::Messages, "messages", _) if at.k == 0 => List::Messages,
            (Wire::Responses, "input", _) if at.k == 0 => List::Input,
            (Wire::Messages, "content", _) if p == List::MessageItem => List::Content,
            (Wire::Messages, "content", Some("tool_result")) if p == List::ContentItem => {
                List::Content
            }
            (Wire::Messages, "content", Some("web_search_tool_result"))
                if p == List::ContentItem =>
            {
                List::WebResults
            }
            (Wire::Messages, "citations", Some("text")) if p == List::ContentItem => {
                List::Citations
            }
            (Wire::Responses, "summary", Some("reasoning")) if p == List::InputItem => {
                List::Summary
            }
            _ => List::None,
        },
    }
}

/// What the parent container is changes how everything inside it is handled.
fn apply_parent(c: &mut Ctx, at: &At<'_>) {
    if let Some(r) = at.info.role {
        c.role = Some(role_of(r));
    }
    let Some(t) = at.info.ty else { return };
    // Responses items without a role take one from their type.
    match t {
        "function_call" | "custom_tool_call" | "reasoning" | "local_shell_call"
        | "computer_call" => {
            c.role = Some(Role::Assistant);
        }
        "function_call_output"
        | "custom_tool_call_output"
        | "local_shell_call_output"
        | "computer_call_output" => c.role = Some(Role::Tool),
        _ => {}
    }
    if is_binary_type(t) || (t == "document" && at.info.source_binary) {
        c.binary = true;
    }
    if walk::tool_call_type(t) {
        c.tool_call = true;
    }
}
