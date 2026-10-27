//! The string-leaf rule (M8 spec §5.2, review C1): every string leaf of a
//! request body is data unless its key is structural or it is an opaque
//! signed field. Known types only change how a leaf is handled.
//!
//! Privacy: a `Leaf` carries request text, so its `Debug` shows class, role,
//! and length only; `Walk`'s `Debug` shows counts only.

use std::collections::HashMap;
use std::ops::Range;
use std::sync::LazyLock;

use crate::config::BinaryMode;
use crate::json::{self, JsonError, Node, NodeKind, Seg};
use crate::routes::Wire;
use crate::wire::{self, At};

/// How a leaf is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// Free text: sanitized.
    Text,
    /// A tool result's content: sanitized, or replaced by the placeholder when blocked.
    ToolResult,
    /// A tool call's input: every key and string is its own block.
    ToolInput,
    /// A tool or schema definition: scanned with `scan_clear`, never changed.
    Definition,
    /// Reasoning, citation, and search-source text: scanned, never changed.
    Scan,
}

/// Who wrote it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
    Other,
}

/// Where a leaf's bytes are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A string or key node of the body.
    Node(usize),
    /// A string literal inside the decoded text of a string node (function
    /// arguments carried as JSON text); `range` is into that decoded text.
    Inner { node: usize, range: Range<usize> },
}

/// One piece of text the pipeline sanitizes, scans, or checks.
#[derive(Clone)]
pub struct Leaf {
    pub class: Class,
    pub role: Role,
    pub target: Target,
    pub text: String,
    pub group: Option<usize>,
    /// Under the leading system prompt (ruling L122, see
    /// [`wire::leading_run`]): Messages top-level `system`, Responses
    /// `instructions`, and the leading run of system/developer items of the
    /// Responses `input` or Chat `messages` array. The only positions whose
    /// text may be harness-static (`pipeline::leaf_origin`).
    pub leading: bool,
}

impl std::fmt::Debug for Leaf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Leaf")
            .field("class", &self.class)
            .field("role", &self.role)
            .field("len", &self.text.len())
            .field("leading", &self.leading)
            .finish()
    }
}

/// A tool result's content (or output) value: replaced whole by the
/// placeholder when withheld.
#[derive(Debug, Clone)]
pub struct Group {
    pub node: usize,
    pub binary: bool,
}

/// The text every replaced part becomes (M8 spec §20 amendment 2026-10-11):
/// the same on every wire and for every kind, with no filename, URL, media
/// type, size, or count of what was there.
pub const PART_PLACEHOLDER: &str = "[inumaki: an attachment (image, document, audio, or file) was removed here and not sent to the model.]";

/// The bytes a part is replaced by: a Messages or Chat text part, a
/// Responses `input_text` part, and a bare JSON string (a data URI).
static PART_BYTES: LazyLock<[Vec<u8>; 3]> = LazyLock::new(|| {
    let p = json::quote(PART_PLACEHOLDER);
    [
        format!(r#"{{"type":"text","text":{p}}}"#).into_bytes(),
        format!(r#"{{"type":"input_text","text":{p}}}"#).into_bytes(),
        p.into_bytes(),
    ]
});

/// The replacement for a part: it depends only on the wire and on whether
/// the part is an object or a string.
pub fn part_replacement(wire: Wire, object: bool) -> &'static [u8] {
    let [chat, responses, string] = &*PART_BYTES;
    match (object, wire) {
        (false, _) => string,
        (true, Wire::Responses) => responses,
        (true, Wire::Messages | Wire::Chat) => chat,
    }
}

/// A binary part outside every tool result, replaced whole in
/// `placeholder` mode: the object from `{` to `}`, or the data-URI string
/// with its quotes. None of its strings is a leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Part {
    pub node: usize,
    pub replacement: &'static [u8],
}

/// A classified body. Leaves come in document order.
pub struct Walk {
    pub nodes: Vec<Node>,
    pub leaves: Vec<Leaf>,
    pub groups: Vec<Group>,
    /// Binary content outside tool results that no part covers (`refuse`
    /// and `forward` walks: all of it; `placeholder` walks: only binary the
    /// walk could not place in a part: a binary root object, a binary
    /// object inside a definition). Refused unless the mode is `forward`.
    pub user_binary: bool,
    /// The parts a `placeholder` walk replaces; empty in the other modes.
    pub parts: Vec<Part>,
    pub stream: bool,
    pub first_system: Option<String>,
    pub first_user: Option<String>,
    /// Bytes the forwarded body leaves out (`removal`): no leaf lies in
    /// them, and `pipeline::apply_edits` splices them away.
    pub removed: Option<Range<usize>>,
}

impl std::fmt::Debug for Walk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Walk")
            .field("nodes", &self.nodes.len())
            .field("leaves", &self.leaves.len())
            .field("groups", &self.groups.len())
            .field("user_binary", &self.user_binary)
            .field("parts", &self.parts.len())
            .field("stream", &self.stream)
            .field(
                "first_system_len",
                &self.first_system.as_ref().map(String::len),
            )
            .field("first_user_len", &self.first_user.as_ref().map(String::len))
            .field("removed", &self.removed.is_some())
            .finish()
    }
}

// The structural keys and the shapes their values must have live in
// `wire::shape` (`key_shape`), spec §5.2 note of 2026-10-05. The opaque
// signed fields (`signature`, `encrypted_content`, `encrypted_index`,
// `redacted_thinking.data`) are opaque only at their real positions
// (`wire::opaque_signed`), and data everywhere else (decision 17).
/// Structural at any depth (its strings must be configuration tokens).
const STRUCTURAL_SUBTREES: &[&str] = &["cache_control"];
/// Structural only as top-level parameters; nested occurrences are data.
const STRUCTURAL_TOP_SUBTREES: &[&str] =
    &["tool_choice", "stream_options", "include", "modalities"];
// `mcp_servers` is a definition, not structural (ruling I5). `truncation`,
// `store`, and `previous_response_id` are structural top-level parameters,
// their strings shape-checked (`wire::shape::top_shape`); `verbosity` and
// `object` are structural keys with closed value sets (spec §5.2 note of
// 2026-10-05).
const STRUCTURAL_TOP: &[&str] = &[
    "model",
    "thinking",
    "reasoning",
    "service_tier",
    "prompt_cache_key",
    "previous_response_id",
    "truncation",
    "stream",
    "store",
];
const TOOL_CALL_TYPES: &[&str] = &[
    "tool_use",
    "server_tool_use",
    "mcp_tool_use",
    "function_call",
    "custom_tool_call",
    "local_shell_call",
    "function",
];

pub(crate) fn structural_subtree(k: &str, top_level: bool) -> bool {
    STRUCTURAL_SUBTREES.contains(&k) || (top_level && STRUCTURAL_TOP_SUBTREES.contains(&k))
}
pub(crate) fn structural_top(k: &str) -> bool {
    STRUCTURAL_TOP.contains(&k)
}
pub(crate) fn tool_call_type(t: &str) -> bool {
    TOOL_CALL_TYPES.contains(&t)
}

/// The top-level parameter a node lies under, where that changes the rule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Top {
    #[default]
    Other,
    /// `prompt` (its `variables` are caller-keyed).
    Prompt,
    /// Responses `text` (its `format` is a definition).
    Text,
}

/// What the descent to a node found. Small and `Copy`: one is kept per container.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Ctx {
    pub structural: bool,
    /// The shape a structural value must have to stay structural; any other
    /// value is data (spec §5.2 note of 2026-10-05).
    pub shape: crate::wire::shape::Shape,
    pub class: Option<Class>,
    pub role: Option<Role>,
    pub binary: bool,
    /// The value node of the enclosing tool result's content.
    pub group_root: Option<usize>,
    /// The enclosing binary part (an object outside every tool result).
    pub part_root: Option<usize>,
    /// The string is JSON text (function arguments).
    pub inner_json: bool,
    /// Inside a tool call object (its `name` is structural).
    pub tool_call: bool,
    /// Inside a caller-keyed map (`metadata`, `prompt.variables`): every key and string is data.
    pub data: bool,
    /// A binary part's payload field (`data`, `file_data`): never a leaf.
    pub payload: bool,
    /// An opaque credential: not data, not scanned.
    pub opaque: bool,
    /// The descent ended at a top-level parameter; nothing below changes.
    pub frozen: bool,
    pub top: Top,
    /// Which known list (or list item) this node is, one level only: the
    /// scanned fields are scanned only at their real positions (decision 17).
    pub list: List,
    /// Under the leading system prompt (ruling L122): set at the top-level
    /// `system`/`instructions` key and at an item of the leading run
    /// (`wire::leading_run`), inherited by everything below.
    pub leading: bool,
}

/// The known lists whose items hold scanned fields (spec §5.2). Set for the
/// node itself only, never inherited: the item of a `citations` list is a
/// `CitationItem`, its children are `None` again.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum List {
    #[default]
    None,
    /// Messages top-level `messages`.
    Messages,
    MessageItem,
    /// Messages `messages[].content`, or a content item's `tool_result.content`.
    Content,
    ContentItem,
    /// Messages `citations` of a `text` content item.
    Citations,
    CitationItem,
    /// Responses top-level `input`.
    Input,
    InputItem,
    /// Responses `summary` of a `reasoning` input item.
    Summary,
    SummaryItem,
    /// Messages `content` of a `web_search_tool_result` content item.
    WebResults,
    WebResultItem,
}

/// What a container is, found before the descent starts (a `type` key may
/// come after the keys it governs).
#[derive(Clone, Copy, Default)]
pub(crate) struct Info<'a> {
    pub ty: Option<&'a str>,
    pub role: Option<&'a str>,
    /// Its `source` child is an object of type `base64`, `url`, or `file`.
    pub source_binary: bool,
    /// Its `source` child is an object of type `text` or `content`.
    pub source_text: bool,
}

/// Lengths only: the strings come from the request body.
impl std::fmt::Debug for Info<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Info")
            .field("ty_len", &self.ty.map(str::len))
            .field("role_len", &self.role.map(str::len))
            .field("source_binary", &self.source_binary)
            .field("source_text", &self.source_text)
            .finish()
    }
}

/// A base64 data URI anywhere is a binary payload (review I3). Both
/// markers match in any case, as URI schemes and parameters do.
fn is_data_uri(s: &str) -> bool {
    s.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("data:"))
        && s.as_bytes()
            .windows(8)
            .any(|w| w.eq_ignore_ascii_case(b";base64,"))
}

fn group_index(w: &mut Walk, map: &mut HashMap<usize, usize>, root: usize) -> usize {
    *map.entry(root).or_insert_with(|| {
        w.groups.push(Group {
            node: root,
            binary: false,
        });
        w.groups.len() - 1
    })
}

/// The `client_metadata` member Codex fills with its turn metadata.
pub const TURN_METADATA_KEY: &str = "x-codex-turn-metadata";

/// The member dropped from a Responses body before anything is sanitized
/// (ruling L58, Option D): `client_metadata["x-codex-turn-metadata"]` of the
/// top-level `client_metadata` object only. Codex copies its turn metadata
/// there; the copy names the repository root path (with the login name),
/// the git remote org/repo, and the latest commit hash, and the provider
/// does not need it to answer. The value is never a leaf, so it is never
/// sanitized, cached, or recorded. Occurrences anywhere else (history items,
/// nested objects) are ordinary data.
///
/// Fail closed: any other shape (`client_metadata` not an object, no such
/// member) removes nothing, and whatever is there goes through the
/// sanitizer as before. Other `client_metadata` members stay; an emptied
/// object stays `{}`. Keys are compared decoded, as the provider reads them.
fn removal(wire: Wire, nodes: &[Node]) -> Option<Range<usize>> {
    if wire != Wire::Responses {
        return None;
    }
    let is_key = |n: &Node, name: &str| matches!(&n.seg, Some(Seg::Key(k)) if k == name);
    let cm = nodes.iter().position(|n| {
        n.parent == Some(0) && n.kind == NodeKind::Object && is_key(n, "client_metadata")
    })?;
    let end = nodes[cm].range.end;
    let key = nodes
        .iter()
        .enumerate()
        .skip(cm + 1)
        .take_while(|(_, n)| n.range.start < end)
        .find(|(_, n)| {
            n.parent == Some(cm) && n.kind == NodeKind::Key && is_key(n, TURN_METADATA_KEY)
        })?
        .0;
    json::member_removal(nodes, cm, key)
}

/// [`walk_for`] in `refuse` mode: every binary part is flagged, none is
/// replaced.
pub fn walk(wire: Wire, body: &[u8]) -> Result<Walk, JsonError> {
    walk_for(wire, body, BinaryMode::Refuse)
}

/// Classify a request `body` for the binary `mode` (M8 spec §20 amendment
/// 2026-10-11). A root that is not an object is refused
/// (`JsonError::Invalid`): no supported API sends one, and a bare string
/// would otherwise be forwarded unsanitized. Linear in the number of nodes: each node's state is its
/// parent's plus one step (see `wire`).
///
/// A *part* is the outermost binary container outside every tool result
/// (its own type is binary, see [`opens_part`]), or a base64 data-URI
/// string outside such a container and outside every tool result. A binary
/// container inside a definition is not a part: it sets `user_binary` in
/// `placeholder` and `refuse` mode.
/// - `placeholder`: each part is listed in `parts`, and nothing inside it
///   is a leaf (none reaches the engine, the cache, or the journal). A tool
///   result inside a part still forms its binary group, so the two edits
///   overlap and the request fails closed.
/// - `refuse`: a part sets `user_binary`; leaves as in `forward`.
/// - `forward`: only payload fields (`data`, `file_data`, data URIs) are
///   skipped; the rest of a binary part is sanitized as data.
pub fn walk_for(wire: Wire, body: &[u8], mode: BinaryMode) -> Result<Walk, JsonError> {
    let nodes = json::scan(body)?;
    let n = nodes.len();
    if nodes.first().map(|r| r.kind) != Some(NodeKind::Object) {
        return Err(JsonError::Invalid);
    }
    let stream = nodes.iter().any(|m| {
        m.parent == Some(0)
            && m.kind == NodeKind::Other
            && matches!(&m.seg, Some(Seg::Key(k)) if k == "stream")
            && &body[m.range.clone()] == b"true"
    });
    let mut w = Walk {
        nodes: Vec::new(),
        leaves: Vec::new(),
        groups: Vec::new(),
        user_binary: false,
        parts: Vec::new(),
        stream,
        first_system: None,
        first_user: None,
        removed: removal(wire, &nodes),
    };

    // Pass 1: what each container is.
    let mut info: Vec<Info<'_>> = vec![Info::default(); n];
    for m in &nodes {
        if let (NodeKind::String, Some(p), Some(Seg::Key(k))) = (m.kind, m.parent, &m.seg) {
            match k.as_str() {
                "type" => info[p].ty = m.text.as_deref(),
                "role" => info[p].role = m.text.as_deref(),
                _ => {}
            }
        }
    }
    for (i, m) in nodes.iter().enumerate() {
        if let (NodeKind::Object, Some(p), Some(Seg::Key(k))) = (m.kind, m.parent, &m.seg) {
            if k == "source" && matches!(info[i].ty, Some("base64" | "url" | "file")) {
                info[p].source_binary = true;
            }
            if k == "source" && matches!(info[i].ty, Some("text" | "content")) {
                info[p].source_text = true;
            }
        }
    }

    // The leading run of system/developer items (ruling L122).
    let lead = wire::leading_run(wire, &nodes, &info);

    // Pass 2: states, parent before child (a container precedes its children).
    let mut down: Vec<Ctx> = vec![Ctx::default(); n];
    let mut depth: Vec<u16> = vec![0; n];
    let mut group_of: HashMap<usize, usize> = HashMap::new();
    for (i, m) in nodes.iter().enumerate() {
        // The removed member's key, value, and everything inside it: never
        // leaves, never groups (their descendants are skipped the same way).
        if w.removed
            .as_ref()
            .is_some_and(|r| r.contains(&m.range.start))
        {
            continue;
        }
        let mut ctx = if let (Some(p), Some(seg)) = (m.parent, &m.seg) {
            let container = matches!(m.kind, NodeKind::Object | NodeKind::Array);
            let at = At {
                wire,
                parent: &down[p],
                info: &info[p],
                parent_seg: nodes[p].seg.as_ref(),
                k: usize::from(depth[p]),
                seg,
                value: if m.kind == NodeKind::Key { i + 1 } else { i },
                leading_item: lead
                    .is_some_and(|(arr, run)| p == arr && matches!(seg, Seg::Index(j) if *j < run)),
            };
            let me = wire::step(&at, true);
            if container {
                down[i] = wire::step(&at, false);
                depth[i] = depth[p] + 1;
            }
            // A key is data when the object it sits in is; the segment it names
            // starts nothing for itself (the key `input` of a tool use is not input).
            if m.kind == NodeKind::Key {
                Ctx {
                    opaque: me.opaque,
                    payload: me.payload,
                    ..down[p]
                }
            } else {
                me
            }
        } else {
            // The root, always an object here: default state.
            Ctx::default()
        };

        // A Responses `image_generation` tool's `input_image_mask`
        // (`{image_url, file_id}`, no `type`) names an image the provider
        // fetches itself, unchecked: an https URL or a file id as much as a
        // data URI. It sits in a definition, which is never changed, so it
        // is refused in `placeholder` and `refuse` mode, at any depth below
        // `tools` and in any value shape (recall first).
        if wire == Wire::Responses
            && matches!(m.kind, NodeKind::Object | NodeKind::String)
            && matches!(&m.seg, Some(Seg::Key(k)) if k == "input_image_mask")
            && under_tools(&nodes, i)
        {
            w.user_binary = true;
        }

        // The outermost binary object outside every tool result is a part,
        // under a structural top-level parameter too (`reasoning`,
        // `thinking`): the descent stops there, so only the object's own
        // type tells. Inside a definition (and an MCP server's credential)
        // it is refused in both modes: a definition is never changed. The
        // root never is a part: a binary root stays `user_binary` and is
        // refused.
        if mode != BinaryMode::Forward
            && m.kind == NodeKind::Object
            && i > 0
            && ctx.part_root.is_none()
            && ctx.group_root.is_none()
            && !ctx.binary
            && opens_part(&info[i])
        {
            if ctx.frozen && (ctx.class == Some(Class::Definition) || ctx.opaque) {
                w.user_binary = true;
            } else {
                ctx.part_root = Some(i);
                down[i].part_root = Some(i);
                match mode {
                    BinaryMode::Placeholder => w.parts.push(Part {
                        node: i,
                        replacement: part_replacement(wire, true),
                    }),
                    _ => w.user_binary = true,
                }
            }
        }
        if mode == BinaryMode::Placeholder && ctx.part_root.is_some() {
            // Inside a part: never a leaf. A tool result here still forms
            // its group (binary, so withheld): its edit overlaps the part's
            // and `apply_edits` fails closed.
            if let Some(root) = ctx.group_root {
                let g = group_index(&mut w, &mut group_of, root);
                w.groups[g].binary = true;
            }
            continue;
        }
        let data_uri = m.kind == NodeKind::String && m.text.as_deref().is_some_and(is_data_uri);
        if mode == BinaryMode::Placeholder && data_uri && ctx.group_root.is_none() && !ctx.binary {
            w.parts.push(Part {
                node: i,
                replacement: part_replacement(wire, false),
            });
            continue;
        }
        if ctx.binary || data_uri {
            match ctx.group_root {
                Some(root) => {
                    let g = group_index(&mut w, &mut group_of, root);
                    w.groups[g].binary = true;
                }
                None => w.user_binary = true,
            }
            // Only the payload is never a leaf: a document's title and context,
            // a file's name, and an image URL are still data (review I3).
            if data_uri || ctx.payload {
                continue;
            }
        }
        let keyed = ctx.data || matches!(ctx.class, Some(Class::ToolInput | Class::Definition));
        let is_text = match m.kind {
            NodeKind::String => true,
            NodeKind::Key => keyed && !ctx.opaque,
            _ => false,
        };
        if !is_text {
            continue;
        }
        // A structural value is trusted only in its shape; any other value
        // is data (recall first; spec §5.2 note of 2026-10-05).
        let off_shape = ctx.structural && !keyed;
        if off_shape && ctx.shape.accepts(m.text.as_deref().unwrap_or("")) {
            continue;
        }
        let class = ctx.class.unwrap_or(Class::Text);
        let role = ctx.role.unwrap_or(Role::Other);
        let group = ctx
            .group_root
            .map(|root| group_index(&mut w, &mut group_of, root));
        let text = m.text.clone().unwrap_or_default();
        if ctx.inner_json && m.kind == NodeKind::String {
            if let Ok(inner) = json::scan(text.as_bytes()) {
                for q in inner
                    .iter()
                    .filter(|q| matches!(q.kind, NodeKind::String | NodeKind::Key))
                {
                    w.leaves.push(Leaf {
                        class,
                        role,
                        target: Target::Inner {
                            node: i,
                            range: q.range.clone(),
                        },
                        text: q.text.clone().unwrap_or_default(),
                        group,
                        leading: ctx.leading,
                    });
                }
                continue;
            }
        }
        // A Chat message's `name` is not its text.
        let is_name = matches!(&m.seg, Some(Seg::Key(k)) if k == "name");
        if class == Class::Text && !is_name && !off_shape {
            if role == Role::System && w.first_system.is_none() {
                w.first_system = Some(text.clone());
            }
            if role == Role::User && w.first_user.is_none() {
                w.first_user = Some(text.clone());
            }
        }
        w.leaves.push(Leaf {
            class,
            role,
            target: Target::Node(i),
            text,
            group,
            // A Chat message's `name` and an off-shape value inside a leading
            // item are not harness prose: they keep the Free reading (fail
            // closed, final review M3).
            leading: ctx.leading && !is_name && !off_shape,
        });
    }
    drop(info);
    w.nodes = nodes;
    Ok(w)
}

/// Whether node `i` lies under the top-level `tools` parameter.
fn under_tools(nodes: &[Node], mut i: usize) -> bool {
    while let Some(p) = nodes[i].parent {
        if p == 0 {
            return matches!(&nodes[i].seg, Some(Seg::Key(k)) if k == "tools");
        }
        i = p;
    }
    false
}

/// Whether an object's own type makes it a binary container: one of the
/// wire's binary types (`wire::is_binary_type`, the list the per-wire step
/// uses), or a `document` whose source is not `text` or `content` (an
/// unknown or missing source is binary: fail closed). The type is read
/// directly rather than through the step, because the step stops at a
/// frozen top-level parameter.
fn opens_part(info: &Info<'_>) -> bool {
    match info.ty {
        Some("document") => !info.source_text,
        Some(t) => wire::is_binary_type(t),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: &str = "Zyxwuria";

    fn leaves(wire: Wire, body: serde_json::Value) -> Walk {
        walk(wire, body.to_string().as_bytes()).unwrap()
    }
    fn classes_of(w: &Walk, needle: &str) -> Vec<(Class, Role)> {
        w.leaves
            .iter()
            .filter(|l| l.text.contains(needle))
            .map(|l| (l.class, l.role))
            .collect()
    }

    /// Spec §5.2 / review C1: the named fields are all leaves.
    #[test]
    fn every_named_field_is_a_leaf() {
        let chat = leaves(
            Wire::Chat,
            serde_json::json!({
                "model": "gpt-x", "user": C, "safety_identifier": C,
                "prediction": {"type": "content", "content": C},
                "web_search_options": {"user_location": {"type": "approximate", "approximate": {"city": C}}},
                "messages": [
                    {"role": "system", "content": C},
                    {"role": "user", "name": C, "content": [{"type": "text", "text": C}]},
                    {"role": "assistant", "function_call": {"name": "lookup", "arguments": format!("{{\"q\":\"{C}\"}}")}},
                    {"role": "function", "name": "lookup", "content": C},
                    {"role": "assistant", "tool_calls": [{"id": "call_Y7sK2pQ9vXm4Lw8RtZ3nB6cD", "type": "function", "function": {"name": "lookup", "arguments": format!("{{\"{C}\":1}}")}}]},
                    {"role": "tool", "tool_call_id": "call_Y7sK2pQ9vXm4Lw8RtZ3nB6cD", "content": C}
                ]
            }),
        );
        let got = classes_of(&chat, C);
        assert!(got.contains(&(Class::Text, Role::System)));
        assert!(got.contains(&(Class::Text, Role::User)));
        assert!(
            got.iter().filter(|c| c.0 == Class::ToolInput).count() >= 2,
            "{got:?}"
        );
        assert!(
            got.iter().filter(|c| c.0 == Class::ToolResult).count() >= 2,
            "{got:?}"
        );
        assert!(got.len() >= 10, "{got:?}");
        assert!(chat.leaves.iter().all(|l| l.text != "gpt-x"
            && l.text != "lookup"
            && l.text != "call_Y7sK2pQ9vXm4Lw8RtZ3nB6cD"));

        let resp = leaves(
            Wire::Responses,
            serde_json::json!({
                "model": "gpt-x", "instructions": C, "metadata": {"k": C},
                "prompt": {"id": "pmpt_68af2f9a2b5c8190a1b2c3d4", "variables": {"name": C}},
                "input": [
                    {"type": "message", "role": "user", "content": C},
                    {"type": "reasoning", "id": "rs_68af2f9b1c3c8190b0e4e2d5f6a7b8c9", "summary": [{"type": "summary_text", "text": C}], "encrypted_content": "enc"},
                    {"type": "custom_tool_call", "call_id": "k", "name": "apply_patch", "input": C},
                    {"type": "function_call_output", "call_id": "k", "output": C}
                ],
                "tools": [{"type": "function", "name": "f", "description": C, "user_location": {"city": C}}]
            }),
        );
        let got = classes_of(&resp, C);
        assert!(got.contains(&(Class::Text, Role::System)));
        assert!(got.contains(&(Class::Scan, Role::Assistant)));
        assert!(got.contains(&(Class::ToolInput, Role::Assistant)));
        assert!(got.contains(&(Class::ToolResult, Role::Tool)));
        assert!(got.iter().filter(|c| c.0 == Class::Definition).count() >= 2);
        assert!(
            got.iter().filter(|c| c.0 == Class::Text).count() >= 4,
            "{got:?}"
        );
        assert!(resp.leaves.iter().all(|l| l.text != "enc"));
        assert!(
            resp.leaves
                .iter()
                .all(|l| l.text != "apply_patch" && l.text != "rs_68af2f9b1c3c8190b0e4e2d5f6a7b8c9")
        );

        let msgs = leaves(
            Wire::Messages,
            serde_json::json!({
                "model": "claude-x", "system": [{"type": "text", "text": C, "cache_control": {"type": "ephemeral"}}],
                "metadata": {"user_id": "u1"},
                "unknown_param": {"deep": [C]},
                "messages": [
                    {"role": "user", "content": [
                        {"type": "future_block", "payload": {"note": C}},
                        {"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": C}},
                        {"type": "search_result", "source": C, "title": C, "content": [{"type": "text", "text": C}]}
                    ]},
                    {"role": "assistant", "content": [
                        {"type": "thinking", "thinking": C, "signature": "sig"},
                        {"type": "tool_use", "id": "toolu_01D7FLrfh4GYq7yT1ULmeyqw", "name": "lookup", "input": {C: {"nested": C}}},
                        {"type": "text", "text": "x", "citations": [{"type": "char_location", "cited_text": C}]}
                    ]},
                    {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_01D7FLrfh4GYq7yT1ULmeyqw", "content": [{"type": "text", "text": C}]}]}
                ]
            }),
        );
        let got = classes_of(&msgs, C);
        assert!(got.contains(&(Class::Text, Role::System)));
        assert!(
            got.iter()
                .filter(|c| *c == &(Class::Text, Role::User))
                .count()
                >= 4,
            "{got:?}"
        );
        assert!(
            got.iter().filter(|c| c.0 == Class::ToolInput).count() == 2,
            "key and value: {got:?}"
        );
        assert!(
            got.iter().filter(|c| c.0 == Class::Scan).count() >= 3,
            "thinking, cited_text, search source: {got:?}"
        );
        assert!(got.contains(&(Class::ToolResult, Role::User)));
        assert!(
            got.contains(&(Class::Text, Role::Other)),
            "unknown top-level parameter: {got:?}"
        );
        assert!(
            msgs.leaves
                .iter()
                .all(|l| l.text != "sig" && l.text != "ephemeral" && l.text != "lookup")
        );
        assert!(
            msgs.leaves.iter().any(|l| l.text == "u1"),
            "metadata is caller-keyed: its user_id is data (review C3)"
        );
        // The key that names a tool input is structure; the keys inside it are data.
        assert!(msgs.leaves.iter().all(|l| l.text != "input"));
        assert_eq!(msgs.first_system.as_deref(), Some(C));
    }

    #[test]
    fn binary_parts_are_flagged_and_grouped() {
        let w = leaves(
            Wire::Messages,
            serde_json::json!({"messages": [
                {"role": "user", "content": [{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBOR"}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t", "content": [{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBOR"}}]}]}
            ]}),
        );
        assert!(w.user_binary);
        assert_eq!(w.groups.len(), 1);
        assert!(w.groups[0].binary);
        assert!(w.leaves.iter().all(|l| l.text != "iVBOR"));
        let chat = leaves(
            Wire::Chat,
            serde_json::json!({"messages": [{"role": "user", "content": [{"type": "file", "file": {"file_data": "JVBER", "filename": C}}]}]}),
        );
        assert!(chat.user_binary);
        assert!(chat.leaves.iter().all(|l| l.text != "JVBER"));
        // Review I3: any data URI is binary; computer screenshots too; titles and filenames stay data.
        let any = leaves(
            Wire::Messages,
            serde_json::json!({"messages": [{"role": "user", "content": [{"type": "future_block", "blob": "data:image/png;base64,iVBOR"}]}]}),
        );
        assert!(any.user_binary && any.leaves.iter().all(|l| !l.text.starts_with("data:")));
        let shot = leaves(
            Wire::Responses,
            serde_json::json!({"input": [{"type": "computer_call_output", "call_id": "c", "output": {"type": "computer_screenshot", "image_url": "data:image/png;base64,iVBOR"}}]}),
        );
        assert!(
            shot.groups.iter().any(|g| g.binary),
            "a screenshot in a tool result is a binary group"
        );
        let doc = leaves(
            Wire::Messages,
            serde_json::json!({"messages": [{"role": "user", "content": [{"type": "document", "title": C, "context": C, "source": {"type": "base64", "media_type": "application/pdf", "data": "JVBER"}}]}]}),
        );
        assert!(doc.user_binary);
        assert_eq!(
            classes_of(&doc, C).len(),
            2,
            "title and context are still sanitized"
        );
        assert!(doc.leaves.iter().all(|l| l.text != "JVBER"));
        // The `source` may come before the `type` that makes the document binary.
        let late = leaves(
            Wire::Messages,
            serde_json::json!({"messages": [{"role": "user", "content": [{"source": {"data": "JVBER", "type": "base64"}, "type": "document"}]}]}),
        );
        assert!(late.user_binary);
        assert!(late.leaves.iter().all(|l| l.text != "JVBER"));
    }

    /// Review C3: caller-keyed maps: every key and string is data.
    #[test]
    fn caller_keyed_maps_are_data_at_every_key() {
        for (wire, body, n) in [
            (
                Wire::Messages,
                serde_json::json!({"metadata": {"user_id": C, "customer_id": C}, "messages": []}),
                2,
            ),
            (
                Wire::Responses,
                serde_json::json!({"metadata": {"id": C, "type": C, "status": C}, "prompt": {"id": "pmpt_68af2f9a2b5c8190a1b2c3d4", "variables": {"order_id": C}}, "input": []}),
                4,
            ),
            (
                Wire::Chat,
                serde_json::json!({"metadata": {"session_id": C}, "messages": []}),
                1,
            ),
        ] {
            let w = leaves(wire, body);
            assert_eq!(
                w.leaves.iter().filter(|l| l.text == C).count(),
                n,
                "{wire:?}"
            );
            assert!(
                w.leaves
                    .iter()
                    .all(|l| l.text != "pmpt_68af2f9a2b5c8190a1b2c3d4"),
                "prompt.id stays structural"
            );
        }
        let w = leaves(
            Wire::Messages,
            serde_json::json!({"metadata": {"customer_id": "x"}, "messages": []}),
        );
        assert!(
            w.leaves.iter().any(|l| l.text == "customer_id"),
            "keys are data too"
        );
        assert!(
            w.leaves.iter().all(|l| l.text != "metadata"),
            "the map's own key is structure"
        );
    }

    /// Ruling I5: `mcp_servers` are definitions; their credential is opaque.
    #[test]
    fn mcp_servers_are_definitions_and_their_token_is_opaque() {
        let w = leaves(
            Wire::Messages,
            serde_json::json!({"mcp_servers": [{"type": "url", "url": "https://mcp.example.invalid/sse", "name": C,
            "authorization_token": "secret-token", "tool_configuration": {"allowed_tools": [C]}}], "messages": []}),
        );
        assert_eq!(
            classes_of(&w, C)
                .iter()
                .filter(|c| c.0 == Class::Definition)
                .count(),
            2
        );
        assert!(
            w.leaves
                .iter()
                .all(|l| l.text != "secret-token" && l.text != "authorization_token")
        );
    }

    /// Codex responses-lite (0.162): the tools of an `additional_tools`
    /// input item, namespaced ones included, are definitions like the
    /// top-level `tools`; the item's `type` is structure.
    #[test]
    fn additional_tools_items_hold_definitions() {
        let w = leaves(
            Wire::Responses,
            serde_json::json!({"input": [
                {"type": "additional_tools", "role": "developer", "tools": [
                    {"type": "namespace", "name": "ns", "description": C, "tools": [
                        {"type": "function", "name": "f", "description": C,
                         "parameters": {"type": "object", "properties": {"q": {"type": "string", "description": C}}}}
                    ]}
                ]},
                {"type": "message", "role": "user", "content": "U1"}
            ]}),
        );
        let got = classes_of(&w, C);
        assert_eq!(got.len(), 3, "{got:?}");
        assert!(got.iter().all(|c| c.0 == Class::Definition), "{got:?}");
        assert!(
            w.leaves.iter().all(|l| l.text != "additional_tools"),
            "the item type is structure"
        );
    }

    #[test]
    fn stream_flag_is_read() {
        assert!(
            leaves(
                Wire::Messages,
                serde_json::json!({"stream": true, "messages": []})
            )
            .stream
        );
        assert!(!leaves(Wire::Messages, serde_json::json!({"messages": []})).stream);
    }

    /// Function arguments are JSON text: each key and string is its own leaf,
    /// addressed by its range in the decoded text; text that is not JSON is one leaf.
    #[test]
    fn function_arguments_are_split_into_inner_leaves() {
        let args = format!("{{\"q\":\"{C}\",\"n\":[\"b\"]}}");
        let w = leaves(
            Wire::Responses,
            serde_json::json!({"input": [
                {"type": "function_call", "call_id": "k", "name": "f", "arguments": args},
                {"type": "function_call", "call_id": "k", "name": "f", "arguments": format!("not json {C}")}
            ]}),
        );
        let inner: Vec<&Leaf> = w
            .leaves
            .iter()
            .filter(|l| matches!(l.target, Target::Inner { .. }))
            .collect();
        assert_eq!(
            inner.len(),
            4,
            "keys q and n, strings Zyxwuria and b: {inner:?}"
        );
        for l in inner {
            let Target::Inner { node, range } = &l.target else {
                unreachable!()
            };
            let decoded = w.nodes[*node].text.as_deref().unwrap();
            assert_eq!(&decoded[range.clone()], format!("\"{}\"", l.text));
            assert_eq!((l.class, l.role), (Class::ToolInput, Role::Assistant));
        }
        let whole: Vec<&Leaf> = w
            .leaves
            .iter()
            .filter(|l| l.text.starts_with("not json"))
            .collect();
        assert_eq!(whole.len(), 1);
        assert!(matches!(whole[0].target, Target::Node(_)));
    }

    /// A request body is an object: a bare string (which would be forwarded
    /// unsanitized) and every other non-object root are refused.
    #[test]
    fn non_object_roots_are_refused() {
        for body in [
            "\"Max Mustermann AT611904300234573201\"",
            "[\"Max Mustermann\"]",
            "42",
            "null",
        ] {
            assert_eq!(
                walk(Wire::Messages, body.as_bytes()).unwrap_err(),
                JsonError::Invalid
            );
        }
    }

    /// Arguments text that is itself a JSON string literal still yields its inner leaf.
    #[test]
    fn a_string_root_inside_arguments_is_an_inner_leaf() {
        let w = leaves(
            Wire::Responses,
            serde_json::json!({"input": [{"type": "function_call", "call_id": "k", "name": "f",
                "arguments": format!("\"{C}\"")}]}),
        );
        let inner: Vec<&Leaf> = w.leaves.iter().filter(|l| l.text == C).collect();
        assert_eq!(inner.len(), 1);
        assert!(matches!(inner[0].target, Target::Inner { .. }));
    }

    /// Spec §5.2: `redacted_thinking.data` is an opaque signed blob: never a
    /// leaf, so the pipeline never changes it.
    #[test]
    fn redacted_thinking_data_is_opaque() {
        let blob = "EpQBCkYIBxgCKkB-opaque-blob";
        let w = leaves(
            Wire::Messages,
            serde_json::json!({"messages": [{"role": "assistant", "content": [
                {"type": "redacted_thinking", "data": blob},
                {"type": "text", "text": C}
            ]}]}),
        );
        assert!(w.leaves.iter().all(|l| l.text != blob && l.text != "data"));
        assert_eq!(classes_of(&w, C), vec![(Class::Text, Role::Assistant)]);
        // The blob is still in the node list untouched, available to be forwarded as received.
        assert!(w.nodes.iter().any(|m| m.text.as_deref() == Some(blob)));
    }

    /// `include`, `modalities`, `tool_choice`, `stream_options` are structural
    /// only as top-level parameters; nested, they are data. `cache_control` is
    /// structural at any depth, for its known `type` and `ttl` values only.
    #[test]
    fn structural_subtrees_are_top_level_except_cache_control() {
        let w = leaves(
            Wire::Responses,
            serde_json::json!({"include": ["reasoning.encrypted_content"], "tool_choice": {"type": "function", "name": "f"},
                "input": [{"type": "message", "role": "user", "content": [
                    {"type": "future_block", "include": [C], "cache_control": {"type": "ephemeral", "note": "n1"}}]}]}),
        );
        assert!(
            w.leaves.iter().any(|l| l.text == C),
            "nested include is data"
        );
        assert!(
            w.leaves
                .iter()
                .all(|l| l.text != "reasoning.encrypted_content"
                    && l.text != "f"
                    && l.text != "ephemeral")
        );
        assert!(
            w.leaves.iter().any(|l| l.text == "n1"),
            "cache_control holds only type and ttl; any other string is data"
        );
    }

    /// The first user text is the message's text, not its `name`.
    #[test]
    fn first_user_skips_name() {
        let w = leaves(
            Wire::Chat,
            serde_json::json!({"messages": [{"role": "user", "name": "alice", "content": C}]}),
        );
        assert_eq!(w.first_user.as_deref(), Some(C));
        assert!(
            w.leaves.iter().any(|l| l.text == "alice"),
            "name is still sanitized"
        );
    }

    /// Privacy: no `Debug` of a classified body shows request text.
    #[test]
    fn debug_shows_no_text() {
        let w = leaves(
            Wire::Messages,
            serde_json::json!({"system": C, "messages": [{"role": "user", "content": C}]}),
        );
        assert!(w.first_system.is_some() && w.first_user.is_some());
        let shown = format!("{w:?} {:?} {:?} {:?}", w.leaves, w.groups, w.nodes);
        assert!(!shown.contains(C), "{shown}");
        assert!(format!("{:?}", Target::Node(1)).len() < 20);
    }

    /// 200k nodes at depth ~100 must walk in linear time (no per-node path rebuilds).
    #[test]
    fn deep_large_bodies_walk_in_linear_time() {
        let depth = 100;
        let mut body = String::from("{\"unknown\":");
        for _ in 0..depth {
            body.push_str("{\"a\":");
        }
        body.push('[');
        for i in 0..200_000 {
            if i > 0 {
                body.push(',');
            }
            body.push_str("\"s\"");
        }
        body.push(']');
        for _ in 0..depth {
            body.push('}');
        }
        body.push('}');
        let start = std::time::Instant::now();
        let w = walk(Wire::Messages, body.as_bytes()).unwrap();
        let took = start.elapsed();
        assert!(w.leaves.len() >= 200_000);
        assert!(took.as_secs_f64() < 3.0, "{took:?}");
    }

    /// Decision 17 (fix round, recall): `cited_text`, `summary_text.text`,
    /// `thinking`, and `search_result.source` are scanned only at the
    /// positions spec §5.2 names; under an unknown parameter they are data.
    #[test]
    fn scanned_keys_are_scanned_only_at_their_real_positions() {
        let msgs = leaves(
            Wire::Messages,
            serde_json::json!({
                "unknown_param": {
                    "cited_text": C,
                    "citations": [{"type": "char_location", "cited_text": C}],
                    "content": [{"type": "thinking", "thinking": C}, {"type": "search_result", "source": C}]
                },
                "messages": [
                    {"role": "user", "content": [
                        {"type": "search_result", "source": C, "title": "t", "content": [{"type": "text", "text": "x"}]},
                        {"type": "tool_result", "tool_use_id": "t", "content": [{"type": "search_result", "source": C}]},
                        {"type": "future", "citations": [{"cited_text": C}]}
                    ]},
                    {"role": "assistant", "content": [
                        {"type": "thinking", "thinking": C, "signature": "s"},
                        {"type": "text", "text": "x", "citations": [{"type": "char_location", "cited_text": C}]}
                    ]}
                ]
            }),
        );
        let got = classes_of(&msgs, C);
        assert_eq!(
            got.iter().filter(|c| c.0 == Class::Scan).count(),
            4,
            "user search source, tool-result search source, thinking, citation: {got:?}"
        );
        assert_eq!(
            got.iter().filter(|c| c.0 == Class::Text).count(),
            5,
            "the unknown parameter's four and the untyped citation: {got:?}"
        );
        let resp = leaves(
            Wire::Responses,
            serde_json::json!({
                "unknown_param": {"type": "summary_text", "text": C, "summary": [{"type": "summary_text", "text": C}]},
                "input": [
                    {"type": "reasoning", "id": "r", "summary": [{"type": "summary_text", "text": C}]},
                    {"type": "message", "role": "user", "content": [{"type": "summary_text", "text": C}]}
                ]
            }),
        );
        let got = classes_of(&resp, C);
        assert_eq!(
            got.iter().filter(|c| c.0 == Class::Scan).count(),
            1,
            "{got:?}"
        );
        assert_eq!(
            got.iter().filter(|c| c.0 == Class::Text).count(),
            3,
            "{got:?}"
        );
    }

    /// Decision 17 (Task 7 follow-up): the opaque signed fields are opaque
    /// only at their real positions; under an unknown parameter they are data.
    #[test]
    fn opaque_signed_fields_are_opaque_only_at_their_real_positions() {
        let fields = serde_json::json!([
            {"type": "thinking", "thinking": "t", "signature": C},
            {"type": "redacted_thinking", "data": C},
            {"type": "web_search_tool_result", "tool_use_id": "w", "content": [
                {"type": "web_search_result", "url": "https://example.invalid", "title": "t", "encrypted_content": C}
            ]},
            {"type": "text", "text": "x", "citations": [
                {"type": "web_search_result_location", "url": "https://example.invalid", "title": "t", "encrypted_index": C, "cited_text": "c"}
            ]}
        ]);
        let msgs = leaves(
            Wire::Messages,
            serde_json::json!({
                "unknown_param": {"content": fields, "signature": C, "encrypted_index": C, "encrypted_content": C},
                "messages": [{"role": "assistant", "content": fields}]
            }),
        );
        let got = classes_of(&msgs, C);
        assert_eq!(got.len(), 7, "only the unknown parameter's: {got:?}");
        assert!(got.iter().all(|c| c.0 == Class::Text), "{got:?}");
        let resp = leaves(
            Wire::Responses,
            serde_json::json!({
                "unknown_param": {"type": "reasoning", "encrypted_content": C},
                "input": [
                    {"type": "reasoning", "id": "r", "summary": [], "encrypted_content": C},
                    {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "x", "encrypted_content": C}]}
                ]
            }),
        );
        let got = classes_of(&resp, C);
        assert_eq!(
            got.len(),
            2,
            "the unknown parameter's and the message part's: {got:?}"
        );
        assert!(got.iter().all(|c| c.0 == Class::Text), "{got:?}");
    }

    /// Ruling 2026-10-05 (recall first): a structural key's value is trusted
    /// only in its shape; free text under a structural key is a Text leaf.
    #[test]
    fn off_shape_structural_values_are_text_leaves() {
        for (wire, body, value) in [
            (
                Wire::Messages,
                serde_json::json!({"unknown_param": {"customer_id": "K-123456"}}),
                "K-123456",
            ),
            (
                Wire::Messages,
                serde_json::json!({"unknown_param": {"detail": "Sarah Leitner called"}}),
                "Sarah Leitner called",
            ),
            (
                Wire::Messages,
                serde_json::json!({"messages": [{"role": "user", "content": [{"type": "text", "text": "x", "status": "Sarah Leitner called"}]}]}),
                "Sarah Leitner called",
            ),
            (
                Wire::Messages,
                serde_json::json!({"messages": [{"role": "user", "content": [{"type": "Sarah Leitner", "text": "x"}]}]}),
                "Sarah Leitner",
            ),
            (
                Wire::Chat,
                serde_json::json!({"messages": [{"role": "Sarah Leitner", "content": "x"}]}),
                "Sarah Leitner",
            ),
            (
                Wire::Responses,
                serde_json::json!({"input": [], "unknown_param": {"model": "Sarah Leitner"}}),
                "Sarah Leitner",
            ),
            (
                Wire::Responses,
                serde_json::json!({"input": [{"type": "function_call_output", "call_id": "Sarah Leitner", "output": "x"}]}),
                "Sarah Leitner",
            ),
            (
                Wire::Messages,
                serde_json::json!({"messages": [{"role": "assistant", "content": [{"type": "tool_use", "id": "Zyxwuria Quolnath", "name": "n", "input": {}}]}]}),
                "Zyxwuria Quolnath",
            ),
            // A known prefix with a name after it is not an API id.
            (
                Wire::Chat,
                serde_json::json!({"messages": [{"role": "tool", "tool_call_id": "call_Sarah", "content": "x"}]}),
                "call_Sarah",
            ),
            (
                Wire::Messages,
                serde_json::json!({"messages": [{"role": "assistant", "id": "msg_Leitner", "content": "x"}]}),
                "msg_Leitner",
            ),
            (
                Wire::Messages,
                serde_json::json!({"messages": [{"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_Max", "name": "n", "input": {}}]}]}),
                "toolu_Max",
            ),
            // `@` in a model only as a version suffix.
            (
                Wire::Messages,
                serde_json::json!({"unknown_param": {"model": "a@b.at"}}),
                "a@b.at",
            ),
            (
                Wire::Messages,
                serde_json::json!({"model": "max@mustermann.at", "messages": []}),
                "max@mustermann.at",
            ),
            // `cache_control` holds only `type: ephemeral` and `ttl: 5m|1h`.
            (
                Wire::Messages,
                serde_json::json!({"messages": [{"role": "user", "content": [{"type": "text", "text": "x", "cache_control": {"type": "Sarah Leitner"}}]}]}),
                "Sarah Leitner",
            ),
            (
                Wire::Messages,
                serde_json::json!({"system": [{"type": "text", "text": "x", "cache_control": {"type": "ephemeral", "ttl": "5m", "note": "Max"}}]}),
                "Max",
            ),
            // Below a non-string value at an opaque position, strings are data.
            (
                Wire::Messages,
                serde_json::json!({"messages": [{"role": "assistant", "content": [{"type": "thinking", "thinking": "t", "signature": {"x": "Sarah Leitner"}}]}]}),
                "Sarah Leitner",
            ),
            (
                Wire::Messages,
                serde_json::json!({"messages": [{"role": "assistant", "content": [{"type": "redacted_thinking", "data": ["Sarah Leitner"]}]}]}),
                "Sarah Leitner",
            ),
            (
                Wire::Messages,
                serde_json::json!({"messages": [{"role": "user", "content": [{"type": "image", "source": {"type": "url", "url": "https://x.invalid/a.png", "media_type": "a@b.at"}}]}]}),
                "a@b.at",
            ),
            (
                Wire::Chat,
                serde_json::json!({"messages": [], "unknown_param": {"object": "chat.completion for Sarah", "verbosity": "Sarah"}}),
                "chat.completion for Sarah",
            ),
            (
                Wire::Responses,
                serde_json::json!({"input": [], "model": "gpt 5 for Sarah Leitner"}),
                "gpt 5 for Sarah Leitner",
            ),
            (
                Wire::Responses,
                serde_json::json!({"input": [], "previous_response_id": "Sarah Leitner"}),
                "Sarah Leitner",
            ),
            (
                Wire::Messages,
                serde_json::json!({"messages": [], "tool_choice": {"type": "tool", "name": "a@b.at"}}),
                "a@b.at",
            ),
        ] {
            let w = leaves(wire, body.clone());
            assert!(
                w.leaves
                    .iter()
                    .any(|l| l.text == value && matches!(l.class, Class::Text | Class::ToolResult)),
                "{wire:?} {body}"
            );
        }
    }

    /// Ruling 2026-10-05: real API ids, enums, models, and media types stay
    /// structural (no leaf), so agent loops see no false refusals.
    #[test]
    fn real_api_ids_and_enums_are_not_leaves() {
        let structural = [
            "claude-sonnet-4-5",
            "gpt-5.1-codex",
            "msg_01XFDUDYJgAACzvnptvVoYEL",
            "toolu_01A09q90qw90lq917835lq9",
            "srvtoolu_014hJH82Qum7Td6UV8gDXThB",
            "call_DdmO9pD3xa9XTPNJ32zg2hcA",
            "fc_68af2f9e7d4c8190a5a7c5e1b3f0e2d1",
            "rs_68af2f9b1c3c8190b0e4e2d5f6a7b8c9",
            "resp_68af2f9a2b5c8190a1b2c3d4e5f6a7b8",
            "chatcmpl-B9MHDbslfkBeAs8l4bebGdFOJ6PeG",
            "image/png",
            "in_progress",
            "completed",
            "developer",
            "high",
            "end_turn",
            "tool_calls",
            "ephemeral",
            "claude-sonnet-4-5@20250929",
            "1h",
            "input_tokens",
            "tool_uses",
            "clear_tool_uses_20250919",
            "web_search_20250305",
            "reasoning.encrypted_content",
        ];
        let msgs = serde_json::json!({
            "model": "claude-sonnet-4-5", "thinking": {"type": "enabled", "budget_tokens": 1024},
            "tool_choice": {"type": "auto"},
            "messages": [
                {"role": "user", "content": [
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBOR"}},
                    {"type": "text", "text": "look", "cache_control": {"type": "ephemeral"}}
                ]},
                {"role": "assistant", "id": "msg_01XFDUDYJgAACzvnptvVoYEL", "stop_reason": "end_turn", "content": [
                    {"type": "server_tool_use", "id": "srvtoolu_014hJH82Qum7Td6UV8gDXThB", "name": "web_search", "input": {"query": "q"}},
                    {"type": "tool_use", "id": "toolu_01A09q90qw90lq917835lq9", "name": "Read", "input": {"file_path": "/tmp/a"}}
                ]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_01A09q90qw90lq917835lq9", "content": "ok"}]}
            ],
            "context_management": {"edits": [{"type": "web_search_20250305"}, {"type": "clear_tool_uses_20250919", "trigger": {"type": "input_tokens", "value": 30000}, "keep": {"type": "tool_uses", "value": 3}}]},
            "unknown_param": {"model": "claude-sonnet-4-5@20250929", "cache_control": {"type": "ephemeral", "ttl": "1h"}}
        });
        let resp = serde_json::json!({
            "model": "gpt-5.1-codex", "previous_response_id": "resp_68af2f9a2b5c8190a1b2c3d4e5f6a7b8",
            "reasoning": {"effort": "high", "summary": "auto"}, "include": ["reasoning.encrypted_content"],
            "text": {"verbosity": "high"}, "service_tier": "auto",
            "input": [
                {"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "be brief"}]},
                {"type": "message", "role": "user", "content": [{"type": "input_image", "image_url": "https://x.invalid/a.png", "detail": "high"}]},
                {"type": "reasoning", "id": "rs_68af2f9b1c3c8190b0e4e2d5f6a7b8c9", "summary": []},
                {"type": "function_call", "id": "fc_68af2f9e7d4c8190a5a7c5e1b3f0e2d1", "call_id": "call_DdmO9pD3xa9XTPNJ32zg2hcA", "name": "shell", "arguments": "{}", "status": "completed"},
                {"type": "function_call_output", "call_id": "call_DdmO9pD3xa9XTPNJ32zg2hcA", "output": "ok", "status": "in_progress"}
            ]
        });
        let chat = serde_json::json!({
            "model": "gpt-5.1-codex", "id": "chatcmpl-B9MHDbslfkBeAs8l4bebGdFOJ6PeG",
            "messages": [
                {"role": "developer", "content": "be brief"},
                {"role": "user", "content": [{"type": "image_url", "image_url": {"url": "https://x.invalid/a.png", "detail": "high"}}]},
                {"role": "assistant", "finish_reason": "tool_calls", "tool_calls": [{"id": "call_DdmO9pD3xa9XTPNJ32zg2hcA", "type": "function", "function": {"name": "f", "arguments": "{}"}}]},
                {"role": "tool", "tool_call_id": "call_DdmO9pD3xa9XTPNJ32zg2hcA", "content": "ok"}
            ]
        });
        for (wire, body) in [
            (Wire::Messages, msgs),
            (Wire::Responses, resp),
            (Wire::Chat, chat),
        ] {
            let w = leaves(wire, body);
            for v in structural {
                assert!(
                    w.leaves.iter().all(|l| l.text != v),
                    "{wire:?}: {v} became a leaf"
                );
            }
            for v in [
                "user",
                "assistant",
                "tool",
                "message",
                "function",
                "text",
                "auto",
                "base64",
            ] {
                assert!(
                    w.leaves.iter().all(|l| l.text != v),
                    "{wire:?}: {v} became a leaf"
                );
            }
        }
    }

    /// Ruling L122: only the leading system prompt is `leading`. Each
    /// marker text is checked on every leaf that carries it.
    #[test]
    fn only_the_leading_system_prompt_is_leading() {
        let lead = |w: &Walk, needle: &str| -> Vec<bool> {
            let got: Vec<bool> = w
                .leaves
                .iter()
                .filter(|l| l.text == needle)
                .map(|l| l.leading)
                .collect();
            assert!(!got.is_empty(), "{needle}: no leaf");
            got
        };
        let yes = |w: &Walk, needle: &str| assert!(lead(w, needle).iter().all(|b| *b), "{needle}");
        let no = |w: &Walk, needle: &str| assert!(lead(w, needle).iter().all(|b| !*b), "{needle}");

        // Messages: the top-level `system` (string and blocks) only.
        let m = leaves(
            Wire::Messages,
            serde_json::json!({"system": [{"type": "text", "text": "S1"}], "messages": [
                {"role": "system", "content": "S2"},
                {"role": "user", "content": "U1"},
                {"role": "system", "content": [{"type": "text", "text": "S3"}]}
            ]}),
        );
        yes(&m, "S1");
        no(&m, "S2");
        no(&m, "U1");
        no(&m, "S3");
        let m = leaves(
            Wire::Messages,
            serde_json::json!({"system": "S1", "messages": [{"role": "user", "content": "U1"}]}),
        );
        yes(&m, "S1");
        no(&m, "U1");

        // Responses: `instructions`, then the leading system/developer items.
        let r = leaves(
            Wire::Responses,
            serde_json::json!({"instructions": "I1", "input": [
                {"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "D1"}]},
                {"role": "system", "content": "S1"},
                {"type": "message", "role": "user", "content": "U1"},
                {"type": "message", "role": "developer", "content": "D2"},
                {"role": "system", "content": "S2"}
            ]}),
        );
        yes(&r, "I1");
        yes(&r, "D1");
        yes(&r, "S1");
        no(&r, "U1");
        no(&r, "D2");
        no(&r, "S2");
        // A role-less item ends the run.
        let r = leaves(
            Wire::Responses,
            serde_json::json!({"input": [
                {"role": "developer", "content": "D1"},
                {"type": "function_call", "call_id": "c", "name": "f", "arguments": "{\"q\":\"A1\"}"},
                {"role": "system", "content": "S2"}
            ]}),
        );
        yes(&r, "D1");
        no(&r, "A1");
        no(&r, "S2");
        for first in [
            serde_json::json!({"content": "X3"}),
            serde_json::json!({"type": "reasoning", "id": "rs_1", "summary": []}),
            serde_json::json!({"type": "item_reference", "id": "msg_1"}),
            serde_json::json!({"role": "narrator", "content": "N1"}),
            serde_json::json!({"type": "function_call", "role": "developer", "call_id": "c", "name": "f", "arguments": "{}"}),
            serde_json::json!("X1"),
            serde_json::json!(["X2"]),
        ] {
            let r = leaves(
                Wire::Responses,
                serde_json::json!({"input": [first, {"role": "developer", "content": "D2"}]}),
            );
            no(&r, "D2");
        }
        // Codex responses-lite (0.162): the tool definitions arrive as a
        // leading developer `additional_tools` item; it continues the run.
        let lite = |first: serde_json::Value| {
            leaves(
                Wire::Responses,
                serde_json::json!({"input": [
                    first,
                    {"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "D1"}]},
                    {"type": "message", "role": "user", "content": "U1"},
                    {"type": "additional_tools", "role": "developer", "tools": []},
                    {"type": "message", "role": "developer", "content": "D2"}
                ]}),
            )
        };
        let r = lite(
            serde_json::json!({"type": "additional_tools", "id": "at_1", "role": "developer", "tools": []}),
        );
        yes(&r, "D1");
        no(&r, "U1");
        no(&r, "D2");
        // Only as a developer/system item: another role still ends the run.
        for first in [
            serde_json::json!({"type": "additional_tools", "role": "user", "tools": []}),
            serde_json::json!({"type": "additional_tools", "tools": []}),
        ] {
            no(&lite(first), "D1");
        }
        // A plain-string input is a user message: no leading leaf.
        let r = leaves(
            Wire::Responses,
            serde_json::json!({"instructions": "I1", "input": "U1"}),
        );
        yes(&r, "I1");
        no(&r, "U1");
        let r = leaves(Wire::Responses, serde_json::json!({"input": "U1"}));
        assert!(r.leaves.iter().all(|l| !l.leading));

        // Chat: the leading system/developer messages.
        let c = leaves(
            Wire::Chat,
            serde_json::json!({"messages": [
                {"role": "system", "name": "N0", "content": "S1"},
                {"role": "developer", "content": [{"type": "text", "text": "D1"}]},
                {"role": "user", "content": "U1"},
                {"role": "system", "content": "S2"},
                {"role": "developer", "content": "D2"}
            ]}),
        );
        // A message's `name` is not harness prose (L2-58): it stays Free.
        no(&c, "N0");
        yes(&c, "S1");
        yes(&c, "D1");
        no(&c, "U1");
        no(&c, "S2");
        no(&c, "D2");
        // An off-shape value (here a free-text `id`) inside a leading item
        // is data, not harness prose (L2-58): not leading.
        let c = leaves(
            Wire::Chat,
            serde_json::json!({"messages": [
                {"role": "system", "id": "O1 free text", "content": "S1"},
                {"role": "user", "content": "U1"}
            ]}),
        );
        no(&c, "O1 free text");
        yes(&c, "S1");
        let c = leaves(
            Wire::Chat,
            serde_json::json!({"messages": [
                {"role": "assistant", "content": "A1"},
                {"role": "system", "content": "S2"}
            ]}),
        );
        no(&c, "A1");
        no(&c, "S2");
        let c = leaves(
            Wire::Chat,
            serde_json::json!({"messages": [
                {"role": "system", "content": "S1"},
                {"role": "assistant", "content": "A1"},
                {"role": "system", "content": "S2"}
            ]}),
        );
        yes(&c, "S1");
        no(&c, "S2");
        // A system object anywhere else is not leading: under an unknown
        // parameter, or nested inside a leading item.
        let c = leaves(
            Wire::Chat,
            serde_json::json!({"extra": [{"role": "system", "content": "X1"}], "messages": [
                {"role": "system", "content": "S1"},
                {"role": "user", "content": [{"role": "system", "text": "X2"}]}
            ]}),
        );
        yes(&c, "S1");
        no(&c, "X1");
        no(&c, "X2");
        // Only the top-level list: a nested `messages` array that comes first
        // in document order (`json!` sorts `aux` before `messages`) is not it.
        let c = leaves(
            Wire::Chat,
            serde_json::json!({"aux": {"messages": [{"role": "system", "content": "X4"}]}, "messages": [
                {"role": "system", "content": "S1"},
                {"role": "user", "content": "U1"}
            ]}),
        );
        no(&c, "X4");
        yes(&c, "S1");
        // `messages` is not the leading list on Responses, `input` not on Chat.
        let r = leaves(
            Wire::Responses,
            serde_json::json!({"messages": [{"role": "system", "content": "X1"}]}),
        );
        no(&r, "X1");
        let c = leaves(
            Wire::Chat,
            serde_json::json!({"input": [{"role": "system", "content": "X1"}]}),
        );
        no(&c, "X1");
    }
}
