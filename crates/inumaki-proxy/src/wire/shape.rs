//! Structural value shapes (M8 spec §5.2 note of 2026-10-05; integrator
//! ruling, recall first). A structural key is trusted only when its value
//! has the shape the APIs give that key: a closed enum, an API-issued id, a
//! model id, a media type, or a config token. Any other value is data and
//! is sanitized, so `{"unknown_param": {"customer_id": "K-123456",
//! "detail": "Sarah Leitner called"}}` never crosses in clear.
//!
//! A value missing from a set costs one engine pass over a short string,
//! which leaves an enum word unchanged; a value wrongly accepted crosses
//! unsanitized. So the sets are generous with real API names and strict
//! about shape: no whitespace, no `@`, nothing outside the listed alphabet.

/// What a structural value must look like to stay structural.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Shape {
    /// Trusted at its position whatever the value: opaque signed fields at
    /// their real positions, an MCP credential, a tool call's name.
    #[default]
    Any,
    /// One of a closed set of API values.
    OneOf(&'static [&'static str]),
    /// A content, item, block, or event `type`: [`TYPES`], or a versioned
    /// server-tool or edit type (`snake_case_YYYYMMDD`).
    Type,
    /// An API-issued id: a known prefix, then 12 to 128 characters of
    /// `[A-Za-z0-9_-]` with at least one digit; or a UUID.
    Id,
    /// A model id: `[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}`, optionally with a
    /// version suffix `@YYYYMMDD` or `@latest` (no other `@`).
    Model,
    /// A media type: `token/token`, tokens of `[A-Za-z0-9.+-]`.
    Mime,
    /// A configuration token inside a structural subtree (`thinking`,
    /// `reasoning`, `tool_choice`, `include`, `cache_control`, ...):
    /// `[A-Za-z0-9._:/-]{1,128}`, no whitespace.
    Token,
    /// Inside `cache_control` (any depth): `type` must be `ephemeral` and
    /// `ttl` one of `5m`, `1h`; any other string is data.
    CacheControl,
}

impl Shape {
    /// Whether `v` has this shape. The empty string carries nothing and is
    /// accepted.
    pub(crate) fn accepts(self, v: &str) -> bool {
        if v.is_empty() {
            return true;
        }
        match self {
            Shape::Any => true,
            Shape::OneOf(set) => set.contains(&v),
            Shape::Type => TYPES.contains(&v) || versioned(v),
            Shape::Id => id(v),
            Shape::Model => model(v),
            // A string where `cache_control`'s object belongs is not an API value.
            Shape::CacheControl => false,
            Shape::Mime => v.len() <= 128 && mime(v),
            Shape::Token => {
                v.len() <= 128
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
            }
        }
    }
}

/// The shape a structural key's value must have, or `None` when the key is
/// not structural. Applies below the top level; top-level parameters use
/// [`top_shape`].
pub(crate) fn key_shape(name: &str) -> Option<Shape> {
    Some(match name {
        "type" => Shape::Type,
        "role" => Shape::OneOf(ROLES),
        "model" => Shape::Model,
        "id" | "call_id" => Shape::Id,
        n if n.ends_with("_id") => Shape::Id,
        "status" => Shape::OneOf(STATUS),
        "stop_reason" => Shape::OneOf(STOP_REASONS),
        "finish_reason" => Shape::OneOf(FINISH_REASONS),
        "media_type" | "mime_type" => Shape::Mime,
        "detail" => Shape::OneOf(DETAIL),
        "effort" => Shape::OneOf(EFFORT),
        "service_tier" => Shape::OneOf(SERVICE_TIERS),
        "prompt_cache_key" => Shape::Token,
        "verbosity" => Shape::OneOf(VERBOSITY),
        "object" => Shape::OneOf(OBJECTS),
        _ => return None,
    })
}

/// The shape of a structural top-level parameter's string values (the
/// parameter itself, or any string below it).
pub(crate) fn top_shape(name: &str) -> Shape {
    match name {
        "model" => Shape::Model,
        "previous_response_id" => Shape::Id,
        "service_tier" => Shape::OneOf(SERVICE_TIERS),
        "truncation" => Shape::OneOf(&["auto", "disabled"]),
        _ => Shape::Token,
    }
}

/// `snake_case_YYYYMMDD`: versioned server tools and context edits
/// (`web_search_20250305`, `clear_tool_uses_20250919`).
fn versioned(v: &str) -> bool {
    let Some((head, date)) = v.rsplit_once('_') else {
        return false;
    };
    date.len() == 8
        && date.bytes().all(|b| b.is_ascii_digit())
        && !head.is_empty()
        && head.len() <= 64
        && head.as_bytes()[0].is_ascii_lowercase()
        && head
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn model(v: &str) -> bool {
    let (head, suffix) = match v.split_once('@') {
        Some((h, s)) => (h, Some(s)),
        None => (v, None),
    };
    let version = suffix
        .is_none_or(|s| s == "latest" || (s.len() == 8 && s.bytes().all(|b| b.is_ascii_digit())));
    version
        && !head.is_empty()
        && v.len() <= 128
        && head.as_bytes()[0].is_ascii_alphanumeric()
        && head
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
}

fn mime(v: &str) -> bool {
    let tok = |t: &str| {
        !t.is_empty()
            && t.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
    };
    v.split_once('/').is_some_and(|(a, b)| tok(a) && tok(b))
}

fn uuid(v: &str) -> bool {
    v.len() == 36
        && v.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

fn id(v: &str) -> bool {
    if uuid(v) {
        return true;
    }
    // After the prefix, an API-issued id is long and random: at least 12
    // characters of `[A-Za-z0-9_-]` with at least one digit, so a name
    // after a known prefix (`call_Sarah`) is data (integrator ruling).
    ID_PREFIXES.iter().any(|p| {
        v.strip_prefix(p).is_some_and(|rest| {
            (12..=128).contains(&rest.len())
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                && rest.bytes().any(|b| b.is_ascii_digit())
        })
    })
}

/// Prefixes of ids the Anthropic and OpenAI APIs issue.
const ID_PREFIXES: &[&str] = &[
    // Anthropic
    "msg_",
    "toolu_",
    "srvtoolu_",
    "mcptoolu_",
    "msgbatch_",
    "file_",
    "container_",
    "req_",
    // OpenAI Responses, Chat Completions, and the rest of the platform
    "resp_",
    "rs_",
    "fc_",
    "fcr_",
    "ctc_",
    "call_",
    "lsh_",
    "cu_",
    "ws_",
    "fs_",
    "ig_",
    "ci_",
    "mcp_",
    "mcpr_",
    "mcpl_",
    "cmp_",
    "item_",
    "conv_",
    "pmpt_",
    "chatcmpl-",
    "cmpl-",
    "file-",
    "audio_",
    "vs_",
    "cntr_",
    "asst_",
    "thread_",
    "run_",
    "step_",
];

const ROLES: &[&str] = &[
    "system",
    "user",
    "assistant",
    "tool",
    "developer",
    "function",
];

const STATUS: &[&str] = &[
    "in_progress",
    "completed",
    "incomplete",
    "failed",
    "cancelled",
    "queued",
    "searching",
    "generating",
    "interpreting",
    "calling",
    "requires_action",
    "expired",
];

const STOP_REASONS: &[&str] = &[
    "end_turn",
    "max_tokens",
    "stop_sequence",
    "tool_use",
    "pause_turn",
    "refusal",
    "model_context_window_exceeded",
];

const FINISH_REASONS: &[&str] = &[
    "stop",
    "length",
    "tool_calls",
    "content_filter",
    "function_call",
];

const DETAIL: &[&str] = &["auto", "low", "high", "original"];

const EFFORT: &[&str] = &["none", "minimal", "low", "medium", "high", "xhigh", "max"];

const SERVICE_TIERS: &[&str] = &[
    "auto",
    "default",
    "flex",
    "priority",
    "scale",
    "standard_only",
];

const VERBOSITY: &[&str] = &["low", "medium", "high"];

const OBJECTS: &[&str] = &[
    "response",
    "chat.completion",
    "chat.completion.chunk",
    "list",
    "model",
    "message",
    "response.compaction",
    "conversation",
    "conversation.item",
];

/// Block, item, part, source, citation, action, and choice types of the
/// three APIs (generous: a missing name only costs an engine pass).
const TYPES: &[&str] = &[
    // Messages content blocks and sources
    "text",
    "image",
    "document",
    "tool_use",
    "tool_result",
    "thinking",
    "redacted_thinking",
    "server_tool_use",
    "mcp_tool_use",
    "mcp_tool_result",
    "web_search_tool_result",
    "web_search_result",
    "web_search_tool_result_error",
    "web_fetch_tool_result",
    "web_fetch_result",
    "web_fetch_tool_result_error",
    "code_execution_tool_result",
    "code_execution_result",
    "code_execution_output",
    "code_execution_tool_result_error",
    "bash_code_execution_tool_result",
    "bash_code_execution_result",
    "bash_code_execution_output",
    "bash_code_execution_tool_result_error",
    "text_editor_code_execution_tool_result",
    "text_editor_code_execution_view_result",
    "text_editor_code_execution_create_result",
    "text_editor_code_execution_str_replace_result",
    "text_editor_code_execution_tool_result_error",
    "tool_search_tool_result",
    "tool_search_tool_search_result",
    "tool_reference",
    "container_upload",
    "search_result",
    "compaction",
    "base64",
    "url",
    "file",
    "content",
    "char_location",
    "page_location",
    "content_block_location",
    "web_search_result_location",
    "search_result_location",
    "ephemeral",
    "enabled",
    "disabled",
    "adaptive",
    "auto",
    "any",
    "tool",
    "none",
    "required",
    "allowed_tools",
    "message",
    "error",
    // Responses items, parts, annotations, and actions
    "additional_tools",
    "input_text",
    "input_image",
    "input_file",
    "input_audio",
    "output_text",
    "output_audio",
    "refusal",
    "reasoning",
    "summary_text",
    "reasoning_text",
    "function_call",
    "function_call_output",
    "custom_tool_call",
    "custom_tool_call_output",
    "local_shell_call",
    "local_shell_call_output",
    "shell_call",
    "shell_call_output",
    "apply_patch_call",
    "apply_patch_call_output",
    "computer_call",
    "computer_call_output",
    "computer_screenshot",
    "web_search_call",
    "file_search_call",
    "image_generation_call",
    "code_interpreter_call",
    "mcp_call",
    "mcp_list_tools",
    "mcp_approval_request",
    "mcp_approval_response",
    "item_reference",
    "url_citation",
    "file_citation",
    "container_file_citation",
    "file_path",
    "logs",
    "files",
    "exec",
    "search",
    "open_page",
    "find",
    "find_in_page",
    "input_tokens",
    "tool_uses",
    "thinking_turns",
    "click",
    "double_click",
    "drag",
    "keypress",
    "move",
    "screenshot",
    "scroll",
    "type",
    "wait",
    "json_schema",
    "json_object",
    "grammar",
    "lark",
    "regex",
    // Chat Completions
    "function",
    "custom",
    "image_url",
    "approximate",
    "audio",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes_accept_api_values_and_refuse_free_text() {
        for (s, ok, bad) in [
            (Shape::Id, "toolu_01A09q90qw90lq917835lq9", "K-123456"),
            (
                Shape::Id,
                "chatcmpl-B9MHDbslfkBeAs8l4bebGdFOJ6PeG",
                "Sarah Leitner",
            ),
            (Shape::Id, "call_DdmO9pD3xa9XTPNJ32zg2hcA", "call_Sarah"),
            (
                Shape::Id,
                "msg_01XFDUDYJgAACzvnptvVoYEL",
                "msg_LeitnerSarahMaxi",
            ),
            (Shape::Id, "3f2b8c1e-9d4a-4b7e-8f00-1a2b3c4d5e6f", "call_"),
            (Shape::Model, "claude-sonnet-4-5@20250929", "gpt 5"),
            (Shape::Mime, "image/png", "Sarah Leitner/x y"),
            (Shape::Type, "web_search_20250305", "Sarah Leitner called"),
            (Shape::Token, "reasoning.encrypted_content", "a@b.at"),
            (Shape::Model, "claude-opus-4-1@latest", "a@b.at"),
            (Shape::Model, "gemini-2.5-pro", "max@mustermann.at"),
        ] {
            assert!(s.accepts(ok), "{s:?} {ok}");
            assert!(!s.accepts(bad), "{s:?} {bad}");
        }
    }
}
