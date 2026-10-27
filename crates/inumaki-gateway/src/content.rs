//! The content path (M4 spec §5.3 table, §5.4): what is strictly
//! rehydrated (arguments, template parameters), what is sanitized as
//! blocks by the contract (text items, structured content, embedded text
//! resources, links, prompt text), what is rejected (binary, unclassified
//! numbers, unlisted keys, dynamic keys without a map rule, unknown content
//! kinds), and how a blocked, uncertain, or upstream-error result is
//! answered. Every function is pure over [`Blocks`]; callers run them on a
//! blocking thread.
//!
//! No block carries redactions: [`TextBlock`](crate::TextBlock) has no
//! such field, so the engine's trust in validated redactions is never
//! reached from here.

use std::collections::HashMap;
use std::sync::LazyLock;

use inumaki_core::span::EntityKind;
use inumaki_vault::CheckLabel;

use rmcp::model::{
    CallToolResult, ContentBlock, ErrorData, GetPromptResult, JsonObject, ReadResourceResult,
    ResourceContents,
};
use serde_json::{Map, Value};

use crate::aggregate::TemplateRoute;
use crate::contract::{
    FieldRules, PromptContract, Rule, TemplateContract, ToolContract, pointer_escape,
};
use crate::discovery::{
    Collector, DiscoveryError, SLOT, fill, fill_resource, fill_str, plan_resource, slot_index,
    valid_mime,
};
use crate::handles::{HandleStore, Owner, expand_template};
use crate::service::{BlockOutcome, BlockResult, Blocks, BlocksError, FieldHint};

/// Why a result or request could not be served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentError {
    /// At least one block was `Blocked`; the whole result is discarded.
    Blocked {
        /// Kinds, deduplicated by label, first-seen order.
        kinds: Vec<EntityKind>,
        /// Checks, deduplicated, first-seen order.
        checks: Vec<CheckLabel>,
    },
    /// At least one block was `PassUncertain`; withheld (M4 spec §5.3).
    Uncertain {
        /// Kinds, deduplicated by label.
        kinds: Vec<EntityKind>,
        /// Checks, deduplicated.
        checks: Vec<CheckLabel>,
    },
    /// An unsupported shape; fixed class.
    Unsupported(&'static str),
    /// Strict restoration failed before dispatch.
    Unresolved {
        /// Unknown tokens.
        unknown: usize,
        /// Removed markers.
        removed: usize,
    },
    /// The engine failed.
    Blocks(BlocksError),
}

impl From<BlocksError> for ContentError {
    fn from(e: BlocksError) -> Self {
        match e {
            BlocksError::Unresolved { unknown, removed } => {
                ContentError::Unresolved { unknown, removed }
            }
            BlocksError::Unsupported(c) => ContentError::Unsupported(c),
            other => ContentError::Blocks(other),
        }
    }
}

impl From<DiscoveryError> for ContentError {
    fn from(e: DiscoveryError) -> Self {
        match e {
            DiscoveryError::Unsupported(c) => ContentError::Unsupported(c),
            DiscoveryError::Blocks(b) => b.into(),
        }
    }
}

/// What one sanitized result cost.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SanitizeStats {
    /// Blocks sent to the engine.
    pub blocks: usize,
    /// Blocks served from the cache.
    pub cached: usize,
    /// Replaced kinds (deduplicated by label, first-seen order) with the
    /// number of blocks each was replaced in, for activity records.
    pub replaced: Vec<(EntityKind, u32)>,
}

/// Kind labels as the agent sees them (`PERSON`, `IBAN`).
pub fn kind_labels(kinds: &[EntityKind]) -> Vec<&str> {
    kinds.iter().map(EntityKind::label).collect()
}

/// Check names as the agent sees them (`Leak`, `ClearValue`).
pub fn check_names(checks: &[CheckLabel]) -> Vec<&'static str> {
    checks.iter().map(|c| c.as_str()).collect()
}

/// `blocked by inumaki (kinds: PERSON, IBAN; checks: Leak)`.
pub fn blocked_text(kinds: &[EntityKind], checks: &[CheckLabel]) -> String {
    format!(
        "blocked by inumaki (kinds: {}; checks: {})",
        kind_labels(kinds).join(", "),
        check_names(checks).join(", ")
    )
}

/// `withheld by inumaki (uncertain; kinds: DATE; checks: Combination)`.
pub fn withheld_text(kinds: &[EntityKind], checks: &[CheckLabel]) -> String {
    format!(
        "withheld by inumaki (uncertain; kinds: {}; checks: {})",
        kind_labels(kinds).join(", "),
        check_names(checks).join(", ")
    )
}

/// Every string or number value and every object key in `v`, depth first
/// (a number is scanned as text: a card number or identifier the model
/// wrote as a JSON number is still a value to check). Used by the
/// clear-value tripwire (M4 spec §16.1) to scan model-written arguments
/// before rehydration. Keys are included because a key under a `map` rule
/// is data and gets rehydrated like a value (final review, finding 5); a
/// static key is a schema name, which the listing already scanned, so
/// including it costs nothing but a short scan.
pub fn string_leaves(v: &Value) -> Vec<String> {
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::String(s) => out.push(s.clone()),
            Value::Number(n) => out.push(n.to_string()),
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            Value::Object(o) => {
                for (k, x) in o {
                    out.push(k.clone());
                    walk(x, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(v, &mut out);
    out
}

/// `upstream_error` with the upstream's JSON-RPC code only: the message and
/// data of an upstream error may echo rehydrated arguments.
pub fn upstream_error(e: &ErrorData) -> ErrorData {
    ErrorData::new(
        e.code,
        "upstream_error",
        Some(serde_json::json!({ "code": e.code.0 })),
    )
}

/// Add `k` unless a kind with the same label is there (all secrets share
/// `SECRET`).
fn push_kind(v: &mut Vec<EntityKind>, k: &EntityKind) {
    if !v.iter().any(|x| x.label() == k.label()) {
        v.push(k.clone());
    }
}

/// Kinds (the block's kinds, then its reasons' kinds) and checks of a
/// non-passing block, merged into the result's lists.
fn collect_labels(r: &BlockResult, kinds: &mut Vec<EntityKind>, checks: &mut Vec<CheckLabel>) {
    for k in &r.kinds {
        push_kind(kinds, k);
    }
    for reason in &r.reasons {
        push_kind(kinds, &reason.kind);
        let c = CheckLabel::of(&reason.check);
        if !checks.contains(&c) {
            checks.push(c);
        }
    }
}

/// Run a result batch: `Blocked` → `Blocked`, `PassUncertain` → `Uncertain`.
fn run_result_batch(
    col: Collector,
    blocks: &dyn Blocks,
    dataset: &str,
    stats: &mut SanitizeStats,
) -> Result<Vec<String>, ContentError> {
    if col.blocks.is_empty() {
        return Ok(Vec::new());
    }
    let n = col.blocks.len();
    let results = blocks.sanitize_blocks(dataset, col.blocks)?;
    if results.len() != n {
        return Err(ContentError::Blocks(BlocksError::Internal("block count")));
    }
    let mut kinds = Vec::new();
    let mut checks = Vec::new();
    let mut blocked = false;
    let mut uncertain = false;
    for r in &results {
        match r.outcome {
            BlockOutcome::Blocked => {
                blocked = true;
                collect_labels(r, &mut kinds, &mut checks);
            }
            BlockOutcome::PassUncertain => {
                uncertain = true;
                collect_labels(r, &mut kinds, &mut checks);
            }
            BlockOutcome::Pass => {}
        }
    }
    if blocked {
        return Err(ContentError::Blocked { kinds, checks });
    }
    if uncertain {
        return Err(ContentError::Uncertain { kinds, checks });
    }
    stats.blocks += results.len();
    stats.cached += results.iter().filter(|r| r.cached).count();
    for r in &results {
        let mut seen: Vec<EntityKind> = Vec::new();
        for k in &r.kinds {
            push_kind(&mut seen, k);
        }
        for k in seen {
            match stats
                .replaced
                .iter_mut()
                .find(|(x, _)| x.label() == k.label())
            {
                Some((_, n)) => *n += 1,
                None => stats.replaced.push((k, 1)),
            }
        }
    }
    Ok(results.into_iter().map(|r| r.text).collect())
}

/// Like `discovery::fill`, but keys may be slots too (map rules); a key
/// collision after sanitization is an error.
fn fill_keys(v: Value, texts: &[String]) -> Result<Value, ContentError> {
    match v {
        Value::Array(a) => Ok(Value::Array(
            a.into_iter()
                .map(|x| fill_keys(x, texts))
                .collect::<Result<_, _>>()?,
        )),
        Value::Object(o) => {
            let mut out = Map::new();
            for (k, x) in o {
                let nk = fill_str(&k, texts);
                if out.insert(nk, fill_keys(x, texts)?).is_some() {
                    return Err(ContentError::Unsupported("key_collision"));
                }
            }
            Ok(Value::Object(out))
        }
        Value::String(_) => Ok(fill(v, texts)),
        other => Ok(other),
    }
}

/// Walk a `structuredContent` value against `rules`, registering blocks.
/// `inherited` is the rule a `map` rule hands to its values. An object's
/// keys are static field names with a rule at or below them, or, under a
/// `map` rule, free-text blocks; nothing else.
fn walk_result(
    v: &Value,
    ptr: &str,
    rules: &FieldRules,
    inherited: Option<&Rule>,
    col: &mut Collector,
) -> Result<Value, ContentError> {
    let rule = rules.get(ptr).or(inherited);
    match v {
        Value::String(s) => match rule {
            None | Some(Rule::FreeText) => Ok(col.slot_value(s)),
            Some(Rule::Identifier(k)) => {
                Ok(Value::String(col.slot(s, FieldHint::Identifier(k.clone()))))
            }
            // A kept string never looks like a slot marker.
            Some(Rule::Preserve) if !s.contains('\u{0}') => Ok(v.clone()),
            // Kept only if the daemon minted it (provenance, not shape).
            Some(Rule::Handle) => Ok(Value::String(col.slot(s, FieldHint::Handle))),
            Some(Rule::Preserve | Rule::Quantity | Rule::Map(_)) => {
                Err(ContentError::Unsupported("string_rule"))
            }
        },
        Value::Number(n) => match rule {
            Some(Rule::Quantity | Rule::Preserve) => Ok(v.clone()),
            Some(Rule::Identifier(k)) => Ok(Value::String(
                col.slot(&n.to_string(), FieldHint::Identifier(k.clone())),
            )),
            _ => Err(ContentError::Unsupported("number")),
        },
        // No handle (a draft that could not be located): nothing to check.
        Value::Null if matches!(rule, Some(Rule::Handle)) => Ok(v.clone()),
        Value::Bool(_) | Value::Null => match rule {
            None | Some(Rule::Preserve | Rule::Quantity) => Ok(v.clone()),
            _ => Err(ContentError::Unsupported("scalar_rule")),
        },
        Value::Array(a) => {
            let child = format!("{ptr}/*");
            // Element rules sit at `…/*` (or come from a `map` rule); a
            // scalar rule on the array itself is a shape mismatch.
            let inner = match rule {
                None => None,
                Some(Rule::Map(r)) => Some(r.as_ref()),
                Some(_) => return Err(ContentError::Unsupported("array_rule")),
            };
            Ok(Value::Array(
                a.iter()
                    .map(|x| walk_result(x, &child, rules, inner, col))
                    .collect::<Result<_, _>>()?,
            ))
        }
        Value::Object(o) => {
            let mut out = Map::new();
            if let Some(Rule::Map(inner)) = rule {
                let child = format!("{ptr}/*");
                for (k, x) in o {
                    let nk = col.slot(k, FieldHint::FreeText);
                    out.insert(
                        nk,
                        walk_result(x, &child, rules, Some(inner.as_ref()), col)?,
                    );
                }
                return Ok(Value::Object(out));
            }
            for (k, x) in o {
                let child = format!("{ptr}/{}", pointer_escape(k));
                if !rules.has_prefix(&child) {
                    return Err(ContentError::Unsupported("result_key"));
                }
                out.insert(k.clone(), walk_result(x, &child, rules, None, col)?);
            }
            Ok(Value::Object(out))
        }
    }
}

/// Plan one content item: register its blocks; returns the item with slot
/// markers in place of every text. Binary and unknown items are unsupported.
fn plan_item(
    item: ContentBlock,
    col: &mut Collector,
    handles: &mut HandleStore,
    owner: &Owner,
) -> Result<ContentBlock, ContentError> {
    match item {
        ContentBlock::Text(mut t) => {
            t.text = col.slot(&t.text, FieldHint::FreeText);
            t.meta = None;
            t.annotations = None;
            Ok(ContentBlock::Text(t))
        }
        ContentBlock::Image(_) | ContentBlock::Audio(_) => Err(ContentError::Unsupported("binary")),
        ContentBlock::Resource(mut e) => {
            e.resource = match e.resource {
                ResourceContents::TextResourceContents {
                    uri,
                    mime_type,
                    text,
                    ..
                } => ResourceContents::TextResourceContents {
                    uri: handles.resource(owner, &uri),
                    mime_type: mime_type.filter(|m| valid_mime(m)),
                    text: col.slot(&text, FieldHint::FreeText),
                    meta: None,
                },
                ResourceContents::BlobResourceContents { .. } => {
                    return Err(ContentError::Unsupported("binary"));
                }
                _ => return Err(ContentError::Unsupported("content_type")),
            };
            e.meta = None;
            e.annotations = None;
            Ok(ContentBlock::Resource(e))
        }
        ContentBlock::ResourceLink(r) => Ok(ContentBlock::ResourceLink(plan_resource(
            &r, owner, col, handles,
        ))),
        _ => Err(ContentError::Unsupported("content_type")),
    }
}

/// Put the sanitized texts into an item planned by [`plan_item`].
fn fill_item(item: ContentBlock, texts: &[String]) -> ContentBlock {
    match item {
        ContentBlock::Text(mut t) => {
            t.text = fill_str(&t.text, texts);
            ContentBlock::Text(t)
        }
        ContentBlock::Resource(mut e) => {
            if let ResourceContents::TextResourceContents { text, .. } = &mut e.resource {
                *text = fill_str(text, texts);
            }
            ContentBlock::Resource(e)
        }
        ContentBlock::ResourceLink(r) => ContentBlock::ResourceLink(fill_resource(r, texts)),
        other => other,
    }
}

/// Sanitize a `tools/call` result through the tool's contract. Resource
/// URIs in it become handles of `owner`.
pub fn sanitize_call_result(
    blocks: &dyn Blocks,
    dataset: &str,
    contract: Option<&ToolContract>,
    handles: &mut HandleStore,
    owner: &Owner,
    mut r: CallToolResult,
) -> Result<(CallToolResult, SanitizeStats), ContentError> {
    let mut stats = SanitizeStats::default();
    let mut col = Collector::new();
    let items = std::mem::take(&mut r.content);
    let planned: Vec<ContentBlock> = items
        .into_iter()
        .map(|i| plan_item(i, &mut col, handles, owner))
        .collect::<Result<_, _>>()?;
    let structured = match r.structured_content.take() {
        None => None,
        Some(v) => {
            let rules = contract
                .and_then(|c| c.result.as_ref())
                .ok_or(ContentError::Unsupported("structured_content"))?;
            Some(walk_result(&v, "", rules, None, &mut col)?)
        }
    };
    let texts = run_result_batch(col, blocks, dataset, &mut stats)?;
    r.content = planned.into_iter().map(|i| fill_item(i, &texts)).collect();
    r.structured_content = match structured {
        Some(v) => Some(fill_keys(v, &texts)?),
        None => None,
    };
    r.meta = None;
    Ok((r, stats))
}

/// Sanitize a `resources/read` result; every content item's URI becomes
/// the handle the agent asked with.
pub fn sanitize_read_result(
    blocks: &dyn Blocks,
    dataset: &str,
    exposed_uri: &str,
    mut r: ReadResourceResult,
) -> Result<(ReadResourceResult, SanitizeStats), ContentError> {
    let mut stats = SanitizeStats::default();
    let mut col = Collector::new();
    let contents = std::mem::take(&mut r.contents);
    let mut planned: Vec<(Option<String>, String)> = Vec::with_capacity(contents.len());
    for c in contents {
        match c {
            ResourceContents::TextResourceContents {
                mime_type, text, ..
            } => planned.push((
                mime_type.filter(|m| valid_mime(m)),
                col.slot(&text, FieldHint::FreeText),
            )),
            ResourceContents::BlobResourceContents { .. } => {
                return Err(ContentError::Unsupported("binary"));
            }
            _ => return Err(ContentError::Unsupported("content_type")),
        }
    }
    let texts = run_result_batch(col, blocks, dataset, &mut stats)?;
    r.contents = planned
        .into_iter()
        .map(|(mime_type, slot)| ResourceContents::TextResourceContents {
            uri: exposed_uri.to_string(),
            mime_type,
            text: fill_str(&slot, &texts),
            meta: None,
        })
        .collect();
    r.meta = None;
    Ok((r, stats))
}

/// Sanitize a `prompts/get` result: description and every message item.
pub fn sanitize_prompt_result(
    blocks: &dyn Blocks,
    dataset: &str,
    handles: &mut HandleStore,
    owner: &Owner,
    mut r: GetPromptResult,
) -> Result<(GetPromptResult, SanitizeStats), ContentError> {
    let mut stats = SanitizeStats::default();
    let mut col = Collector::new();
    let description = r
        .description
        .take()
        .map(|d| col.slot(&d, FieldHint::FreeText));
    let mut planned = Vec::with_capacity(r.messages.len());
    for m in &mut r.messages {
        let item = std::mem::replace(&mut m.content, ContentBlock::text(""));
        planned.push(plan_item(item, &mut col, handles, owner)?);
    }
    let texts = run_result_batch(col, blocks, dataset, &mut stats)?;
    r.description = description.map(|d| fill_str(&d, &texts));
    for (m, item) in r.messages.iter_mut().zip(planned) {
        m.content = fill_item(item, &texts);
    }
    r.meta = None;
    Ok((r, stats))
}

/// The JSON Schema node describing `key` under `schema`, if any.
fn schema_property<'a>(
    schema: &'a Map<String, Value>,
    key: &str,
) -> Option<&'a Map<String, Value>> {
    schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|p| p.get(key))
        .and_then(Value::as_object)
}

/// Stands for a schema node that is present but says nothing usable (a
/// boolean subschema, unconstrained tuple elements): an identifier under
/// it has no determinable type.
static UNKNOWN_SCHEMA: LazyLock<Map<String, Value>> = LazyLock::new(Map::new);

/// The schema node of element `i` of an array: `prefixItems[i]` (or a
/// draft-7 tuple `items[i]`), else `items` (or `additionalItems` after a
/// draft-7 tuple). `None` when the array schema describes no elements at
/// all; [`UNKNOWN_SCHEMA`] when it does but not as a schema object.
fn schema_element(schema: &Map<String, Value>, i: usize) -> Option<&Map<String, Value>> {
    let (tuple, rest) = match (schema.get("prefixItems"), schema.get("items")) {
        (Some(t), rest) => (Some(t), rest),
        (None, Some(t @ Value::Array(_))) => (Some(t), schema.get("additionalItems")),
        (None, rest) => (None, rest),
    };
    if let Some(t) = tuple {
        match t.as_array().and_then(|a| a.get(i)) {
            Some(e) => return Some(e.as_object().unwrap_or(&UNKNOWN_SCHEMA)),
            None if !t.is_array() => return Some(&UNKNOWN_SCHEMA),
            None => {}
        }
    }
    match rest {
        Some(Value::Object(o)) => Some(o),
        Some(_) => Some(&UNKNOWN_SCHEMA),
        None if tuple.is_some() => Some(&UNKNOWN_SCHEMA),
        None => None,
    }
}

fn schema_additional(schema: &Map<String, Value>) -> Option<&Map<String, Value>> {
    schema
        .get("additionalProperties")
        .and_then(Value::as_object)
}

/// How many `$ref` hops or nested combinators a type lookup follows.
const MAX_SCHEMA_DEPTH: usize = 16;

/// Follow local `$ref`s (`#` or `#/…`, RFC 6901) from `node` within
/// `root`; the node itself when it has no `$ref`, `None` when a reference
/// is not local, does not resolve, or loops.
fn deref<'a>(
    root: &'a Map<String, Value>,
    mut node: &'a Map<String, Value>,
) -> Option<&'a Map<String, Value>> {
    for _ in 0..MAX_SCHEMA_DEPTH {
        let Some(r) = node.get("$ref") else {
            return Some(node);
        };
        let path = r.as_str()?.strip_prefix('#')?;
        let mut cur = root;
        if !path.is_empty() {
            for seg in path.strip_prefix('/')?.split('/') {
                let seg = seg.replace("~1", "/").replace("~0", "~");
                cur = cur.get(&seg)?.as_object()?;
            }
        }
        node = cur;
    }
    None
}

/// The one non-`null` scalar type `node` admits: its `type` (a list may
/// add only `null`), through local `$ref`s and `anyOf`/`oneOf`/`allOf`
/// branches that agree (`Optional[int]` is `anyOf: [integer, null]`).
/// `None` when it cannot be determined or is ambiguous.
fn node_type(
    root: &Map<String, Value>,
    node: &Map<String, Value>,
    depth: usize,
    budget: &mut usize,
) -> Option<String> {
    // A shared visit budget: a `$defs` DAG whose branches reference the
    // same definitions would otherwise be walked exponentially often.
    if depth > MAX_SCHEMA_DEPTH || *budget == 0 {
        return None;
    }
    *budget -= 1;
    let node = deref(root, node)?;
    match node.get("type") {
        Some(Value::String(t)) => return Some(t.clone()),
        Some(Value::Array(a)) => {
            let mut non_null = a.iter().filter(|t| t.as_str() != Some("null"));
            return match (non_null.next(), non_null.next()) {
                (Some(Value::String(t)), None) => Some(t.clone()),
                _ => None,
            };
        }
        Some(_) => return None,
        None => {}
    }
    let mut found: Option<String> = None;
    for key in ["anyOf", "oneOf", "allOf"] {
        let Some(branches) = node.get(key) else {
            continue;
        };
        for b in branches.as_array()? {
            let t = node_type(root, b.as_object()?, depth + 1, budget)?;
            if t == "null" {
                continue;
            }
            match &found {
                Some(f) if *f != t => return None,
                _ => found = Some(t),
            }
        }
    }
    found
}

/// Schema nodes one argument walk (one tool call) may visit to determine
/// identifier types; a very large, identifier-heavy schema fails closed.
const TYPE_VISIT_BUDGET: usize = 256;

/// Strings to rehydrate (values and dynamic keys, in walk order), with the
/// upstream's scalar type for identifier fields.
struct ArgPlan {
    strings: Vec<String>,
    /// (slot index, identifier target type) for identifier fields.
    typed: Vec<(usize, String)>,
    /// Target types already determined, by schema node address.
    types: HashMap<usize, Option<String>>,
    /// Schema node visits left for type lookups ([`TYPE_VISIT_BUDGET`]).
    budget: usize,
}

impl ArgPlan {
    fn new() -> Self {
        ArgPlan {
            strings: Vec::new(),
            typed: Vec::new(),
            types: HashMap::new(),
            budget: TYPE_VISIT_BUDGET,
        }
    }

    fn slot(&mut self, s: &str) -> String {
        self.strings.push(s.to_string());
        format!("{SLOT}{}", self.strings.len() - 1)
    }

    /// The scalar type an identifier argument converts back to: `string`
    /// when the field has no schema node at all (a dynamic key without
    /// `additionalProperties`, an array without `items`), else the node's
    /// one type; a node whose type cannot be determined (or whose lookup
    /// exhausts the walk's budget) is `argument_type`, never a silent string.
    fn target_type(
        &mut self,
        root: &Map<String, Value>,
        schema: Option<&Map<String, Value>>,
    ) -> Result<String, ContentError> {
        let Some(node) = schema else {
            return Ok("string".into());
        };
        let key = std::ptr::from_ref(node) as usize;
        let ty = match self.types.get(&key) {
            Some(t) => t.clone(),
            None => {
                let t = node_type(root, node, 0, &mut self.budget);
                self.types.insert(key, t.clone());
                t
            }
        };
        ty.ok_or(ContentError::Unsupported("argument_type"))
    }
}

/// Walk the agent's arguments. `root` is the upstream's input schema
/// (for local `$ref`s), `schema` the node describing this value.
fn walk_args<'a>(
    v: &Value,
    ptr: &str,
    root: &'a Map<String, Value>,
    schema: Option<&'a Map<String, Value>>,
    rules: Option<&FieldRules>,
    inherited: Option<&Rule>,
    plan: &mut ArgPlan,
) -> Result<Value, ContentError> {
    let rule = rules.and_then(|r| r.get(ptr)).or(inherited);
    let schema = schema.map(|s| deref(root, s).unwrap_or(s));
    match v {
        Value::String(s) => {
            let target = match rule {
                Some(Rule::Identifier(_)) => Some(plan.target_type(root, schema)?),
                _ => None,
            };
            let marker = plan.slot(s);
            if let Some(ty) = target {
                plan.typed.push((plan.strings.len() - 1, ty));
            }
            Ok(Value::String(marker))
        }
        Value::Array(a) => {
            let child = format!("{ptr}/*");
            let inner = match rule {
                Some(Rule::Map(r)) => Some(r.as_ref()),
                _ => None,
            };
            Ok(Value::Array(
                a.iter()
                    .enumerate()
                    .map(|(i, x)| {
                        let item = schema.and_then(|s| schema_element(s, i));
                        walk_args(x, &child, root, item, rules, inner, plan)
                    })
                    .collect::<Result<_, _>>()?,
            ))
        }
        Value::Object(o) => {
            let mut out = Map::new();
            let map_inner = match rule {
                Some(Rule::Map(r)) => Some(r.as_ref()),
                _ => None,
            };
            for (k, x) in o {
                if let Some(sub) = schema.and_then(|s| schema_property(s, k)) {
                    let child = format!("{ptr}/{}", pointer_escape(k));
                    out.insert(
                        k.clone(),
                        walk_args(x, &child, root, Some(sub), rules, None, plan)?,
                    );
                } else if let Some(inner) = map_inner {
                    // A dynamic key is data the agent may have tokenized.
                    let child = format!("{ptr}/*");
                    let sub = schema.and_then(schema_additional);
                    let key = plan.slot(k);
                    out.insert(
                        key,
                        walk_args(x, &child, root, sub, rules, Some(inner), plan)?,
                    );
                } else {
                    return Err(ContentError::Unsupported("argument_key"));
                }
            }
            Ok(Value::Object(out))
        }
        other => Ok(other.clone()),
    }
}

fn typed_value(t: String, ty: &str) -> Result<Value, ContentError> {
    let bad = || ContentError::Unsupported("argument_type");
    match ty {
        "integer" => match serde_json::from_str::<serde_json::Number>(&t) {
            Ok(n) if n.is_i64() || n.is_u64() => Ok(Value::Number(n)),
            _ => Err(bad()),
        },
        "number" => serde_json::from_str::<serde_json::Number>(&t)
            .map(Value::Number)
            .map_err(|_| bad()),
        "boolean" => t.parse::<bool>().map(Value::Bool).map_err(|_| bad()),
        "string" => Ok(Value::String(t)),
        _ => Err(bad()),
    }
}

fn restore_types(
    v: Value,
    texts: &[String],
    typed: &[(usize, String)],
) -> Result<Value, ContentError> {
    match v {
        Value::String(s) => match slot_index(&s) {
            Some(i) => {
                let t = texts.get(i).cloned().unwrap_or_default();
                match typed.iter().find(|(j, _)| *j == i) {
                    Some((_, ty)) => typed_value(t, ty),
                    None => Ok(Value::String(t)),
                }
            }
            None => Ok(Value::String(s)),
        },
        Value::Array(a) => Ok(Value::Array(
            a.into_iter()
                .map(|x| restore_types(x, texts, typed))
                .collect::<Result<_, _>>()?,
        )),
        Value::Object(o) => {
            let mut out = Map::new();
            for (k, x) in o {
                let nk = fill_str(&k, texts);
                if out.insert(nk, restore_types(x, texts, typed)?).is_some() {
                    return Err(ContentError::Unsupported("key_collision"));
                }
            }
            Ok(Value::Object(out))
        }
        other => Ok(other),
    }
}

/// Strict restoration of `strings`, one text per input or an error.
fn rehydrate_all(
    blocks: &dyn Blocks,
    dataset: &str,
    strings: Vec<String>,
) -> Result<Vec<String>, ContentError> {
    if strings.is_empty() {
        return Ok(Vec::new());
    }
    let n = strings.len();
    let texts = blocks.rehydrate_strict(dataset, strings)?;
    if texts.len() != n {
        return Err(ContentError::Blocks(BlocksError::Internal("block count")));
    }
    Ok(texts)
}

/// Strictly rehydrate a tool call's arguments through the contract and the
/// upstream's input schema; identifier fields are converted back to the
/// schema's scalar type, and keys under a `map` rule are restored too.
/// Fails before dispatch on any unresolved placeholder, unknown key, key
/// collision, or type mismatch.
pub fn rehydrate_arguments(
    blocks: &dyn Blocks,
    dataset: &str,
    contract: Option<&ToolContract>,
    input_schema: &JsonObject,
    args: Option<JsonObject>,
) -> Result<Option<JsonObject>, ContentError> {
    let Some(args) = args else {
        return Ok(None);
    };
    let mut plan = ArgPlan::new();
    let planned = walk_args(
        &Value::Object(args),
        "",
        input_schema,
        Some(input_schema),
        contract.map(|c| &c.arguments),
        None,
        &mut plan,
    )?;
    let texts = rehydrate_all(blocks, dataset, plan.strings)?;
    match restore_types(planned, &texts, &plan.typed)? {
        Value::Object(o) => Ok(Some(o)),
        _ => Err(ContentError::Unsupported("arguments")),
    }
}

/// Strictly rehydrate prompt arguments: every value a string, every key a
/// declared argument name.
pub fn rehydrate_prompt_arguments(
    blocks: &dyn Blocks,
    dataset: &str,
    contract: Option<&PromptContract>,
    declared: &[String],
    args: Option<JsonObject>,
) -> Result<Option<JsonObject>, ContentError> {
    let Some(args) = args else {
        return Ok(None);
    };
    let mut strings = Vec::new();
    let mut keys = Vec::new();
    for (k, v) in &args {
        if !declared.iter().any(|d| d == k) {
            return Err(ContentError::Unsupported("argument_key"));
        }
        let Value::String(s) = v else {
            return Err(ContentError::Unsupported("argument_type"));
        };
        let rule = contract.and_then(|c| c.arguments.get(&format!("/{}", pointer_escape(k))));
        if matches!(rule, Some(Rule::Quantity | Rule::Map(_))) {
            return Err(ContentError::Unsupported("argument_rule"));
        }
        keys.push(k.clone());
        strings.push(s.clone());
    }
    let texts = rehydrate_all(blocks, dataset, strings)?;
    Ok(Some(
        keys.into_iter()
            .zip(texts)
            .map(|(k, t)| (k, Value::String(t)))
            .collect(),
    ))
}

/// Percent-decode one template value (RFC 3986); `None` on a malformed
/// escape or a result that is not UTF-8. `pub(crate)`: the tripwire
/// (`handler.rs`) decodes template parameter values the same way before
/// scanning them, since `route_template` hands them over still encoded.
pub(crate) fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            // Two hex digits, nothing else (`from_str_radix` alone would
            // accept a sign, as in `%+F`).
            let (h, l) = (*b.get(i + 1)?, *b.get(i + 2)?);
            if !h.is_ascii_hexdigit() || !l.is_ascii_hexdigit() {
                return None;
            }
            let hex = [h, l];
            out.push(u8::from_str_radix(std::str::from_utf8(&hex).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Percent-encode every byte outside RFC 3986 `unreserved` (RFC 6570
/// simple expansion).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Strictly rehydrate template parameter values by their rules and expand
/// the upstream's template. Values arrive percent-encoded (RFC 6570); they
/// are decoded before restoration, so an encoded token is still found, and
/// encoded again for the upstream URI.
pub fn rehydrate_template_params(
    blocks: &dyn Blocks,
    dataset: &str,
    contract: &TemplateContract,
    route: &TemplateRoute,
    values: Vec<String>,
) -> Result<String, ContentError> {
    if values.len() != route.params.len() {
        return Err(ContentError::Unsupported("template_values"));
    }
    for p in &route.params {
        match contract.params.get(p) {
            Some(Rule::FreeText | Rule::Identifier(_) | Rule::Preserve) => {}
            _ => return Err(ContentError::Unsupported("template_param")),
        }
    }
    let decoded = values
        .iter()
        .map(|v| percent_decode(v))
        .collect::<Option<Vec<_>>>()
        .ok_or(ContentError::Unsupported("template_values"))?;
    let restored: Vec<String> = rehydrate_all(blocks, dataset, decoded)?
        .iter()
        .map(|v| percent_encode(v))
        .collect();
    expand_template(&route.original, &route.params, &restored)
        .ok_or(ContentError::Unsupported("template_values"))
}

#[cfg(test)]
mod tripwire_tests {
    use serde_json::json;

    use super::string_leaves;

    #[test]
    fn string_leaves_walks_keys_and_values_and_includes_numbers() {
        let v = json!({ "Zyxwuria": 1, "a": ["x", { "b": "y" }], "c": true });
        assert_eq!(
            string_leaves(&v),
            ["Zyxwuria", "1", "a", "x", "b", "y", "c"]
        );
    }
}
