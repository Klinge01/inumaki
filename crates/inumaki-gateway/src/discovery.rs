//! Discovery metadata (M4 spec §5.2, §5.3): only reviewed static names and
//! schema structure are exposed; descriptions, titles, examples, string
//! defaults are sanitized blocks; enum and const values and patterns must
//! survive sanitization unchanged; `$ref` must be local; `type`, `format`,
//! and `required` are limited to a fixed vocabulary or static names; an
//! identifier field is a plain `{"type": "string"}` with sanitized prose,
//! and definitions it reaches through `$ref` lose their sample values;
//! extensions, `$schema`, `$id`, `_meta`, icons, and annotations are
//! stripped; resource URIs become handles; templates are exposed only
//! under a reviewed parameter mapping. A blocked or uncertain block, or an
//! unsupported shape, fails the whole listing.
//!
//! Names are exposed as they are, so they are checked, not trusted: every
//! tool, prompt, prompt argument, schema property, definition, `required`
//! entry, and template parameter name of a listing goes through one
//! [`Blocks::scan_names`] pass (known entities and validated identifiers,
//! no NER), as written and split into words; a single-word known person,
//! organization, or street does not count. A hit fails the listing: a
//! server that names things after its records (`Mueller_GmbH_orders`, a
//! property `sarah.leitner`) would otherwise hand those records to the
//! provider in the name itself.
//!
//! The schema walk follows an allowlist of subschema keywords (`properties`,
//! `items`, `prefixItems`, `additionalProperties`, `anyOf`/`oneOf`/`allOf`,
//! local `$ref`, `$defs`/`definitions`, and `discriminator`, checked and
//! stripped), each mapped to the data pointer it describes. A local `$ref`
//! on the way to an identifier rule is inlined as an `allOf` branch, so the
//! rule matches nested models. Every other keyword that could carry a
//! subschema fails the listing: the contract's identifier rules are matched
//! against walked nodes, and a node the walk never visits could describe an
//! identifier field with its raw type and samples.

use std::collections::{BTreeSet, HashSet};

use rmcp::model::{Prompt, PromptArgument, Resource, ResourceTemplate, Tool};
use serde_json::{Map, Value};

use crate::aggregate::{RawLists, TemplateRoute, UpstreamLists, valid_static_name};
use crate::contract::{Contract, FieldRules, Rule, pointer_escape};
use crate::handles::{HandleStore, Owner, template_params};
use crate::service::{BlockOutcome, Blocks, BlocksError, FieldHint, TextBlock};

/// Why a listing could not be exposed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DiscoveryError {
    /// An unsupported shape or a blocked/uncertain block; fixed class.
    #[error("unsupported discovery content: {0}")]
    Unsupported(&'static str),
    /// The engine failed.
    #[error(transparent)]
    Blocks(#[from] BlocksError),
}

/// Marker prefix of a slot string inside a value under construction. The
/// NUL makes it unlike any text a walker keeps as is: those refuse NUL.
pub(crate) const SLOT: &str = "\u{0}inumaki-slot:";

/// The block index of a slot marker, `None` for any other string.
pub(crate) fn slot_index(s: &str) -> Option<usize> {
    s.strip_prefix(SLOT)?.parse().ok()
}

/// The text for `s` when it is a slot marker, else `s` unchanged.
pub(crate) fn fill_str(s: &str, texts: &[String]) -> String {
    match slot_index(s) {
        Some(i) => texts.get(i).cloned().unwrap_or_default(),
        None => s.to_string(),
    }
}

/// Collects blocks; hands out slot markers to put where the sanitized
/// text will go.
pub(crate) struct Collector {
    pub(crate) blocks: Vec<TextBlock>,
    /// Slots whose text must come back unchanged, with the class to fail
    /// with when it does not (enum/const values, patterns).
    static_slots: Vec<(usize, &'static str)>,
    /// Names exposed unchanged, for the clear-value scan in [`Collector::run`].
    names: Vec<String>,
}

impl Collector {
    pub(crate) fn new() -> Self {
        Collector {
            blocks: Vec::new(),
            static_slots: Vec::new(),
            names: Vec::new(),
        }
    }

    /// A name exposed as it is; [`Collector::run`] scans it.
    fn name(&mut self, name: &str) {
        self.names.push(name.to_string());
    }

    pub(crate) fn slot(&mut self, text: &str, hint: FieldHint) -> String {
        self.blocks.push(TextBlock {
            text: text.to_string(),
            hint,
        });
        format!("{SLOT}{}", self.blocks.len() - 1)
    }

    pub(crate) fn slot_value(&mut self, text: &str) -> Value {
        Value::String(self.slot(text, FieldHint::FreeText))
    }

    /// A listing's prose slot ([`FieldHint::Metadata`]).
    fn meta_value(&mut self, text: &str) -> Value {
        Value::String(self.slot(text, FieldHint::Metadata))
    }

    fn slot_static(&mut self, text: &str, class: &'static str) -> Value {
        let s = self.slot(text, FieldHint::Metadata);
        self.static_slots.push((self.blocks.len() - 1, class));
        Value::String(s)
    }

    /// An `enum`/`const` value: a string or a number must survive
    /// sanitization unchanged (a number is checked as its decimal text and
    /// kept as a number); booleans and null are kept.
    fn static_value(&mut self, v: &Value) -> Result<Value, DiscoveryError> {
        match v {
            Value::String(s) => Ok(self.slot_static(s, "enum")),
            Value::Number(n) => {
                self.slot_static(&n.to_string(), "enum");
                Ok(v.clone())
            }
            Value::Bool(_) | Value::Null => Ok(v.clone()),
            _ => Err(DiscoveryError::Unsupported("schema")),
        }
    }

    /// Scan the names, then run the batch. A name with a known entity or a
    /// validated identifier in it, or `Blocked`/`PassUncertain` anywhere,
    /// fails everything.
    fn run(self, blocks: &dyn Blocks, dataset: &str) -> Result<Vec<String>, DiscoveryError> {
        scan_names(blocks, dataset, &self.names)?;
        if self.blocks.is_empty() {
            return Ok(Vec::new());
        }
        let originals: Vec<String> = self.blocks.iter().map(|b| b.text.clone()).collect();
        let results = blocks.sanitize_blocks(dataset, self.blocks)?;
        if results.len() != originals.len() {
            return Err(BlocksError::Internal("block count").into());
        }
        if results.iter().any(|r| r.outcome == BlockOutcome::Blocked) {
            return Err(DiscoveryError::Unsupported("blocked_metadata"));
        }
        if results
            .iter()
            .any(|r| r.outcome == BlockOutcome::PassUncertain)
        {
            return Err(DiscoveryError::Unsupported("uncertain_metadata"));
        }
        let texts: Vec<String> = results.into_iter().map(|r| r.text).collect();
        for (i, class) in self.static_slots {
            if texts[i] != originals[i] {
                return Err(DiscoveryError::Unsupported(class));
            }
        }
        Ok(texts)
    }
}

/// `name` with `seps` turned into spaces.
fn spaced(name: &str, seps: &[char]) -> String {
    name.chars()
        .map(|c| if seps.contains(&c) { ' ' } else { c })
        .collect()
}

/// `s` with a space between a lower-case letter and the upper-case letter
/// after it (`sarahLeitner` → `sarah Leitner`).
fn camel_split(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    let mut prev_lower = false;
    for c in s.chars() {
        if prev_lower && c.is_uppercase() {
            out.push(' ');
        }
        prev_lower = c.is_lowercase();
        out.push(c);
    }
    out
}

/// One [`Blocks::scan_names`] pass over every exposed name of a listing, in
/// the forms a detector can match: as written (`AT611904300234573201`,
/// `Hans-Peter`), with `_` and `.` as spaces, with `-` as a space too, and
/// each of those split at case changes. The detectors match words, and in
/// `Mueller_GmbH_orders` the underscores join them into one. A single-word
/// known person, organization, or street does not count (plan 2c), so a
/// known `Max` does not fail `max_results`. Any hit fails the listing with
/// the fixed class `name`; nothing about the name is reported.
fn scan_names(blocks: &dyn Blocks, dataset: &str, names: &[String]) -> Result<(), DiscoveryError> {
    let mut texts: BTreeSet<String> = BTreeSet::new();
    for n in names {
        let words = spaced(n, &['_', '.']);
        let all = spaced(n, &['_', '.', '-']);
        texts.insert(camel_split(&words));
        texts.insert(camel_split(&all));
        texts.insert(words);
        texts.insert(all);
        texts.insert(n.clone());
    }
    if texts.is_empty() {
        return Ok(());
    }
    let texts: Vec<String> = texts.into_iter().collect();
    if blocks.scan_names(dataset, &texts)? == 0 {
        Ok(())
    } else {
        Err(DiscoveryError::Unsupported("name"))
    }
}

/// Replace slot markers in string values by their texts. Keys are never
/// slots here.
pub(crate) fn fill(v: Value, texts: &[String]) -> Value {
    match v {
        Value::String(s) => Value::String(fill_str(&s, texts)),
        Value::Array(a) => Value::Array(a.into_iter().map(|x| fill(x, texts)).collect()),
        Value::Object(o) => {
            Value::Object(o.into_iter().map(|(k, x)| (k, fill(x, texts))).collect())
        }
        other => other,
    }
}

/// JSON Schema type names.
const TYPES: &[&str] = &[
    "object", "array", "string", "number", "integer", "boolean", "null",
];
/// `format` values kept; any other format is dropped (it is only a hint).
const FORMATS: &[&str] = &[
    "date-time",
    "date",
    "time",
    "duration",
    "email",
    "idn-email",
    "hostname",
    "idn-hostname",
    "ipv4",
    "ipv6",
    "uri",
    "uri-reference",
    "iri",
    "iri-reference",
    "uuid",
    "uri-template",
    "json-pointer",
    "relative-json-pointer",
    "regex",
    "int32",
    "int64",
    "float",
    "double",
    "byte",
    "binary",
    "password",
];
/// `contentEncoding` values kept; any other is dropped.
const ENCODINGS: &[&str] = &[
    "7bit",
    "8bit",
    "binary",
    "quoted-printable",
    "base16",
    "base32",
    "base64",
];
/// Keywords whose value must be a number or a boolean.
const NUMERIC_OR_FLAG: &[&str] = &[
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "multipleOf",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
    "uniqueItems",
    "minProperties",
    "maxProperties",
    "nullable",
    "deprecated",
    "readOnly",
    "writeOnly",
];
/// Keywords holding one subschema that describes `…/*` of the data (array
/// elements, dynamic keys).
const ELEMENT_ONE: &[&str] = &["items", "additionalProperties"];
/// Keywords holding a list of subschemas; `prefixItems` describes `…/*`,
/// the combinators describe the same data as their parent.
const RECURSE_MANY: &[&str] = &["allOf", "anyOf", "oneOf", "prefixItems"];
/// Subschema-bearing keywords the walk does not follow. Each can describe
/// data at a pointer the walk never visits under that name (`contains`,
/// `unevaluatedItems`, and `additionalItems` describe elements,
/// `unevaluatedProperties`, `patternProperties`, and `propertyNames`
/// describe keys, the rest apply whole subschemas conditionally), so an
/// identifier rule could be satisfied by one node while another describes
/// the field with its samples. Any of them fails the listing.
const REFUSED: &[&str] = &[
    "contains",
    "unevaluatedItems",
    "additionalItems",
    "unevaluatedProperties",
    "patternProperties",
    "propertyNames",
    "not",
    "if",
    "then",
    "else",
    "dependentSchemas",
    "dependencies",
];

/// Sample-value keywords, plus `pattern` and the numeric bounds, which can
/// spell a value out (`minimum == maximum` pins it like `const`). Under a
/// schema an identifier field reaches through a local `$ref` they are
/// dropped: a sample there is a raw identifier that no detector recognizes
/// as one. Length and count bounds carry sizes, not values, and stay.
const SAMPLES: &[&str] = &[
    "default",
    "examples",
    "enum",
    "const",
    "pattern",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "multipleOf",
];

/// State of one schema's exposure walk.
struct SchemaCtx<'r> {
    /// The contract's rules over the data this schema describes.
    rules: Option<&'r FieldRules>,
    /// Schema locations (JSON pointers into the schema) whose subtree
    /// loses its [`SAMPLES`].
    strip: HashSet<String>,
    /// References found under identifier nodes and in the `$ref` and
    /// combinators of their ancestors.
    id_refs: Vec<String>,
    /// Pointers of the rules that are or contain an identifier.
    id_ptrs: Vec<String>,
    /// Those of `id_ptrs` the walk reached at a schema node.
    matched: HashSet<String>,
    /// The schema root, for local references.
    root: &'r Value,
    /// `(data pointer, reference)` pairs being inlined, for cycle checks.
    inlining: Vec<(String, String)>,
    /// References inlined in this walk ([`MAX_INLINED`]).
    inlined: usize,
}

impl SchemaCtx<'_> {
    /// True when `ptr` is a strict ancestor of an identifier rule's pointer.
    fn identifier_ancestor(&self, ptr: &str) -> bool {
        let prefix = format!("{ptr}/");
        self.id_ptrs.iter().any(|p| p.starts_with(&prefix))
    }

    /// True when `ptr` is the direct parent of an identifier rule that
    /// names its field (its last segment is not `*`).
    fn identifier_parent(&self, ptr: &str) -> bool {
        self.id_ptrs.iter().any(|p| {
            p.rsplit_once('/')
                .is_some_and(|(parent, seg)| parent == ptr && seg != "*")
        })
    }
}

/// Every `$ref` string anywhere under `v`.
fn collect_refs(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(o) => {
            for (k, x) in o {
                match (k.as_str(), x) {
                    ("$ref", Value::String(r)) => out.push(r.clone()),
                    _ => collect_refs(x, out),
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect_refs(x, out)),
        _ => {}
    }
}

/// The node at a local JSON pointer (RFC 6901) inside `root`.
fn resolve_pointer<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() {
        return Some(root);
    }
    let mut cur = root;
    for seg in path.strip_prefix('/')?.split('/') {
        let seg = seg.replace("~1", "/").replace("~0", "~");
        cur = match cur {
            Value::Object(o) => o.get(&seg)?,
            Value::Array(a) => a.get(seg.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}

/// Schema locations reachable from `refs` through local references,
/// transitively. Every reference must be a local JSON pointer (`#` or
/// `#/…`, unencoded) that resolves; anything else (an anchor like `#Cid`,
/// a percent-encoded pointer, a remote or dangling reference) could hide a
/// definition whose samples would stay, so it fails the listing.
fn reachable_locations(root: &Value, refs: Vec<String>) -> Result<HashSet<String>, DiscoveryError> {
    let mut seen = HashSet::new();
    let mut work = refs;
    while let Some(r) = work.pop() {
        let path = r
            .strip_prefix('#')
            .filter(|p| p.is_empty() || (p.starts_with('/') && !p.contains('%')))
            .ok_or(DiscoveryError::Unsupported("ref"))?;
        if !seen.insert(path.to_string()) {
            continue;
        }
        let node = resolve_pointer(root, path).ok_or(DiscoveryError::Unsupported("ref"))?;
        collect_refs(node, &mut work);
    }
    Ok(seen)
}

/// The exposed form of one upstream schema under `rules`. Identifier nodes
/// become `{"type": "string"}` with their prose sanitized; a first pass
/// (scratch collector, output discarded) finds the definitions they, or
/// their ancestors' `$ref`s and combinators, reach, which then lose their
/// sample values. Every identifier rule must match a node of the walk (a
/// `map` rule where its values are walked, not at the container): a field
/// the walk cannot reach (under a keyword it does not follow, say) would be
/// exposed with its raw type and samples, so the listing fails instead.
fn expose_schema(
    schema: &Map<String, Value>,
    rules: Option<&FieldRules>,
    col: &mut Collector,
) -> Result<Value, DiscoveryError> {
    let root = Value::Object(schema.clone());
    let id_ptrs: Vec<String> = rules
        .iter()
        .flat_map(|r| r.iter())
        .filter(|(_, rule)| rule_has_identifier(rule))
        .map(|(p, _)| p.clone())
        .collect();
    let mut cx = SchemaCtx {
        rules,
        strip: HashSet::new(),
        id_refs: Vec::new(),
        id_ptrs,
        matched: HashSet::new(),
        root: &root,
        inlining: Vec::new(),
        inlined: 0,
    };
    if !cx.id_ptrs.is_empty() {
        walk_schema(&root, "", "", None, false, &mut cx, &mut Collector::new())?;
        if cx.id_ptrs.iter().any(|p| !cx.matched.contains(p)) {
            return Err(DiscoveryError::Unsupported("schema"));
        }
        cx.strip = reachable_locations(&root, std::mem::take(&mut cx.id_refs))?;
        cx.inlined = 0;
    }
    walk_schema(&root, "", "", None, false, &mut cx, col)
}

fn rule_has_identifier(rule: &Rule) -> bool {
    match rule {
        Rule::Identifier(_) => true,
        Rule::Map(inner) => rule_has_identifier(inner),
        _ => false,
    }
}

fn valid_type(v: &Value) -> bool {
    match v {
        Value::String(s) => TYPES.contains(&s.as_str()),
        Value::Array(a) => a
            .iter()
            .all(|t| t.as_str().is_some_and(|s| TYPES.contains(&s))),
        _ => false,
    }
}

/// A local reference whose path segments are static names (`#`, `#/$defs/Id`).
fn valid_ref(s: &str) -> bool {
    match s.strip_prefix('#') {
        Some("") => true,
        Some(path) => path.strip_prefix('/').is_some_and(|p| {
            p.split('/')
                .all(|seg| valid_static_name(seg) || seg == "$defs")
        }),
        None => false,
    }
}

/// Most references one schema walk inlines on identifier paths; a wide
/// reference DAG on the way to an identifier fails the listing instead.
const MAX_INLINED: usize = 64;

/// Walk the target of local reference `r` at data pointer `ptr`: it
/// describes the same data as the node that holds it. Used for nodes on
/// the way to an identifier rule, which the walk must reach by pointer. A
/// reference already being inlined at this pointer (a cycle that never
/// reaches the field), a dangling one, or more than [`MAX_INLINED`] fail
/// the listing.
fn inline_ref(
    r: &str,
    ptr: &str,
    inherited: Option<(&str, &Rule)>,
    strip: bool,
    cx: &mut SchemaCtx<'_>,
    col: &mut Collector,
) -> Result<Value, DiscoveryError> {
    let path = r
        .strip_prefix('#')
        .ok_or(DiscoveryError::Unsupported("ref"))?;
    let root = cx.root;
    let target = resolve_pointer(root, path).ok_or(DiscoveryError::Unsupported("ref"))?;
    if cx.inlined >= MAX_INLINED || cx.inlining.iter().any(|(p, x)| p == ptr && x == r) {
        return Err(DiscoveryError::Unsupported("ref"));
    }
    cx.inlined += 1;
    cx.inlining.push((ptr.to_string(), r.to_string()));
    // The target's own location keeps the sample stripping consistent
    // with the definition itself.
    let walked = walk_schema(target, ptr, path, inherited, strip, cx, col);
    cx.inlining.pop();
    walked
}

/// Pydantic's (OpenAPI) `discriminator`: `propertyName` a static name and
/// `mapping`, when present, static values mapped to local references; no
/// other key. An annotation, not a subschema: checked, never exposed.
fn check_discriminator(x: &Value) -> Result<(), DiscoveryError> {
    let bad = || DiscoveryError::Unsupported("schema");
    let o = x.as_object().ok_or_else(bad)?;
    if !o
        .get("propertyName")
        .and_then(Value::as_str)
        .is_some_and(valid_static_name)
    {
        return Err(bad());
    }
    for (k, v) in o {
        match (k.as_str(), v) {
            ("propertyName", _) => {}
            ("mapping", Value::Object(m))
                if m.iter().all(|(key, r)| {
                    valid_static_name(key) && r.as_str().is_some_and(valid_ref)
                }) => {}
            _ => return Err(bad()),
        }
    }
    Ok(())
}

/// Walk one JSON Schema. `ptr` is the data pointer this schema describes
/// (`cx.rules` decides which fields are identifiers); `loc` is this node's
/// location in the schema itself; `inherited` is the rule in force from an
/// enclosing node (a `map` rule's values, a combinator branch) with the
/// pointer of the contract rule it came from; `strip` drops sample values
/// in this subtree.
fn walk_schema(
    v: &Value,
    ptr: &str,
    loc: &str,
    inherited: Option<(&str, &Rule)>,
    strip: bool,
    cx: &mut SchemaCtx<'_>,
    col: &mut Collector,
) -> Result<Value, DiscoveryError> {
    let Value::Object(o) = v else {
        return match v {
            Value::Bool(_) => Ok(v.clone()),
            _ => Err(DiscoveryError::Unsupported("schema")),
        };
    };
    let own = cx.rules.and_then(|r| r.get(ptr));
    // The rule in force, and the pointer of the contract rule it comes from.
    let (origin, rule) = match (own, inherited) {
        (Some(r), _) => (ptr, Some(r)),
        (None, Some((origin, r))) => (origin, Some(r)),
        (None, None) => (ptr, None),
    };
    if matches!(rule, Some(Rule::Identifier(_))) {
        // This node describes the identifier's values: the rule is matched
        // here (for a `map` rule, at its values, never at the container).
        cx.matched.insert(origin.to_string());
        // The agent sees a string token here, whatever the upstream
        // declares: a plain string with sanitized prose, nothing else (no
        // `$ref`, combinators, constraints, or samples).
        collect_refs(v, &mut cx.id_refs);
        let mut out = Map::new();
        out.insert("type".into(), Value::String("string".into()));
        for k in ["description", "title"] {
            match o.get(k) {
                None => {}
                Some(Value::String(s)) => {
                    out.insert(k.into(), col.meta_value(s));
                }
                Some(_) => return Err(DiscoveryError::Unsupported("schema")),
            }
        }
        return Ok(Value::Object(out));
    }
    // This node is on the way to an identifier rule.
    let id_path = rule.is_some_and(rule_has_identifier) || cx.identifier_ancestor(ptr);
    let map_inner = match rule {
        Some(Rule::Map(inner)) => Some(inner.as_ref()),
        _ => None,
    };
    if id_path {
        // The data below may be described through a reference too, where
        // the walk never matches it by pointer: those definitions lose
        // their samples as well.
        for k in ["$ref", "anyOf", "oneOf", "allOf"] {
            match o.get(k) {
                Some(Value::String(r)) => cx.id_refs.push(r.clone()),
                Some(x) => collect_refs(x, &mut cx.id_refs),
                None => {}
            }
        }
    }
    // A named identifier field's parent must not describe its keys
    // generically as well: `additionalProperties` here (in this branch of a
    // combinator, say) would describe the field at `…/*`, where the rule
    // never matches, with its raw type and samples.
    if cx.identifier_parent(ptr)
        && o.get("additionalProperties")
            .is_some_and(|x| !x.is_boolean())
    {
        return Err(DiscoveryError::Unsupported("schema"));
    }
    // Under a `map` rule every key is a value of the inner rule; static
    // `properties` beside them would be exposed under no rule at all.
    if map_inner.is_some_and(rule_has_identifier) && o.contains_key("properties") {
        return Err(DiscoveryError::Unsupported("schema"));
    }
    let strip = strip || cx.strip.contains(loc);
    // What a `map` rule hands to its values (elements, dynamic keys).
    let values_inherit = map_inner.map(|r| (origin, r));
    let mut out = Map::new();
    // Targets of references inlined at this node, exposed as `allOf` branches.
    let mut inlined: Vec<Value> = Vec::new();
    for (k, x) in o {
        if strip && SAMPLES.contains(&k.as_str()) {
            continue;
        }
        match k.as_str() {
            "description" | "title" => match x {
                Value::String(s) => {
                    out.insert(k.clone(), col.meta_value(s));
                }
                _ => return Err(DiscoveryError::Unsupported("schema")),
            },
            "examples" => {
                if let Value::Array(a) = x {
                    if a.iter().all(Value::is_string) {
                        out.insert(
                            k.clone(),
                            Value::Array(
                                a.iter()
                                    .map(|e| col.meta_value(e.as_str().unwrap_or_default()))
                                    .collect(),
                            ),
                        );
                    }
                }
            }
            "default" => {
                if let Value::String(s) = x {
                    out.insert(k.clone(), col.meta_value(s));
                }
            }
            "enum" => {
                let Value::Array(a) = x else {
                    return Err(DiscoveryError::Unsupported("enum"));
                };
                let mut vals = Vec::with_capacity(a.len());
                for e in a {
                    vals.push(col.static_value(e)?);
                }
                out.insert(k.clone(), Value::Array(vals));
            }
            "const" => {
                let c = col.static_value(x)?;
                out.insert(k.clone(), c);
            }
            "pattern" => match x {
                Value::String(s) => {
                    out.insert(k.clone(), col.slot_static(s, "schema"));
                }
                _ => return Err(DiscoveryError::Unsupported("schema")),
            },
            "$ref" => {
                let Value::String(s) = x else {
                    return Err(DiscoveryError::Unsupported("ref"));
                };
                if !valid_ref(s) {
                    return Err(DiscoveryError::Unsupported("ref"));
                }
                for seg in s.split('/').skip(1) {
                    col.name(seg);
                }
                if id_path {
                    // On the way to an identifier field (a Pydantic nested
                    // model, a root `$ref`) the walk must see what the
                    // reference describes at this data pointer: the target
                    // is walked here and exposed inline as an `allOf` branch.
                    inlined.push(inline_ref(
                        s,
                        ptr,
                        rule.map(|r| (origin, r)),
                        strip,
                        cx,
                        col,
                    )?);
                } else {
                    out.insert(k.clone(), x.clone());
                }
            }
            "type" => {
                if !valid_type(x) {
                    return Err(DiscoveryError::Unsupported("schema"));
                }
                out.insert(k.clone(), x.clone());
            }
            "required" => {
                let Value::Array(a) = x else {
                    return Err(DiscoveryError::Unsupported("schema"));
                };
                if !a.iter().all(|n| n.as_str().is_some_and(valid_static_name)) {
                    return Err(DiscoveryError::Unsupported("schema"));
                }
                for n in a.iter().filter_map(Value::as_str) {
                    col.name(n);
                }
                out.insert(k.clone(), x.clone());
            }
            "format" => {
                if x.as_str().is_some_and(|f| FORMATS.contains(&f)) {
                    out.insert(k.clone(), x.clone());
                }
            }
            "contentEncoding" => {
                if x.as_str().is_some_and(|f| ENCODINGS.contains(&f)) {
                    out.insert(k.clone(), x.clone());
                }
            }
            "contentMediaType" => {
                if x.as_str().is_some_and(valid_mime) {
                    out.insert(k.clone(), x.clone());
                }
            }
            "properties" | "$defs" | "definitions" => {
                let Value::Object(props) = x else {
                    return Err(DiscoveryError::Unsupported("schema"));
                };
                let mut np = Map::new();
                for (name, sub) in props {
                    if !valid_static_name(name) {
                        return Err(DiscoveryError::Unsupported("property_name"));
                    }
                    col.name(name);
                    let child = if k == "properties" {
                        format!("{ptr}/{}", pointer_escape(name))
                    } else {
                        format!("{ptr}/$defs/{name}")
                    };
                    let child_loc = format!("{loc}/{k}/{}", pointer_escape(name));
                    np.insert(
                        name.clone(),
                        walk_schema(sub, &child, &child_loc, None, strip, cx, col)?,
                    );
                }
                out.insert(k.clone(), Value::Object(np));
            }
            key if ELEMENT_ONE.contains(&key) => {
                let child = format!("{ptr}/*");
                let child_loc = format!("{loc}/{key}");
                let s = match x {
                    Value::Bool(_) => x.clone(),
                    other => {
                        walk_schema(other, &child, &child_loc, values_inherit, strip, cx, col)?
                    }
                };
                out.insert(k.clone(), s);
            }
            key if RECURSE_MANY.contains(&key) => {
                let Value::Array(a) = x else {
                    return Err(DiscoveryError::Unsupported("schema"));
                };
                // A combinator branch describes the same data as this node
                // and keeps its rule; tuple elements are values.
                let (child, inner) = if key == "prefixItems" {
                    (format!("{ptr}/*"), values_inherit)
                } else {
                    (ptr.to_string(), rule.map(|r| (origin, r)))
                };
                let mut v2 = Vec::with_capacity(a.len());
                for (i, s) in a.iter().enumerate() {
                    let child_loc = format!("{loc}/{key}/{i}");
                    v2.push(walk_schema(s, &child, &child_loc, inner, strip, cx, col)?);
                }
                out.insert(k.clone(), Value::Array(v2));
            }
            key if NUMERIC_OR_FLAG.contains(&key) => {
                if !(x.is_number() || x.is_boolean()) {
                    return Err(DiscoveryError::Unsupported("schema"));
                }
                out.insert(k.clone(), x.clone());
            }
            "discriminator" => check_discriminator(x)?,
            key if REFUSED.contains(&key) => return Err(DiscoveryError::Unsupported("schema")),
            // Extensions (`x-…`), `$schema`, `$id`, `$comment`, vendor keys:
            // a scalar is stripped; an object or array could carry
            // subschemas the walk would not follow.
            _ => {
                if x.is_object() || x.is_array() {
                    return Err(DiscoveryError::Unsupported("schema"));
                }
            }
        }
    }
    if !inlined.is_empty() {
        match out.get_mut("allOf") {
            Some(Value::Array(a)) => a.extend(inlined),
            _ => {
                out.insert("allOf".into(), Value::Array(inlined));
            }
        }
    }
    Ok(Value::Object(out))
}

/// A MIME type of token characters only, at most 64 bytes.
pub(crate) fn valid_mime(m: &str) -> bool {
    !m.is_empty()
        && m.len() <= 64
        && m.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'+' | b'-'))
}

/// Sanitize one upstream's lists into what the catalog exposes. Handles
/// are minted for `owner`; `index` is its position in the dataset's
/// upstream vector.
pub fn sanitize_lists(
    blocks: &dyn Blocks,
    dataset: &str,
    owner: &Owner,
    index: usize,
    raw: &RawLists,
    contract: &Contract,
    handles: &mut HandleStore,
) -> Result<UpstreamLists, DiscoveryError> {
    let mut col = Collector::new();
    // tools
    let mut tools: Vec<(Tool, Value, Option<Value>)> = Vec::with_capacity(raw.tools.len());
    for t in &raw.tools {
        if !valid_static_name(&t.name) {
            return Err(DiscoveryError::Unsupported("tool_name"));
        }
        col.name(&t.name);
        let tc = contract.tools.get(t.name.as_ref());
        let input = expose_schema(&t.input_schema, tc.map(|c| &c.arguments), &mut col)?;
        let output = match &t.output_schema {
            Some(s) => Some(expose_schema(
                s,
                tc.and_then(|c| c.result.as_ref()),
                &mut col,
            )?),
            None => None,
        };
        let description = t
            .description
            .as_deref()
            .map(|d| std::borrow::Cow::Owned(col.slot(d, FieldHint::Metadata)));
        let mut tool = Tool::new_with_raw(t.name.clone(), description, Map::new());
        tool.title = t.title.as_deref().map(|s| col.slot(s, FieldHint::Metadata));
        tools.push((tool, input, output));
    }
    // prompts
    let mut prompts: Vec<Prompt> = Vec::with_capacity(raw.prompts.len());
    for p in &raw.prompts {
        if !valid_static_name(&p.name) {
            return Err(DiscoveryError::Unsupported("prompt_name"));
        }
        col.name(&p.name);
        let mut args = Vec::new();
        for a in p.arguments.iter().flatten() {
            if !valid_static_name(&a.name) {
                return Err(DiscoveryError::Unsupported("prompt_argument"));
            }
            col.name(&a.name);
            let mut na = PromptArgument::new(&a.name);
            na.required = a.required;
            na.description = a
                .description
                .as_deref()
                .map(|d| col.slot(d, FieldHint::Metadata));
            na.title = a.title.as_deref().map(|d| col.slot(d, FieldHint::Metadata));
            args.push(na);
        }
        let description = p
            .description
            .as_deref()
            .map(|d| col.slot(d, FieldHint::Metadata));
        let mut np = Prompt::new(&p.name, description, Some(args));
        np.title = p.title.as_deref().map(|d| col.slot(d, FieldHint::Metadata));
        prompts.push(np);
    }
    // resources
    let mut resources: Vec<(Resource, String)> = Vec::with_capacity(raw.resources.len());
    for r in &raw.resources {
        resources.push((plan_resource(r, owner, &mut col, handles), r.uri.clone()));
    }
    // templates: reviewed ones only
    let mut templates: Vec<(ResourceTemplate, TemplateRoute)> = Vec::new();
    for t in &raw.templates {
        let Some(tc) = contract.templates.get(&t.uri_template) else {
            tracing::debug!(upstream = %owner.name, "template not in the contract; omitted");
            continue;
        };
        let params = template_params(&t.uri_template);
        if params.is_empty()
            || params
                .iter()
                .any(|p| !tc.params.contains_key(p) || !valid_static_name(p))
        {
            return Err(DiscoveryError::Unsupported("template_param"));
        }
        let mut exposed = handles.template(owner, &t.uri_template);
        for p in &params {
            col.name(p);
            exposed.push_str(&format!("/{{{p}}}"));
        }
        let mut nt = ResourceTemplate::new(exposed, col.slot(&t.name, FieldHint::Metadata));
        nt.title = t.title.as_deref().map(|s| col.slot(s, FieldHint::Metadata));
        nt.description = t
            .description
            .as_deref()
            .map(|s| col.slot(s, FieldHint::Metadata));
        nt.mime_type = t.mime_type.clone().filter(|m| valid_mime(m));
        templates.push((
            nt,
            TemplateRoute {
                original: t.uri_template.clone(),
                params,
            },
        ));
    }
    let texts = col.run(blocks, dataset)?;
    let tools = tools
        .into_iter()
        .map(|(mut t, input, output)| {
            t.description = t
                .description
                .map(|d| std::borrow::Cow::Owned(fill_str(&d, &texts)));
            t.title = t.title.map(|d| fill_str(&d, &texts));
            if let Value::Object(o) = fill(input, &texts) {
                t.input_schema = std::sync::Arc::new(o);
            }
            t.output_schema = output.and_then(|s| match fill(s, &texts) {
                Value::Object(o) => Some(std::sync::Arc::new(o)),
                _ => None,
            });
            t
        })
        .collect();
    let prompts = prompts
        .into_iter()
        .map(|mut p| {
            p.description = p.description.map(|d| fill_str(&d, &texts));
            p.title = p.title.map(|d| fill_str(&d, &texts));
            if let Some(args) = &mut p.arguments {
                for a in args {
                    a.description = a.description.take().map(|d| fill_str(&d, &texts));
                    a.title = a.title.take().map(|d| fill_str(&d, &texts));
                }
            }
            p
        })
        .collect();
    let resources = resources
        .into_iter()
        .map(|(r, o)| (fill_resource(r, &texts), o))
        .collect();
    let templates = templates
        .into_iter()
        .map(|(mut t, route)| {
            t.name = fill_str(&t.name, &texts);
            t.title = t.title.map(|s| fill_str(&s, &texts));
            t.description = t.description.map(|s| fill_str(&s, &texts));
            (t, route)
        })
        .collect();
    Ok(UpstreamLists {
        name: owner.name.clone(),
        index,
        tools,
        prompts,
        resources,
        templates,
    })
}

/// A resource (listed, or a link in a result) with its URI behind a handle
/// of `owner`, its name, title, and description as slots, a MIME type only
/// when it is a plain token, the size kept, icons/meta/annotations dropped.
pub(crate) fn plan_resource(
    r: &Resource,
    owner: &Owner,
    col: &mut Collector,
    handles: &mut HandleStore,
) -> Resource {
    let mut nr = Resource::new(
        handles.resource(owner, &r.uri),
        col.slot(&r.name, FieldHint::FreeText),
    );
    nr.title = r.title.as_deref().map(|s| col.slot(s, FieldHint::FreeText));
    nr.description = r
        .description
        .as_deref()
        .map(|s| col.slot(s, FieldHint::FreeText));
    nr.mime_type = r.mime_type.clone().filter(|m| valid_mime(m));
    nr.size = r.size;
    nr
}

/// Put the sanitized texts into a resource planned by [`plan_resource`].
pub(crate) fn fill_resource(mut r: Resource, texts: &[String]) -> Resource {
    r.name = fill_str(&r.name, texts);
    r.title = r.title.map(|s| fill_str(&s, texts));
    r.description = r.description.map(|s| fill_str(&s, texts));
    r
}
