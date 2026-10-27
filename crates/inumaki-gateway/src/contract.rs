//! Field contracts (M4 spec §5.3): the locally reviewed `content_policy`
//! of an upstream, addressing fields with JSON pointers (`*` = any array
//! index or map key), and the fingerprint of the upstream schema it was
//! reviewed against. Upstream annotations never authorize anything; only
//! this file does.

use std::collections::BTreeMap;

use inumaki_core::policy::{Action, Profile};
use inumaki_core::span::EntityKind;
use rmcp::model::{Prompt, ResourceTemplate, Tool};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::aggregate::valid_static_name;

/// What a field holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// Free text: sanitized (results) or strictly rehydrated (arguments).
    FreeText,
    /// A number that is not an identifier; kept.
    Quantity,
    /// A boolean, null, or string kept as is (reviewed static value).
    Preserve,
    /// A typed identifier: tokenized as `kind` even when no detector fires.
    Identifier(EntityKind),
    /// An object with dynamic keys: keys are free-text blocks, values follow the inner rule.
    Map(Box<Rule>),
    /// A locally minted handle (mail folders and messages): in a result it
    /// is kept only when the daemon confirms it minted the value
    /// ([`FieldHint::Handle`](crate::FieldHint::Handle)), `null` and an
    /// absent field are allowed; in arguments it is strictly rehydrated like
    /// any string (a handle has no `<`) and the connector resolves it. Shape
    /// alone never authorizes keeping a value.
    Handle,
}

/// Rules keyed by normalized JSON pointer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FieldRules {
    rules: BTreeMap<String, Rule>,
}

impl FieldRules {
    /// The rule at exactly `pointer` (with `*` for indexes and map keys).
    pub fn get(&self, pointer: &str) -> Option<&Rule> {
        self.rules.get(pointer)
    }

    /// True when a rule sits at `pointer` or below it.
    pub fn has_prefix(&self, pointer: &str) -> bool {
        let with_slash = format!("{pointer}/");
        self.rules
            .keys()
            .any(|k| k == pointer || k.starts_with(&with_slash))
    }

    /// No rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Every (pointer, rule).
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Rule)> {
        self.rules.iter()
    }
}

/// Rules for one tool.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolContract {
    /// Rules over the agent's arguments.
    pub arguments: FieldRules,
    /// Rules over `structuredContent`; `None` = structured content is unsupported.
    pub result: Option<FieldRules>,
}

/// Rules for one prompt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PromptContract {
    /// Rules over the prompt arguments (`/<name>`).
    pub arguments: FieldRules,
}

/// Rules for one resource template.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TemplateContract {
    /// A rule per template parameter.
    pub params: BTreeMap<String, Rule>,
}

/// One upstream's contract.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Contract {
    /// Format version (1).
    pub version: u32,
    /// Per tool.
    pub tools: BTreeMap<String, ToolContract>,
    /// Per prompt.
    pub prompts: BTreeMap<String, PromptContract>,
    /// Per template (keyed by the upstream's URI template).
    pub templates: BTreeMap<String, TemplateContract>,
}

/// Why a policy was refused. Paths name the local policy file's keys;
/// a name, key, or pointer segment that is not a static name (it may be a
/// data value) is shown as `<invalid>`, and a resource template is named
/// by its position (`#0`), never by its URI.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContractError {
    /// Not a JSON object.
    #[error("content_policy is not a JSON object")]
    Json,
    /// Unsupported `version`.
    #[error("content_policy version is not 1")]
    Version,
    /// An unknown or invalid key.
    #[error("content_policy: unknown or invalid key {0}")]
    Key(String),
    /// A pointer that is not `/…`.
    #[error("content_policy: invalid pointer {0}")]
    Pointer(String),
    /// A rule that is not one of the allowed forms.
    #[error("content_policy: invalid rule at {0}")]
    Rule(String),
    /// An identifier kind that is not a label, or `SECRET`.
    #[error("content_policy: invalid kind at {0}")]
    Kind(String),
    /// An identifier kind the dataset's profile blocks or removes: a typed
    /// field always tokenizes, which would override that action.
    #[error("content_policy: identifier kind at {0} is blocked or removed by the profile")]
    KindAction(String),
}

/// An identifier kind has the one kind-label shape, `[A-Z][A-Z_]{0,31}`
/// (activity records store it; M4 spec §16.4).
fn valid_kind_label(k: &str) -> bool {
    inumaki_core::span::valid_kind_label(k)
}

fn parse_rule(v: &Value, at: &str) -> Result<Rule, ContractError> {
    match v {
        Value::String(s) => match s.as_str() {
            "free_text" => Ok(Rule::FreeText),
            "quantity" => Ok(Rule::Quantity),
            "preserve" => Ok(Rule::Preserve),
            "handle" => Ok(Rule::Handle),
            _ => Err(ContractError::Rule(at.to_string())),
        },
        Value::Object(o) if o.len() == 1 => {
            if let Some(Value::String(k)) = o.get("identifier") {
                // A secret is removed and never restored; a typed token
                // would make it restorable.
                if !valid_kind_label(k) || k == "SECRET" {
                    return Err(ContractError::Kind(at.to_string()));
                }
                return Ok(Rule::Identifier(EntityKind::from_label(k)));
            }
            if let Some(inner) = o.get("map") {
                return Ok(Rule::Map(Box::new(parse_rule(inner, at)?)));
            }
            Err(ContractError::Rule(at.to_string()))
        }
        _ => Err(ContractError::Rule(at.to_string())),
    }
}

/// Rules a string-only field may carry (prompt arguments, template parameters).
fn string_rule(v: &Value, at: &str) -> Result<Rule, ContractError> {
    match parse_rule(v, at)? {
        r @ (Rule::FreeText | Rule::Preserve | Rule::Identifier(_)) => Ok(r),
        // A handle is a structured-content and tool-argument rule only.
        Rule::Quantity | Rule::Map(_) | Rule::Handle => Err(ContractError::Rule(at.to_string())),
    }
}

/// A pointer as an error may show it: segments that are static names or
/// `*` are kept, any other segment (it may be a data key) is `<invalid>`.
fn show_pointer(p: &str) -> String {
    p.split('/')
        .map(|seg| {
            if seg.is_empty() || seg == "*" || valid_static_name(seg) {
                seg
            } else {
                "<invalid>"
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// A policy key as an error may show it.
fn show_key(k: &str) -> &str {
    if valid_static_name(k) { k } else { "<invalid>" }
}

fn valid_pointer(p: &str) -> bool {
    p.starts_with('/') && p.len() > 1 && p[1..].split('/').all(|seg| !seg.is_empty())
}

fn parse_rules(
    v: &Value,
    at: &str,
    rule: fn(&Value, &str) -> Result<Rule, ContractError>,
) -> Result<FieldRules, ContractError> {
    let Value::Object(o) = v else {
        return Err(ContractError::Key(at.to_string()));
    };
    let mut rules = BTreeMap::new();
    for (ptr, r) in o {
        let shown = format!("{at}{}", show_pointer(ptr));
        if !valid_pointer(ptr) {
            return Err(ContractError::Pointer(shown));
        }
        rules.insert(ptr.clone(), rule(r, &shown)?);
    }
    Ok(FieldRules { rules })
}

fn check_keys(
    o: &serde_json::Map<String, Value>,
    allowed: &[&str],
    at: &str,
) -> Result<(), ContractError> {
    for k in o.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(ContractError::Key(format!("{at}{}", show_key(k))));
        }
    }
    Ok(())
}

/// Every identifier kind inside `rule` (through map rules).
fn identifier_kind(rule: &Rule) -> Option<&EntityKind> {
    match rule {
        Rule::Identifier(k) => Some(k),
        Rule::Map(inner) => identifier_kind(inner),
        _ => None,
    }
}

impl Contract {
    /// Nothing reviewed: text-only tools work, everything else is unsupported.
    pub fn empty() -> Contract {
        Contract {
            version: 1,
            ..Contract::default()
        }
    }

    /// Parse the JSON policy text.
    pub fn parse(json: &str) -> Result<Contract, ContractError> {
        let v: Value = serde_json::from_str(json).map_err(|_| ContractError::Json)?;
        let Value::Object(o) = v else {
            return Err(ContractError::Json);
        };
        check_keys(
            &o,
            &["version", "tools", "prompts", "resource_templates"],
            "/",
        )?;
        let version = match o.get("version") {
            None => 1,
            Some(Value::Number(n)) if n.as_u64() == Some(1) => 1,
            Some(_) => return Err(ContractError::Version),
        };
        let mut c = Contract {
            version,
            ..Contract::default()
        };
        if let Some(tools) = o.get("tools") {
            let Value::Object(tools) = tools else {
                return Err(ContractError::Key("/tools".into()));
            };
            for (name, t) in tools {
                if !valid_static_name(name) {
                    return Err(ContractError::Key("/tools/<invalid name>".into()));
                }
                let Value::Object(t) = t else {
                    return Err(ContractError::Key(format!("/tools/{name}")));
                };
                check_keys(t, &["arguments", "result"], &format!("/tools/{name}/"))?;
                let arguments = match t.get("arguments") {
                    Some(v) => parse_rules(v, &format!("/tools/{name}/arguments"), parse_rule)?,
                    None => FieldRules::default(),
                };
                let result = match t.get("result") {
                    Some(v) => Some(parse_rules(
                        v,
                        &format!("/tools/{name}/result"),
                        parse_rule,
                    )?),
                    None => None,
                };
                c.tools
                    .insert(name.clone(), ToolContract { arguments, result });
            }
        }
        if let Some(prompts) = o.get("prompts") {
            let Value::Object(prompts) = prompts else {
                return Err(ContractError::Key("/prompts".into()));
            };
            for (name, p) in prompts {
                if !valid_static_name(name) {
                    return Err(ContractError::Key("/prompts/<invalid name>".into()));
                }
                let Value::Object(p) = p else {
                    return Err(ContractError::Key(format!("/prompts/{name}")));
                };
                check_keys(p, &["arguments"], &format!("/prompts/{name}/"))?;
                let arguments = match p.get("arguments") {
                    Some(v) => parse_rules(v, &format!("/prompts/{name}/arguments"), string_rule)?,
                    None => FieldRules::default(),
                };
                c.prompts.insert(name.clone(), PromptContract { arguments });
            }
        }
        if let Some(templates) = o.get("resource_templates") {
            let Value::Object(templates) = templates else {
                return Err(ContractError::Key("/resource_templates".into()));
            };
            // Template keys are URIs: errors name them by position only.
            for (i, (tpl, t)) in templates.iter().enumerate() {
                let Value::Object(t) = t else {
                    return Err(ContractError::Key(format!("/resource_templates/#{i}")));
                };
                check_keys(t, &["params"], &format!("/resource_templates/#{i}/"))?;
                let mut params = BTreeMap::new();
                match t.get("params") {
                    None => {}
                    Some(Value::Object(ps)) => {
                        for (name, rule) in ps {
                            if !valid_static_name(name) {
                                return Err(ContractError::Key(format!(
                                    "/resource_templates/#{i}/params/<invalid>"
                                )));
                            }
                            let at = format!("/resource_templates/#{i}/params/{name}");
                            params.insert(name.clone(), string_rule(rule, &at)?);
                        }
                    }
                    Some(_) => {
                        return Err(ContractError::Key(format!(
                            "/resource_templates/#{i}/params"
                        )));
                    }
                }
                c.templates.insert(tpl.clone(), TemplateContract { params });
            }
        }
        Ok(c)
    }

    /// Refuse the contract when it types a field as an identifier kind that
    /// `profile` blocks or removes (its per-kind or default action). A typed
    /// field is always tokenized, so it would release as a restorable token
    /// what the profile says must never leave or never come back. Call it
    /// with the dataset's profile whenever a contract is loaded or the
    /// dataset's profile changes.
    pub fn check_profile(&self, profile: &Profile) -> Result<(), ContractError> {
        let refused =
            |k: &EntityKind| matches!(profile.policy_for(k).action, Action::Block | Action::Remove);
        let check = |at: String, rule: &Rule| match identifier_kind(rule) {
            Some(k) if refused(k) => Err(ContractError::KindAction(at)),
            _ => Ok(()),
        };
        for (name, t) in &self.tools {
            for (ptr, rule) in t.arguments.iter() {
                check(
                    format!("/tools/{name}/arguments{}", show_pointer(ptr)),
                    rule,
                )?;
            }
            for (ptr, rule) in t.result.iter().flat_map(FieldRules::iter) {
                check(format!("/tools/{name}/result{}", show_pointer(ptr)), rule)?;
            }
        }
        for (name, p) in &self.prompts {
            for (ptr, rule) in p.arguments.iter() {
                check(
                    format!("/prompts/{name}/arguments{}", show_pointer(ptr)),
                    rule,
                )?;
            }
        }
        for (i, t) in self.templates.values().enumerate() {
            for (name, rule) in &t.params {
                check(format!("/resource_templates/#{i}/params/{name}"), rule)?;
            }
        }
        Ok(())
    }
}

/// RFC 6901 escaping of one key (`~` → `~0`, `/` → `~1`).
pub fn pointer_escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// `sha256:<hex>` over the schema-bearing parts of an upstream's lists:
/// tool names with input and output schemas, prompt names with argument
/// names, template URIs. Descriptions and titles are data, not schema,
/// and are left out.
pub fn schema_fingerprint(
    tools: &[Tool],
    prompts: &[Prompt],
    templates: &[ResourceTemplate],
) -> String {
    let mut t: Vec<Value> = tools
        .iter()
        .map(|t| {
            serde_json::json!({
                "name": t.name.as_ref(),
                "input": Value::Object(strip_descriptions(&t.input_schema)),
                "output": t.output_schema.as_ref().map(|s| Value::Object(strip_descriptions(s))),
            })
        })
        .collect();
    t.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    let mut p: Vec<Value> = prompts
        .iter()
        .map(|p| {
            let mut args: Vec<(String, bool)> = p
                .arguments
                .iter()
                .flatten()
                .map(|a| (a.name.clone(), a.required.unwrap_or(false)))
                .collect();
            args.sort();
            serde_json::json!({ "name": p.name, "args": args })
        })
        .collect();
    p.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    let mut u: Vec<&str> = templates.iter().map(|t| t.uri_template.as_str()).collect();
    u.sort_unstable();
    let canonical =
        serde_json::to_string(&serde_json::json!({ "tools": t, "prompts": p, "templates": u }))
            .unwrap_or_default();
    let hex: String = Sha256::digest(canonical.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("sha256:{hex}")
}

/// A schema without its `description`, `title`, and `examples` keywords at
/// any depth: prose an upstream may reword without changing the shape.
/// Property names are kept even when one is literally called `description`.
fn strip_descriptions(schema: &serde_json::Map<String, Value>) -> serde_json::Map<String, Value> {
    fn walk(v: &Value, in_schema: bool) -> Value {
        match v {
            Value::Object(o) => Value::Object(
                o.iter()
                    .filter(|(k, _)| {
                        !(in_schema && matches!(k.as_str(), "description" | "title" | "examples"))
                    })
                    .map(|(k, x)| {
                        // Under `properties`/`$defs`/`definitions` the keys
                        // are names and every value is a schema again.
                        let names = in_schema
                            && matches!(k.as_str(), "properties" | "$defs" | "definitions");
                        let child = if names {
                            match x {
                                Value::Object(m) => Value::Object(
                                    m.iter().map(|(n, s)| (n.clone(), walk(s, true))).collect(),
                                ),
                                other => walk(other, false),
                            }
                        } else {
                            walk(x, in_schema)
                        };
                        (k.clone(), child)
                    })
                    .collect(),
            ),
            Value::Array(a) => Value::Array(a.iter().map(|x| walk(x, in_schema)).collect()),
            other => other.clone(),
        }
    }
    match walk(&Value::Object(schema.clone()), true) {
        Value::Object(o) => o,
        _ => serde_json::Map::new(),
    }
}
