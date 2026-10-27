//! M4 spec §5.3 table and §13 field coverage: contracts, discovery
//! metadata, arguments, structured content, embedded resources, links,
//! errors. A fake `Blocks` stands in for the engine; Task 7 runs the same
//! walkers against the real daemon.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use inumaki_core::policy::{Action, EntityPolicy, Profile, VerifierSettings};
use inumaki_core::span::EntityKind;
use inumaki_core::verify::{CheckId, Reason};
use inumaki_gateway::aggregate::{RawLists, TemplateRoute};
use inumaki_gateway::content::{
    ContentError, blocked_text, rehydrate_arguments, rehydrate_prompt_arguments,
    rehydrate_template_params, sanitize_call_result, sanitize_prompt_result, sanitize_read_result,
    upstream_error, withheld_text,
};
use inumaki_gateway::contract::{
    Contract, ContractError, Rule, TemplateContract, schema_fingerprint,
};
use inumaki_gateway::discovery::{DiscoveryError, sanitize_lists};
use inumaki_gateway::handles::{HandleStore, Owner};
use inumaki_gateway::scripted::{IBAN, IDENTITY, ScriptedUpstream};
use inumaki_gateway::{BlockOutcome, BlockResult, Blocks, BlocksError, FieldHint, TextBlock};
use inumaki_vault::CheckLabel;
use rmcp::model::{
    CallToolResult, ContentBlock, EmbeddedResource, ErrorCode, ErrorData, GetPromptResult,
    MetaObject, Prompt, PromptArgument, PromptMessage, ReadResourceResult, Resource,
    ResourceContents, ResourceTemplate, Role, Tool,
};
use serde_json::{Value, json};

const NAME_TOKEN: &str = "<PERSON_aaaaaa>";
const IBAN_TOKEN: &str = "<IBAN_bbbbbb>";
const CID_TOKEN: &str = "<CUSTOMER_ID_cccccc>";

/// Replaces the canary name/IBAN/customer id with fixed tokens in free text; a typed
/// identifier block becomes `<KIND_cccccc>`; `BLOCKME` blocks, `MAYBE` is
/// uncertain. Strict restoration maps the three tokens back and fails on
/// any other `<…_…>`. The clear-value scan finds the canary name (any
/// case) as a known entity and the canary IBAN (any spacing).
#[derive(Default)]
struct Fake {
    calls: Mutex<usize>,
    seen: Mutex<Vec<Vec<TextBlock>>>,
    scans: Mutex<Vec<Vec<String>>>,
}

impl Blocks for Fake {
    fn sanitize_blocks(
        &self,
        _dataset: &str,
        blocks: Vec<TextBlock>,
    ) -> Result<Vec<BlockResult>, BlocksError> {
        *self.calls.lock().unwrap() += 1;
        self.seen.lock().unwrap().push(blocks.clone());
        // The daemon answers this for a handle it never minted; the fake
        // treats the two prefixes as minted.
        if blocks.iter().any(|b| {
            b.hint == FieldHint::Handle && !(b.text.starts_with("mm_") || b.text.starts_with("mf_"))
        }) {
            return Err(BlocksError::Unsupported("handle_provenance"));
        }
        Ok(blocks
            .into_iter()
            .map(|b| match b.hint {
                FieldHint::Handle => BlockResult {
                    outcome: BlockOutcome::Pass,
                    text: b.text,
                    replacements: 0,
                    kinds: vec![],
                    reasons: vec![],
                    cached: false,
                },
                FieldHint::Identifier(kind) => BlockResult {
                    outcome: BlockOutcome::Pass,
                    text: if b.text.is_empty() {
                        String::new()
                    } else {
                        format!("<{}_cccccc>", kind.label())
                    },
                    replacements: 1,
                    kinds: vec![kind],
                    reasons: vec![],
                    cached: false,
                },
                FieldHint::FreeText | FieldHint::Metadata => {
                    if b.text.contains("BLOCKME") {
                        return BlockResult {
                            outcome: BlockOutcome::Blocked,
                            text: String::new(),
                            replacements: 0,
                            kinds: vec![EntityKind::Person, EntityKind::Iban],
                            reasons: vec![Reason {
                                kind: EntityKind::Person,
                                check: CheckId::Leak,
                            }],
                            cached: false,
                        };
                    }
                    let text = b
                        .text
                        .replace(IDENTITY, NAME_TOKEN)
                        .replace(IBAN, IBAN_TOKEN)
                        .replace("8439271", CID_TOKEN);
                    let uncertain = b.text.contains("MAYBE");
                    BlockResult {
                        outcome: if uncertain {
                            BlockOutcome::PassUncertain
                        } else {
                            BlockOutcome::Pass
                        },
                        replacements: usize::from(text != b.text),
                        text,
                        kinds: vec![],
                        reasons: if uncertain {
                            vec![Reason {
                                kind: EntityKind::Date,
                                check: CheckId::Combination,
                            }]
                        } else {
                            vec![]
                        },
                        cached: false,
                    }
                }
            })
            .collect())
    }

    fn rehydrate_strict(
        &self,
        _dataset: &str,
        blocks: Vec<String>,
    ) -> Result<Vec<String>, BlocksError> {
        *self.calls.lock().unwrap() += 1;
        let mut unknown = 0;
        let out: Vec<String> = blocks
            .iter()
            .map(|b| {
                let t = b
                    .replace(NAME_TOKEN, IDENTITY)
                    .replace(IBAN_TOKEN, IBAN)
                    .replace(CID_TOKEN, "8439271");
                unknown += t.matches("<PERSON_").count()
                    + t.matches("<IBAN_").count()
                    + t.matches("<X_").count();
                t
            })
            .collect();
        if unknown > 0 {
            return Err(BlocksError::Unresolved {
                unknown,
                removed: 0,
            });
        }
        Ok(out)
    }

    fn profile(
        &self,
        _dataset: &str,
    ) -> Result<std::sync::Arc<inumaki_core::policy::Profile>, BlocksError> {
        Err(BlocksError::Internal("fake"))
    }

    fn scan_clear(
        &self,
        _dataset: &str,
        texts: &[String],
    ) -> Result<Vec<(String, u32)>, BlocksError> {
        self.scans.lock().unwrap().push(texts.to_vec());
        let iban = IBAN.replace(' ', "");
        let mut found = Vec::new();
        for t in texts {
            if t.to_lowercase().contains(&IDENTITY.to_lowercase()) {
                found.push(("PERSON".to_string(), 1));
            }
            if t.replace(' ', "").contains(&iban) {
                found.push(("IBAN".to_string(), 1));
            }
        }
        Ok(found)
    }
}

fn obj(v: serde_json::Value) -> rmcp::model::JsonObject {
    v.as_object().cloned().unwrap()
}

fn texts(r: &CallToolResult) -> Vec<String> {
    r.content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect()
}

fn owner() -> Owner {
    Owner::new("a", 1)
}

const POLICY: &str = include_str!("../../../docs/examples/scripted-upstream.policy.json");

#[test]
fn contract_parses_the_reference_policy_and_rejects_bad_ones() {
    let c = Contract::parse(POLICY).unwrap();
    assert_eq!(c.version, 1);
    let record = &c.tools["record"];
    let result = record.result.as_ref().unwrap();
    assert_eq!(
        result.get("/customer/id"),
        Some(&Rule::Identifier(EntityKind::CustomerId))
    );
    assert_eq!(result.get("/customer/count"), Some(&Rule::Quantity));
    assert_eq!(result.get("/customer/tags/*"), Some(&Rule::FreeText));
    assert!(result.has_prefix("/customer"));
    assert!(!result.has_prefix("/other"));
    assert_eq!(
        c.tools["dynamic"].result.as_ref().unwrap().get("/by_name"),
        Some(&Rule::Map(Box::new(Rule::Quantity)))
    );
    assert_eq!(
        c.tools["lookup"].arguments.get("/customer_id"),
        Some(&Rule::Identifier(EntityKind::CustomerId))
    );
    assert_eq!(
        c.prompts["greet"].arguments.get("/name"),
        Some(&Rule::FreeText)
    );
    assert_eq!(c.templates["mem://note/{id}"].params["id"], Rule::FreeText);
    assert!(Contract::parse("{}").unwrap().tools.is_empty());
    assert_eq!(Contract::parse("[]"), Err(ContractError::Json));
    assert_eq!(
        Contract::parse("{\"version\":2}"),
        Err(ContractError::Version)
    );
    assert!(matches!(
        Contract::parse("{\"bogus\":1}"),
        Err(ContractError::Key(_))
    ));
    assert!(matches!(
        Contract::parse("{\"tools\":{\"t\":{\"result\":{\"no-slash\":\"free_text\"}}}}"),
        Err(ContractError::Pointer(_))
    ));
    assert!(matches!(
        Contract::parse("{\"tools\":{\"t\":{\"result\":{\"/a\":\"loud\"}}}}"),
        Err(ContractError::Rule(_))
    ));
    assert!(matches!(
        Contract::parse(
            "{\"tools\":{\"t\":{\"result\":{\"/a\":{\"identifier\":\"not a label\"}}}}}"
        ),
        Err(ContractError::Kind(_))
    ));
    // no digits: a kind label cannot carry a number (M4 spec §16.4)
    assert!(matches!(
        Contract::parse("{\"tools\":{\"t\":{\"result\":{\"/a\":{\"identifier\":\"IBAN_AT61\"}}}}}"),
        Err(ContractError::Kind(_))
    ));
    assert!(matches!(
        Contract::parse("{\"tools\":{\"Bad Name\":{}}}"),
        Err(ContractError::Key(_))
    ));
    // a secret is removed and never restored, so it is never a typed token
    assert!(matches!(
        Contract::parse("{\"tools\":{\"t\":{\"result\":{\"/a\":{\"identifier\":\"SECRET\"}}}}}"),
        Err(ContractError::Kind(_))
    ));
    // template parameters and prompt arguments are strings: no quantity, no map
    assert!(matches!(
        Contract::parse(
            "{\"resource_templates\":{\"mem://x/{id}\":{\"params\":{\"id\":\"quantity\"}}}}"
        ),
        Err(ContractError::Rule(_))
    ));
    let e = Contract::parse(&format!(
        "{{\"resource_templates\":{{\"mem://customer/{IDENTITY}/{{id}}\":{{\"params\":[]}}}}}}"
    ))
    .unwrap_err();
    assert!(matches!(e, ContractError::Key(_)), "{e:?}");
    assert!(
        !e.to_string().contains("Zyxwuria"),
        "a template is named by position: {e}"
    );
    let e = Contract::parse(&format!("{{\"tools\":{{\"{IDENTITY}\":{{}}}}}}")).unwrap_err();
    assert!(
        !e.to_string().contains("Zyxwuria"),
        "an invalid name is not repeated: {e}"
    );
    assert!(matches!(
        Contract::parse("{\"prompts\":{\"p\":{\"arguments\":{\"/n\":{\"map\":\"free_text\"}}}}}"),
        Err(ContractError::Rule(_))
    ));
}

/// A policy error names only what it can show safely: a pointer segment,
/// key, or template parameter that is not a static name may be a data
/// value and is shown as `<invalid>`.
#[test]
fn contract_errors_never_echo_data_like_policy_strings() {
    let cases = [
        format!("{{\"{IDENTITY}\":1}}"),
        format!("{{\"tools\":{{\"t\":{{\"{IDENTITY}\":{{}}}}}}}}"),
        format!("{{\"tools\":{{\"t\":{{\"result\":{{\"{IDENTITY}\":\"free_text\"}}}}}}}}"),
        format!("{{\"tools\":{{\"t\":{{\"result\":{{\"/by_name/{IDENTITY}\":\"loud\"}}}}}}}}"),
        format!(
            "{{\"tools\":{{\"t\":{{\"result\":{{\"/by_name/{IDENTITY}\":{{\"identifier\":\"x\"}}}}}}}}}}"
        ),
        format!(
            "{{\"resource_templates\":{{\"mem://x/{{id}}\":{{\"params\":{{\"{IDENTITY}\":\"free_text\"}}}}}}}}"
        ),
    ];
    for json in &cases {
        let e = Contract::parse(json).unwrap_err();
        let shown = format!("{e} {e:?}");
        assert!(!shown.contains("Zyxwuria"), "{shown}");
        assert!(shown.contains("<invalid>"), "{shown}");
    }
    let c = Contract::parse(&format!(
        "{{\"tools\":{{\"t\":{{\"result\":{{\"/by_name/{IDENTITY}\":{{\"identifier\":\"IBAN\"}}}}}}}}}}"
    ))
    .unwrap();
    let e = c
        .check_profile(&profile("IBAN", Action::Block))
        .unwrap_err();
    assert!(!format!("{e} {e:?}").contains("Zyxwuria"), "{e}");
    assert_eq!(
        e,
        ContractError::KindAction("/tools/t/result/by_name/<invalid>".into())
    );
}

fn profile(kind: &str, action: Action) -> Profile {
    let mut entities = HashMap::new();
    entities.insert(
        kind.to_string(),
        EntityPolicy {
            action,
            min_confidence: 0.5,
        },
    );
    Profile {
        name: "p".into(),
        language: None,
        entities,
        default: EntityPolicy {
            action: Action::Tokenize,
            min_confidence: 0.5,
        },
        escalate_below: 0.3,
        verifier: VerifierSettings::default(),
        ner_sanitizer: None,
        ner_verifier: None,
    }
}

/// Task 3 review: a typed identifier block always tokenizes, so a contract
/// must not type a field as a kind the dataset's profile blocks or removes.
#[test]
fn contract_refuses_identifier_kinds_the_profile_blocks_or_removes() {
    let c = Contract::parse(POLICY).unwrap();
    assert!(
        c.check_profile(&profile("CUSTOMER_ID", Action::Tokenize))
            .is_ok()
    );
    assert!(
        c.check_profile(&profile("CUSTOMER_ID", Action::Preserve))
            .is_ok(),
        "tokenizing is stricter than preserving"
    );
    for action in [Action::Block, Action::Remove] {
        match c.check_profile(&profile("CUSTOMER_ID", action)) {
            Err(ContractError::KindAction(at)) => {
                assert!(
                    at.contains("CUSTOMER_ID") || at.starts_with("/tools/"),
                    "{at}"
                )
            }
            other => panic!("{action:?}: {other:?}"),
        }
    }
    // inside a map rule and in a template parameter too
    let m = Contract::parse(
        "{\"tools\":{\"t\":{\"result\":{\"/m\":{\"map\":{\"identifier\":\"IBAN\"}}}}}}",
    )
    .unwrap();
    assert!(matches!(
        m.check_profile(&profile("IBAN", Action::Block)),
        Err(ContractError::KindAction(_))
    ));
    let t = Contract::parse(
        "{\"resource_templates\":{\"mem://x/{id}\":{\"params\":{\"id\":{\"identifier\":\"PERSON\"}}}}}",
    )
    .unwrap();
    assert!(matches!(
        t.check_profile(&profile("PERSON", Action::Remove)),
        Err(ContractError::KindAction(_))
    ));
    // the default policy counts for unlisted kinds
    let mut p = profile("PERSON", Action::Tokenize);
    p.default.action = Action::Block;
    assert!(matches!(
        c.check_profile(&p),
        Err(ContractError::KindAction(_))
    ));
}

#[test]
fn schema_fingerprint_is_stable_and_sensitive() {
    let mk = |desc: &str| {
        Tool::new(
            "a",
            desc.to_string(),
            obj(json!({ "type": "object", "properties": { "q": { "type": "string" } } })),
        )
    };
    let p = Prompt::new("greet", Some("g"), Some(vec![PromptArgument::new("name")]));
    let t = ResourceTemplate::new("mem://note/{id}", "n");
    let a = schema_fingerprint(
        &[mk("one")],
        std::slice::from_ref(&p),
        std::slice::from_ref(&t),
    );
    assert!(a.starts_with("sha256:") && a.len() == 7 + 64);
    assert_eq!(
        a,
        schema_fingerprint(
            &[mk("other description")],
            std::slice::from_ref(&p),
            std::slice::from_ref(&t)
        ),
        "descriptions are not part of the schema"
    );
    let changed = Tool::new(
        "a",
        "one",
        obj(json!({ "type": "object", "properties": { "q": { "type": "integer" } } })),
    );
    assert_ne!(
        a,
        schema_fingerprint(
            &[changed],
            std::slice::from_ref(&p),
            std::slice::from_ref(&t)
        )
    );
    let reworded = Tool::new(
        "a",
        "one",
        obj(
            json!({ "type": "object", "description": "prose", "properties": { "q": { "type": "string", "title": "Q", "examples": ["x"] } } }),
        ),
    );
    assert_eq!(
        a,
        schema_fingerprint(
            &[reworded],
            std::slice::from_ref(&p),
            std::slice::from_ref(&t)
        ),
        "nested prose is not schema either"
    );
    let renamed = Tool::new(
        "a",
        "one",
        obj(json!({ "type": "object", "properties": { "description": { "type": "string" } } })),
    );
    assert_ne!(
        a,
        schema_fingerprint(
            &[renamed],
            std::slice::from_ref(&p),
            std::slice::from_ref(&t)
        ),
        "a property named description is schema"
    );
    assert_ne!(a, schema_fingerprint(&[mk("one")], &[], &[t]));
}

fn raw_scripted() -> RawLists {
    // The scripted server's lists, without running it: mirror its shapes.
    let mut record = Tool::new(
        "record",
        format!("the customer record of {IDENTITY}"),
        obj(json!({ "type": "object", "properties": {} })),
    );
    record.output_schema = Some(Arc::new(obj(
        json!({ "type": "object", "properties": { "customer": { "type": "object", "properties": { "id": { "type": "integer", "description": "customer number" }, "name": { "type": "string" } } } } }),
    )));
    RawLists {
        tools: vec![
            Tool::new(
                "echo",
                "echo the query",
                obj(
                    json!({ "type": "object", "properties": { "query": { "type": "string", "description": "free text", "examples": ["hi", IDENTITY], "default": 3, "x-vendor": "drop me" } }, "required": ["query"] }),
                ),
            ),
            record,
            Tool::new(
                "lookup",
                "look up",
                obj(
                    json!({ "type": "object", "properties": { "customer_id": { "type": "integer" } } }),
                ),
            ),
        ],
        prompts: vec![Prompt::new(
            "greet",
            Some(format!("greet {IDENTITY}")),
            Some(vec![PromptArgument::new("name")]),
        )],
        resources: vec![
            Resource::new(
                format!("mem://customer/{IDENTITY}"),
                format!("record of {IDENTITY}"),
            )
            .with_description(format!("IBAN {IBAN}"))
            .with_mime_type("text/plain")
            .with_size(12)
            .with_meta(MetaObject(obj(json!({ "who": IDENTITY })))),
        ],
        templates: vec![
            ResourceTemplate::new("mem://note/{id}", "note"),
            ResourceTemplate::new("mem://secret/{who}", "unlisted"),
        ],
    }
}

#[test]
fn discovery_sanitizes_metadata_hides_uris_rewrites_identifier_types_and_drops_extensions() {
    let f = Fake::default();
    let c = Contract::parse(POLICY).unwrap();
    let mut handles = HandleStore::new();
    let lists = sanitize_lists(&f, "mail", &owner(), 0, &raw_scripted(), &c, &mut handles).unwrap();
    assert_eq!(*f.calls.lock().unwrap(), 1, "one batch for all metadata");
    assert_eq!(lists.name, "a");
    let echo = &lists.tools[0];
    let q = &echo.input_schema["properties"]["query"];
    assert_eq!(q["examples"], json!(["hi", NAME_TOKEN]));
    assert!(q.get("default").is_none(), "non-string default dropped");
    assert!(q.get("x-vendor").is_none(), "extension stripped");
    assert_eq!(q["description"], "free text");
    assert_eq!(echo.input_schema["required"], json!(["query"]));
    let record = &lists.tools[1];
    assert_eq!(
        record.description.as_deref(),
        Some(format!("the customer record of {NAME_TOKEN}").as_str())
    );
    let out = record.output_schema.as_ref().unwrap();
    assert_eq!(
        out["properties"]["customer"]["properties"]["id"]["type"], "string",
        "identifier fields are exposed as strings"
    );
    let lookup = &lists.tools[2];
    assert_eq!(
        lookup.input_schema["properties"]["customer_id"]["type"],
        "string"
    );
    assert_eq!(
        lists.prompts[0].description.as_deref(),
        Some(format!("greet {NAME_TOKEN}").as_str())
    );
    let (r, original) = &lists.resources[0];
    assert!(r.uri.starts_with("inumaki://res/"), "{}", r.uri);
    assert_eq!(original, &format!("mem://customer/{IDENTITY}"));
    assert_eq!(r.name, format!("record of {NAME_TOKEN}"));
    assert_eq!(
        r.description.as_deref(),
        Some(format!("IBAN {IBAN_TOKEN}").as_str())
    );
    assert!(r.meta.is_none() && r.icons.is_none());
    assert_eq!(r.size, Some(12));
    assert_eq!(lists.templates.len(), 1, "unlisted template omitted");
    let (t, route) = &lists.templates[0];
    assert!(
        t.uri_template.starts_with("inumaki://tpl/") && t.uri_template.ends_with("/{id}"),
        "{}",
        t.uri_template
    );
    assert_eq!(route.original, "mem://note/{id}");
    assert_eq!(route.params, ["id"]);
    assert_eq!(
        handles.resolve_resource(&r.uri).unwrap().1,
        format!("mem://customer/{IDENTITY}")
    );
    let whole = serde_json::to_string(&lists.tools).unwrap()
        + &serde_json::to_string(&lists.resources.iter().map(|(r, _)| r).collect::<Vec<_>>())
            .unwrap();
    assert!(
        !whole.contains("Zyxwuria") && !whole.contains("AT61"),
        "{whole}"
    );
}

/// Final review, finding 1: every exposed name (tools, prompts, prompt
/// arguments, schema properties, definitions, `required` entries, template
/// parameters) goes through one clear-value scan per listing, as written and
/// split into words; a known entity or a validated identifier in any of them
/// fails the whole listing with class `name`, and nothing names it.
#[test]
fn names_with_known_entities_or_identifiers_fail_the_listing() {
    let f = Fake::default();
    let c = Contract::parse(POLICY).unwrap();
    let lists =
        |raw: &RawLists| sanitize_lists(&f, "mail", &owner(), 0, raw, &c, &mut HandleStore::new());
    // Ordinary names pass, in one scan for the whole listing.
    lists(&raw_scripted()).unwrap();
    {
        let scans = f.scans.lock().unwrap();
        assert_eq!(scans.len(), 1, "one scan per listing");
        for n in [
            "echo",
            "record",
            "customer",
            "customer_id",
            "greet",
            "name",
            "id",
        ] {
            assert!(scans[0].iter().any(|t| t == n), "{n} not scanned");
        }
    }
    let fails = |raw: &RawLists| {
        let e = lists(raw).unwrap_err();
        assert!(matches!(e, DiscoveryError::Unsupported("name")), "{e:?}");
        let d = format!("{e} {e:?}").to_lowercase();
        assert!(!d.contains("zyxwuria") && !d.contains("at61"), "{d}");
    };
    // A tool the contract does not name, named after a record.
    let mut raw = raw_scripted();
    raw.tools.push(Tool::new(
        "Zyxwuria_Quolnath_orders",
        "orders",
        obj(json!({})),
    ));
    fails(&raw);
    // A schema property named after a person, dotted and camel-cased.
    for prop in ["zyxwuria.quolnath", "ZyxwuriaQuolnath"] {
        let mut raw = raw_scripted();
        raw.tools[0].input_schema = Arc::new(obj(
            json!({ "type": "object", "properties": { "query": { "type": "string" }, prop: { "type": "string" } } }),
        ));
        fails(&raw);
    }
    // An IBAN-shaped property name, compact and with separators.
    for prop in ["AT611904300234573201", "AT61_1904_3002_3457_3201"] {
        let mut raw = raw_scripted();
        raw.tools[0].input_schema = Arc::new(obj(
            json!({ "type": "object", "properties": { "query": { "type": "string" }, prop: { "type": "string" } } }),
        ));
        fails(&raw);
    }
    // A `required` entry, a definition name, and a prompt argument.
    let mut raw = raw_scripted();
    raw.tools[0].input_schema = Arc::new(obj(
        json!({ "type": "object", "properties": { "query": { "type": "string" } }, "required": ["query", "Zyxwuria-Quolnath"] }),
    ));
    fails(&raw);
    let mut raw = raw_scripted();
    raw.tools[0].input_schema = Arc::new(obj(
        json!({ "type": "object", "properties": { "query": { "type": "string" } }, "$defs": { "Zyxwuria_Quolnath": { "type": "string" } } }),
    ));
    fails(&raw);
    let mut raw = raw_scripted();
    raw.prompts.push(Prompt::new(
        "notes",
        Some("notes"),
        Some(vec![PromptArgument::new("zyxwuria_quolnath")]),
    ));
    fails(&raw);
}

/// Review Focus 2.
#[test]
fn blocked_description_fails_the_listing() {
    let f = Fake::default();
    let c = Contract::empty();
    let lists =
        |raw: &RawLists| sanitize_lists(&f, "mail", &owner(), 0, raw, &c, &mut HandleStore::new());
    let mut raw = raw_scripted();
    raw.tools
        .push(Tool::new("bad", "BLOCKME account", obj(json!({}))));
    let e = lists(&raw).unwrap_err();
    assert!(
        matches!(e, DiscoveryError::Unsupported("blocked_metadata")),
        "{e:?}"
    );
    let mut raw = raw_scripted();
    raw.tools
        .push(Tool::new("Zyxwuria Quolnath", "spaces", obj(json!({}))));
    assert!(matches!(
        lists(&raw).unwrap_err(),
        DiscoveryError::Unsupported("tool_name")
    ));
    let mut raw = raw_scripted();
    raw.tools[0].input_schema = Arc::new(obj(
        json!({ "type": "object", "properties": { "q": { "$ref": "https://evil.example/schema" } } }),
    ));
    assert!(matches!(
        lists(&raw).unwrap_err(),
        DiscoveryError::Unsupported("ref")
    ));
    let mut raw = raw_scripted();
    raw.tools[0].input_schema = Arc::new(obj(
        json!({ "type": "object", "properties": { "q": { "type": "string", "enum": ["a", IDENTITY] } } }),
    ));
    assert!(
        matches!(
            lists(&raw).unwrap_err(),
            DiscoveryError::Unsupported("enum")
        ),
        "an enum value that sanitizes to something else is data"
    );
    let mut raw = raw_scripted();
    raw.tools[0].input_schema = Arc::new(obj(
        json!({ "type": "object", "properties": { "q": { "type": "string", "enum": ["a", "b"] } } }),
    ));
    assert!(lists(&raw).is_ok(), "static enums pass");
    let mut raw = raw_scripted();
    raw.tools[0].description = Some("MAYBE".into());
    assert!(matches!(
        lists(&raw).unwrap_err(),
        DiscoveryError::Unsupported("uncertain_metadata")
    ));
    // a blocked prompt description and a blocked resource name fail the
    // whole listing the same way, and the error carries no text
    let mut raw = raw_scripted();
    raw.prompts[0].description = Some(format!("BLOCKME {IDENTITY}"));
    let e = lists(&raw).unwrap_err();
    assert!(
        matches!(e, DiscoveryError::Unsupported("blocked_metadata")),
        "{e:?}"
    );
    assert!(!format!("{e:?} {e}").contains("Zyxwuria"));
    let mut raw = raw_scripted();
    raw.resources[0].name = format!("BLOCKME {IDENTITY}");
    let e = lists(&raw).unwrap_err();
    assert!(
        matches!(e, DiscoveryError::Unsupported("blocked_metadata")),
        "{e:?}"
    );
    assert!(!format!("{e:?} {e}").contains("Zyxwuria"));
}

/// An identifier field exposes no sample of its raw value: a string
/// `default`/`examples`/`enum` would reach the agent as free text that no
/// detector recognizes as an identifier.
#[test]
fn identifier_fields_expose_no_sample_values() {
    let f = Fake::default();
    let c = Contract::parse(POLICY).unwrap();
    let raw = RawLists {
        tools: vec![Tool::new(
            "lookup",
            "look up",
            obj(json!({ "type": "object", "properties": {
                "customer_id": { "type": "string", "default": "8439271", "examples": ["8439271"], "enum": ["8439271"], "const": "8439271", "description": "the number" },
                "note": { "type": "string", "default": "8439271" } } })),
        )],
        ..RawLists::default()
    };
    let lists = sanitize_lists(&f, "mail", &owner(), 0, &raw, &c, &mut HandleStore::new()).unwrap();
    let id = &lists.tools[0].input_schema["properties"]["customer_id"];
    assert_eq!(id["type"], "string");
    assert_eq!(id["description"], "the number");
    for k in ["default", "examples", "enum", "const"] {
        assert!(id.get(k).is_none(), "{k}");
    }
    let whole = serde_json::to_string(&lists.tools).unwrap();
    assert!(!whole.contains("8439271"), "{whole}");
}

/// An identifier node is exposed as a plain `{"type": "string"}` with its
/// prose sanitized: no `$ref`, combinators, constraints, or samples. A
/// definition it reaches through `$ref` (transitively) loses its samples;
/// other definitions keep theirs.
#[test]
fn identifier_nodes_are_plain_strings_and_their_definitions_lose_samples() {
    let f = Fake::default();
    let c = Contract::parse(POLICY).unwrap();
    let expose = |schema: serde_json::Value| {
        let raw = RawLists {
            tools: vec![Tool::new("lookup", "look up", obj(schema))],
            ..RawLists::default()
        };
        sanitize_lists(&f, "mail", &owner(), 0, &raw, &c, &mut HandleStore::new())
            .map(|l| l.tools[0].input_schema.clone())
    };
    // the reviewed shape: a $ref to a definition with a string default
    let schema = expose(json!({ "type": "object",
        "$defs": { "Cid": { "type": "string", "default": "8439271" } },
        "properties": { "customer_id": { "$ref": "#/$defs/Cid" } } }))
    .unwrap();
    assert_eq!(
        schema["properties"]["customer_id"],
        json!({ "type": "string" })
    );
    let whole = serde_json::to_string(&*schema).unwrap();
    assert!(!whole.contains("8439271"), "{whole}");
    // transitively, through a combinator, with a numeric enum; an unrelated
    // definition keeps its enum
    let schema = expose(json!({ "type": "object",
        "$defs": {
            "Cid": { "anyOf": [{ "$ref": "#/$defs/Inner" }, { "type": "null" }], "examples": ["8439271"] },
            "Inner": { "type": "integer", "enum": [8439271], "const": 8439271 },
            "Mode": { "type": "string", "enum": ["fast", "slow"] } },
        "properties": {
            "customer_id": { "$ref": "#/$defs/Cid", "description": "the number" },
            "note": { "$ref": "#/$defs/Mode" } } }))
    .unwrap();
    assert_eq!(
        schema["properties"]["customer_id"],
        json!({ "type": "string", "description": "the number" })
    );
    let whole = serde_json::to_string(&*schema).unwrap();
    assert!(!whole.contains("8439271"), "{whole}");
    assert_eq!(schema["$defs"]["Mode"]["enum"], json!(["fast", "slow"]));
    // Pydantic Optional[int]: exposed as a plain string, restored as an integer
    let upstream = obj(json!({ "type": "object", "properties": {
        "customer_id": { "anyOf": [{ "type": "integer" }, { "type": "null" }], "default": null, "title": "Customer Id" } } }));
    let schema = expose(Value::Object(upstream.clone())).unwrap();
    assert_eq!(
        schema["properties"]["customer_id"],
        json!({ "type": "string", "title": "Customer Id" })
    );
    let out = rehydrate_arguments(
        &f,
        "mail",
        c.tools.get("lookup"),
        &upstream,
        Some(obj(json!({ "customer_id": CID_TOKEN }))),
    )
    .unwrap()
    .unwrap();
    assert_eq!(out["customer_id"], json!(8439271));
}

/// Plan 2c: a Pydantic nested model behind `$ref` on the way to an
/// identifier rule is inlined where the field is (an `allOf` branch), so
/// the rule matches, the field is a plain string, and the definition loses
/// its samples. A rule the model does not satisfy, a dangling reference,
/// and a reference cycle at one data pointer still fail the listing;
/// arguments under `Optional[Model]` are still refused.
#[test]
fn identifier_rules_reach_nested_models_through_local_refs() {
    let f = Fake::default();
    let c = Contract::parse(
        "{\"tools\":{\"t\":{\"arguments\":{\"/customer/id\":{\"identifier\":\"CUSTOMER_ID\"}},\"result\":{\"/customer/id\":{\"identifier\":\"CUSTOMER_ID\"}}}}}",
    )
    .unwrap();
    let nested = json!({ "type": "object",
        "$defs": { "Customer": { "type": "object", "properties": {
            "id": { "type": "integer", "default": "8439271", "examples": ["8439271"] } } } },
        "properties": { "customer": { "$ref": "#/$defs/Customer" } } });
    let direct = json!({ "type": "object", "properties": { "customer": { "type": "object", "properties": {
        "id": { "type": "integer", "default": "8439271" } } } } });
    let list = |input: serde_json::Value, output: Option<serde_json::Value>| {
        let mut t = Tool::new("t", "d", obj(input));
        t.output_schema = output.map(|o| Arc::new(obj(o)));
        let raw = RawLists {
            tools: vec![t],
            ..RawLists::default()
        };
        sanitize_lists(&f, "mail", &owner(), 0, &raw, &c, &mut HandleStore::new())
    };
    let lists = list(nested.clone(), Some(nested.clone())).unwrap();
    let t = &lists.tools[0];
    assert_eq!(
        t.input_schema["properties"]["customer"]["allOf"][0]["properties"]["id"],
        json!({ "type": "string" })
    );
    assert_eq!(
        t.output_schema.as_ref().unwrap()["properties"]["customer"]["allOf"][0]["properties"]["id"],
        json!({ "type": "string" })
    );
    assert!(!serde_json::to_string(t).unwrap().contains("8439271"));
    assert!(cid_hints_sent(&f).is_empty(), "{:?}", cid_hints_sent(&f));
    // the argument side reaches the same field and restores its type
    let out = rehydrate_arguments(
        &f,
        "mail",
        c.tools.get("t"),
        &obj(nested.clone()),
        Some(obj(json!({ "customer": { "id": CID_TOKEN } }))),
    )
    .unwrap()
    .unwrap();
    assert_eq!(out["customer"]["id"], json!(8439271));
    for (input, class) in [
        (
            json!({ "type": "object", "$defs": { "Customer": { "type": "object", "properties": { "name": { "type": "string" } } } },
                "properties": { "customer": { "$ref": "#/$defs/Customer" } } }),
            "schema",
        ),
        (
            json!({ "type": "object", "properties": { "customer": { "$ref": "#/$defs/Missing" } } }),
            "ref",
        ),
        (
            json!({ "type": "object", "$defs": { "A": { "$ref": "#/$defs/B" }, "B": { "$ref": "#/$defs/A" } },
                "properties": { "customer": { "$ref": "#/$defs/A" } } }),
            "ref",
        ),
    ] {
        let e = list(input, None).unwrap_err();
        assert!(
            matches!(e, DiscoveryError::Unsupported(x) if x == class),
            "{class}: {e:?}"
        );
    }
    // Optional[Customer] (`anyOf: [$ref, null]`) lists the same way, one
    // level down; a call with arguments under it is refused
    // (`argument_key`): the argument walk follows `properties` through
    // `$ref` but not through combinators. A known fail-closed limit.
    let optional = json!({ "type": "object",
        "$defs": { "Customer": { "type": "object", "properties": {
            "id": { "type": "integer", "default": "8439271" } } } },
        "properties": { "customer": { "anyOf": [{ "$ref": "#/$defs/Customer" }, { "type": "null" }] } } });
    let lists = list(optional.clone(), None).unwrap();
    assert_eq!(
        lists.tools[0].input_schema["properties"]["customer"]["anyOf"][0]["allOf"][0]["properties"]
            ["id"],
        json!({ "type": "string" })
    );
    assert!(
        !serde_json::to_string(&lists.tools[0])
            .unwrap()
            .contains("8439271")
    );
    assert!(matches!(
        rehydrate_arguments(
            &f,
            "mail",
            c.tools.get("t"),
            &obj(optional),
            Some(obj(json!({ "customer": { "id": CID_TOKEN } }))),
        ),
        Err(ContentError::Unsupported("argument_key"))
    ));
    // described both directly and through a combinator reference: the
    // rule matches, and the referenced definition loses its samples too
    let mixed = json!({ "type": "object",
        "$defs": { "Customer": { "type": "object", "properties": {
            "id": { "type": "integer", "default": "8439271" } } } },
        "properties": { "customer": { "type": "object",
            "properties": { "id": { "type": "integer" } },
            "allOf": [{ "$ref": "#/$defs/Customer" }] } } });
    let lists = list(mixed, None).unwrap();
    assert!(
        !serde_json::to_string(&lists.tools[0])
            .unwrap()
            .contains("8439271")
    );
    let lists = list(direct, None).unwrap();
    assert_eq!(
        lists.tools[0].input_schema["properties"]["customer"]["properties"]["id"],
        json!({ "type": "string" })
    );
}

/// Plan 2c: Pydantic's `discriminator` (a static `propertyName`, a
/// `mapping` from static values to local references) is checked and
/// stripped from the exposed schema; any other shape fails the listing.
#[test]
fn pydantic_discriminators_are_checked_and_stripped() {
    let f = Fake::default();
    let union = |disc: Value| {
        json!({ "type": "object",
            "$defs": {
                "Cat": { "type": "object", "properties": { "kind": { "const": "cat" }, "lives": { "type": "integer" } } },
                "Dog": { "type": "object", "properties": { "kind": { "const": "dog" }, "good": { "type": "boolean" } } } },
            "properties": { "pet": {
                "oneOf": [{ "$ref": "#/$defs/Cat" }, { "$ref": "#/$defs/Dog" }],
                "discriminator": disc } } })
    };
    let schema = expose_under(
        &f,
        "{}",
        union(json!({ "propertyName": "kind", "mapping": { "cat": "#/$defs/Cat", "dog": "#/$defs/Dog" } })),
    )
    .unwrap();
    assert!(
        schema["properties"]["pet"].get("discriminator").is_none(),
        "{schema}"
    );
    assert_eq!(
        schema["properties"]["pet"]["oneOf"][0],
        json!({ "$ref": "#/$defs/Cat" })
    );
    expose_under(&f, "{}", union(json!({ "propertyName": "kind" }))).unwrap();
    for bad in [
        json!({ "propertyName": "the kind" }),
        json!({}),
        json!("kind"),
        json!({ "propertyName": "kind", "mapping": { "cat": "https://example.com/s#/$defs/Cat" } }),
        json!({ "propertyName": "kind", "mapping": { "cat": { "$ref": "#/$defs/Cat" } } }),
        json!({ "propertyName": "kind", "mapping": { "a cat": "#/$defs/Cat" } }),
        json!({ "propertyName": "kind", "x-extra": { "properties": {} } }),
    ] {
        let e = expose_under(&f, "{}", union(bad.clone())).unwrap_err();
        assert!(
            matches!(e, DiscoveryError::Unsupported("schema")),
            "{bad}: {e:?}"
        );
    }
}

/// A reference under an identifier node must be a plain local JSON
/// pointer that resolves; an anchor or a percent-encoded pointer could hide
/// the definition whose samples must be dropped.
#[test]
fn identifier_references_must_resolve_as_local_pointers() {
    let f = Fake::default();
    let c = lookup_contract();
    for r in [
        "#Cid",
        "#/%24defs/Cid",
        "#/$defs/Missing",
        "https://example.test/cid",
    ] {
        let raw = RawLists {
            tools: vec![Tool::new(
                "lookup",
                "look up",
                obj(json!({ "type": "object",
                    "$defs": { "Cid": { "$anchor": "Cid", "type": "string", "default": "8439271" } },
                    "properties": { "customer_id": { "$ref": r } } })),
            )],
            ..RawLists::default()
        };
        let e =
            sanitize_lists(&f, "mail", &owner(), 0, &raw, &c, &mut HandleStore::new()).unwrap_err();
        assert!(
            matches!(e, DiscoveryError::Unsupported("ref")),
            "{r}: {e:?}"
        );
        assert!(!format!("{e:?} {e}").contains("8439271"));
    }
}

/// Plan 2c final review: a wide reference DAG on the way to an identifier
/// rule is refused with the same `ref` class as a dangling reference or a
/// cycle, but for a different reason (`MAX_INLINED`). Seven levels
/// (`D0` through `D6`), each two identical, always-resolving `$ref`s to
/// the next level, would take 2^7 = 128 inline attempts to fully reach the
/// terminal `D7`; the walk hits the 64-attempt cap first, before any
/// dangling or cyclic reference is in play.
#[test]
fn wide_reference_dag_trips_max_inlined() {
    let f = Fake::default();
    let mut defs = serde_json::Map::new();
    for n in 0..7 {
        defs.insert(
            format!("D{n}"),
            json!({ "allOf": [
                { "$ref": format!("#/$defs/D{}", n + 1) },
                { "$ref": format!("#/$defs/D{}", n + 1) },
            ] }),
        );
    }
    defs.insert(
        "D7".to_string(),
        json!({ "type": "object", "properties": { "id": { "type": "integer" } } }),
    );
    let schema = json!({ "type": "object",
        "$defs": Value::Object(defs),
        "properties": { "customer": { "$ref": "#/$defs/D0" } } });
    let e = expose_under(&f, CUSTOMER_ID_FIELD, schema).unwrap_err();
    assert!(matches!(e, DiscoveryError::Unsupported("ref")), "{e:?}");
}

/// A `map` rule's identifier values follow the same exposure and
/// restoration as a named identifier field.
#[test]
fn identifier_values_under_a_map_rule_are_plain_strings() {
    let f = Fake::default();
    let c = Contract::parse(
        "{\"tools\":{\"t\":{\"arguments\":{\"/by\":{\"map\":{\"identifier\":\"CUSTOMER_ID\"}}}}}}",
    )
    .unwrap();
    let upstream = obj(
        json!({ "type": "object", "properties": { "by": { "type": "object",
        "additionalProperties": { "anyOf": [{ "type": "integer", "examples": [8439271], "enum": [8439271] }, { "type": "null" }] } } } }),
    );
    let raw = RawLists {
        tools: vec![Tool::new("t", "d", upstream.clone())],
        ..RawLists::default()
    };
    let lists = sanitize_lists(&f, "mail", &owner(), 0, &raw, &c, &mut HandleStore::new()).unwrap();
    let schema = &lists.tools[0].input_schema;
    assert_eq!(
        schema["properties"]["by"]["additionalProperties"],
        json!({ "type": "string" })
    );
    assert!(
        !serde_json::to_string(&**schema)
            .unwrap()
            .contains("8439271")
    );
    let out = rehydrate_arguments(
        &f,
        "mail",
        c.tools.get("t"),
        &upstream,
        Some(obj(json!({ "by": { "k": CID_TOKEN } }))),
    )
    .unwrap()
    .unwrap();
    assert_eq!(out["by"]["k"], json!(8439271));
}

const MAP_BY: &str =
    "{\"tools\":{\"t\":{\"arguments\":{\"/by\":{\"map\":{\"identifier\":\"CUSTOMER_ID\"}}}}}}";
const NESTED_MAP_BY: &str = "{\"tools\":{\"t\":{\"arguments\":{\"/by\":{\"map\":{\"map\":{\"identifier\":\"CUSTOMER_ID\"}}}}}}}";
const IDS_ELEMENTS: &str =
    "{\"tools\":{\"t\":{\"arguments\":{\"/ids/*\":{\"identifier\":\"CUSTOMER_ID\"}}}}}";
const CUSTOMER_ID_FIELD: &str =
    "{\"tools\":{\"t\":{\"arguments\":{\"/customer/id\":{\"identifier\":\"CUSTOMER_ID\"}}}}}";
const CUSTOMER_ID_ROOT: &str =
    "{\"tools\":{\"t\":{\"arguments\":{\"/customer_id\":{\"identifier\":\"CUSTOMER_ID\"}}}}}";

/// The exposed input schema of one tool `t` with `schema`, listed under
/// the contract `policy`.
fn expose_under(f: &Fake, policy: &str, schema: Value) -> Result<Value, DiscoveryError> {
    let c = Contract::parse(policy).unwrap();
    let raw = RawLists {
        tools: vec![Tool::new("t", "d", obj(schema))],
        ..RawLists::default()
    };
    sanitize_lists(f, "mail", &owner(), 0, &raw, &c, &mut HandleStore::new())
        .map(|l| Value::Object((*l.tools[0].input_schema).clone()))
}

/// The hints of every block carrying the canary customer number that was
/// sent to the engine. A sample of an identifier field sent as
/// `FreeText` is judged as prose (and the fake would tokenize it, hiding
/// the leak from an output check); identifier nodes send no samples at all.
fn cid_hints_sent(f: &Fake) -> Vec<FieldHint> {
    f.seen
        .lock()
        .unwrap()
        .iter()
        .flatten()
        .filter(|b| b.text.contains("8439271"))
        .map(|b| b.hint.clone())
        .collect()
}

/// Neither the canary nor a token standing for it is in `schema`.
fn no_cid_in(schema: &Value) {
    let s = schema.to_string();
    assert!(!s.contains("8439271") && !s.contains(CID_TOKEN), "{s}");
}

/// A `map` rule is matched where its values are walked with the inherited
/// identifier, never at the container: values behind a `$ref` are walked
/// through the inlined definition; values described directly, through a
/// nested map, a combinator, or as array elements, are plain strings and
/// no sample of theirs is judged as prose. Static `properties` beside them
/// would be exposed under no rule and fail the listing too.
#[test]
fn map_rule_values_are_matched_where_they_are_walked() {
    let f = Fake::default();
    // map values behind a `$ref` are walked through the inlined definition
    let g = Fake::default();
    let schema = expose_under(&g, MAP_BY, json!({ "type": "object",
        "$defs": { "ByMap": { "type": "object", "additionalProperties": { "type": "integer", "default": "8439271" } } },
        "properties": { "by": { "$ref": "#/$defs/ByMap" } } }))
    .unwrap();
    assert_eq!(
        schema["properties"]["by"]["allOf"][0]["additionalProperties"],
        json!({ "type": "string" })
    );
    no_cid_in(&schema);
    let e = expose_under(
        &f,
        MAP_BY,
        json!({ "type": "object", "properties": { "by": { "type": "object",
        "properties": { "fixed": { "type": "integer", "default": "8439271" } },
        "additionalProperties": { "type": "integer" } } } }),
    )
    .unwrap_err();
    assert!(matches!(e, DiscoveryError::Unsupported("schema")), "{e:?}");
    assert_eq!(
        *f.calls.lock().unwrap(),
        0,
        "refused before any block is sent"
    );
    // nested map, with a combinator at the inner container
    let schema = expose_under(&f, NESTED_MAP_BY, json!({ "type": "object", "properties": { "by": { "type": "object",
        "additionalProperties": { "anyOf": [
            { "type": "object", "additionalProperties": { "type": "integer", "default": "8439271", "examples": ["8439271"] } },
            { "type": "null" } ] } } } }))
    .unwrap();
    assert_eq!(
        schema["properties"]["by"]["additionalProperties"]["anyOf"][0]["additionalProperties"],
        json!({ "type": "string" })
    );
    no_cid_in(&schema);
    // array elements under a map rule are its values too
    let schema = expose_under(
        &f,
        MAP_BY,
        json!({ "type": "object", "properties": { "by": { "type": "array",
        "items": { "type": "integer", "default": "8439271" },
        "prefixItems": [{ "type": "integer", "const": "8439271" }] } } }),
    )
    .unwrap();
    assert_eq!(
        schema["properties"]["by"]["items"],
        json!({ "type": "string" })
    );
    assert_eq!(
        schema["properties"]["by"]["prefixItems"],
        json!([{ "type": "string" }])
    );
    no_cid_in(&schema);
    assert!(cid_hints_sent(&f).is_empty(), "{:?}", cid_hints_sent(&f));
}

/// `unevaluatedProperties` describes dynamic keys the walk does not visit;
/// it fails the listing, with or without a rule over the data.
#[test]
fn unevaluated_properties_fail_the_listing() {
    let f = Fake::default();
    let shape = json!({ "type": "object", "properties": { "by": { "type": "object",
        "unevaluatedProperties": { "type": "integer", "default": "8439271" } } } });
    for policy in [MAP_BY, "{}"] {
        let e = expose_under(&f, policy, shape.clone()).unwrap_err();
        assert!(matches!(e, DiscoveryError::Unsupported("schema")), "{e:?}");
        assert!(!format!("{e:?} {e}").contains("8439271"));
    }
    assert_eq!(*f.calls.lock().unwrap(), 0);
}

/// Element keywords other than `items`/`prefixItems` describe elements the
/// walk does not visit under `…/*`; each fails the listing. `items` and
/// `prefixItems` are the elements, exposed as plain strings.
#[test]
fn element_keywords_the_walk_does_not_follow_fail_the_listing() {
    let f = Fake::default();
    for kw in ["contains", "unevaluatedItems", "additionalItems"] {
        let e = expose_under(
            &f,
            IDS_ELEMENTS,
            json!({ "type": "object", "properties": { "ids": { "type": "array",
            "items": { "type": "integer" }, kw: { "type": "integer", "default": "8439271" } } } }),
        )
        .unwrap_err();
        assert!(
            matches!(e, DiscoveryError::Unsupported("schema")),
            "{kw}: {e:?}"
        );
    }
    assert_eq!(*f.calls.lock().unwrap(), 0);
    let schema = expose_under(
        &f,
        IDS_ELEMENTS,
        json!({ "type": "object", "properties": { "ids": { "type": "array",
        "items": { "type": "integer", "default": "8439271" },
        "prefixItems": [{ "type": "integer", "examples": ["8439271"] }] } } }),
    )
    .unwrap();
    assert_eq!(
        schema["properties"]["ids"]["items"],
        json!({ "type": "string" })
    );
    assert_eq!(
        schema["properties"]["ids"]["prefixItems"],
        json!([{ "type": "string" }])
    );
    no_cid_in(&schema);
    assert!(cid_hints_sent(&f).is_empty(), "{:?}", cid_hints_sent(&f));
}

/// At the direct parent of a named identifier field, a non-boolean
/// `additionalProperties` in any branch describes the field at `…/*`, where
/// the rule never matches: the listing fails. A boolean one is fine.
#[test]
fn additional_properties_beside_a_named_identifier_fail_the_listing() {
    let f = Fake::default();
    for combinator in ["anyOf", "oneOf", "allOf"] {
        let e = expose_under(
            &f,
            CUSTOMER_ID_FIELD,
            json!({ "type": "object", "properties": { "customer": {
            combinator: [
                { "properties": { "id": { "type": "string" } } },
                { "additionalProperties": { "type": "integer", "default": "8439271" } } ] } } }),
        )
        .unwrap_err();
        assert!(
            matches!(e, DiscoveryError::Unsupported("schema")),
            "{combinator}: {e:?}"
        );
    }
    let e = expose_under(
        &f,
        CUSTOMER_ID_FIELD,
        json!({ "type": "object", "properties": { "customer": { "type": "object",
        "properties": { "id": { "type": "integer" } },
        "additionalProperties": { "type": "integer", "default": "8439271" } } } }),
    )
    .unwrap_err();
    assert!(matches!(e, DiscoveryError::Unsupported("schema")), "{e:?}");
    // the root is the parent of a top-level field
    let e = expose_under(
        &f,
        CUSTOMER_ID_ROOT,
        json!({ "type": "object",
        "properties": { "customer_id": { "type": "integer" } },
        "additionalProperties": { "type": "string", "default": "8439271" } }),
    )
    .unwrap_err();
    assert!(matches!(e, DiscoveryError::Unsupported("schema")), "{e:?}");
    assert_eq!(*f.calls.lock().unwrap(), 0);
    let schema = expose_under(&f, CUSTOMER_ID_FIELD, json!({ "type": "object", "properties": { "customer": {
        "anyOf": [
            { "type": "object", "properties": { "id": { "type": "integer", "default": "8439271" } }, "additionalProperties": false },
            { "type": "null" } ] } } }))
    .unwrap();
    assert_eq!(
        schema["properties"]["customer"]["anyOf"][0]["properties"]["id"],
        json!({ "type": "string" })
    );
    no_cid_in(&schema);
    assert!(cid_hints_sent(&f).is_empty(), "{:?}", cid_hints_sent(&f));
}

/// A `properties.id` under a conditional or key keyword is not the field:
/// those keywords fail the listing before any rule could be matched by
/// them. An unknown keyword carrying an object or array is refused too
/// (`discriminator` is the one checked annotation, see
/// `pydantic_discriminators_are_checked_and_stripped`); a scalar one is
/// dropped.
#[test]
fn decoy_keywords_never_satisfy_an_identifier_rule() {
    let f = Fake::default();
    for kw in [
        "not",
        "if",
        "then",
        "else",
        "propertyNames",
        "patternProperties",
        "dependentSchemas",
        "dependencies",
    ] {
        let shape = json!({ "type": "object", "properties": { "customer": { "type": "object",
            kw: { "properties": { "id": { "type": "string" } } },
            "additionalProperties": false } } });
        for policy in [CUSTOMER_ID_FIELD, "{}"] {
            let e = expose_under(&f, policy, shape.clone()).unwrap_err();
            assert!(
                matches!(e, DiscoveryError::Unsupported("schema")),
                "{kw}: {e:?}"
            );
        }
    }
    let e = expose_under(
        &f,
        CUSTOMER_ID_FIELD,
        json!({ "type": "object", "properties": { "customer": { "type": "object",
        "properties": { "id": { "type": "integer" } },
        "x-shape": { "properties": { "id": { "type": "integer", "default": "8439271" } } } } } }),
    )
    .unwrap_err();
    assert!(matches!(e, DiscoveryError::Unsupported("schema")), "{e:?}");
    assert_eq!(*f.calls.lock().unwrap(), 0);
    let schema = expose_under(&f, CUSTOMER_ID_FIELD, json!({ "type": "object", "properties": { "customer": { "type": "object",
        "properties": { "id": { "type": "integer", "description": "Kundennummer", "default": "8439271" } },
        "x-note": "drop" } } }))
    .unwrap();
    assert!(schema["properties"]["customer"].get("x-note").is_none());
    assert_eq!(
        schema["properties"]["customer"]["properties"]["id"],
        json!({ "type": "string", "description": "Kundennummer" })
    );
    no_cid_in(&schema);
    // the field's prose is judged as metadata; its sample is never sent
    let seen = f.seen.lock().unwrap().concat();
    assert!(
        seen.iter()
            .any(|b| b.text == "Kundennummer" && b.hint == FieldHint::Metadata)
    );
    assert!(cid_hints_sent(&f).is_empty(), "{:?}", cid_hints_sent(&f));
}

/// Numeric bounds pin a value like `const` does (`minimum == maximum`):
/// a definition an identifier reaches loses them, for a named field and
/// for map values. Length bounds and an unrelated definition's bounds stay.
#[test]
fn identifier_definitions_lose_their_numeric_bounds() {
    let f = Fake::default();
    let pinned = json!({ "type": "integer", "minimum": 8439271, "maximum": 8439271,
        "exclusiveMinimum": 8439270, "exclusiveMaximum": 8439272, "multipleOf": 8439271,
        "minLength": 7, "maxLength": 7 });
    let range = json!({ "type": "integer", "minimum": 1, "maximum": 5 });
    // P1: a named field behind a $ref
    let schema = expose_under(
        &f,
        CUSTOMER_ID_ROOT,
        json!({ "type": "object",
        "$defs": { "Cid": pinned, "Qty": range },
        "properties": { "customer_id": { "$ref": "#/$defs/Cid" }, "qty": { "$ref": "#/$defs/Qty" } } }),
    )
    .unwrap();
    assert_eq!(
        schema["properties"]["customer_id"],
        json!({ "type": "string" })
    );
    assert_eq!(
        schema["$defs"]["Cid"],
        json!({ "type": "integer", "minLength": 7, "maxLength": 7 })
    );
    assert_eq!(schema["$defs"]["Qty"], range);
    no_cid_in(&schema);
    // P7: map values (array elements and dynamic keys) behind a $ref
    for values in ["items", "additionalProperties"] {
        let kind = if values == "items" { "array" } else { "object" };
        let schema = expose_under(
            &f,
            MAP_BY,
            json!({ "type": "object",
            "$defs": { "V": pinned },
            "properties": { "by": { "type": kind, values: { "$ref": "#/$defs/V" } } } }),
        )
        .unwrap();
        assert_eq!(
            schema["properties"]["by"][values],
            json!({ "type": "string" }),
            "{values}"
        );
        no_cid_in(&schema);
    }
    assert!(cid_hints_sent(&f).is_empty(), "{:?}", cid_hints_sent(&f));
}

/// Numeric `enum`/`const` values are data like string ones: they must
/// survive sanitization unchanged or the listing fails.
#[test]
fn numeric_enum_values_must_survive_sanitization() {
    let f = Fake::default();
    let c = Contract::empty();
    let lists = |schema: serde_json::Value| {
        let mut raw = RawLists::default();
        raw.tools.push(Tool::new("t", "d", obj(schema)));
        sanitize_lists(&f, "mail", &owner(), 0, &raw, &c, &mut HandleStore::new())
    };
    let ok = lists(json!({ "type": "object", "properties": { "p": { "type": "integer", "enum": [1, 2, 3] }, "b": { "const": true } } })).unwrap();
    assert_eq!(
        ok.tools[0].input_schema["properties"]["p"]["enum"],
        json!([1, 2, 3]),
        "kept as numbers"
    );
    for bad in [
        json!({ "type": "object", "properties": { "p": { "type": "integer", "enum": [1, 8439271] } } }),
        json!({ "type": "object", "properties": { "p": { "const": 8439271 } } }),
    ] {
        assert!(matches!(
            lists(bad),
            Err(DiscoveryError::Unsupported("enum"))
        ));
    }
}

/// Schema keywords that carry free strings are either sanitized as static
/// values, restricted to a fixed vocabulary, or dropped; never passed raw.
#[test]
fn schema_strings_are_never_passed_raw() {
    let f = Fake::default();
    let c = Contract::empty();
    let lists = |schema: serde_json::Value| {
        let mut raw = RawLists::default();
        raw.tools.push(Tool::new("t", "d", obj(schema)));
        sanitize_lists(&f, "mail", &owner(), 0, &raw, &c, &mut HandleStore::new())
    };
    let ok = lists(json!({
        "$schema": format!("https://schemas.example/{IDENTITY}"),
        "$id": format!("urn:{IDENTITY}"),
        "type": "object",
        "properties": { "q": { "type": ["string", "null"], "format": "Zyxwuria", "pattern": "^[0-9]{6}$", "contentMediaType": "text/plain" },
                        "d": { "type": "string", "format": "date-time" } },
        "$defs": { "Id": { "type": "string" } },
        "additionalProperties": false
    }))
    .unwrap();
    let s = serde_json::to_string(&ok.tools).unwrap();
    assert!(!s.contains("Zyxwuria"), "{s}");
    let schema = &ok.tools[0].input_schema;
    assert!(schema.get("$schema").is_none() && schema.get("$id").is_none());
    assert!(
        schema["properties"]["q"].get("format").is_none(),
        "unknown format dropped"
    );
    assert_eq!(schema["properties"]["d"]["format"], "date-time");
    assert_eq!(schema["properties"]["q"]["pattern"], "^[0-9]{6}$");
    for (bad, class) in [
        (
            json!({ "type": "object", "required": [IDENTITY] }),
            "schema",
        ),
        (json!({ "type": IDENTITY.to_string() }), "schema"),
        (
            json!({ "type": "object", "properties": { "q": { "pattern": format!("^{IDENTITY}$") } } }),
            "schema",
        ),
        (
            json!({ "type": "object", "properties": { "q": { "$ref": format!("#/$defs/{IDENTITY}") } } }),
            "ref",
        ),
        (json!({ "type": "object", "minimum": IDENTITY }), "schema"),
    ] {
        match lists(bad) {
            Err(DiscoveryError::Unsupported(c)) => assert_eq!(c, class),
            other => panic!("{class}: {other:?}"),
        }
    }
}

fn lookup_contract() -> Contract {
    Contract::parse(POLICY).unwrap()
}

/// Review Focus 1 (argument side).
#[test]
fn numeric_identifier_round_trips_through_its_typed_token() {
    let f = Fake::default();
    let c = lookup_contract();
    let schema = obj(
        json!({ "type": "object", "properties": { "customer_id": { "type": "integer" }, "note": { "type": "string" } } }),
    );
    let args = obj(json!({ "customer_id": CID_TOKEN, "note": format!("about {NAME_TOKEN}") }));
    let out = rehydrate_arguments(&f, "mail", c.tools.get("lookup"), &schema, Some(args))
        .unwrap()
        .unwrap();
    assert_eq!(
        out["customer_id"],
        json!(8439271),
        "an integer again, not a string"
    );
    assert_eq!(out["note"], format!("about {IDENTITY}"));
    assert_eq!(*f.calls.lock().unwrap(), 1);
    // an identifier token that does not resolve to the schema's type
    let args = obj(json!({ "customer_id": NAME_TOKEN }));
    assert!(matches!(
        rehydrate_arguments(&f, "mail", c.tools.get("lookup"), &schema, Some(args)),
        Err(ContentError::Unsupported("argument_type"))
    ));
    // unknown key, unresolved token, no arguments
    let args = obj(json!({ "customer_id": CID_TOKEN, "extra": "x" }));
    assert!(matches!(
        rehydrate_arguments(&f, "mail", c.tools.get("lookup"), &schema, Some(args)),
        Err(ContentError::Unsupported("argument_key"))
    ));
    let args = obj(json!({ "note": "<PERSON_zzzzzz>" }));
    assert!(matches!(
        rehydrate_arguments(&f, "mail", c.tools.get("lookup"), &schema, Some(args)),
        Err(ContentError::Unresolved {
            unknown: 1,
            removed: 0
        })
    ));
    assert!(
        rehydrate_arguments(&f, "mail", None, &schema, None)
            .unwrap()
            .is_none()
    );
    // nested arrays and objects, numbers untouched
    let schema = obj(
        json!({ "type": "object", "properties": { "filter": { "type": "object", "properties": { "names": { "type": "array", "items": { "type": "string" } }, "n": { "type": "integer" } } } } }),
    );
    let args = obj(json!({ "filter": { "names": [NAME_TOKEN, "x"], "n": 2 } }));
    let out = rehydrate_arguments(&f, "mail", None, &schema, Some(args))
        .unwrap()
        .unwrap();
    assert_eq!(out["filter"]["names"][0], IDENTITY);
    assert_eq!(out["filter"]["n"], 2);
}

/// Review Focus 1 through schema indirection: the target type of an
/// identifier argument is found behind a local `$ref` and in the one
/// non-null branch of `anyOf`/`oneOf` (Pydantic `Optional[int]`); a schema
/// whose type cannot be determined is refused, never sent as a string.
#[test]
fn identifier_argument_type_resolves_refs_and_optional() {
    let f = Fake::default();
    let c = lookup_contract();
    let lookup = c.tools.get("lookup");
    let call = |schema: serde_json::Value| {
        rehydrate_arguments(
            &f,
            "mail",
            lookup,
            &obj(schema),
            Some(obj(json!({ "customer_id": CID_TOKEN }))),
        )
    };
    for schema in [
        json!({ "type": "object", "$defs": { "CustomerId": { "type": "integer" } }, "properties": { "customer_id": { "$ref": "#/$defs/CustomerId" } } }),
        json!({ "type": "object", "definitions": { "Id": { "$ref": "#/definitions/Inner" }, "Inner": { "type": "integer" } }, "properties": { "customer_id": { "$ref": "#/definitions/Id" } } }),
        json!({ "type": "object", "properties": { "customer_id": { "anyOf": [{ "type": "integer" }, { "type": "null" }], "default": null } } }),
        json!({ "type": "object", "properties": { "customer_id": { "oneOf": [{ "type": "null" }, { "$ref": "#/$defs/Id" }] } }, "$defs": { "Id": { "type": "integer" } } }),
        json!({ "type": "object", "properties": { "customer_id": { "type": ["null", "integer"] } } }),
    ] {
        let out = call(schema.clone()).unwrap().unwrap();
        assert_eq!(out["customer_id"], json!(8439271), "{schema}");
    }
    for schema in [
        json!({ "type": "object", "properties": { "customer_id": {} } }),
        json!({ "type": "object", "properties": { "customer_id": { "description": "no type" } } }),
        json!({ "type": "object", "properties": { "customer_id": { "$ref": "#/$defs/Missing" } } }),
        json!({ "type": "object", "properties": { "customer_id": { "$ref": "https://example.test/id" } } }),
        json!({ "type": "object", "properties": { "customer_id": { "anyOf": [{ "type": "integer" }, { "type": "string" }] } } }),
        json!({ "type": "object", "properties": { "customer_id": { "type": ["integer", "string"] } } }),
        json!({ "type": "object", "$defs": { "A": { "$ref": "#/$defs/A" } }, "properties": { "customer_id": { "$ref": "#/$defs/A" } } }),
    ] {
        assert!(
            matches!(
                call(schema.clone()),
                Err(ContentError::Unsupported("argument_type"))
            ),
            "{schema}"
        );
    }
}

/// A `$defs` DAG whose branches share definitions cannot make the type
/// lookup exponential: a shared visit budget fails it closed.
#[test]
fn identifier_type_lookup_is_bounded_on_a_definition_dag() {
    let f = Fake::default();
    let c = lookup_contract();
    let dag = |levels: usize, fan: usize| {
        let mut defs = serde_json::Map::new();
        for i in 0..levels {
            let r = json!({ "$ref": format!("#/$defs/A{}", i + 1) });
            defs.insert(format!("A{i}"), json!({ "anyOf": vec![r; fan] }));
        }
        defs.insert(format!("A{levels}"), json!({ "type": "integer" }));
        obj(
            json!({ "type": "object", "$defs": defs, "properties": { "customer_id": { "$ref": "#/$defs/A0" } } }),
        )
    };
    let args = || Some(obj(json!({ "customer_id": CID_TOKEN })));
    // small: resolves
    let out = rehydrate_arguments(&f, "mail", c.tools.get("lookup"), &dag(2, 2), args())
        .unwrap()
        .unwrap();
    assert_eq!(out["customer_id"], json!(8439271));
    // 4^15 paths: refused quickly instead of walked
    let started = std::time::Instant::now();
    assert!(matches!(
        rehydrate_arguments(&f, "mail", c.tools.get("lookup"), &dag(15, 4), args()),
        Err(ContentError::Unsupported("argument_type"))
    ));
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
}

/// Tuple arrays: an identifier element takes its type from `prefixItems`
/// (or a draft-7 `items` array and `additionalItems`); an element the
/// tuple does not describe has no determinable type and is refused.
#[test]
fn identifier_elements_of_tuple_arrays_resolve_or_fail() {
    let f = Fake::default();
    let c = Contract::parse(
        "{\"tools\":{\"t\":{\"arguments\":{\"/ids/*\":{\"identifier\":\"CUSTOMER_ID\"}}}}}",
    )
    .unwrap();
    let call = |ids: serde_json::Value, n: usize| {
        let schema = obj(json!({ "type": "object", "properties": { "ids": ids } }));
        let args = obj(json!({ "ids": vec![CID_TOKEN; n] }));
        rehydrate_arguments(&f, "mail", c.tools.get("t"), &schema, Some(args))
    };
    let ok = [
        (
            json!({ "type": "array", "prefixItems": [{ "type": "integer" }] }),
            1,
        ),
        (
            json!({ "type": "array", "prefixItems": [{ "type": "integer" }], "items": { "type": "integer" } }),
            3,
        ),
        (
            json!({ "type": "array", "items": [{ "type": "integer" }], "additionalItems": { "type": "integer" } }),
            2,
        ),
        (
            json!({ "type": "array", "items": { "type": "integer" } }),
            2,
        ),
    ];
    for (ids, n) in ok {
        let out = call(ids.clone(), n).unwrap().unwrap();
        assert_eq!(out["ids"], json!(vec![8439271; n]), "{ids}");
    }
    let refused = [
        (
            json!({ "type": "array", "prefixItems": [{ "type": "integer" }] }),
            2,
        ),
        (
            json!({ "type": "array", "items": [{ "type": "integer" }] }),
            2,
        ),
        (json!({ "type": "array", "items": true }), 1),
        (json!({ "type": "array", "prefixItems": [true] }), 1),
    ];
    for (ids, n) in refused {
        assert!(
            matches!(
                call(ids.clone(), n),
                Err(ContentError::Unsupported("argument_type"))
            ),
            "{ids}"
        );
    }
    // an array schema that says nothing about elements: no schema node
    let out = call(json!({ "type": "array" }), 1).unwrap().unwrap();
    assert_eq!(out["ids"], json!(["8439271"]));
}

/// Keys under a `map` rule are data: strictly rehydrated like values.
#[test]
fn dynamic_argument_keys_are_strictly_rehydrated() {
    let f = Fake::default();
    let c = Contract::parse("{\"tools\":{\"t\":{\"arguments\":{\"/by\":{\"map\":\"quantity\"}}}}}")
        .unwrap();
    let schema = obj(
        json!({ "type": "object", "properties": { "by": { "type": "object", "additionalProperties": { "type": "integer" } } } }),
    );
    let args = obj(json!({ "by": { NAME_TOKEN: 3, "Muster GmbH": 1 } }));
    let out = rehydrate_arguments(&f, "mail", c.tools.get("t"), &schema, Some(args))
        .unwrap()
        .unwrap();
    assert_eq!(out["by"], json!({ IDENTITY: 3, "Muster GmbH": 1 }));
    let args = obj(json!({ "by": { "<PERSON_zzzzzz>": 3 } }));
    assert!(matches!(
        rehydrate_arguments(&f, "mail", c.tools.get("t"), &schema, Some(args)),
        Err(ContentError::Unresolved { unknown: 1, .. })
    ));
    let args = obj(json!({ "by": { NAME_TOKEN: 3, IDENTITY: 1 } }));
    assert!(matches!(
        rehydrate_arguments(&f, "mail", c.tools.get("t"), &schema, Some(args)),
        Err(ContentError::Unsupported("key_collision"))
    ));
    // without the map rule the same keys are unknown
    let args = obj(json!({ "by": { NAME_TOKEN: 3 } }));
    assert!(matches!(
        rehydrate_arguments(&f, "mail", None, &schema, Some(args)),
        Err(ContentError::Unsupported("argument_key"))
    ));
}

#[test]
fn structured_content_follows_the_contract_and_rejects_the_rest() {
    let f = Fake::default();
    let c = lookup_contract();
    let mut handles = HandleStore::new();
    let mut r = CallToolResult::success(vec![ContentBlock::text(format!(
        "Kunde: {IDENTITY} IBAN {IBAN}"
    ))]);
    r.structured_content = Some(
        json!({ "customer": { "id": 8439271, "name": IDENTITY, "iban": IBAN, "count": 3, "tags": ["vip", IDENTITY], "active": true } }),
    );
    r.meta = Some(MetaObject(obj(json!({ "trace": IDENTITY }))));
    let (out, stats) =
        sanitize_call_result(&f, "mail", c.tools.get("record"), &mut handles, &owner(), r).unwrap();
    assert_eq!(
        texts(&out),
        [format!("Kunde: {NAME_TOKEN} IBAN {IBAN_TOKEN}")]
    );
    let sc = out.structured_content.unwrap();
    assert_eq!(
        sc["customer"]["id"], CID_TOKEN,
        "number → typed string token"
    );
    assert_eq!(sc["customer"]["name"], NAME_TOKEN);
    assert_eq!(sc["customer"]["count"], 3);
    assert_eq!(sc["customer"]["tags"], json!(["vip", NAME_TOKEN]));
    assert_eq!(sc["customer"]["active"], true);
    assert!(out.meta.is_none(), "_meta stripped");
    assert_eq!(
        stats.blocks, 6,
        "text + name + iban + 2 tags + the typed id block"
    );
    assert_eq!(
        stats.replaced,
        [(EntityKind::CustomerId, 1)],
        "replaced kinds are typed, with block counts (activity records)"
    );
    assert_eq!(*f.calls.lock().unwrap(), 1, "one batch per result");
    let seen = f.seen.lock().unwrap();
    assert!(
        seen[0]
            .iter()
            .any(|b| b.hint == FieldHint::Identifier(EntityKind::CustomerId) && b.text == "8439271")
    );
    drop(seen);
    // no result contract → structured content is unsupported
    let mut r = CallToolResult::success(vec![ContentBlock::text("x")]);
    r.structured_content = Some(json!({ "a": "b" }));
    assert!(matches!(
        sanitize_call_result(&f, "mail", None, &mut handles, &owner(), r),
        Err(ContentError::Unsupported("structured_content"))
    ));
    // an unlisted key, an unclassified number
    let mut r = CallToolResult::success(vec![]);
    r.structured_content = Some(json!({ "customer": { "id": 1, "surprise": "x" } }));
    assert!(matches!(
        sanitize_call_result(&f, "mail", c.tools.get("record"), &mut handles, &owner(), r),
        Err(ContentError::Unsupported("result_key"))
    ));
    let mut r = CallToolResult::success(vec![]);
    r.structured_content = Some(json!({ "received": 5 }));
    assert!(matches!(
        sanitize_call_result(&f, "mail", c.tools.get("echo"), &mut handles, &owner(), r),
        Err(ContentError::Unsupported("number"))
    ));
    // dynamic keys through a map rule: keys are sanitized, collisions rejected
    let mut r = CallToolResult::success(vec![]);
    r.structured_content = Some(json!({ "by_name": { IDENTITY: 3, "Muster GmbH": 1 } }));
    let (out, _) = sanitize_call_result(
        &f,
        "mail",
        c.tools.get("dynamic"),
        &mut handles,
        &owner(),
        r,
    )
    .unwrap();
    assert_eq!(
        out.structured_content.unwrap()["by_name"],
        json!({ NAME_TOKEN: 3, "Muster GmbH": 1 })
    );
    let mut r = CallToolResult::success(vec![]);
    r.structured_content = Some(json!({ "by_name": { IDENTITY: 3, NAME_TOKEN: 1 } }));
    assert!(matches!(
        sanitize_call_result(
            &f,
            "mail",
            c.tools.get("dynamic"),
            &mut handles,
            &owner(),
            r
        ),
        Err(ContentError::Unsupported("key_collision"))
    ));
    let mut r = CallToolResult::success(vec![]);
    r.structured_content = Some(json!({ "by_name": { "x": "not a quantity" } }));
    assert!(matches!(
        sanitize_call_result(
            &f,
            "mail",
            c.tools.get("dynamic"),
            &mut handles,
            &owner(),
            r
        ),
        Err(ContentError::Unsupported("string_rule"))
    ));
    // a nested object under a map rule: its keys are neither static nor sanitized
    let mut r = CallToolResult::success(vec![]);
    r.structured_content = Some(json!({ "by_name": { "x": { IDENTITY: 1 } } }));
    assert!(matches!(
        sanitize_call_result(
            &f,
            "mail",
            c.tools.get("dynamic"),
            &mut handles,
            &owner(),
            r
        ),
        Err(ContentError::Unsupported("result_key"))
    ));
}

/// A `quantity` field keeps a plain number and never makes it a block;
/// anything else in it (an identifier-looking string) is refused, not kept.
#[test]
fn quantity_keeps_numbers_and_refuses_identifier_looking_values() {
    let c = lookup_contract();
    let mut handles = HandleStore::new();
    let f = Fake::default();
    let mut r = CallToolResult::success(vec![]);
    r.structured_content = Some(json!({ "customer": { "count": 8439271 } }));
    let (out, stats) =
        sanitize_call_result(&f, "mail", c.tools.get("record"), &mut handles, &owner(), r).unwrap();
    assert_eq!(
        out.structured_content.unwrap()["customer"]["count"],
        8439271
    );
    assert_eq!(stats.blocks, 0, "a quantity is not a block");
    assert_eq!(
        *f.calls.lock().unwrap(),
        0,
        "nothing to sanitize, no engine call"
    );
    for v in [
        json!(IBAN),
        json!("K-123456"),
        json!(IDENTITY),
        json!(["1"]),
        json!({ "n": 1 }),
    ] {
        let mut r = CallToolResult::success(vec![]);
        r.structured_content = Some(json!({ "customer": { "count": v } }));
        let e = sanitize_call_result(&f, "mail", c.tools.get("record"), &mut handles, &owner(), r)
            .unwrap_err();
        assert!(matches!(e, ContentError::Unsupported(_)), "{v}: {e:?}");
    }
}

#[test]
fn binary_and_blocked_and_uncertain_discard_the_whole_result() {
    let f = Fake::default();
    let mut handles = HandleStore::new();
    let r = CallToolResult::success(vec![
        ContentBlock::image("iVBORw0KGgo=", "image/png"),
        ContentBlock::text("caption"),
    ]);
    assert!(matches!(
        sanitize_call_result(&f, "mail", None, &mut handles, &owner(), r),
        Err(ContentError::Unsupported("binary"))
    ));
    let r = CallToolResult::success(vec![ContentBlock::audio("AAAA", "audio/wav")]);
    assert!(matches!(
        sanitize_call_result(&f, "mail", None, &mut handles, &owner(), r),
        Err(ContentError::Unsupported("binary"))
    ));
    let r = CallToolResult::success(vec![
        ContentBlock::text("fine"),
        ContentBlock::text("BLOCKME"),
    ]);
    match sanitize_call_result(&f, "mail", None, &mut handles, &owner(), r).unwrap_err() {
        ContentError::Blocked { kinds, checks } => {
            assert_eq!(kinds, [EntityKind::Person, EntityKind::Iban]);
            assert_eq!(checks, [CheckLabel::Leak]);
            assert_eq!(
                blocked_text(&kinds, &checks),
                "blocked by inumaki (kinds: PERSON, IBAN; checks: Leak)"
            );
        }
        other => panic!("{other:?}"),
    }
    let r = CallToolResult::success(vec![ContentBlock::text("MAYBE")]);
    match sanitize_call_result(&f, "mail", None, &mut handles, &owner(), r).unwrap_err() {
        ContentError::Uncertain { kinds, checks } => {
            assert_eq!(checks, [CheckLabel::Combination]);
            assert_eq!(
                withheld_text(&kinds, &checks),
                "withheld by inumaki (uncertain; kinds: DATE; checks: Combination)"
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        blocked_text(&[], &[]),
        "blocked by inumaki (kinds: ; checks: )"
    );
}

#[test]
fn embedded_resources_and_links_are_blocks_with_handles() {
    let f = Fake::default();
    let mut handles = HandleStore::new();
    let link = Resource::new(
        format!("mem://customer/{IDENTITY}"),
        format!("{IDENTITY}.pdf"),
    )
    .with_title(format!("about {IDENTITY}"))
    .with_description(format!("IBAN {IBAN}"))
    .with_mime_type("application/pdf")
    .with_size(3)
    .with_meta(MetaObject(obj(json!({ "x": 1 }))));
    let r = CallToolResult::success(vec![
        ContentBlock::Resource(
            EmbeddedResource::new(
                ResourceContents::text(
                    format!("Kunde {IDENTITY}"),
                    format!("mem://customer/{IDENTITY}"),
                )
                .with_mime_type("text/plain"),
            )
            .with_meta(MetaObject(obj(json!({ "y": IDENTITY })))),
        ),
        ContentBlock::ResourceLink(link),
    ]);
    let (out, stats) = sanitize_call_result(&f, "mail", None, &mut handles, &owner(), r).unwrap();
    assert_eq!(stats.blocks, 4);
    match &out.content[0] {
        ContentBlock::Resource(e) => {
            assert!(e.meta.is_none());
            match &e.resource {
                ResourceContents::TextResourceContents {
                    uri,
                    text,
                    mime_type,
                    meta,
                } => {
                    assert!(
                        uri.starts_with("inumaki://res/"),
                        "embedded uri replaced by a handle: {uri}"
                    );
                    assert_eq!(text, &format!("Kunde {NAME_TOKEN}"));
                    assert_eq!(mime_type.as_deref(), Some("text/plain"));
                    assert!(meta.is_none());
                }
                _ => panic!("text resource expected"),
            }
        }
        _ => panic!("resource expected"),
    }
    match &out.content[1] {
        ContentBlock::ResourceLink(l) => {
            assert!(l.uri.starts_with("inumaki://res/"));
            assert_eq!(
                handles.resolve_resource(&l.uri).unwrap().1,
                format!("mem://customer/{IDENTITY}")
            );
            assert_eq!(l.name, format!("{NAME_TOKEN}.pdf"));
            assert_eq!(
                l.title.as_deref(),
                Some(format!("about {NAME_TOKEN}").as_str())
            );
            assert_eq!(
                l.description.as_deref(),
                Some(format!("IBAN {IBAN_TOKEN}").as_str())
            );
            assert_eq!(l.size, Some(3));
            assert!(l.meta.is_none());
        }
        _ => panic!("link expected"),
    }
    let r = CallToolResult::success(vec![ContentBlock::Resource(EmbeddedResource::new(
        ResourceContents::blob("AAAA", "mem://logo"),
    ))]);
    assert!(matches!(
        sanitize_call_result(&f, "mail", None, &mut handles, &owner(), r),
        Err(ContentError::Unsupported("binary"))
    ));
    let whole = serde_json::to_string(&out).unwrap();
    assert!(
        !whole.contains("Zyxwuria") && !whole.contains("AT61"),
        "{whole}"
    );
}

#[test]
fn read_and_prompt_results_follow_the_same_rules() {
    let f = Fake::default();
    let r = ReadResourceResult::new(vec![ResourceContents::text(
        format!("Kunde {IDENTITY}"),
        format!("mem://customer/{IDENTITY}"),
    )]);
    let (out, stats) =
        sanitize_read_result(&f, "mail", "inumaki://res/0123456789abcdef", r).unwrap();
    assert_eq!(stats.blocks, 1);
    match &out.contents[0] {
        ResourceContents::TextResourceContents { uri, text, .. } => {
            assert_eq!(
                uri, "inumaki://res/0123456789abcdef",
                "the agent's handle comes back, never the raw uri"
            );
            assert_eq!(text, &format!("Kunde {NAME_TOKEN}"));
        }
        _ => panic!(),
    }
    let r = ReadResourceResult::new(vec![
        ResourceContents::blob("AAAA", "mem://logo").with_mime_type("image/png"),
    ]);
    assert!(matches!(
        sanitize_read_result(&f, "mail", "inumaki://res/0123456789abcdef", r),
        Err(ContentError::Unsupported("binary"))
    ));
    let mut handles = HandleStore::new();
    let mut p = GetPromptResult::new(vec![PromptMessage::new_text(
        Role::User,
        format!("Hello {IDENTITY}"),
    )]);
    p.description = Some(format!("about {IDENTITY}"));
    let (out, stats) = sanitize_prompt_result(&f, "mail", &mut handles, &owner(), p).unwrap();
    assert_eq!(stats.blocks, 2);
    assert_eq!(
        out.description.as_deref(),
        Some(format!("about {NAME_TOKEN}").as_str())
    );
    assert_eq!(
        out.messages[0].content.as_text().unwrap().text,
        format!("Hello {NAME_TOKEN}")
    );
    let p = GetPromptResult::new(vec![PromptMessage::new(
        Role::Assistant,
        ContentBlock::image("AAAA", "image/png"),
    )]);
    assert!(matches!(
        sanitize_prompt_result(&f, "mail", &mut handles, &owner(), p),
        Err(ContentError::Unsupported("binary"))
    ));
    let c = lookup_contract();
    let out = rehydrate_prompt_arguments(
        &f,
        "mail",
        c.prompts.get("greet"),
        &["name".into()],
        Some(obj(json!({ "name": NAME_TOKEN }))),
    )
    .unwrap()
    .unwrap();
    assert_eq!(out["name"], IDENTITY);
    assert!(matches!(
        rehydrate_prompt_arguments(
            &f,
            "mail",
            c.prompts.get("greet"),
            &["name".into()],
            Some(obj(json!({ "other": "x" })))
        ),
        Err(ContentError::Unsupported("argument_key"))
    ));
    assert!(matches!(
        rehydrate_prompt_arguments(
            &f,
            "mail",
            None,
            &["name".into()],
            Some(obj(json!({ "name": 5 })))
        ),
        Err(ContentError::Unsupported("argument_type"))
    ));
}

#[test]
fn template_params_are_rehydrated_by_rule_and_expanded() {
    let f = Fake::default();
    let mut params = BTreeMap::new();
    params.insert("id".to_string(), Rule::Identifier(EntityKind::CustomerId));
    let tc = TemplateContract { params };
    let route = TemplateRoute {
        original: "mem://note/{id}".into(),
        params: vec!["id".into()],
    };
    let uri = rehydrate_template_params(&f, "mail", &tc, &route, vec![CID_TOKEN.into()]).unwrap();
    assert_eq!(uri, "mem://note/8439271");
    assert!(matches!(
        rehydrate_template_params(&f, "mail", &tc, &route, vec!["<X_1234>".into()]),
        Err(ContentError::Unresolved { .. })
    ));
    assert!(matches!(
        rehydrate_template_params(&f, "mail", &tc, &route, vec![]),
        Err(ContentError::Unsupported("template_values"))
    ));
    // the agent percent-encodes per RFC 6570; the token inside is still
    // found, and the restored value is encoded again for the upstream URI
    let mut params = BTreeMap::new();
    params.insert("id".to_string(), Rule::FreeText);
    let tc = TemplateContract { params };
    let uri =
        rehydrate_template_params(&f, "mail", &tc, &route, vec!["%3CPERSON_aaaaaa%3E".into()])
            .unwrap();
    assert_eq!(uri, "mem://note/Zyxwuria%20Quolnath");
    assert!(matches!(
        rehydrate_template_params(&f, "mail", &tc, &route, vec!["%3CPERSON_zzzzzz%3E".into()]),
        Err(ContentError::Unresolved { .. })
    ));
    for bad in ["%FF", "%+F", "%-1", "%4", "%", "%zz"] {
        assert!(
            matches!(
                rehydrate_template_params(&f, "mail", &tc, &route, vec![bad.into()]),
                Err(ContentError::Unsupported("template_values"))
            ),
            "{bad}"
        );
    }
}

/// Review Focus 3.
#[test]
fn upstream_errors_become_fixed_classes() {
    let e = ErrorData::new(
        ErrorCode::INTERNAL_ERROR,
        format!("lookup failed for {IDENTITY}"),
        Some(json!({ "query": IDENTITY })),
    );
    let out = upstream_error(&e);
    assert_eq!(out.message, "upstream_error");
    assert_eq!(out.code, ErrorCode::INTERNAL_ERROR);
    assert_eq!(out.data.unwrap(), json!({ "code": -32603 }));
    let whole = serde_json::to_string(&upstream_error(&e)).unwrap();
    assert!(
        !whole.contains("Zyxwuria") && !whole.contains("lookup"),
        "{whole}"
    );
}

#[test]
fn scripted_upstream_lists_match_the_reference_policy() {
    // Every tool, prompt, and template the reference policy names exists on
    // the scripted server, with every argument pointer's first segment a
    // property of the tool's input schema, so the Task 7 smoke test and the
    // e2e tests agree on the contract.
    let s = ScriptedUpstream::default();
    let c = Contract::parse(POLICY).unwrap();
    let tools = s.tools();
    for (name, tc) in &c.tools {
        let tool = tools
            .iter()
            .find(|t| t.name == name.as_str())
            .unwrap_or_else(|| panic!("{name} not on the scripted server"));
        for (ptr, _) in tc.arguments.iter() {
            let first = ptr[1..].split('/').next().unwrap();
            assert!(
                tool.input_schema["properties"].get(first).is_some(),
                "{name}{ptr}"
            );
        }
    }
    let prompts = s.prompts();
    for name in c.prompts.keys() {
        assert!(prompts.iter().any(|p| &p.name == name), "{name}");
    }
    let templates = s.templates();
    for uri in c.templates.keys() {
        assert!(templates.iter().any(|t| &t.uri_template == uri), "{uri}");
    }
    // and the listing sanitizes cleanly under the reference policy
    let raw = RawLists {
        tools,
        prompts,
        resources: vec![],
        templates,
    };
    let lists = sanitize_lists(
        &Fake::default(),
        "mail",
        &owner(),
        0,
        &raw,
        &c,
        &mut HandleStore::new(),
    )
    .unwrap();
    assert_eq!(lists.templates.len(), 1);
}

/// Plan 2c: listing prose goes to the metadata profile; a listed resource
/// and every block of a result (text, embedded resource) are data and stay
/// free text.
#[test]
fn listing_prose_is_metadata_and_resources_and_results_are_free_text() {
    let f = Fake::default();
    let c = Contract::parse(POLICY).unwrap();
    let mut handles = HandleStore::new();
    sanitize_lists(&f, "mail", &owner(), 0, &raw_scripted(), &c, &mut handles).unwrap();
    {
        let seen = f.seen.lock().unwrap().concat();
        let hint = |text: &str| seen.iter().find(|b| b.text == text).map(|b| b.hint.clone());
        assert_eq!(hint("echo the query"), Some(FieldHint::Metadata));
        assert_eq!(hint("free text"), Some(FieldHint::Metadata));
        assert_eq!(hint("hi"), Some(FieldHint::Metadata), "an example");
        assert_eq!(
            hint(&format!("greet {IDENTITY}")),
            Some(FieldHint::Metadata)
        );
        assert_eq!(
            hint(&format!("record of {IDENTITY}")),
            Some(FieldHint::FreeText)
        );
        assert_eq!(hint(&format!("IBAN {IBAN}")), Some(FieldHint::FreeText));
    }
    let before = f.seen.lock().unwrap().len();
    let r = CallToolResult::success(vec![
        ContentBlock::text(format!("about {IDENTITY}")),
        ContentBlock::Resource(EmbeddedResource::new(
            ResourceContents::text(format!("Kunde {IDENTITY}"), "mem://customer/x")
                .with_mime_type("text/plain"),
        )),
    ]);
    sanitize_call_result(&f, "mail", None, &mut handles, &owner(), r).unwrap();
    let seen = f.seen.lock().unwrap();
    let result_blocks: Vec<&TextBlock> = seen[before..].iter().flatten().collect();
    assert!(
        result_blocks
            .iter()
            .any(|b| b.text == format!("Kunde {IDENTITY}"))
    );
    assert!(
        result_blocks.iter().all(|b| b.hint == FieldHint::FreeText),
        "result blocks are free text"
    );
}

/// Plan 3 (mail): the `handle` rule keeps a value only by provenance (the
/// daemon minted it), allows `null` and an absent field, and fails the
/// whole result for anything else; it is valid for tool arguments and
/// results but not for prompt arguments or template parameters.
#[test]
fn handle_rule_preserves_by_provenance_and_allows_null_or_absent() {
    let f = Fake::default();
    let c = Contract::parse(
        r#"{ "tools": { "m": { "result": { "/messages/*/id": "handle", "/messages/*/from": "free_text", "/draft/id": "handle", "/draft/folder": "handle" } } } }"#,
    )
    .unwrap();
    assert_eq!(
        c.tools["m"].result.as_ref().unwrap().get("/draft/id"),
        Some(&Rule::Handle)
    );
    let mut handles = HandleStore::new();
    let mut r = CallToolResult::success(vec![]);
    r.structured_content = Some(json!({
        "messages": [{ "id": "mm_abcdefghijklmnop", "from": IDENTITY }],
        "draft": { "id": null, "folder": "mf_abcdefghijklmnop" }
    }));
    let (out, stats) =
        sanitize_call_result(&f, "mail", c.tools.get("m"), &mut handles, &owner(), r).unwrap();
    let sc = out.structured_content.unwrap();
    assert_eq!(
        sc["messages"][0]["id"], "mm_abcdefghijklmnop",
        "a minted handle passes unchanged"
    );
    assert_eq!(sc["messages"][0]["from"], NAME_TOKEN);
    assert!(
        sc["draft"]["id"].is_null(),
        "null is allowed under a handle rule"
    );
    assert_eq!(sc["draft"]["folder"], "mf_abcdefghijklmnop");
    assert_eq!(
        stats.blocks, 3,
        "handles are blocks (validated), null is not"
    );
    {
        let seen = f.seen.lock().unwrap();
        assert!(
            seen[0]
                .iter()
                .any(|b| b.hint == FieldHint::Handle && b.text == "mm_abcdefghijklmnop")
        );
        assert!(
            !seen[0]
                .iter()
                .any(|b| b.hint == FieldHint::FreeText && b.text.starts_with("mm_")),
            "a handle is never sent as free text"
        );
    }
    // the connector omits the id of a draft it could not locate
    let mut r = CallToolResult::success(vec![]);
    r.structured_content = Some(json!({ "draft": { "folder": "mf_abcdefghijklmnop" } }));
    let (out, _) =
        sanitize_call_result(&f, "mail", c.tools.get("m"), &mut handles, &owner(), r).unwrap();
    let sc = out.structured_content.unwrap();
    assert!(
        sc["draft"].get("id").is_none(),
        "an absent handle stays absent"
    );
    // shape is not provenance: the daemon refuses, the whole result is unsupported
    let mut r = CallToolResult::success(vec![]);
    r.structured_content = Some(json!({ "messages": [{ "id": "not-a-handle", "from": "x" }] }));
    assert!(matches!(
        sanitize_call_result(&f, "mail", c.tools.get("m"), &mut handles, &owner(), r),
        Err(ContentError::Unsupported("handle_provenance"))
    ));
    // a number, a boolean, or an object under a handle rule is unsupported
    let mut r = CallToolResult::success(vec![]);
    r.structured_content = Some(json!({ "messages": [{ "id": 7, "from": "x" }] }));
    assert!(matches!(
        sanitize_call_result(&f, "mail", c.tools.get("m"), &mut handles, &owner(), r),
        Err(ContentError::Unsupported("number"))
    ));
    let mut r = CallToolResult::success(vec![]);
    r.structured_content = Some(json!({ "messages": [{ "id": true, "from": "x" }] }));
    assert!(matches!(
        sanitize_call_result(&f, "mail", c.tools.get("m"), &mut handles, &owner(), r),
        Err(ContentError::Unsupported("scalar_rule"))
    ));
    let mut r = CallToolResult::success(vec![]);
    r.structured_content =
        Some(json!({ "messages": [{ "id": { "x": "mm_abcdefghijklmnop" }, "from": "x" }] }));
    assert!(sanitize_call_result(&f, "mail", c.tools.get("m"), &mut handles, &owner(), r).is_err());
    // valid for tool arguments; refused for prompt arguments and template parameters
    assert!(
        Contract::parse(r#"{ "tools": { "m": { "arguments": { "/id": "handle" } } } }"#).is_ok()
    );
    assert!(matches!(
        Contract::parse(r#"{ "prompts": { "p": { "arguments": { "/id": "handle" } } } }"#),
        Err(ContractError::Rule(_))
    ));
    assert!(matches!(
        Contract::parse(
            r#"{ "resource_templates": { "mem://x/{id}": { "params": { "id": "handle" } } } }"#
        ),
        Err(ContractError::Rule(_))
    ));
}

/// The contract inumaki-mail ships parses under the `handle` rule (T4 carry).
#[test]
fn the_shipped_mail_contract_parses() {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../inumaki-mail/contract.json"
    ))
    .unwrap();
    let c = Contract::parse(&text).unwrap();
    let draft = c.tools["mail_draft_reply"].result.as_ref().unwrap();
    assert_eq!(draft.get("/draft/id"), Some(&Rule::Handle));
    assert_eq!(
        c.tools["mail_search"].arguments.get("/folder"),
        Some(&Rule::Handle)
    );
}
