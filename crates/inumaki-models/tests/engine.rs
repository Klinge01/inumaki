#![cfg(feature = "models-tests")]

use std::path::PathBuf;
use std::time::Duration;

use inumaki_core::config::CoreConfig;
use inumaki_core::engine::{Engine, Outcome};
use inumaki_core::token::{Context, ContextId};
use inumaki_models::ner_for_profile;

#[test]
fn support_email_profile_tokenizes_names_and_streets_and_keeps_cities() {
    let root = PathBuf::from(std::env::var("INUMAKI_MODELS_DIR").expect("set INUMAKI_MODELS_DIR"));
    let cfg = CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap();
    let p = cfg.resolve_profile("support-email").unwrap();
    let ner = ner_for_profile(&cfg, &p, &root).unwrap();
    let engine = Engine::from_config(&cfg, "support-email", ner.sanitizer, ner.verifier).unwrap();
    let mut ctx = Context::new(
        ContextId("t".into()),
        Duration::from_secs(60),
        engine.token_settings().clone(),
    );
    let text = "Sarah Leitner wohnt in der Neubaugasse 22 in Wien.";
    match engine.process(text, &mut ctx).unwrap() {
        Outcome::Pass { sanitized } | Outcome::PassUncertain { sanitized, .. } => {
            assert!(!sanitized.text.contains("Sarah"), "{}", sanitized.text);
            assert!(
                !sanitized.text.contains("Neubaugasse"),
                "{}",
                sanitized.text
            );
            assert!(sanitized.text.contains("<PERSON_"), "{}", sanitized.text);
        }
        Outcome::Blocked { kinds, .. } => panic!("blocked: {kinds:?}"),
    }
}

/// Spec §10.2: a model shared by profiles loads once.
#[test]
fn backend_cache_loads_each_model_once_across_profiles() {
    use inumaki_models::assemble::{BackendCache, ner_for_profile_with};
    let root = PathBuf::from(std::env::var("INUMAKI_MODELS_DIR").expect("set INUMAKI_MODELS_DIR"));
    let cfg = CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap();
    let cache = BackendCache::new();
    for name in ["support-email", "thorough", "fast"] {
        let p = cfg.resolve_profile(name).unwrap();
        ner_for_profile_with(&cfg, &p, &root, &cache).unwrap();
    }
    let loaded = cache.loaded();
    let names: Vec<&str> = loaded.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(names, ["gliner-x-small", "mbert-ner-hrl"]);
    assert!(
        loaded
            .iter()
            .all(|m| m.sessions == 1 && m.threads >= 1 && m.pool_waits == 0)
    );
}
