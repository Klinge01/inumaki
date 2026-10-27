use std::time::Duration;

use inumaki_core::config::TokenSettings;
use inumaki_core::policy::{Action, Decision};
use inumaki_core::rehydrate::Rehydrator;
use inumaki_core::sanitize::sanitize;
use inumaki_core::span::{DetectorId, EntityKind, Span};
use inumaki_core::token::{Context, ContextId};
use proptest::prelude::*;

fn kind_strategy() -> impl Strategy<Value = EntityKind> {
    prop_oneof![
        Just(EntityKind::Person),
        Just(EntityKind::Email),
        Just(EntityKind::Iban),
        Just(EntityKind::City),
    ]
}

/// A document is a sequence of words; some words are entities (unique, non-dictionary tokens).
fn doc_strategy() -> impl Strategy<Value = (String, Vec<(usize, usize, EntityKind)>)> {
    let word = prop_oneof![
        "[a-zäöüß]{1,8}",
        "[😀-🙏]{1,2}",
        Just(",".to_string()),
        Just("\n".to_string()),
    ];
    prop::collection::vec(
        (word, proptest::bool::weighted(0.3), kind_strategy()),
        0..40,
    )
    .prop_map(|items| {
        let mut text = String::new();
        let mut spans = Vec::new();
        for (i, (w, is_entity, kind)) in items.into_iter().enumerate() {
            if !text.is_empty() {
                text.push(' ');
            }
            let start = text.len();
            if is_entity {
                text.push_str(&format!("Ent{i}Xq"));
                spans.push((start, text.len(), kind));
            } else {
                text.push_str(&w);
            }
        }
        (text, spans)
    })
}

fn settings_strategy() -> impl Strategy<Value = TokenSettings> {
    prop_oneof![
        Just(TokenSettings::default()),
        Just(TokenSettings {
            suffix_len: 6,
            open: "{{".into(),
            close: "}}".into(),
            ..TokenSettings::default()
        }),
        Just(TokenSettings {
            // M4 spec §5.3: the rehydrator now recognizes 4- to 12-hex
            // suffixes regardless of `suffix_len`, matching the config
            // loader's own 4..=12 validation (`CoreConfig` §config.rs); a
            // shorter suffix is not a configuration this system can produce.
            suffix_len: 4,
            open: "[[".into(),
            close: "]]".into(),
            ..TokenSettings::default()
        }),
    ]
}

proptest! {
    #[test]
    fn sanitize_then_rehydrate_restores_original((text, spans) in doc_strategy(), settings in settings_strategy()) {
        let mut ctx = Context::new(ContextId("p".into()), Duration::from_secs(60), settings.clone());
        let decisions: Vec<Decision> = spans
            .iter()
            .map(|(s, e, k)| Decision { span: Span::new(*s, *e, k.clone(), 0.9, DetectorId::Ner), action: Action::Tokenize })
            .collect();
        let sanitized = sanitize(&text, &decisions, &mut ctx).unwrap();

        // every tokenized original is gone from the candidate
        for (s, e, _) in &spans {
            prop_assert!(!sanitized.text.contains(&text[*s..*e]));
        }
        // every out_range is a char boundary and holds the token
        for r in &sanitized.replacements {
            prop_assert!(sanitized.text.is_char_boundary(r.out_range.start));
            prop_assert!(sanitized.text.is_char_boundary(r.out_range.end));
            prop_assert_eq!(&sanitized.text[r.out_range.clone()], r.token.as_ref().unwrap().as_str());
        }
        // tokens are unique
        let mut toks: Vec<&str> = sanitized.replacements.iter().map(|r| r.token.as_ref().unwrap().as_str()).collect();
        let n = toks.len();
        toks.sort();
        toks.dedup();
        prop_assert_eq!(toks.len(), n);

        let (back, unknown) = Rehydrator::new(&settings).rehydrate(&sanitized.text, &ctx);
        prop_assert_eq!(back, text);
        prop_assert_eq!(unknown, 0);
    }
}

/// The offline engine (no models) over the shipped configuration.
fn offline_engine() -> inumaki_core::Engine {
    let cfg =
        inumaki_core::CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap();
    inumaki_core::Engine::from_config(&cfg, "offline", None, None).unwrap()
}

fn fresh_ctx() -> Context {
    Context::new(
        ContextId("home".into()),
        Duration::from_secs(60),
        TokenSettings::default(),
    )
}

/// L127: a home-folder path is tokenized, keeps its shape, and rehydrates to
/// the original, under both origins; a generic login stays in clear.
#[test]
fn home_folder_paths_round_trip_in_both_origins() {
    use inumaki_core::{Outcome, TextOrigin};
    let text = "cwd /Users/mhuber/projekte/app, Notizen in ~mhuber/notes, \
                Kopie unter C:\\Users\\mhuber\\Documents\\x.docx, CI unter /Users/runner/work";
    let engine = offline_engine();
    for origin in [TextOrigin::Free, TextOrigin::HarnessStatic] {
        let mut ctx = fresh_ctx();
        let Outcome::Pass { sanitized } =
            engine.process_with_at(text, &mut ctx, &[], origin).unwrap()
        else {
            panic!("{origin:?}: not a pass");
        };
        let out = &sanitized.text;
        assert!(out.contains("/Users/<PERSON_"), "{origin:?}: {out}");
        assert!(out.contains("/Users/runner/work"), "{origin:?}: {out}");
        assert!(!out.contains("mhuber"), "{origin:?}: {out}");
        // The three logins carry one token.
        let toks: Vec<&str> = sanitized
            .replacements
            .iter()
            .filter(|r| &text[r.span.start..r.span.end] == "mhuber")
            .map(|r| r.token.as_ref().expect("tokenized").as_str())
            .collect();
        assert_eq!(toks.len(), 3, "{origin:?}: {out}");
        assert!(toks.iter().all(|t| *t == toks[0]), "{origin:?}: {out}");
        let (back, unknown) = Rehydrator::new(&TokenSettings::default()).rehydrate(out, &ctx);
        assert_eq!(back, text, "{origin:?}");
        assert_eq!(unknown, 0);
    }
}

/// L131 (rulings L3-28, L3-29): a rare document word as a home login and a
/// `~login` without a slash are tokenized end to end, not refused.
#[test]
fn rare_word_and_tilde_logins_are_tokenized_end_to_end() {
    use inumaki_core::{Outcome, TextOrigin};
    let engine = offline_engine();
    for (text, login) in [
        ("Pfad /home/steuer/ prüfen", "steuer"),
        ("Pfad C:\\Users\\Preis\\ prüfen", "Preis"),
        ("Notizen (~mhuber) ansehen", "mhuber"),
    ] {
        for origin in [TextOrigin::Free, TextOrigin::HarnessStatic] {
            let mut ctx = fresh_ctx();
            let Outcome::Pass { sanitized } =
                engine.process_with_at(text, &mut ctx, &[], origin).unwrap()
            else {
                panic!("{text} {origin:?}: not a pass");
            };
            assert!(
                !sanitized.text.contains(login),
                "{origin:?}: {}",
                sanitized.text
            );
            assert!(
                sanitized.text.contains("<PERSON_"),
                "{origin:?}: {}",
                sanitized.text
            );
            let (back, unknown) =
                Rehydrator::new(&TokenSettings::default()).rehydrate(&sanitized.text, &ctx);
            assert_eq!(back, text, "{origin:?}");
            assert_eq!(unknown, 0, "{origin:?}");
        }
    }
}
