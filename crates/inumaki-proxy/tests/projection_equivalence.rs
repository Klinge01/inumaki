#![cfg(feature = "models-tests")]
//! Differential harness (M8 spec §20, 2026-10-12; ruling L2-02): projection
//! of a cached text against today's full re-run, over the eval corpora and
//! adversarial fixtures. Prints counts and kind labels only.
//!
//! Each case: a fresh context; `T0` = the full engine's output for a corpus
//! text; one store value minted (as a later turn of the conversation would);
//! `P` = `Engine::project(T0)`; then the full re-run of the original text on
//! the same context with the closure's redactions (the shadow mode's order).
//! Hard checks on every projected case: no store form in clear in `P`
//! (the consistency dictionary), no leak in `P` by the verifier's leak check
//! (its per-call build, an automaton independent of the store's index),
//! every clear word of `P` is a clear word of `T0` (the clear-byte
//! invariant), every word of a D1 replacement that `P` keeps in clear is a
//! clear word of `T0`, and every clear word of a D2 candidate is a clear
//! word of `T0`. Measured: D1, a value the full re-run tokenizes or removes
//! that `P` keeps in clear (by kind), and D2, a full re-run that does not
//! pass (by outcome label).
//!
//! The minted values, one per case, by source (ruling L2-13; one report
//! line each):
//! - `gold-in-clear`: every gold span of any kind whose text `T0` still holds
//!   in clear (a recall miss, or a kind the policy preserves), minted as its
//!   gold kind; for a PERSON also each of its name parts in clear.
//! - `capitalized`: up to 8 capitalized clear words of `T0` with 4 or more
//!   letters (not a common or salutation word), each minted as PERSON: the
//!   open-ended mints of an NER false positive.
//! - `own-gold`: the plan's cases, each gold PERSON and its name parts.
//! - `adversarial`: the fixtures below.
//!
//! Runs only with `INUMAKI_PROJECTION_HARNESS=1` (and `INUMAKI_MODELS_DIR`):
//! `INUMAKI_PROJECTION_DOCS` documents per corpus family (default 200),
//! sharded by document with `INUMAKI_PROJECTION_SHARD=i/n` (default `0/1`).
//! The 2 000-case minimum (plan Task 7, review P9, ruling L2-13) counts
//! *projected* cases of `gold-in-clear` and `capitalized`, summed over
//! shards. For those two sources `t0_not_pass` counts documents, for the
//! others cases. The adversarial fixtures run in shard 0 only, so a sum
//! over shards counts them once.

use inumaki_core::Verdict;
use inumaki_core::config::CoreConfig;
use inumaki_core::consistency::StoreDict;
use inumaki_core::detect::regex::RegexDetector;
use inumaki_core::engine::{Engine, Outcome, Projection, ProjectionScratch, real_token};
use inumaki_core::policy::{Action, VerifierSettings};
use inumaki_core::redact::RedactionAction;
use inumaki_core::rehydrate::Rehydrator;
use inumaki_core::sanitize::Sanitized;
use inumaki_core::span::{DetectorId, EntityKind, Span};
use inumaki_core::token::{Context, ContextId, NormKey, TokenStore, normalize};
use inumaki_core::verify::{CheckId, SecondPassVerifier};
use inumaki_eval::generate::{GenFamily, GenOptions, generate};
use std::collections::{BTreeMap, HashSet};
use std::ops::Range;
use std::time::Duration;

const ADVERSARIAL: &[(&str, &str)] = &[
    (
        "Kanzlei Dr. Huber und Dr. Quorvel Rechtsanwälte OG, Wien.",
        "Lena Quorvel",
    ),
    (
        "Mehr unter www.quorvel-huber.at oder telefonisch.",
        "Lena Quorvel",
    ),
    ("Eva Quorvel hat gestern angerufen.", "Lena Quorvel"),
    (
        "Quorvel war da. Rückruf bitte an Thomas, morgen.",
        "Lena Quorvel",
    ),
    ("Mit freundlichen Grüßen\nEva\nQuorvel", "Lena Quorvel"),
    ("bitte eva quorvel zurückrufen", "Lena Quorvel"),
    ("Herr Quorvel und Frau Berger kommen.", "Lena Quorvel"),
];

/// Counts and labels only (F24: no R1/R2 here; those come from the shadow
/// counters).
#[derive(Default)]
struct Tally {
    /// `T0` did not pass, so there was nothing cached to project.
    t0_not_pass: u64,
    attempted: u64,
    projected: u64,
    abandoned: BTreeMap<String, u64>,
    invariant: u64,
    form_in_clear: u64,
    /// The verifier's leak check (per-call build: `verify_with_leak` with no
    /// index) found a store value in clear in `P` (a hard failure).
    leak_in_p: u64,
    /// The same leak check on `T0` after the mint (the value minted is in
    /// clear there for sources (i) and (ii)): the check's liveness, so
    /// `leak_in_p = 0` is not a check that never fires.
    leak_in_t0: u64,
    d1: BTreeMap<String, u64>,
    d2: BTreeMap<String, u64>,
    /// Ruling L77, on every D2 case: clear words of the full re-run's
    /// candidate that are clear words of `T0` (already sent) or not
    /// (`d2_words_outside`, a hard failure). The verifier's flagged span
    /// ranges are not public (`Reason` carries kind and check only), so
    /// this checks a superset: every clear word of the candidate, which
    /// holds every clear word of every flagged span (`check_ner` reads the
    /// candidate with its tokens masked).
    d2_words_already_sent: u64,
    d2_words_outside: u64,
    /// The integrator's D1 condition, on every D1 replacement: the words of
    /// its slice that are clear in `P` and are clear words of `T0` (already
    /// sent) or not (`d1_words_outside`, a hard failure). Word-set based like
    /// L77, not positional, and blind to runs of fewer than 2 letters.
    d1_words_already_sent: u64,
    d1_words_outside: u64,
}

fn engine(cfg: &CoreConfig, profile: &str) -> Engine {
    let p = cfg.resolve_profile(profile).unwrap();
    let root = inumaki_models::resolve_models_dir(None, cfg.ner.models_dir.as_deref());
    let ner = inumaki_models::ner_for_profile(cfg, &p, &root).expect("models (INUMAKI_MODELS_DIR)");
    Engine::from_config(cfg, profile, ner.sanitizer, ner.verifier).unwrap()
}

/// Byte ranges of the token-shaped substrings of `text`.
fn token_ranges(tokens: &regex::Regex, text: &str) -> Vec<Range<usize>> {
    tokens.find_iter(text).map(|m| m.range()).collect()
}

/// Whether `start..end` lies inside a token-shaped substring of `text` that
/// is a real token of `store` (the service's covered rule).
fn token_at(
    store: &dyn TokenStore,
    tokens: &regex::Regex,
    text: &str,
    start: usize,
    end: usize,
) -> bool {
    tokens
        .find_iter(text)
        .any(|m| m.start() <= start && end <= m.end() && real_token(store, m.as_str()))
}

/// Whether the verifier's leak check finds a store value of `store` in
/// clear in `p`. The leak check runs with no index, so it builds its own
/// automaton from the store for this call (independent of the store's
/// cached leak index and of the projector's dictionary). `P`'s tokens are
/// its token-shaped substrings that are real tokens of `store`, passed as
/// protected ranges. A leak fails first, so a `Fail` carrying a `Leak`
/// reason is exactly the leak check's answer; the later re-scans are not
/// read.
fn leak_in(leak: &SecondPassVerifier, store: &Context, tokens: &regex::Regex, p: &str) -> bool {
    let s = Sanitized {
        text: p.to_string(),
        replacements: Vec::new(),
        blocked: Vec::new(),
        escalated: Vec::new(),
        protected: tokens
            .find_iter(p)
            .filter(|m| real_token(store, m.as_str()))
            .map(|m| m.range())
            .collect(),
    };
    matches!(
        leak.verify_with_leak(&s, store, None),
        Verdict::Fail(rs) if rs.iter().any(|r| r.check == CheckId::Leak)
    )
}

/// The words of `text`: maximal alphanumeric runs with two or more letters,
/// as normalized keys (lower-cased, diacritics folded, `ß` → `ss`).
fn words(text: &str) -> Vec<NormKey> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.chars().filter(|c| c.is_alphabetic()).count() >= 2)
        .map(normalize)
        .collect()
}

/// [`words`] of `text` outside its token-shaped substrings.
fn clear_words(tokens: &regex::Regex, text: &str) -> HashSet<NormKey> {
    let mut out = HashSet::new();
    let mut at = 0;
    for r in token_ranges(tokens, text) {
        out.extend(words(&text[at..r.start]));
        at = r.end;
    }
    out.extend(words(&text[at..]));
    out
}

/// The clear segments of `text`: the stretches between its token-shaped
/// substrings.
fn clear_segments<'a>(tokens: &regex::Regex, text: &'a str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut at = 0;
    for r in token_ranges(tokens, text) {
        out.push(&text[at..r.start]);
        at = r.end;
    }
    out.push(&text[at..]);
    out
}

/// Whether `value` occurs word-bounded in a clear segment of `t0`.
fn in_clear(segments: &[&str], value: &str) -> bool {
    let bounded = |seg: &str, i: usize| {
        let before = seg[..i].chars().next_back();
        let after = seg[i + value.len()..].chars().next();
        !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
    };
    !value.trim().is_empty()
        && segments
            .iter()
            .any(|seg| seg.match_indices(value).any(|(i, _)| bounded(seg, i)))
}

/// Source (i): gold spans `T0` holds in clear, as their gold kind; for a
/// PERSON also its name parts in clear. Deduplicated.
fn gold_in_clear<'a>(
    doc: &'a inumaki_eval::corpus::Doc,
    segments: &[&str],
) -> Vec<(EntityKind, &'a str)> {
    let mut out: Vec<(EntityKind, &str)> = Vec::new();
    for g in &doc.spans {
        let kind = EntityKind::from_label(&g.kind);
        let v = &doc.text[g.start..g.end];
        let parts = (kind == EntityKind::Person)
            .then(|| inumaki_core::stoplist::name_parts(v))
            .into_iter()
            .flatten();
        for value in std::iter::once(v).chain(parts) {
            if in_clear(segments, value) && !out.iter().any(|(k, w)| *k == kind && *w == value) {
                out.push((kind.clone(), value));
            }
        }
    }
    out
}

/// Source (ii): up to 8 capitalized clear words of `T0` with 4 or more
/// letters, not a common or salutation word, and not a PERSON value of
/// source (i) (`gold`). Deduplicated.
fn capitalized<'a>(segments: &[&'a str], gold: &[(EntityKind, &str)]) -> Vec<&'a str> {
    let mut out: Vec<&str> = Vec::new();
    for w in segments
        .iter()
        .flat_map(|seg| seg.split(|c: char| !c.is_alphanumeric()))
    {
        if out.len() == 8 {
            break;
        }
        if w.chars().next().is_some_and(char::is_uppercase)
            && w.chars().all(char::is_alphabetic)
            && w.chars().count() >= 4
            && !inumaki_core::stoplist::is_common_word(w)
            && !inumaki_core::stoplist::is_salutation_word(w)
            && !out.contains(&w)
            && !gold
                .iter()
                .any(|(k, v)| *k == EntityKind::Person && *v == w)
        {
            out.push(w);
        }
    }
    out
}

/// Variant, check ids, and kind labels of a non-passing outcome; no text.
fn outcome_label(o: &Outcome) -> String {
    let reasons = |rs: &[inumaki_core::Reason]| {
        rs.iter()
            .map(|r| format!("{:?}/{}", r.check, r.kind.label()))
            .collect::<Vec<_>>()
            .join(",")
    };
    match o {
        Outcome::Pass { .. } => "Pass(no candidate)".into(),
        Outcome::PassUncertain { reasons: rs, .. } => format!("PassUncertain[{}]", reasons(rs)),
        Outcome::Blocked { reasons: rs, kinds } => format!(
            "Blocked[{}][{}]",
            reasons(rs),
            kinds
                .iter()
                .map(|k| k.label().to_string())
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

/// One case: fresh context; T0; mint `value`; project; full re-run on the
/// same context (the shadow mode's order); compare.
fn case(
    e: &Engine,
    leak: &SecondPassVerifier,
    tokens: &regex::Regex,
    text: &str,
    kind: &EntityKind,
    value: &str,
    t: &mut Tally,
) {
    let mut c = Context::new(
        ContextId("h".into()),
        Duration::from_secs(600),
        e.token_settings().clone(),
    );
    let Ok(Outcome::Pass { sanitized }) = e.process(text, &mut c) else {
        t.t0_not_pass += 1;
        return;
    };
    let t0 = sanitized.text;
    c.token_for(kind, value).unwrap();
    t.attempted += 1;
    if leak_in(leak, &c, tokens, &t0) {
        t.leak_in_t0 += 1;
    }
    let p = match e
        .project(
            &t0,
            &mut c,
            &|_, _| Ok(true),
            &mut ProjectionScratch::default(),
        )
        .unwrap()
    {
        Projection::Projected { text, .. } => {
            t.projected += 1;
            text
        }
        Projection::Abandoned { reason, .. } => {
            *t.abandoned.entry(format!("{reason:?}")).or_default() += 1;
            return;
        }
        Projection::Inconsistent => panic!("inconsistent projection"),
    };
    // hard: no store form in clear in P (the consistency dictionary)
    let d = StoreDict::build(&c).unwrap();
    if d.uncovered_match(&p, |a, b| token_at(&c, tokens, &p, a, b))
        .unwrap()
        .is_some()
    {
        t.form_in_clear += 1;
    }
    // hard: no leak in P by the verifier's own leak check (per-call build)
    if leak_in(leak, &c, tokens, &p) {
        t.leak_in_p += 1;
    }
    // hard: every clear word of P is in T0
    let clear_p = clear_words(tokens, &p);
    let clear_t0 = clear_words(tokens, &t0);
    if !clear_p.iter().all(|w| clear_t0.contains(w)) {
        t.invariant += 1;
    }
    // the full re-run with the closure redactions (all store forms)
    let nfc = inumaki_core::engine::normalize_input(text).into_owned();
    // P9: the closure's semantics (`pipeline::closure_redactions`): a match
    // of a kind the profile removes becomes a removal.
    let reds: Vec<_> = d
        .redactions(&nfc, &[], &[])
        .unwrap()
        .into_iter()
        .map(|m| {
            let mut r = m.redaction;
            let span = Span::new(
                r.start,
                r.end,
                EntityKind::from_label(&r.kind),
                1.0,
                DetectorId::Redaction,
            );
            if e.profile().action_for(&span) == Some(Action::Remove) {
                r.action = RedactionAction::Remove;
            }
            r
        })
        .collect();
    let full = e.process_detailed(&nfc, &mut c, &reds).unwrap();
    // D1 whenever the full re-run has a candidate, whatever its outcome
    // (as the proxy's `shadow_compare` does); D2 when it does not pass.
    if let Some(s) = &full.candidate {
        for r in &s.replacements {
            if !matches!(r.action, Action::Tokenize | Action::Remove) {
                continue;
            }
            let slice = &nfc[r.span.start..r.span.end];
            let in_p: Vec<NormKey> = words(slice)
                .into_iter()
                .filter(|w| clear_p.contains(w))
                .collect();
            if !in_p.is_empty() {
                *t.d1.entry(r.span.kind.label().to_string()).or_default() += 1;
                for w in &in_p {
                    if clear_t0.contains(w) {
                        t.d1_words_already_sent += 1;
                    } else {
                        t.d1_words_outside += 1;
                    }
                }
            }
        }
    }
    if !matches!(
        (&full.outcome, &full.candidate),
        (Outcome::Pass { .. }, Some(_))
    ) {
        *t.d2.entry(outcome_label(&full.outcome)).or_default() += 1;
        // A block on the NER re-scan judged a candidate: it must be here,
        // so the already-sent word check below is never skipped silently.
        if let Outcome::Blocked { reasons, .. } = &full.outcome
            && reasons
                .iter()
                .any(|r| r.check == inumaki_core::verify::CheckId::Ner)
        {
            assert!(
                full.candidate.is_some(),
                "a Ner block without its candidate"
            );
        }
        if let Some(s) = &full.candidate {
            for w in clear_words(tokens, &s.text) {
                if clear_t0.contains(&w) {
                    t.d2_words_already_sent += 1;
                } else {
                    t.d2_words_outside += 1;
                }
            }
        }
    }
}

/// The corpus cases of one document: sources (i) and (ii) from one
/// discovery pass of `T0`, then the plan's own-gold cases (iii). Every case
/// runs on its own fresh context.
fn corpus_doc(
    e: &Engine,
    leak: &SecondPassVerifier,
    tokens: &regex::Regex,
    d: &inumaki_eval::corpus::Doc,
    [gold, caps, own]: [&mut Tally; 3],
) {
    let mut c = Context::new(
        ContextId("d".into()),
        Duration::from_secs(600),
        e.token_settings().clone(),
    );
    if let Ok(Outcome::Pass { sanitized }) = e.process(&d.text, &mut c) {
        let segments = clear_segments(tokens, &sanitized.text);
        let gold_values = gold_in_clear(d, &segments);
        for (kind, value) in &gold_values {
            case(e, leak, tokens, &d.text, kind, value, gold);
        }
        // A (PERSON, value) case source (i) already ran counts once.
        for value in capitalized(&segments, &gold_values) {
            case(e, leak, tokens, &d.text, &EntityKind::Person, value, caps);
        }
    } else {
        gold.t0_not_pass += 1;
        caps.t0_not_pass += 1;
    }
    for g in d.spans.iter().filter(|g| g.kind == "PERSON") {
        let v = &d.text[g.start..g.end];
        for value in std::iter::once(v).chain(inumaki_core::stoplist::name_parts(v)) {
            case(e, leak, tokens, &d.text, &EntityKind::Person, value, own);
        }
    }
}

impl Tally {
    /// The sum of two tallies (the combined (i)+(ii) line).
    fn plus(&self, o: &Tally) -> Tally {
        let add = |a: &BTreeMap<String, u64>, b: &BTreeMap<String, u64>| {
            let mut m = a.clone();
            for (k, v) in b {
                *m.entry(k.clone()).or_default() += v;
            }
            m
        };
        Tally {
            t0_not_pass: self.t0_not_pass + o.t0_not_pass,
            attempted: self.attempted + o.attempted,
            projected: self.projected + o.projected,
            abandoned: add(&self.abandoned, &o.abandoned),
            invariant: self.invariant + o.invariant,
            form_in_clear: self.form_in_clear + o.form_in_clear,
            leak_in_p: self.leak_in_p + o.leak_in_p,
            leak_in_t0: self.leak_in_t0 + o.leak_in_t0,
            d1: add(&self.d1, &o.d1),
            d2: add(&self.d2, &o.d2),
            d2_words_already_sent: self.d2_words_already_sent + o.d2_words_already_sent,
            d2_words_outside: self.d2_words_outside + o.d2_words_outside,
            d1_words_already_sent: self.d1_words_already_sent + o.d1_words_already_sent,
            d1_words_outside: self.d1_words_outside + o.d1_words_outside,
        }
    }
}

fn report(t: &Tally) -> String {
    format!(
        "t0_not_pass {} attempted {} projected {} abandoned {:?} invariant {} form_in_clear {} leak_in_p {} leak_in_t0 {} d1 {:?} d2 {:?} d2_words_already_sent {} d2_words_outside {} d1_words_already_sent {} d1_words_outside {}",
        t.t0_not_pass,
        t.attempted,
        t.projected,
        t.abandoned,
        t.invariant,
        t.form_in_clear,
        t.leak_in_p,
        t.leak_in_t0,
        t.d1,
        t.d2,
        t.d2_words_already_sent,
        t.d2_words_outside,
        t.d1_words_already_sent,
        t.d1_words_outside
    )
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .map(|v| v.parse().expect("a number"))
        .unwrap_or(default)
}

/// `INUMAKI_PROJECTION_SHARD=i/n`, default `0/1`.
fn shard() -> (usize, usize) {
    let Ok(v) = std::env::var("INUMAKI_PROJECTION_SHARD") else {
        return (0, 1);
    };
    let (i, n) = v.split_once('/').expect("INUMAKI_PROJECTION_SHARD=i/n");
    let (i, n): (usize, usize) = (i.parse().unwrap(), n.parse().unwrap());
    assert!(n > 0 && i < n, "INUMAKI_PROJECTION_SHARD=i/n with i < n");
    (i, n)
}

#[test]
// The report is the harness's output: counts and kind labels only.
#[allow(clippy::print_stdout, clippy::print_stderr)]
fn projection_against_the_full_rerun_over_the_eval_corpora() {
    if std::env::var("INUMAKI_PROJECTION_HARNESS").as_deref() != Ok("1") {
        eprintln!("skipped: set INUMAKI_PROJECTION_HARNESS=1");
        return;
    }
    let cfg = CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap();
    let (shard, shards) = shard();
    let docs_per = env_usize("INUMAKI_PROJECTION_DOCS", 200);
    for profile in ["support-email"] {
        let e = engine(&cfg, profile);
        let tokens = regex::Regex::new(&Rehydrator::pattern(e.token_settings())).unwrap();
        // The leak check only (no NER re-scan is read; see `leak_in`).
        let leak = SecondPassVerifier::new(
            RegexDetector::new(),
            None,
            &VerifierSettings {
                allow_no_ner: true,
                ..VerifierSettings::default()
            },
        )
        .unwrap();
        let (mut gold, mut caps, mut own, mut adv) = Default::default();
        let mut n = 0usize;
        for (family, transforms) in [
            (GenFamily::Tuning, false),
            (GenFamily::Tuning, true),
            (GenFamily::HeldOut, false),
            (GenFamily::HeldOut, true),
        ] {
            for d in generate(&GenOptions {
                seed: 7,
                count: docs_per,
                transforms,
                family,
            }) {
                n += 1;
                if n % shards != shard {
                    continue;
                }
                corpus_doc(&e, &leak, &tokens, &d, [&mut gold, &mut caps, &mut own]);
            }
        }
        if shard == 0 {
            for (text, value) in ADVERSARIAL {
                for v in std::iter::once(*value).chain(inumaki_core::stoplist::name_parts(value)) {
                    case(&e, &leak, &tokens, text, &EntityKind::Person, v, &mut adv);
                }
            }
        }
        // counts and labels only
        let sources = [
            ("gold-in-clear", &gold),
            ("capitalized", &caps),
            ("own-gold", &own),
            ("adversarial", &adv),
        ];
        for (name, t) in sources {
            if name != "adversarial" || shard == 0 {
                println!("{profile} {name} shard {shard}/{shards}: {}", report(t));
            }
        }
        // The Task 7 gate's line: sources (i) and (ii) together.
        let both = gold.plus(&caps);
        println!(
            "{profile} (i)+(ii) shard {shard}/{shards}: attempted {} projected {} leak_in_p {} leak_in_t0 {} d1 {:?} d2 {:?} d2_words_already_sent {} d2_words_outside {} d1_words_already_sent {} d1_words_outside {}",
            both.attempted,
            both.projected,
            both.leak_in_p,
            both.leak_in_t0,
            both.d1,
            both.d2,
            both.d2_words_already_sent,
            both.d2_words_outside,
            both.d1_words_already_sent,
            both.d1_words_outside
        );
        let sum = |f: fn(&Tally) -> u64| sources.iter().map(|(_, t)| f(t)).sum::<u64>();
        assert_eq!(sum(|t| t.invariant), 0, "clear-byte invariant");
        assert_eq!(sum(|t| t.form_in_clear), 0, "store form in clear");
        assert_eq!(sum(|t| t.leak_in_p), 0, "leak check finds a value in P");
        // The leak check is live: it fires on T0 holding the minted value.
        assert!(
            both.attempted == 0 || both.leak_in_t0 > 0,
            "the leak check never fired on T0"
        );
        // L77: what the full re-run flagged where the projection forwarded
        // was already sent in T0.
        assert_eq!(sum(|t| t.d2_words_outside), 0, "d2 word outside T0");
        // The integrator's D1 condition: what projection keeps in clear where
        // the full re-run tokenizes or removes was already sent in T0.
        assert_eq!(sum(|t| t.d1_words_outside), 0, "d1 word outside T0");
    }
}
