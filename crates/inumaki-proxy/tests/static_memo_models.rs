#![cfg(feature = "models-tests")]
//! The determinism stop condition of the static-prompt NER memo (M8 spec §20,
//! amendment 2026-10-12; plan Task 0b): the memo returns a stored NER result
//! in place of a later call, which is sound only when the model returns the
//! same spans for the same text however the calls interleave.
//!
//! The backends are built the way the daemon builds them
//! (`ner_for_profile_with` over one shared `BackendCache`, the default
//! config's `threads`, `sessions` raised to 2 so concurrent calls run in
//! parallel sessions). For the sanitizer and the verifier NER of
//! `support-email` and of `fast` (`fast` has no verifier NER), and for four
//! inputs, 3 rounds of 4 concurrent calls from 4 threads run, the process's
//! cold first call to each model included. One input is meant to overflow a
//! chunk's token budget (the `InputTooLong` split path; argued, not observed).
//! Start, end, kind and the bit
//! pattern of the confidence must be equal across all 12 calls of a
//! (detector, input) pair. Failures print counts, offsets and kinds only,
//! never text.
//!
//! The `InputTooLong` split is a pure function of the input bytes (argued, not
//! observed): `predict_into` splits only when the backend answers
//! `InputTooLong`, which depends on the tokenizer's token count for these
//! bytes, and the split point is `chunks(text, len / 2 + 1, min(overlap,
//! half / 2))`, which depends only on the bytes and fixed construction
//! constants: no thread count, pool or timing input.
//!
//! The test is slow (about 23 minutes in debug), so it is `#[ignore]`d and run
//! in release in the final gate:
//! `INUMAKI_MODELS_DIR=... cargo test --release -p inumaki-proxy --features
//! models-tests --test static_memo_models -- --ignored`

use std::sync::{Barrier, Mutex, PoisonError};

use inumaki_core::config::CoreConfig;
use inumaki_core::detect::{DetectCtx, Detector};
use inumaki_core::span::Span;
use inumaki_models::{BackendCache, ner_for_profile_with, resolve_models_dir};
use inumaki_proxy::bench_text::harness_system;

const ROUNDS: usize = 3;
const THREADS: usize = 4;

/// A German synthetic business mail: invented names and numbers.
const GERMAN_MAIL: &str = "Betreff: Rückfrage zur Rechnung\n\n\
Sehr geehrte Frau Mustermann,\n\n\
vielen Dank für Ihre Nachricht vom Montag. Die Lieferung an die Musterstraße 12, \
1010 Wien, wurde gestern durch Herrn Erwin Beispiel von der Beispiel Handels GmbH \
quittiert. Bitte überweisen Sie den offenen Betrag auf das Konto AT61 1904 3002 3457 3201 \
und melden Sie sich unter +43 1 234 5678 oder per E-Mail an erwin.beispiel@beispiel.example, \
falls Sie Fragen haben. Unsere Kundennummer lautet K-123456.\n\n\
Mit freundlichen Grüßen\nMax Muster\nGeschäftsführer, Muster & Söhne KG, Graz\n";

/// Dense non-ASCII text, several chunks long: German with diacritics, then
/// Cyrillic, Japanese, Chinese and Greek.
fn dense_non_ascii() -> String {
    let blocks = [
        "Übergrößenträger müssen für äußerst schwierige Zuständigkeitsfragen \
         Gebührenbescheide überprüfen lassen, weil Ärztinnen und Ärzte, Bürgermeister \
         und Straßenbahnfahrer Größenordnungen anders beurteilen. ",
        "Это тестовый текст для проверки обработки длинных русских предложений \
         с большим количеством символов, а также имён, таких как Иван Петров из Москвы. ",
        "これは長い日本語の文章を処理するための試験用の文章です。東京の山田太郎さんが \
         大阪の会社に連絡しました。住所は東京都千代田区です。 ",
        "这是一段用于测试长中文句子处理的示例文本。李明在北京的公司工作,\
         他的同事王芳住在上海。请根据需要联系他们。 ",
        "Ελληνικό κείμενο δοκιμής με πολλούς χαρακτήρες και ονόματα όπως ο Γιώργος \
         Παπαδόπουλος από την Αθήνα. ",
    ];
    let mut out = String::new();
    let mut i = 0usize;
    while out.len() < 48 * 1024 {
        out.push_str(blocks[i % blocks.len()]);
        i += 1;
    }
    out
}

/// Text meant to tokenize at about one token per byte or more: single digits
/// and punctuation (each its own token) with a short name every so often. A
/// chunk is `3 x max_input_tokens` bytes, so a chunk of this text should
/// exceed the model's input limit and make the backend answer `InputTooLong`,
/// which the detector handles by splitting. That the split path is taken is
/// argued from the tokenization, not observed: the backends are not reachable
/// through `NerPair` and `inumaki-models` is not to be touched.
fn token_dense() -> String {
    let mut out = String::new();
    let mut i = 0usize;
    while out.len() < 48 * 1024 {
        let d = |k: usize| char::from(b'0' + ((i + k) % 10) as u8);
        out.push_str(&format!("{};{},{}.{}:{} ", d(1), d(3), d(5), d(7), d(9)));
        if i % 12 == 0 {
            out.push_str("Max Muster ");
        }
        i += 1;
    }
    out
}

/// What must be equal across calls, as plain data.
type Key = Vec<(usize, usize, String, u32)>;

fn key(spans: &[Span]) -> Key {
    spans
        .iter()
        .map(|s| {
            (
                s.start,
                s.end,
                format!("{:?}", s.kind),
                s.confidence.to_bits(),
            )
        })
        .collect()
}

/// One round: `THREADS` calls started together.
fn round(det: &dyn Detector, text: &str, ctx: &DetectCtx) -> Vec<Key> {
    let barrier = Barrier::new(THREADS);
    let out = Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for _ in 0..THREADS {
            s.spawn(|| {
                barrier.wait();
                let spans = det.detect(text, ctx).expect("NER call failed");
                out.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(key(&spans));
            });
        }
    });
    out.into_inner().unwrap_or_else(PoisonError::into_inner)
}

/// Offsets and kinds only: how `got` differs from `want`.
fn describe_diff(want: &Key, got: &Key) -> String {
    let only_got: Vec<_> = got
        .iter()
        .filter(|g| !want.contains(g))
        .map(|g| format!("{}..{} {} conf-bits {:#x}", g.0, g.1, g.2, g.3))
        .collect();
    let only_want: Vec<_> = want
        .iter()
        .filter(|w| !got.contains(w))
        .map(|w| format!("{}..{} {} conf-bits {:#x}", w.0, w.1, w.2, w.3))
        .collect();
    format!(
        "{} spans vs {}; only in this call: [{}]; only in the first: [{}]",
        got.len(),
        want.len(),
        only_got.join("; "),
        only_want.join("; ")
    )
}

#[test]
#[ignore = "slow (about 23 min in debug): run in --release in the final gate"]
#[allow(clippy::print_stderr)]
fn ner_results_are_identical_across_concurrent_calls() {
    let mut cfg = CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap();
    // The daemon's `threads` (the default config's 0, which selects
    // min(4, cores)); `sessions` of 2 so concurrent calls use different sessions.
    assert_eq!(cfg.ner.threads, 0, "the default config's threads changed");
    cfg.ner.sessions = 2;
    let root = resolve_models_dir(None, cfg.ner.models_dir.as_deref());
    let cache = BackendCache::new();
    let mut detectors: Vec<(&str, std::sync::Arc<dyn Detector>)> = Vec::new();
    for profile in ["support-email", "fast"] {
        let p = cfg.resolve_profile(profile).unwrap();
        let pair =
            ner_for_profile_with(&cfg, &p, &root, &cache).expect("models (INUMAKI_MODELS_DIR)");
        match profile {
            "support-email" => {
                detectors.push((
                    "support-email sanitizer",
                    pair.sanitizer.expect("support-email has a sanitizer NER"),
                ));
                detectors.push((
                    "support-email verifier",
                    pair.verifier.expect("support-email has a verifier NER"),
                ));
            }
            _ => {
                detectors.push((
                    "fast sanitizer",
                    pair.sanitizer.expect("fast has a sanitizer NER"),
                ));
                // The plan names the verifier NER of `fast`; the profile has none.
                assert!(
                    pair.verifier.is_none(),
                    "fast now has a verifier NER: add it"
                );
            }
        }
    }
    let inputs: [(&str, String); 4] = [
        ("harness text", harness_system(20 * 1024)),
        ("german mail", GERMAN_MAIL.to_string()),
        ("dense non-ascii", dense_non_ascii()),
        ("token-dense ascii", token_dense()),
    ];
    let mut failures: Vec<String> = Vec::new();
    for (dname, det) in &detectors {
        for (iname, text) in &inputs {
            let ctx = DetectCtx::for_text(text);
            let mut calls: Vec<Key> = Vec::new();
            for _ in 0..ROUNDS {
                calls.extend(round(det.as_ref(), text, &ctx));
            }
            assert_eq!(calls.len(), ROUNDS * THREADS);
            let first = &calls[0];
            // Non-vacuity: a backend that returns nothing must not pass. The
            // harness text is expected to hold spans only for the gliner
            // sanitizer (the other models find none in it).
            if *iname != "harness text" || *dname == "support-email sanitizer" {
                assert!(
                    !first.is_empty(),
                    "{dname} / {iname}: the NER returned no spans"
                );
            }
            let differing: Vec<usize> = (1..calls.len()).filter(|&i| &calls[i] != first).collect();
            eprintln!(
                "{dname} / {iname} ({} bytes): {} spans, {} of {} calls differ from the first",
                text.len(),
                first.len(),
                differing.len(),
                calls.len()
            );
            if let Some(&i) = differing.first() {
                failures.push(format!(
                    "{dname} / {iname}: {} of {} calls differ; first difference is call {i}: {}",
                    differing.len(),
                    calls.len(),
                    describe_diff(first, &calls[i])
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "the memo's premise does not hold:\n{}",
        failures.join("\n")
    );
}
