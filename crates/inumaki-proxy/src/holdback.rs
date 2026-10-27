//! Per-channel holdback (M8 spec §6.3). The token grammar is
//! `Rehydrator::pattern`, compiled into an anchored lazy DFA. The rule:
//! hold the longest suffix of the channel's text that is still a live
//! prefix of the pattern, emit everything before it. A complete token is
//! resolved once, so an original is never scanned again (no chained
//! substitution). The cap is `Rehydrator::max_token_len`, counted with the
//! escaped delimiters in argument channels; reaching it flushes, which can
//! only leave a token unrestored.

use std::borrow::Cow;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use inumaki_core::config::TokenSettings;
use inumaki_core::rehydrate::Rehydrator;
use regex::Regex;
use regex_automata::hybrid::dfa::{Cache, DFA};
use regex_automata::{Anchored, Input};
use zeroize::Zeroizing;

use crate::error::Fail;

/// The JSON-escaped delimiter forms some providers write inside argument
/// strings (either hex case). Only used when the delimiters are `<`/`>`;
/// `{{ }}` and `[[ ]]` are never escaped by JSON.
const ESCAPED: [(&str, &str); 2] = [("\\u003c", "\\u003e"), ("\\u003C", "\\u003E")];

/// One compiled token grammar: the shared token pattern (plus, for JSON
/// argument channels with `<`/`>` delimiters, its escaped-delimiter forms).
pub struct Grammar {
    dfa: DFA,
    full: Regex,
    starts: Vec<u8>,
    cap: usize,
    open: String,
    close: String,
}

impl std::fmt::Debug for Grammar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Grammar")
            .field("cap", &self.cap)
            .finish_non_exhaustive()
    }
}

impl Grammar {
    fn build(settings: &TokenSettings, escaped: bool) -> Grammar {
        let mut variants = vec![settings.clone()];
        if escaped && settings.open == "<" && settings.close == ">" {
            for (o, c) in ESCAPED {
                variants.push(TokenSettings {
                    open: o.into(),
                    close: c.into(),
                    ..settings.clone()
                });
            }
        }
        let alt = variants
            .iter()
            .map(|s| format!("(?:{})", Rehydrator::pattern(s)))
            .collect::<Vec<_>>()
            .join("|");
        let dfa = DFA::new(&alt).expect("the shared token pattern compiles");
        let full = Regex::new(&format!("^(?:{alt})")).expect("the shared token pattern compiles");
        let mut starts: Vec<u8> = variants
            .iter()
            .filter_map(|s| s.open.bytes().next())
            .collect();
        starts.sort_unstable();
        starts.dedup();
        let cap = variants
            .iter()
            .map(Rehydrator::max_token_len)
            .max()
            .unwrap_or(0);
        Grammar {
            dfa,
            full,
            starts,
            cap,
            open: settings.open.clone(),
            close: settings.close.clone(),
        }
    }

    /// `(text channels, JSON argument channels)` for these delimiters,
    /// compiled once per process.
    pub fn for_settings(settings: &TokenSettings) -> (Arc<Grammar>, Arc<Grammar>) {
        type Entry = (String, String, Arc<Grammar>, Arc<Grammar>);
        static CACHE: OnceLock<Mutex<Vec<Entry>>> = OnceLock::new();
        let mut c = CACHE
            .get_or_init(|| Mutex::new(Vec::new()))
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some((_, _, t, a)) = c
            .iter()
            .find(|(o, cl, _, _)| *o == settings.open && *cl == settings.close)
        {
            return (Arc::clone(t), Arc::clone(a));
        }
        let (t, a) = (
            Arc::new(Grammar::build(settings, false)),
            Arc::new(Grammar::build(settings, true)),
        );
        c.push((
            settings.open.clone(),
            settings.close.clone(),
            Arc::clone(&t),
            Arc::clone(&a),
        ));
        (t, a)
    }

    /// Most bytes a holdback keeps (it always keeps fewer).
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Whether `s` is a proper prefix of some token (the anchored DFA never dies on it).
    fn live(&self, cache: &mut Cache, s: &str) -> bool {
        let input = Input::new(s).anchored(Anchored::Yes);
        let Ok(mut sid) = self.dfa.start_state_forward(cache, &input) else {
            return false;
        };
        for &b in s.as_bytes() {
            sid = match self.dfa.next_state(cache, sid, b) {
                Ok(x) => x,
                Err(_) => return false, // cache trouble: flush (only leaves a token unrestored)
            };
            if sid.is_dead() || sid.is_quit() {
                return false;
            }
        }
        true
    }

    /// The `<…>` form of a token written with escaped delimiters.
    fn normalize<'t>(&self, tok: &'t str) -> Cow<'t, str> {
        for (o, c) in ESCAPED {
            if let Some(mid) = tok.strip_prefix(o).and_then(|t| t.strip_suffix(c)) {
                return Cow::Owned(format!("{}{mid}{}", self.open, self.close));
            }
        }
        Cow::Borrowed(tok)
    }
}

/// Token (in `<…>` form) → original; `None` leaves the token as received.
pub type Resolve<'r> = dyn FnMut(&str) -> Result<Option<Zeroizing<String>>, Fail> + 'r;

/// Append to a zeroized buffer without leaving a stale copy behind: when
/// the buffer must grow, the text moves into a fresh allocation and the old
/// one is zeroized on drop (a plain `push_str` would reallocate and free the
/// old bytes as they are).
pub(crate) fn push_z(buf: &mut Zeroizing<String>, s: &str) {
    if buf.capacity() - buf.len() < s.len() {
        let want = (buf.len() + s.len()).max(buf.capacity().saturating_mul(2));
        let mut grown = Zeroizing::new(String::with_capacity(want));
        grown.push_str(buf);
        *buf = grown;
    }
    buf.push_str(s);
}

/// One channel's holdback. `Debug` prints the held length only.
pub struct Holdback {
    g: Arc<Grammar>,
    cache: Cache,
    pending: Zeroizing<String>,
    escape: bool,
    /// Whether the text already emitted ends in an odd run of backslashes,
    /// so an escaped-delimiter form at the start of `pending` is a literal
    /// `<` (`\\u003c` in JSON), not an escaped `<`.
    odd_backslashes: bool,
}

impl std::fmt::Debug for Holdback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Holdback")
            .field("held", &self.pending.len())
            .finish()
    }
}

impl Holdback {
    /// A holdback over `grammar`. `escape`: JSON-string-escape originals
    /// (argument channels, whose text is JSON).
    pub fn new(grammar: Arc<Grammar>, escape: bool) -> Holdback {
        let cache = grammar.dfa.create_cache();
        Holdback {
            g: grammar,
            cache,
            pending: Zeroizing::new(String::new()),
            escape,
            odd_backslashes: false,
        }
    }

    /// Bytes held back right now (always below the grammar's cap).
    pub fn held(&self) -> usize {
        self.pending.len()
    }

    /// Append a delta; the text that can be emitted now.
    pub fn push(
        &mut self,
        delta: &str,
        resolve: &mut Resolve<'_>,
    ) -> Result<Zeroizing<String>, Fail> {
        push_z(&mut self.pending, delta);
        self.drain(resolve, false)
    }

    /// The channel ended: everything still held.
    pub fn finish(&mut self, resolve: &mut Resolve<'_>) -> Result<Zeroizing<String>, Fail> {
        self.drain(resolve, true)
    }

    /// Whether the run of backslashes before byte `i` of `b` (continuing
    /// into the text already emitted) has even length: then a backslash at
    /// `i` starts an escape of its own.
    fn even_backslashes_before(&self, b: &[u8], i: usize) -> bool {
        let run = b[..i].iter().rev().take_while(|&&c| c == b'\\').count();
        let odd = (run % 2 == 1) ^ (run == i && self.odd_backslashes);
        !odd
    }

    /// Record that `consumed` (the input text up to the new pending start)
    /// was emitted, for the backslash parity across deltas.
    fn note_emitted(&mut self, consumed: &[u8]) {
        let run = consumed.iter().rev().take_while(|&&c| c == b'\\').count();
        let odd = run % 2 == 1;
        self.odd_backslashes = if run == consumed.len() {
            self.odd_backslashes ^ odd
        } else {
            odd
        };
    }

    fn drain(&mut self, resolve: &mut Resolve<'_>, end: bool) -> Result<Zeroizing<String>, Fail> {
        let text = std::mem::take(&mut self.pending);
        let mut out = Zeroizing::new(String::with_capacity(text.len()));
        let (mut i, mut cursor) = (0usize, 0usize);
        let b = text.as_bytes();
        while i < b.len() {
            // Start bytes are ASCII, so `i` is a character boundary here.
            if !self.g.starts.contains(&b[i]) {
                i += 1;
                continue;
            }
            let rest = &text[i..];
            if let Some(m) = self.g.full.find(rest) {
                // An escaped-delimiter form after an odd run of backslashes
                // is a literal `<…` in the JSON, not a token: skip it.
                if b[i] == b'\\' && !self.even_backslashes_before(b, i) {
                    i += 1;
                    continue;
                }
                push_z(&mut out, &text[cursor..i]);
                let tok = m.as_str();
                match resolve(&self.g.normalize(tok))? {
                    Some(o) if self.escape => {
                        let q = Zeroizing::new(crate::json::quote(&o));
                        push_z(&mut out, &q[1..q.len() - 1]);
                    }
                    Some(o) => push_z(&mut out, &o),
                    None => push_z(&mut out, tok),
                }
                i += m.end();
                cursor = i;
                continue;
            }
            if !end && rest.len() < self.g.cap && self.g.live(&mut self.cache, rest) {
                push_z(&mut out, &text[cursor..i]);
                self.note_emitted(&b[..i]);
                push_z(&mut self.pending, rest);
                return Ok(out);
            }
            i += 1;
        }
        push_z(&mut out, &text[cursor..]);
        self.note_emitted(b);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use inumaki_core::rehydrate::Rehydrator;

    fn table() -> HashMap<&'static str, &'static str> {
        HashMap::from([
            ("<PERSON_a7f2c9_3e>", "Zoë Quolnath"),
            ("<PERSON_a7f2c9>", "Zyxwuria Quolnath"),
            // An original that is itself token-shaped: must not be resolved again.
            ("<EMAIL_b1b2>", "<PERSON_a7f2c9>"),
            // Needs JSON escaping in argument channels.
            ("<NOTE_c3c3>", "O\"Brien \\ Ölz\nzwei"),
        ])
    }

    fn run(g: &Arc<Grammar>, escape: bool, parts: &[&str]) -> String {
        let t = table();
        let mut resolve = |tok: &str| -> Result<Option<Zeroizing<String>>, Fail> {
            Ok(t.get(tok).map(|o| Zeroizing::new((*o).to_string())))
        };
        let mut h = Holdback::new(Arc::clone(g), escape);
        let mut out = String::new();
        for p in parts {
            out.push_str(&h.push(p, &mut resolve).unwrap());
            assert!(h.held() < g.cap(), "held {} bytes", h.held());
        }
        out.push_str(&h.finish(&mut resolve).unwrap());
        out
    }

    /// Two-part splits at every character boundary, plus one character per part.
    fn splits(s: &str) -> Vec<Vec<&str>> {
        let bounds: Vec<usize> = (0..=s.len()).filter(|i| s.is_char_boundary(*i)).collect();
        let mut out: Vec<Vec<&str>> = bounds.iter().map(|&i| vec![&s[..i], &s[i..]]).collect();
        out.push(bounds.windows(2).map(|w| &s[w[0]..w[1]]).collect());
        out
    }

    /// Spec §15 test 10 (holdback part); Review Focus 1 and 2.
    #[test]
    fn every_split_restores_like_the_unsplit_text() {
        let (text_g, _) = Grammar::for_settings(&TokenSettings::default());
        let cases = [
            (
                "Hallo <PERSON_a7f2c9_3e>, Grüße an <PERSON_a7f2c9>!",
                "Hallo Zoë Quolnath, Grüße an Zyxwuria Quolnath!",
            ),
            ("Ende <PERSON_a7f2c9>", "Ende Zyxwuria Quolnath"),
            (
                "<PERSON_ffff> bleibt, <SECRET_REMOVED> auch",
                "<PERSON_ffff> bleibt, <SECRET_REMOVED> auch",
            ),
            (
                "kein Kettenersatz: <EMAIL_b1b2>",
                "kein Kettenersatz: <PERSON_a7f2c9>",
            ),
            (
                "a < b, <Person_abcd>, <PERSON_ab>, <<PERSON_a7f2c9>>",
                "a < b, <Person_abcd>, <PERSON_ab>, <Zyxwuria Quolnath>",
            ),
        ];
        for (input, want) in cases {
            for parts in splits(input) {
                assert_eq!(
                    run(&text_g, false, &parts),
                    want,
                    "split into {} parts",
                    parts.len()
                );
            }
        }
    }

    /// Spec §15 test 11 (holdback part): originals JSON-escaped, in the literal form and the
    /// escaped forms in both hex cases (`\u003c…\u003e` and `\u003C…\u003E`).
    #[test]
    fn argument_channels_escape_originals_in_both_delimiter_forms() {
        let (_, args_g) = Grammar::for_settings(&TokenSettings::default());
        let input = r#"{"note":"<NOTE_c3c3>","to":"\u003cNOTE_c3c3\u003e","up":"\u003CNOTE_c3c3\u003E","x":"\u003CPERSON_a7f2c9\u003E"}"#;
        for parts in splits(input) {
            let out = run(&args_g, true, &parts);
            let v: serde_json::Value = serde_json::from_str(&out)
                .unwrap_or_else(|e| panic!("not JSON ({e}), len {}", out.len()));
            assert_eq!(v["note"], "O\"Brien \\ Ölz\nzwei");
            assert_eq!(
                v["to"], "O\"Brien \\ Ölz\nzwei",
                "lower-case escaped delimiters"
            );
            assert_eq!(
                v["up"], "O\"Brien \\ Ölz\nzwei",
                "upper-case escaped delimiters"
            );
            assert_eq!(v["x"], "Zyxwuria Quolnath");
        }
    }

    /// Addendum hardening: an escaped-delimiter form preceded by an odd run
    /// of backslashes is a literal `\u003c` the model wrote (`\\u003c` in
    /// JSON), not an escaped `<`; restoring it would break the JSON. Left
    /// unchanged, in every split, including runs that span deltas.
    #[test]
    fn an_escaped_backslash_before_an_escaped_delimiter_is_left_alone() {
        let (_, args_g) = Grammar::for_settings(&TokenSettings::default());
        let odd = r#"{"a":"\\u003cNOTE_c3c3\u003e","b":"\\\\\\u003CNOTE_c3c3\u003E"}"#;
        for parts in splits(odd) {
            assert_eq!(
                run(&args_g, true, &parts),
                odd,
                "split into {} parts",
                parts.len()
            );
        }
        // An even run before it: a real escaped `<`, restored.
        let even = r#"{"a":"\\\u003cNOTE_c3c3\u003e"}"#;
        for parts in splits(even) {
            let out = run(&args_g, true, &parts);
            let v: serde_json::Value = serde_json::from_str(&out)
                .unwrap_or_else(|e| panic!("not JSON ({e}), len {}", out.len()));
            assert_eq!(v["a"], "\\O\"Brien \\ Ölz\nzwei");
        }
    }

    /// Review Focus 2: a live prefix longer than the cap is released, not held forever.
    #[test]
    fn a_long_live_prefix_is_flushed_at_the_cap() {
        let s = TokenSettings::default();
        let (g, a) = Grammar::for_settings(&s);
        assert_eq!(g.cap(), Rehydrator::max_token_len(&s));
        assert!(
            a.cap() > g.cap(),
            "the escaped delimiters count in argument channels"
        );
        let long = format!("<{}", "A".repeat(300));
        let parts: Vec<&str> = long
            .as_bytes()
            .chunks(7)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        assert_eq!(run(&g, false, &parts), long);
    }
}
