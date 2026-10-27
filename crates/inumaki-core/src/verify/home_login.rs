//! The verifier's own home-folder login check (ruling L127, spec S12, S32).
//!
//! A home-folder login (`/home/<x>/`, `/Users/<x>/`, `C:\Users\<x>\`,
//! `~<x>`) names the person who owns the machine. The sanitizer tokenizes it
//! as a `PERSON` of source `Position` (the `path_names` detector, R1 and
//! R4); this check is the independent backstop: it fails a candidate in
//! which such a login is still in clear. It shares no code with the
//! sanitizer's detector (S12): it has its own root matching and its own
//! list of generic accounts ([`VERIFIER_GENERIC_LOGINS`]), which a test
//! keeps equal to the detector's list, so a drift fails the build without
//! the two sides sharing runtime code.
//!
//! # Roots
//!
//! - `/home`, `/homes` and `/Users` (exact case), followed by `/` or `\`;
//! - a drive letter, `:`, a separator, `Users` (any case), a separator
//!   (`C:\Users\`, also `C:/Users/`);
//! - a `~` path: `~` followed by a letter, after the start, whitespace, a
//!   separator, a quote, a bracket, `<`, `>`, `,`, `:` or `=`, whose login
//!   ends at `/` or `\` (`~mhuber/notes`, `https://example.com/~leitner/`,
//!   `scp f host:~mhuber/notes`, `--dir=~mhuber/x`; after `:` or `=`
//!   whatever precedes it, ruling L136, so `x=~mask/2` counts and the
//!   sanitizer tokenizes it);
//! - a slashless `~word` (ruling L3-30), only in a login context: (a) the
//!   `~` starts the text or follows whitespace, a quote or `(`, or follows
//!   `:` or `=` right after an option or an all-caps variable
//!   (`--dir=~mhuber`, `HOME_DIR=~mhuber`; ruling L136); after
//!   whitespace or `(` the last character before it (spaces skipped) is no
//!   operator ([`VERIFIER_TILDE_OPERATORS`]: `x & ~flags`, `mode: ~fast`)
//!   and the word before it no code keyword ([`VERIFIER_TILDE_KEYWORDS`]:
//!   `return ~mask;`, `if (~idx)`), and a `(` right after a letter, digit
//!   or `_` is a call; (b) the word (`[A-Za-z0-9._-]`, trailing dots off)
//!   has three or more characters, starts with a letter and holds a
//!   lowercase letter (`~FLAG_READY` is a constant); (c) it is followed by
//!   the end, a sentence-final `.`, `,`, `;`, `:`, `)`, a quote, or spaces
//!   up to the end of the line or a character that is no letter or digit
//!   (`cd ~mhuber && ls`), never by a word (`~zwei Stunden`, `takes ~half
//!   the time`); (d) it is no stoplist common word that is not name-like
//!   ([`VERIFIER_TILDE_COMMON_WORDS`]) and no generic account.
//!
//! A run of separators counts as one (`//home//x`, the JSON-escaped
//! `\/home\/x` and `C:\\Users\\x`), so an escaped path puts its login after
//! its root, as it does in the sanitizer. Not roots (residuals): `home$`
//! and UNC `\\server\Users\` shares, and Claude Code's flattened project
//! directories (`-Users-<login>-…`); the sanitizer reads them.
//!
//! # The login
//!
//! The characters after the root up to the next `/`, `\`, whitespace,
//! quote or backtick, bracket, `,`, `;`, `:`, `|`, or placeholder character
//! `$ < > { }`, without a trailing `.`, `!` or `?`. A login that starts with
//! a placeholder character, or with a `%` that does not start a `%XX`
//! escape, is a placeholder (`${USER}`, `<you>`, `%USERNAME%`); one that
//! only contains one is not (`/Users/mhuber${SUFFIX}` → `mhuber`,
//! `/Users/mhuber%`; fix round 1, item 2). The login fails the candidate
//! when it is in clear, holds a letter (so `/Users/kl/` and `/home/a/` fail;
//! ruling L134) and is not a generic account (ASCII case folded).
//!
//! In clear means outside every `Tokenize` or `Remove` output range, every
//! protected token, and every `Preserve` or `Escalate` range of kind
//! `PERSON` (the same exemption [`Sanitized::is_exempt`] grants a re-scan
//! hit). Only the offsets of those ranges are used; no token text is read.
//! A login partly covered by a token fails when a clear piece of it, trimmed
//! of `. _ -`, still holds a letter and is not generic (fail closed); a
//! login led by a token is judged by what follows the token, and a file
//! extension right after it (`<PERSON_…>.txt`, `.` and 1–5 letters or
//! digits) is none where it ends the segment (fix round 1, item 3; not
//! before `/` or `\`, fix round 2, item 4).
//!
//! The sanitizer's path detector tokenizes every login this check would
//! refuse after these roots (ruling L134); a test in `verify` sanitizes
//! shared rows with the detector's spans and runs this check on them.
//!
//! # Result
//!
//! One [`Reason`] of kind `PERSON` and check [`CheckId::Regex`] per text:
//! this is a deterministic pattern re-scan, and a new check id would change
//! the reasons every API client and the app read. The reason carries no
//! text or offset. It runs for every origin, right after the regex re-scan
//! and before the NER re-scan (`SecondPassVerifier::verify_with_at`).

use std::ops::Range;

use super::{CheckId, Reason};
use crate::policy::Action;
use crate::sanitize::Sanitized;
use crate::span::EntityKind;

/// Logins that name no person (compared lowercased): system, service and CI
/// accounts, shared and placeholder folders. The verifier's own copy of the
/// sanitizer's list; `verifier_generic_logins_equal_the_detector_list`
/// keeps the two equal as sets.
pub(crate) const VERIFIER_GENERIC_LOGINS: &[&str] = &[
    "admin",
    "administrator",
    "all",
    "app",
    "appuser",
    "apache",
    "backup",
    "bin",
    "build",
    "builder",
    "centos",
    "ci",
    "circleci",
    "codespace",
    "daemon",
    "debian",
    "default",
    "deploy",
    "dev",
    "developer",
    "docker",
    "ec2-user",
    "everyone",
    "fedora",
    "git",
    "gitlab-runner",
    "guest",
    "jenkins",
    "linuxbrew",
    "local",
    "localadmin",
    "me",
    "mysql",
    "nginx",
    "nobody",
    "node",
    "office",
    "operator",
    "owner",
    "pi",
    "postgres",
    "public",
    "redis",
    "root",
    "runner",
    "server",
    "service",
    "shared",
    "staff",
    "sys",
    "system",
    "test",
    "tester",
    "travis",
    "ubuntu",
    "user",
    "username",
    "users",
    "vagrant",
    "vscode",
    "work",
    "www",
    "www-data",
];

/// The verifier's own copy of the code keywords after which a slashless
/// `~word` is code (`return ~mask;`, `if (~idx)`; ruling L3-30).
pub(crate) const VERIFIER_TILDE_KEYWORDS: &[&str] = &[
    "and", "assert", "await", "case", "elif", "for", "if", "in", "match", "not", "or", "return",
    "sizeof", "switch", "unless", "until", "when", "while", "yield",
];

/// The verifier's own copy of the characters after which (spaces skipped)
/// a slashless `~word` is code (`x & ~flags`, `mode: ~fast`; ruling L3-30).
pub(crate) const VERIFIER_TILDE_OPERATORS: &str = "&|^=:!+/%<>?,;~([{";

/// The verifier's own copy of the stoplist's common words that are not
/// name-like (lowercased): a slashless `~word` that is one of them is no
/// login (ruling L3-30). Equal to the stoplist by a test.
pub(crate) const VERIFIER_TILDE_COMMON_WORDS: &[&str] = &[
    "a",
    "aber",
    "about",
    "above",
    "after",
    "against",
    "all",
    "alle",
    "als",
    "although",
    "and",
    "as",
    "at",
    "auch",
    "auf",
    "aus",
    "because",
    "before",
    "behind",
    "beim",
    "below",
    "best",
    "between",
    "bevor",
    "bis",
    "bitte",
    "but",
    "by",
    "colleagues",
    "customer",
    "damen",
    "damit",
    "danke",
    "dann",
    "dass",
    "dear",
    "dein",
    "deine",
    "dem",
    "denn",
    "dich",
    "die",
    "dies",
    "diese",
    "dieser",
    "dieses",
    "dir",
    "doch",
    "doktor",
    "durch",
    "during",
    "ein",
    "eine",
    "einem",
    "einen",
    "einer",
    "eines",
    "er",
    "es",
    "euch",
    "euer",
    "everyone",
    "falls",
    "firma",
    "for",
    "frau",
    "from",
    "fuer",
    "für",
    "geehrte",
    "geehrter",
    "gegen",
    "gruesse",
    "grüße",
    "hallo",
    "have",
    "hello",
    "herr",
    "herren",
    "hinter",
    "his",
    "i",
    "ich",
    "if",
    "ihm",
    "ihn",
    "ihnen",
    "ihr",
    "ihre",
    "ihren",
    "into",
    "it",
    "its",
    "kollegen",
    "kolleginnen",
    "kunde",
    "kunden",
    "kundenservice",
    "kundin",
    "liebe",
    "lieber",
    "madam",
    "mate",
    "me",
    "mein",
    "meine",
    "meinem",
    "meinen",
    "mich",
    "mit",
    "mitarbeiter",
    "nach",
    "nachdem",
    "neben",
    "nicht",
    "noch",
    "nor",
    "ob",
    "ober",
    "obwohl",
    "oder",
    "of",
    "off",
    "ohne",
    "onto",
    "or",
    "our",
    "ours",
    "over",
    "please",
    "regards",
    "schon",
    "sehr",
    "sein",
    "seine",
    "seit",
    "service",
    "she",
    "sich",
    "sie",
    "since",
    "sir",
    "sobald",
    "sondern",
    "sowie",
    "support",
    "team",
    "thanks",
    "that",
    "the",
    "their",
    "theirs",
    "them",
    "these",
    "they",
    "this",
    "those",
    "though",
    "through",
    "toward",
    "towards",
    "ueber",
    "und",
    "under",
    "unless",
    "uns",
    "unser",
    "unsere",
    "unter",
    "until",
    "upon",
    "us",
    "via",
    "vor",
    "waehrend",
    "we",
    "wegen",
    "welt",
    "wenn",
    "what",
    "whereas",
    "whether",
    "which",
    "while",
    "who",
    "whom",
    "whose",
    "wir",
    "wishes",
    "with",
    "within",
    "without",
    "während",
    "yet",
    "your",
    "yours",
    "zusammen",
    "zwischen",
    "über",
];

/// One `PERSON`/`Regex` reason when `s.text` holds a home-folder login in
/// clear (module docs); empty otherwise. Linear in the text: one pass for
/// the roots, and the covered ranges are collected only once a root is
/// found.
pub(crate) fn check_home_logins(s: &Sanitized) -> Vec<Reason> {
    let text = s.text.as_str();
    let b = text.as_bytes();
    let mut covered: Option<Vec<Range<usize>>> = None;
    let mut i = 0;
    while i < b.len() {
        let hit = match b[i] {
            b'/' => after_root(b, i + 1, b"home", false)
                .or_else(|| after_root(b, i + 1, b"homes", false))
                .or_else(|| after_root(b, i + 1, b"Users", false))
                .map(Hit::Path),
            // A lone drive letter: `smb:/users/`, `https://users/` and
            // `xC:\users\` are no drive root (final fix wave item 2).
            b':' if i > 0
                && b[i - 1].is_ascii_alphabetic()
                && (i < 2 || !b[i - 2].is_ascii_alphanumeric()) =>
            {
                let k = skip_seps(b, i + 1);
                if k > i + 1 {
                    after_root(b, k, b"users", true).map(Hit::Path)
                } else {
                    None
                }
            }
            b'~' => tilde_hit(text, i),
            _ => None,
        };
        let Some(hit) = hit else {
            i += 1;
            continue;
        };
        let cov = covered.get_or_insert_with(|| covered_ranges(s));
        let (fails, end) = match hit {
            Hit::Path(a) => path_login_fails(text, a, cov),
            Hit::Bare(a, e) => (
                clear_pieces(a, e, cov).iter().any(|p| has_letter(text, p)),
                e,
            ),
        };
        if fails {
            return vec![Reason {
                kind: EntityKind::Person,
                check: CheckId::Regex,
            }];
        }
        i = end.max(i + 1);
    }
    Vec::new()
}

/// A login found after a root.
enum Hit {
    /// A login after a home root or a `~` path (`~mhuber/x`), starting at
    /// this offset.
    Path(usize),
    /// A slashless `~word` login (`~mhuber`), this range.
    Bare(usize, usize),
}

/// When `b[at..]` starts with `root` (any ASCII case if `fold`) followed by
/// one or more separators, the offset after them.
fn after_root(b: &[u8], at: usize, root: &[u8], fold: bool) -> Option<usize> {
    let w = b.get(at..at + root.len())?;
    let hit = if fold {
        w.eq_ignore_ascii_case(root)
    } else {
        w == root
    };
    let k = skip_seps(b, at + root.len());
    (hit && k > at + root.len()).then_some(k)
}

/// The offset after the run of `/` and `\` that starts at `at`.
fn skip_seps(b: &[u8], mut at: usize) -> usize {
    while at < b.len() && matches!(b[at], b'/' | b'\\') {
        at += 1;
    }
    at
}

/// The `~` at byte `i` as a root (module docs): a `~` path when its login
/// ends at `/` or `\`, else a slashless `~word` under ruling L3-30.
fn tilde_hit(text: &str, i: usize) -> Option<Hit> {
    let b = text.as_bytes();
    let a = i + 1;
    let e = login_end(b, a);
    if matches!(b.get(e), Some(b'/' | b'\\')) {
        let prev_ok = text[..i]
            .chars()
            .next_back()
            .is_none_or(|p| p.is_whitespace() || "/\\\"'([{<>,)]}:=".contains(p));
        let letter = text[a..].chars().next().is_some_and(char::is_alphabetic);
        return (prev_ok && letter).then_some(Hit::Path(a));
    }
    bare_tilde_word(text, i).map(|(x, y)| Hit::Bare(x, y))
}

/// The slashless `~word` at byte `i` (ruling L3-30; module docs), as the
/// word's range, when it is in a login context.
fn bare_tilde_word(text: &str, i: usize) -> Option<(usize, usize)> {
    // (a) What comes before the `~`. Right after `:` or `=` only when an
    // option or an all-caps variable precedes it (`--dir=~mhuber`,
    // `HOME_DIR=~mhuber`; ruling L136).
    let before: &str = match text[..i].chars().next_back() {
        None => "",
        Some(':' | '=') if assigns_to_option_or_variable(&text[..i - 1]) => "",
        Some('"' | '\'') => "",
        Some(p) if p.is_whitespace() => &text[..i],
        Some('(') => {
            let head = &text[..i - 1];
            match head.chars().next_back() {
                Some(c) if c.is_alphanumeric() || c == '_' => return None,
                _ => head,
            }
        }
        Some(_) => return None,
    };
    let head = before.trim_end();
    if let Some(c) = head.chars().next_back() {
        if VERIFIER_TILDE_OPERATORS.contains(c) {
            return None;
        }
        let kw = head
            .rsplit(|c: char| !c.is_ascii_alphabetic())
            .next()
            .unwrap_or("");
        if VERIFIER_TILDE_KEYWORDS.contains(&kw) {
            return None;
        }
    }
    // (b) The word.
    let b = text.as_bytes();
    let a = i + 1;
    let mut run_end = a;
    while run_end < b.len()
        && (b[run_end].is_ascii_alphanumeric() || matches!(b[run_end], b'.' | b'_' | b'-'))
    {
        run_end += 1;
    }
    let mut e = run_end;
    while e > a && b[e - 1] == b'.' {
        e -= 1;
    }
    let w = &text[a..e];
    if w.len() < 3
        || !w.as_bytes()[0].is_ascii_alphabetic()
        || !w.bytes().any(|c| c.is_ascii_lowercase())
    {
        return None;
    }
    // (c) What follows it.
    let rest = &text[run_end..];
    let next = rest.chars().next();
    let follows_ok = if e < run_end {
        next.is_none_or(char::is_whitespace)
    } else {
        match next {
            None | Some(',' | ';' | ':' | ')' | '"' | '\'') => true,
            Some(c) if c.is_whitespace() => {
                let line = rest.trim_start_matches(|c: char| c.is_whitespace() && c != '\n');
                line.chars()
                    .next()
                    .is_none_or(|c| c == '\n' || !c.is_alphanumeric())
            }
            _ => false,
        }
    };
    // (d) Not a common word, not a generic account.
    let common = VERIFIER_TILDE_COMMON_WORDS
        .iter()
        .any(|c| c.eq_ignore_ascii_case(w));
    (follows_ok && !common && !is_generic(w)).then_some((a, e))
}

/// `head` ends with an option (`--dir`) or an all-caps variable
/// (`HOME_DIR`): the run of `[A-Za-z0-9_-]` before a `:` or `=`.
fn assigns_to_option_or_variable(head: &str) -> bool {
    let n = head
        .bytes()
        .rev()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
        .count();
    let w = &head.as_bytes()[head.len() - n..];
    (w.len() > 2 && w.starts_with(b"--"))
        || (w
            .first()
            .is_some_and(|c| c.is_ascii_uppercase() || *c == b'_')
            && w.iter().any(u8::is_ascii_uppercase)
            && w.iter()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_'))
}

/// The end of the login that starts at `a` (module docs).
fn login_end(b: &[u8], a: usize) -> usize {
    let mut e = a;
    while e < b.len()
        && !b[e].is_ascii_whitespace()
        && !matches!(
            b[e],
            b'/' | b'\\'
                | b'"'
                | b'\''
                | b'`'
                | b'('
                | b')'
                | b'['
                | b']'
                | b','
                | b';'
                | b':'
                | b'|'
                | b'$'
                | b'<'
                | b'>'
                | b'{'
                | b'}'
        )
    {
        e += 1;
    }
    // Non-ASCII whitespace (a no-break space) ends it too.
    if let Ok(t) = std::str::from_utf8(&b[a..e]) {
        if let Some(k) = t.find(char::is_whitespace) {
            e = a + k;
        }
    }
    while e > a && matches!(b[e - 1], b'.' | b'!' | b'?') {
        e -= 1;
    }
    e
}

/// The output ranges a login may lie in without being in clear (module
/// docs), sorted by start.
fn covered_ranges(s: &Sanitized) -> Vec<Range<usize>> {
    let mut v: Vec<Range<usize>> = s
        .replacements
        .iter()
        .filter(|r| match r.action {
            Action::Tokenize | Action::Remove => true,
            Action::Preserve | Action::Escalate => r.span.kind == EntityKind::Person,
            Action::Block => false,
        })
        .map(|r| r.out_range.clone())
        .chain(s.protected.iter().cloned())
        .filter(|r| r.start < r.end)
        .collect();
    v.sort_by_key(|r| r.start);
    v
}

/// Whether the path login that starts at `a` names someone in clear, and
/// where the scan goes on.
fn path_login_fails(text: &str, a: usize, covered: &[Range<usize>]) -> (bool, usize) {
    let b = text.as_bytes();
    // Led by a token: only what follows the token counts, and a file
    // extension right after it is none (`<PERSON_…>.txt`; fix round 1,
    // item 3).
    let k = covered.partition_point(|r| r.start <= a);
    if k > 0 && a < covered[k - 1].end {
        let c = covered[k - 1].end;
        let e = login_end(b, c);
        let piece = &text[c..e];
        // Only where it ends the segment (`<PERSON_…>.huber/x` is no
        // extension; fix round 2, item 4).
        let ext = piece.len() >= 2
            && piece.len() <= 6
            && piece.starts_with('.')
            && piece[1..].bytes().all(|x| x.is_ascii_alphanumeric())
            && !matches!(b.get(e), Some(b'/' | b'\\'));
        if e == c || ext {
            return (false, e.max(c));
        }
        let fails = clear_pieces(c, e, covered)
            .iter()
            .any(|p| trimmed_names(text, p));
        return (fails, e);
    }
    // A placeholder exempts a login only at its start (fix round 1, item 2).
    let placeholder = match b.get(a) {
        Some(b'$' | b'<' | b'>' | b'{' | b'}') => true,
        Some(b'%') => {
            !(b.len() > a + 2 && b[a + 1].is_ascii_hexdigit() && b[a + 2].is_ascii_hexdigit())
        }
        _ => false,
    };
    if placeholder {
        return (false, a + 1);
    }
    let e = login_end(b, a);
    let pieces = clear_pieces(a, e, covered);
    let fails = if pieces.len() == 1 && pieces[0] == (a..e) {
        let w = &text[a..e];
        w.chars().any(char::is_alphabetic) && !is_generic(w)
    } else {
        pieces.iter().any(|p| trimmed_names(text, p))
    };
    (fails, e)
}

/// The parts of `a..e` outside every covered range.
fn clear_pieces(a: usize, e: usize, covered: &[Range<usize>]) -> Vec<Range<usize>> {
    let mut pieces = Vec::new();
    let mut cur = a;
    let first = covered.partition_point(|r| r.end <= a);
    for r in &covered[first..] {
        if r.start >= e {
            break;
        }
        if r.start > cur {
            pieces.push(cur..r.start);
        }
        cur = cur.max(r.end);
    }
    if cur < e {
        pieces.push(cur..e);
    }
    pieces
}

/// The piece holds a letter (fail closed off a char boundary).
fn has_letter(text: &str, p: &Range<usize>) -> bool {
    text.get(p.clone())
        .is_none_or(|w| w.chars().any(char::is_alphabetic))
}

/// A clear piece next to a token, trimmed of `. _ -`, holds a letter and is
/// not generic (fail closed off a char boundary).
fn trimmed_names(text: &str, p: &Range<usize>) -> bool {
    text.get(p.clone()).is_none_or(|w| {
        let w = w.trim_matches(['.', '_', '-']);
        w.chars().any(char::is_alphabetic) && !is_generic(w)
    })
}

/// In [`VERIFIER_GENERIC_LOGINS`], ASCII case folded (the list is ASCII,
/// so a non-ASCII look-alike never makes a login generic).
fn is_generic(w: &str) -> bool {
    VERIFIER_GENERIC_LOGINS
        .iter()
        .any(|g| g.eq_ignore_ascii_case(w))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Action;
    use crate::sanitize::{Replacement, Sanitized};
    use crate::span::{DetectorId, EntityKind, Span};

    fn clear(text: &str) -> Sanitized {
        Sanitized {
            text: text.to_string(),
            replacements: Vec::new(),
            blocked: Vec::new(),
            escalated: Vec::new(),
            protected: Vec::new(),
        }
    }

    fn with_token(a: &str, tok: &str, b: &str) -> Sanitized {
        let mut s = clear(&format!("{a}{tok}{b}"));
        s.replacements.push(Replacement {
            span: Span::new(
                a.len(),
                a.len() + 6,
                EntityKind::Person,
                0.9,
                DetectorId::Position,
            ),
            action: Action::Tokenize,
            token: None,
            out_range: a.len()..a.len() + tok.len(),
        });
        s
    }

    #[test]
    fn clear_home_logins_fail_and_tokens_or_generic_logins_pass() {
        // fail: a clear, non-generic login after each root
        for text in [
            "cwd /Users/mhuber/app",
            "in /home/agruber/x",
            r"C:\Users\sleitner\Desktop",
            "siehe ~mhuber/notes",
        ] {
            assert_eq!(check_home_logins(&clear(text)).len(), 1, "{text}");
        }
        // pass: generic, placeholder, token-covered, not a root
        for text in [
            "/Users/runner/work",
            "/home/linuxbrew/.linuxbrew",
            "/Users/<you>/x",
            "/home/$USER/x",
            r"C:\Users\%USERNAME%\x",
            "~/projects",
            "https://x.com/users/mhuber",
            "etwa ~5 Minuten",
        ] {
            assert!(check_home_logins(&clear(text)).is_empty(), "{text}");
        }
        assert!(check_home_logins(&with_token("/Users/", "<PERSON_ab12>", "/app")).is_empty());
    }

    /// Final fix wave item 2 (L139 m1): a drive root needs a lone drive
    /// letter, as the detector's `X:` segment does; a scheme or a word
    /// glued before the letter is no drive.
    #[test]
    fn drive_roots_need_a_lone_letter() {
        for text in ["smb:/users/ab/", "https://users/kl/", r"xC:\users\kl\"] {
            assert!(check_home_logins(&clear(text)).is_empty(), "{text}");
        }
        for text in [
            r"C:\Users\mhuber\",
            r"Pfad C:\Users\mhuber\x",
            r"(D:\users\kl\)",
        ] {
            assert_eq!(check_home_logins(&clear(text)).len(), 1, "{text}");
        }
    }

    /// The module's own choices beyond the brief's table: separator runs,
    /// login ends, `~` word starts, `%XX` escapes, partial tokens, and a
    /// preserved `PERSON` range.
    #[test]
    fn escaped_roots_partial_tokens_and_login_ends() {
        for text in [
            "Pfad //home//huber prüfen",
            r#"{"cwd":"\/home\/huber\/x"}"#,
            r#"{"cwd":"C:\\Users\\mhuber\\x"}"#,
            "C:/Users/mhuber/x",
            "/Users/anna%20gruber/Desktop",
            "Ende: /home/mhuber.",
            "mhuber:x:1000:1000::/home/mhuber:/bin/bash",
            "(~mhuber)",
        ] {
            assert_eq!(check_home_logins(&clear(text)).len(), 1, "{text}");
        }
        for text in [
            "`/Users/runner`",
            "ubuntu:x:1000:1000::/home/ubuntu:/bin/bash",
            "/home/ROOT/x",
            "das ist ~~veraltet~~ jetzt",
            "HEAD~main",
            "/homepage/anna",
            "/Users/.../x",
            r"C:\Users\Public\x",
        ] {
            assert!(check_home_logins(&clear(text)).is_empty(), "{text}");
        }
        // A clear piece next to a token still names someone (fail closed).
        assert_eq!(
            check_home_logins(&with_token("/Users/anna.", "[[PERSON_ab12]]", "/x")).len(),
            1
        );
        assert!(check_home_logins(&with_token("/Users/", "[[PERSON_ab12]]", "/x")).is_empty());
        // A preserved PERSON range is the policy's call; another kind is not.
        let mut s = with_token("/Users/", "mhuber", "/x");
        s.replacements[0].action = Action::Preserve;
        assert!(check_home_logins(&s).is_empty());
        s.replacements[0].span.kind = EntityKind::Url;
        assert_eq!(check_home_logins(&s).len(), 1);
    }

    /// Fix round 1 (rulings L3-30, L134): a slashless `~word` only in a
    /// login context; a login ends at a placeholder character, which exempts
    /// it only at its start; `/homes/`; short logins; a file extension right
    /// after a token.
    #[test]
    fn fix1_tilde_contexts_placeholders_and_extensions() {
        for text in [
            "~mhuber",
            "~mhuber/",
            r#""~mhuber""#,
            "(~mhuber)",
            "~mhuber.",
            "cd ~mhuber && ls",
            "export P=/Users/mhuber${SUFFIX}/bin",
            "cp a /home/mhuber$EXT",
            "/Users/mhuber%",
            r"C:\Users\mhuber%TEMP%",
            "<td>/home/mhuber</td>",
            "/homes/mhuber/x",
            "/Users/kl/x",
            "/home/a/x",
        ] {
            assert_eq!(check_home_logins(&clear(text)).len(), 1, "{text}");
        }
        for text in [
            "return ~x;",
            "x & ~flags",
            "return ~mask;",
            "df[~df.active]",
            "MyClass::~MyClass()",
            "~strike~",
            "etwa ~ca. 5",
            "~FLAG_READY",
            "if (~idx)",
            "mode: ~fast",
            "~zwei Stunden",
            "takes ~half the time",
            "x&~flags/2",
            "/Users/${USER}/",
            "/home/<you>/",
        ] {
            assert!(check_home_logins(&clear(text)).is_empty(), "{text}");
        }
        // Item 3: an extension right after a token is no login.
        assert!(check_home_logins(&with_token("/Users/", "<PERSON_ab12>", ".txt")).is_empty());
        assert!(check_home_logins(&with_token("/Users/", "[[PERSON_ab12]]", ".txt")).is_empty());
        assert!(check_home_logins(&with_token("/Users/", "[[PERSON_ab12]]", ".pdf x")).is_empty());
        assert_eq!(
            check_home_logins(&with_token("/Users/", "[[PERSON_ab12]]", "huber/x")).len(),
            1
        );
    }

    /// Fix round 2 (ruling L136): a `~login/` after `:` or `=` is a root
    /// whatever precedes it; without the slash, `:` or `=` before `~login`
    /// counts only after an option or an all-caps variable; an extension
    /// after a token is exempt only where it ends the segment.
    #[test]
    fn fix2_tilde_after_colon_or_assignment_and_extension_end() {
        for text in [
            "scp f user@host:~mhuber/notes",
            "rsync -a srv:~mhuber/ .",
            "--dir=~mhuber/x",
            "PATH=$PATH:~mhuber/bin",
            "export HOME_DIR=~mhuber/x",
            "Pfad:~mhuber/notes",
            "x=~mask/2",
            "a.b=~c/d",
            "--dir=~mhuber",
            "HOME_DIR=~mhuber",
        ] {
            assert_eq!(check_home_logins(&clear(text)).len(), 1, "{text}");
        }
        for text in ["x&~flags/2", "x=~mhuber", "mode:~fast"] {
            assert!(check_home_logins(&clear(text)).is_empty(), "{text}");
        }
        // Item 4: `.huber` before a `/` is no extension.
        assert_eq!(
            check_home_logins(&with_token("/Users/", "<PERSON_ab12>", ".huber/x")).len(),
            1
        );
        assert_eq!(
            check_home_logins(&with_token("/Users/", "[[PERSON_ab12]]", ".txt/x")).len(),
            1
        );
        assert!(check_home_logins(&with_token("/Users/", "<PERSON_ab12>", ".txt, x")).is_empty());
    }

    /// Fix round 2 (L135 item 4): a long piece without a home root is not
    /// refused (the detector skips pieces over 4096 bytes; the check reads
    /// roots only), and a long piece with a clear login is (fail closed).
    #[test]
    fn long_pieces_without_a_home_root_pass() {
        // A deterministic 12 KB base64 blob (holds `/` and `+`).
        const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut x: u32 = 0x1234_5678;
        let blob: String = (0..12 * 1024)
            .map(|_| {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                B64[(x >> 26) as usize] as char
            })
            .collect();
        assert!(blob.contains('/'));
        let png = format!("data:image/png;base64,{blob}");
        let img = format!(r#"<img src="{png}">"#);
        let js = "y=a&~flags/4;z=b/c;w=!~idx;".repeat(12 * 1024 / 27 + 1);
        for text in [blob.as_str(), png.as_str(), img.as_str(), js.as_str()] {
            assert!(text.len() > 4096);
            assert!(check_home_logins(&clear(text)).is_empty());
        }
        let pad = "a/b".repeat(1400);
        assert_eq!(
            check_home_logins(&clear(&format!("{pad}/home/mhuber/{pad}"))).len(),
            1
        );
        assert!(check_home_logins(&clear(&format!("{pad}/Users/runner/{pad}"))).is_empty());
    }

    /// Latency (L117 style): the check over 4, 30, 120 and 240 KB of text
    /// full of generic home paths (every root is judged, none fails, so the
    /// whole text is scanned). Release, by hand:
    /// `cargo test --release -p inumaki-core --lib home_login_timing -- --ignored --nocapture`.
    #[test]
    #[ignore = "timing measurement, run in release by hand"]
    #[allow(clippy::print_stderr)] // a measurement prints its numbers; no input text
    fn home_login_timing() {
        let unit = "cwd /Users/runner/work/app, Kopie unter C:\\Users\\Public\\x.docx, \
                    siehe ~root/notes und /home/ubuntu/.cargo, etwa ~5 Minuten. ";
        for kb in [4usize, 30, 120, 240] {
            let text = unit.repeat(kb * 1024 / unit.len() + 1);
            let s = clear(&text);
            let mut best = std::time::Duration::MAX;
            for _ in 0..7 {
                let t = std::time::Instant::now();
                assert!(check_home_logins(std::hint::black_box(&s)).is_empty());
                best = best.min(t.elapsed());
            }
            eprintln!(
                "home_login {kb} KB: best of 7 {:.3} ms",
                best.as_secs_f64() * 1e3
            );
        }
    }
}
