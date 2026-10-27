//! Names in paths and URLs: a deterministic detector of positional cues and
//! first names (spec §4, ruling S8).
//!
//! A path or URL component is a login or a person when its position says
//! so. The model rarely tags `/home/huber/`, and a surname list at runtime
//! would catch ordinary words (S8), so this detector reads the structure
//! instead. Every span it reports is a `PERSON` of source
//! [`DetectorId::Position`] (S9), at overlap priority 1, like a model span.
//! It runs in every profile and every origin, with no switch (S13); the
//! engine pushes it outside the `linking.anchors` block. It is sanitizer
//! only: the verifier has its own home-login check, sharing no code with
//! this module (S12, S32).
//!
//! # Candidates
//!
//! A whitespace-delimited token that holds `/` or `\` is cut into pieces at
//! JSON and markup punctuation (`" , { } [ ] ' < > ( )`), in one pass, so a
//! minified JSON line or a Markdown link is scanned piece by piece (fix
//! round 1). A candidate is such a piece that holds `/` or `\`, trimmed of
//! leading `( [ { " ' < «` and trailing `) ] } " ' > » , ; : ! ?` and `.`.
//! A slashless `~word` (`cd ~mhuber && ls`) is found by a separate pass
//! over the text, only in a login context ([`tilde_words`]; rulings L3-29,
//! L3-30). A piece longer than [`MAX_TOKEN_BYTES`] is skipped whole (spec
//! Review Focus 4). A piece is split as:
//!
//! - a URL (`scheme://host/…`, the JSON-escaped `scheme:\/\/host\/…`, or
//!   `www.host/…`), found after any prefix (`repo=https://…`; the prefix is
//!   a piece of its own): host (lowercased, a leading `www.` removed) and
//!   path segments at `/` and `\` (ruling L132); query and fragment are cut
//!   off, and a URL nested in them (`?next=https://github.com/x`) is scanned
//!   as a URL of its own (ruling L133);
//! - an scp-style remote (`git@github.com:agruber/notizen.git`): host plus
//!   the path after `:`;
//! - a path whose first segment is a code host or `linkedin.com`
//!   (`github.com/mhuber/tool`, no scheme): that host plus the rest;
//! - any other piece: a filesystem path, split at `/` and `\`.
//!
//! A rule's "previous segment" is the nearest non-empty one, so an escaped
//! or doubled separator (`C:\\Users\\mhuber`, `\/home\/huber`) still
//! puts the login after its root.
//!
//! # The rules (one span per name segment)
//!
//! | rule | position | confidence |
//! |---|---|---|
//! | R1 | the segment after a home root (`home`, `homes`, `home$`, `users`, any case) | 0.90 |
//! | R2 | the segment after a person cue (`team`, `people`, `mitarbeiter`, …; `in` only on `linkedin.com`) | 0.80 |
//! | R3 | the first path segment on a code host (`github.com`, `gitlab.com`, …, scp included) | 0.80 |
//! | R4 | a segment `~name` (the part after `~`) | 0.90 |
//! | R5 | the login in Claude Code's flattened project directory (`-Users-<login>-…`, `-home-<login>-…`, Windows `C--Users-<login>-…`) | 0.90 |
//! | R6 | a run of 2–3 parts holding a first name, in a segment no R1–R5 span covers, or in a text that is one token (a mirror stem, S26) | 0.80 |
//!
//! **A login ends** at a placeholder character (`$ < > { }`) or the
//! punctuation the verifier stops at (`: ; | ( ) [ ]`, backtick, quote,
//! `,`), without trailing `. ! ?` ([`login_cut`]); a login that *starts*
//! with a placeholder (`${USER}`, `<you>`, `%USERNAME%`) is none (fix round
//! 1, item 2). **After a root the verifier also reads** (`home`, `homes`,
//! `Users` exact case, `users` after a drive) and in R4, the login is
//! judged as the verifier judges it ([`home_login_range`]: a letter and not
//! generic), so the sanitizer tokenizes whatever the verifier would refuse,
//! one- and two-letter logins included (ruling L134). Other roots
//! (`HOME`, `home$`, a lowercase `users` in a URL) and R2, R3, R5 use the
//! name segment rules below. R4 also reads a `~` and a letter after `:` or
//! `=` inside a segment (`host:~mhuber/`, `--dir=~mhuber/`, `x=~mask/2`;
//! ruling L136), as the verifier does. After a root the verifier reads, R1
//! comes before R4 (unless the segment starts with `~`) and R5, and a URL
//! whose host is a home root (`C://Users/x`) gives its first path segment
//! that root (fix round 2).
//!
//! **The name segment of R1–R5** ([`is_login`]) is the segment, without a
//! trailing `.ext` when it is the last one and the extension is a listed
//! file extension or holds a digit. It has 2–64 characters of letters,
//! digits, `. _ -`, and `%` only as `%` plus two hex digits (`anna%20gruber`;
//! a placeholder such as `$USER`, `%USERNAME%` or `<you>` is never a name),
//! holds a letter, is not a generic account ([`GENERIC_ACCOUNTS`]) or a
//! route word (`/users/search` is no name), and its letter parts (split at
//! `. _ -`, `%XX` and digits) are not all filler (one or two letters).
//!
//! - One letter part: a first name always passes. Otherwise it is rejected
//!   when it is a generic account, a route word, an `Unmarked` or `Rare`
//!   vocabulary word, or a stoplist common word that is not name-like
//!   (`is_common_word && !is_name_like_word`; review C1). So `weber`,
//!   `koch`, `fischer`, `bauer`, `wagner` (common *and* name-like) and a
//!   `Surname`-marked word (`branch`, `model`) are names. Right after a
//!   home root (R1, R4, R5) a `Rare` word is a login too (`/home/steuer/`,
//!   `C:\Users\Preis\`; ruling L3-28, Task 4b): tokenizing it beats the
//!   verifier's refusal, and the cost is a document word lost as a token.
//! - Two or more letter parts: a name when one part is a first name, a word
//!   of three or more letters that is neither vocabulary (any mark) nor a
//!   stoplist word, or a name-like stoplist surname next to a single-letter
//!   initial (`m.weber`, `j-koch`, `h_bauer`; review N2, L129). An initial
//!   is one letter standing alone at the segment's start or between
//!   separators; it never makes a vocabulary or non-name-like word a name
//!   (`a-team`, `rust-lang`, `data-pipeline` stay out). Residual: a login
//!   made only of stoplist surnames (`weber.koch`) is no name.
//! - R1 continuation (review I4): when the login segment ends its token and
//!   the next whitespace-separated token starts with a letters-only word
//!   directly followed by `\` or `/`, the login and that word are judged as
//!   one two-part login and the span runs over the space
//!   (`C:\Users\Anna Gruber\Documents` → `Anna Gruber`). Residual: a
//!   three-word login (`C:\Users\Anna Maria Gruber\`) keeps only `Anna`.
//!
//! **R6** needs a part that is a gazetteer first name, not an `ALSO_NAMES`
//! word and in neither vocabulary, next to a first name or a letters-only
//! part of three or more letters that is not an `Unmarked` or `Rare`
//! vocabulary word (a `Surname`-marked word counts: `anna-branch`) and, if
//! a stoplist word, is name-like (`anna-weber`). Parts are split at
//! `- _ .`; a part with a digit breaks the run, and a listed file
//! extension after a `.` is no part. The span is the run
//! (`angebot-anna-gruber` → `anna-gruber`); a run of more than three such
//! parts is covered whole (`anna_maria_gruber_huber`), never cut to three.
//! An R5 login takes the R6 run that holds it (`-Users-sarah-leitner-…` →
//! `sarah-leitner`, not `sarah`).
//!
//! # URLs yield to the names inside them
//!
//! [`cut_urls_around_positions`] cuts a `URL` span around the `Position`
//! names it strictly contains, before overlap resolution (S10): without it
//! the URL (priority 5, preserved by `support-email` and `offline`) would
//! evict the name and forward it in clear. The cut is one sorted sweep
//! (review I3).
//!
//! The detector holds no text and reports only offsets.

use std::sync::LazyLock;

use super::{DetectCtx, Detector};
use crate::Result;
use crate::detect::technical::{Mark, is_also_name, vocabulary_mark};
use crate::gazetteer::is_first_name;
use crate::span::{DetectorId, EntityKind, Span};
use crate::stoplist::{is_common_word, is_name_like_word};

/// Confidence of R1 (home root), R4 (tilde) and R5 (flattened project).
const CONF_HOME: f32 = 0.90;
/// Confidence of R2 (person cue), R3 (code host) and R6 (first name).
const CONF_CUE: f32 = 0.80;

/// A token longer than this many bytes is skipped whole (Review Focus 4).
pub const MAX_TOKEN_BYTES: usize = 4096;

/// Longest name segment, in characters.
const MAX_NAME_CHARS: usize = 64;

/// R1: a segment after one of these (any case) is a login.
const HOME_ROOTS: &[&str] = &["home", "homes", "home$", "users"];

/// R2: a segment after one of these (any case) is a person. `in` counts
/// only on `linkedin.com` ([`is_person_cue`]).
const PERSON_CUES: &[&str] = &[
    "user",
    "u",
    "people",
    "person",
    "persons",
    "personen",
    "staff",
    "team",
    "member",
    "members",
    "profile",
    "profiles",
    "profil",
    "author",
    "authors",
    "autor",
    "autoren",
    "mitarbeiter",
    "mitarbeiterin",
    "mitarbeiterinnen",
    "benutzer",
];

/// R3: the first path segment on one of these hosts is an account.
const CODE_HOSTS: &[&str] = &[
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "codeberg.org",
    "x.com",
    "twitter.com",
    "instagram.com",
    "facebook.com",
];

/// Logins that name no person: system, service and CI accounts, shared and
/// placeholder folders (compared lowercased). Never a name for R1–R5.
/// `crates/inumakid/src/identity.rs` keeps its own list; the two drift
/// until the follow-up of ruling S11.
pub const GENERIC_ACCOUNTS: &[&str] = &[
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

/// A slashless `~word` is code, not a login, after one of these words
/// (`return ~mask;`, `if (~idx)`; ruling L3-30). The verifier keeps its own
/// copy, equal by a test.
pub(crate) const TILDE_CODE_KEYWORDS: &[&str] = &[
    "and", "assert", "await", "case", "elif", "for", "if", "in", "match", "not", "or", "return",
    "sizeof", "switch", "unless", "until", "when", "while", "yield",
];

/// A slashless `~word` is code, not a login, when the last character before
/// it (spaces skipped) is one of these (`x & ~flags`, `mode: ~fast`; ruling
/// L3-30). `-` and `*` are not in it, so a list bullet stays a login
/// context. The verifier keeps its own copy, equal by a test.
pub(crate) const TILDE_OPERATORS: &str = "&|^=:!+/%<>?,;~([{";

/// Site routes that follow a cue segment without naming anyone
/// (`/users/search`, `/team/about`; compared lowercased).
const ROUTE_WORDS: &[&str] = &[
    "about",
    "api",
    "apps",
    "archive",
    "blog",
    "careers",
    "collections",
    "contact",
    "datenschutz",
    "docs",
    "download",
    "downloads",
    "edit",
    "enterprise",
    "explore",
    "faq",
    "features",
    "guide",
    "guides",
    "help",
    "home",
    "impressum",
    "imprint",
    "index",
    "install",
    "issues",
    "jobs",
    "karriere",
    "kontakt",
    "list",
    "login",
    "logout",
    "marketplace",
    "new",
    "news",
    "notifications",
    "orgs",
    "overview",
    "page",
    "pages",
    "pricing",
    "privacy",
    "pulls",
    "register",
    "search",
    "settings",
    "signin",
    "signup",
    "sitemap",
    "sponsors",
    "terms",
    "topics",
    "trending",
];

/// File extensions cut off a last name segment (`gruber.html` → `gruber`).
/// An unlisted extension without a digit stays, so a `first.last` login
/// that ends a path (`/home/anna.lutz`) is judged whole.
const FILE_EXTENSIONS: &[&str] = &[
    "asp", "aspx", "bak", "c", "cfg", "cgi", "cjs", "conf", "cpp", "cs", "css", "csv", "doc",
    "docx", "eml", "env", "gif", "go", "gz", "h", "heic", "hpp", "htm", "html", "ics", "ini",
    "ipynb", "java", "jpeg", "jpg", "js", "json", "jsp", "jsx", "kt", "lock", "log", "md", "mjs",
    "mov", "msg", "odp", "ods", "odt", "pdf", "php", "png", "ppt", "pptx", "py", "rb", "rs", "rtf",
    "scss", "sh", "sql", "svg", "swift", "tar", "tgz", "tif", "tiff", "tmp", "toml", "ts", "tsx",
    "txt", "vcf", "vue", "webp", "xhtml", "xls", "xlsx", "xml", "yaml", "yml", "zip",
];

/// A whitespace token is cut into pieces at these characters before it is
/// scanned (JSON and markup punctuation; fix round 1, item 3).
const PIECE_DELIMITERS: &[char] = &['"', ',', '{', '}', '[', ']', '\'', '<', '>', '(', ')'];

const LEADING: &[char] = &['(', '[', '{', '"', '\'', '<', '«'];
const TRAILING: &[char] = &[
    ')', ']', '}', '"', '\'', '>', '»', ',', ';', ':', '!', '?', '.',
];

/// Names in paths and URLs (see the module docs). Holds no state.
#[derive(Debug, Default, Clone, Copy)]
pub struct PathNameDetector;

impl PathNameDetector {
    /// The detector.
    pub fn new() -> Self {
        PathNameDetector
    }
}

impl Detector for PathNameDetector {
    fn id(&self) -> DetectorId {
        DetectorId::Position
    }

    fn detect(&self, text: &str, _ctx: &DetectCtx) -> Result<Vec<Span>> {
        Ok(find(text)
            .into_iter()
            .map(|(a, b, c)| Span::new(a, b, EntityKind::Person, c, DetectorId::Position))
            .collect())
    }
}

/// `(start, end, confidence)` of every name, sorted, non-overlapping.
fn find(text: &str) -> Vec<(usize, usize, f32)> {
    let paths = find_paths(text);
    let tilde = tilde_words(text);
    if tilde.is_empty() {
        return paths;
    }
    // Both lists are sorted; a slashless `~word` lies in a token without a
    // path separator, so the two hardly ever overlap. Merge, drop overlaps.
    let mut all: Vec<(usize, usize, f32)> = paths.into_iter().chain(tilde).collect();
    all.sort_by_key(|&(a, b, _)| (a, b));
    let mut out = Out::default();
    for (a, b, c) in all {
        out.push(a, b, c);
    }
    out.spans
}

/// The path and URL names (every rule but the slashless `~word`).
fn find_paths(text: &str) -> Vec<(usize, usize, f32)> {
    let mut out = Out::default();
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return out.spans;
    }
    // S26: a text that is one token with no path separator (a mirror stem).
    if !trimmed.contains(char::is_whitespace) && !trimmed.contains(['/', '\\']) {
        if trimmed.len() <= MAX_TOKEN_BYTES {
            let start = text.len() - text.trim_start().len();
            if let Some((a, b)) = trim_token(text, start, start + trimmed.len()) {
                r6(text, a, b, &mut out);
            }
        }
        return out.spans;
    }
    let base = text.as_ptr() as usize;
    let mut tokens = text
        .split_whitespace()
        .map(|t| {
            let s = t.as_ptr() as usize - base;
            (s, s + t.len())
        })
        .peekable();
    while let Some((s, e)) = tokens.next() {
        if !text[s..e].contains(['/', '\\']) {
            continue;
        }
        let next = tokens.peek().copied();
        // Pieces between JSON and markup punctuation (fix round 1, item 3):
        // one pass over the token, so a minified JSON line of any length is
        // scanned piece by piece.
        let mut a = s;
        for (i, c) in text[s..e].char_indices() {
            if PIECE_DELIMITERS.contains(&c) {
                scan_piece(text, a, s + i, None, &mut out);
                a = s + i + c.len_utf8();
            }
        }
        scan_piece(text, a, e, next, &mut out);
    }
    out.spans
}

/// One piece `s..e` of a whitespace token; `next` (the following token) is
/// given only for the piece that ends the token. A piece longer than
/// [`MAX_TOKEN_BYTES`] or without a path separator is skipped.
fn scan_piece(text: &str, s: usize, e: usize, next: Option<(usize, usize)>, out: &mut Out) {
    if s < e && e - s <= MAX_TOKEN_BYTES && text[s..e].contains(['/', '\\']) {
        scan_token(text, s, e, next, out);
    }
}

/// The slashless `~word` logins of `text` (R4 without a path; rulings
/// L3-29, L3-30), sorted. A `~` counts only in a login context, never in
/// code or an approximation:
///
/// - (a) it starts the text, or follows whitespace, a quote, or `(`, or
///   follows `:` or `=` right after an option or an all-caps variable
///   (`--dir=~mhuber`, `HOME_DIR=~mhuber`; ruling L136);
///   after whitespace or `(` the last character before it (spaces
///   skipped) is no operator ([`TILDE_OPERATORS`]: `x & ~flags`,
///   `mode: ~fast`) and the word before it is no code keyword
///   ([`TILDE_CODE_KEYWORDS`]: `return ~mask;`, `if (~idx)`); a `(` right
///   after a letter, digit or `_` is a call (`f(~x)`);
/// - (b) the word, `[A-Za-z0-9._-]` without trailing dots, has three or
///   more characters, starts with a letter and holds a lowercase letter
///   (`~FLAG_READY` is a constant);
/// - (c) it is followed by the end, a sentence-final `.`, `,`, `;`, `:`,
///   `)`, a quote, or spaces up to the end of the line or a character that
///   is no letter or digit (`cd ~mhuber && ls`); a following word means an
///   approximation (`~zwei Stunden`, `takes ~half the time`); `/` or `\\`
///   makes it a path, which R4 reads in [`scan_token`];
/// - (d) the word is no stoplist common word that is not name-like and no
///   generic account.
///
/// The verifier's home-login check applies the same rule with its own code
/// and its own copies of the lists (equal by tests), so the two sides agree
/// (ruling L134).
fn tilde_words(text: &str) -> Vec<(usize, usize, f32)> {
    let mut out = Vec::new();
    let b = text.as_bytes();
    for (i, _) in text.match_indices('~') {
        if !tilde_context_ok(text, i) {
            continue;
        }
        let a = i + 1;
        let run = b[a..]
            .iter()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
            .count();
        let run_end = a + run;
        let mut w_end = run_end;
        while w_end > a && b[w_end - 1] == b'.' {
            w_end -= 1;
        }
        let w = &text[a..w_end];
        if w.len() < 3
            || !w.as_bytes()[0].is_ascii_alphabetic()
            || !w.bytes().any(|c| c.is_ascii_lowercase())
        {
            continue;
        }
        let rest = &text[run_end..];
        let after_ok = if w_end < run_end {
            // Sentence-final dots.
            rest.chars().next().is_none_or(char::is_whitespace)
        } else {
            match rest.chars().next() {
                None => true,
                Some(',' | ';' | ':' | ')' | '"' | '\'') => true,
                Some(c) if c.is_whitespace() => {
                    let r = rest.trim_start_matches(|c: char| c.is_whitespace() && c != '\n');
                    r.chars()
                        .next()
                        .is_none_or(|c| c == '\n' || !c.is_alphanumeric())
                }
                _ => false,
            }
        };
        if !after_ok || (is_common_word(w) && !is_name_like_word(w)) || in_set(&GENERIC_SET, w) {
            continue;
        }
        out.push((a, w_end, CONF_HOME));
    }
    out
}

/// Where R4's login starts in the segment `word`: after a leading `~`, or
/// after a `~` and a letter that follow `:` or `=` inside it
/// (`host:~mhuber`, `--dir=~mhuber`, `x=~mask`; ruling L136, the verifier
/// reads the same roots).
fn tilde_login_start(word: &str) -> Option<usize> {
    if word.starts_with('~') {
        return Some(1);
    }
    let b = word.as_bytes();
    (1..b.len())
        .find(|&k| {
            b[k] == b'~'
                && matches!(b[k - 1], b':' | b'=')
                && word[k + 1..]
                    .chars()
                    .next()
                    .is_some_and(char::is_alphabetic)
        })
        .map(|k| k + 1)
}

/// The run of `[A-Za-z0-9_-]` that ends `head` is an option (`--dir`) or an
/// all-caps variable (`HOME_DIR`): then a `:` or `=` right after it may
/// precede a slashless `~login` (ruling L136).
fn is_option_or_variable(head: &str) -> bool {
    let n = head
        .bytes()
        .rev()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
        .count();
    let w = &head[head.len() - n..];
    if let Some(opt) = w.strip_prefix("--") {
        return !opt.is_empty();
    }
    !w.starts_with(|c: char| c.is_ascii_digit())
        && w.bytes().any(|c| c.is_ascii_uppercase())
        && w.bytes()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
}

/// Rule (a) of [`tilde_words`] for the `~` at byte `i`.
fn tilde_context_ok(text: &str, i: usize) -> bool {
    let Some(p) = text[..i].chars().next_back() else {
        return true;
    };
    if p == '"' || p == '\'' {
        return true;
    }
    if p == ':' || p == '=' {
        return is_option_or_variable(&text[..i - 1]);
    }
    let before = if p.is_whitespace() {
        &text[..i]
    } else if p == '(' {
        let b = &text[..i - 1];
        if b.chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
        {
            return false;
        }
        b
    } else {
        return false;
    };
    let t = before.trim_end();
    match t.chars().next_back() {
        None => true,
        Some(c) if TILDE_OPERATORS.contains(c) => false,
        Some(c) if c.is_ascii_alphabetic() => {
            let word_len = t.bytes().rev().take_while(u8::is_ascii_alphabetic).count();
            !TILDE_CODE_KEYWORDS.contains(&&t[t.len() - word_len..])
        }
        _ => true,
    }
}

/// Spans in text order; a span that starts inside the previous one (an R1
/// continuation reaching into the next token) is dropped.
#[derive(Default)]
struct Out {
    spans: Vec<(usize, usize, f32)>,
}

impl Out {
    fn push(&mut self, a: usize, b: usize, conf: f32) {
        if a >= b {
            return;
        }
        if self.spans.last().is_some_and(|&(_, e, _)| a < e) {
            return;
        }
        self.spans.push((a, b, conf));
    }
}

/// The token `s..e` without its surrounding quotes, brackets and trailing
/// sentence punctuation; `None` when nothing is left.
fn trim_token(text: &str, s: usize, e: usize) -> Option<(usize, usize)> {
    let t = &text[s..e];
    let lead = t.len() - t.trim_start_matches(LEADING).len();
    let rest = &t[lead..];
    let core = rest.trim_end_matches(TRAILING);
    (!core.is_empty()).then(|| (s + lead, s + lead + core.len()))
}

/// A byte range of the text.
#[derive(Debug, Clone, Copy)]
struct Seg {
    start: usize,
    end: usize,
}

/// A candidate split into host and path segments.
struct Parsed {
    /// Lowercased host without a leading `www.` (URL and scp only).
    host: Option<String>,
    /// The host's range, scanned by R6 only.
    host_seg: Option<Seg>,
    /// Path segments (empty ones included, so `prev` is exact).
    segs: Vec<Seg>,
    /// A filesystem path (the R1 continuation applies only there).
    filesystem: bool,
    /// Where a URL's query or fragment starts (`?` or `#`), if it has one.
    query_start: Option<usize>,
}

fn split_into(text: &str, start: usize, end: usize, seps: &[char]) -> Vec<Seg> {
    let mut out = Vec::new();
    let mut a = start;
    for (i, c) in text[start..end].char_indices() {
        if seps.contains(&c) {
            out.push(Seg {
                start: a,
                end: start + i,
            });
            a = start + i + c.len_utf8();
        }
    }
    out.push(Seg { start: a, end });
    out
}

/// Where a URL starts inside `core`, and whether it has a scheme: the
/// longest run of scheme characters starting with a letter right before the
/// first `://`, or a `www.` at the start or after a character that is not
/// part of a host name (`repo=https://…`, `href=www.…`; fix round 1, item 1).
fn url_start(core: &str) -> Option<(usize, bool)> {
    let b = core.as_bytes();
    let scheme = scheme_sep(core).and_then(|(i, _)| {
        let mut st = i;
        while st > 0
            && (b[st - 1].is_ascii_alphanumeric() || matches!(b[st - 1], b'+' | b'-' | b'.'))
        {
            st -= 1;
        }
        while st < i && !b[st].is_ascii_alphabetic() {
            st += 1;
        }
        (st < i).then_some(st)
    });
    let www = (0..b.len().saturating_sub(4)).find(|&p| {
        b[p..p + 4].eq_ignore_ascii_case(b"www.")
            && (p == 0
                || !(b[p - 1].is_ascii_alphanumeric()
                    || matches!(b[p - 1], b'.' | b'-' | b'/' | b':')))
    });
    match (scheme, www) {
        (Some(a), Some(w)) if w < a => Some((w, false)),
        (Some(a), _) => Some((a, true)),
        (None, Some(w)) => Some((w, false)),
        (None, None) => None,
    }
}

/// The first scheme separator in `core`: `://`, or its JSON-escaped form
/// `:\/\/` (ruling L132); its offset and length.
fn scheme_sep(core: &str) -> Option<(usize, usize)> {
    let plain = core.find("://").map(|i| (i, 3));
    let escaped = core.find(r":\/\/").map(|i| (i, 5));
    match (plain, escaped) {
        (Some(p), Some(x)) => Some(if x.0 < p.0 { x } else { p }),
        (p, None) => p,
        (None, x) => x,
    }
}

fn parse(text: &str, cs: usize, ce: usize) -> Parsed {
    let core = &text[cs..ce];
    if let Some((off, scheme)) = url_start(core) {
        if scheme {
            let (i, len) = scheme_sep(&core[off..]).unwrap_or((0, 3));
            return parse_url(text, cs + off + i + len, ce);
        }
        return parse_url(text, cs + off, ce);
    }
    if let Some(p) = parse_scp(text, cs, ce) {
        return p;
    }
    let segs = split_into(text, cs, ce, &['/', '\\']);
    // A URL without a scheme on a code host or LinkedIn
    // (`github.com/mhuber/tool`, `linkedin.com/in/mhuber`).
    if segs.len() > 1 && is_bare_host(&text[segs[0].start..segs[0].end]) {
        let (host, host_seg) = host_of(text, segs[0].start, segs[0].end);
        return Parsed {
            host,
            host_seg,
            segs: segs[1..].to_vec(),
            filesystem: false,
            query_start: None,
        };
    }
    Parsed {
        host: None,
        host_seg: None,
        segs,
        filesystem: true,
        query_start: None,
    }
}

fn host_of(text: &str, a: usize, b: usize) -> (Option<String>, Option<Seg>) {
    if a >= b {
        return (None, None);
    }
    let raw = text[a..b].to_lowercase();
    let host = raw.strip_prefix("www.").map(str::to_string).unwrap_or(raw);
    (Some(host), Some(Seg { start: a, end: b }))
}

/// `a..ce` is the part after `scheme://` (or a `www.` token). The path is
/// split at `/` and `\`, so a JSON-escaped URL (`github.com\/mhuber`) has
/// its segments too; empty segments are skipped by the rules (ruling L132).
fn parse_url(text: &str, a: usize, ce: usize) -> Parsed {
    let rest = &text[a..ce];
    let auth_len = rest.find(['/', '\\', '?', '#']).unwrap_or(rest.len());
    let auth = &rest[..auth_len];
    let h0 = auth.rfind('@').map_or(0, |i| i + 1);
    let h1 = auth[h0..].find(':').map_or(auth.len(), |i| h0 + i);
    let (host, host_seg) = host_of(text, a + h0, a + h1);
    let path_start = a + auth_len;
    let path_end = path_start
        + text[path_start..ce]
            .find(['?', '#'])
            .unwrap_or(ce - path_start);
    let segs = if path_start < path_end && text[path_start..].starts_with(['/', '\\']) {
        split_into(text, path_start + 1, path_end, &['/', '\\'])
    } else {
        Vec::new()
    };
    Parsed {
        host,
        host_seg,
        segs,
        filesystem: false,
        query_start: (path_end < ce).then_some(path_end),
    }
}

/// `user@host:path` with no separator before the `:` and a dotted host.
fn parse_scp(text: &str, cs: usize, ce: usize) -> Option<Parsed> {
    let core = &text[cs..ce];
    let colon = core.find(':')?;
    let before = &core[..colon];
    if before.contains(['/', '\\']) || core[colon + 1..].starts_with('/') {
        return None;
    }
    let at = before.find('@')?;
    let user = &before[..at];
    let host = &before[at + 1..];
    let user_ok = !user.is_empty()
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    let host_ok = host.contains('.')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
    if !user_ok || !host_ok {
        return None;
    }
    let (h, host_seg) = host_of(text, cs + at + 1, cs + colon);
    Some(Parsed {
        host: h,
        host_seg,
        segs: split_into(text, cs + colon + 1, ce, &['/']),
        filesystem: false,
        query_start: None,
    })
}

/// `w` is in `list` (ASCII entries), any case; no allocation. For the
/// short lists ([`HOME_ROOTS`], [`CODE_HOSTS`]).
fn listed(list: &[&str], w: &str) -> bool {
    list.iter().any(|x| x.eq_ignore_ascii_case(w))
}

/// A sorted copy of a word list, for [`in_set`].
fn sorted(list: &'static [&'static str]) -> Vec<&'static str> {
    let mut v = list.to_vec();
    v.sort_unstable();
    v
}

static GENERIC_SET: LazyLock<Vec<&'static str>> = LazyLock::new(|| sorted(GENERIC_ACCOUNTS));
static ROUTE_SET: LazyLock<Vec<&'static str>> = LazyLock::new(|| sorted(ROUTE_WORDS));
static CUE_SET: LazyLock<Vec<&'static str>> = LazyLock::new(|| sorted(PERSON_CUES));
static EXT_SET: LazyLock<Vec<&'static str>> = LazyLock::new(|| sorted(FILE_EXTENSIONS));

/// `w` (any case) is in the sorted ASCII word list `set`: lowercased on
/// the stack and binary-searched, since these checks run for every
/// segment (latency, L117). A word with a non-ASCII character is in none.
fn in_set(set: &[&str], w: &str) -> bool {
    let mut buf = [0u8; 32];
    if w.len() > buf.len() || !w.is_ascii() {
        return false;
    }
    for (d, b) in buf.iter_mut().zip(w.bytes()) {
        *d = b.to_ascii_lowercase();
    }
    std::str::from_utf8(&buf[..w.len()]).is_ok_and(|l| set.binary_search(&l).is_ok())
}

/// `raw` (any case, a leading `www.` allowed) is a [`CODE_HOSTS`] host or
/// `linkedin.com`: a bare `host/path` token there is read as a URL.
fn is_bare_host(raw: &str) -> bool {
    let h = match raw.get(..4) {
        Some(p) if p.eq_ignore_ascii_case("www.") => &raw[4..],
        _ => raw,
    };
    listed(CODE_HOSTS, h) || h.eq_ignore_ascii_case("linkedin.com")
}

fn is_person_cue(w: &str, host: Option<&str>) -> bool {
    in_set(&CUE_SET, w) || (w.eq_ignore_ascii_case("in") && host == Some("linkedin.com"))
}

/// One candidate token `s..e`; `next` is the following token, for the R1
/// continuation.
fn scan_token(text: &str, s: usize, e: usize, next: Option<(usize, usize)>, out: &mut Out) {
    let Some((cs, ce)) = trim_token(text, s, e) else {
        return;
    };
    // A prefix before a URL (`repo=`, `href=`) is a piece of its own.
    if let Some((off, _)) = url_start(&text[cs..ce]).filter(|&(off, _)| off > 0) {
        scan_piece(text, cs, cs + off, None, out);
        return scan_token(text, cs + off, ce, next, out);
    }
    let p = parse(text, cs, ce);
    if let Some(h) = p.host_seg {
        // The top-level domain is no name part (`www.anna-gruber.at`).
        let end = text[h.start..h.end]
            .rfind('.')
            .map_or(h.end, |i| h.start + i);
        r6(text, h.start, end, out);
    }
    let code_host = p.host.as_deref().is_some_and(|h| CODE_HOSTS.contains(&h));
    let n = p.segs.len();
    // The nearest non-empty segment before this one: an escaped or doubled
    // separator (`C:\\Users`, `\/home\/x`, `//home//x`) leaves empty
    // segments between a root and its login (fix round 1, item 2).
    let mut prev: Option<&str> = None;
    let mut prev2: Option<&str> = None;
    // A URL whose host is a home root (`C://Users/x`, `http://home/x`): the
    // verifier reads `/Users/`, `/home/` there, so the host is the first
    // path segment's root, and a one-letter scheme is a drive (fix round 2,
    // found by the property test).
    if let Some(h) = p.host_seg {
        let host = &text[h.start..h.end];
        if listed(HOME_ROOTS, host) {
            prev = Some(host);
            let pre = &text.as_bytes()[cs..h.start];
            if pre.len() > 2
                && pre[0].is_ascii_alphabetic()
                && pre[1] == b':'
                && pre[2..].iter().all(|c| matches!(c, b'/' | b'\\'))
            {
                prev2 = Some(&text[cs..cs + 2]);
            }
        }
    }
    let mut first = true;
    for (k, seg) in p.segs.iter().enumerate() {
        if seg.start == seg.end {
            continue;
        }
        let word = &text[seg.start..seg.end];
        let is_first = std::mem::replace(&mut first, false);
        let last = k + 1 == n;
        // After a root the verifier reads, the verifier judges the whole
        // segment, so R1 comes before R4 (unless the segment starts with
        // `~`) and R5 there (`/Users\-Users-x`, `C:\Users\C:~x`; fix
        // round 2, found by the property test).
        let verifier_prev = prev.is_some_and(|w| is_verifier_root(w, prev2));
        let tilde = tilde_login_start(word).map(|k| seg.start + k);
        let r1 = prev.is_some_and(|w| listed(HOME_ROOTS, w))
            && (verifier_prev && !word.starts_with('~') || tilde.is_none());
        let r5 = if verifier_prev {
            None
        } else {
            r5_login(text, *seg)
        };
        let covered = if r1 {
            // R1, with the continuation over a space (review I4).
            let cont = (p.filesystem && seg.end == ce && ce == e)
                .then(|| continuation(text, next))
                .flatten();
            let r1_span = match cont {
                Some((ws, we)) if is_login(&format!("{word}-{}", &text[ws..we]), true) => {
                    Some((seg.start, we))
                }
                // A root the verifier also reads: the verifier's judgement,
                // so whatever it would refuse is tokenized (ruling L134).
                _ if verifier_prev => home_login_range(text, seg.start, seg.end, last),
                _ => login_cut(text, seg.start, seg.end)
                    .and_then(|(a, b)| name_range(text, a, b, last && b == seg.end, true)),
            };
            if let Some((a, b)) = r1_span {
                out.push(a, b, CONF_HOME);
            }
            // A `~login` after `:` or `=` inside the login segment is a root
            // of its own for the verifier (`/Users/C:~x/`).
            let r4_span = tilde
                .filter(|&a| r1_span.is_none_or(|(_, b)| a >= b))
                .and_then(|a| home_login_range(text, a, seg.end, last));
            if let Some((a, b)) = r4_span {
                out.push(a, b, CONF_HOME);
            }
            (r1_span.is_some() || r4_span.is_some()).then_some(())
        } else if let Some(a) = tilde {
            // R4: judged as the verifier judges a home login (ruling L134).
            home_login_range(text, a, seg.end, last).map(|(a, b)| out.push(a, b, CONF_HOME))
        } else if let Some((a, b)) = r5 {
            // R5; the login takes the R6 run that holds it.
            let (a, b) = r6_runs(text, seg.start, seg.end)
                .into_iter()
                .find(|&(ra, rb)| ra <= a && b <= rb)
                .unwrap_or((a, b));
            out.push(a, b, CONF_HOME);
            Some(())
        } else if prev.is_some_and(|w| is_person_cue(w, p.host.as_deref()))
            || (is_first && code_host)
        {
            // R2, R3. After a person cue a `Rare` word is a name too, as
            // after a home root (L3-28; final fix wave item 3).
            let cue = prev.is_some_and(|w| is_person_cue(w, p.host.as_deref()));
            login_cut(text, seg.start, seg.end)
                .and_then(|(a, b)| name_range(text, a, b, last && b == seg.end, cue))
                .map(|(a, b)| out.push(a, b, CONF_CUE))
        } else {
            None
        };
        if covered.is_none() {
            r6(text, seg.start, seg.end, out);
        }
        prev2 = prev;
        prev = Some(word);
    }
    // A URL nested in the query or fragment (`?next=https://github.com/x`;
    // ruling L133): scanned as a URL of its own, after the outer one.
    if let Some(q) = p.query_start {
        if let Some((off, true)) = url_start(&text[q..ce]) {
            scan_token(text, q + off, ce, None, out);
        }
    }
}

/// Characters that end a login inside a path segment (fix round 1, item
/// 2): a placeholder character (`$ < > { }`) and the punctuation the
/// verifier's home-login check stops at. A placeholder exempts a login only
/// at its start ([`login_cut`]).
const LOGIN_STOPS: &[char] = &[
    '$', '<', '>', '{', '}', ':', ';', '|', '`', '(', ')', '[', ']', ',', '"', '\'',
];

/// The login in the segment `a..b`: up to the first [`LOGIN_STOPS`]
/// character, without trailing `. ! ?`; `None` when it starts with a
/// placeholder (`$`, `<`, `>`, `{`, `}`, or a `%` that does not start a
/// `%XX` escape: `${USER}`, `<you>`, `%USERNAME%`) or is empty.
fn login_cut(text: &str, a: usize, b: usize) -> Option<(usize, usize)> {
    let seg = &text[a..b];
    let sb = seg.as_bytes();
    let placeholder = match sb.first() {
        Some(b'$' | b'<' | b'>' | b'{' | b'}') => true,
        Some(b'%') => !(sb.len() > 2 && sb[1].is_ascii_hexdigit() && sb[2].is_ascii_hexdigit()),
        _ => false,
    };
    if placeholder {
        return None;
    }
    let mut e = a + seg.find(LOGIN_STOPS).unwrap_or(seg.len());
    while e > a && matches!(text.as_bytes()[e - 1], b'.' | b'!' | b'?') {
        e -= 1;
    }
    (e > a).then_some((a, e))
}

/// The previous segment `w` is a home root the verifier's home-login check
/// also reads: `home`, `homes`, `Users` (exact case), or `users` in any
/// case after a drive (`C:`).
fn is_verifier_root(w: &str, prev2: Option<&str>) -> bool {
    matches!(w, "home" | "homes" | "Users")
        || (w.eq_ignore_ascii_case("users")
            && prev2.is_some_and(|d| {
                let d = d.as_bytes();
                d.len() == 2 && d[0].is_ascii_alphabetic() && d[1] == b':'
            }))
}

/// A home login after a root the verifier reads, or after `~` (R1, R4;
/// ruling L134): the login ([`login_cut`]) is a name when it holds a letter
/// and is not a generic account, which is exactly when the verifier would
/// refuse it in clear, so one- and two-letter logins (`/Users/kl/`) and
/// words (`/home/about`) count. The last segment loses a listed or
/// digit-holding extension when the stem is still such a login
/// (`/Users/mhuber.txt` → `mhuber`; the verifier passes an extension right
/// after a token).
fn home_login_range(text: &str, a: usize, b: usize, last: bool) -> Option<(usize, usize)> {
    let (a, e) = login_cut(text, a, b)?;
    let ok = |x: usize, y: usize| {
        let w = &text[x..y];
        w.chars().any(char::is_alphabetic) && !in_set(&GENERIC_SET, w)
    };
    if !ok(a, e) {
        return None;
    }
    if last && e == b {
        if let Some(dot) = text[a..e].rfind('.') {
            let ext = &text[a + dot + 1..e];
            let ext_ok = (1..=5).contains(&ext.len())
                && ext.chars().all(|c| c.is_ascii_alphanumeric())
                && (in_set(&EXT_SET, ext) || ext.bytes().any(|c| c.is_ascii_digit()));
            if dot > 0 && ext_ok && ok(a, a + dot) {
                return Some((a, a + dot));
            }
        }
    }
    Some((a, e))
}

/// The range of the letters-only word that starts the next token when a
/// `\` or `/` follows it directly (`Gruber\Documents` → `Gruber`).
fn continuation(text: &str, next: Option<(usize, usize)>) -> Option<(usize, usize)> {
    let (ns, ne) = next?;
    let t = &text[ns..ne];
    let wl = t.len() - t.trim_start_matches(char::is_alphabetic).len();
    (wl > 0 && t[wl..].starts_with(['\\', '/'])).then_some((ns, ns + wl))
}

/// R5: the login range in `-Users-<login>-…`, `-home-<login>-…` or a
/// Windows `C--Users-<login>-…`, when it is a name.
fn r5_login(text: &str, seg: Seg) -> Option<(usize, usize)> {
    let w = &text[seg.start..seg.end];
    let b = w.as_bytes();
    let skip = if b.len() > 3 && b[0].is_ascii_alphabetic() && &b[1..3] == b"--" {
        2
    } else {
        0
    };
    let rest = &w[skip..];
    let prefix = ["-users-", "-home-"].into_iter().find(|p| {
        // Bytes, not a str slice: `p.len()` may fall inside a multi-byte
        // character (`Adressänderung`; fix round 1, found by the code
        // sample gate).
        rest.len() > p.len() && rest.as_bytes()[..p.len()].eq_ignore_ascii_case(p.as_bytes())
    })?;
    let a = seg.start + skip + prefix.len();
    let login_len = text[a..seg.end].find('-').unwrap_or(seg.end - a);
    let (a, b) = (a, a + login_len);
    is_login(&text[a..b], true).then_some((a, b))
}

/// The name range of a R1–R5 segment `a..b`: without a listed extension
/// when it is the last segment; `None` when it is no name. `home` is true
/// for R1, R4 and R5 ([`is_login`]).
fn name_range(text: &str, a: usize, b: usize, last: bool, home: bool) -> Option<(usize, usize)> {
    let seg = &text[a..b];
    if last {
        if let Some(dot) = seg.rfind('.') {
            let ext = &seg[dot + 1..];
            let ext_ok =
                (1..=5).contains(&ext.len()) && ext.chars().all(|c| c.is_ascii_alphanumeric());
            if ext_ok && dot > 0 {
                let stem = (a, a + dot);
                if in_set(&EXT_SET, ext) || ext.bytes().any(|c| c.is_ascii_digit()) {
                    return is_login(&text[stem.0..stem.1], home).then_some(stem);
                }
                if is_login(seg, home) {
                    return Some((a, b));
                }
                return is_login(&text[stem.0..stem.1], home).then_some(stem);
            }
        }
    }
    is_login(seg, home).then_some((a, b))
}

/// Closes the letter run in `run` at `end` (see [`letter_parts`]).
fn close_part<'a>(
    seg: &'a str,
    parts: &mut Vec<Part<'a>>,
    run: &mut Option<(usize, bool)>,
    end: usize,
    sep_after: bool,
) {
    if let Some((s, sep_before)) = run.take() {
        let word = &seg[s..end];
        let one = word.chars().count() == 1;
        parts.push(Part {
            word,
            initial: one && sep_before && sep_after,
        });
    }
}

/// A letter part of a login and whether it is a single-letter initial.
struct Part<'a> {
    word: &'a str,
    initial: bool,
}

/// The letter parts of `seg` (split at `. _ -`, `%XX` and digits), or
/// `None` when `seg` holds a character a login cannot hold.
fn letter_parts(seg: &str) -> Option<Vec<Part<'_>>> {
    let b = seg.as_bytes();
    let mut parts = Vec::new();
    // (start of the current letter run, whether a separator or the start
    // precedes it)
    let mut run: Option<(usize, bool)> = None;
    let mut after_sep = true;
    let mut i = 0;
    while i < b.len() {
        let c = seg[i..].chars().next()?;
        let l = c.len_utf8();
        if c.is_alphabetic() {
            if run.is_none() {
                run = Some((i, after_sep));
            }
            i += l;
            continue;
        }
        if matches!(c, '.' | '_' | '-') {
            close_part(seg, &mut parts, &mut run, i, true);
            after_sep = true;
            i += l;
        } else if c == '%' {
            if i + 2 < b.len() && b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit() {
                close_part(seg, &mut parts, &mut run, i, true);
                after_sep = true;
                i += 3;
            } else {
                return None;
            }
        } else if c.is_alphanumeric() {
            close_part(seg, &mut parts, &mut run, i, false);
            after_sep = false;
            i += l;
        } else {
            return None;
        }
    }
    close_part(seg, &mut parts, &mut run, b.len(), true);
    Some(parts)
}

/// Whether `seg` is a login or person name segment for R1–R5 (module docs).
/// `home` is true right after a home root (R1, R4, R5): a `Rare`
/// vocabulary word is then a login too (`/home/steuer/`; ruling L3-28).
fn is_login(seg: &str, home: bool) -> bool {
    let n = seg.chars().count();
    if !(2..=MAX_NAME_CHARS).contains(&n) || !seg.chars().any(char::is_alphabetic) {
        return false;
    }
    if in_set(&GENERIC_SET, seg) || in_set(&ROUTE_SET, seg) {
        return false;
    }
    let Some(parts) = letter_parts(seg) else {
        return false;
    };
    if parts.iter().all(|p| p.word.chars().count() <= 2) {
        return false;
    }
    // The gazetteer lookup is the costly check, so it runs last: only when
    // the word checks alone would reject the segment (latency, L117).
    if let [only] = parts.as_slice() {
        let w = only.word;
        let mark = vocabulary_mark(w);
        // L3-28: after a home root a `Rare` word (a rare Census surname that
        // is also a document word) is a login; an `Unmarked` one never is.
        let home_rare = home && mark == Some(Mark::Rare);
        let rejected = in_set(&GENERIC_SET, w)
            || in_set(&ROUTE_SET, w)
            || mark == Some(Mark::Unmarked)
            || (mark == Some(Mark::Rare) && !home_rare)
            || (!home_rare && is_common_word(w) && !is_name_like_word(w));
        return !rejected || is_first_name(w);
    }
    let by_word = parts.iter().enumerate().any(|(k, p)| {
        let w = p.word;
        let common = is_common_word(w);
        if w.chars().count() >= 3 && !common && vocabulary_mark(w).is_none() {
            return true;
        }
        let next_to_initial =
            (k > 0 && parts[k - 1].initial) || parts.get(k + 1).is_some_and(|q| q.initial);
        common && is_name_like_word(w) && next_to_initial
    });
    by_word || parts.iter().any(|p| is_first_name(p.word))
}

/// How a part counts for R6.
#[derive(Clone, Copy, PartialEq)]
enum R6Part {
    /// A first name, not `ALSO_NAMES`, in neither vocabulary.
    Anchor,
    /// A first name, or a letters-only word of 3+ letters that is not an
    /// `Unmarked` or `Rare` vocabulary word and, if a stoplist word, is
    /// name-like.
    Adjacent,
    None,
}

fn r6_class(w: &str) -> R6Part {
    // Both classes need three letters (the gazetteer's own minimum).
    if w.chars().count() < 3 || !w.chars().all(char::is_alphabetic) || w.eq_ignore_ascii_case("www")
    {
        return R6Part::None;
    }
    let mark = vocabulary_mark(w);
    let listed_vocab = matches!(mark, Some(Mark::Unmarked | Mark::Rare));
    // A stoplist word is never a gazetteer first name (the stoplist wins),
    // so the costly lookup runs only for the other words.
    if is_common_word(w) {
        return if is_name_like_word(w) && !listed_vocab {
            R6Part::Adjacent
        } else {
            R6Part::None
        };
    }
    if is_first_name(w) {
        if mark.is_none() && !is_also_name(w) {
            return R6Part::Anchor;
        }
        return R6Part::Adjacent;
    }
    if listed_vocab {
        R6Part::None
    } else {
        R6Part::Adjacent
    }
}

/// The R6 runs in `a..b` (module docs), in text order.
fn r6_runs(text: &str, a: usize, b: usize) -> Vec<(usize, usize)> {
    // A run needs two parts, so a separator; most segments have none.
    if !text[a..b].contains(['-', '_', '.']) {
        return Vec::new();
    }
    let mut segs = split_into(text, a, b, &['-', '_', '.']);
    // A listed file extension is no name part (`Anna-Gruber.pdf`).
    if let [.., prev, last] = segs.as_slice() {
        if text[prev.end..last.start].starts_with('.')
            && in_set(&EXT_SET, &text[last.start..last.end])
        {
            segs.pop();
        }
    }
    let mut runs = Vec::new();
    if segs.len() < 2 {
        return runs;
    }
    let class: Vec<R6Part> = segs
        .iter()
        .map(|s| r6_class(&text[s.start..s.end]))
        .collect();
    let mut i = 0;
    while i < segs.len() {
        if class[i] == R6Part::None {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < segs.len() && class[j] != R6Part::None {
            j += 1;
        }
        if j - i >= 2 && (i..j).any(|k| class[k] == R6Part::Anchor) {
            runs.push((segs[i].start, segs[j - 1].end));
        }
        i = j;
    }
    runs
}

fn r6(text: &str, a: usize, b: usize, out: &mut Out) {
    for (ra, rb) in r6_runs(text, a, b) {
        out.push(ra, rb, CONF_CUE);
    }
}

/// Cuts every `URL` span that strictly contains one or more `Position`
/// `PERSON` spans into its pieces outside them (ruling S10). A piece keeps
/// kind, source, confidence and `crossed_line_break`; a piece without a
/// letter or digit is dropped. Other spans are returned unchanged, in their
/// order.
///
/// One sorted sweep (review I3): the names are sorted by start, the URLs
/// visited by start, and a cursor over the names only moves forward, so the
/// work after the sort is linear in the number of spans (plus the bytes of
/// the pieces, read once for the alphanumeric check).
pub fn cut_urls_around_positions(text: &str, spans: Vec<Span>) -> Vec<Span> {
    let mut names: Vec<(usize, usize)> = spans
        .iter()
        .filter(|s| s.source == DetectorId::Position && s.kind == EntityKind::Person)
        .map(|s| (s.start, s.end))
        .collect();
    if names.is_empty() || !spans.iter().any(|s| s.kind == EntityKind::Url) {
        return spans;
    }
    names.sort_unstable();
    let mut urls: Vec<usize> = (0..spans.len())
        .filter(|&i| spans[i].kind == EntityKind::Url)
        .collect();
    urls.sort_by_key(|&i| spans[i].start);
    let mut pieces: Vec<Option<Vec<(usize, usize)>>> = vec![None; spans.len()];
    let mut j = 0;
    for i in urls {
        let (us, ue) = (spans[i].start, spans[i].end);
        // A name that starts before this URL starts before every later one.
        while j < names.len() && names[j].0 < us {
            j += 1;
        }
        let mut pos = us;
        let mut cut: Option<Vec<(usize, usize)>> = None;
        let mut k = j;
        while k < names.len() && names[k].0 < ue {
            let (a, b) = names[k];
            if b <= ue && (a, b) != (us, ue) {
                let v = cut.get_or_insert_with(Vec::new);
                if a > pos {
                    v.push((pos, a));
                }
                pos = pos.max(b);
            }
            k += 1;
        }
        if let Some(mut v) = cut {
            if pos < ue {
                v.push((pos, ue));
            }
            pieces[i] = Some(v);
        }
    }
    let mut out = Vec::with_capacity(spans.len() + 2);
    for (s, cut) in spans.into_iter().zip(pieces) {
        match cut {
            None => out.push(s),
            Some(v) => {
                for (a, b) in v {
                    if text[a..b].chars().any(char::is_alphanumeric) {
                        out.push(Span {
                            start: a,
                            end: b,
                            ..s.clone()
                        });
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(text: &str) -> Vec<&str> {
        let ctx = DetectCtx::for_text(text);
        PathNameDetector::new()
            .detect(text, &ctx)
            .unwrap()
            .iter()
            .map(|s| &text[s.start..s.end])
            .collect()
    }

    #[test]
    fn names_in_paths_and_urls_are_found() {
        for (text, want) in [
            ("unter /home/huber/projekte/angebot.txt, bitte", "huber"),
            ("in /Users/agruber/Downloads/report.pdf now", "agruber"),
            (r"unter C:\Users\mhuber\Documents\Vertrag.docx ab", "mhuber"),
            ("unter /home/sarah.leitner/backup prüfen", "sarah.leitner"),
            (
                r"Der Ordner \\fileserver\home$\agruber\Scans ist voll",
                "agruber",
            ),
            (
                "in /srv/share/bewerbungen/anna-gruber/cv.pdf bereit",
                "anna-gruber",
            ),
            ("unter https://example.com/team/gruber, bitte", "gruber"),
            ("https://example.com/team/gruber?tab=cv#top", "gruber"),
            ("https://example.com/team/gruber/", "gruber"),
            (
                "Profile: https://example.org/people/anna-gruber",
                "anna-gruber",
            ),
            (
                "https://intranet.example.at/mitarbeiter/sarah.leitner/kalender",
                "sarah.leitner",
            ),
            ("https://github.com/mhuber/angebot-tool", "mhuber"),
            ("https://example.com/~leitner/urlaub.jpg", "leitner"),
            (
                "https://www.linkedin.com/in/anna-gruber-4711/",
                "anna-gruber-4711",
            ),
            ("Repo: git@github.com:agruber/notizen.git", "agruber"),
            ("/private/tmp/claude-503/-Users-mhuber-code-app/x", "mhuber"),
            ("/projekte/angebot-anna-gruber/entwurf.txt", "anna-gruber"),
            ("/home/branch/notes", "branch"),
            // Review C1: stoplist surnames that are name-like are names.
            ("unter /home/weber/angebote/ bitte", "weber"),
            ("https://example.com/team/koch", "koch"),
            ("https://github.com/fischer/tools", "fischer"),
            ("/srv/bewerbungen/anna-bauer/cv.pdf", "anna-bauer"),
            (r"C:\Users\wagner\Desktop", "wagner"),
            // Review N2: an initial next to a stoplist surname.
            ("Kopie unter /home/m.weber/backup", "m.weber"),
            ("https://github.com/j-koch/tools", "j-koch"),
            (r"C:\Users\h_bauer\Desktop", "h_bauer"),
            // S26 minor: a Surname-marked word next to a first name.
            ("/srv/bewerbungen/anna-branch/cv.pdf", "anna-branch"),
        ] {
            assert_eq!(found(text), vec![want], "{text}");
        }
        // S26: a text that is one token (a mirror stem).
        assert_eq!(found("anna-gruber-cv"), vec!["anna-gruber"]);
        assert_eq!(found("CV_Anna_Gruber"), vec!["Anna_Gruber"]);
        assert!(found("CV_Anna_Model").contains(&"Anna_Model"));
        assert!(found("angebot-entwurf-v2").is_empty());
    }

    /// Review Focus 3.
    #[test]
    fn placeholders_and_generic_accounts_are_not_names() {
        for text in [
            "/Users/<you>/projects",
            "/home/$USER/.cargo",
            r"C:\Users\%USERNAME%\AppData",
            "~/projects/app",
            "/Users/Shared/tmp",
            "/home/runner/work/app/build.log",
            "/private/tmp/claude-506/-Users-runner-code-mobile-app/225751b8",
            "/root/.ssh/config",
            "https://github.com/rust-lang/cargo/issues",
            "https://example.com/team/about",
            "https://example.com/people/search?q=angebot",
            "https://docs.example.com/user/guide/install.html",
            "/var/folders/3e/s6cz7qfoumdgx17c4lv0k4/T/codex-E1mMfyfL",
            "/tmp/scratch-wez38yhw",
            "/abs/path/app.py",
            "/home/admin/code/billing-api",
            "/Users/ci/src/cli-tools",
        ] {
            assert!(found(text).is_empty(), "{text}: {:?}", found(text));
        }
    }

    /// Review Focus 2.
    #[test]
    fn home_logins_with_spaces_or_escapes() {
        assert_eq!(
            found(r"C:\Users\Anna Gruber\Documents"),
            vec!["Anna Gruber"]
        );
        assert_eq!(found(r"C:\Users\Anna Gruber hat angerufen"), vec!["Anna"]);
        // Residual (recorded): a three-word login keeps only its first word.
        assert_eq!(found(r"C:\Users\Anna Maria Gruber\Documents"), vec!["Anna"]);
        assert_eq!(found("/Users/anna%20gruber/Desktop"), vec!["anna%20gruber"]);
    }

    /// Fix round 1 (items 1, 2, 4): a URL after a prefix (`"`, `=`, `(`,
    /// an attribute), a JSON-escaped path, a doubled separator, and a bare
    /// `linkedin.com` URL.
    #[test]
    fn urls_after_prefixes_and_escaped_paths_are_found() {
        for (text, want) in [
            (r#"{"u":"https://github.com/mhuber/x"}"#, "mhuber"),
            (r#"<a href="https://github.com/mhuber">"#, "mhuber"),
            ("repo=https://github.com/mhuber/tool", "mhuber"),
            ("[repo](https://github.com/mhuber)", "mhuber"),
            (r#"{"u":"https://www.linkedin.com/in/mhuber"}"#, "mhuber"),
            ("link=www.linkedin.com/in/mhuber", "mhuber"),
            (r#"{"cwd":"C:\\Users\\mhuber\\x"}"#, "mhuber"),
            (r#"{"cwd":"\/home\/huber\/x"}"#, "huber"),
            ("Pfad //home//huber prüfen", "huber"),
            ("Profil: linkedin.com/in/mhuber", "mhuber"),
        ] {
            assert_eq!(found(text), vec![want], "{text}");
        }
    }

    /// Fix round 1 (item 3, Review Focus 4): a minified JSON line longer
    /// than one token's limit is split at JSON punctuation, so its paths
    /// are still scanned.
    #[test]
    fn long_minified_json_lines_are_scanned() {
        let unit = r#"{"p":"/home/huber/a.txt"},"#;
        let n = 6900 / unit.len();
        let text = format!("[{}]", unit.repeat(n));
        assert!(text.len() > MAX_TOKEN_BYTES);
        let got = found(&text);
        assert_eq!(got.len(), n);
        assert!(got.iter().all(|w| *w == "huber"));
    }

    /// Task 4b (L131, rulings L3-28, L3-29, L132): a `Rare` vocabulary word
    /// is a login right after a home root; a `~login` token needs no slash;
    /// a JSON-escaped URL is read as a URL.
    #[test]
    fn rare_logins_tilde_tokens_and_escaped_urls_are_found() {
        for (text, want) in [
            ("unter /home/steuer/ bitte", "steuer"),
            (r"unter C:\Users\Preis\ bitte", "Preis"),
            ("/home/foto/x", "foto"),
            ("/private/tmp/claude-1/-Users-steuer-code-app/x", "steuer"),
            ("frag ~mhuber, bitte", "mhuber"),
            ("(~mhuber)", "mhuber"),
            (r#"{"u":"https:\/\/github.com\/mhuber"}"#, "mhuber"),
            (r#"{"u":"https:\/\/github.com\/mhuber\/tool"}"#, "mhuber"),
        ] {
            assert_eq!(found(text), vec![want], "{text}");
        }
        for text in [
            "~ alone",
            "~/",
            "etwa ~1 Minute",
            "~root",
            "~runner hat",
            "/home/runner/x",
            // `Unmarked` vocabulary words stay out after a home root.
            "/Users/Shared/tmp",
        ] {
            assert!(found(text).is_empty(), "{text}: {:?}", found(text));
        }
    }

    /// Final fix wave item 3 (L139 m2): after a person cue (R2) a `Rare`
    /// word is a name too, as after a home root (L3-28).
    #[test]
    fn rare_words_after_a_person_cue_are_names() {
        for (text, want) in [
            ("https://kanzlei.at/team/preis", "preis"),
            ("siehe /mitarbeiter/steuer bitte", "steuer"),
        ] {
            assert_eq!(found(text), vec![want], "{text}");
        }
        // an `Unmarked` word after a cue stays out
        assert!(found("https://kanzlei.at/team/rechnung").is_empty());
    }

    /// Task 4b fix round 1 (rulings L3-30, L133, L134): a slashless
    /// `~word` only in a login context, never in code or an approximation;
    /// a login ends at a placeholder character, which exempts it only at
    /// its start; `/homes/`; one- and two-letter logins after a home root;
    /// a URL nested in a query string.
    #[test]
    fn fix1_tilde_contexts_placeholders_roots_and_nested_urls() {
        for (text, want) in [
            ("~mhuber", "mhuber"),
            ("~mhuber/", "mhuber"),
            (r#""~mhuber""#, "mhuber"),
            ("(~mhuber)", "mhuber"),
            ("~mhuber.", "mhuber"),
            ("Notizen (~mhuber) ansehen", "mhuber"),
            ("cd ~mhuber && ls", "mhuber"),
            ("export P=/Users/mhuber${SUFFIX}/bin", "mhuber"),
            ("cp a /home/mhuber$EXT", "mhuber"),
            ("/Users/mhuber%", "mhuber%"),
            (r"C:\Users\mhuber%TEMP%", "mhuber%TEMP%"),
            ("<td>/home/mhuber</td>", "mhuber"),
            ("/homes/mhuber/x", "mhuber"),
            ("/Users/kl/x", "kl"),
            ("/home/a/x", "a"),
            ("mhuber:x:1000:1000::/home/mhuber:/bin/bash", "mhuber"),
            ("`/Users/mhuber`", "mhuber"),
            ("https://example.com/home/about", "about"),
            ("/home/runner.txt", "runner.txt"),
            (
                "https://example.com/login?next=https://github.com/mhuber",
                "mhuber",
            ),
        ] {
            assert_eq!(found(text), vec![want], "{text}");
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
            assert!(found(text).is_empty(), "{text}: {:?}", found(text));
        }
    }

    /// Task 4b fix round 2 (ruling L136): a `~login/` after `:` or `=` is
    /// R4 whatever precedes it (the verifier reads the same roots; code such
    /// as `x=~mask/2` is tokenized, a precision cost); without the slash,
    /// `:` or `=` before `~login` counts only after an option (`--dir`) or
    /// an all-caps variable. `x&~flags/2` stays code.
    #[test]
    fn fix2_tilde_paths_after_colon_or_assignment() {
        for (text, want) in [
            ("scp f user@host:~mhuber/notes", "mhuber"),
            ("scp f user@srv.example.com:~mhuber/notes", "mhuber"),
            ("rsync -a srv:~mhuber/ .", "mhuber"),
            ("--dir=~mhuber/x", "mhuber"),
            ("PATH=$PATH:~mhuber/bin", "mhuber"),
            ("export HOME_DIR=~mhuber/x", "mhuber"),
            ("Pfad:~mhuber/notes", "mhuber"),
            ("x=~mask/2", "mask"),
            ("a.b=~c/d", "c"),
            ("--dir=~mhuber", "mhuber"),
            ("HOME_DIR=~mhuber", "mhuber"),
        ] {
            assert_eq!(found(text), vec![want], "{text}");
        }
        for text in [
            "x&~flags/2",
            "x=~mhuber",
            "mode:~fast",
            "MyClass::~MyClass()",
        ] {
            assert!(found(text).is_empty(), "{text}: {:?}", found(text));
        }
    }

    /// Fix round 2 (L135 item 3): a multi-byte character at a slice point
    /// of R5's prefix test never panics (fix round 1 found
    /// `Adressänderung` in a document chunk).
    #[test]
    fn multi_byte_characters_at_slice_points_do_not_panic() {
        for text in [
            "a/Adressänderung/b",
            "x/homesö/y",
            "x/-homeü/y",
            "x/-users€/y",
            "C--Users-mü/x",
        ] {
            let _ = found(text);
        }
        assert_eq!(found("/x/-Users-müller-code/y"), vec!["müller"]);
    }

    /// S10, review I3: a URL is cut around the names it strictly contains;
    /// a piece with no letter or digit is dropped; other spans stay.
    #[test]
    fn urls_are_cut_around_position_names() {
        let text = "a https://example.com/team/gruber/x b https://example.org/u/anna-gruber/ c";
        let mut spans = PathNameDetector::new()
            .detect(text, &DetectCtx::for_text(text))
            .unwrap();
        for (i, _) in text.match_indices("https://") {
            let end = text[i..].find(' ').map_or(text.len(), |e| i + e);
            spans.push(Span::new(
                i,
                end,
                EntityKind::Url,
                0.9,
                DetectorId::RegexValidated,
            ));
        }
        let out = cut_urls_around_positions(text, spans);
        let mut got: Vec<(&str, &str)> = out
            .iter()
            .map(|s| (s.kind.label(), &text[s.start..s.end]))
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("PERSON", "anna-gruber"),
                ("PERSON", "gruber"),
                ("URL", "/x"),
                ("URL", "https://example.com/team/"),
                ("URL", "https://example.org/u/"),
            ]
        );
    }

    /// Review Focus 4: linear time on long input (prints only).
    #[test]
    #[ignore = "timing measurement, run in release by hand"]
    #[allow(clippy::print_stderr)] // a measurement prints its numbers; no input text
    fn path_names_timing() {
        let prose = "Bitte /home/huber/a.txt und C:\\Users\\mhuber\\Desktop sowie /srv/x/anna-gruber/cv.pdf \
                     prüfen, siehe https://example.com/team/gruber und https://github.com/mhuber/tool. ";
        let json = r#"{"p":"/home/huber/a.txt","u":"https://example.com/team/gruber"},"#;
        for (name, unit) in [("prose", prose), ("json-line", json)] {
            for kb in [4usize, 30, 120, 240] {
                let text = unit.repeat(kb * 1024 / unit.len());
                let t = std::time::Instant::now();
                let mut spans = PathNameDetector::new()
                    .detect(&text, &DetectCtx::for_text("x"))
                    .unwrap();
                for (i, _) in text.match_indices("https://") {
                    let end = text[i..].find([' ', '"']).map_or(text.len(), |e| i + e);
                    spans.push(Span::new(
                        i,
                        end,
                        EntityKind::Url,
                        0.9,
                        DetectorId::RegexValidated,
                    ));
                }
                let n = spans.len();
                let out = cut_urls_around_positions(&text, spans);
                eprintln!(
                    "TIMING {name} {kb} KB spans={n} out={} took={:?}",
                    out.len(),
                    t.elapsed()
                );
            }
        }
    }
}
