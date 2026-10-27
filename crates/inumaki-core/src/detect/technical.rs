//! Precision filter for model-found person spans in technical text
//! (harness-static precision, rulings L60 and L3-05).
//!
//! An agent harness sends the same technical text with every request. A NER
//! model tags parts of it as `PERSON` (`user`, `$CODEX_HOME`, a commit hash),
//! mostly in the escalation band, so under `on_uncertain = "block"` every
//! request is refused. [`is_technical_person`] says which model-found person
//! spans are technical text. Only the sanitizer applies it; the verifier's
//! NER stays unfiltered, an independent backstop for any name dropped here.
//!
//! Recall first: a span is technical only when every word of it is and one
//! word is evidence. A first name, a name-like word, an honorific, an unknown
//! capitalized word, a capitalized `_` segment, a letters-only name piece of
//! an identifier, or a placeholder next to it keeps the span. The 0.85
//! confidence cap ([`CONFIDENT`]) is not a recall guard: names in JSON and
//! paths score below it. The caller says where the text came from
//! ([`TextOrigin`]); the default, free text, is the narrower reading.
//!
//! # The rule
//!
//! - **Scope.** Only `Ner`-source `PERSON` spans below [`CONFIDENT`] (0.85)
//!   are judged. That cap does not guard names in JSON or paths, which score
//!   below it. The guards below do.
//! - **Widening.** The span is widened to its enclosing token, up to the
//!   nearest whitespace or one of `" ' ` { } [ ] ( ) , ; : < > | * “ ” „ « »`.
//!   A span inside an unbroken run of more than 1024 bytes on a side is kept.
//! - **Placeholders.** A widened range that overlaps a token range, or is
//!   next to one (only whitespace or punctuation between, at most two line
//!   breaks), is kept. In the sanitizer, the token ranges are the protected
//!   input tokens.
//! - **Business numbers.** A word shaped like a business number keeps the
//!   span: a licence plate in any case (`w-123ab`, `gu-12ab`, `m-ab-123`), or
//!   a letter prefix of at most six letters in one or more groups, digit
//!   groups with at least 4 digits, and at most two trailing letters
//!   (`RE-2026-63895`, `kunde-123456`, `KD-NR-12345`, `4867526`, an unspaced
//!   account number). The model's `PERSON` tag on such a word is sometimes
//!   the only detector covering an invoice, plate, or customer number the
//!   regexes missed (measured at the Task 2 recall checkpoint). The
//!   verifier is no backstop here: its regex re-scan has the same gaps.
//!   Not business numbers (ruling S6): a camera or scanner counter, that is
//!   digit groups after a device prefix such as `IMG`, `DSC`, `PXL`, or
//!   `scan`, glued or as the word before (`IMG_2034`, `DSC01234`,
//!   `IMG 2034`, `Scan 20261001`), which makes the span technical; and an
//!   ISO date or month (`2025-07-14`, `2026-03`, separators `- _ .`, valid
//!   ranges) with no prefix, a device prefix, or an unmarked vocabulary
//!   word that is no label word of the shipped domain rules
//!   (`scan_2026-10-01`, `angebot-2026-03`, not `rechnung-2026-10` or
//!   `re_2026-10-01`).
//!   Neither are versions (`25.0.0`), 13-digit epoch
//!   timestamps, 10-digit ones with a time cue (a time key such as `ts`,
//!   `expires`, or `created_at` right next to it, or an ISO date on its
//!   line; without one a 10-digit value may be an account or social
//!   security number, ruling L88), and a lowercase hex-shaped word
//!   (`f211934`, `4348594`) with a commit cue next to it (`commit`, `sha`,
//!   `HEAD`, a 40-digit hash on the line, a conventional commit subject
//!   after it, or a neighbour line that starts with a hash that is not
//!   itself business-shaped). Without a cue such a word is ambiguous and
//!   kept (rulings L85, L88). A word with `=` or `:` in it is also judged
//!   per part: a value glued to its key (`Konto=1234010180`,
//!   `kundennr:K-123456`) is checked as if it stood alone, with the key as
//!   its time-cue neighbour (`"ts":1712345678` stays a timestamp). The time
//!   and commit cues read at most 256 bytes on each side of the word; a cue
//!   farther away on a long line does not count (the word is kept), and a
//!   date, key, or hash cut by that window edge is no cue.
//! - **Word classes.** Each whitespace word is *strong* (contains
//!   `< > | { } [ ] $ =` or a backtick or `://`, or its core is a UUID or a
//!   hex string of 7 or more characters with a digit and a letter),
//!   *machine* (its core has a digit; contains `_`; has a path slash; has
//!   `#` glued before an alphanumeric; ends in a listed file extension; or
//!   has an inner capital such as `claudeMd` or `TodoWrite`, but not
//!   `McDonald` or `GitHub`), or *plain*. `@ \ ~` are not markers:
//!   `@leitner` and `C:\Users\mhuber` are names. Besides the technical
//!   vocabulary there is a document vocabulary ([`document_vocabulary`],
//!   `data/document_words.txt`: office, file-default, and table-label words
//!   such as `rechnung`, `notizen`, `unbenannt`); a word that is a rare US
//!   Census surname (`mail`, `foto`) counts only in a *file position*: the
//!   word has an extension or a path separator, or the text is a file name
//!   ([`TextOrigin::FileName`]; rulings S3, L123, L129).
//! - **Strong or machine word.** It is evidence, unless it names a person:
//!   an alphabetic run of 3 or more letters is a first name or name-like
//!   word (not inside a hash or UUID, not a hex-letter-only run in a segment
//!   with digits, not an `ALSO_NAMES` run with technical context), or a
//!   segment split at `_ - . / \ = # & ? + @` and at digits is a capitalized
//!   word with a vowel that is in neither vocabulary
//!   (`Rechnung_Huber_2026`, `Huber.txt`, `Huber85`, `nachname=Huber`,
//!   `Huber#2`). A surname-marked vocabulary word counts as vocabulary there
//!   only in a code file name (`App.tsx`), never with a document extension
//!   or a digit run (`Rechnung_Branch_2026.pdf`, `Model.txt`; ruling L3-09),
//!   and a rare-surname document word only in a file position
//!   (`Mail_2026.txt`, not `Mail_Anfrage` in free text). In free text and
//!   file names segments are also split at inner capitals, so a surname
//!   glued in CamelCase (`HuberMaier`, `GruberAG`) keeps the span, as before
//!   this rule (ruling L118). In a harness-static text they are not: there a
//!   CamelCase identifier (`$SkillName`, `TodoWrite`) is dropped unless a run
//!   is a first name.
//! - **Piece inside an identifier.** When the model span is one
//!   letters-only piece of a strong or machine word, the piece is judged
//!   alone: a name, an unknown lowercase word, or filler keeps the span;
//!   evidence and a document word are technical (`notizen` in
//!   `notizen.txt`); an `ALSO_NAMES` word is technical only with
//!   technical context (`CLAUDE` in `CLAUDE.md`); a capitalized
//!   surname-marked vocabulary word only in a code file name (`App` in
//!   `App.tsx`, not `Branch` in `Rechnung_Branch_2026.pdf`).
//! - **Plain word.** It is cut into alphanumeric parts (after removing a
//!   trailing `'s`), and each part is judged: an honorific or a first name
//!   or name-like word keeps the span; an `ALSO_NAMES` word counts only
//!   with other evidence, or all-lowercase when not a first name; a word of
//!   the technical vocabulary ([`vocabulary`], role nouns such as `user`
//!   and `reviewer`, and developer words) is evidence, except that a
//!   capitalized one that is a US Census surname (`Model`, `Branch`,
//!   `Sender`) counts like an `ALSO_NAMES` word and needs other evidence
//!   (C2); a lowercase one (`fish`, `rust`, `head`), like a lowercase
//!   `ALSO_NAMES` word standing alone, is evidence only in a harness-static
//!   text ([`TextOrigin::HarnessStatic`]) or between backticks. In free
//!   text, alone, it keeps the span (ruling L98: `danke rust`). Inside an
//!   identifier, the identifier is the cue. A document word makes the span
//!   technical, but it is no evidence for a surname-marked or `ALSO_NAMES`
//!   word next to it, so `angebot-weber`, `angebot-branch`, and
//!   `Angebot Model` stay names (S2). A document word also clears nothing
//!   when another letter run of its token, or a two-letter word of the
//!   span, is no vocabulary or non-name-like stoplist word, so a lowercase
//!   or two-letter surname next to it keeps the span (`Rechnung_huber_2026`,
//!   `Bewerbung_mueller.pdf`, `Rechnung Li`; ruling L139); the same holds
//!   for a capitalized document segment and a document piece of an
//!   identifier (`runs_are_vocabulary`). A single letter is evidence;
//!   two letters and common words are filler; another all-lowercase word
//!   counts only alongside a strong word; a word with any other capital
//!   keeps the span.
//! - **Model ids and products.** A word that is a model id (`gpt-6-sol`,
//!   `codex-mini-latest`, `claude-opus-5`) is judged as a whole: its prefix
//!   is a known model family, and a first-name segment is allowed only with a
//!   digit or as `sol` or `luna` (`gpt-anna` stays a name); `claude-` also
//!   needs a digit. `Three.js` is a product token (case-sensitive).
//! - **`Claude`.** The standalone word `Claude` counts as the product only
//!   with a cue: the next word is `Code`, `Opus`, `Sonnet`, or `Haiku`, or the
//!   text holds the whole word `Anthropic` or `Claude Code` (C3). Otherwise it
//!   is a first name. The cue never clears a `claude` piece inside an
//!   identifier (`/Users/claude/`, `claude_dubois`).
//! - **Result.** The span is technical iff nothing kept it and there is
//!   evidence.

use std::cell::OnceCell;
use std::collections::HashMap;
use std::ops::Range;
use std::sync::LazyLock;

use regex::Regex;

use crate::detect::plausible::{CONFIDENT, HONORIFICS};
use crate::gazetteer::is_first_name;
use crate::origin::TextOrigin;
use crate::span::{DetectorId, EntityKind, Span};
use crate::stoplist::{is_common_word, is_name_like_word};
use crate::verify::second_pass::is_next_to_ranges;

/// File extensions that make `stem.ext` a file name (case-insensitive).
const EXTENSIONS: &[&str] = &[
    "md", "rs", "ts", "tsx", "js", "jsx", "json", "toml", "yaml", "yml", "txt", "py", "sh", "lock",
    "html", "css", "ipynb", "sql", "xml", "csv", "log", "cfg", "ini",
];

/// Office, image, media, archive, and mail extensions (case-insensitive).
/// With [`EXTENSIONS`] they make a word a file position (S3,
/// [`ends_in_extension`]); they do not make a word a machine word.
const DOCUMENT_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf", "jpg", "jpeg",
    "png", "gif", "heic", "tif", "tiff", "mp4", "mov", "zip", "eml", "msg",
];

/// Code-file extensions (case-insensitive). In a code file name, a
/// capitalized surname-marked vocabulary segment is technical (`App.tsx`);
/// a document extension (`pdf`, `txt`, `csv`) or a digit run does not clear
/// one (ruling L3-09).
const CODE_EXTENSIONS: &[&str] = &[
    "rs", "ts", "tsx", "js", "jsx", "mjs", "cjs", "py", "go", "java", "kt", "swift", "rb", "c",
    "h", "cpp", "hpp", "cs", "sh", "toml", "yaml", "yml", "json", "md", "lock",
];

/// Technical words that are also first names or name-like words. As a plain
/// word one counts only next to other evidence, or all-lowercase when it is
/// not a first name; inside an identifier only with technical context
/// ([`technical_context`]).
const ALSO_NAMES: &[&str] = &["admin", "claude", "darwin", "line", "page"];

const WORDS: &str = include_str!("../../data/technical_words.txt");

const DOCUMENT_WORDS: &str = include_str!("../../data/document_words.txt");

/// How the US Census 2010 surname list marks a vocabulary word
/// (`scripts/harness-corpus/check-surnames.sh` checks the marks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mark {
    /// Not a Census surname.
    Unmarked,
    /// A document word with 1-999 Census bearers: a document word only in a
    /// file position (rulings S3, L123, L129). The technical vocabulary has
    /// no such mark.
    Rare,
    /// A Census surname with at least 1000 bearers in the document
    /// vocabulary, or any Census surname in the technical vocabulary.
    Surname,
}

/// The entries of a vocabulary file: one word per line, optionally followed
/// by `surname` or `rare`; `#` starts a comment line.
fn entries(data: &'static str) -> impl Iterator<Item = (&'static str, Mark)> {
    data.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| match l.split_once(' ') {
            Some((w, mark)) => (
                w,
                match mark.trim() {
                    "surname" => Mark::Surname,
                    "rare" => Mark::Rare,
                    _ => Mark::Unmarked,
                },
            ),
            None => (l, Mark::Unmarked),
        })
}

/// The technical vocabulary (`data/technical_words.txt`): each word and
/// whether it is a US Census surname.
pub fn vocabulary() -> impl Iterator<Item = (&'static str, bool)> {
    entries(WORDS).map(|(w, m)| (w, m == Mark::Surname))
}

/// The document vocabulary (`data/document_words.txt`): each word and
/// whether it is a US Census surname with at least 1000 bearers. A `rare`
/// word (1-999 bearers) is reported unmarked here.
pub fn document_vocabulary() -> impl Iterator<Item = (&'static str, bool)> {
    entries(DOCUMENT_WORDS).map(|(w, m)| (w, m == Mark::Surname))
}

/// One vocabulary entry: its Census mark and which file it comes from.
#[derive(Clone, Copy)]
struct Vocab {
    mark: Mark,
    /// From the document vocabulary (S1-S3), not the technical one.
    document: bool,
}

static VOCABULARY: LazyLock<HashMap<&'static str, Vocab>> = LazyLock::new(|| {
    let technical = entries(WORDS).map(|(w, mark)| {
        // the technical file knows only unmarked and surname-marked words
        let mark = if mark == Mark::Surname {
            Mark::Surname
        } else {
            Mark::Unmarked
        };
        (
            w,
            Vocab {
                mark,
                document: false,
            },
        )
    });
    let document = entries(DOCUMENT_WORDS).map(|(w, mark)| {
        (
            w,
            Vocab {
                mark,
                document: true,
            },
        )
    });
    technical.chain(document).collect()
});

/// The Census mark of `word` (case-insensitive) in either vocabulary;
/// `None` when it is in neither.
pub(crate) fn vocabulary_mark(word: &str) -> Option<Mark> {
    VOCABULARY.get(word.to_lowercase().as_str()).map(|v| v.mark)
}

/// True when `word` (case-insensitive) is an [`ALSO_NAMES`] word.
pub(crate) fn is_also_name(word: &str) -> bool {
    ALSO_NAMES.contains(&word.to_lowercase().as_str())
}

/// True when the word `w` (core `core`) is a file position (rulings S3,
/// L129): the text is a file or directory name ([`TextOrigin::FileName`]),
/// the word is a path (a path slash by [`has_path_slash`], so a
/// capitalized `Steuer/Preis` is none, or a backslash), or it ends in a
/// listed extension ([`ends_in_extension`]). A whole text is never a file
/// position by its length alone: a JSON value, a one-field CSV record, or a
/// one-word message is judged as free text (review N1).
fn is_file_position(w: &str, core: &str, origin: TextOrigin) -> bool {
    origin == TextOrigin::FileName
        || has_path_slash(w)
        || w.contains('\\')
        || ends_in_extension(core)
}

/// `core` ends in `.` and an extension from the closed lists
/// [`EXTENSIONS`] and [`DOCUMENT_EXTENSIONS`] (any case), after a stem that
/// holds a letter (`notizen.txt`, `Mail_2026.JPEG`). A missing space after a
/// full stop (`Steuer.danke`, `Preis.OK`) is no extension (fix round 1).
fn ends_in_extension(core: &str) -> bool {
    core.rsplit_once('.').is_some_and(|(stem, ext)| {
        stem.chars().any(char::is_alphabetic) && is_listed_extension(ext)
    })
}

/// `ext` is in [`EXTENSIONS`] or [`DOCUMENT_EXTENSIONS`] (any case).
fn is_listed_extension(ext: &str) -> bool {
    EXTENSIONS
        .iter()
        .chain(DOCUMENT_EXTENSIONS)
        .any(|e| e.eq_ignore_ascii_case(ext))
}

fn is_break(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '"' | '\''
                | '`'
                | '{'
                | '}'
                | '['
                | ']'
                | '('
                | ')'
                | ','
                | ';'
                | ':'
                | '<'
                | '>'
                | '|'
                | '*'
                | '“'
                | '”'
                | '„'
                | '«'
                | '»'
        )
}

/// Most bytes the per-span context scans read on each side of a word
/// ([`time_cue`], [`commit_cue`]), so one long line (minified JSON) costs a
/// bounded scan per span instead of the whole line (final review A3). A cue
/// farther away than this does not count: the span is kept, recall first.
const CONTEXT_WINDOW: usize = 256;

/// Longest run [`enclosing`] widens over on each side of a span. A span in a
/// longer unbroken token is kept (recall first), at a bounded cost.
const MAX_TOKEN_SIDE: usize = 1024;

/// The largest char boundary of `text` at or below `i`.
fn floor_boundary(text: &str, i: usize) -> usize {
    let mut i = i.min(text.len());
    while !text.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// The smallest char boundary of `text` at or above `i`.
fn ceil_boundary(text: &str, i: usize) -> usize {
    let mut i = i.min(text.len());
    while !text.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// The line around the word `text[ws..we]`, clipped to [`CONTEXT_WINDOW`]
/// bytes on each side: `(ls, le, starts_line, ends_line)`. `starts_line`
/// says `ls` is the real line start, `ends_line` that `le` is the real line
/// end (a newline or the end of the text).
fn line_window(text: &str, ws: usize, we: usize) -> (usize, usize, bool, bool) {
    let lo = floor_boundary(text, ws.saturating_sub(CONTEXT_WINDOW));
    let hi = ceil_boundary(text, we.saturating_add(CONTEXT_WINDOW));
    let (ls, starts_line) = match text[lo..ws].rfind('\n') {
        Some(i) => (lo + i + 1, true),
        None => (lo, lo == 0),
    };
    let (le, ends_line) = match text[we..hi].find('\n') {
        Some(i) => (we + i, true),
        None => (hi, hi == text.len()),
    };
    (ls, le, starts_line, ends_line)
}

/// `start..end` widened to the nearest breaks; `None` (kept) for an empty,
/// out-of-range, or non-boundary range, or one inside an unbroken run longer
/// than [`MAX_TOKEN_SIDE`] bytes on a side.
fn enclosing(text: &str, start: usize, end: usize) -> Option<(usize, usize)> {
    if start >= end
        || end > text.len()
        || !text.is_char_boundary(start)
        || !text.is_char_boundary(end)
    {
        return None;
    }
    let floor = floor_boundary(text, start.saturating_sub(MAX_TOKEN_SIDE));
    let lo = match text[floor..start]
        .char_indices()
        .rev()
        .find(|(_, c)| is_break(*c))
    {
        Some((i, c)) => floor + i + c.len_utf8(),
        None if floor == 0 => 0,
        None => return None,
    };
    let ceil = ceil_boundary(text, end.saturating_add(MAX_TOKEN_SIDE));
    let hi = match text[end..ceil].char_indices().find(|(_, c)| is_break(*c)) {
        Some((i, _)) => end + i,
        None if ceil == text.len() => ceil,
        None => return None,
    };
    Some((lo, hi))
}

/// Whitespace-separated words of `s` with their byte offsets.
fn words(s: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut from = None;
    for (i, c) in s.char_indices() {
        match (c.is_whitespace(), from) {
            (false, None) => from = Some(i),
            (true, Some(f)) => {
                out.push((f, &s[f..i]));
                from = None;
            }
            _ => {}
        }
    }
    if let Some(f) = from {
        out.push((f, &s[f..]));
    }
    out
}

/// Letters, digit groups, letters: the shape of a customer, invoice,
/// contract, or account number (`K-954701`, `RE-2026-63895`, `KD-NR-12345`,
/// `kunde-123456`). The letter prefix may hold several groups; its letters
/// are counted in [`is_business_number`].
static BUSINESS_NUMBER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A(?P<pre>(?:\p{L}+[-_/.]?)*)[0-9]+(?:[-_/.][0-9]+)*[-_/.]?\p{L}{0,2}\z").unwrap()
});

/// A licence plate in any case: `w-123ab`, `gu-12ab`, `W-12345A`,
/// `m-ab-123`. `gpt-5` and `claude-501` do not match.
static PLATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A(?:\p{L}{1,2}-[0-9]{1,5}\p{L}{1,3}|\p{L}{1,3}-\p{L}{1,2}-?[0-9]{1,4})\z")
        .unwrap()
});

/// Most letters a business-number prefix holds (`kunde-`, `KD-NR-`).
const MAX_PREFIX_LETTERS: usize = 6;

/// Camera, phone, and scanner file-name prefixes (`IMG_2034`, `DSC01234`,
/// `PXL_20261001_123456789`, `scan0001`; ruling S6). A counter after one is
/// no business number ([`is_business_number`], [`is_device_counter`]).
const DEVICE_PREFIXES: &[&str] = &[
    "img", "vid", "pxl", "mvimg", "pano", "dsc", "dscn", "dscf", "dcim", "gopr", "dji", "scan",
];

/// True when `w` is a whole [`DEVICE_PREFIXES`] word (ASCII
/// case-insensitive).
fn is_device_prefix(w: &str) -> bool {
    DEVICE_PREFIXES.iter().any(|p| p.eq_ignore_ascii_case(w))
}

/// Label words of the shipped domain rules (`configs/default.toml`): an ISO
/// date after one may be an invoice or contract number (`rechnung-2026-10`),
/// so it keeps the business-number guard (S6, plan review minor).
const LABEL_WORDS: &[&str] = &[
    "rechnung",
    "rechnungen",
    "rechnungsnummer",
    "vertrag",
    "verträge",
    "kundennummer",
    "invoice",
    "invoices",
    "contract",
    "contracts",
];

/// True when `s` is exactly an ISO date `YYYY-MM-DD` or month `YYYY-MM`,
/// each separator `-`, `_`, or `.`, year 1900-2099, month 01-12, day 01-31
/// (S6).
fn is_iso_date_or_month(s: &str) -> bool {
    let b = s.as_bytes();
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
    let num = |r: std::ops::Range<usize>| s[r].parse::<u32>().ok();
    let sep = |i: usize| matches!(b[i], b'-' | b'_' | b'.');
    if !(b.len() == 7 || b.len() == 10) || !digits(0..4) || !sep(4) || !digits(5..7) {
        return false;
    }
    let year_month = num(0..4).is_some_and(|y| (1900..=2099).contains(&y))
        && num(5..7).is_some_and(|m| (1..=12).contains(&m));
    year_month
        && (b.len() == 7
            || (sep(7) && digits(8..10) && num(8..10).is_some_and(|d| (1..=31).contains(&d))))
}

/// True when the prefix word `pre` (separators removed) lets an ISO date
/// after it pass as a date (S6): none, a device prefix, or an unmarked
/// vocabulary word that is no label word ([`LABEL_WORDS`]). A name or an
/// unknown word before a date keeps the guard (`re_2026-10-01`).
fn date_prefix_ok(pre: &str) -> bool {
    pre.is_empty()
        || is_device_prefix(pre)
        || (vocabulary_mark(pre) == Some(Mark::Unmarked)
            && !LABEL_WORDS.contains(&pre.to_lowercase().as_str()))
}

/// True when the core of the whitespace word `w` holds only ASCII digits,
/// `_`, and `-` (`2034`, `20261001_123456`).
fn is_counter_word(w: &str) -> bool {
    let core = trim_word(w);
    !core.is_empty()
        && core
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

/// True when the widened range `text[lo..hi]` is a camera or scanner
/// counter (S6): its first word's core is a device prefix and every other
/// word, at least one, is a counter word ([`is_counter_word`]: `IMG 2034`,
/// `Scan 20261001`); or every word is a counter word and the word right
/// before `lo` on its line, after spaces or tabs only, is a device prefix
/// (`VID 20261001_101010` with the model span on the digits). Reads at most
/// one short word before `lo`.
fn is_device_counter(text: &str, lo: usize, hi: usize) -> bool {
    let ws = words(&text[lo..hi]);
    let Some(((_, first), rest)) = ws.split_first() else {
        return false;
    };
    if is_device_prefix(trim_word(first)) {
        return !rest.is_empty() && rest.iter().all(|(_, w)| is_counter_word(w));
    }
    if !ws.iter().all(|(_, w)| is_counter_word(w)) {
        return false;
    }
    let before = &text[..lo];
    let gap = before.trim_end_matches([' ', '\t']);
    if gap.len() == before.len() {
        return false;
    }
    // The longest device prefix has five letters: read at most six
    // characters back, so a longer word is never scanned in full.
    let mut start = gap.len();
    for (n, (i, c)) in gap.char_indices().rev().enumerate() {
        if is_break(c) {
            break;
        }
        if n == 6 {
            return false;
        }
        start = i;
    }
    is_device_prefix(&gap[start..])
}

/// An epoch time from 2001-09-09 to 2040-01-01: a 13-digit value in
/// milliseconds, or a 10-digit value in seconds with a time cue next to it
/// ([`time_cue`]). A bare 10-digit value may be an account, social security,
/// or customer number and is not one (ruling L88: recall first).
fn is_epoch_timestamp(text: &str, ws: usize, we: usize, core: &str) -> bool {
    const END_S: u64 = 2_208_988_800;
    if !core.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Ok(v) = core.parse::<u64>() else {
        return false;
    };
    match core.len() {
        10 => (1_000_000_000..END_S).contains(&v) && time_cue(text, ws, we),
        13 => (1_000_000_000_000..END_S * 1000).contains(&v),
        _ => false,
    }
}

/// An ISO date shape (`2024-04-05`); [`has_iso_date`] checks that no digit
/// is glued to it.
static ISO_DATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:19|20)[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])").unwrap()
});

/// True when `text[lo..hi]` holds an ISO date not glued to other digits.
/// The neighbours are read in the full `text`, so a window edge inside
/// `12024-04-05` or `2024-04-053` is no date boundary (round 3).
fn has_iso_date(text: &str, lo: usize, hi: usize) -> bool {
    let hay = &text[..hi];
    let mut at = lo;
    while let Some(m) = ISO_DATE.find_at(hay, at) {
        let glued_before = text[..m.start()].ends_with(|c: char| c.is_ascii_digit());
        let glued_after = text[m.end()..].starts_with(|c: char| c.is_ascii_digit());
        if !glued_before && !glued_after {
            return true;
        }
        // a match starts with an ASCII digit, so the next byte is a boundary
        at = m.start() + 1;
    }
    false
}

/// A time key name (case-insensitive, whole key): `time`, `ts`, `epoch`,
/// `expires`, `exp`, or one ending in `_at`, `time`, or `timestamp`
/// (`created_at`, `mtime`). `Export` or `Experte` is no time key.
fn is_time_key(key: &str) -> bool {
    let ends = |suffix: &str| {
        key.len() >= suffix.len()
            && key.is_char_boundary(key.len() - suffix.len())
            && key[key.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    };
    ["time", "ts", "epoch", "expires", "exp"]
        .iter()
        .any(|k| k.eq_ignore_ascii_case(key))
        || ends("_at")
        || ends("time")
        || ends("timestamp")
}

/// Key characters: letters, digits, `_`.
fn is_key_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Characters between a key and its value (`"ts": 1`, `exp=1`, `ts 1`).
fn is_key_gap(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\'' | '`' | ':' | '=')
}

/// True when a time cue is next to the word `text[ws..we]`: the key or word
/// right before or after it on its line is a time key ([`is_time_key`]),
/// or its line holds an ISO date. Only [`CONTEXT_WINDOW`] bytes of the line
/// on each side are read.
fn time_cue(text: &str, ws: usize, we: usize) -> bool {
    let (ls, le, starts_line, ends_line) = line_window(text, ws, we);
    if has_iso_date(text, ls, le) {
        return true;
    }
    let before_all = text[ls..ws].trim_end_matches(is_key_gap);
    let key_start = before_all
        .char_indices()
        .rev()
        .find(|(_, c)| !is_key_char(*c))
        .map_or(0, |(i, c)| i + c.len_utf8());
    let before = &before_all[key_start..];
    // a key cut by the window edge is no key
    let before_cut = key_start == 0 && !starts_line && text[..ls].ends_with(is_key_char);
    let after_all = text[we..le].trim_start_matches(is_key_gap);
    let key_end = after_all
        .find(|c| !is_key_char(c))
        .unwrap_or(after_all.len());
    let after = &after_all[..key_end];
    let after_cut = key_end == after_all.len() && !ends_line && text[le..].starts_with(is_key_char);
    (!before.is_empty() && !before_cut && is_time_key(before))
        || (!after.is_empty() && !after_cut && is_time_key(after))
}

/// True when the word `text[ws..we]`, with core `core`, looks like a
/// business number: a plate shape, or a letter prefix of at most
/// [`MAX_PREFIX_LETTERS`] letters, digit groups with at least 4 digits, and
/// at most two trailing letters. Not one: a version (`25.0.0`: dotted groups
/// of at most three digits), an epoch timestamp, and a lowercase hex-shaped
/// word (`f211934`, `4348594`) with a commit cue next to it
/// ([`commit_cue`]). Without a cue such a word is ambiguous and kept
/// (ruling L85: recall first).
fn is_business_number(text: &str, ws: usize, we: usize, core: &str) -> bool {
    if PLATE.is_match(core) {
        return true;
    }
    let Some(caps) = BUSINESS_NUMBER.captures(core) else {
        return false;
    };
    // S6: a camera or scanner counter (`IMG_2034`, `DSC01234`) and an ISO
    // date or month after no prefix, a device prefix, or an unmarked
    // vocabulary word that is no label word (`2025-07-14`,
    // `scan_2026-10-01`, `angebot-2026-03`) are no business numbers.
    let pre = &caps["pre"];
    let pre_word: String = pre.chars().filter(|c| c.is_alphabetic()).collect();
    if is_device_prefix(&pre_word)
        || (is_iso_date_or_month(&core[pre.len()..]) && date_prefix_ok(&pre_word))
    {
        return false;
    }
    let prefix_letters = pre.chars().filter(|c| c.is_alphabetic()).count();
    let digits = core.bytes().filter(u8::is_ascii_digit).count();
    let version = core.contains('.')
        && core
            .split(|c: char| !c.is_ascii_digit())
            .all(|g| g.len() <= 3);
    if digits < 4
        || prefix_letters > MAX_PREFIX_LETTERS
        || version
        || is_epoch_timestamp(text, ws, we, core)
    {
        return false;
    }
    !(is_lower_hex(core) && commit_cue(text, ws, we))
}

/// True when the word `text[ws..we]` is a business number, or one of its
/// parts split at `=` or `:` is (`Konto=1234010180`, `kundennr:K-123456`).
/// A part is judged as if it stood alone, so the key before a value is the
/// value's neighbour for [`time_cue`] and [`commit_cue`] (`"ts":1712345678`
/// stays a timestamp).
fn holds_business_number(text: &str, ws: usize, we: usize) -> bool {
    let w = &text[ws..we];
    if is_business_number(text, ws, we, trim_word(w)) {
        return true;
    }
    let mut from = ws;
    for (i, sep) in w
        .char_indices()
        .filter(|(_, c)| matches!(c, '=' | ':'))
        .chain(std::iter::once((w.len(), ' ')))
    {
        let (ps, pe) = (from, ws + i);
        let part = trim_word(&text[ps..pe]);
        if pe - ps < w.len() && !part.is_empty() && is_business_number(text, ps, pe, part) {
            return true;
        }
        from = pe + sep.len_utf8();
    }
    false
}

/// Seven or more lowercase hex digits (`f211934`, `e1234567`, `4348594`).
fn is_lower_hex(core: &str) -> bool {
    core.len() >= 7
        && core
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A git-log subject after a hash: a conventional commit type, an optional
/// scope, an optional `!`, then `:` (`fix: …`, `feat(cart): …`, `fix!: …`).
/// Other words (`status: offen`, `betreff: …`) are no subject.
static CONVENTIONAL_SUBJECT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\A\s+(?:feat|fix|docs|chore|refactor|test|perf|build|ci|style|revert)(?:\([^)\n]*\))?!?:\s",
    )
    .unwrap()
});

/// A line that starts with a lowercase hash holding a letter, then a space:
/// a git-log line. A hash that is itself business-shaped (`e1234567`,
/// `f7654321`) does not count: a list of customer numbers is no git log.
fn starts_with_hash(line: &str) -> bool {
    let first = line
        .trim_start()
        .split(char::is_whitespace)
        .next()
        .unwrap_or("");
    is_hash(first)
        && is_lower_hex(first)
        && !BUSINESS_NUMBER.is_match(first)
        && line.trim_start().len() > first.len()
}

/// `w` without leading and trailing non-alphanumerics.
fn trim_word(w: &str) -> &str {
    w.trim_matches(|c: char| !c.is_alphanumeric())
}

/// True when a commit cue is next to the word `text[ws..we]`: the word
/// before or after it is `commit`, `commits`, `sha`, or `HEAD`; another
/// word on its line is a 40-digit hex hash; or its line is a git-log line
/// (the word starts the line and a conventional subject follows, or the
/// line before or after starts with a hash). Only [`CONTEXT_WINDOW`] bytes
/// on each side are read; a neighbour word or line cut by the window is no
/// cue (the word is kept, recall first).
fn commit_cue(text: &str, ws: usize, we: usize) -> bool {
    let is_cue = |w: &str| {
        let w = trim_word(w);
        w == "HEAD"
            || ["commit", "commits", "sha"]
                .iter()
                .any(|c| c.eq_ignore_ascii_case(w))
    };
    let lo = floor_boundary(text, ws.saturating_sub(CONTEXT_WINDOW));
    let hi = ceil_boundary(text, we.saturating_add(CONTEXT_WINDOW));
    let before = word_before(text, lo, ws);
    let after = word_after(text, we, hi);
    if before.is_some_and(is_cue) || after.is_some_and(is_cue) {
        return true;
    }
    let (ls, le, starts_line, ends_line) = line_window(text, ws, we);
    let line = &text[ls..le];
    let word = &text[ws..we];
    if words(line).into_iter().any(|(off, w)| {
        // A word cut by the window edge is no 40-digit hash (round 2).
        let (a, b) = (ls + off, ls + off + w.len());
        let cut = (a == ls && !starts_line && !text[..ls].ends_with(char::is_whitespace))
            || (b == le && !ends_line && !text[le..].starts_with(char::is_whitespace));
        let c = trim_word(w);
        !cut && c != trim_word(word) && c.len() == 40 && is_lower_hex(c)
    }) {
        return true;
    }
    if !starts_line || !text[ls..ws].trim().is_empty() {
        return false;
    }
    if CONVENTIONAL_SUBJECT.is_match(&text[we..le]) {
        return true;
    }
    // The line before, read back at most CONTEXT_WINDOW bytes from its end;
    // a longer one is no cue.
    let prev = (ls > 0)
        .then(|| {
            let pe = ls - 1;
            let pl = floor_boundary(text, pe.saturating_sub(CONTEXT_WINDOW));
            match text[pl..pe].rfind('\n') {
                Some(i) => Some(&text[pl + i + 1..pe]),
                None if pl == 0 => Some(&text[..pe]),
                None => None,
            }
        })
        .flatten();
    // The line after: its first CONTEXT_WINDOW bytes hold the hash.
    let next = (ends_line && le < text.len())
        .then(|| {
            let nh = ceil_boundary(text, (le + 1).saturating_add(CONTEXT_WINDOW));
            text[le + 1..nh].split('\n').next()
        })
        .flatten();
    prev.is_some_and(starts_with_hash) || next.is_some_and(starts_with_hash)
}

/// The last whitespace word of `text[lo..ws]`; `None` when there is none or
/// it may run on before `lo` (cut by the window).
fn word_before(text: &str, lo: usize, ws: usize) -> Option<&str> {
    let s = text[lo..ws].trim_end();
    match s.char_indices().rev().find(|(_, c)| c.is_whitespace()) {
        Some((i, c)) => Some(&s[i + c.len_utf8()..]),
        None if s.is_empty() => None,
        None if lo == 0 || text[..lo].ends_with(char::is_whitespace) => Some(s),
        None => None,
    }
}

/// The first whitespace word of `text[we..hi]`; `None` when there is none or
/// it may run on after `hi` (cut by the window).
fn word_after(text: &str, we: usize, hi: usize) -> Option<&str> {
    let s = text[we..hi].trim_start();
    match s.find(char::is_whitespace) {
        Some(i) => Some(&s[..i]),
        None if s.is_empty() => None,
        None if hi == text.len() || text[hi..].starts_with(char::is_whitespace) => Some(s),
        None => None,
    }
}

fn is_uuid(core: &str) -> bool {
    core.len() == 36
        && core.char_indices().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

fn is_hash(core: &str) -> bool {
    core.len() >= 7
        && core.chars().all(|c| c.is_ascii_hexdigit())
        && core.chars().any(|c| c.is_ascii_digit())
        && core.chars().any(|c| c.is_ascii_alphabetic())
}

fn is_strong(w: &str, core: &str) -> bool {
    w.contains(['<', '>', '|', '{', '}', '[', ']', '$', '=', '`'])
        || w.contains("://")
        || is_uuid(core)
        || is_hash(core)
}

/// An uppercase letter followed only by lowercase letters, hyphens, or
/// apostrophes, with at least one lowercase letter (`Huber`, `Hans-Peter`).
fn is_capitalized(s: &str) -> bool {
    s.chars().next().is_some_and(char::is_uppercase)
        && s.chars().skip(1).any(char::is_lowercase)
        && s.chars()
            .skip(1)
            .all(|c| c.is_lowercase() || matches!(c, '-' | '\'' | '’'))
}

fn has_path_slash(w: &str) -> bool {
    let t = w
        .trim_start_matches(|c: char| !(c.is_alphanumeric() || matches!(c, '/' | '~' | '.')))
        .trim_end_matches(|c: char| !c.is_alphanumeric());
    t.contains('/')
        && (t.starts_with(['/', '~', '.'])
            || t.split('/')
                .filter(|s| !s.is_empty())
                .any(|s| !is_capitalized(s)))
}

fn has_code_extension(core: &str) -> bool {
    core.rsplit_once('.').is_some_and(|(stem, ext)| {
        stem.chars().any(char::is_alphanumeric)
            && CODE_EXTENSIONS.iter().any(|e| e.eq_ignore_ascii_case(ext))
    })
}

fn has_extension(core: &str) -> bool {
    core.rsplit_once('.').is_some_and(|(stem, ext)| {
        stem.chars().any(char::is_alphanumeric)
            && EXTENSIONS.iter().any(|e| e.eq_ignore_ascii_case(ext))
    })
}

/// A digit, a listed extension, or a leading `$`: the identifier is code,
/// so an [`ALSO_NAMES`] word in it is the product or tool (`claude-501`,
/// `CLAUDE.md`), or a model id (`gpt-6-sol`).
fn technical_context(w: &str, core: &str) -> bool {
    core.bytes().any(|b| b.is_ascii_digit())
        || has_extension(core)
        || is_model_id(core)
        || w.trim_start_matches(['(', '"']).starts_with('$')
}

/// Alphabetic runs, split at non-letters and at lower→upper changes.
fn alpha_runs(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut from: Option<usize> = None;
    let mut prev_lower = false;
    for (i, c) in s.char_indices() {
        if !c.is_alphabetic() || (c.is_uppercase() && prev_lower) {
            if let Some(f) = from.take() {
                out.push(&s[f..i]);
            }
        }
        if c.is_alphabetic() && from.is_none() {
            from = Some(i);
        }
        prev_lower = c.is_lowercase();
    }
    if let Some(f) = from {
        out.push(&s[f..]);
    }
    out
}

/// A lowercase-initial run with a later capital (`claudeMd`), or a capital
/// after a lowercase letter at char position 4 or later (`TodoWrite`).
/// `McDonald`, `MacLeod`, `DeMarco`, `GitHub` stay below position 4.
fn has_inner_capital(core: &str) -> bool {
    core.split(|c: char| !c.is_alphabetic()).any(|run| {
        let cs: Vec<char> = run.chars().collect();
        let lower_start = cs.first().is_some_and(|c| c.is_lowercase());
        (1..cs.len())
            .any(|i| cs[i].is_uppercase() && cs[i - 1].is_lowercase() && (lower_start || i >= 4))
    })
}

fn is_machine(w: &str, core: &str) -> bool {
    core.bytes().any(|b| b.is_ascii_digit())
        || w.contains('_')
        || has_path_slash(w)
        || w.char_indices()
            .any(|(i, c)| c == '#' && w[i + 1..].starts_with(char::is_alphanumeric))
        || has_extension(core)
        || has_inner_capital(core)
}

/// True when a strong or machine word names a person (C1, I3): a run of 3+
/// letters that is a first name or name-like word, except in a hash or UUID,
/// a hex-letter-only run in a segment with digits, or an [`ALSO_NAMES`] run
/// with technical context; or a capitalized segment ([`is_segment_break`],
/// in free text also cut at inner capitals) that is not a technical word
/// (`Rechnung_Huber_2026`, `Huber85`, free-text `HuberMaier`).
fn machine_word_names_a_person(
    w: &str,
    core: &str,
    origin: TextOrigin,
    file_position: bool,
) -> bool {
    if is_uuid(core) || is_hash(core) {
        return false;
    }
    let context = technical_context(w, core);
    let run_names = core.split(['/', '_', '-', '.', '\\', '@']).any(|seg| {
        let seg_digits = seg.bytes().any(|b| b.is_ascii_digit());
        alpha_runs(seg).into_iter().any(|r| {
            r.chars().count() >= 3
                && !(seg_digits
                    && r.chars()
                        .all(|c| matches!(c.to_ascii_lowercase(), 'a'..='f')))
                && (is_first_name(r) || is_name_like_word(r))
                && !(context && is_also_name(r))
        })
    });
    // N2: a capitalized, vowelled, non-vocabulary segment of an identifier
    // or file name (`Rechnung_Huber_2026`, `Rechnung-Huber-2026.pdf`,
    // `Huber.txt`). The vowel check keeps random suffixes (`Hnpyzrjd`) out.
    // A1: segments also end at a key's `=`, at `#`, at URL query marks, and
    // at digits, so a glued surname is one too (`Huber85`, `nachname=Huber`,
    // `Huber#2`). L118: in free text a segment is also split at inner
    // capitals (`HuberMaier`, `GruberAG`), as before the precision rule; in
    // harness-static text it is not, so `TodoWrite` and `$SkillName` stay
    // technical. A file name ([`TextOrigin::FileName`]) is split like free
    // text (L129).
    let free = origin != TextOrigin::HarnessStatic;
    let capital_segment = core
        .split(is_segment_break)
        .flat_map(|seg| if free { camel_parts(seg) } else { vec![seg] })
        .any(|seg| {
            seg.chars().count() >= 3
                && is_capitalized(seg)
                && seg.chars().any(|c| "aeiouäöüAEIOUÄÖÜ".contains(c))
                && !clears_capital_segment(seg, core, file_position, free)
        });
    run_names || capital_segment
}

/// `s` cut before each capital that follows a lowercase letter
/// (`HuberMaier` -> `Huber`, `Maier`; `GruberAG` -> `Gruber`, `AG`).
fn camel_parts(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut from = 0;
    let mut prev_lower = false;
    for (i, c) in s.char_indices() {
        if c.is_uppercase() && prev_lower {
            out.push(&s[from..i]);
            from = i;
        }
        prev_lower = c.is_lowercase();
    }
    out.push(&s[from..]);
    out
}

/// Where [`machine_word_names_a_person`] cuts an identifier into segments
/// for the capitalized-segment check: `_ - . / \\ = # & ? + @` and every
/// digit, so a digit run is a boundary (`Huber85` -> `Huber`).
fn is_segment_break(c: char) -> bool {
    matches!(
        c,
        '_' | '-' | '.' | '/' | '\\' | '=' | '#' | '&' | '?' | '+' | '@'
    ) || c.is_ascii_digit()
}

/// True when the capitalized segment `seg` of the identifier `core` is
/// vocabulary: an unmarked technical or document word (`Users`,
/// `Report.md`, `Rechnung_Huber_2026`), a rare-surname document word in a
/// file position (`Mail_2026.txt`, not `Mail_2026` as free text; S3,
/// L123), or a surname-marked one in a code file name (`App.tsx`).
/// Elsewhere a surname-marked word is a name (`Rechnung_Branch_2026.pdf`,
/// `Model.txt`; rulings C2, L3-09).
/// A document segment clears only when every letter run of `core` is
/// vocabulary ([`runs_are_vocabulary`]), so `Bewerbung_mueller.pdf` and
/// `Rechnung_Li_2026.pdf` keep the span (final fix wave, L139). `camel`
/// says the caller cut the segments at inner capitals too (not in a
/// harness-static text); the runs are cut the same way.
fn clears_capital_segment(seg: &str, core: &str, file_position: bool, camel: bool) -> bool {
    match VOCABULARY.get(seg.to_lowercase().as_str()) {
        Some(v) => match v.mark {
            Mark::Unmarked if v.document => runs_are_vocabulary(core, file_position, camel),
            Mark::Unmarked => true,
            Mark::Rare => file_position && runs_are_vocabulary(core, file_position, camel),
            Mark::Surname => has_code_extension(core),
        },
        None => false,
    }
}

/// True when every letter run of the token `core` (split at non-letters,
/// a trailing listed extension left out) could stand next to a document
/// word without being a name: a single letter, a stoplist word that is not
/// name-like, an unmarked word of either vocabulary, a `Rare` word in a file
/// position, or a lowercase surname-marked technical word (`branch`). A
/// lowercase surname (`mueller`), a two-letter one (`Li`, `ng`), a first
/// name, or a document `Surname` word (`menge`) is none (final fix wave
/// item 1, L139: a document word must never clear the name next to it).
/// With `camel` (every origin but harness-static, as
/// [`machine_word_names_a_person`] cuts its segments) a run is also cut at
/// inner capitals, so `FolderInfo` is `Folder` and `Info` (round 2, L140).
fn runs_are_vocabulary(core: &str, file_position: bool, camel: bool) -> bool {
    let stem = match core.rsplit_once('.') {
        Some((stem, ext)) if is_listed_extension(ext) => stem,
        _ => core,
    };
    stem.split(|c: char| !c.is_alphabetic())
        .filter(|r| !r.is_empty())
        .flat_map(|r| if camel { camel_parts(r) } else { vec![r] })
        .all(|r| {
            r.chars().count() == 1
                || (is_common_word(r) && !is_name_like_word(r))
                || match VOCABULARY.get(r.to_lowercase().as_str()) {
                    Some(v) => match v.mark {
                        Mark::Unmarked => true,
                        Mark::Rare => file_position,
                        Mark::Surname => !v.document && all_lowercase(r),
                    },
                    None => false,
                }
        })
}

/// How one alphabetic part of a plain word counts.
#[derive(Debug, PartialEq)]
enum Part {
    /// Technical evidence: a single letter, or a technical vocabulary word
    /// (a capitalized Census surname only as [`Part::Also`]).
    Evidence,
    /// An unmarked document word (S2): technical only for a span with no
    /// surname-marked or `ALSO_NAMES` word. A rare-surname document word
    /// counts only in a file position (S3, L123).
    Document,
    /// Neither evidence nor a name (`of`, `Li`, `the`).
    Filler,
    /// Counts only next to other evidence, or lowercase and no first name.
    Also,
    /// A lowercase vocabulary word that is a US Census surname (`fish`,
    /// `rust`, `head`): evidence inside an identifier, in a harness-static
    /// text, or between backticks; in free text, alone, it keeps the span
    /// (ruling L98, `danke rust`).
    LowerSurname,
    /// An unknown all-lowercase word: a name unless code syntax is near.
    LowerOther,
    /// A name, an honorific, or an unknown capitalized word: keep the span.
    Name,
}

fn judge(part: &str, claude_cue: bool, file_position: bool) -> Part {
    if claude_cue && part == "Claude" {
        return Part::Evidence;
    }
    let lower = part.to_lowercase();
    if HONORIFICS.contains(&lower.as_str()) {
        return Part::Name;
    }
    if ALSO_NAMES.contains(&lower.as_str()) {
        return Part::Also;
    }
    if let Some(v) = VOCABULARY.get(lower.as_str()) {
        match v.mark {
            Mark::Unmarked if v.document => return Part::Document,
            Mark::Unmarked => return Part::Evidence,
            Mark::Rare if file_position => return Part::Document,
            // L123: outside a file position a rare-surname document word is
            // judged as if it were in no vocabulary (`Herr Mail`, `Foto`).
            Mark::Rare => {}
            // C2: a capitalized word that is also a surname needs other evidence.
            Mark::Surname if !all_lowercase(part) => return Part::Also,
            // L98: a lowercase one needs a harness-static text or a code cue.
            Mark::Surname => return Part::LowerSurname,
        }
    }
    match part.chars().count() {
        1 => return Part::Evidence,
        2 => return Part::Filler,
        _ => {}
    }
    if is_first_name(part) || is_name_like_word(part) {
        return Part::Name;
    }
    if is_common_word(part) {
        return Part::Filler;
    }
    if all_lowercase(part) {
        Part::LowerOther
    } else {
        Part::Name
    }
}

fn all_lowercase(s: &str) -> bool {
    s.chars().all(|c| !c.is_alphabetic() || c.is_lowercase())
}

/// C3: `Claude` names the product only with a cue: the next word is `Code`,
/// `Opus`, `Sonnet`, or `Haiku`, or the text holds `Anthropic` or
/// `Claude Code`. Without one it stays a first name. The text-wide part is
/// computed at most once per text (`text_cue`, final review A2): it scans
/// the whole text, and per span that was quadratic.
fn claude_cue(text: &str, end: usize, text_cue: &OnceCell<bool>) -> bool {
    let next = text[end..].trim_start_matches(|c: char| c.is_whitespace() || c == ',');
    ["Code", "Opus", "Sonnet", "Haiku"]
        .iter()
        .any(|p| starts_with_word(next, p))
        || *text_cue.get_or_init(|| has_word(text, "Anthropic") || has_word(text, "Claude Code"))
}

/// `s` starts with `word`, and no letter or digit follows it.
fn starts_with_word(s: &str, word: &str) -> bool {
    s.strip_prefix(word)
        .is_some_and(|r| !r.starts_with(char::is_alphanumeric))
}

/// `word` occurs in `text` with no letter or digit on either side.
fn has_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(i, _)| {
        !text[..i].ends_with(char::is_alphanumeric) && starts_with_word(&text[i..], word)
    })
}

/// Model-id prefixes. A prefix that is a first name (`claude`) needs a digit
/// in the rest, so `claude-dubois` is not one; a segment that is a first
/// name is allowed only with a digit or as the catalog release names `sol`
/// and `luna`, so `gpt-anna` is not one.
const MODEL_PREFIXES: &[(&str, bool)] = &[
    ("gpt", false),
    ("codex", false),
    ("gemini", false),
    ("llama", false),
    ("mistral", false),
    ("qwen", false),
    ("claude", true),
];

fn is_model_id(core: &str) -> bool {
    let l = core.to_ascii_lowercase();
    MODEL_PREFIXES.iter().any(|(p, needs_digit)| {
        l.strip_prefix(p)
            .and_then(|r| r.strip_prefix('-'))
            .is_some_and(|rest| {
                !rest.is_empty()
                    && rest
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'))
                    && (!needs_digit || rest.bytes().any(|b| b.is_ascii_digit()))
                    && rest.split(['-', '.']).all(|seg| {
                        !(is_first_name(seg) || is_name_like_word(seg))
                            || seg.bytes().any(|b| b.is_ascii_digit())
                            || matches!(seg, "sol" | "luna")
                    })
            })
    })
}

/// Product tokens whose capitalized first segment is no name
/// (case-sensitive, with the `.js`).
const PRODUCT_TOKENS: &[&str] = &["Three.js"];

/// True when the model-found `PERSON` span `start..end` of `text`, at
/// `confidence`, is technical text (see the module docs). `tokens` are the
/// placeholder token ranges in `text`. Free text ([`TextOrigin::Free`]).
pub fn is_technical_person(
    text: &str,
    start: usize,
    end: usize,
    confidence: f32,
    tokens: &[Range<usize>],
) -> bool {
    is_technical_person_at(text, start, end, confidence, tokens, TextOrigin::Free)
}

/// [`is_technical_person`] for a text of known origin (ruling L3-14): under
/// [`TextOrigin::HarnessStatic`] a lowercase surname-marked or `ALSO_NAMES`
/// word alone is technical without a code cue (L98), and a CamelCase
/// identifier is not split at its inner capitals (L118). Under
/// [`TextOrigin::FileName`] the text is judged as free text in which every
/// word is a file position (S3, L129).
pub fn is_technical_person_at(
    text: &str,
    start: usize,
    end: usize,
    confidence: f32,
    tokens: &[Range<usize>],
    origin: TextOrigin,
) -> bool {
    technical_at(
        text,
        start,
        end,
        confidence,
        tokens,
        origin,
        &OnceCell::new(),
    )
}

/// [`is_technical_person_at`] with the text-wide `Claude` cue shared across
/// the spans of one text ([`claude_cue`]).
fn technical_at(
    text: &str,
    start: usize,
    end: usize,
    confidence: f32,
    tokens: &[Range<usize>],
    origin: TextOrigin,
    text_cue: &OnceCell<bool>,
) -> bool {
    if confidence >= CONFIDENT {
        return false;
    }
    let Some((lo, hi)) = enclosing(text, start, end) else {
        return false;
    };
    if tokens.iter().any(|t| t.start <= hi && lo <= t.end)
        || is_next_to_ranges(text, lo, hi, tokens)
    {
        return false;
    }
    // S6: a camera or scanner counter (`IMG 2034`, `Scan 20261001`).
    if is_device_counter(text, lo, hi) {
        return true;
    }
    let lower_cue = origin == TextOrigin::HarnessStatic || in_backticks(text, lo, hi);
    let piece = &text[start..end];
    let piece_only = piece.chars().all(char::is_alphabetic);
    let (mut evidence, mut strong, mut lower_other) = (false, false, false);
    let (mut lower_surname, mut document, mut short_unknown) = (false, false, false);
    let mut also: Vec<&str> = Vec::new();
    for (off, w) in words(&text[lo..hi]) {
        let core = w.trim_matches(|c: char| !c.is_alphanumeric());
        if holds_business_number(text, lo + off, lo + off + w.len()) {
            return false;
        }
        let is_code = is_strong(w, core);
        let file_position = is_file_position(w, core, origin);
        if PRODUCT_TOKENS.contains(&core) {
            evidence = true;
            continue;
        }
        let model_id = is_model_id(core);
        if is_code || model_id || is_machine(w, core) {
            let (ws, we) = (lo + off, lo + off + w.len());
            if piece_only && ws <= start && end <= we && piece != core {
                // C1: the model tagged one letters-only piece of an identifier.
                // I3: hex letters in an identifier with digits are no name.
                let hex_piece = piece
                    .chars()
                    .all(|c| matches!(c.to_ascii_lowercase(), 'a'..='f'))
                    && core.bytes().any(|b| b.is_ascii_digit());
                if !hex_piece {
                    // The cue never clears a piece inside an identifier
                    // (`/Users/claude/`, `claude_dubois`).
                    match judge(piece, false, file_position) {
                        // The identifier is the technical cue for a lowercase
                        // surname piece (R16).
                        Part::Evidence | Part::LowerSurname => {}
                        // A document piece is technical only among
                        // vocabulary (`notizen` in `notizen.txt`, not
                        // `Rechnung` in `Rechnung_huber_2026`; L139).
                        Part::Document
                            if runs_are_vocabulary(
                                core,
                                file_position,
                                origin != TextOrigin::HarnessStatic,
                            ) => {}
                        // An `ALSO_NAMES` piece needs technical context; a
                        // capitalized surname-marked vocabulary piece needs a
                        // code file name (L3-09).
                        Part::Also
                            if if is_also_name(piece) {
                                technical_context(w, core)
                            } else {
                                has_code_extension(core)
                            } => {}
                        _ => return false,
                    }
                }
            } else if !model_id && machine_word_names_a_person(w, core, origin, file_position) {
                return false;
            }
            strong |= is_code;
            evidence = true;
            continue;
        }
        let core = core
            .strip_suffix("'s")
            .or_else(|| core.strip_suffix("’s"))
            .unwrap_or(core);
        for part in core
            .split(|c: char| !c.is_alphanumeric())
            .filter(|p| !p.is_empty())
        {
            let cue = part == "Claude" && claude_cue(text, end, text_cue);
            match judge(part, cue, file_position) {
                Part::Evidence => evidence = true,
                Part::Document => document = true,
                // L139: a two-letter word that is no stoplist word may be a
                // surname (`Rechnung Li`); it never rides on a document word.
                Part::Filler => {
                    short_unknown |= part.chars().count() == 2 && !is_common_word(part);
                }
                Part::Also => also.push(part),
                Part::LowerSurname => lower_surname = true,
                Part::LowerOther => lower_other = true,
                Part::Name => return false,
            }
        }
    }
    if lower_other && !strong {
        return false;
    }
    // L98: a lowercase surname word (`fish`, `rust`) is evidence only in a
    // harness-static text or between backticks. With other evidence in the
    // span it is technical either way; alone in free text it stays a name
    // (`danke rust`).
    if lower_surname {
        if lower_cue {
            evidence = true;
        } else if !evidence {
            return false;
        }
    }
    // S2: a document word makes the span technical, but only `evidence`
    // clears a lowercase surname word above or an `ALSO_NAMES` or
    // capitalized surname word below (`angebot-branch`, `Angebot Model`).
    let mut technical = evidence || (document && !short_unknown);
    for part in also {
        if evidence {
            continue;
        }
        // R17: a lowercase ALSO_NAMES word alone (`page`) follows L98 too.
        if all_lowercase(part) && !is_first_name(part) && lower_cue {
            technical = true;
        } else {
            return false;
        }
    }
    technical
}

/// L98's technical cue in free text: the widened token stands directly
/// between backticks (`` `fish` ``), as code does in Markdown (R16). A
/// backtick inside the range means it runs over two code spans
/// (`` `rust` and `fish` ``) and is no single code span.
fn in_backticks(text: &str, lo: usize, hi: usize) -> bool {
    text[..lo].ends_with('`') && text[hi..].starts_with('`') && !text[lo..hi].contains('`')
}

/// Remove the model-found `PERSON` spans that [`is_technical_person`] calls
/// technical. Other kinds and other detectors pass through unchanged. Free
/// text ([`TextOrigin::Free`]).
pub fn drop_technical_persons(text: &str, spans: Vec<Span>, tokens: &[Range<usize>]) -> Vec<Span> {
    drop_technical_persons_at(text, spans, tokens, TextOrigin::Free)
}

/// [`drop_technical_persons`] for a text of known origin ([`TextOrigin`]).
pub fn drop_technical_persons_at(
    text: &str,
    spans: Vec<Span>,
    tokens: &[Range<usize>],
    origin: TextOrigin,
) -> Vec<Span> {
    let text_cue = OnceCell::new();
    spans
        .into_iter()
        .filter(|s| {
            !(s.kind == EntityKind::Person
                && s.source == DetectorId::Ner
                && technical_at(
                    text,
                    s.start,
                    s.end,
                    s.confidence,
                    tokens,
                    origin,
                    &text_cue,
                ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use unicode_normalization::UnicodeNormalization;

    fn tech(text: &str, needle: &str) -> bool {
        let start = text.find(needle).expect("needle in text");
        is_technical_person(text, start, start + needle.len(), 0.6, &[])
    }

    fn tech_static(text: &str, needle: &str) -> bool {
        let start = text.find(needle).expect("needle in text");
        is_technical_person_at(
            text,
            start,
            start + needle.len(),
            0.6,
            &[],
            TextOrigin::HarnessStatic,
        )
    }

    fn tech_file(text: &str, needle: &str) -> bool {
        let start = text.find(needle).expect("needle in text");
        is_technical_person_at(
            text,
            start,
            start + needle.len(),
            0.6,
            &[],
            TextOrigin::FileName,
        )
    }

    /// B6 (S1-S3): file-name stems and office words the model tags as persons.
    /// `mail-anfrage` as free text is not here: `mail` is a rare Census
    /// surname and counts only in a file position (L123, L129; pinned in
    /// `rare_surname_document_words_count_only_in_file_name_positions`).
    #[test]
    fn document_words_drop_file_name_spans() {
        for (text, needle) in [
            ("notizen", "notizen"),
            ("readme", "readme"),
            ("anhang", "anhang"),
            ("tabelle", "tabelle"),
            ("index", "index"),
            ("offerte", "offerte"),
            ("mahnung", "mahnung"),
            ("kundenliste", "kundenliste"),
            ("anfrage-kunde", "anfrage-kunde"),
            ("Unbenannt", "Unbenannt"),
            ("Untitled", "Untitled"),
            ("Neues Dokument", "Neues Dokument"),
            ("Mappe1", "Mappe1"),
            ("Dokument1", "Dokument1"),
            ("Quartalsbericht", "Quartalsbericht"),
            ("Datei notizen.txt anbei", "notizen"),
            ("Nachname;Vorname", "Nachname"),
            ("mail-anfrage.txt", "mail-anfrage.txt"),
        ] {
            assert!(tech(text, needle), "must drop: {needle:?}");
        }
    }

    /// Review Focus 1, S2: a surname next to a document word keeps the span.
    #[test]
    fn surnames_next_to_document_words_are_kept() {
        for (text, needle) in [
            ("anfrage-koch", "anfrage-koch"),
            ("angebot-weber", "angebot-weber"),
            ("weber-angebot", "weber-angebot"),
            ("angebot-branch", "angebot-branch"),
            ("Angebot Model", "Angebot Model"),
            ("Rechnung_Weber_2026", "Rechnung_Weber_2026"),
            ("Rechnung_Huber_2026.pdf", "Rechnung_Huber_2026"),
            ("Huber.txt", "Huber"),
            ("anna-gruber-cv", "anna-gruber-cv"),
            ("huber", "huber"),
            ("leitner-angebot", "leitner-angebot"),
            ("Herr Steuer", "Herr Steuer"),
            ("Ort", "Ort"),
            ("danke ort", "ort"),
        ] {
            assert!(!tech(text, needle), "must keep: {needle:?}");
        }
    }

    /// L123, L129 (S3 position-scoped): a rare-surname document word counts
    /// only in a file position: a token with an extension or a path
    /// separator, or a text the caller marks `TextOrigin::FileName`.
    /// Everything else, one-word texts and JSON values included, is judged
    /// as on `a82fd28`.
    #[test]
    fn rare_surname_document_words_count_only_in_file_name_positions() {
        for (text, needle) in [
            ("Mail_2026.txt", "Mail_2026"),
            ("Ordner /daten/foto/2026 anbei", "foto"),
        ] {
            assert!(
                tech(text, needle),
                "extension or path separator, must drop: {needle:?}"
            );
        }
        for (text, needle) in [
            ("mail-anfrage", "mail-anfrage"),
            ("foto", "foto"),
            ("steuer-bescheid", "steuer-bescheid"),
            ("foto 2025-07-14", "foto"),
            ("Mail_Anfrage", "Mail_Anfrage"),
        ] {
            assert!(
                tech_file(text, needle),
                "FileName origin, must drop: {needle:?}"
            );
        }
        for (text, needle) in [
            ("Herr Mail hat angerufen.", "Herr Mail"),
            ("Gestern hat Mail angerufen.", "Mail"),
            ("Bitte an Steuer weiterleiten.", "Steuer"),
            (r#"{"nachname":"Steuer"}"#, "Steuer"),
            ("mail-anfrage", "mail-anfrage"),
            ("Foto", "Foto"),
            ("Mail_2026", "Mail_2026"),
            ("Mail_Anfrage", "Mail_Anfrage"),
            // fix round 1: a missing space after a full stop is no extension,
            // and a capitalized `A/B` is no path (`has_path_slash`)
            ("Bitte an Steuer.danke", "Steuer"),
            ("Termin mit Preis.lg", "Preis"),
            ("Preis.ok", "Preis"),
            ("Preis.OK", "Preis"),
            ("Kanzlei Steuer/Preis", "Steuer"),
            ("Kanzlei Steuer/Rechnung", "Steuer"),
        ] {
            assert!(
                !tech(text, needle),
                "free text, not a file position, must keep: {needle:?}"
            );
        }
        for (text, needle) in [
            ("huber", "huber"),
            ("leitner-angebot", "leitner-angebot"),
            ("anna-gruber-cv", "anna-gruber-cv"),
            ("Rechnung_Huber_2026", "Rechnung_Huber_2026"),
        ] {
            assert!(
                !tech_file(text, needle),
                "FileName origin, a name, must keep: {needle:?}"
            );
        }
        // A year glued to a word stays a business number (L85 guard, S20;
        // spec section 3 residual `steuer-2025`), in a file name too.
        assert!(!tech_file("Mail_2026", "Mail_2026"));
    }

    /// Rule 1 must-drop table (planner-measured corpus spans).
    #[test]
    fn identifier_shaped_spans_are_technical() {
        for (text, needle) in [
            ("Recent commits:\na3f9c12 fix(api): retry", "a3f9c12"),
            (
                "2399c78 chore: bump vite to 7.1.2",
                "2399c78 chore: bump vite to 7.1.2",
            ),
            ("retry once on a 503", "503"),
            (
                r#"{"turn_id":"019a2f4e-7c1d-7b3a-9e5f-2c8d4a6b1f30"}"#,
                "019a2f4e-7c1d-7b3a-9e5f-2c8d4a6b1f30",
            ),
            (
                "git_head 8b9fa496bbf2c47aebd62e85a080b9a522a455b5",
                "8b9fa496bbf2c47aebd62e85a080b9a522a455b5",
            ),
            (
                "<root>/var/folders/7q/x2k9m4vd1t5c8b0000gn/T/codex-Hnpyzrjd</root>",
                "codex-Hnpyzrjd",
            ),
            ("/private/tmp/claude-501/scratch-k3x9q2vd", "claude-501"),
            (
                "model claude-opus-5-5-20261001.",
                "claude-opus-5-5-20261001",
            ),
            (
                "Current branch: feature/checkout-retry",
                "feature/checkout-retry",
            ),
            (
                "Status:\nM src/checkout/payment.ts",
                "M src/checkout/payment",
            ),
            ("files in $HOME and $CODEX_HOME", "$HOME"),
            ("files in $HOME and $CODEX_HOME", "$CODEX_HOME"),
            ("call apply_patch then update_plan", "apply_patch"),
            (
                "\"node_repl_auto_review_required\":true",
                "node_repl_auto_review_required",
            ),
            (
                "user_5f2a9c7e41b8d3a6_account_3c9e1d7a-4b2f",
                "user_5f2a9c7e41b8d3a6_account_3c9e1d7a-4b2f",
            ),
            ("links start with https:// here", "https://"),
            ("register r0 holds", "r0"),
            ("# CLAUDE.md", "# CLAUDE.md"),
            ("Contents of CLAUDE.md here", "CLAUDE"),
            ("see i.e. AGENTS.md first", "i.e. AGENTS.md"),
            ("OS Version: Darwin 25.0.0", "Darwin 25.0.0"),
            ("a [USER] marker", "[USER]"),
            ("Sender: <author>", "<author"),
            (
                "run git pull | tee output.txt now",
                "git pull | tee output.txt",
            ),
            ("never run rm -rf $HOME", "rm -rf $HOME"),
            ("brand/product/place/person", "brand/product/place/person"),
            ("started 1760140800123", "1760140800123"),
            ("started_at_ms", "started_at_ms"),
        ] {
            assert!(tech(text, needle), "should be technical: {needle:?}");
        }
    }

    /// Review Focus 1 (C1): names inside identifiers, paths, handles, URLs.
    #[test]
    fn names_inside_identifiers_are_kept() {
        for (text, needle) in [
            ("Im Anhang Rechnung_Huber_2026.pdf", "Huber"),
            ("Im Anhang Rechnung_Huber_2026.pdf", "Rechnung_Huber_2026"),
            ("Im Anhang Rechnung-Huber-2026.pdf", "Rechnung-Huber-2026"),
            ("Im Anhang Rechnung-Huber-2026.pdf", "Huber"),
            ("Die Liste steht in Huber.txt", "Huber"),
            ("Die Liste steht in Huber.txt", "Huber.txt"),
            ("Export: Huber.csv", "Huber.csv"),
            ("cat /home/x/Huber.txt", "Huber.txt"),
            ("Please ask @leitner first", "leitner"),
            ("Please ask @leitner first", "@leitner"),
            ("backup under /Users/claude/Documents/taxes", "claude"),
            ("Log in as claude_dubois today", "claude_dubois"),
            ("Datei unter C:\\Users\\mhuber\\Documents", "mhuber"),
            ("Team: https://kanzlei-beispiel.at/team/huber", "huber"),
            ("cd /home/huber/projects", "huber"),
            ("Working directory: /Users/dev/projects/acme-webshop", "dev"),
            ("login sarah_leitner85", "sarah_leitner85"),
            ("login anna85", "anna85"),
            ("login Anna_Huber", "Anna_Huber"),
            ("cd /Users/sarah.leitner/Documents", "sarah.leitner"),
        ] {
            assert!(!tech(text, needle), "must be kept: {needle:?}");
        }
    }

    /// Final review A2: the text-wide `Claude` cue, computed once per text,
    /// gives each span the same answer as a per-span call.
    #[test]
    fn claude_cue_is_shared_across_the_spans_of_one_text() {
        let span = |text: &str, n: &str| {
            let s = text.find(n).unwrap();
            Span::new(s, s + n.len(), EntityKind::Person, 0.6, DetectorId::Ner)
        };
        let text = "ask the user. Claude answers. Made by Anthropic.";
        let kept =
            drop_technical_persons(text, vec![span(text, "user"), span(text, "Claude")], &[]);
        assert!(kept.is_empty());
        let text = "ask the user. Claude hat angerufen.";
        let kept =
            drop_technical_persons(text, vec![span(text, "user"), span(text, "Claude")], &[]);
        assert_eq!(kept.len(), 1);
        assert_eq!(&text[kept[0].start..kept[0].end], "Claude");
    }

    /// Final review A3: the context scans read a bounded window. Cues inside
    /// it work on one long line; a cue farther away, or a span inside a very
    /// long unbroken run, keeps the span (recall first).
    #[test]
    fn context_scans_are_bounded() {
        let pad = "x,".repeat(400);
        let text = format!("{pad}\"ts\":1712345678,{pad}");
        assert!(tech(&text, "1712345678"));
        let text = format!("{pad} see commit 263225e for details {pad}");
        assert!(tech(&text, "263225e"));
        // an ISO date 800 bytes away on the same line is no time cue
        let text = format!("2024-04-05 {pad} build 1712345678");
        assert!(!tech(&text, "1712345678"));
        assert!(tech("2024-04-05 build 1712345678", "1712345678"));
        // a span inside an unbroken run of more than MAX_TOKEN_SIDE bytes
        let run = format!("{}_apply_patch", "a".repeat(MAX_TOKEN_SIDE + 10));
        assert!(!tech(&run, "apply_patch"));
        assert!(tech("call x_apply_patch now", "x_apply_patch"));
    }

    /// Round 2 (re-review): the window edge is no `\A` / `\z`. A digit-glued
    /// date cut at the edge (`12024-04-05` read from `2024-04-05`) is no time
    /// cue, and a longer hex word cut to 40 characters is no commit cue; both
    /// values are kept.
    #[test]
    fn window_edges_are_no_anchors() {
        let pre = format!("{}1", "a".repeat(10));
        let text = format!(
            "{pre}2024-04-05 {} build ",
            "b".repeat(CONTEXT_WINDOW - 10 - 1 - " build ".len())
        );
        assert_eq!(text.len() - CONTEXT_WINDOW, pre.len());
        let text = format!("{text}1712345678");
        assert!(!tech(&text, "1712345678"));
        // the same date not glued to a digit is a cue
        let ok = text.replacen("a1", "a ", 1);
        assert!(tech(&ok, "1712345678"));

        // Round 3: the same glued dates shifted by one byte (the `2` of
        // `12024` just before the window, or the last `5` of `2024-04-053`
        // just inside its end) are no cue either.
        let text0 = format!(
            "{pre}2024-04-05 {} build ",
            "b".repeat(CONTEXT_WINDOW - 10 - 1 - " build ".len() + 1)
        );
        assert_eq!(text0.len() - CONTEXT_WINDOW, pre.len() + 1);
        assert!(!tech(&format!("{text0}1712345678"), "1712345678"));
        let lead = "x 1712345678";
        let mid = format!(
            " build {} ",
            "b".repeat(CONTEXT_WINDOW - " build ".len() - 1 - 9)
        );
        let text = format!("{lead}{mid}2024-04-053 rest");
        assert_eq!(
            &text[lead.len() + CONTEXT_WINDOW..lead.len() + CONTEXT_WINDOW + 1],
            "5"
        );
        assert!(!tech(&text, "1712345678"));
        let mid = format!(
            " build {} ",
            "b".repeat(CONTEXT_WINDOW - " build ".len() - 1 - 10)
        );
        let text = format!("{lead}{mid}2024-04-053 rest");
        assert!(!tech(&text, "1712345678"));
        // control: an unglued date inside the window is a cue
        let text = format!("{lead}{mid}2024-04-05 rest");
        assert!(tech(&text, "1712345678"));

        let hex = "a1b2c3d4e5".repeat(5);
        let lead = "Rechnung f211934 ";
        let fill = "z".repeat(CONTEXT_WINDOW - 40 - 2);
        let text = format!("{lead}{fill} {hex} rest");
        let we = lead.len() - 1;
        assert_eq!(
            &text[we + CONTEXT_WINDOW - 40..we + CONTEXT_WINDOW],
            &hex[..40]
        );
        assert!(!tech(&text, "f211934"));
        // a real 40-digit hash inside the window is a cue
        let ok = format!("{lead}{fill} {} rest", &hex[..40]);
        assert!(tech(&ok, "f211934"));
    }

    /// Final review A2/A3: the filter's cost on a ~240 KB dense synthetic
    /// text, prose with many role-noun spans and one line of minified JSON
    /// with timestamps and hex ids. A measurement, not a gate (prints only):
    /// `cargo test --release -p inumaki-core --lib long_text_timing -- --ignored --nocapture`
    #[test]
    #[ignore = "timing measurement, run in release by hand"]
    #[allow(clippy::print_stderr)] // a measurement prints its numbers; no input text
    fn long_text_timing() {
        let prose = "The user runs `cargo test` in /tmp/work and the reviewer checks node_repl_auto_review_required here. ";
        let json = r#"{"id":"f211934","ts":1712345678,"role":"user","note":"reviewer"},"#;
        for (name, unit, needles) in [
            ("prose", prose, &["user", "reviewer"][..]),
            (
                "json-line",
                json,
                &["f211934", "1712345678", "user", "reviewer"][..],
            ),
        ] {
            for kb in [4usize, 30, 120, 240] {
                let text = unit.repeat(kb * 1024 / unit.len());
                let mut spans = Vec::new();
                for n in needles {
                    for (i, _) in text.match_indices(n) {
                        spans.push(Span::new(
                            i,
                            i + n.len(),
                            EntityKind::Person,
                            0.6,
                            DetectorId::Ner,
                        ));
                    }
                }
                let n = spans.len();
                let t = std::time::Instant::now();
                let out = drop_technical_persons_at(&text, spans, &[], TextOrigin::HarnessStatic);
                eprintln!(
                    "TIMING {name} {kb} KB spans={n} kept={} took={:?}",
                    out.len(),
                    t.elapsed()
                );
            }
        }
    }

    /// Final review A1: a capitalized surname glued to digits, `#`, or a
    /// key with `=` in a model span over the whole token is a name under
    /// both origins (`Huber85`, `nachname=Huber`); the harness identifiers
    /// stay technical.
    #[test]
    fn glued_surnames_in_whole_token_spans_are_kept() {
        for (text, needle) in [
            ("Bitte an Huber85 senden.", "Huber85"),
            ("Bitte an Leitner2026 senden.", "Leitner2026"),
            ("Mail Huber#2 ok", "Huber#2"),
            ("Formular nachname=Huber ok", "nachname=Huber"),
            ("Formular Kunde=Gruber ok", "Kunde=Gruber"),
            (
                "Link https://x.at/?kunde=Huber&id=7 ok",
                "https://x.at/?kunde=Huber&id=7",
            ),
            ("Ordner 2026Huber ok", "2026Huber"),
        ] {
            assert!(!tech(text, needle), "free text, must be kept: {needle:?}");
            assert!(
                !tech_static(text, needle),
                "harness-static, must be kept: {needle:?}"
            );
        }
        for (text, needle) in [
            ("files in $HOME and $CODEX_HOME", "$CODEX_HOME"),
            (
                "\"node_repl_auto_review_required\":true",
                "node_repl_auto_review_required",
            ),
            ("commit 3ada9f2 here", "3ada9f2"),
            (
                "id 0ebba3c1-7c1d-7b3a-9e5f-2c8d4a6b1f30",
                "0ebba3c1-7c1d-7b3a-9e5f-2c8d4a6b1f30",
            ),
            ("OS Version: Darwin 25.0.0", "Darwin 25.0.0"),
            ("export RUST_LOG=debug", "RUST_LOG=debug"),
            ("run with --color=always", "--color=always"),
            ("built with rust-v0.159.2 today", "rust-v0.159.2"),
        ] {
            assert!(
                tech(text, needle),
                "free text, should be technical: {needle:?}"
            );
            assert!(
                tech_static(text, needle),
                "harness-static, should be technical: {needle:?}"
            );
        }
    }

    /// Ruling L118: a CamelCase surname part keeps a whole-token model span
    /// in free text, as before the precision rule (L117); in harness-static
    /// text CamelCase is not split, so harness identifiers stay technical.
    #[test]
    fn camel_case_surnames_are_kept_in_free_text_only() {
        for (text, needle) in [
            ("siehe HuberMaier ok", "HuberMaier"),
            ("Firma GruberAG ok", "GruberAG"),
        ] {
            assert!(!tech(text, needle), "free text, must be kept: {needle:?}");
            assert!(
                tech_static(text, needle),
                "harness-static, should be technical: {needle:?}"
            );
        }
        // Harness identifiers: technical in harness-static text. In free text
        // their CamelCase part keeps them (L118; moved here from
        // `identifier_shaped_spans_are_technical`, a free-text table).
        for (text, needle) in [
            ("Use the TodoWrite tool", "TodoWrite"),
            ("name it $SkillName.", "$SkillName"),
            (
                "fede7fa feat(cart): keep the cart in localStorage",
                "fede7fa feat(cart): keep the cart in localStorage",
            ),
        ] {
            assert!(
                tech_static(text, needle),
                "harness-static, should be technical: {needle:?}"
            );
            assert!(!tech(text, needle), "free text, kept: {needle:?}");
        }
        // a first-name part keeps it in both origins
        assert!(!tech("siehe MaxHuber ok", "MaxHuber"));
        assert!(!tech_static("siehe MaxHuber ok", "MaxHuber"));
    }

    /// Recall checkpoint (Task 2): the model's `PERSON` tag on a business
    /// number is the only cover when no regex matched it. Measured leaks on
    /// the tuning corpus when these were dropped.
    #[test]
    fn business_numbers_are_kept() {
        for (text, needle) in [
            (
                "dear sir or madam,\n\ninvoiec re-2026-63895 dated 09.06.2026",
                "re-2026-63895",
            ),
            (
                "a reminder for nivoice RE-2026-79580 although I paid",
                "RE-2026-79580",
            ),
            (
                "eine Mhanung zur Rechunng RE-2026-55327 erhalten",
                "RE-2026-55327",
            ),
            (
                "das fahrzeug mit dem kennzeichen l-89821b, zugelassen",
                "l-89821b",
            ),
            (
                "das fahrzeug mit dem kennzeichen w-9666c, zugelassen",
                "w-9666c",
            ),
            ("the vehicle with plate g-16131a, registered", "g-16131a"),
            ("Meine Kudnennummer ist 4867526. Bitte", "4867526"),
            ("Kundennummer K-954701.", "K-954701"),
            ("Vertrag V-49141088", "V-49141088"),
            ("Kennzeichen W-12345A", "W"),
            ("Rechnung 2026/12345", "2026/12345"),
        ] {
            assert!(!tech(text, needle), "must be kept: {needle:?}");
        }
    }

    /// Fix round 1 (L85): real business-number shapes beyond the generator's.
    #[test]
    fn real_business_number_shapes_are_kept() {
        for (text, needle) in [
            ("Kunde e1234567 hat angerufen", "e1234567"),
            ("Kennzeichen w-123ab bitte", "w-123ab"),
            ("Kennzeichen gu-12ab bitte", "gu-12ab"),
            ("Kennzeichen m-ab-123 bitte", "m-ab-123"),
            ("Kennzeichen W-12345A", "W-12345A"),
            ("Nummer kunde-123456 bitte", "kunde-123456"),
            ("Nummer KD-NR-12345 bitte", "KD-NR-12345"),
            ("Nummer AT-W-12345 bitte", "AT-W-12345"),
            ("Konto 12345678901234 bitte", "12345678901234"),
            ("IBAN AT6119043002345732011 bitte", "AT6119043002345732011"),
            ("Vertrag V12345678", "V12345678"),
            ("Kunde E1234567", "E1234567"),
        ] {
            assert!(!tech(text, needle), "must be kept: {needle:?}");
        }
    }

    /// S6: camera and scanner counters and ISO dates are not business numbers.
    #[test]
    fn device_counters_and_iso_dates_are_not_business_numbers() {
        for (text, needle) in [
            ("IMG_2034", "IMG_2034"),
            ("IMG 2034", "IMG 2034"),
            ("IMG_20261001_123456", "IMG_20261001_123456"),
            ("IMG 20261001_123456", "IMG 20261001_123456"),
            ("PXL_20261001_123456789", "PXL_20261001_123456789"),
            ("DSC01234", "DSC01234"),
            ("DSCN0042", "DSCN0042"),
            ("VID 20261001_101010", "20261001_101010"),
            ("scan0001", "scan0001"),
            ("Scan 20261001", "Scan 20261001"),
            ("scan_2026-10-01", "scan_2026-10-01"),
            ("foto 2025-07-14", "2025-07-14"),
            ("angebot 2026-03", "2026-03"),
        ] {
            assert!(tech(text, needle), "must drop: {needle:?}");
        }
        for (text, needle) in [
            ("RE-2026-10", "RE-2026-10"),
            ("RE-2026-63895", "RE-2026-63895"),
            ("kunde-123456", "kunde-123456"),
            ("K-954701", "K-954701"),
            ("4867526", "4867526"),
            ("w-123ab", "w-123ab"),
            ("IMG_Huber", "IMG_Huber"),
            ("Nummer 2026-13-01", "2026-13-01"),
            ("Rechnung 20261001", "20261001"),
            ("re_2026-10-01", "re_2026-10-01"),
        ] {
            assert!(!tech(text, needle), "must keep: {needle:?}");
        }
    }

    /// The plate and prefix shapes leave model ids, tool dirs, versions,
    /// and epoch timestamps technical.
    #[test]
    fn model_ids_and_timestamps_stay_technical() {
        for (text, needle) in [
            ("model gpt-5 here", "gpt-5"),
            ("dir claude-501 here", "claude-501"),
            (
                "model claude-opus-5-5-20261001.",
                "claude-opus-5-5-20261001",
            ),
            ("built with rust-v0.159.2 today", "rust-v0.159.2"),
            ("\"started_at_ms\":1785006575038,", "1785006575038"),
        ] {
            assert!(tech(text, needle), "should be technical: {needle:?}");
        }
    }

    #[test]
    fn product_names_and_model_ids_are_technical() {
        for (text, needle) in [
            ("You are Codex, an agent", "Codex"),
            ("Use Mermaid for diagrams", "Mermaid"),
            ("switch between Opus, Sonnet, and Haiku", "Opus"),
            ("model gpt-6-sol here", "gpt-6-sol"),
            ("model gpt-6-luna here", "gpt-6-luna"),
            ("model gpt-5.6-luna here", "gpt-5.6-luna"),
            ("slug gpt-daybreak-red-latest", "gpt-daybreak-red-latest"),
            ("a Jupyter notebook", "Jupyter notebook"),
            // Controller addition A.
            ("Made by Anthropic for you", "Anthropic"),
            ("Render it with Three.js in the page", "Three.js"),
            ("Render it with Three.js in the page", "Three"),
        ] {
            assert!(tech(text, needle), "should be technical: {needle:?}");
        }
        for (text, needle) in [("Herr Three", "Three"), ("Three hat angerufen", "Three")] {
            assert!(!tech(text, needle), "must be kept: {needle:?}");
        }
    }

    /// Review Focus 5 (C3): `Claude` is the product only with a cue (the
    /// next word is Code, Opus, Sonnet, or Haiku, or the text holds
    /// `Anthropic` or `Claude Code`); otherwise a first name.
    #[test]
    fn claude_is_a_product_only_with_a_cue() {
        for (text, needle) in [
            (
                "You are Claude Code, Anthropic's coding agent",
                "Claude Code",
            ),
            (
                "You are Claude Code. Claude should answer briefly.",
                "Claude should",
            ),
            ("Made by Anthropic. Ask Claude for help.", "Claude"),
            ("switch to Claude Opus now", "Claude Opus"),
        ] {
            assert!(tech(text, needle), "should be technical: {needle:?}");
        }
        for (text, needle) in [
            ("Claude hat angerufen", "Claude"),
            (r#"{"vorname":"Claude"}"#, "Claude"),
            ("Thanks, Claude, for the form", "Claude"),
            ("Anfrage von Claude Dubois", "Claude Dubois"),
            ("login claude-dubois", "claude-dubois"),
            // Fix round 1: the cue never clears a piece inside an identifier.
            ("You are Claude Code. cwd: /Users/claude/project", "claude"),
            ("Made by Anthropic. login claude_dubois", "claude"),
            ("Made by Anthropic. login claude_dubois", "claude_dubois"),
            // Fix round 1: the cue needs word boundaries.
            ("Anfrage von Claude Coderre", "Claude Coderre"),
            ("Anfrage von Claude Coderre", "Claude"),
            ("Anfrage von Claude, Anthropics Kunde", "Claude"),
            ("Claude und Anna", "Claude und Anna"),
            ("Luna", "Luna"),
            ("gpt-anna", "gpt-anna"),
        ] {
            assert!(!tech(text, needle), "must be kept: {needle:?}");
        }
    }

    /// Fix round 2 (ruling L88): a 10-digit value is an epoch time only with
    /// a time cue next to it (`ts`, `expires`, `created_at`, ...) or an ISO
    /// date on its line. Without one it may be an account, SV, or customer
    /// number and is kept.
    #[test]
    fn ten_digit_numbers_need_a_time_cue() {
        for (text, needle) in [
            ("{\"ts\": 1712345678}", "1712345678"),
            ("expires=1712345678", "1712345678"),
            ("created_at 1712345678", "1712345678"),
            ("\"exp\": 1712345678,", "1712345678"),
            ("2024-04-05 build 1712345678", "1712345678"),
            ("{\"expires\": 1712345678}", "1712345678"),
        ] {
            assert!(tech(text, needle), "should be technical: {needle:?}");
        }
        for (text, needle) in [
            ("Konto 1234010180 bitte", "1234010180"),
            ("SV-Nummer 1234010180", "1234010180"),
            ("Versicherungsnummer: 4711150385", "4711150385"),
            ("Kundennummer 2034567890", "2034567890"),
            ("Export 1234010180", "1234010180"),
            ("at 1760140800 seconds", "1760140800"),
        ] {
            assert!(!tech(text, needle), "must be kept: {needle:?}");
        }
    }

    /// Task 3 (controller addition A): a value glued to its key with `=` or
    /// `:` goes through the business-number guard and the time cue as if it
    /// stood alone, with the key as its neighbour.
    #[test]
    fn values_glued_to_a_key_are_judged_alone() {
        for (text, needle) in [
            ("Konto=1234010180", "1234010180"),
            ("Konto=1234010180", "Konto=1234010180"),
            ("{\"kontonummer\":1234010180}", "1234010180"),
            ("{\"kontonummer\":1234010180}", "kontonummer\":1234010180"),
            ("kundennr:K-123456 bitte", "K-123456"),
            ("kundennr:K-123456 bitte", "kundennr:K-123456"),
        ] {
            assert!(!tech(text, needle), "must be kept: {needle:?}");
        }
        for (text, needle) in [
            ("{\"ts\":1712345678}", "1712345678"),
            ("{\"ts\":1712345678}", "ts\":1712345678"),
            ("expires=1712345678", "1712345678"),
            ("expires=1712345678", "expires=1712345678"),
            ("export RUST_LOG=debug", "RUST_LOG=debug"),
            ("run with --color=always", "--color=always"),
        ] {
            assert!(tech(text, needle), "should be technical: {needle:?}");
        }
    }

    /// Rules 2 and 3 must-drop table (planner-measured corpus spans).
    #[test]
    fn role_nouns_and_technical_phrases_are_technical() {
        for (text, needle) in [
            ("ask the user first", "user"),
            ("All users agree", "users"),
            ("the User decides", "User"),
            ("user's prompt", "user's prompt"),
            ("the reviewer agent", "reviewer"),
            ("the assistant replies", "assistant"),
            (
                "Filesystem sandboxing defines which files",
                "Filesystem sandboxing",
            ),
            ("## Intermediate commentary", "Intermediate commentary"),
            (
                "an incompatible new objective",
                "incompatible new objective",
            ),
            ("“Binaries” under “Rust Workspace”", "Rust Workspace"),
            ("# Writing style", "# Writing style"),
            ("run git reset first", "git reset"),
            ("Use GitHub-flavored Markdown", "GitHub-flavored Markdown"),
            ("rendered in a Monospace font", "Monospace"),
            ("B/I icons", "B/I icons"),
            ("contrastive framing such as \"X, not Y\"", "X, not Y"),
            (":line[:column] or #Lline[Ccolumn]", "Lline"),
            ("files in $HOME and $CODEX_HOME", "HOME"),
            ("[My Report.md](/abs/My Report.md)", "My Report.md"),
            ("Status:\n D Cargo.toml", "D Cargo.toml"),
            ("open src/web/App.tsx", "App.tsx"),
            (
                "<root>/private/tmp/claude-515/-home-admin-work-billing-api/7f97a24b-d66d-7884-9927-a7922972d531</root>",
                "7f97a24b-d66d-7884-9927-a7922972d531",
            ),
        ] {
            assert!(tech(text, needle), "should be technical: {needle:?}");
        }
    }

    /// Ruling L98 (and R16, R17): a lowercase surname-marked vocabulary word
    /// (or a lowercase `ALSO_NAMES` word) that is the span's only evidence is
    /// technical in a harness-static text; in free text only between
    /// backticks, inside an identifier, or with other evidence in the span.
    /// Elsewhere in free text it stays a name (`danke rust`).
    #[test]
    fn lowercase_surname_words_need_a_harness_static_text_or_a_code_cue() {
        for (text, needle) in [
            ("Shell: fish", "fish"),
            ("a senior engineer", "senior engineer"),
            ("wrapped my head around", "head"),
            ("type \"rust\" or \"py\"", "rust"),
            ("Main branch (you will usually use this)", "Main branch"),
            ("danke rust", "rust"),
            ("fish", "fish"),
            ("danke page", "page"),
        ] {
            assert!(
                tech_static(text, needle),
                "harness-static, should be technical: {needle:?}"
            );
            assert!(!tech(text, needle), "free text, must be kept: {needle:?}");
        }
        for (text, needle) in [
            ("set the shell to `fish` first", "fish"),
            ("type `rust` here", "rust"),
            ("run git main now", "git main"),
            ("built with rust-v0.159.2 today", "rust"),
        ] {
            assert!(
                tech(text, needle),
                "free text with a code cue, should be technical: {needle:?}"
            );
        }
        // a backtick on one side only is no cue
        assert!(!tech("danke `rust", "rust"));
        // two code spans joined by a word are no single code span. Asserted on
        // the cue itself: end to end such a range is dropped anyway, because a
        // word holding a backtick is a strong code word (`is_strong`).
        let two = "set `rust` and `fish` first";
        let (lo, hi) = (5, two.find("` first").unwrap());
        assert_eq!(&two[lo..hi], "rust` and `fish");
        assert!(!in_backticks(two, lo, hi));
        assert!(in_backticks(two, 5, 9));
        // capitalized surname words keep C2 under both origins
        assert!(!tech_static("Herr Model hat angerufen", "Model"));
        assert!(!tech_static("Ansprechpartner: Sender", "Sender"));
    }

    /// Review Focus 4 (C2): a capitalized vocabulary word that is a Census
    /// surname, alone or after an honorific, is a name.
    #[test]
    fn surname_vocabulary_words_alone_are_kept() {
        for (text, needle) in [
            ("Herr Model hat angerufen", "Herr Model"),
            ("Herr Model hat angerufen", "Model"),
            ("Frau Branch bittet um Rückruf", "Branch"),
            (r#"{"vorname":"Anna","nachname":"Model"}"#, "Model"),
            ("Nachname;Vorname\nBranch;Anna", "Branch"),
            ("Ansprechpartner: Sender", "Sender"),
            ("Bitte an Koch weiterleiten", "Koch"),
            ("Weber", "Weber"),
            ("Line", "Line"),
            ("Darwin", "Darwin"),
            ("Termin mit Frau Mode", "Frau Mode"),
            ("the user Gruber", "user Gruber"),
        ] {
            assert!(!tech(text, needle), "must be kept: {needle:?}");
        }
    }

    /// Ruling L3-09: a capitalized surname-marked vocabulary word inside an
    /// identifier or file name is a name; only a code-file extension clears
    /// it (`App.tsx`), never a document extension or a digit run.
    #[test]
    fn surname_vocabulary_segments_in_file_names_are_kept() {
        for (text, needle) in [
            ("Im Anhang Rechnung_Branch_2026.pdf", "Branch"),
            ("Im Anhang Rechnung_Branch_2026.pdf", "Rechnung_Branch_2026"),
            ("Die Liste steht in Model.txt", "Model"),
            ("Die Liste steht in Model.txt", "Model.txt"),
            ("Export: Sender_2026.csv", "Sender"),
            ("Export: Sender.csv", "Sender.csv"),
        ] {
            assert!(!tech(text, needle), "must be kept: {needle:?}");
        }
        for (text, needle) in [
            ("open src/web/App.tsx", "App.tsx"),
            ("open src/web/App.tsx", "App"),
        ] {
            assert!(tech(text, needle), "should be technical: {needle:?}");
        }
    }

    /// Review Focus 4: lowercase names stay names without code syntax.
    #[test]
    fn lowercase_names_are_kept_without_code_context() {
        for (text, needle) in [
            ("danke illichmann", "illichmann"),
            ("danke luna", "luna"),
            ("grüße an huber und team", "huber und team"),
            ("hallo sarah user", "sarah user"),
            ("ask leitner", "leitner"),
            ("login admin", "admin"),
        ] {
            assert!(!tech(text, needle), "must be kept: {needle:?}");
        }
    }

    /// No entry is a first name, a name-like word, an honorific, or an
    /// also-name; every entry is one lowercase ASCII word.
    #[test]
    fn vocabulary_holds_no_names() {
        for (w, _) in vocabulary() {
            assert!(
                !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase()),
                "{w:?}"
            );
            assert!(
                !is_first_name(w) && !is_name_like_word(w),
                "{w:?} is a name"
            );
            assert!(
                !HONORIFICS.contains(&w) && !ALSO_NAMES.contains(&w),
                "{w:?}"
            );
        }
    }

    /// Final fix wave item 1 (L139): a document word clears a span only when
    /// every other letter run of its token is vocabulary, a single letter,
    /// or a stoplist word that is not name-like. A lowercase surname or a
    /// two-letter one next to it keeps the span, as on `e041659`, in free
    /// text and in file names.
    #[test]
    fn document_words_never_clear_a_surname_next_to_them() {
        for (text, needle) in [
            ("Bewerbung_mueller.pdf", "Bewerbung_mueller"),
            ("Bewerbung_mueller.pdf", "Bewerbung"),
            ("Angebot_leitner_v2.docx", "Angebot_leitner_v2"),
            ("Angebot_leitner_v2.docx", "Angebot"),
            ("Rechnung_huber_2026", "Rechnung_huber_2026"),
            ("Rechnung_huber_2026", "Rechnung"),
            ("Rechnung_Li_2026.pdf", "Rechnung_Li_2026"),
            ("Rechnung_Li_2026.pdf", "Rechnung"),
            ("Anbei die Rechnung Li zur Prüfung.", "Rechnung Li"),
            ("bewerbung_ng", "bewerbung"),
        ] {
            assert!(
                !tech(text, needle),
                "free text, must keep: {needle:?} in {text:?}"
            );
            assert!(
                !tech_file(text, needle),
                "file name, must keep: {needle:?} in {text:?}"
            );
        }
        // Residual by design (L140): a lowercase unknown run next to a
        // document word keeps the span, in code too.
        assert!(!tech(
            "let x = FolderInfo.outbox_destination;",
            "FolderInfo.outbox_destination"
        ));
        // the B6 shapes with only vocabulary around them still drop; in free
        // text the runs are cut at inner capitals as the segments are
        // (round 2, L140: `FolderInfo` is `Folder` + `Info`)
        for (text, needle) in [
            ("class FolderInfo", "FolderInfo"),
            ("class FolderConfig", "FolderConfig"),
            ("class FolderStatus", "FolderStatus"),
            ("Mappe1", "Mappe1"),
            ("Rechnung_2026.pdf", "Rechnung_2026"),
            ("Bericht_final_v3.docx", "Bericht_final_v3"),
            ("Datei notizen.txt anbei", "notizen"),
            ("anfrage-kunde", "anfrage-kunde"),
        ] {
            assert!(tech(text, needle), "must drop: {needle:?} in {text:?}");
        }
    }

    /// S2-S4: the document vocabulary holds no name and no technical word.
    #[test]
    fn document_vocabulary_holds_no_names() {
        let technical: std::collections::HashSet<&str> = vocabulary().map(|(w, _)| w).collect();
        for (w, _) in document_vocabulary() {
            assert!(
                !w.is_empty() && w.chars().all(|c| c.is_alphabetic() && c.is_lowercase()),
                "{w:?}"
            );
            assert!(w.nfc().eq(w.chars()), "{w:?} is not NFC");
            assert!(
                !is_first_name(w) && !is_name_like_word(w),
                "{w:?} is a name"
            );
            assert!(
                !HONORIFICS.contains(&w) && !ALSO_NAMES.contains(&w),
                "{w:?}"
            );
            assert!(!technical.contains(w), "{w:?} is already a technical word");
        }
    }

    /// L85: a lowercase hex-shaped word (`f211934`, `e1234567`, `4348594`)
    /// is kept unless a commit cue is next to it.
    #[test]
    fn hex_shaped_numbers_need_a_commit_cue() {
        for (text, needle) in [
            ("Recent commits:\nf211934 fix(api): retry", "f211934"),
            ("Recent commits:\ndee0994 docs: steps", "dee0994"),
            (
                "b5f8044 fix(api): retry once on a 503\n4348594 fix(ui): keep focus",
                "4348594",
            ),
            ("f84609c Merge branch x\nb5f8044 Update readme", "f84609c"),
            ("see commit 263225e for details", "263225e"),
            ("the sha e1234567 is fine", "e1234567"),
            ("e1234567 (HEAD -> main) Update", "e1234567"),
            (
                "f84609c 8b9fa496bbf2c47aebd62e85a080b9a522a455b5",
                "f84609c",
            ),
            ("abc1234 fix(core): retry", "abc1234"),
        ] {
            assert!(tech(text, needle), "should be technical: {needle:?}");
        }
        for (text, needle) in [
            ("Rechnung f211934 bitte zahlen", "f211934"),
            ("Nummer 4348594 bitte", "4348594"),
            ("4867526 Huber\n4867527 Maier", "4867526"),
            ("4867526 fix\nKunde", "4867526"),
            // Fix round 2 (L88): a business-shaped neighbour hash is no
            // git-log cue, and only conventional commit types are subjects.
            ("e1234567 Huber\n4867526 Maier", "4867526"),
            ("e1234567 Huber\nf7654321 Maier", "e1234567"),
            ("e1234567 Huber\nf7654321 Maier", "f7654321"),
            ("4867526 status: offen", "4867526"),
            ("e1234567 betreff: Rechnung", "e1234567"),
        ] {
            assert!(!tech(text, needle), "must be kept: {needle:?}");
        }
    }

    /// Fix round 1, Important 2: technical shapes next to or glued to a
    /// placeholder are kept; the same text without tokens is technical.
    #[test]
    fn placeholders_keep_technical_shapes() {
        let text = "<PERSON_xxxx> r0";
        assert!(is_technical_person(text, 14, 16, 0.6, &[]));
        assert!(!is_technical_person(
            text,
            14,
            16,
            0.6,
            std::slice::from_ref(&(0..13))
        ));
        let text = "a3f9c12_<PERSON_xxxx>";
        assert!(is_technical_person(text, 0, 7, 0.6, &[]));
        assert!(!is_technical_person(
            text,
            0,
            7,
            0.6,
            std::slice::from_ref(&(8..21))
        ));
    }

    /// Review Focus 3.
    #[test]
    fn names_with_punctuation_and_inner_capitals_are_kept() {
        for (text, needle) in [
            ("Sehr geehrter Herr McDonald,", "McDonald"),
            ("Hi Ewan MacLeod", "Ewan MacLeod"),
            ("from Siobhan O'Brien", "Siobhan O'Brien"),
            ("from O'Brien", "O'Brien"),
            ("Hans-Peter Gruber schrieb", "Hans-Peter Gruber"),
            ("Dear J. Smith,", "J. Smith"),
            ("Termin mit Dr. Huber", "Dr. Huber"),
            ("Gruß, Anna M.", "Anna M."),
            ("Ansprechpartner: Huber/Maier.", "Huber/Maier"),
            ("Max.Mustermann hat geschrieben", "Max.Mustermann"),
            ("Liebe AnnaLena,", "AnnaLena"),
            ("Ewa Li und Tom Wu", "Li"),
            ("Herr Huber ruft an", "Herr Huber"),
            ("Darwin", "Darwin"),
            ("Liebe Line,", "Line"),
            ("Anfrage von Claude Dubois", "Claude Dubois"),
        ] {
            assert!(!tech(text, needle), "must be kept: {needle:?}");
        }
    }

    /// Review Focus 2.
    #[test]
    fn json_and_markup_names_are_judged_alone() {
        for (text, needle) in [
            (r#"{"name":"Huber"}"#, "Huber"),
            (r#"{"author": "anna.berger"}"#, "anna.berger"),
            (r#"{"user":"leitner","id":7}"#, "leitner"),
            ("<td>Gruber</td>", "Gruber"),
            ("`Huber` hat angerufen", "Huber"),
            ("Danke an “Huber” für alles", "Huber"),
        ] {
            assert!(!tech(text, needle), "must be kept: {needle:?}");
        }
    }

    /// Review Focus 6 (I3): letters of a random id that spell a name.
    #[test]
    fn hex_runs_are_not_names() {
        for (text, needle) in [
            ("commit 3ada9f2", "3ada9f2"),
            ("build 3ada9f2", "ada"),
            (
                "id 0ebba3c1-7c1d-7b3a-9e5f-2c8d4a6b1f30",
                "0ebba3c1-7c1d-7b3a-9e5f-2c8d4a6b1f30",
            ),
            ("/var/folders/7q/edda12x9/T/x", "edda12x9"),
        ] {
            assert!(tech(text, needle), "should be technical: {needle:?}");
        }
    }

    /// R5: next to or glued to a placeholder, never technical.
    #[test]
    fn spans_next_to_a_token_are_never_technical() {
        let text = "huber_<PERSON_xxxx> and <PERSON_xxxx> huber85 then a3f9c12";
        let tokens = [6..19, 24..37];
        assert!(!is_technical_person(text, 0, 6, 0.6, &tokens));
        assert!(!is_technical_person(text, 38, 45, 0.6, &tokens));
        let h = text.find("a3f9c12").unwrap();
        assert!(is_technical_person(text, h, h + 7, 0.6, &tokens));
    }

    #[test]
    fn confident_spans_and_bad_offsets_are_kept() {
        let text = "Recent commits: a3f9c12";
        let s = text.find("a3f9c12").unwrap();
        assert!(!is_technical_person(text, s, s + 7, CONFIDENT, &[]));
        assert!(!is_technical_person(text, s, s + 99, 0.6, &[]));
        assert!(!is_technical_person("Grüße", 3, 4, 0.6, &[])); // byte 3 is inside `ü`
    }

    #[test]
    fn only_model_person_spans_are_dropped() {
        let text = "branch feature/checkout-retry";
        let (s, e) = (text.find("feature").unwrap(), text.len());
        let spans = vec![
            Span::new(s, e, EntityKind::Person, 0.6, DetectorId::Ner),
            Span::new(s, e, EntityKind::Organization, 0.6, DetectorId::Ner),
            Span::new(s, e, EntityKind::Person, 0.6, DetectorId::Dictionary),
        ];
        let kept = drop_technical_persons(text, spans, &[]);
        assert_eq!(kept.len(), 2);
        assert!(
            kept.iter()
                .all(|k| k.kind != EntityKind::Person || k.source != DetectorId::Ner)
        );
    }
}
