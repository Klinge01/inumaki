//! A harness's `PostToolUse` payload (docs/harness-adapters.md §5, hook shapes).

use std::collections::HashSet;
use std::path::Path;

use inumaki_client::{HookHarness, HookTool};
use serde_json::Value;

use crate::{BlockClass, Harness};

/// The Claude Code built-in tools the hook matcher lists. Equal to
/// `HOOK_TOOLS` in `inumaki-adapters/src/harness/claude_code.rs` (pinned by
/// `tests/hook.rs`, which reads that file's text: the adapter crate is not
/// a dependency of the hook). MCP tools (`mcp__…`) are matched separately.
pub const CLAUDE_TOOLS: &[&str] = &[
    "Bash",
    "PowerShell",
    "Read",
    "Grep",
    "Glob",
    "Edit",
    "WebFetch",
    "ReadMcpResourceTool",
];

/// Codex shell tool names. In 0.158.0 every shell tool (`exec_command`,
/// `write_stdin`) reaches hooks as `Bash` (docs/harness-adapters.md §7
/// deviation 10; the adapter's matcher is `^Bash$`). The older names are
/// kept so an older Codex still maps its shell output to `bash`.
pub const CODEX_SHELL_TOOLS: &[&str] = &["Bash", "shell", "local_shell", "exec_command"];

/// One tool call. `Debug` prints the tool class and counts only: the tool
/// name of an MCP tool holds a server name, and the rest is user data.
pub struct ToolCall {
    /// Contract harness.
    pub harness: HookHarness,
    /// Tool class.
    pub tool: HookTool,
    /// The harness's tool name (block templates are keyed by it).
    pub name: String,
    /// Absolute working directory.
    pub cwd: String,
    /// Referenced paths (absolute, or relative to `cwd`; the daemon resolves them).
    pub paths: Vec<String>,
    /// The tool's output in its own shape.
    pub response: Value,
    /// The output carries base64 data (a Claude Code `Read` of an image,
    /// PDF, or parts, or a `Bash` image): it cannot be sanitized in place,
    /// so any `replace` answer becomes a block (docs/harness-adapters.md §5).
    pub binary: bool,
}

impl std::fmt::Debug for ToolCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolCall")
            .field("harness", &self.harness)
            .field("tool", &self.tool)
            .field("paths", &self.paths.len())
            .field("binary", &self.binary)
            .finish_non_exhaustive()
    }
}

/// Claude Code tool names to classes (docs/harness-adapters.md §5, the
/// `HOOK_TOOLS` table). A tool outside the list is `Other`.
pub fn claude_tool(name: &str) -> HookTool {
    match name {
        "Bash" | "PowerShell" => HookTool::Bash,
        "Read" => HookTool::Read,
        "Grep" => HookTool::Grep,
        "Glob" => HookTool::Glob,
        "Edit" => HookTool::Edit,
        "WebFetch" => HookTool::WebFetch,
        "ReadMcpResourceTool" => HookTool::Mcp,
        n if n.starts_with("mcp__") => HookTool::Mcp,
        _ => HookTool::Other,
    }
}

/// Codex tool names to classes.
pub fn codex_tool(name: &str) -> HookTool {
    if CODEX_SHELL_TOOLS.contains(&name) {
        HookTool::Bash
    } else {
        HookTool::Other
    }
}

/// One shell word and whether its first character was quoted with `'…'`
/// or escaped (then a leading `$HOME` is literal, as in the shell).
struct Word {
    text: String,
    literal_start: bool,
}

/// Words under construction.
#[derive(Default)]
struct Words {
    done: Vec<Word>,
    cur: String,
    started: bool,
    literal_start: bool,
}

impl Words {
    /// A word starts (at a quote or a character); its first character's
    /// quoting decides `literal_start`.
    fn open(&mut self, literal: bool) {
        if !self.started {
            self.started = true;
            self.literal_start = literal;
        }
    }

    fn add(&mut self, c: char, literal: bool) {
        self.open(literal);
        self.cur.push(c);
    }

    fn end(&mut self) {
        if self.started {
            let text = std::mem::take(&mut self.cur);
            self.done.push(Word {
                text,
                literal_start: self.literal_start,
            });
        }
        self.started = false;
    }
}

/// Split a shell command into words, honouring `'…'`, `"…"`, and (when
/// `backslash_escapes`, i.e. not PowerShell) `\` escapes. Unquoted
/// whitespace and `; | & < > ( )` separate words.
fn shell_words(cmd: &str, backslash_escapes: bool) -> Vec<Word> {
    #[derive(PartialEq)]
    enum Q {
        None,
        Single,
        Double,
    }
    let mut w = Words::default();
    let mut q = Q::None;
    let mut it = cmd.chars().peekable();
    while let Some(c) = it.next() {
        match q {
            Q::Single if c == '\'' => q = Q::None,
            Q::Single => w.add(c, true),
            Q::Double => match c {
                '"' => q = Q::None,
                '\\' if backslash_escapes && matches!(it.peek(), Some('"' | '\\' | '$' | '`')) => {
                    let n = it.next().unwrap_or('\\');
                    w.add(n, true);
                }
                _ => w.add(c, false),
            },
            Q::None => match c {
                '\'' => {
                    q = Q::Single;
                    w.open(true);
                }
                '"' => {
                    q = Q::Double;
                    w.open(false);
                }
                '\\' if backslash_escapes => {
                    if let Some(n) = it.next() {
                        w.add(n, true);
                    }
                }
                c if c.is_whitespace() || matches!(c, ';' | '|' | '&' | '<' | '>' | '(' | ')') => {
                    w.end()
                }
                _ => w.add(c, false),
            },
        }
    }
    w.end();
    w.done
}

/// A leading unquoted `$HOME` or `${HOME}` replaced by `home` (the hook
/// process's `HOME`, read once per payload); other variables stay literal.
fn expand_home(w: &str, home: Option<&str>) -> String {
    if let Some(home) = home {
        for var in ["${HOME}", "$HOME"] {
            if let Some(rest) = w.strip_prefix(var) {
                if rest.is_empty() || rest.starts_with('/') {
                    return format!("{home}{rest}");
                }
            }
        }
    }
    w.to_string()
}

fn looks_like_path(w: &str) -> bool {
    !w.is_empty()
        && (w.contains('/') || w.contains('\\') || w.starts_with('~') || w.starts_with('.'))
}

/// The path-shaped value of one word: the word itself, the value of
/// `--opt=value` or `-o=value`, or the attached value of `-f/path`.
fn path_of(w: &Word, home: Option<&str>) -> Option<String> {
    let text = w.text.as_str();
    let (value, literal) = if let Some(flag) = text.strip_prefix('-') {
        if let Some((_, v)) = flag.split_once('=') {
            (v, false)
        } else if !flag.starts_with('-') && flag.len() > 1 && flag.is_char_boundary(1) {
            (&flag[1..], false)
        } else {
            return None;
        }
    } else {
        (text, w.literal_start)
    };
    let v = if literal {
        value.to_string()
    } else {
        expand_home(value, home)
    };
    looks_like_path(&v).then_some(v)
}

/// Path-shaped words of a plain whitespace/separator split, quotes trimmed
/// (the pre-tokenizer rule). It needs no quote state, so an apostrophe in a
/// `#` comment or a heredoc body (`customer's`), which bash does not treat
/// as a quote, cannot hide a later path from it.
fn split_paths(cmd: &str) -> Vec<String> {
    cmd.split(|c: char| c.is_whitespace() || matches!(c, ';' | '|' | '&' | '<' | '>' | '(' | ')'))
        .map(|w| w.trim_matches(|c| c == '"' || c == '\''))
        .filter(|w| !w.starts_with('-') && looks_like_path(w))
        .map(str::to_string)
        .collect()
}

/// Paths in first-seen order without duplicates, in linear time (a command
/// can hold a very large number of words; a quadratic dedupe would outlast
/// the harness's hook timeout, which then uses the original output).
#[derive(Default)]
struct PathSet {
    list: Vec<String>,
    seen: HashSet<String>,
}

impl PathSet {
    fn extend(&mut self, more: impl IntoIterator<Item = String>) {
        for p in more {
            if self.seen.insert(p.clone()) {
                self.list.push(p);
            }
        }
    }
}

/// Add the path-shaped words of a shell command to `set`: the quote-aware
/// tokenizer's, then those of the plain split it missed. Extra fragments
/// only widen the daemon's path rule (dataset mode or a block), never narrow it.
fn add_path_words(set: &mut PathSet, cmd: &str, backslash_escapes: bool, home: Option<&str>) {
    set.extend(
        shell_words(cmd, backslash_escapes)
            .iter()
            .filter_map(|w| path_of(w, home)),
    );
    set.extend(split_paths(cmd));
}

/// The payload's `cwd` when it is absolute, else the hook process's own
/// working directory (the harness starts the hook in the session's
/// directory). The daemon refuses a relative `cwd`, and `/` would widen
/// nothing safely, so without either the hook blocks.
fn absolute_cwd(v: &Value) -> Option<String> {
    if let Some(c) = v.get("cwd").and_then(Value::as_str) {
        if Path::new(c).is_absolute() {
            return Some(c.to_string());
        }
    }
    let here = std::env::current_dir().ok().filter(|p| p.is_absolute())?;
    here.to_str().map(str::to_string)
}

fn is_binary(h: Harness, name: &str, response: &Value) -> bool {
    if h != Harness::ClaudeCode {
        return false;
    }
    match name {
        "Read" => matches!(
            response.get("type").and_then(Value::as_str),
            Some("image" | "pdf" | "parts")
        ),
        "Bash" | "PowerShell" => response.get("isImage").and_then(Value::as_bool) == Some(true),
        _ => false,
    }
}

/// The payload's `tool_name`, for choosing a block template when the rest
/// of the payload does not parse.
pub fn tool_name(v: &Value) -> Option<&str> {
    v.get("tool_name").and_then(Value::as_str)
}

/// Parse a decoded payload. `Err` when it lacks `tool_name` or
/// `tool_response` (`UnparsablePayload`) or no absolute working directory
/// is known (`Internal`).
pub fn parse(h: Harness, mut v: Value) -> Result<ToolCall, BlockClass> {
    let name = tool_name(&v)
        .ok_or(BlockClass::UnparsablePayload)?
        .to_string();
    let response = v
        .get_mut("tool_response")
        .map(Value::take)
        .ok_or(BlockClass::UnparsablePayload)?;
    let cwd = absolute_cwd(&v).ok_or(BlockClass::Internal)?;
    let input = v.get("tool_input").unwrap_or(&Value::Null);
    let (harness, tool) = match h {
        Harness::ClaudeCode => (HookHarness::ClaudeCode, claude_tool(&name)),
        Harness::Codex => (HookHarness::Codex, codex_tool(&name)),
    };
    let s = |k: &str| input.get(k).and_then(Value::as_str).map(str::to_string);
    let mut paths: Vec<String> = match tool {
        HookTool::Read | HookTool::Edit => s("file_path").into_iter().collect(),
        HookTool::Grep | HookTool::Glob => s("path").into_iter().collect(),
        HookTool::Bash => {
            let home = std::env::var("HOME").ok().filter(|h| !h.is_empty());
            let escapes = name != "PowerShell";
            let mut set = PathSet::default();
            match input.get("command") {
                Some(Value::String(c)) => add_path_words(&mut set, c, escapes, home.as_deref()),
                // An argv array: each element is one word, and may itself be a
                // shell command (`["bash", "-lc", "cat ~/x"]`).
                Some(Value::Array(a)) => {
                    for w in a.iter().filter_map(Value::as_str) {
                        let word = Word {
                            text: w.to_string(),
                            literal_start: false,
                        };
                        set.extend(path_of(&word, home.as_deref()));
                        add_path_words(&mut set, w, escapes, home.as_deref());
                    }
                }
                _ => {}
            }
            set.list
        }
        _ => Vec::new(),
    };
    // Review I8: a shell command runs in `cwd` (`cat notes.txt`), and a Grep
    // or Glob without a path searches it.
    if tool == HookTool::Bash
        || (matches!(tool, HookTool::Grep | HookTool::Glob) && paths.is_empty())
    {
        paths.push(cwd.clone());
    }
    let binary = is_binary(h, &name, &response);
    Ok(ToolCall {
        harness,
        tool,
        name,
        cwd,
        paths,
        response,
        binary,
    })
}

/// The value of the `\uXXXX` escape at `b[i..]`, if there is one.
fn escape_unit(b: &[u8], i: usize) -> Option<u16> {
    let e = b.get(i..i + 6)?;
    if e[0] != b'\\' || e[1] != b'u' || !e[2..].iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u16::from_str_radix(std::str::from_utf8(&e[2..]).ok()?, 16).ok()
}

/// `b` with every lone UTF-16 surrogate escape (a `\uD800`–`\uDBFF` not
/// followed by a `\uDC00`–`\uDFFF`, or a stray `\uDC00`–`\uDFFF`) replaced
/// by `�`; `None` when there is none. Claude Code is a JavaScript
/// program: a tool output cut inside a non-BMP character (an emoji at a
/// truncation limit) is serialized with a lone surrogate escape, which
/// `serde_json` refuses. Escape sequences are scanned pairwise, so an
/// escaped backslash (`\\ud83d`) stays text.
pub fn fix_lone_surrogates(b: &[u8]) -> Option<Vec<u8>> {
    let surrogate = |u: u16| (0xD800..=0xDFFF).contains(&u);
    let high = |u: u16| (0xD800..=0xDBFF).contains(&u);
    let low = |u: u16| (0xDC00..=0xDFFF).contains(&u);
    let mut out = Vec::with_capacity(b.len());
    let mut changed = false;
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        match escape_unit(b, i) {
            Some(u) if high(u) && escape_unit(b, i + 6).is_some_and(low) => {
                out.extend_from_slice(&b[i..i + 12]);
                i += 12;
            }
            Some(u) if surrogate(u) => {
                out.extend_from_slice(b"\\uFFFD");
                changed = true;
                i += 6;
            }
            Some(_) => {
                out.extend_from_slice(&b[i..i + 6]);
                i += 6;
            }
            None => {
                let end = (i + 2).min(b.len());
                out.extend_from_slice(&b[i..end]);
                i = end;
            }
        }
    }
    changed.then_some(out)
}

/// The tool name of a payload that does not decode (or was cut at
/// `MAX_STDIN`), found by scanning for the first `"tool_name": "<name>"`
/// (Claude Code writes it before `tool_input` and `tool_response`; an
/// occurrence inside a JSON string has escaped quotes and does not match).
/// Only a hooked Claude Code tool or an `mcp__` name is returned: it
/// chooses the block template and is never printed.
pub fn recover_tool_name(b: &[u8]) -> Option<String> {
    const KEY: &[u8] = b"\"tool_name\"";
    let mut i = b.windows(KEY.len()).position(|w| w == KEY)? + KEY.len();
    let skip_ws = |i: &mut usize| {
        while b.get(*i).is_some_and(|c| c.is_ascii_whitespace()) {
            *i += 1;
        }
    };
    skip_ws(&mut i);
    (b.get(i) == Some(&b':')).then_some(())?;
    i += 1;
    skip_ws(&mut i);
    (b.get(i) == Some(&b'"')).then_some(())?;
    i += 1;
    let start = i;
    while b
        .get(i)
        .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
    {
        i += 1;
    }
    (b.get(i) == Some(&b'"') && i > start).then_some(())?;
    let name = std::str::from_utf8(&b[start..i]).ok()?;
    (CLAUDE_TOOLS.contains(&name) || name.starts_with("mcp__")).then(|| name.to_string())
}
