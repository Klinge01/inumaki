//! Where the caller got a text (harness-static precision, rulings L98,
//! L103, L3-14).
//!
//! The engine cannot tell from a text alone whether it is harness text (a
//! system prompt, model instructions) or text a user or a tool wrote. The
//! caller can: the proxy knows a leaf's role. A caller that knows a text is
//! harness-static says so, and a caller that passes a file or directory name
//! says that (ruling S3). Every other text, and every entry point without an
//! origin parameter, is [`TextOrigin::Free`].

/// Where a text came from. Fail-closed default: [`TextOrigin::Free`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextOrigin {
    /// A user message, a tool result, a mail, a file, or any text of unknown
    /// origin. The default.
    #[default]
    Free,
    /// Text an agent harness sends with every request, in a position the
    /// caller knows: the system prompt, `instructions`, or a `developer`
    /// message. In the sanitizer, a lowercase surname-marked vocabulary word
    /// standing alone is then technical without a code cue (ruling L98).
    /// In the verifier, a `PERSON` hit that is exactly a listed product name
    /// (`Claude`) is then not a failure (ruling L103).
    HarnessStatic,
    /// A file or directory name stem the caller passes as such: the folder
    /// mirror's `sanitize_names`, both scanned spellings and phase 2. Judged
    /// as [`TextOrigin::Free`] except that every token is a file position
    /// (ruling S3): a document word with a rare Census surname (`mail`,
    /// `foto`) counts as a document word there.
    FileName,
}

impl TextOrigin {
    /// The CLI and report label: `free`, `harness-static`, or `file-name`.
    pub fn label(self) -> &'static str {
        match self {
            TextOrigin::Free => "free",
            TextOrigin::HarnessStatic => "harness-static",
            TextOrigin::FileName => "file-name",
        }
    }

    /// The origin a [`TextOrigin::label`] names.
    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "free" => Some(TextOrigin::Free),
            "harness-static" => Some(TextOrigin::HarnessStatic),
            "file-name" => Some(TextOrigin::FileName),
            _ => None,
        }
    }
}
