//! Formats (M5 spec §5.2, §5.3): an allow-list, decoding to UTF-8, blocks
//! that reassemble exactly, and verification blocks for values sanitized
//! out of their context.

mod delimited;
mod json;
mod text;

pub use delimited::split_records;

/// Extensions kept verbatim in names (spec §4.3 rule 1).
pub const KEPT_EXTENSIONS: &[&str] = &[
    "txt", "text", "md", "markdown", "log", "yaml", "yml", "csv", "tsv", "json", "jsonl", "ndjson",
    "eml", "html", "htm", "pdf", "docx", "xlsx", "pptx", "odt", "png", "jpg", "jpeg", "gif", "zip",
];

/// A supported format, or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Plain text family and extensionless files.
    Text,
    /// CSV (`,`) or TSV (`\t`).
    Delimited(u8),
    /// One JSON document.
    Json,
    /// One JSON document per line.
    JsonLines,
    /// An e-mail message.
    Eml,
    /// HTML.
    Html,
    /// Placeholder.
    Unsupported,
}

/// The last `.`-suffix as written (case kept), if it is on the kept list.
pub fn kept_extension(name: &str) -> Option<&str> {
    let (stem, ext) = name.rsplit_once('.')?;
    if stem.is_empty() {
        return None;
    }
    KEPT_EXTENSIONS
        .iter()
        .any(|k| k.eq_ignore_ascii_case(ext))
        .then_some(ext)
}

/// True when any block exceeds [`MirrorConfig::MAX_BLOCK_BYTES`](crate::MirrorConfig::MAX_BLOCK_BYTES):
/// the pipeline checks a doc's `blocks()` and an assembly's `verify` with
/// this before sending them and withholds the whole file when it holds.
pub fn oversized(blocks: &[String]) -> bool {
    blocks
        .iter()
        .any(|b| b.len() > crate::MirrorConfig::MAX_BLOCK_BYTES)
}

/// Classify by name (spec §5.2).
pub fn classify(name: &[u8]) -> Format {
    let Ok(name) = std::str::from_utf8(name) else {
        return Format::Unsupported;
    };
    let Some((stem, ext)) = name.rsplit_once('.') else {
        return Format::Text;
    };
    if stem.is_empty() {
        return Format::Unsupported;
    }
    match ext.to_ascii_lowercase().as_str() {
        "txt" | "text" | "md" | "markdown" | "log" | "yaml" | "yml" => Format::Text,
        "csv" => Format::Delimited(b','),
        "tsv" => Format::Delimited(b'\t'),
        "json" => Format::Json,
        "jsonl" | "ndjson" => Format::JsonLines,
        "eml" => Format::Eml,
        "html" | "htm" => Format::Html,
        _ => Format::Unsupported,
    }
}

/// Suffix appended to the mirror name (`x.eml` → `x.eml.md`).
pub fn mirror_suffix(f: Format) -> Option<&'static str> {
    matches!(f, Format::Eml | Format::Html).then_some(".md")
}

/// Why a file is not text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A NUL byte in the first 8 KiB, or unsupported.
    Binary,
}

/// UTF-8 (BOM stripped), UTF-16 with a BOM, else Windows-1252 unless a NUL
/// byte in the first 8 KiB makes it binary.
pub fn decode(bytes: &[u8]) -> Result<String, Refusal> {
    if let Some(rest) = bytes.strip_prefix(b"\xEF\xBB\xBF") {
        if rest[..rest.len().min(8192)].contains(&0) {
            return Err(Refusal::Binary);
        }
        return std::str::from_utf8(rest)
            .map(str::to_owned)
            .or_else(|_| cp1252(rest));
    }
    if bytes.starts_with(b"\xFF\xFE") || bytes.starts_with(b"\xFE\xFF") {
        let enc = if bytes[0] == 0xFF {
            encoding_rs::UTF_16LE
        } else {
            encoding_rs::UTF_16BE
        };
        let (s, _, bad) = enc.decode(bytes);
        return if bad {
            Err(Refusal::Binary)
        } else {
            Ok(s.into_owned())
        };
    }
    if bytes[..bytes.len().min(8192)].contains(&0) {
        return Err(Refusal::Binary);
    }
    match std::str::from_utf8(bytes) {
        Ok(s) => Ok(s.to_owned()),
        Err(_) => cp1252(bytes),
    }
}

fn cp1252(bytes: &[u8]) -> Result<String, Refusal> {
    if bytes[..bytes.len().min(8192)].contains(&0) {
        return Err(Refusal::Binary);
    }
    Ok(encoding_rs::WINDOWS_1252.decode(bytes).0.into_owned())
}

/// Decode, render (eml, html), and split.
pub fn prepare(format: Format, bytes: &[u8]) -> Result<Doc, Refusal> {
    match format {
        Format::Unsupported => Err(Refusal::Binary),
        Format::Eml => match inumaki_mail::render::parse_message(bytes) {
            Some(p) => Ok(text::doc(&inumaki_mail::render::render_markdown(&p))),
            None => Ok(text::doc(&decode(bytes)?)),
        },
        Format::Html => Ok(text::doc(&inumaki_mail::render::html_to_text(&decode(
            bytes,
        )?))),
        Format::Text => Ok(text::doc(&decode(bytes)?)),
        Format::Delimited(d) => Ok(delimited::doc(&decode(bytes)?, d)),
        Format::Json => {
            let s = decode(bytes)?;
            Ok(json::doc(&s).unwrap_or_else(|| text::doc(&s)))
        }
        Format::JsonLines => {
            let s = decode(bytes)?;
            Ok(json::lines_doc(&s).unwrap_or_else(|| text::doc(&s)))
        }
    }
}

/// Blocks plus what is needed to put them back.
#[derive(Clone)]
pub struct Doc {
    blocks: Vec<String>,
    shape: Shape,
}

#[derive(Clone)]
enum Shape {
    /// Blocks are contiguous slices; output is their concatenation.
    Concat,
    /// One block per raw CSV record.
    Records { delimiter: u8 },
    /// Per-field blocks of the records at the given positions.
    Fields(delimited::FieldShape),
    /// JSON (one document or lines).
    Json(json::JsonShape),
}

/// Reassembled output and the blocks to verify (spec §5.2 object check).
pub struct Assembled {
    /// The mirror file's text.
    pub text: String,
    /// Assembled context (objects, per-field records) to re-sanitize.
    pub verify: Vec<String>,
}

/// The file must be sanitized again in another shape.
pub enum Redo {
    /// As plain text (alias key merge).
    AsText(Doc),
    /// Some records per field.
    Records(Doc),
}

/// Names the variant only: a doc's blocks are file content.
impl std::fmt::Debug for Redo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Redo::AsText(_) => "Redo::AsText",
            Redo::Records(_) => "Redo::Records",
        })
    }
}

/// Counts only: a doc's blocks are file content.
impl std::fmt::Debug for Doc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Doc({} blocks)", self.blocks.len())
    }
}

impl Doc {
    /// The blocks to sanitize.
    pub fn blocks(&self) -> &[String] {
        &self.blocks
    }

    /// Put sanitized blocks back (same length and order as `blocks()`).
    pub fn assemble(&self, out: &[String]) -> Result<Assembled, Redo> {
        assert_eq!(out.len(), self.blocks.len(), "one result per block");
        match &self.shape {
            Shape::Concat => Ok(Assembled {
                text: out.concat(),
                verify: Vec::new(),
            }),
            Shape::Records { delimiter } => {
                delimited::assemble_records(&self.blocks, out, *delimiter)
            }
            Shape::Fields(s) => delimited::assemble_fields(s, out)
                .ok_or_else(|| Redo::AsText(text::doc(&delimited::source(s)))),
            Shape::Json(s) => {
                json::assemble(s, out).ok_or_else(|| Redo::AsText(text::doc(&json::source(s))))
            }
        }
    }
}
