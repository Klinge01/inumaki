//! CSV/TSV (spec §5.2): one block per raw record; a sanitized record must
//! re-parse to the same field count, else that record is redone per field
//! and its reassembled form becomes a verification block.

use super::{Assembled, Doc, Redo, Shape};

/// Raw record slices (line terminator included), covering `text` exactly.
///
/// The csv crate ends a record at the first byte of its terminator, so a
/// record's start can point at the `\n` of a `\r\n` or at blank lines. Every
/// start after the first moves past such a run: the whole terminator, blank
/// lines included, stays at the end of the previous record.
pub fn split_records(text: &str, delimiter: u8) -> Vec<String> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .delimiter(delimiter)
        .from_reader(text.as_bytes());
    let mut starts: Vec<usize> = Vec::new();
    let mut rec = csv::ByteRecord::new();
    loop {
        let pos = rdr.position().byte() as usize;
        match rdr.read_byte_record(&mut rec) {
            Ok(true) => starts.push(pos.min(text.len())),
            _ => break,
        }
    }
    if starts.first() != Some(&0) {
        starts.insert(0, 0);
    }
    let bytes = text.as_bytes();
    let adjusted: Vec<usize> = starts
        .iter()
        .enumerate()
        .map(|(i, &s)| {
            if i == 0 {
                return s;
            }
            let bound = starts.get(i + 1).copied().unwrap_or(text.len());
            let mut s = s;
            while s < bound && matches!(bytes[s], b'\r' | b'\n') {
                s += 1;
            }
            s
        })
        .collect();
    let mut out = Vec::with_capacity(adjusted.len());
    for (i, &s) in adjusted.iter().enumerate() {
        let e = adjusted.get(i + 1).copied().unwrap_or(text.len());
        if s < e {
            out.push(text[s..e].to_string());
        }
    }
    out
}

/// The leading and trailing runs of `\r` and `\n` of a record slice.
fn runs(record: &str) -> (&str, &str) {
    let body = record.trim_matches(['\r', '\n']);
    if body.is_empty() {
        return (record, "");
    }
    let start = record.len() - record.trim_start_matches(['\r', '\n']).len();
    let end = record.trim_end_matches(['\r', '\n']).len();
    (&record[..start], &record[end..])
}

fn fields(record: &str, delimiter: u8) -> Option<Vec<String>> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .delimiter(delimiter)
        .from_reader(record.as_bytes());
    let mut recs = rdr.records();
    let first = recs.next()?.ok()?;
    if recs.next().is_some() {
        return None;
    }
    Some(first.iter().map(str::to_owned).collect())
}

pub(super) fn doc(text: &str, delimiter: u8) -> Doc {
    Doc {
        blocks: split_records(text, delimiter),
        shape: Shape::Records { delimiter },
    }
}

/// Per-field shape: for each record, either `Whole(i)` (block index of a
/// sanitized raw record kept as is) or the fields of a record whose shape
/// changed, with its own line breaks kept verbatim.
#[derive(Clone)]
pub struct FieldShape {
    delimiter: u8,
    parts: Vec<Part>,
    /// The file as it was, for a text redo when a record cannot be written.
    source: String,
}

#[derive(Clone)]
enum Part {
    Whole(usize),
    Fields {
        start: usize,
        len: usize,
        leading: String,
        terminator: String,
    },
}

pub(super) fn source(s: &FieldShape) -> String {
    s.source.clone()
}

pub(super) fn assemble_records(
    blocks: &[String],
    out: &[String],
    delimiter: u8,
) -> Result<Assembled, Redo> {
    let mut bad = Vec::new();
    for (i, (src, san)) in blocks.iter().zip(out).enumerate() {
        // Unchanged, or not parseable as one record: nothing to compare.
        if src == san {
            continue;
        }
        let Some(a) = fields(src, delimiter).map(|f| f.len()) else {
            continue;
        };
        let b = fields(san, delimiter).map(|f| f.len());
        if Some(a) != b || runs(src) != runs(san) {
            bad.push(i);
        }
    }
    if bad.is_empty() {
        return Ok(Assembled {
            text: out.concat(),
            verify: Vec::new(),
        });
    }
    // Redo: good records keep their sanitized text as a block (it is
    // re-sanitized, which is idempotent on tokens); bad ones split into fields.
    let mut new_blocks = Vec::new();
    let mut parts = Vec::new();
    for (i, src) in blocks.iter().enumerate() {
        let fs = bad.contains(&i).then(|| fields(src, delimiter)).flatten();
        match fs {
            Some(fs) => {
                let (leading, terminator) = runs(src);
                parts.push(Part::Fields {
                    start: new_blocks.len(),
                    len: fs.len(),
                    leading: leading.to_string(),
                    terminator: terminator.to_string(),
                });
                new_blocks.extend(fs);
            }
            None => {
                parts.push(Part::Whole(new_blocks.len()));
                new_blocks.push(out[i].clone());
            }
        }
    }
    Err(Redo::Records(Doc {
        blocks: new_blocks,
        shape: Shape::Fields(FieldShape {
            delimiter,
            parts,
            source: blocks.concat(),
        }),
    }))
}

/// `None` when a record cannot be written: the caller redoes the file as text.
pub(super) fn assemble_fields(s: &FieldShape, out: &[String]) -> Option<Assembled> {
    let mut text = String::new();
    let mut verify = Vec::new();
    for p in &s.parts {
        match p {
            Part::Whole(i) => text.push_str(&out[*i]),
            Part::Fields {
                start,
                len,
                leading,
                terminator,
            } => {
                let mut w = csv::WriterBuilder::new()
                    .delimiter(s.delimiter)
                    .terminator(csv::Terminator::Any(b'\n'))
                    .from_writer(Vec::new());
                w.write_record(&out[*start..*start + *len]).ok()?;
                let rec = String::from_utf8(w.into_inner().ok()?).ok()?;
                let rec = rec.trim_end_matches('\n');
                verify.push(rec.to_string());
                text.push_str(leading);
                text.push_str(rec);
                text.push_str(terminator);
            }
        }
    }
    Some(Assembled { text, verify })
}
