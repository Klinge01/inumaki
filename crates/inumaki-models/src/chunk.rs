//! Splitting long text into model-sized chunks that overlap.

/// A piece of a longer text.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Chunk<'a> {
    /// Byte offset of `text` inside the full text.
    pub offset: usize,
    /// The chunk text.
    pub text: &'a str,
}

impl std::fmt::Debug for Chunk<'_> {
    /// Hand-written: `text` is input and must never reach a log or panic message.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chunk")
            .field("offset", &self.offset)
            .field("len", &self.text.len())
            .finish()
    }
}

fn floor_boundary(text: &str, mut i: usize) -> usize {
    i = i.min(text.len());
    while !text.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Best cut position in `text[start..hard_end]`: just after the last sentence
/// end (`.`, `!`, `?` followed by whitespace, or a newline) in the second half
/// of the window, else just after the last whitespace there, else `hard_end`.
fn cut_point(text: &str, start: usize, hard_end: usize) -> usize {
    let window = &text[start..hard_end];
    let half = window.len() / 2;
    let mut sentence = None;
    let mut space = None;
    let mut prev: Option<char> = None;
    for (i, c) in window.char_indices() {
        let after = i + c.len_utf8();
        if i >= half {
            if c == '\n' || (c.is_whitespace() && matches!(prev, Some('.' | '!' | '?'))) {
                sentence = Some(after);
            }
            if c.is_whitespace() {
                space = Some(after);
            }
        }
        prev = Some(c);
    }
    start + sentence.or(space).unwrap_or(window.len())
}

/// Split `text` into chunks of at most `max_bytes` bytes. Cuts prefer sentence
/// ends, then whitespace, then any char boundary. Each chunk after the first
/// starts up to `overlap_bytes` before the previous cut, at a whitespace
/// boundary where one exists, so an entity crossing a cut appears whole in at
/// least one chunk when it is shorter than the overlap.
pub fn chunks(text: &str, max_bytes: usize, overlap_bytes: usize) -> Vec<Chunk<'_>> {
    let max_bytes = max_bytes.max(8);
    let overlap = overlap_bytes.min(max_bytes / 2);
    let mut out = Vec::new();
    let mut start = 0usize;
    loop {
        let hard_end = floor_boundary(text, start + max_bytes);
        if hard_end >= text.len() {
            out.push(Chunk {
                offset: start,
                text: &text[start..],
            });
            return out;
        }
        let mut cut = cut_point(text, start, hard_end);
        if cut <= start {
            cut = hard_end.max(start + text[start..].chars().next().map_or(1, char::len_utf8));
        }
        out.push(Chunk {
            offset: start,
            text: &text[start..cut],
        });
        // Next start: the first whitespace boundary at or after cut - overlap.
        let from = floor_boundary(text, cut.saturating_sub(overlap)).max(start + 1);
        let from = floor_boundary(text, from).max(start + 1);
        // Reachable, not dead code: `from` above is the result of two `floor_boundary` calls
        // each followed by `.max(start + 1)`, and `.max` can push a valid boundary forward to
        // `start + 1`, which is itself not a boundary whenever the character at `start` is
        // multi-byte (e.g. a chunk beginning on 'Ü'). In that case there is no valid overlap
        // start close to `cut`, so the next chunk starts at `cut` with no overlap at all,
        // rather than panicking by slicing on a non-boundary.
        let from = if text.is_char_boundary(from) {
            from
        } else {
            cut
        };
        let next = text[from..cut]
            .char_indices()
            .find(|(_, c)| c.is_whitespace())
            .map(|(i, c)| from + i + c.len_utf8())
            .filter(|&n| n < cut)
            .unwrap_or(from);
        start = if next > start { next } else { cut };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn covers_all(text: &str, cs: &[Chunk<'_>]) {
        let mut reach = 0;
        for c in cs {
            assert!(c.offset <= reach, "gap before {}", c.offset);
            assert_eq!(&text[c.offset..c.offset + c.text.len()], c.text);
            reach = reach.max(c.offset + c.text.len());
        }
        assert_eq!(reach, text.len());
    }

    #[test]
    fn short_text_is_one_chunk() {
        let cs = chunks("Hallo Welt.", 100, 20);
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0].offset, 0);
    }

    #[test]
    fn cuts_after_sentence_ends_and_overlaps() {
        let text = "Erster Satz hier. Zweiter Satz folgt. Dritter Satz kommt. Vierter Satz endet.";
        let cs = chunks(text, 40, 15);
        assert!(cs.len() >= 2);
        covers_all(text, &cs);
        for w in cs.windows(2) {
            let prev_end = w[0].offset + w[0].text.len();
            assert!(w[1].offset < prev_end, "chunks must overlap");
            assert!(w[1].offset > w[0].offset, "chunks must advance");
        }
        assert!(
            cs[0].text.ends_with(". ") || cs[0].text.ends_with('.'),
            "{:?}",
            cs[0].text
        );
    }

    #[test]
    fn multibyte_text_never_splits_a_char() {
        let text = "Grüße aus Köln, Jürgen Müller wohnt in der Straße. ".repeat(40);
        for max in [17, 33, 64, 101, 256] {
            let cs = chunks(&text, max, max / 4);
            covers_all(&text, &cs);
            for c in &cs {
                assert!(text.is_char_boundary(c.offset));
                assert!(text.is_char_boundary(c.offset + c.text.len()));
                assert!(c.text.len() <= max);
            }
        }
    }

    #[test]
    fn text_without_spaces_still_advances() {
        let text = "x".repeat(1000);
        let cs = chunks(&text, 100, 20);
        covers_all(&text, &cs);
        assert!(cs.len() >= 10);
    }
}
