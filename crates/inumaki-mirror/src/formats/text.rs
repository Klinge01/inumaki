//! Text: contiguous chunks of at most 4 KiB, cut after a blank line, else at
//! a line end, else at whitespace, else at a character boundary.

use super::{Doc, Shape};

const MAX: usize = 4096;

pub(super) fn chunks(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        if rest.len() <= MAX {
            out.push(rest.to_string());
            break;
        }
        let window = &rest[..floor(rest, MAX)];
        let cut = window
            .rfind("\n\n")
            .map(|i| i + 2)
            .or_else(|| window.rfind('\n').map(|i| i + 1))
            .or_else(|| window.rfind(char::is_whitespace).map(|i| i + 1))
            .filter(|&i| i > 0)
            .unwrap_or(window.len());
        let cut = floor(rest, cut);
        out.push(rest[..cut].to_string());
        rest = &rest[cut..];
    }
    out
}

/// The largest char boundary `<= i`, but never 0: at least the first
/// character, so every chunk makes progress.
fn floor(s: &str, mut i: usize) -> usize {
    i = i.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    if i == 0 {
        s.char_indices().nth(1).map_or(s.len(), |(j, _)| j)
    } else {
        i
    }
}

pub(super) fn doc(text: &str) -> Doc {
    Doc {
        blocks: chunks(text),
        shape: Shape::Concat,
    }
}
