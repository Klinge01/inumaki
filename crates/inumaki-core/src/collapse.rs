//! Whitespace-collapsed view of a text, with a map back to original offsets.
//!
//! The dictionary detector and the verifier's leak check search this view
//! so that any run of whitespace in the text (spaces, tabs, newlines,
//! no-break spaces) matches a single space in a pattern.

use zeroize::Zeroizing;

/// A text with every whitespace run replaced by one `' '`.
///
/// When the text has no whitespace other than single spaces, the view
/// borrows it and no map is built. Otherwise the collapsed copy is held in
/// `Zeroizing` and wiped on drop.
pub(crate) struct Collapsed<'a> {
    original: &'a str,
    owned: Option<Zeroizing<String>>,
    /// `map[i]` is the original byte offset of collapsed byte `i`;
    /// `map[len]` is the original length.
    map: Vec<usize>,
}

/// Collapse internal whitespace runs of a pattern to single spaces and trim.
pub(crate) fn collapse_pattern(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn needs_collapse(text: &str) -> bool {
    let mut prev_ws = false;
    for c in text.chars() {
        let ws = c.is_whitespace();
        if ws && (c != ' ' || prev_ws) {
            return true;
        }
        prev_ws = ws;
    }
    false
}

impl<'a> Collapsed<'a> {
    /// Build the view.
    pub(crate) fn new(text: &'a str) -> Self {
        if !needs_collapse(text) {
            return Collapsed {
                original: text,
                owned: None,
                map: Vec::new(),
            };
        }
        let mut out = String::with_capacity(text.len());
        let mut map = Vec::with_capacity(text.len() + 1);
        let mut chars = text.char_indices().peekable();
        while let Some((i, c)) = chars.next() {
            if c.is_whitespace() {
                while chars.next_if(|(_, c2)| c2.is_whitespace()).is_some() {}
                out.push(' ');
                map.push(i);
            } else {
                out.push(c);
                map.extend(i..i + c.len_utf8());
            }
        }
        map.push(text.len());
        Collapsed {
            original: text,
            owned: Some(Zeroizing::new(out)),
            map,
        }
    }

    /// The collapsed text.
    pub(crate) fn text(&self) -> &str {
        self.owned.as_deref().map_or(self.original, String::as_str)
    }

    /// Original byte offset for a collapsed byte offset (`0..=text().len()`).
    /// A start or end offset on a char boundary of the view maps to a char
    /// boundary of the original.
    pub(crate) fn to_original(&self, offset: usize) -> usize {
        if self.owned.is_none() {
            offset
        } else {
            self.map[offset]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrows_when_nothing_to_collapse() {
        let c = Collapsed::new("Sarah Leitner kam");
        assert!(c.owned.is_none());
        assert_eq!(c.text(), "Sarah Leitner kam");
        assert_eq!(c.to_original(6), 6);
    }

    #[test]
    fn maps_collapsed_offsets_back() {
        let text = "a  Sarah\n\t Leitnerß x";
        let c = Collapsed::new(text);
        assert_eq!(c.text(), "a Sarah Leitnerß x");
        let s = c.text().find("Sarah").unwrap();
        let e = s + "Sarah Leitnerß".len();
        let (os, oe) = (c.to_original(s), c.to_original(e));
        assert_eq!(&text[os..oe], "Sarah\n\t Leitnerß");
        assert_eq!(c.to_original(c.text().len()), text.len());
    }

    #[test]
    fn pattern_collapse_trims_and_joins() {
        assert_eq!(collapse_pattern("  Max \t Gruber\n"), "Max Gruber");
    }
}
