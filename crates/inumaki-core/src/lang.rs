//! Cheap stopword-based language hint. Not a classifier; a hint for detectors.

/// Language hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    /// German.
    De,
    /// English.
    En,
    /// Not enough signal.
    Unknown,
}

const DE: &[&str] = &[
    "und", "der", "die", "das", "ich", "nicht", "mit", "ist", "sie", "für", "auf", "bitte",
    "meine", "mein", "habe", "eine", "einen", "zu", "dem", "den", "wir", "ihnen", "sehr",
];
const EN: &[&str] = &[
    "the", "and", "is", "to", "of", "my", "please", "have", "with", "for", "this", "that", "you",
    "are", "not", "about", "an", "we", "your", "can", "would",
];

/// Guess the language from stopword counts.
pub fn detect_language(text: &str) -> Language {
    let (mut de, mut en) = (0usize, 0usize);
    for raw in text.split_whitespace() {
        let w = raw
            .trim_matches(|c: char| !c.is_alphanumeric())
            .to_lowercase();
        if w.is_empty() {
            continue;
        }
        if DE.contains(&w.as_str()) {
            de += 1;
        }
        if EN.contains(&w.as_str()) {
            en += 1;
        }
    }
    match de.cmp(&en) {
        std::cmp::Ordering::Greater => Language::De,
        std::cmp::Ordering::Less => Language::En,
        std::cmp::Ordering::Equal => Language::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn german() {
        assert_eq!(
            detect_language("Hallo, ich habe eine Frage zu meiner Rechnung und dem Vertrag."),
            Language::De
        );
    }
    #[test]
    fn english() {
        assert_eq!(
            detect_language("Hello, I have a question about the invoice and my contract."),
            Language::En
        );
    }
    #[test]
    fn unknown_when_empty() {
        assert_eq!(detect_language(""), Language::Unknown);
        assert_eq!(detect_language("K-928174"), Language::Unknown);
    }
}
