//! Deterministic pattern detector. Every rule is a compile-time constant.

use std::sync::LazyLock;

use regex::{Regex, RegexSet};

use super::validate;
use super::{DetectCtx, Detector};
use crate::span::{DetectorId, EntityKind, Span};

#[derive(Clone, Copy)]
enum Check {
    None,
    Luhn,
    Iban,
    Phone,
    Ipv4,
    Ipv6,
    AtSvnr,
    DeSteuerId,
    ChAhv,
    Url,
    Address,
    BareStreet,
}

struct Rule {
    pattern: &'static str,
    kind: EntityKind,
    check: Check,
    confidence: f32,
    source: DetectorId,
    /// Capture group holding the entity, 0 for the whole match.
    group: usize,
}

const V: DetectorId = DetectorId::RegexValidated;
const S: DetectorId = DetectorId::RegexSyntax;

fn rules() -> Vec<Rule> {
    use EntityKind as K;
    vec![
        Rule {
            // Unicode letters/marks in local part and domain (IDN, umlauts),
            // so "jörg.huber@…" is never cut to "…rg.huber@…".
            pattern: r"[\p{L}\p{M}\p{N}._%+\-]+@[\p{L}\p{M}\p{N}.\-]+\.[\p{L}\p{M}]{2,}",
            kind: K::Email,
            check: Check::None,
            confidence: 0.95,
            source: V,
            group: 0,
        },
        Rule {
            pattern: r#"\b(?:https?://|www\.)[^\s<>"']+"#,
            kind: K::Url,
            check: Check::Url,
            confidence: 0.90,
            source: V,
            group: 0,
        },
        Rule {
            pattern: r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            kind: K::IpAddress,
            check: Check::Ipv4,
            confidence: 0.95,
            source: V,
            group: 0,
        },
        Rule {
            pattern: r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b",
            kind: K::IpAddress,
            check: Check::Ipv6,
            confidence: 0.95,
            source: V,
            group: 0,
        },
        Rule {
            // Only the start (country code + check digits); the extent is
            // decided by `iban_extent` from the country length table, so a
            // trailing `BIC …` or capitalized word never swallows the IBAN.
            pattern: r"[A-Za-z]{2}\d{2}",
            kind: K::Iban,
            check: Check::Iban,
            confidence: 0.99,
            source: V,
            group: 0,
        },
        Rule {
            // Whole digit runs; `card_spans` picks the card windows inside.
            // Groups are joined by a space, a hyphen, or a line break (LF or
            // CRLF, with optional trailing hyphen/blanks around it) because
            // mail clients wrap long numbers.
            pattern: r"\d+(?:(?:[ \t\-]*\r?\n[ \t]*|[ \-])\d+)*",
            kind: K::CreditCard,
            check: Check::Luhn,
            confidence: 0.99,
            source: V,
            group: 0,
        },
        Rule {
            pattern: r"\b\d{4}[ ]?\d{6}\b",
            kind: K::NationalId,
            check: Check::AtSvnr,
            confidence: 0.99,
            source: V,
            group: 0,
        },
        Rule {
            pattern: r"\b\d{11}\b",
            kind: K::NationalId,
            check: Check::DeSteuerId,
            confidence: 0.99,
            source: V,
            group: 0,
        },
        Rule {
            pattern: r"\b756\.?\d{4}\.?\d{4}\.?\d{2}\b",
            kind: K::NationalId,
            check: Check::ChAhv,
            confidence: 0.99,
            source: V,
            group: 0,
        },
        Rule {
            pattern: r"\bATU\d{8}\b",
            kind: K::TaxId,
            check: Check::None,
            confidence: 0.90,
            source: S,
            group: 0,
        },
        Rule {
            pattern: r"\bDE\d{9}\b",
            kind: K::TaxId,
            check: Check::None,
            confidence: 0.85,
            source: S,
            group: 0,
        },
        Rule {
            pattern: r"\bCHE-?\d{3}\.?\d{3}\.?\d{3}\b",
            kind: K::TaxId,
            check: Check::None,
            confidence: 0.90,
            source: S,
            group: 0,
        },
        Rule {
            pattern: r"\+\d{1,3}[\s./\-]?(?:\(0\)[\s./\-]?)?\d(?:[\s./\-]?\d){5,13}",
            kind: K::Phone,
            check: Check::Phone,
            confidence: 0.85,
            source: S,
            group: 0,
        },
        Rule {
            pattern: r"\b00\d{1,3}[\s./\-]?\d(?:[\s./\-]?\d){5,13}",
            kind: K::Phone,
            check: Check::Phone,
            confidence: 0.85,
            source: S,
            group: 0,
        },
        Rule {
            // National number with the area code in parentheses: (0664) 123 45 67
            pattern: r"\(0\d{1,4}\)[\s./\-]?\d(?:[\s./\-]?\d){3,10}\b",
            kind: K::Phone,
            check: Check::Phone,
            confidence: 0.85,
            source: S,
            group: 0,
        },
        Rule {
            // International number with the area code in parentheses: +43 (664) 123 45 67
            pattern: r"\+\d{1,3}[\s./\-]?\(\d{1,4}\)[\s./\-]?\d(?:[\s./\-]?\d){3,12}\b",
            kind: K::Phone,
            check: Check::Phone,
            confidence: 0.85,
            source: S,
            group: 0,
        },
        Rule {
            pattern: r"\b0\d{1,4}[\s./\-]?\d(?:[\s./\-]?\d){3,10}\b",
            kind: K::Phone,
            check: Check::Phone,
            confidence: 0.85,
            source: S,
            group: 0,
        },
        Rule {
            pattern: r"(?i)\b(?:geboren(?:\s+am)?|geburtsdatum|geb\.?|date of birth|dob|born(?:\s+on)?)\s*[:\-]?\s*(\d{1,2}[./\-]\d{1,2}[./\-]\d{2,4}|\d{4}-\d{2}-\d{2})",
            kind: K::DateOfBirth,
            check: Check::None,
            confidence: 0.90,
            source: S,
            group: 1,
        },
        Rule {
            pattern: r"\b\d{1,2}\.\d{1,2}\.\d{4}\b|\b\d{4}-\d{2}-\d{2}\b",
            kind: K::Date,
            check: Check::None,
            confidence: 0.85,
            source: S,
            group: 0,
        },
        Rule {
            pattern: r"\b(\d{4,5})\s+[A-ZÄÖÜ][\wäöüß\-]+",
            kind: K::PostalCode,
            check: Check::None,
            confidence: 0.85,
            source: S,
            group: 1,
        },
        Rule {
            pattern: ADDRESS_PATTERN,
            kind: K::StreetAddress,
            check: Check::Address,
            confidence: 0.85,
            source: S,
            group: 0,
        },
        Rule {
            pattern: BARE_STREET_PATTERN,
            kind: K::StreetAddress,
            check: Check::BareStreet,
            confidence: 0.60,
            source: S,
            group: 0,
        },
        Rule {
            pattern: r"\b[A-Z]{1,2}-\d{1,5}\s?[A-Z]{1,3}\b|\b[A-Z]{1,2}-[A-Z]{1,3}\s?\d{1,5}\b",
            kind: K::LicensePlate,
            check: Check::None,
            confidence: 0.85,
            source: S,
            group: 0,
        },
        Rule {
            pattern: r"\b[A-ZÄÖÜ]{1,3}-[A-Z]{1,2}[- ]?\d{1,4}[EH]?\b",
            kind: K::LicensePlate,
            check: Check::None,
            confidence: 0.85,
            source: S,
            group: 0,
        },
        Rule {
            pattern: r"\b(?:AG|AI|AR|BE|BL|BS|FR|GE|GL|GR|JU|LU|NE|NW|OW|SG|SH|SO|SZ|TG|TI|UR|VD|VS|ZG|ZH)[- ]\d{4,6}\b",
            kind: K::LicensePlate,
            check: Check::None,
            confidence: 0.85,
            source: S,
            group: 0,
        },
    ]
}

/// Street with a house number. Four shapes (plus the wrapped variant 2b), all followed by whitespace (a
/// line break allowed, as mail clients wrap there), an optional `Nr.`, and a
/// house number (`22`, `5a`, `12/3`, `12-14`):
/// 1. adjectival word ending in `er`/`e`/`es`/`en` plus a compound street (`Wiedner Hauptstraße`, `Obere Donaustraße`),
/// 2. any word of three or more letters plus a standalone suffix (`Lange Gasse`, `Mariahilfer Straße`); variant 2b is a capitalized `-er` word, one line break, and a capitalized standalone suffix (`Grazer\nStraße`, as a mail client wraps it),
/// 3. a compound of three or more letters plus a suffix (`Neubaugasse`, `Hauptstr.`),
/// 4. `Am`/`Im`/`Zum`/`Zur`/`Beim` plus a capitalized name (`Am Graben`, `Im Winkel`).
///
/// Shapes 1, 2 and 2b may be preceded by one capitalized word ending in `er`
/// (`Wiener Neustädter Straße 17`, `Wiener` plus shape 2). A lower-case word
/// is never a prefix; a capitalized sentence-initial article or possessive
/// that lands there is trimmed by `address_extent`.
///
/// Words inside a shape are joined by spaces or tabs only, never a line
/// break, so a signature line `Wagner\nWaldweg 5` does not swallow the name.
/// The one exception is shape 2b, where the second word is a bare suffix and the
/// first is an `-er` adjective.
/// A leading article, preposition, or noun captured by shapes 1–2
/// (`der Neubaugasse 22`, `Adresse Neubaugasse 22`) is trimmed by
/// `address_extent`; compound nouns that merely end in a suffix
/// (`Arbeitsplatz`, `Sackgasse`) are rejected there.
const ADDRESS_PATTERN: &str = r"(?:(?:[A-ZÄÖÜ][\p{L}\-]{2,}er[ \t]+)?[\p{L}][\p{L}\-]{2,}(?:er|e|es|en)[ \t]+[\p{L}][\p{L}\-]{2,}(?i:straße|strasse|str\.|gasse|weg|platz|allee|ring|ufer|damm|markt|zeile|promenade|steig)|(?:[A-ZÄÖÜ][\p{L}\-]{2,}er[ \t]+)?[\p{L}][\p{L}\-]{2,}[ \t]+(?i:straße|strasse|str\.|gasse|weg|platz|allee|ring|ufer|damm|markt|zeile|promenade|steig)|(?:[A-ZÄÖÜ][\p{L}\-]{2,}er[ \t]+)?[A-ZÄÖÜ][\p{L}\-]{2,}er[ \t]*\r?\n[ \t]*(?:Straße|Strasse|Str\.|Gasse|Weg|Platz|Allee|Ring|Ufer|Damm|Markt|Zeile|Promenade|Steig)|[\p{L}][\p{L}\-]{2,}(?i:straße|strasse|str\.|gasse|weg|platz|allee|ring|ufer|damm|markt|zeile|promenade|steig)|(?i:am|im|zum|zur|beim)[ \t]+[A-ZÄÖÜ][\p{L}\-]{2,})\s+(?:(?i:nr\.?)\s*)?\d{1,4}[a-zA-Z]?(?:\s?[/\-]\s?\d{1,4}[a-zA-Z]?){0,2}";

/// A capitalized compound street name without a house number (`Hauptstraße`).
/// Only suffixes that rarely form ordinary nouns; emitted at low confidence.
const BARE_STREET_PATTERN: &str =
    r"\b[A-ZÄÖÜ][\p{L}\-]{2,}(?i:straße|strasse|gasse|allee|promenade)\b";

/// Words that shapes 1–2 may capture in front of a street but that are not
/// part of it. Never list `am`, `im`, `zum`, `zur`, `beim`, `neue`, `alte`,
/// `obere`, `untere`, `lange`: they begin real street names.
const ADDRESS_LEAD_STOP: &[&str] = &[
    "der",
    "die",
    "das",
    "den",
    "dem",
    "des",
    "ein",
    "eine",
    "einen",
    "einem",
    "einer",
    "eines",
    "und",
    "oder",
    "aber",
    "unter",
    "hinter",
    "über",
    "ueber",
    "neben",
    "vor",
    "nach",
    "bei",
    "von",
    "vom",
    "aus",
    "mit",
    "seit",
    "durch",
    "für",
    "fuer",
    "gegenüber",
    "immer",
    "wieder",
    "meiner",
    "meine",
    "unser",
    "unsere",
    "unserer",
    "ihre",
    "ihrer",
    "seine",
    "seiner",
    "dieser",
    "diese",
    "jeder",
    "jede",
    "keine",
    "bitte",
    "danke",
    "the",
    "and",
    "our",
    "your",
    "their",
    "at",
    "in",
    "on",
    "to",
    "of",
    "for",
    "from",
    "with",
    "near",
    "opposite",
    "please",
    "thanks",
    "adresse",
    "address",
    "anschrift",
    "lieferadresse",
    "rechnungsadresse",
    "wohnhaft",
    "wohnort",
    "filiale",
    "büro",
    "buero",
    "office",
    "praxis",
    "ordination",
    "auf",
];

/// Compound nouns that end in a street suffix but are not streets.
const NOT_STREETS: &[&str] = &[
    "sackgasse",
    "arbeitsplatz",
    "parkplatz",
    "sitzplatz",
    "stellplatz",
    "vorplatz",
    "umweg",
    "ausweg",
    "irrweg",
    "heimweg",
    "rückweg",
    "rueckweg",
    "hinweg",
    "bundesstraße",
    "bundesstrasse",
    "einbahnstraße",
    "einbahnstrasse",
    "schnellstraße",
    "schnellstrasse",
    "autostraße",
    "autostrasse",
    "landesstraße",
    "landesstrasse",
    "nebenstraße",
    "nebenstrasse",
    "seitenstraße",
    "seitenstrasse",
    "querstraße",
    "querstrasse",
    "milchstraße",
    "milchstrasse",
    "datenautobahn",
    "ranking",
];

/// Prepositions that open shape 4 of `ADDRESS_PATTERN` (`am`, `im`, `zum`,
/// `zur`, `beim`); checked case-insensitively against the first word of a
/// shape-4 match to find the noun that follows.
const SHAPE4_PREPS: &[&str] = &["am", "im", "zum", "zur", "beim"];

/// Nouns that routinely follow a shape-4 preposition plus a number in
/// ordinary prose (`im Jahr 2020`, `am Schalter 5`, `Zum Beispiel 3`) rather
/// than naming a street; shape 4 cannot otherwise tell these apart from a
/// real address like `Am Hof 5` or `Im Werd 2`, since both are just a
/// preposition, a capitalized word, and a number.
///
/// `platz` is deliberately absent: `Am Platz` is a genuine street name in
/// several Austrian towns (e.g. Linz), so listing it would suppress a real
/// address. `stand` stays despite the same risk (`Am Stand` names real
/// lakeside streets) because the reported false positive (`am Stand 5`, a
/// trade-fair booth number) was judged the more common case in business
/// mail; the rest of this list was re-checked and none of `tisch`,
/// `schalter`, `raum`, `zimmer`, `stock`, `rang`, `gleis`, `bahnsteig` is a
/// known DACH street name.
const SHAPE4_NOT_STREETS: &[&str] = &[
    "jahr",
    "jahre",
    "beispiel",
    "raum",
    "zimmer",
    "stand",
    "schalter",
    "stock",
    "termin",
    "punkt",
    "kapitel",
    "seite",
    "abschnitt",
    "absatz",
    "artikel",
    "paragraph",
    "tag",
    "monat",
    "woche",
    "quartal",
    "semester",
    "minute",
    "stunde",
    "prozent",
    "rang",
    "level",
    "gate",
    "gleis",
    "bahnsteig",
    "tisch",
    "januar",
    "februar",
    "märz",
    "april",
    "mai",
    "juni",
    "juli",
    "august",
    "september",
    "oktober",
    "november",
    "dezember",
    "montag",
    "dienstag",
    "mittwoch",
    "donnerstag",
    "freitag",
    "samstag",
    "sonntag",
];

static ADDRESS_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(ADDRESS_PATTERN).unwrap());

static DATE_LIKE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\d{1,2}[./\-]\d{1,2}[./\-]\d{2,4}$").unwrap());

/// A town right after a postal code: one capitalized word (internal
/// hyphens allowed, `Wiener-Neudorf`), optionally a second one joined by
/// `an der` (`Bruck an der Mur`). `am`, `im` and `bei` do not join (ruling
/// L53): `Linz bei Gruber` names a person. Spaces and tabs only: never
/// across a line break. Group 1 is the town, group 2 its first word,
/// group 3 the joined word.
static TOWN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^[ \t]+(([A-ZÄÖÜ]\p{L}+(?:-\p{L}+)*)(?:[ \t]+an[ \t]+der[ \t]+([A-ZÄÖÜ]\p{L}+(?:-\p{L}+)*))?)",
    )
    .unwrap()
});

/// Country prefixes written in front of a DACH postal code (`A-1010`).
const POSTAL_COUNTRY_PREFIXES: &[&str] = &["A", "D", "CH", "AT", "DE", "FL", "LI"];

/// Street words a town word must not be (`2340 Gasse`): the standalone
/// suffixes of `ADDRESS_PATTERN`, and compounds on the suffixes that rarely
/// end a town name (`Hauptstraße`). The verifier's place filter reads it
/// too, as substrings (`str` covers `Hauptstr.`).
pub(crate) const TOWN_NOT_STREET: &[&str] = &[
    "straße",
    "strasse",
    "str",
    "gasse",
    "weg",
    "platz",
    "allee",
    "ring",
    "ufer",
    "damm",
    "markt",
    "zeile",
    "promenade",
    "steig",
];
const TOWN_NOT_STREET_COMPOUND: &[&str] = &["straße", "strasse", "gasse", "allee", "promenade"];

/// Capitalized nouns that follow a number in ordinary prose (`2340 Stück`,
/// `1500 Euro`, `2000 Mitarbeiter`): never a town.
const TOWN_NOT_QUANTITY: &[&str] = &[
    "stück",
    "stk",
    "euro",
    "eur",
    "chf",
    "usd",
    "dollar",
    "franken",
    "cent",
    "mal",
    "prozent",
    "kilometer",
    "meter",
    "kilo",
    "gramm",
    "liter",
    "minuten",
    "stunden",
    "tage",
    "wochen",
    "monate",
    "jahre",
    "mitarbeiter",
    "kunden",
    "personen",
    "leute",
    "einwohner",
    "exemplare",
    "seiten",
    "punkte",
    "teilnehmer",
    "artikel",
    "einheiten",
    "packungen",
];

struct Compiled {
    set: RegexSet,
    regexes: Vec<Regex>,
    rules: Vec<Rule>,
}

static COMPILED: LazyLock<Compiled> = LazyLock::new(|| {
    let rules = rules();
    let regexes: Vec<Regex> = rules
        .iter()
        .map(|r| Regex::new(r.pattern).expect("static pattern"))
        .collect();
    let set = RegexSet::new(rules.iter().map(|r| r.pattern)).expect("static set");
    Compiled {
        set,
        regexes,
        rules,
    }
});

/// Regex-based detector for structured identifiers (email, phone, IBAN,
/// cards, IPs, URLs, national/tax IDs, plates, dates, postal codes).
///
/// All state is static (compiled once per process); the type itself carries
/// no data and is cheap to construct and clone.
#[derive(Clone, Default)]
pub struct RegexDetector;

impl RegexDetector {
    /// Construct. Patterns are compiled once per process.
    pub fn new() -> Self {
        LazyLock::force(&COMPILED);
        RegexDetector
    }
}

fn passes(check: Check, matched: &str) -> bool {
    match check {
        Check::None | Check::Url => true,
        Check::Address | Check::BareStreet => true,
        Check::Luhn => {
            let d = validate::digits_only(matched);
            (13..=19).contains(&d.len())
                && matches!(d.as_bytes()[0], b'3'..=b'6')
                && validate::luhn(&d)
        }
        Check::Iban => validate::iban(&matched.replace(' ', "")),
        Check::Phone => {
            let n = validate::digits_only(matched).len();
            (7..=15).contains(&n) && !DATE_LIKE.is_match(matched.trim())
        }
        Check::Ipv4 => matched.parse::<std::net::Ipv4Addr>().is_ok(),
        Check::Ipv6 => matched.parse::<std::net::Ipv6Addr>().is_ok(),
        Check::AtSvnr => validate::at_svnr(&validate::digits_only(matched)),
        Check::DeSteuerId => validate::de_steuer_id(matched),
        Check::ChAhv => validate::ch_ahv(&validate::digits_only(matched)),
    }
}

fn is_iban_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// If a group separator starts at `i` and an IBAN character follows it,
/// the offset of that character. A separator is a single space, or, when
/// `allow_break`, one line break (LF or CRLF) with optional blanks around it
/// between two digits, as left by a mail client that wrapped the number.
/// Across a break only digits may follow, so a word on the next line is never
/// collected into the IBAN.
fn iban_group_gap(bytes: &[u8], i: usize, allow_break: bool) -> Option<usize> {
    let skip_blanks = |mut j: usize| {
        while matches!(bytes.get(j), Some(b' ' | b'\t')) {
            j += 1;
        }
        j
    };
    let mut j = skip_blanks(i);
    if bytes.get(j) == Some(&b'\r') {
        j += 1;
    }
    if bytes.get(j) == Some(&b'\n') {
        let next = skip_blanks(j + 1);
        return (allow_break
            && i > 0
            && bytes[i - 1].is_ascii_digit()
            && bytes.get(next).is_some_and(u8::is_ascii_digit))
        .then_some(next);
    }
    if bytes.get(i) == Some(&b' ') {
        let next = i + 1;
        return bytes
            .get(next)
            .copied()
            .is_some_and(is_iban_char)
            .then_some(next);
    }
    None
}

/// End of the IBAN starting at `start` (which points at the country code),
/// or `None` when no valid IBAN starts there.
///
/// Reads the country code, looks up the expected length, and collects exactly
/// that many `[A-Z0-9]` characters, allowing a single space between groups.
/// For a country in the length table, one line break between two digit groups
/// is also allowed (see `iban_group_gap`); an unknown country is never wrapped.
/// For countries missing from the length table, up to 34 characters are
/// collected and lengths are tried from longest to shortest in `15..=34`; the
/// first that passes mod-97 wins.
fn iban_extent(text: &str, start: usize) -> Option<usize> {
    // Not glued to a preceding ASCII letter or digit; a non-ASCII letter
    // (e.g. `ü` in running German text) is allowed.
    if text[..start]
        .chars()
        .next_back()
        .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        return None;
    }
    let bytes = text.as_bytes();
    let cc = text.get(start..start + 2)?.to_ascii_uppercase();
    let want = validate::iban_len(&cc);
    let max = want.unwrap_or(34);
    let mut compact = String::with_capacity(max);
    // ends[k] = byte offset just past the (k+1)-th collected character.
    let mut ends: Vec<usize> = Vec::with_capacity(max);
    let mut i = start;
    let mut wrapped = false;
    while compact.len() < max && i < bytes.len() {
        let b = bytes[i];
        if is_iban_char(b) {
            compact.push(b.to_ascii_uppercase() as char);
            i += 1;
            ends.push(i);
        } else if compact.len() >= 4
            && let Some(next) = iban_group_gap(bytes, i, want.is_some() && !wrapped)
        {
            wrapped |= bytes[i..next].contains(&b'\n');
            i = next;
        } else {
            break;
        }
    }
    match want {
        Some(n) => (compact.len() == n && validate::iban(&compact)).then(|| ends[n - 1]),
        None => (15..=compact.len())
            .rev()
            .find(|&n| validate::iban(&compact[..n]))
            .map(|n| ends[n - 1]),
    }
}

/// Card number spans inside a digit run `start..end` that holds no line break
/// (digits separated by single spaces or hyphens).
///
/// With separators, every window of 13–19 digits that starts at a group start
/// and ends at a group end is tried; every window passing the Luhn and prefix
/// check is kept, and overlapping kept windows are merged into their union.
/// Merging over-redacts a neighbouring group rather than risk leaving part of
/// a card behind. Without separators, windows start at the run start and are
/// tried from 19 down to 13 digits; the first valid one wins.
///
/// A run directly preceded by an alphanumeric character (`K12 4111 ...`) has
/// a glued first group that is not part of a card: that group is skipped and
/// the windows starting at the later groups are still tried.
fn card_spans_line(text: &str, start: usize, end: usize) -> Vec<(usize, usize)> {
    if text[..start]
        .chars()
        .next_back()
        .is_some_and(|c| c.is_alphanumeric())
    {
        let sep = text.as_bytes()[start..end]
            .iter()
            .position(|&b| b == b' ' || b == b'-');
        return match sep {
            Some(k) if start + k + 1 < end => card_spans_line(text, start + k + 1, end),
            _ => Vec::new(),
        };
    }
    let bytes = text.as_bytes();
    let pos: Vec<usize> = (start..end)
        .filter(|&i| bytes[i].is_ascii_digit())
        .collect();
    let n = pos.len();
    let separated = bytes[start..end].iter().any(|&b| b == b' ' || b == b'-');
    if !separated {
        for len in (13..=19).rev() {
            if len <= n && passes(Check::Luhn, &text[pos[0]..=pos[len - 1]]) {
                return vec![(pos[0], pos[len - 1] + 1)];
            }
        }
        return Vec::new();
    }
    let is_group_start = |s: usize| s == 0 || !bytes[pos[s] - 1].is_ascii_digit();
    let is_group_end = |e: usize| group_ends_at(bytes, pos[e - 1]);
    let mut windows: Vec<(usize, usize)> = Vec::new();
    for s in (0..n).filter(|&s| is_group_start(s)) {
        for len in 13..=19 {
            let e = s + len;
            if e > n || !is_group_end(e) {
                continue;
            }
            let (a, b) = (pos[s], pos[e - 1] + 1);
            let w = &text[a..b];
            if w.bytes().filter(|&c| c == b'\n').count() <= 1
                && passes(Check::Luhn, w)
                && !overlaps_iban(text, a, b)
            {
                windows.push((a, b));
            }
        }
    }
    windows.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (a, b) in windows {
        match merged.last_mut() {
            Some(last) if a < last.1 => last.1 = last.1.max(b),
            _ => merged.push((a, b)),
        }
    }
    merged
}

/// Card number spans inside a digit run `start..end`: digits joined by single
/// spaces or hyphens, or by a line break as left by a mail client that wrapped
/// the number.
///
/// The result is a superset of the single-line behaviour. The run is first
/// split at line breaks and each line is searched on its own with
/// `card_spans_line`, so a glued prefix or an unseparated digit string on one
/// line never hides a card on another. Then windows that span exactly one line
/// break are tried as extra candidates (13-19 digits, group boundaries at both
/// ends, prefix and Luhn check). The per-line spans are returned exactly as
/// the single-line search found them; a cross-line window is added only when
/// it starts at a group that is not glued to a letter, overlaps neither a
/// per-line span nor an IBAN (`overlaps_iban`), and cross-line windows are
/// merged only among themselves. Keeping the sets apart means a chance Luhn
/// hit across two rows of a numeric table (unlikely, not impossible; the cost
/// is a redaction) can never swallow or displace an IBAN or a real card
/// found on a single line.
fn card_spans(text: &str, start: usize, end: usize) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    if !bytes[start..end].contains(&b'\n') {
        return card_spans_line(text, start, end);
    }
    let mut line_spans: Vec<(usize, usize)> = Vec::new();
    let is_blank = |b: u8| matches!(b, b' ' | b'\t' | b'\r' | b'-');
    let mut line_start = start;
    while line_start <= end {
        let line_end = bytes[line_start..end]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(end, |k| line_start + k);
        let (mut a, mut b) = (line_start, line_end);
        while a < b && is_blank(bytes[a]) {
            a += 1;
        }
        while b > a && is_blank(bytes[b - 1]) {
            b -= 1;
        }
        if a < b {
            line_spans.extend(card_spans_line(text, a, b));
        }
        line_start = line_end + 1;
    }
    let pos: Vec<usize> = (start..end)
        .filter(|&i| bytes[i].is_ascii_digit())
        .collect();
    let n = pos.len();
    let is_group_start = |s: usize| s == 0 || !bytes[pos[s] - 1].is_ascii_digit();
    let is_group_end = |e: usize| group_ends_at(bytes, pos[e - 1]);
    let mut cross: Vec<(usize, usize)> = Vec::new();
    for s in (0..n).filter(|&s| is_group_start(s)) {
        let a = pos[s];
        let glued = text[..a]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric());
        if glued {
            continue;
        }
        for len in 13..=19 {
            let e = s + len;
            if e > n || !is_group_end(e) {
                continue;
            }
            let w = &text[a..pos[e - 1] + 1];
            let b = pos[e - 1] + 1;
            if w.bytes().filter(|&c| c == b'\n').count() == 1
                && passes(Check::Luhn, w)
                && !overlaps_sorted(&line_spans, a, b)
                && !overlaps_iban(text, a, b)
            {
                cross.push((a, b));
            }
        }
    }
    cross.sort_unstable();
    let mut out = line_spans;
    let first_cross = out.len();
    for (a, b) in cross {
        match out[first_cross..].last_mut() {
            Some(last) if a < last.1 => last.1 = last.1.max(b),
            _ => out.push((a, b)),
        }
    }
    out
}

/// True when the digit at `i` ends a digit group: it is not followed by
/// another digit, nor by `.` and a digit (`201.158.132.18` is an address, not
/// a card tail).
fn group_ends_at(bytes: &[u8], i: usize) -> bool {
    match bytes.get(i + 1) {
        Some(b) if b.is_ascii_digit() => false,
        Some(b'.') => !bytes.get(i + 2).is_some_and(u8::is_ascii_digit),
        _ => true,
    }
}

/// True when `a..b` overlaps one of `spans`, which are sorted and disjoint.
fn overlaps_sorted(spans: &[(usize, usize)], a: usize, b: usize) -> bool {
    let k = spans.partition_point(|&(x, _)| x < b);
    k > 0 && spans[k - 1].1 > a
}

/// True when a valid single-line IBAN overlaps `a..b`. Looks for IBAN starts
/// from the line before `a` up to `b`, so a window cannot begin or end inside
/// an IBAN. A wrapped IBAN is only a guess and is not considered here.
fn overlaps_iban(text: &str, a: usize, b: usize) -> bool {
    let bytes = text.as_bytes();
    let this_line = text[..a].rfind('\n').map_or(0, |i| i + 1);
    let from = text[..this_line.saturating_sub(1)]
        .rfind('\n')
        .map_or(0, |i| i + 1);
    (from..b.min(bytes.len().saturating_sub(3))).any(|p| {
        bytes[p].is_ascii_alphabetic()
            && bytes[p + 1].is_ascii_alphabetic()
            && bytes[p + 2].is_ascii_digit()
            && bytes[p + 3].is_ascii_digit()
            && iban_extent(text, p).is_some_and(|e| e > a && !text[p..e].contains('\n'))
    })
}

/// Trim characters that end sentences but rarely end URLs.
fn trim_url(text: &str, start: usize, mut end: usize) -> usize {
    while end > start
        && matches!(
            text.as_bytes()[end - 1],
            b'.' | b',' | b';' | b':' | b')' | b'!' | b'?'
        )
    {
        end -= 1;
    }
    end
}

fn is_not_street_word(word: &str) -> bool {
    let w = word
        .trim_matches(|c: char| !c.is_alphanumeric())
        .to_lowercase();
    NOT_STREETS.contains(&w.as_str())
}

/// True when `text[start..end]` opens with a shape-4 preposition
/// (`am`/`im`/`zum`/`zur`/`beim`) followed by a noun in `SHAPE4_NOT_STREETS`
/// (`im Jahr 2020`, `am Schalter 5`): `am`/`im` are never trimmed as leading
/// stop words (they open real addresses like `Am Hof 5`), so this closed
/// list is the only way to reject the ordinary-prose case.
fn is_shape4_common_noun(text: &str, start: usize, end: usize) -> bool {
    let slice = &text[start..end];
    let Some(prep_len) = slice.find(char::is_whitespace) else {
        return false;
    };
    if !SHAPE4_PREPS.contains(&slice[..prep_len].to_lowercase().as_str()) {
        return false;
    }
    let rest = slice[prep_len..].trim_start();
    let noun_len = rest
        .find(|c: char| !c.is_alphabetic())
        .unwrap_or(rest.len());
    SHAPE4_NOT_STREETS.contains(&rest[..noun_len].to_lowercase().as_str())
}

/// Extent of the address matched at `start..end`, with leading articles,
/// prepositions, or nouns (`der`, `unter`, `Adresse`, `In der`) trimmed, or
/// `None` when the match is glued to a preceding letter, contains a
/// non-street compound, is a shape-4 preposition plus a common noun
/// (`im Jahr 2020`), or is nothing but stop words plus a suffix
/// (`der Weg 5`, `auf Platz 3`).
fn address_extent(text: &str, start: usize, end: usize) -> Option<(usize, usize)> {
    if text[..start]
        .chars()
        .next_back()
        .is_some_and(char::is_alphanumeric)
    {
        return None;
    }
    if text[start..end].split_whitespace().any(is_not_street_word) {
        return None;
    }
    let mut a = start;
    let mut trimmed = false;
    loop {
        let slice = &text[a..end];
        let first_len = slice.find(char::is_whitespace)?;
        let first = slice[..first_len].to_lowercase();
        if !ADDRESS_LEAD_STOP.contains(&first.as_str()) {
            break;
        }
        let rest = slice[first_len..].trim_start();
        a = end - rest.len();
        trimmed = true;
    }
    if trimmed {
        // What is left must still be a whole address on its own.
        let m = ADDRESS_RE.find(&text[a..end])?;
        if m.start() != 0 || m.end() != end - a {
            return None;
        }
    }
    if is_shape4_common_noun(text, a, end) {
        return None;
    }
    Some((a, end))
}

/// A bare street name is kept unless it is a known non-street compound.
fn bare_street_ok(text: &str, start: usize, end: usize) -> bool {
    !is_not_street_word(&text[start..end])
}

impl Detector for RegexDetector {
    fn id(&self) -> DetectorId {
        DetectorId::RegexSyntax
    }

    fn detect(&self, text: &str, _ctx: &DetectCtx) -> crate::Result<Vec<Span>> {
        let c = &*COMPILED;
        let mut out = Vec::new();
        for idx in c.set.matches(text).iter() {
            let rule = &c.rules[idx];
            let re = &c.regexes[idx];
            for caps in re.captures_iter(text) {
                let Some(m) = caps.get(rule.group) else {
                    continue;
                };
                let (start, mut end) = (m.start(), m.end());
                let push = |out: &mut Vec<Span>, a: usize, b: usize| {
                    out.push(Span::new(
                        a,
                        b,
                        rule.kind.clone(),
                        rule.confidence,
                        rule.source,
                    ))
                };
                match rule.check {
                    Check::Iban => {
                        if let Some(b) = iban_extent(text, start) {
                            push(&mut out, start, b);
                        }
                        continue;
                    }
                    Check::Luhn => {
                        for (a, b) in card_spans(text, start, end) {
                            push(&mut out, a, b);
                        }
                        continue;
                    }
                    Check::Address => {
                        if let Some((a, b)) = address_extent(text, start, end) {
                            push(&mut out, a, b);
                        }
                        continue;
                    }
                    Check::BareStreet => {
                        if bare_street_ok(text, start, end) {
                            push(&mut out, start, end);
                        }
                        continue;
                    }
                    _ => {}
                }
                if matches!(rule.check, Check::Url) {
                    end = trim_url(text, start, end);
                }
                let matched = &text[start..end];
                if !passes(rule.check, matched) {
                    continue;
                }
                push(&mut out, start, end);
            }
        }
        let towns = town_spans(text, &out);
        out.extend(towns);
        Ok(drop_wrapped_under_single_line(text, out))
    }
}

/// True when the postal code at `start` opens an address line: it stands
/// at the start of the text or a line, after a list separator (`,` `;`
/// `|` `·` `•`), or after `in`, with an optional country prefix (`A-`).
/// `Rechnung 20231 Huber` and `Rechnung: 20231 Huber` do not qualify: a
/// number before a capitalized word is as often an order number before a
/// name.
fn postal_opens_address(text: &str, start: usize) -> bool {
    let mut head = &text[..start];
    if let Some(h) = head.strip_suffix('-') {
        let Some(p) = POSTAL_COUNTRY_PREFIXES.iter().find(|p| h.ends_with(**p)) else {
            return false;
        };
        head = &h[..h.len() - p.len()];
        if head.chars().next_back().is_some_and(char::is_alphanumeric) {
            return false;
        }
    }
    let head = head.trim_end_matches([' ', '\t']);
    match head.chars().next_back() {
        None | Some('\n' | '\r' | ',' | ';' | '|' | '·' | '•') => true,
        Some(_) => {
            let word_start = head
                .char_indices()
                .rev()
                .take_while(|(_, c)| c.is_alphanumeric())
                .last()
                .map_or(head.len(), |(i, _)| i);
            head[word_start..].eq_ignore_ascii_case("in")
        }
    }
}

/// CITY spans for a town written right after a postal code on the same
/// line (mails5-diag S3, ruling L48): `Hauptstraße 5, 2340 Mödling.`,
/// `1010 Wien`, `8600 Bruck an der Mur`. The model often finds no span over
/// such a town, and the verifier's model then reads it as a name.
///
/// Narrow on purpose, since this span outranks a model span over the same
/// word (`yield_towns_to_persons` lets a model PERSON win): the postal code
/// must open an address line ([`postal_opens_address`]), the town's first
/// word is not a common word, salutation word, first name, or street word,
/// and no further capitalized word follows on the line (`1010 Wien Anna`).
/// A word that may be (part of) a town: not a common word, a salutation
/// word, a first name, a name-like word (`Rose`), a street word, or a
/// quantity noun.
fn plausible_town_word(word: &str) -> bool {
    let lower = word.to_lowercase();
    !(crate::stoplist::is_common_word(word)
        || crate::stoplist::is_name_like_word(word)
        || crate::stoplist::is_salutation_word(word)
        || crate::gazetteer::is_first_name(word)
        || TOWN_NOT_STREET.contains(&lower.as_str())
        || TOWN_NOT_QUANTITY.contains(&lower.as_str())
        || TOWN_NOT_STREET_COMPOUND
            .iter()
            .any(|suf| lower.ends_with(suf)))
}

fn town_spans(text: &str, found: &[Span]) -> Vec<Span> {
    let mut out = Vec::new();
    for p in found.iter().filter(|s| s.kind == EntityKind::PostalCode) {
        if !postal_opens_address(text, p.start) {
            continue;
        }
        let Some(caps) = TOWN_RE.captures(&text[p.end..]) else {
            continue;
        };
        let (Some(town), Some(first)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        if !plausible_town_word(first.as_str()) {
            continue;
        }
        // The joined word must itself be a plausible town part; otherwise
        // the town ends before the joiner (`Bruck an der Anna`).
        let end = match caps.get(3) {
            Some(j) if !plausible_town_word(j.as_str()) => first.end(),
            _ => town.end(),
        };
        let (a, b) = (p.end + town.start(), p.end + end);
        let rest = &text[b..];
        let next = rest.chars().next();
        let after_blank = rest.trim_start_matches([' ', '\t']).chars().next();
        let glued = next.is_some_and(|c| c.is_alphanumeric() || matches!(c, '@' | '_' | '-'))
            || (next == Some('.') && rest[1..].chars().next().is_some_and(char::is_alphanumeric));
        let another_word =
            matches!(next, Some(' ' | '\t')) && after_blank.is_some_and(char::is_uppercase);
        if glued || another_word {
            continue;
        }
        out.push(Span::new(a, b, EntityKind::City, p.confidence, p.source));
    }
    out
}

/// True for a town span from [`town_spans`]: the only regex CITY.
pub fn is_town_span(s: &Span) -> bool {
    s.kind == EntityKind::City && s.source == DetectorId::RegexSyntax
}

/// Drops a town span from [`town_spans`] (a regex CITY) that overlaps any
/// PERSON span. Source priority would otherwise let the regex CITY evict a
/// model's PERSON over the same word (`10234 Gruber.`), and a profile that
/// preserves cities would forward the name. Where the model says PERSON,
/// PERSON stays; the town rule only adds coverage where nothing else
/// claimed the word.
pub fn yield_towns_to_persons(spans: Vec<Span>) -> Vec<Span> {
    let persons: Vec<(usize, usize)> = spans
        .iter()
        .filter(|s| s.kind == EntityKind::Person)
        .map(|s| (s.start, s.end))
        .collect();
    if persons.is_empty() {
        return spans;
    }
    spans
        .into_iter()
        .filter(|s| !(is_town_span(s) && persons.iter().any(|&(a, b)| a < s.end && s.start < b)))
        .collect()
}

/// Drops card and IBAN candidates that cross a line break and overlap a
/// validated identifier found on a single line. A wrapped candidate is a
/// guess that digits on two lines belong together; an identifier that is valid
/// on one line is stronger evidence, and the verifier's whitespace-collapsed
/// leak check still blocks a wrapped identifier that goes undetected.
fn drop_wrapped_under_single_line(text: &str, out: Vec<Span>) -> Vec<Span> {
    use EntityKind as K;
    let crosses = |s: &Span| text.as_bytes()[s.start..s.end].contains(&b'\n');
    if !out
        .iter()
        .any(|s| crosses(s) && matches!(s.kind, K::CreditCard | K::Iban))
    {
        return out;
    }
    // A wrapped IBAN is length- and mod-97-checked, so it yields only to a
    // phone number anchored by `+`, `00` or `(`: a bare `0...` digit run is as
    // likely to be the tail of the wrapped IBAN. A wrapped card is only
    // Luhn-checked (about one chance window in ten), so it yields to any phone,
    // including one that spans the break.
    let anchored = |s: &Span| {
        let t = &text[s.start..s.end];
        t.starts_with(['+', '(']) || t.starts_with("00")
    };
    let union_of = |keep: &dyn Fn(&Span) -> bool, phone_may_cross: bool| {
        let mut firm: Vec<(usize, usize)> = out
            .iter()
            .filter(|s| {
                matches!(
                    s.kind,
                    K::CreditCard
                        | K::Iban
                        | K::Phone
                        | K::NationalId
                        | K::IpAddress
                        | K::Email
                        | K::TaxId
                        | K::Url
                ) && (!crosses(s) || (phone_may_cross && s.kind == K::Phone))
                    && keep(s)
            })
            .map(|s| (s.start, s.end))
            .collect();
        firm.sort_unstable();
        let mut union: Vec<(usize, usize)> = Vec::with_capacity(firm.len());
        for (a, b) in firm {
            match union.last_mut() {
                Some(last) if a < last.1 => last.1 = last.1.max(b),
                _ => union.push((a, b)),
            }
        }
        union
    };
    let for_iban = union_of(&|s| s.kind != K::Phone || anchored(s), false);
    // A phone match that itself runs over the line break also protects: the
    // card guess may not take the second line away from it.
    let for_card = union_of(&|_| true, true);
    out.into_iter()
        .filter(|s| {
            let union = match s.kind {
                K::Iban => &for_iban,
                K::CreditCard => &for_card,
                _ => return true,
            };
            !(crosses(s) && overlaps_sorted(union, s.start, s.end))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::span::EntityKind as K;

    const FIXTURE: &str = include_str!("../../tests/fixtures/regex_de.txt");

    fn kinds_with_text(text: &str) -> Vec<(K, String)> {
        let d = RegexDetector::new();
        let mut v: Vec<_> = d
            .detect(text, &DetectCtx::for_text(text))
            .unwrap()
            .into_iter()
            .map(|s| (s.kind.clone(), s.slice(text).to_string()))
            .collect();
        v.sort_by(|a, b| a.1.cmp(&b.1));
        v
    }

    fn has(v: &[(K, String)], k: K, t: &str) -> bool {
        v.iter().any(|(kk, tt)| *kk == k && tt == t)
    }

    /// Some CreditCard span's text contains `want`.
    fn covers(v: &[(K, String)], k: K, want: &str) -> bool {
        v.iter().any(|(kk, t)| *kk == k && t.contains(want))
    }

    #[test]
    fn detects_everything_in_fixture() {
        let v = kinds_with_text(FIXTURE);
        assert!(has(&v, K::Phone, "+43 660 1234567"));
        assert!(has(&v, K::Email, "sarah.leitner@example.at"));
        assert!(has(&v, K::Iban, "AT61 1904 3002 3457 3201"));
        assert!(has(&v, K::DateOfBirth, "12.03.1985"));
        assert!(has(&v, K::PostalCode, "1010"));
        assert!(has(&v, K::LicensePlate, "W-12345A"));
        assert!(has(&v, K::TaxId, "ATU12345678"));
        assert!(has(&v, K::IpAddress, "192.168.1.10"));
        assert!(has(&v, K::Url, "https://example.at/kunden/382910"));
        assert!(has(&v, K::CreditCard, "4111 1111 1111 1111"));
        assert!(has(&v, K::NationalId, "1237 010180"));
        assert!(has(&v, K::NationalId, "86095742719"));
        assert!(has(&v, K::Date, "24.09.2026"));
    }

    #[test]
    fn dates_are_not_phones() {
        let v = kinds_with_text("Termin am 01.02.2024 um 10 Uhr.");
        assert!(!v.iter().any(|(k, _)| *k == K::Phone));
        assert!(has(&v, K::Date, "01.02.2024"));
    }

    #[test]
    fn invalid_checksums_are_rejected() {
        let v = kinds_with_text("IBAN AT61 1904 3002 3457 3202 und Karte 4111 1111 1111 1112");
        assert!(!v.iter().any(|(k, _)| *k == K::Iban || *k == K::CreditCard));
    }

    #[test]
    fn confidence_and_source_tiers() {
        let d = RegexDetector::new();
        let text = "AT611904300234573201 +43 660 1234567";
        let spans = d.detect(text, &DetectCtx::for_text(text)).unwrap();
        let iban = spans.iter().find(|s| s.kind == K::Iban).unwrap();
        let phone = spans.iter().find(|s| s.kind == K::Phone).unwrap();
        assert_eq!(iban.source, DetectorId::RegexValidated);
        assert!((iban.confidence - 0.99).abs() < 1e-6);
        assert_eq!(phone.source, DetectorId::RegexSyntax);
        assert!((phone.confidence - 0.85).abs() < 1e-6);
    }

    #[test]
    fn offsets_are_char_boundaries_with_umlauts() {
        let text = "Straße: Hauptstraße 12, 1010 Wien, Mail: müller@example.de";
        let d = RegexDetector::new();
        for s in d.detect(text, &DetectCtx::for_text(text)).unwrap() {
            assert!(text.is_char_boundary(s.start) && text.is_char_boundary(s.end));
            let _ = s.slice(text);
        }
    }

    /// C1: a failing greedy match must not hide a valid shorter extent.
    #[test]
    fn iban_extent_comes_from_the_country_length_table() {
        for (text, want) in [
            (
                "IBAN AT61 1904 3002 3457 3201 BIC BKAUATWW",
                "AT61 1904 3002 3457 3201",
            ),
            (
                "IBAN AT611904300234573201 BIC BKAUATWW",
                "AT611904300234573201",
            ),
            (
                "… AT61 1904 3002 3457 3201 DANKE",
                "AT61 1904 3002 3457 3201",
            ),
            (
                "DE89 3704 0044 0532 0130 00 Danke",
                "DE89 3704 0044 0532 0130 00",
            ),
            // country missing from the length table: longest valid length wins
            ("XK05 1212 0123 4567 8906 OK", "XK05 1212 0123 4567 8906"),
        ] {
            let v = kinds_with_text(text);
            assert!(has(&v, K::Iban, want), "{text}: {v:?}");
        }
    }

    #[test]
    fn card_is_cut_at_a_group_boundary_when_the_full_match_fails_luhn() {
        for (text, want) in [
            (
                "Karte 4111 1111 1111 1111 123 gueltig",
                "4111 1111 1111 1111",
            ),
            ("4111 1111 1111 1111 12 26", "4111 1111 1111 1111"),
            ("4111-1111-1111-1111-123", "4111-1111-1111-1111"),
            ("Karte 4111111111111111123 ok", "4111111111111111"),
            ("Ref 12 4111 1111 1111 1111", "4111 1111 1111 1111"),
        ] {
            let v = kinds_with_text(text);
            assert!(covers(&v, K::CreditCard, want), "{text}: {v:?}");
        }
        // a group boundary is required when separators are present
        let v = kinds_with_text("4111 1111 1111 1111123");
        assert!(!v.iter().any(|(k, _)| *k == K::CreditCard), "{v:?}");
    }

    #[test]
    fn card_after_leading_digit_group_is_found() {
        for (text, card) in [
            ("Jahr 2024 4111 1111 1111 1111", "4111 1111 1111 1111"),
            ("Tel 0664 4111 1111 1111 1111", "4111 1111 1111 1111"),
            ("Bestellung 2024 5500 0000 0000 0004", "5500 0000 0000 0004"),
            ("Kunde 6 4111 1111 1111 1111", "4111 1111 1111 1111"),
            ("Ref 12 4111-1111-1111-1111 ok", "4111-1111-1111-1111"),
            // Fullwidth digit prefix (M1 carry-over): `\d` is Unicode, so the run
            // includes it; `card_spans` only uses ASCII digit positions.
            ("Nr. ０4111 1111 1111 1111 ok", "4111 1111 1111 1111"),
            // Fullwidth digit glued to card: misclassified as separated if checking
            // byte count, but should use prefix search because there are no actual separators.
            ("Nr. ０41111111111111119 ok", "4111111111111111"),
        ] {
            let v = kinds_with_text(text);
            assert!(covers(&v, K::CreditCard, card), "{text}: {v:?}");
        }
    }

    /// A card wrapped across a line (LF, CRLF, trailing blanks) is found and
    /// the span covers exactly the digits and inner separators; two adjacent
    /// non-Luhn number lines are not a card.
    #[test]
    fn card_wrapped_across_a_line_is_detected_and_redacted() {
        let groups = ["4111", "1111", "1111", "1111"];
        for (text, card) in [
            ("Karte 4111 1111\n1111 1111 gueltig", "4111 1111\n1111 1111"),
            (
                "Karte 4111 1111\r\n1111 1111 gueltig",
                "4111 1111\r\n1111 1111",
            ),
            ("Karte 4111 1111 \n  1111 1111.", "4111 1111 \n  1111 1111"),
            ("Karte 4111-1111-\n1111-1111", "4111-1111-\n1111-1111"),
        ] {
            let d = RegexDetector::new();
            let spans = d.detect(text, &DetectCtx::for_text(text)).unwrap();
            let cards: Vec<_> = spans.iter().filter(|s| s.kind == K::CreditCard).collect();
            assert_eq!(cards.len(), 1, "{text:?}: {spans:?}");
            assert_eq!(cards[0].slice(text), card, "{text:?}");
            let sanitized = format!("{}<CARD>{}", &text[..cards[0].start], &text[cards[0].end..]);
            assert!(
                groups.iter().all(|g| !sanitized.contains(g)),
                "{sanitized:?}"
            );
        }
        // a glued or unseparated digit string on another line never hides a card
        for (text, card) in [
            ("Kunde K12\n4111 1111 1111 1111", "4111 1111 1111 1111"),
            (
                "RE2026-0042\n4111 1111 1111 1111 danke",
                "4111 1111 1111 1111",
            ),
            ("Betrag 12\n41111111111111119", "4111111111111111"),
            ("Kunde K12 4111 1111 1111 1111", "4111 1111 1111 1111"),
            ("Kunde K12 4111 1111\n1111 1111", "4111 1111\n1111 1111"),
        ] {
            let v = kinds_with_text(text);
            assert!(covers(&v, K::CreditCard, card), "{text:?}: {v:?}");
        }
        let v = kinds_with_text("Summen 1234 5678 9012\n3456 7890 1234 und 4000 1234\n5678 9012");
        assert!(!v.iter().any(|(k, _)| *k == K::CreditCard), "{v:?}");
    }

    #[test]
    fn long_unseparated_digit_runs_are_not_cards() {
        let v = kinds_with_text("Referenz 12345678901234567890123 bitte");
        assert!(!v.iter().any(|(k, _)| *k == K::CreditCard), "{v:?}");
    }

    #[test]
    fn digit_run_glued_to_letters_is_skipped() {
        let v = kinds_with_text("Code X4111111111111111 ende");
        assert!(!v.iter().any(|(k, _)| *k == K::CreditCard), "{v:?}");
    }

    /// I6: national numbers with the area code in parentheses.
    #[test]
    fn phone_with_parenthesized_area_code() {
        for (text, want) in [
            ("Tel. (0664) 123 45 67 bitte", "(0664) 123 45 67"),
            ("Tel. (01) 234 56 78", "(01) 234 56 78"),
            ("Tel. +43 (664) 123 45 67", "+43 (664) 123 45 67"),
        ] {
            let v = kinds_with_text(text);
            assert!(has(&v, K::Phone, want), "{text}: {v:?}");
        }
    }

    /// I6: non-ASCII local parts and internationalized domains.
    #[test]
    fn email_with_non_ascii_local_part_or_domain() {
        for (text, want) in [
            ("Mail an office@müller-bau.at bitte", "office@müller-bau.at"),
            ("Mail an jörg.huber@example.at.", "jörg.huber@example.at"),
            ("an Ümit.Çelik@beispiel.de", "Ümit.Çelik@beispiel.de"),
        ] {
            let v = kinds_with_text(text);
            assert!(has(&v, K::Email, want), "{text}: {v:?}");
            assert_eq!(
                v.iter().filter(|(k, _)| *k == K::Email).count(),
                1,
                "{text}: {v:?}"
            );
        }
    }

    #[test]
    fn url_trailing_punctuation_is_trimmed() {
        let v = kinds_with_text("Siehe https://example.at/x. Danke.");
        assert!(has(&v, K::Url, "https://example.at/x"));
    }

    /// An IBAN wrapped across a line is found with its inner separators and
    /// redacted; the next line is not absorbed once the length is reached.
    #[test]
    fn iban_wrapped_across_a_line_is_detected_and_redacted() {
        let groups = ["AT61", "1904", "3002", "3457", "3201"];
        for (text, iban) in [
            (
                "IBAN AT61 1904 3002\n3457 3201 danke",
                "AT61 1904 3002\n3457 3201",
            ),
            (
                "IBAN AT61 1904 3002\r\n3457 3201 danke",
                "AT61 1904 3002\r\n3457 3201",
            ),
            (
                "IBAN AT61 1904 3002 \n  3457 3201\n12345 6789",
                "AT61 1904 3002 \n  3457 3201",
            ),
        ] {
            let d = RegexDetector::new();
            let spans = d.detect(text, &DetectCtx::for_text(text)).unwrap();
            let ibans: Vec<_> = spans.iter().filter(|s| s.kind == K::Iban).collect();
            assert_eq!(ibans.len(), 1, "{text:?}: {spans:?}");
            assert_eq!(ibans[0].slice(text), iban, "{text:?}");
            let sanitized = format!("{}<IBAN>{}", &text[..ibans[0].start], &text[ibans[0].end..]);
            assert!(
                groups.iter().all(|g| !sanitized.contains(g)),
                "{sanitized:?}"
            );
        }
        // an unrelated number line after a complete IBAN stays outside the span
        let text = "AT61 1904 3002 3457 3201\n3457 3201";
        let v = kinds_with_text(text);
        assert!(has(&v, K::Iban, "AT61 1904 3002 3457 3201"), "{v:?}");
    }

    /// Spans after overlap resolution, as the engine sees them.
    fn resolved(text: &str) -> Vec<(K, usize, usize)> {
        let d = RegexDetector::new();
        crate::resolve::resolve_overlaps(d.detect(text, &DetectCtx::for_text(text)).unwrap())
            .into_iter()
            .map(|s| (s.kind.clone(), s.start, s.end))
            .collect()
    }

    /// A card on the line after an IBAN (and an IBAN after a card) must not
    /// let a cross-line window displace either entity.
    #[test]
    fn card_after_iban_line_keeps_both_entities_covered() {
        for (text, iban, card) in [
            (
                "IBAN AT48 3200 0000 1234 5864\n4111 1111 1111 1111 danke",
                "AT48 3200 0000 1234 5864",
                "4111 1111 1111 1111",
            ),
            (
                "IBAN AT02 2050 3021 0102 3600\r\n6011 1111 1111 1117",
                "AT02 2050 3021 0102 3600",
                "6011 1111 1111 1117",
            ),
        ] {
            let r = resolved(text);
            for (kind, want) in [(K::Iban, iban), (K::CreditCard, card)] {
                let a = text.find(want).unwrap();
                let covered = |i: usize| r.iter().any(|(_, s, e)| *s <= i && i < *e);
                assert!(
                    (a..a + want.len()).all(covered),
                    "{kind:?} in {text:?}: {r:?}"
                );
                assert!(
                    r.iter()
                        .any(|(k, s, e)| *k == kind && *s <= a && a + want.len() <= *e)
                );
            }
        }
    }

    /// A resolved span of `kind` covers every byte of the first `want` in `text`.
    fn assert_entity_covered(text: &str, kind: K, want: &str) {
        let r = resolved(text);
        let a = text.find(want).unwrap();
        assert!(
            r.iter()
                .any(|(k, s, e)| *k == kind && *s <= a && a + want.len() <= *e),
            "{kind:?} {want:?} not covered in {text:?}: {r:?}"
        );
    }

    /// A candidate that crosses a line break never displaces an identifier
    /// that is valid on a single line.
    #[test]
    fn wrapped_candidates_never_displace_single_line_identifiers() {
        for (text, kind, want) in [
            (
                "Ref RE45 2610\r\n4111 1111 1111 1111",
                K::CreditCard,
                "4111 1111 1111 1111",
            ),
            (
                "IBAN AT48 3200 0000 1234 586\n4111 1111 1111 1111 danke",
                K::CreditCard,
                "4111 1111 1111 1111",
            ),
            (
                "Karte AB45 0745\r\nx AT48 3200 0000 1234 5864 ",
                K::Iban,
                "AT48 3200 0000 1234 5864",
            ),
            (
                "IBAN DE05 3704 0044 0532 0130 0\nAT61 1904 3002 3457 3201",
                K::Iban,
                "AT61 1904 3002 3457 3201",
            ),
            (
                "\t6040 322431\n\t0664 630 5206 -",
                K::NationalId,
                "6040 322431",
            ),
            (
                "Tel +43 664 1012919 12\r\n\t10.0.48.240 -",
                K::IpAddress,
                "10.0.48.240",
            ),
            (
                "IBAN AT61 1904 3002 3457 3201 12164 1 4978",
                K::Iban,
                "AT61 1904 3002 3457 3201",
            ),
            (
                "Server K12 6011 4340 4426 0979 12 201.158.132.18",
                K::IpAddress,
                "201.158.132.18",
            ),
            (
                "Tel +41 44 668 18 00\n0664 123 4567",
                K::Phone,
                "0664 123 4567",
            ),
            ("Tel +41 44 668 18 00\n06641234567", K::Phone, "06641234567"),
            (
                "IBAN AT02 2050 3021\n0102 3600",
                K::Iban,
                "AT02 2050 3021\n0102 3600",
            ),
        ] {
            assert_entity_covered(text, kind, want);
        }
    }

    /// Everything the single-line search finds on two lines alone is still
    /// covered once the lines are joined by LF or CRLF and overlaps are
    /// resolved: the line-wrap handling only ever adds.
    #[test]
    fn joining_lines_never_loses_a_single_line_identifier() {
        let lines = [
            "IBAN AT48 3200 0000 1234 5864",
            "IBAN AT02 2050 3021 0102 3600",
            "DE89 3704 0044 0532 0130 00",
            "Karte 4111 1111 1111 1111 danke",
            "6011 1111 1111 1117",
            "Ref 3782 822463 10005",
            "Tel +43 664 1234567",
            "Tel (0664) 123 45 67",
            "SVNR 1237 010180",
            "Steuer-ID 86095742719",
            "Server 192.168.1.10",
            "\t6040 322431",
            "\t0664 630 5206 -",
            "\t10.0.48.240 -",
            "Betrag 12",
            "Ref RE45 2610",
            "Kunde K12 4111 1111 1111 1111",
            "RE2026-0042",
            "IBAN AT61 1904 3002 3457 3201",
            "IBAN DE05 3704 0044 0532 0130 0",
        ];
        // Phone is not tracked: a number followed by a card line loses to the
        // card (ledgered, predates the wrap handling).
        let tracked = |k: &K| matches!(k, K::Iban | K::CreditCard | K::NationalId | K::IpAddress);
        for first in lines {
            for second in lines {
                for sep in ["\n", "\r\n"] {
                    let text = format!("{first}{sep}{second}");
                    let joined = resolved(&text);
                    let covered = |i: usize| joined.iter().any(|(_, s, e)| *s <= i && i < *e);
                    for (line, base) in [(first, 0), (second, first.len() + sep.len())] {
                        for (k, s, e) in resolved(line).into_iter().filter(|(k, ..)| tracked(k)) {
                            assert!(
                                (base + s..base + e).all(covered),
                                "{k:?} {:?} lost in {text:?}: {joined:?}",
                                &line[s..e]
                            );
                        }
                    }
                }
            }
        }
    }

    /// Wrapped IBANs collect digits only, once, and only for known countries.
    #[test]
    fn iban_wrap_collects_digit_groups_only() {
        for text in [
            "IBAN DE05 3704 0044 0532 0130 0\nAT61",
            "IBAN XK05 1212 0123\n4567 8906",
            "IBAN AT61 1904 3002\nx 3457 3201",
        ] {
            let v = kinds_with_text(text);
            assert!(
                !v.iter().any(|(k, t)| *k == K::Iban && t.contains('\n')),
                "{text:?}: {v:?}"
            );
        }
    }

    /// A long numeric table stays bounded (completes; no timing assertion).
    #[test]
    fn long_numeric_table_completes() {
        let text = "4111 1111 1111 1111 6\n".repeat(20_000);
        let spans = RegexDetector::new()
            .detect(&text, &DetectCtx::for_text(&text))
            .unwrap();
        assert!(spans.iter().any(|s| s.kind == K::CreditCard));
    }

    #[test]
    fn iban_after_non_ascii_letter_and_in_lower_case() {
        let v = kinds_with_text("KontoüAT611904300234573201 danke");
        assert!(has(&v, K::Iban, "AT611904300234573201"), "{v:?}");
        let v = kinds_with_text("iban at61 1904 3002 3457 3201 bitte");
        assert!(has(&v, K::Iban, "at61 1904 3002 3457 3201"), "{v:?}");
    }

    #[test]
    fn iban_glued_to_ascii_letters_is_skipped() {
        let v = kinds_with_text("XBAT611904300234573201");
        assert!(!v.iter().any(|(k, _)| *k == K::Iban), "{v:?}");
    }

    /// `STREET_ADDRESS` spans after overlap resolution (the bare-street rule
    /// also fires inside every numbered address and loses to the longer span).
    fn street(text: &str) -> Vec<String> {
        let d = RegexDetector::new();
        crate::resolve::resolve_overlaps(d.detect(text, &DetectCtx::for_text(text)).unwrap())
            .into_iter()
            .filter(|s| s.kind == K::StreetAddress)
            .map(|s| s.slice(text).to_string())
            .collect()
    }

    /// Spec §13.1: DACH street addresses with a house number.
    #[test]
    fn dach_street_addresses_with_house_numbers_are_detected() {
        for (text, want) in [
            (
                "Hi, I'm Sarah Leitner, contract 8439271, moved to Neubaugasse 22.",
                "Neubaugasse 22",
            ),
            (
                "ich wohne jetzt in der Neubaugasse 22, 1070 Wien",
                "Neubaugasse 22",
            ),
            (
                "Lieferung an Mariahilfer Straße 7 bitte",
                "Mariahilfer Straße 7",
            ),
            (
                "Unser Büro: Wiedner Hauptstraße 12/3, 1040 Wien.",
                "Wiedner Hauptstraße 12/3",
            ),
            ("Landstraßer Hauptstraße 5", "Landstraßer Hauptstraße 5"),
            ("Lange Gasse 12-14 ist gesperrt", "Lange Gasse 12-14"),
            ("wohnhaft Am Graben 3", "Am Graben 3"),
            ("Bitte an Hauptstr. 5a liefern", "Hauptstr. 5a"),
            ("Bahnhofstraße Nr. 7", "Bahnhofstraße Nr. 7"),
            (
                "Bitte liefern an Neubaugasse\n22, 1070 Wien",
                "Neubaugasse\n22",
            ),
            ("Sonnenweg 9, 8010 Graz", "Sonnenweg 9"),
            ("Rathausplatz 1", "Rathausplatz 1"),
            ("Schubertring 3", "Schubertring 3"),
            (
                "Adresse Neubaugasse 22, Telefon 0664 123 45 67.",
                "Neubaugasse 22",
            ),
            ("unter Hauptstraße 5 finden Sie uns", "Hauptstraße 5"),
            ("Kärntner Straße 10", "Kärntner Straße 10"),
            ("Obere Donaustraße 4", "Obere Donaustraße 4"),
            ("Im Winkel 8", "Im Winkel 8"),
            (
                "In der Neubaugasse 22 wohnt niemand mehr.",
                "Neubaugasse 22",
            ),
            ("Michael Wagner\nWaldweg 5\n4020 Linz", "Waldweg 5"),
        ] {
            assert_eq!(street(text), vec![want.to_string()], "{text:?}");
        }
    }

    /// Review Focus 1: lower-cased mail still yields the address.
    #[test]
    fn lower_case_addresses_with_a_house_number_are_detected() {
        for (text, want) in [
            (
                "hallo, ich wohne in der neubaugasse 22, 1070 wien",
                "neubaugasse 22",
            ),
            ("lieferung an mariahilfer straße 7", "mariahilfer straße 7"),
            ("wiedner hauptstraße 12", "wiedner hauptstraße 12"),
        ] {
            assert_eq!(street(text), vec![want.to_string()], "{text:?}");
        }
    }

    #[test]
    fn bare_capitalized_street_names_are_low_confidence_addresses() {
        let d = RegexDetector::new();
        let text = "Ich wohne gegenüber der Kirche in der Hauptstraße in Mödling.";
        let spans = d.detect(text, &DetectCtx::for_text(text)).unwrap();
        let s = spans
            .iter()
            .find(|s| s.kind == K::StreetAddress)
            .expect("bare street");
        assert_eq!(s.slice(text), "Hauptstraße");
        assert!((s.confidence - 0.60).abs() < 1e-6);
        // with a number the longer, higher-confidence span is the one emitted after overlap resolution
        let text = "Hauptstraße 12";
        let spans =
            crate::resolve::resolve_overlaps(d.detect(text, &DetectCtx::for_text(text)).unwrap());
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].slice(text), "Hauptstraße 12");
    }

    #[test]
    fn street_negatives_are_not_addresses() {
        for text in [
            "Der Weg nach Hause war weit, wir haben 5 Stunden gebraucht.",
            "Wir sind auf Platz 3 gelandet; Arbeitsplatz 5 ist frei.",
            "Die Verhandlung ist eine Sackgasse; die Straße war nass.",
            "Parkplatz 12 ist reserviert.",
            "Ring 3 ist ausverkauft.",
            "Im Ranking 3 Punkte verloren.",
            "die lange gasse hinter dem haus",
            "Bundesstraße gesperrt",
            "Madam Graben 3 ist kein Ort.",
        ] {
            assert!(
                street(text).is_empty(),
                "{text:?}: {:?}",
                kinds_with_text(text)
            );
        }
    }

    #[test]
    fn two_adjectival_words_and_a_wrapped_suffix_line_are_one_street() {
        let v =
            kinds_with_text("ich wohne jetzt in der Wiener Neustädter Straße 17, 9500 Villach.");
        assert!(
            has(&v, K::StreetAddress, "Wiener Neustädter Straße 17"),
            "{v:?}"
        );
        let v = kinds_with_text("I now live at Wiener Neustädter Straße Nr. 79/8, 90402 Nürnberg.");
        assert!(
            has(&v, K::StreetAddress, "Wiener Neustädter Straße Nr. 79/8"),
            "{v:?}"
        );
        let v =
            kinds_with_text("Kundennummer K-417775, Adresse Grazer\nStraße 79/18, 6900 Bregenz.");
        assert!(has(&v, K::StreetAddress, "Grazer\nStraße 79/18"), "{v:?}");
        // the wrapped shape takes the same optional preceding -er word
        let v = kinds_with_text("Adresse Wiener Neustädter\nStraße 17, 9500 Villach.");
        assert!(
            has(&v, K::StreetAddress, "Wiener Neustädter\nStraße 17"),
            "{v:?}"
        );
        assert!(
            !v.iter().any(|(_, t)| t == "Neustädter\nStraße 17"),
            "{v:?}"
        );
        // a signature name above a compound street stays out of the street
        let v = kinds_with_text("Viele Grüße\nWagner\nWaldweg 5\n1010 Wien");
        assert!(has(&v, K::StreetAddress, "Waldweg 5"), "{v:?}");
        assert!(!v.iter().any(|(_, t)| t.contains("Wagner")), "{v:?}");
        // a lower-case possessive is not a prefix
        let v = kinds_with_text("in unserer Neustädter Straße 3 ist es laut");
        assert!(has(&v, K::StreetAddress, "Neustädter Straße 3"), "{v:?}");
    }

    /// Review finding: shape 4 (preposition + capitalized word + number)
    /// over-matched ordinary prose at the same confidence as real addresses.
    #[test]
    fn shape4_common_nouns_are_not_streets() {
        for text in [
            "Wir haben das im Jahr 2020 gemacht.",
            "Zum Beispiel 3 Kunden haben reklamiert.",
            "Wir treffen uns im Raum 204.",
            "Bitte kommen Sie am Stand 5 vorbei.",
            "Der Termin ist am Schalter 5.",
            "Wir sehen uns am Montag 3 Mal.",
            "Die Lieferung kommt im März 2024.",
        ] {
            assert!(
                street(text).is_empty(),
                "{text:?}: {:?}",
                kinds_with_text(text)
            );
        }
    }

    /// Real shape-4 street names must still be detected: the fix above must
    /// not turn `am`/`im` into a blanket rejection.
    #[test]
    fn shape4_real_street_names_still_match() {
        for (text, want) in [
            ("Termin bei mir, Am Hof 5", "Am Hof 5"),
            ("Wohnhaft Im Werd 2", "Im Werd 2"),
            ("Wohnhaft Am Platz 3, 4020 Linz.", "Am Platz 3"),
        ] {
            assert_eq!(street(text), vec![want.to_string()], "{text:?}");
        }
    }

    fn cities(text: &str) -> Vec<String> {
        kinds_with_text(text)
            .into_iter()
            .filter(|(k, _)| *k == K::City)
            .map(|(_, t)| t)
            .collect()
    }

    /// Ruling L48 (S3): a town written right after a postal code on the
    /// same line is a CITY; a common word, a street word, a first name,
    /// or a word on the next line is not.
    #[test]
    fn a_town_after_a_postal_code_is_a_city() {
        for (text, want) in [
            ("Hauptstraße 5, 2340 Mödling.", "Mödling"),
            ("1010 Wien", "Wien"),
            ("8600 Bruck an der Mur", "Bruck an der Mur"),
            (
                "Hauptplatz 1, A-2351 Wiener-Neudorf, Österreich",
                "Wiener-Neudorf",
            ),
            ("Frankfurter Weg 3\n60311 Frankfurt am Main\n", "Frankfurt"),
            ("wohnhaft in 4020 Linz, seit 2019", "Linz"),
            // L53 (2): only `an der` joins; `bei Gruber` is a person.
            ("Ich bin in 4020 Linz bei Gruber.", "Linz"),
            ("8600 Bruck an der Anna", "Bruck"),
        ] {
            assert_eq!(cities(text), vec![want.to_string()], "{text:?}");
        }
        for text in [
            "2340 Stück",
            "2340\nMödling",
            "2340 Gasse",
            "1010 Anna",
            "Rechnung 20231 Huber",
            "Rechnung: 20231 Huber",
            "1010 Wien Anna",
        ] {
            assert!(cities(text).is_empty(), "{text:?}");
        }
    }

    /// Recall: a regex town never evicts a PERSON span over the same word
    /// (`10234 Gruber.` where the model says PERSON); other cities stay.
    #[test]
    fn a_regex_town_yields_to_an_overlapping_person() {
        let text = "Hauptstraße 5\n10234 Gruber.\n1010 Wien";
        let d = RegexDetector::new();
        let mut spans = d.detect(text, &DetectCtx::for_text(text)).unwrap();
        assert_eq!(spans.iter().filter(|s| s.kind == K::City).count(), 2);
        let g = text.find("Gruber").unwrap();
        spans.push(Span::new(g, g + 6, K::Person, 0.55, DetectorId::Ner));
        let cities: Vec<&str> = yield_towns_to_persons(spans)
            .iter()
            .filter(|s| s.kind == K::City)
            .map(|s| s.slice(text))
            .collect();
        assert_eq!(cities, ["Wien"]);
    }
}
