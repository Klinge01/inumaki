//! Words that are also common surnames or ordinary vocabulary. A surname in
//! this list is never emitted on its own by the dictionary or leak checks.

use std::collections::HashSet;
use std::sync::LazyLock;

/// English words that are also names.
const NAME_WORDS_EN: &[&str] = &[
    "may", "rose", "hunter", "summer", "will", "mark", "bill", "grace", "hope", "faith", "april",
    "june", "august", "carol", "chase", "cliff", "dean", "drew", "gene", "glen", "hazel", "holly",
    "iris", "ivy", "jade", "jay", "joy", "lane", "lily", "olive", "page", "pearl", "reed", "rich",
    "rob", "ruby", "sandy", "sky", "victor", "violet", "wade", "baker", "brown", "cook", "fisher",
    "green", "hill", "king", "knight", "long", "miller", "moore", "parker", "smith", "stone",
    "taylor", "turner", "walker", "white", "wood", "young", "black", "bell", "bush", "field",
    "ford", "fox", "frost", "hall", "hart", "hunt", "lake", "marsh", "north", "west", "south",
    "east", "price", "rice", "ray", "sharp", "short", "snow",
];

/// German words that are also names.
const NAME_WORDS_DE: &[&str] = &[
    "berg",
    "könig",
    "koenig",
    "kaiser",
    "klein",
    "groß",
    "gross",
    "lang",
    "kurz",
    "jung",
    "alt",
    "weiß",
    "weiss",
    "schwarz",
    "braun",
    "roth",
    "rot",
    "grün",
    "gruen",
    "hahn",
    "wolf",
    "fuchs",
    "vogel",
    "bauer",
    "koch",
    "schneider",
    "fischer",
    "weber",
    "wagner",
    "becker",
    "schäfer",
    "schaefer",
    "richter",
    "krüger",
    "krueger",
    "hofmann",
    "hoffmann",
    "lehmann",
    "schulz",
    "schulze",
    "wald",
    "stein",
    "feld",
    "bach",
    "brunner",
    "sommer",
    "winter",
    "herbst",
    "frühling",
    "montag",
    "freitag",
    "sonntag",
    "morgen",
    "abend",
    "licht",
    "kraft",
    "stark",
    "gut",
    "gute",
    "reich",
    "arm",
    "engel",
    "ritter",
    "graf",
    "fürst",
    "kaufmann",
    "krämer",
    "schuster",
    "zimmermann",
    "hauser",
    "haus",
    "garten",
    "blume",
    "rose",
    "linde",
    "eiche",
    "birke",
    "buche",
    "tanne",
    "ahorn",
    "adler",
    "falke",
    "taube",
    "lamm",
    "hirsch",
    "bär",
    "baer",
    "löwe",
    "loewe",
    "strauss",
    "strauß",
    "vogt",
    "amann",
    "mann",
    "kind",
    "ende",
    "anfang",
    "mitte",
    "neu",
    "neue",
    "erste",
    "letzte",
    "hell",
    "dunkel",
    "still",
];

/// Frequent function words in both languages.
const FUNCTION_WORDS: &[&str] = &[
    "und", "oder", "aber", "nicht", "eine", "einer", "einem", "einen", "eines", "dies", "diese",
    "dieser", "dieses", "sehr", "auch", "noch", "schon", "wenn", "dann", "dass", "the", "and",
    "for", "with", "this", "that", "from", "have", "your", "please", "thanks", "dear", "best",
    "regards", "hello", "hallo", "sehr", "geehrte", "geehrter", "liebe", "lieber", "grüße",
    "gruesse", "danke", "bitte", "herr", "frau", "firma", "team",
];

/// Closed-class function words (pronouns, articles, prepositions,
/// conjunctions) in both languages, never nouns (L3 step 2, rulings L44
/// and re-review 3 I2). Recall first: a word that is also a plausible
/// first name or surname is left out, so a name is never dismissed as a
/// function word. Left out for that reason:
/// - first names the gazetteer knows: `you`, `him`, `mine`, `per`, `mir`;
/// - DACH or English surnames and given names: `weil`, `meiner`, `des`,
///   `das`; name particles (`der`, `den`, `von`, `vom`, `zum`, `zur`, `am`),
///   which would end an all-lower-case name (`herr von weizsäcker`,
///   ruling L47);
/// - Korean, Chinese, Vietnamese short surnames: `he`, `an`, `du`, `so`,
///   `im`, `um`, `in`, `on`, `her` (Hmong), `my`, `to`, `than`, `bei`, `zu`.
#[rustfmt::skip]
const CLOSED_CLASS_WORDS: &[&str] = &[
    // English pronouns and articles
    "i", "she", "it", "we", "they", "me", "us", "them", "our", "their", "his", "its", "yours",
    "ours", "theirs", "these", "those", "who", "whom", "whose", "which", "what", "a",
    // English prepositions
    "about", "above", "after", "against", "at", "before", "behind", "below", "between", "by",
    "during", "into", "of", "off", "onto", "over", "since", "through", "toward", "towards",
    "under", "until", "upon", "within", "without", "via",
    // English conjunctions
    "but", "or", "nor", "yet", "because", "although", "though", "if", "unless", "while", "whereas",
    "whether", "as",
    // German articles and pronouns
    "die", "dem", "ein", "ich", "er", "sie", "es", "wir", "ihr", "mich", "dich", "sich", "uns",
    "euch", "ihn", "ihm", "ihnen", "dir", "mein", "meine", "meinen", "meinem", "dein", "deine",
    "sein", "seine", "ihre", "ihren", "unser", "unsere", "euer",
    // German prepositions
    "auf", "aus", "bis", "durch", "für", "fuer", "gegen", "hinter", "mit", "nach", "neben", "ohne",
    "seit", "über", "ueber", "unter", "vor", "während", "waehrend", "wegen", "zwischen", "beim",
    // German conjunctions
    "denn", "sondern", "als", "ob", "obwohl", "damit", "sobald", "bevor", "nachdem", "sowie",
    "falls", "doch",
];

/// Single-word sign-off abbreviations (`LG`, `MfG`). The one shared list:
/// [`is_sign_off_abbreviation`] reads it.
pub const SIGN_OFF_ABBREVIATIONS: &[&str] = &["lg", "vg", "mfg", "glg", "bg"];

/// True when `word` (case-insensitive) is a single-word sign-off
/// abbreviation such as `LG` or `MfG`.
pub fn is_sign_off_abbreviation(word: &str) -> bool {
    let w = word.trim().to_lowercase();
    SIGN_OFF_ABBREVIATIONS.contains(&w.as_str())
}

/// Greeting and honorific targets that are not names.
const GREETING_TARGETS: &[&str] = &[
    "damen",
    "herren",
    "zusammen",
    "alle",
    "welt",
    "support",
    "kunde",
    "kundin",
    "kunden",
    "kundenservice",
    "doktor",
    "ober",
    "kollegen",
    "kolleginnen",
    "mitarbeiter",
    "sir",
    "madam",
    "everyone",
    "all",
    "colleagues",
    "customer",
    "service",
    "wishes",
    "mate",
];

/// First names that are ordinary words.
const ORDINARY_FIRST_NAMES: &[&str] = &["ernst", "mai"];

/// Words a salutation or sign-off line is made of. Shared by the verifier's
/// salutation filter and the sanitizer's multi-line piece drop; it is
/// deliberately a separate list from the common words above, so adding a
/// word here never changes what the stoplist rejects as a name.
const SALUTATION_WORDS: &[&str] = &[
    "hallo",
    "hello",
    "hi",
    "hey",
    "servus",
    "moin",
    "dear",
    "liebe",
    "lieber",
    "liebes",
    "sehr",
    "geehrte",
    "geehrter",
    "geehrtes",
    "guten",
    "grüß",
    "grüße",
    "gruß",
    "danke",
    "thanks",
    "regards",
    "team",
    "support",
    "damen",
    "herren",
    "kundenservice",
    "there",
    "all",
    "zusammen",
    "alle",
];

static SET: LazyLock<HashSet<String>> = LazyLock::new(|| {
    [
        NAME_WORDS_EN,
        NAME_WORDS_DE,
        FUNCTION_WORDS,
        CLOSED_CLASS_WORDS,
        GREETING_TARGETS,
        ORDINARY_FIRST_NAMES,
    ]
    .into_iter()
    .flatten()
    .map(|w| w.to_lowercase())
    .collect()
});

static NAME_LIKE: LazyLock<HashSet<String>> = LazyLock::new(|| {
    [NAME_WORDS_EN, NAME_WORDS_DE, ORDINARY_FIRST_NAMES]
        .into_iter()
        .flatten()
        .map(|w| w.to_lowercase())
        .collect()
});

static SALUTATION: LazyLock<HashSet<String>> =
    LazyLock::new(|| SALUTATION_WORDS.iter().map(|w| w.to_lowercase()).collect());

/// True when `word` (case-insensitive) is an ordinary word or ambiguous surname.
pub fn is_common_word(word: &str) -> bool {
    SET.contains(&word.trim().to_lowercase())
}

/// The common words that are not name-like (`is_common_word &&
/// !is_name_like_word`), lowercased: the list the verifier's home-login
/// check copies for its slashless `~word` rule (ruling L3-30). Test only.
#[cfg(test)]
pub(crate) fn common_non_name_like_words() -> std::collections::BTreeSet<String> {
    SET.difference(&NAME_LIKE).cloned().collect()
}

/// True when `word` (case-insensitive) is a common word that is also a
/// plausible name or surname (`Rose`, `May`, `Hunter`, `Ernst`), as opposed
/// to a function word or a greeting target (`Team`, `Kundenservice`). A
/// detector with a strong positional cue, such as a sign-off line, may accept
/// these where a bare dictionary hit may not.
pub fn is_name_like_word(word: &str) -> bool {
    NAME_LIKE.contains(&word.trim().to_lowercase())
}

/// True when `word` (case-insensitive, non-alphanumerics trimmed from both
/// ends) is part of a salutation or sign-off (`Hallo`, `Grüße`, `Team`).
pub fn is_salutation_word(word: &str) -> bool {
    SALUTATION.contains(
        &word
            .trim_matches(|c: char| !c.is_alphanumeric())
            .to_lowercase(),
    )
}

/// Contact- and payment-field labels: the word that opens a contact line
/// in a signature block or a form (`Tel.`, `E-Mail:`, `www.`, `UID`,
/// `IBAN`). Never a name candidate. The one shared list (L3 step 2,
/// integrator ruling in Task 9): the retry guard's signature-label test
/// and the verifier's role/label filter both read it through
/// [`is_contact_field_label`]. Each caller decides how much context it
/// asks for: the retry guard counts a label only in label use (`Handy
/// 0664 …`, never `Handy` alone, which may be a surname); the verifier
/// leaves out [`LABELS_ALSO_NAMES`].
pub const CONTACT_FIELD_LABELS: &[&str] = &[
    "tel", "telefon", "fax", "mobil", "mobile", "phone", "handy", "email", "e-mail", "mail", "web",
    "www", "internet", "adresse", "address", "ust-id", "uid", "iban", "bic",
];

/// True when `word` (case-insensitive, non-alphanumerics trimmed from both
/// ends: `Tel.`, `E-Mail:`) is a contact- or payment-field label.
pub fn is_contact_field_label(word: &str) -> bool {
    let w = word
        .trim_matches(|c: char| !c.is_alphanumeric())
        .to_lowercase();
    CONTACT_FIELD_LABELS.contains(&w.as_str())
}

/// Contact-field labels that are also names: `Handy` (surname, W. C.
/// Handy), `Iban` (Basque given name), `Bic` (surname, Bič). The
/// verifier's role/label filter never drops a hit made of one: next to a
/// token it is the shape of a name the sanitizer missed
/// (`<PERSON_ab12> Handy`). Recall first (Task 9 fix round 1).
const LABELS_ALSO_NAMES: &[&str] = &["handy", "iban", "bic"];

/// Role nouns and form-field labels a model reads as a name next to a
/// placeholder (`Meine Nachbarin <PERSON_ab12>`, `Kundennummer
/// <CUSTOMER_ID_ab12>`). Recall first (Task 9 fix round 1): a word that
/// is also a plausible surname or first name is left out, so `Nachbar`
/// (surname) and `holder` (`Account holder`; Holder is a surname) are not
/// here; the brief's `account` stays (no name).
const ROLE_OR_LABEL_WORDS: &[&str] = &[
    "nachbarin",
    "mitbewohner",
    "mitbewohnerin",
    "techniker",
    "technikerin",
    "technician",
    "neighbour",
    "neighbor",
    "flatmate",
    "kundennummer",
    "kundennr",
    "name",
    "vorname",
    "nachname",
    "kontoinhaber",
    "kontoinhaberin",
    "account",
    "straße",
    "strasse",
    "anschrift",
];

/// True when `word` (case-insensitive, non-alphanumerics trimmed from both
/// ends) is a role noun or field label (`Nachbarin`, `Kundennummer`,
/// `Tel.`): a contact-field label other than one that is also a name,
/// or a word of [`ROLE_OR_LABEL_WORDS`]. Not part of [`is_common_word`]:
/// the verifier uses it only for a hit right next to a placeholder.
pub fn is_role_or_label_word(word: &str) -> bool {
    let w = word
        .trim_matches(|c: char| !c.is_alphanumeric())
        .to_lowercase();
    ROLE_OR_LABEL_WORDS.contains(&w.as_str())
        || (is_contact_field_label(&w) && !LABELS_ALSO_NAMES.contains(&w.as_str()))
}

/// Company legal forms (`GmbH`, `AG`, `Ltd`): never a person name part
/// (mails5-diag S4). A PERSON value minted over a company line
/// (`Huber Bau GmbH`) must not make every later `GmbH` a leak. Words that
/// are also plausible names are left out (`sa`, `co`, `se`, `og` are short
/// surnames or given names in some languages, and the name-part filters
/// already skip words under three or four characters).
const LEGAL_FORMS: &[&str] = &[
    "gmbh", "ag", "kg", "gesmbh", "eu", "ohg", "gbr", "ug", "ltd", "inc", "llc", "plc", "corp",
    "sarl", "bv", "nv",
];

/// True when `word` (case-insensitive, non-alphanumerics trimmed from both
/// ends, inner dots removed: `e.U.`, `Ltd.`) is a company legal form.
pub fn is_legal_form(word: &str) -> bool {
    let w: String = word
        .trim_matches(|c: char| !c.is_alphanumeric())
        .chars()
        .filter(|c| *c != '.')
        .flat_map(char::to_lowercase)
        .collect();
    LEGAL_FORMS.contains(&w.as_str())
}

/// Parts of a full name that are safe to match on their own:
/// at least four characters, not a common word, not a legal form.
pub fn name_parts(full: &str) -> impl Iterator<Item = &str> {
    full.split_whitespace()
        .map(|p| p.trim_matches(|c: char| !c.is_alphanumeric()))
        .filter(|p| p.chars().count() >= 4 && !is_common_word(p) && !is_legal_form(p))
}

#[cfg(test)]
mod tests {
    /// Re-review 3, I2: the closed-class additions hold no plausible
    /// surname or first name (DACH, English, Korean, Chinese, Vietnamese).
    #[test]
    fn closed_class_words_hold_no_plausible_names() {
        for w in [
            "weil", "im", "um", "meiner", "in", "her", "my", "to", "on", "than", "des", "bei",
            "zu", "he", "an", "du", "so", "you", "him", "mine", "per", "mir", "das", "den", "der",
            "von", "vom", "zum", "zur", "am",
        ] {
            assert!(!is_common_word(w), "{w}");
        }
        for w in ["we", "die", "und", "für", "obwohl"] {
            assert!(is_common_word(w), "{w}");
        }
    }

    use super::*;
    #[test]
    fn common_words() {
        for w in [
            "May", "rose", "Hunter", "will", "Berg", "König", "und", "the", "SUMMER",
        ] {
            assert!(is_common_word(w), "{w}");
        }
        for w in ["Leitner", "Gruber", "Müller", "Huber"] {
            assert!(!is_common_word(w), "{w}");
        }
    }
    #[test]
    fn name_parts_filters_short_and_common() {
        let parts: Vec<_> = name_parts("Dr. Sarah May Leitner").collect();
        assert_eq!(parts, vec!["Sarah", "Leitner"]);
    }

    #[test]
    fn greeting_targets_and_ambiguous_first_names_are_common_words() {
        for w in [
            "Team",
            "Damen",
            "Herren",
            "zusammen",
            "alle",
            "Welt",
            "Support",
            "Kunde",
            "Kundin",
            "Kundenservice",
            "Doktor",
            "Ober",
            "Ernst",
            "Mai",
            "Sir",
            "Madam",
            "Wishes",
            "Mate",
        ] {
            assert!(is_common_word(w), "{w}");
        }
        assert!(!is_common_word("Sarah"));
    }

    #[test]
    fn name_like_and_salutation_lists() {
        for w in ["Rose", "May", "Hunter", "SUMMER", "Berg", "Ernst", "Mai"] {
            assert!(is_name_like_word(w), "{w}");
            assert!(is_common_word(w), "{w}");
        }
        for w in ["Team", "Kundenservice", "Support", "und", "Frau", "Sarah"] {
            assert!(!is_name_like_word(w), "{w}");
        }
        for w in ["Hallo,", "Grüße", "Team", "alle!", "Kundenservice", "Dear"] {
            assert!(is_salutation_word(w), "{w}");
        }
        for w in ["Rose", "Sarah", "Morgen", "Gott", "Tag", "Support-Team", ""] {
            assert!(!is_salutation_word(w), "{w}");
        }
    }

    /// Task 9: contact-field labels and role words; a label that is also a
    /// surname is a label for the retry guard's word list but never for the
    /// verifier's role filter; none of them is a common word.
    #[test]
    fn contact_labels_and_role_words() {
        for w in [
            "Tel.", "telefon", "E-Mail:", "UST-ID", "UID", "IBAN", "bic", "www", "Handy",
        ] {
            assert!(is_contact_field_label(w), "{w}");
        }
        for w in [
            "Nachbarin",
            "Kundennummer",
            "Tel.",
            "E-Mail",
            "UID",
            "Account",
        ] {
            assert!(is_role_or_label_word(w), "{w}");
        }
        for w in [
            "Handy", "Holder", "Nachbar", "IBAN", "Bic", "Huber", "Sarah", "",
        ] {
            assert!(!is_role_or_label_word(w), "{w}");
        }
        for w in ["Iban", "Handy", "Nachbar", "Name", "UID"] {
            assert!(!is_common_word(w), "{w}");
        }
    }

    /// mails5-diag S4: a legal form is never a person name part, so a
    /// PERSON value minted over a company line (`Huber Bau GmbH`) does not
    /// turn every `GmbH` into a leak.
    #[test]
    fn legal_forms_are_not_name_parts() {
        let parts: Vec<&str> = name_parts("Huber Bau GmbH").collect();
        assert_eq!(parts, ["Huber"]);
        for f in ["GmbH", "gesmbh", "Corp.", "SARL", "e.U.", "OHG", "Ltd."] {
            assert!(is_legal_form(f), "{f}");
        }
        for w in ["Huber", "Anna", "Gruber"] {
            assert!(!is_legal_form(w), "{w}");
        }
        let link: Vec<String> = crate::link::name_parts_of("Huber Bau GmbH")
            .iter()
            .map(|p| p.key.as_str().to_string())
            .collect();
        assert_eq!(link, ["huber"]);
    }
}
