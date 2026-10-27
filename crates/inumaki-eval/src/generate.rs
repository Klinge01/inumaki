//! Deterministic synthetic support emails with exact gold spans.

use crate::corpus::{Doc, GoldSpan, default_sensitive};
use crate::data;
use crate::data_held_out;
use crate::rng::Rng;

/// Word lists and templates one generator family draws from.
pub(crate) struct Lists {
    pub first: &'static [&'static str],
    pub last: &'static [&'static str],
    pub streets: &'static [&'static str],
    pub cities: &'static [(&'static str, &'static str)],
    pub orgs: &'static [&'static str],
    pub domains: &'static [&'static str],
    pub de_greetings: &'static [&'static str],
    pub en_greetings: &'static [&'static str],
    pub de_bodies: &'static [&'static str],
    pub en_bodies: &'static [&'static str],
    pub de_closings: &'static [&'static str],
    pub en_closings: &'static [&'static str],
    pub de_signature: &'static str,
    pub en_signature: &'static str,
    pub de_quote: &'static str,
    pub en_quote: &'static str,
    /// Probability that a street value uses the `Nr. 5` house-number form.
    pub nr_form: f64,
    /// Document id prefix.
    pub id_prefix: &'static str,
}

impl Lists {
    pub(crate) fn tuning() -> Lists {
        Lists {
            first: data::FIRST_NAMES,
            last: data::LAST_NAMES,
            streets: data::STREETS,
            cities: data::CITIES,
            orgs: data::ORGS,
            domains: data::DOMAINS,
            de_greetings: data::DE_GREETINGS,
            en_greetings: data::EN_GREETINGS,
            de_bodies: data::DE_TEMPLATES,
            en_bodies: data::EN_TEMPLATES,
            de_closings: data::DE_CLOSINGS,
            en_closings: data::EN_CLOSINGS,
            de_signature: data::DE_SIGNATURE,
            en_signature: data::EN_SIGNATURE,
            de_quote: data::DE_QUOTE,
            en_quote: data::EN_QUOTE,
            nr_form: 0.0,
            id_prefix: "gen",
        }
    }

    pub(crate) fn held_out() -> Lists {
        Lists {
            first: data_held_out::FIRST_NAMES,
            last: data_held_out::LAST_NAMES,
            streets: data_held_out::STREETS,
            cities: data_held_out::CITIES,
            orgs: data_held_out::ORGS,
            domains: data_held_out::DOMAINS,
            de_greetings: data_held_out::DE_GREETINGS,
            en_greetings: data_held_out::EN_GREETINGS,
            de_bodies: data_held_out::DE_TEMPLATES,
            en_bodies: data_held_out::EN_TEMPLATES,
            de_closings: data_held_out::DE_CLOSINGS,
            en_closings: data_held_out::EN_CLOSINGS,
            de_signature: data_held_out::DE_SIGNATURE,
            en_signature: data_held_out::EN_SIGNATURE,
            de_quote: data_held_out::DE_QUOTE,
            en_quote: data_held_out::EN_QUOTE,
            nr_form: 0.15,
            id_prefix: "ho",
        }
    }
}

/// Which template and identity family a corpus is generated from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GenFamily {
    /// The tuning family (`data.rs`): the 2 000-document default corpus.
    #[default]
    Tuning,
    /// The held-out family (`data_held_out.rs`): disjoint identities and
    /// templates, never used for tuning (spec §13.1).
    HeldOut,
}

impl GenFamily {
    fn lists(self) -> Lists {
        match self {
            GenFamily::Tuning => Lists::tuning(),
            GenFamily::HeldOut => Lists::held_out(),
        }
    }

    /// Name used in report provenance.
    pub fn name(self) -> &'static str {
        match self {
            GenFamily::Tuning => "tuning",
            GenFamily::HeldOut => "held-out",
        }
    }
}

/// Seed of the pinned held-out corpus.
pub const HELD_OUT_SEED: u64 = 4242;
/// Size of the pinned held-out corpus.
pub const HELD_OUT_COUNT: usize = 200;

/// The pinned held-out corpus (spec §13.1).
pub fn held_out() -> Vec<Doc> {
    generate(&GenOptions {
        seed: HELD_OUT_SEED,
        count: HELD_OUT_COUNT,
        transforms: true,
        family: GenFamily::HeldOut,
    })
}

/// Generator options.
#[derive(Debug, Clone)]
pub struct GenOptions {
    /// Seed; the same seed always produces the same corpus.
    pub seed: u64,
    /// Number of documents.
    pub count: usize,
    /// Apply noise transforms (lower case, typos, wrapping, signatures, quotes, mixed language).
    pub transforms: bool,
    /// Template and identity family.
    pub family: GenFamily,
}

impl Default for GenOptions {
    fn default() -> Self {
        GenOptions {
            seed: 42,
            count: 2000,
            transforms: true,
            family: GenFamily::Tuning,
        }
    }
}

/// One synthetic person: the name parts and the e-mail address derived from them.
pub(crate) struct Person {
    pub(crate) first: String,
    pub(crate) last: String,
    email: String,
}

impl Person {
    /// A person with the e-mail address `person()` would build for these parts.
    pub(crate) fn new(first: &str, last: &str, domain: &str) -> Person {
        let email = format!("{}.{}@{domain}", ascii_part(first), ascii_part(last));
        Person {
            first: first.to_string(),
            last: last.to_string(),
            email,
        }
    }
}

pub(crate) struct Values {
    p: Person,
    p2: Person,
    street: String,
    zip: String,
    city: String,
    phone: String,
    iban: String,
    card: String,
    customer: String,
    contract: String,
    invoice: String,
    date: String,
    dob: String,
    org: String,
    plate: String,
}

impl Values {
    /// The customer id's digits alone, without a `K-` prefix when it has
    /// one: the `tool_json` track's `customer_id` field is a JSON number
    /// (M4 spec §16.6), so its gold value can carry no letters, unlike the
    /// mail track's `{CUSTOMER_ID}` slot, which keeps the prefix when the
    /// draw included one.
    pub(crate) fn customer_digits(&self) -> String {
        self.customer.trim_start_matches("K-").to_string()
    }

    /// The contract id (`V-########`).
    pub(crate) fn contract(&self) -> &str {
        &self.contract
    }

    /// The document date (`DD.MM.YYYY`).
    pub(crate) fn date(&self) -> &str {
        &self.date
    }
}

pub(crate) struct Builder {
    text: String,
    spans: Vec<GoldSpan>,
    lower: bool,
}

impl Builder {
    pub(crate) fn new(lower: bool) -> Self {
        Builder {
            text: String::new(),
            spans: Vec::new(),
            lower,
        }
    }

    pub(crate) fn lit(&mut self, s: &str) {
        if self.lower {
            self.text.push_str(&s.to_lowercase());
        } else {
            self.text.push_str(s);
        }
    }

    fn ent(&mut self, s: &str, kind: &str, entity: Option<&str>) {
        let start = self.text.len();
        self.lit(s);
        self.spans.push(GoldSpan {
            start,
            end: self.text.len(),
            kind: kind.to_string(),
            sensitive: default_sensitive(kind),
            entity: entity.map(str::to_string),
        });
    }

    fn slot(&mut self, name: &str, v: &Values) {
        match name {
            "PERSON" => self.ent(&format!("{} {}", v.p.first, v.p.last), "PERSON", Some("p")),
            "PERSON2" => self.ent(
                &format!("{} {}", v.p2.first, v.p2.last),
                "PERSON",
                Some("p2"),
            ),
            "FIRST" => self.ent(&v.p.first, "PERSON", Some("p")),
            "LAST" => self.ent(&v.p.last, "PERSON", Some("p")),
            "EMAIL" => self.ent(&v.p.email, "EMAIL", None),
            "EMAIL2" => self.ent(&v.p2.email, "EMAIL", None),
            "PHONE" => self.ent(&v.phone, "PHONE", None),
            "STREET" => self.ent(&v.street, "STREET_ADDRESS", None),
            "ZIP_CITY" => {
                self.ent(&v.zip, "POSTAL_CODE", None);
                self.lit(" ");
                self.ent(&v.city, "CITY", None);
            }
            "IBAN" => self.ent(&v.iban, "IBAN", None),
            "CARD" => self.ent(&v.card, "CREDIT_CARD", None),
            "CUSTOMER_ID" => self.ent(&v.customer, "CUSTOMER_ID", None),
            "CONTRACT_ID" => self.ent(&v.contract, "CONTRACT_ID", None),
            "INVOICE_ID" => self.ent(&v.invoice, "INVOICE_ID", None),
            "DATE" => self.ent(&v.date, "DATE", None),
            "DOB" => self.ent(&v.dob, "DATE_OF_BIRTH", None),
            "ORG" => self.ent(&v.org, "ORGANIZATION", None),
            "PLATE" => self.ent(&v.plate, "LICENSE_PLATE", None),
            "ADDRESS_BLOCK" => {
                self.ent(&v.street, "STREET_ADDRESS", None);
                self.lit("\n");
                self.ent(&v.zip, "POSTAL_CODE", None);
                self.lit(" ");
                self.ent(&v.city, "CITY", None);
            }
            other => panic!("unknown template slot {{{other}}}"),
        }
    }

    pub(crate) fn fill(&mut self, template: &str, v: &Values) {
        let mut rest = template;
        while let Some(i) = rest.find('{') {
            self.lit(&rest[..i]);
            let j = i + rest[i..].find('}').expect("template slot is closed");
            self.slot(&rest[i + 1..j], v);
            rest = &rest[j + 1..];
        }
        self.lit(rest);
    }

    /// Consume the builder: the built text and its gold spans. Used by
    /// generators that build one field at a time (the `tool_json` track)
    /// rather than one long document (`build_doc`'s own `Builder { text,
    /// spans, .. } = b` destructuring stays as it is).
    pub(crate) fn into_parts(self) -> (String, Vec<GoldSpan>) {
        (self.text, self.spans)
    }

    /// Consume the builder into a document (the sequence generator builds
    /// one document per step with its own id and language).
    pub(crate) fn into_doc(self, id: String, lang: &str) -> Doc {
        Doc {
            id,
            lang: lang.to_string(),
            text: self.text,
            spans: self.spans,
            why: None,
        }
    }
}

fn ascii_part(s: &str) -> String {
    let mut out = String::new();
    for c in s.to_lowercase().chars() {
        match c {
            'ä' => out.push_str("ae"),
            'ö' => out.push_str("oe"),
            'ü' => out.push_str("ue"),
            'ß' => out.push_str("ss"),
            'ç' | 'č' => out.push('c'),
            'ş' => out.push('s'),
            'ı' => out.push('i'),
            'ğ' => out.push('g'),
            c if c.is_ascii_alphanumeric() => out.push(c),
            _ => {}
        }
    }
    out
}

fn person(rng: &mut Rng, l: &Lists) -> Person {
    let first = *rng.pick(l.first);
    let last = *rng.pick(l.last);
    let domain = *rng.pick(l.domains);
    Person::new(first, last, domain)
}

fn group4(s: &str) -> String {
    s.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).expect("ASCII"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn iban(rng: &mut Rng) -> String {
    let (cc, len) = if rng.chance(0.7) {
        ("AT", 16)
    } else {
        ("DE", 18)
    };
    let bban = rng.digits(len);
    let letters: String = cc
        .chars()
        .map(|c| (c as u32 - 'A' as u32 + 10).to_string())
        .collect();
    let numeric = format!("{bban}{letters}00");
    let rem = numeric
        .bytes()
        .fold(0u32, |r, b| (r * 10 + u32::from(b - b'0')) % 97);
    group4(&format!("{cc}{:02}{bban}", 98 - rem))
}

fn card(rng: &mut Rng) -> String {
    let mut d: Vec<u32> = vec![4];
    for _ in 0..14 {
        d.push(rng.below(10) as u32);
    }
    let sum: u32 = d
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &x)| {
            if i % 2 == 0 {
                let y = x * 2;
                if y > 9 { y - 9 } else { y }
            } else {
                x
            }
        })
        .sum();
    d.push((10 - sum % 10) % 10);
    group4(
        &d.iter()
            .map(|x| char::from(b'0' + *x as u8))
            .collect::<String>(),
    )
}

fn phone(rng: &mut Rng) -> String {
    match rng.below(5) {
        0 => format!("+43 660 {}", rng.digits(7)),
        1 => format!("0664 {} {} {}", rng.digits(3), rng.digits(2), rng.digits(2)),
        2 => format!("+49 30 {}", rng.digits(8)),
        3 => format!("(01) {} {} {}", rng.digits(3), rng.digits(2), rng.digits(2)),
        _ => format!(
            "+43 (664) {} {} {}",
            rng.digits(3),
            rng.digits(2),
            rng.digits(2)
        ),
    }
}

fn date(rng: &mut Rng, from: usize, span: usize) -> String {
    format!(
        "{:02}.{:02}.{}",
        1 + rng.below(28),
        1 + rng.below(12),
        from + rng.below(span)
    )
}

pub(crate) fn values_with(rng: &mut Rng, l: &Lists) -> Values {
    let p = person(rng, l);
    let p2 = person(rng, l);
    values_for(rng, l, p, p2)
}

/// A neutral German body template: no person, first name, surname, or e-mail
/// slot, so a document built from it mentions a person only where the caller
/// adds one.
pub(crate) fn de_neutral_body(rng: &mut Rng, l: &Lists) -> &'static str {
    const PERSONAL: [&str; 6] = [
        "{PERSON}",
        "{PERSON2}",
        "{FIRST}",
        "{LAST}",
        "{EMAIL}",
        "{EMAIL2}",
    ];
    let neutral: Vec<&'static str> = l
        .de_bodies
        .iter()
        .copied()
        .filter(|t| !PERSONAL.iter().any(|slot| t.contains(slot)))
        .collect();
    neutral[rng.below(neutral.len())]
}

/// The non-person values, drawn in the same order `values_with` always drew them.
pub(crate) fn values_for(rng: &mut Rng, l: &Lists, p: Person, p2: Person) -> Values {
    // `rng.pick` then `rng.below` first, in that order, to match the draw sequence of the
    // pre-`Lists` `values()` (`format!("{} {}", rng.pick(STREETS), 1 + rng.below(120))`
    // evaluates its arguments left to right): the tuning family (`nr_form: 0.0`) must consume
    // exactly the same draws in exactly the same order it always did, since one `Rng` is
    // threaded through the whole corpus and any reordering or extra draw here reshuffles every
    // document after it. The `Nr.` decision is a genuinely new draw, so it is only ever made
    // for a family whose `nr_form` is actually positive (`l.nr_form > 0.0` short-circuits
    // `rng.chance` for the tuning family, which never reaches this branch).
    let name = rng.pick(l.streets);
    let number = 1 + rng.below(120);
    let mut street = if l.nr_form > 0.0 && rng.chance(l.nr_form) {
        format!("{name} Nr. {number}")
    } else {
        format!("{name} {number}")
    };
    if rng.chance(0.2) {
        street.push_str(&format!("/{}", 1 + rng.below(20)));
    }
    let (zip, city) = *rng.pick(l.cities);
    Values {
        p,
        p2,
        street,
        zip: zip.to_string(),
        city: city.to_string(),
        phone: phone(rng),
        iban: iban(rng),
        card: card(rng),
        customer: if rng.chance(0.5) {
            format!("K-{}", rng.digits(6))
        } else {
            rng.digits(7)
        },
        contract: format!("V-{}", rng.digits(8)),
        invoice: format!("RE-2026-{}", rng.digits(5)),
        date: date(rng, 2025, 2),
        dob: date(rng, 1940, 65),
        org: rng.pick(l.orgs).to_string(),
        plate: format!(
            "{}-{}{}",
            rng.pick(data::PLATE_PREFIXES),
            1000 + rng.below(90000),
            rng.pick(&["A", "B", "C", "X"])
        ),
    }
}

fn typos(text: &mut String, spans: &[GoldSpan], rng: &mut Rng) {
    let inside = |i: usize| spans.iter().any(|s| s.start <= i && i < s.end);
    let mut bytes = std::mem::take(text).into_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i].is_ascii_lowercase()
            && bytes[i + 1].is_ascii_lowercase()
            && !inside(i)
            && !inside(i + 1)
            && rng.chance(0.02)
        {
            bytes.swap(i, i + 1);
            i += 2;
        } else {
            i += 1;
        }
    }
    *text = String::from_utf8(bytes).expect("swapping ASCII bytes keeps UTF-8 valid");
}

/// Replaces the first space at or past column `width` on each line with a newline, in place
/// (same byte length, so gold span offsets already recorded for `text` stay valid). By design
/// this has no notion of gold span boundaries: a space inside an already-placed entity (an
/// address with a multi-word street name, say) is just as eligible as any other, so an entity
/// can end up split across two lines in the wrapped text.
fn wrap(text: &mut String, width: usize) {
    let mut bytes = std::mem::take(text).into_bytes();
    let mut col = 0usize;
    for b in &mut bytes {
        if *b == b'\n' {
            col = 0;
        } else if *b == b' ' && col >= width {
            *b = b'\n';
            col = 0;
        } else {
            col += 1;
        }
    }
    *text = String::from_utf8(bytes).expect("replacing ASCII keeps UTF-8 valid");
}

fn build_doc(rng: &mut Rng, idx: usize, transforms: bool, l: &Lists) -> Doc {
    let de = rng.chance(0.6);
    let v = values_with(rng, l);
    let mut b = Builder::new(transforms && rng.chance(0.08));
    let (greetings, bodies, closings, sig, quote, other) = if de {
        (
            l.de_greetings,
            l.de_bodies,
            l.de_closings,
            l.de_signature,
            l.de_quote,
            l.en_bodies,
        )
    } else {
        (
            l.en_greetings,
            l.en_bodies,
            l.en_closings,
            l.en_signature,
            l.en_quote,
            l.de_bodies,
        )
    };
    b.fill(rng.pick::<&str>(greetings), &v);
    b.lit("\n\n");
    b.fill(rng.pick::<&str>(bodies), &v);
    let mixed = transforms && rng.chance(0.1);
    if mixed {
        b.lit(" ");
        b.fill(rng.pick::<&str>(other), &v);
    }
    b.lit("\n\n");
    b.fill(rng.pick::<&str>(closings), &v);
    if transforms && rng.chance(0.3) {
        b.fill(sig, &v);
    }
    if transforms && rng.chance(0.25) {
        b.fill(quote, &v);
    }
    let Builder {
        mut text, spans, ..
    } = b;
    if transforms && rng.chance(0.2) {
        typos(&mut text, &spans, rng);
    }
    if transforms && rng.chance(0.2) {
        wrap(&mut text, 72);
    }
    let lang = if mixed {
        "mixed"
    } else if de {
        "de"
    } else {
        "en"
    };
    Doc {
        id: format!("{}-{idx:05}", l.id_prefix),
        lang: lang.to_string(),
        text,
        spans,
        why: None,
    }
}

/// Generate `opts.count` documents from `opts.seed`.
pub fn generate(opts: &GenOptions) -> Vec<Doc> {
    let mut rng = Rng::new(opts.seed);
    let l = opts.family.lists();
    (0..opts.count)
        .map(|i| build_doc(&mut rng, i, opts.transforms, &l))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use inumaki_core::detect::validate;

    fn opts(seed: u64, count: usize) -> GenOptions {
        GenOptions {
            seed,
            count,
            transforms: true,
            family: GenFamily::Tuning,
        }
    }

    #[test]
    fn person_gold_spans_carry_entity_ids_and_are_not_serialized() {
        let docs = generate(&opts(3, 200));
        let with_two = docs.iter().find(|d| {
            d.spans
                .iter()
                .filter(|s| s.kind == "PERSON" && s.entity.as_deref() == Some("p"))
                .count()
                >= 2
        });
        assert!(
            with_two.is_some(),
            "some document mentions the sender twice"
        );
        assert!(
            docs.iter()
                .flat_map(|d| &d.spans)
                .filter(|s| s.kind == "PERSON")
                .all(|s| matches!(s.entity.as_deref(), Some("p" | "p2")))
        );
        assert!(
            docs.iter()
                .flat_map(|d| &d.spans)
                .filter(|s| s.kind != "PERSON")
                .all(|s| s.entity.is_none())
        );
        assert!(
            !serde_json::to_string(&docs[0]).unwrap().contains("entity"),
            "not serialized: corpus digests stay pinned"
        );
    }

    #[test]
    fn same_seed_same_corpus_different_seed_different_corpus() {
        assert_eq!(generate(&opts(7, 50)), generate(&opts(7, 50)));
        assert_ne!(generate(&opts(7, 50)), generate(&opts(8, 50)));
    }

    #[test]
    fn every_doc_is_valid_and_spans_are_non_empty() {
        let docs = generate(&opts(3, 500));
        assert_eq!(docs.len(), 500);
        for d in &docs {
            d.validate().unwrap_or_else(|e| panic!("{e}"));
            assert!(!d.spans.is_empty(), "{}", d.id);
        }
    }

    #[test]
    fn generated_ibans_and_cards_are_valid() {
        let docs = generate(&opts(11, 400));
        let (mut ibans, mut cards) = (0, 0);
        for d in &docs {
            for s in &d.spans {
                let v = &d.text[s.start..s.end];
                match s.kind.as_str() {
                    "IBAN" => {
                        ibans += 1;
                        let compact: String = v.chars().filter(|c| !c.is_whitespace()).collect();
                        assert!(validate::iban(&compact.to_uppercase()), "{v}");
                    }
                    "CREDIT_CARD" => {
                        cards += 1;
                        assert!(validate::luhn(&validate::digits_only(v)), "{v}");
                    }
                    _ => {}
                }
            }
        }
        assert!(ibans > 0 && cards > 0);
    }

    #[test]
    fn transforms_appear() {
        let docs = generate(&opts(5, 500));
        assert!(docs.iter().any(|d| d.lang == "mixed"));
        assert!(
            docs.iter().any(|d| d.text.contains("\n>")),
            "quoted replies"
        );
        assert!(docs.iter().any(|d| d.text.contains("\n--\n")), "signatures");
        let plain = generate(&GenOptions {
            seed: 5,
            count: 100,
            transforms: false,
            family: GenFamily::Tuning,
        });
        assert!(
            plain
                .iter()
                .all(|d| !d.text.contains("\n>") && d.lang != "mixed")
        );
    }

    #[test]
    fn every_template_fills() {
        let lists = Lists::tuning();
        let mut rng = Rng::new(1);
        let v = values_with(&mut rng, &lists);
        for t in lists
            .de_bodies
            .iter()
            .chain(lists.en_bodies)
            .chain(lists.de_greetings)
            .chain(lists.en_greetings)
            .chain(lists.de_closings)
            .chain(lists.en_closings)
            .chain(
                [
                    lists.de_signature,
                    lists.en_signature,
                    lists.de_quote,
                    lists.en_quote,
                ]
                .iter(),
            )
        {
            let mut b = Builder::new(false);
            b.fill(t, &v); // panics on an unknown slot
        }
    }

    /// Spec §13.1: the held-out family shares no identities with the tuning family.
    #[test]
    fn held_out_lists_are_disjoint_from_tuning_lists() {
        let t = Lists::tuning();
        let h = Lists::held_out();
        fn lower(xs: &[&str]) -> std::collections::HashSet<String> {
            xs.iter().map(|s| s.to_lowercase()).collect()
        }
        for (name, a, b) in [
            ("first names", lower(t.first), lower(h.first)),
            ("last names", lower(t.last), lower(h.last)),
            ("streets", lower(t.streets), lower(h.streets)),
            ("orgs", lower(t.orgs), lower(h.orgs)),
            ("domains", lower(t.domains), lower(h.domains)),
            (
                "cities",
                t.cities.iter().map(|(_, c)| c.to_lowercase()).collect(),
                h.cities.iter().map(|(_, c)| c.to_lowercase()).collect(),
            ),
        ] {
            let shared: Vec<_> = a.intersection(&b).collect();
            assert!(shared.is_empty(), "{name} shared: {shared:?}");
        }
        let tb: std::collections::HashSet<&str> =
            t.de_bodies.iter().chain(t.en_bodies).copied().collect();
        assert!(
            h.de_bodies
                .iter()
                .chain(h.en_bodies)
                .all(|x| !tb.contains(x)),
            "templates shared"
        );
    }

    #[test]
    fn held_out_family_generates_valid_distinct_documents() {
        let docs = held_out();
        assert_eq!(docs.len(), HELD_OUT_COUNT);
        for d in &docs {
            d.validate().unwrap_or_else(|e| panic!("{e}"));
            assert!(d.id.starts_with("ho-"), "{}", d.id);
            assert!(!d.spans.is_empty(), "{}", d.id);
        }
        assert!(docs.iter().any(|d| d.lang == "de") && docs.iter().any(|d| d.lang == "en"));
        assert!(
            docs.iter().any(|d| d
                .spans
                .iter()
                .any(|s| s.kind == "STREET_ADDRESS" && d.text[s.start..s.end].contains("Nr."))),
            "some held-out addresses use the `Nr.` house-number form"
        );
        assert!(
            docs.iter()
                .any(|d| d.text.contains("Betreff:") || d.text.contains("Subject:"))
        );
        let tuning = generate(&GenOptions {
            seed: HELD_OUT_SEED,
            count: HELD_OUT_COUNT,
            transforms: true,
            family: GenFamily::Tuning,
        });
        assert_ne!(tuning, docs);
    }

    /// Review Focus 6: the held-out corpus is pinned; a generator change that
    /// alters it must be deliberate (spec revision), not silent.
    #[test]
    fn held_out_corpus_matches_pinned_digest() {
        let pinned = include_str!("../baselines/held-out.sha256").trim();
        let now = crate::corpus::digest(&held_out());
        assert_eq!(
            now, pinned,
            "held-out corpus changed; if the change is deliberate, update baselines/held-out.sha256 together with the spec's §13.1 corpus note"
        );
    }

    /// The tuning family (`nr_form: 0.0`) must draw from `Rng` in exactly the same order and
    /// count it always did: one `Rng` is threaded through the whole corpus, so a single
    /// misplaced or newly-added draw reshuffles every document after it, changing the tuning
    /// corpus (and therefore every measurement against it) without anyone asking for that.
    /// Pinned to the digest commit 75275bc produced, before the held-out family existed.
    #[test]
    fn tuning_corpus_matches_pinned_digest() {
        let pinned = include_str!("../baselines/tuning.sha256").trim();
        let now = crate::corpus::digest(&generate(&GenOptions::default()));
        assert_eq!(
            now, pinned,
            "tuning corpus changed; every document generated from seed 42 feeds the committed \
             baselines, so an intentional generator change here must re-record them (see \
             docs/quality/) and re-pin baselines/tuning.sha256, not slip through unnoticed"
        );
    }

    #[test]
    fn every_held_out_template_fills() {
        let lists = Lists::held_out();
        let mut rng = Rng::new(1);
        let v = values_with(&mut rng, &lists);
        for t in lists
            .de_bodies
            .iter()
            .chain(lists.en_bodies)
            .chain(lists.de_greetings)
            .chain(lists.en_greetings)
            .chain(lists.de_closings)
            .chain(lists.en_closings)
            .chain(
                [
                    lists.de_signature,
                    lists.en_signature,
                    lists.de_quote,
                    lists.en_quote,
                ]
                .iter(),
            )
        {
            let mut b = Builder::new(false);
            b.fill(t, &v);
        }
    }
}
