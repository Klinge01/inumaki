//! Spans, entity kinds, and detector identities. A [`Span`] never carries text.

/// Which detector produced a span. Order of `priority` decides overlap resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DetectorId {
    /// Credential and secret patterns.
    Secrets,
    /// Regex matches validated by checksum or parser (IBAN, card, IDs, email, IP, URL).
    RegexValidated,
    /// Configured domain patterns and label triggers.
    Domain,
    /// Known business data (names, addresses, organizations).
    Dictionary,
    /// Regex matches with syntax only (phone, plates, dates, postal codes).
    RegexSyntax,
    /// Statistical named entity recognition.
    Ner,
    /// Greeting, sign-off, and honorific anchors (plan 4a).
    Anchor,
    /// The name linker's emitted mentions (plan 4a).
    Link,
    /// A span the user marked explicitly (M4 spec §9.1). Wins every overlap.
    Redaction,
    /// A name by its position in structured text: a path or URL component,
    /// a table column or a person label (ruling S9; see
    /// [`crate::detect::path_names`]).
    Position,
}

impl DetectorId {
    /// Higher wins when spans overlap.
    pub fn priority(self) -> u8 {
        match self {
            DetectorId::Redaction => 7,
            DetectorId::Secrets => 6,
            DetectorId::RegexValidated => 5,
            DetectorId::Domain => 4,
            DetectorId::Dictionary => 3,
            DetectorId::RegexSyntax => 2,
            DetectorId::Ner | DetectorId::Anchor | DetectorId::Link | DetectorId::Position => 1,
        }
    }
}

/// Sub-kind of a detected secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum SecretKind {
    Aws,
    GitHub,
    Slack,
    Google,
    Stripe,
    Jwt,
    PrivateKey,
    ConnectionString,
    Bearer,
    Generic,
}

/// Category of a detected entity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum EntityKind {
    Person,
    Email,
    Phone,
    StreetAddress,
    City,
    PostalCode,
    Country,
    Organization,
    Iban,
    CreditCard,
    IpAddress,
    Url,
    Date,
    DateOfBirth,
    NationalId,
    TaxId,
    LicensePlate,
    CustomerId,
    ContractId,
    InvoiceId,
    /// A credential. All secrets share the label `SECRET`.
    Secret(SecretKind),
    /// A kind defined by configuration. Stored upper-cased.
    Custom(String),
}

impl EntityKind {
    /// Build a custom kind; the name is upper-cased.
    pub fn custom(name: &str) -> Self {
        EntityKind::Custom(name.trim().to_uppercase())
    }

    /// Stable upper-case label used in tokens and configuration keys.
    pub fn label(&self) -> &str {
        match self {
            EntityKind::Person => "PERSON",
            EntityKind::Email => "EMAIL",
            EntityKind::Phone => "PHONE",
            EntityKind::StreetAddress => "STREET_ADDRESS",
            EntityKind::City => "CITY",
            EntityKind::PostalCode => "POSTAL_CODE",
            EntityKind::Country => "COUNTRY",
            EntityKind::Organization => "ORGANIZATION",
            EntityKind::Iban => "IBAN",
            EntityKind::CreditCard => "CREDIT_CARD",
            EntityKind::IpAddress => "IP_ADDRESS",
            EntityKind::Url => "URL",
            EntityKind::Date => "DATE",
            EntityKind::DateOfBirth => "DATE_OF_BIRTH",
            EntityKind::NationalId => "NATIONAL_ID",
            EntityKind::TaxId => "TAX_ID",
            EntityKind::LicensePlate => "LICENSE_PLATE",
            EntityKind::CustomerId => "CUSTOMER_ID",
            EntityKind::ContractId => "CONTRACT_ID",
            EntityKind::InvoiceId => "INVOICE_ID",
            EntityKind::Secret(_) => "SECRET",
            EntityKind::Custom(s) => s.as_str(),
        }
    }

    /// Parse a label. Unknown labels become [`EntityKind::Custom`].
    pub fn from_label(label: &str) -> Self {
        match label.trim().to_uppercase().as_str() {
            "PERSON" => EntityKind::Person,
            "EMAIL" => EntityKind::Email,
            "PHONE" => EntityKind::Phone,
            "STREET_ADDRESS" => EntityKind::StreetAddress,
            "CITY" => EntityKind::City,
            "POSTAL_CODE" => EntityKind::PostalCode,
            "COUNTRY" => EntityKind::Country,
            "ORGANIZATION" => EntityKind::Organization,
            "IBAN" => EntityKind::Iban,
            "CREDIT_CARD" => EntityKind::CreditCard,
            "IP_ADDRESS" => EntityKind::IpAddress,
            "URL" => EntityKind::Url,
            "DATE" => EntityKind::Date,
            "DATE_OF_BIRTH" => EntityKind::DateOfBirth,
            "NATIONAL_ID" => EntityKind::NationalId,
            "TAX_ID" => EntityKind::TaxId,
            "LICENSE_PLATE" => EntityKind::LicensePlate,
            "CUSTOMER_ID" => EntityKind::CustomerId,
            "CONTRACT_ID" => EntityKind::ContractId,
            "INVOICE_ID" => EntityKind::InvoiceId,
            "SECRET" => EntityKind::Secret(SecretKind::Generic),
            other => EntityKind::Custom(other.to_string()),
        }
    }

    /// True for any credential kind.
    pub fn is_secret(&self) -> bool {
        matches!(self, EntityKind::Secret(_))
    }
}

/// Whether `label` has the one shape every kind label must have:
/// `[A-Z][A-Z_]{0,31}`. Every built-in kind fits; configuration that
/// declares a custom kind (domain recognizers, NER label maps, gateway
/// contracts, redaction files) is refused unless its label does too. No
/// digits: a label cannot carry an account or record number. The bound is
/// on shape, not meaning; a custom label is operator configuration.
pub fn valid_kind_label(label: &str) -> bool {
    (1..=32).contains(&label.len())
        && label.as_bytes()[0].is_ascii_uppercase()
        && label.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
}

/// A detected region of text. Byte offsets into the original string; no text is stored.
#[derive(Debug, Clone, PartialEq)]
pub struct Span {
    /// Byte offset of the first byte.
    pub start: usize,
    /// Byte offset one past the last byte.
    pub end: usize,
    /// Entity category.
    pub kind: EntityKind,
    /// Detector confidence in `0.0..=1.0`.
    pub confidence: f32,
    /// Detector that produced the span.
    pub source: DetectorId,
    /// The PERSON span as its detector reported it crossed a line break.
    /// Set once in detection, before any later step clips or splits the
    /// span, and kept by every piece cut from it, so the retry's fail-closed
    /// guard (see [`crate::policy::escalate_uncertain_multiline_persons`])
    /// still sees a piece of an uncertain multi-line span as such.
    pub crossed_line_break: bool,
}

impl Span {
    /// Construct a span.
    pub fn new(
        start: usize,
        end: usize,
        kind: EntityKind,
        confidence: f32,
        source: DetectorId,
    ) -> Self {
        debug_assert!(start <= end);
        Span {
            start,
            end,
            kind,
            confidence,
            source,
            crossed_line_break: false,
        }
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// True when the span is empty.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// True when the two byte ranges intersect.
    pub fn overlaps(&self, other: &Span) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// The matched text. Caller must hold the original text explicitly.
    pub fn slice<'a>(&self, text: &'a str) -> &'a str {
        &text[self.start..self.end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_round_trip() {
        for k in [
            EntityKind::Person,
            EntityKind::StreetAddress,
            EntityKind::DateOfBirth,
            EntityKind::CustomerId,
            EntityKind::Secret(SecretKind::Jwt),
            EntityKind::custom("profession"),
        ] {
            let back = EntityKind::from_label(k.label());
            match (&k, &back) {
                (EntityKind::Secret(_), EntityKind::Secret(_)) => {}
                _ => assert_eq!(k, back),
            }
        }
        assert_eq!(EntityKind::custom("profession").label(), "PROFESSION");
        assert_eq!(
            EntityKind::from_label("STREET_ADDRESS"),
            EntityKind::StreetAddress
        );
        assert_eq!(
            EntityKind::from_label("nonsense"),
            EntityKind::custom("nonsense")
        );
    }

    #[test]
    fn every_built_in_label_has_the_kind_label_shape() {
        use SecretKind as S;
        let all = [
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Phone,
            EntityKind::StreetAddress,
            EntityKind::City,
            EntityKind::PostalCode,
            EntityKind::Country,
            EntityKind::Organization,
            EntityKind::Iban,
            EntityKind::CreditCard,
            EntityKind::IpAddress,
            EntityKind::Url,
            EntityKind::Date,
            EntityKind::DateOfBirth,
            EntityKind::NationalId,
            EntityKind::TaxId,
            EntityKind::LicensePlate,
            EntityKind::CustomerId,
            EntityKind::ContractId,
            EntityKind::InvoiceId,
            EntityKind::Secret(S::Aws),
        ];
        for k in &all {
            // Adding a variant breaks this match: add it to `all` too.
            match k {
                EntityKind::Person
                | EntityKind::Email
                | EntityKind::Phone
                | EntityKind::StreetAddress
                | EntityKind::City
                | EntityKind::PostalCode
                | EntityKind::Country
                | EntityKind::Organization
                | EntityKind::Iban
                | EntityKind::CreditCard
                | EntityKind::IpAddress
                | EntityKind::Url
                | EntityKind::Date
                | EntityKind::DateOfBirth
                | EntityKind::NationalId
                | EntityKind::TaxId
                | EntityKind::LicensePlate
                | EntityKind::CustomerId
                | EntityKind::ContractId
                | EntityKind::InvoiceId
                | EntityKind::Secret(_)
                | EntityKind::Custom(_) => {}
            }
            assert!(valid_kind_label(k.label()), "{}", k.label());
        }
        for bad in ["", "person", "IBAN_AT61", "A-B", "A B", "ÄRZTIN", "_X"] {
            assert!(!valid_kind_label(bad), "{bad}");
        }
        assert!(!valid_kind_label(&"A".repeat(33)));
        assert!(valid_kind_label("METER_POINT"));
    }

    #[test]
    fn overlap_and_slice() {
        let text = "Hallo Müller!";
        let a = Span::new(6, 13, EntityKind::Person, 0.9, DetectorId::Ner);
        let b = Span::new(0, 7, EntityKind::Organization, 0.5, DetectorId::Ner);
        let c = Span::new(13, 14, EntityKind::Date, 0.5, DetectorId::RegexSyntax);
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
        assert_eq!(a.slice(text), "Müller");
        assert_eq!(a.len(), 7);
    }

    #[test]
    fn priority_order() {
        assert!(DetectorId::Secrets.priority() > DetectorId::RegexValidated.priority());
        assert!(DetectorId::RegexValidated.priority() > DetectorId::Domain.priority());
        assert!(DetectorId::Domain.priority() > DetectorId::Dictionary.priority());
        assert!(DetectorId::Dictionary.priority() > DetectorId::RegexSyntax.priority());
        assert!(DetectorId::RegexSyntax.priority() > DetectorId::Ner.priority());
        assert!(DetectorId::Redaction.priority() > DetectorId::Secrets.priority());
        assert_eq!(DetectorId::Anchor.priority(), DetectorId::Ner.priority());
        assert_eq!(DetectorId::Link.priority(), DetectorId::Ner.priority());
        assert_eq!(DetectorId::Position.priority(), DetectorId::Ner.priority());
    }

    #[test]
    fn span_debug_has_no_text_field() {
        let s = Span::new(0, 3, EntityKind::Person, 0.9, DetectorId::Ner);
        let d = format!("{s:?}");
        assert!(d.contains("start"));
        assert!(!d.contains("text"));
    }
}
