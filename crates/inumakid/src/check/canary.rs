//! The canary identity: an invented name, an Austrian IBAN with valid check
//! digits, and an email under `example.invalid`. The lists hold made-up
//! names that are not real first or last names, so a check can never
//! collide with a user's data and a hit is always a leak of the canary.

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

// Invented: none is a first name, surname, or place in any common list.
const FIRST: &[&str] = &[
    "Qwendolin",
    "Yrsabel",
    "Zoltrand",
    "Vexmira",
    "Zirravel",
    "Pellqwyn",
    "Xandrila",
    "Quorwin",
];
const LAST: &[&str] = &[
    "Zyxwuria",
    "Quolnath",
    "Vrintoss",
    "Kelmqvorst",
    "Yvendrak",
    "Pexwold",
    "Grumvael",
    "Thwarnquix",
];

/// The synthetic identity of one check. `Debug` prints nothing.
#[derive(Clone, Serialize, Deserialize)]
pub struct Canary {
    /// First name.
    pub first: String,
    /// Last name.
    pub last: String,
    /// IBAN in groups of four.
    pub iban: String,
    /// Email address.
    pub email: String,
}

impl std::fmt::Debug for Canary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Canary(..)")
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    // A failing system RNG is not recoverable for a check; the fallback
    // (zeros) still yields a valid, synthetic identity.
    let _ = getrandom::fill(&mut b);
    b
}

/// `AT` + check digits + `bban` (16 digits: bank code 5, account 11), in groups of four.
pub fn iban_at(bban: &str) -> String {
    let m = mod97(&format!("{bban}AT00"));
    let compact = format!("AT{:02}{bban}", 98 - m);
    compact
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ")
}

fn mod97(s: &str) -> u32 {
    let mut m = 0u32;
    for c in s.chars() {
        match c.to_digit(36) {
            Some(v) if v >= 10 => m = (m * 100 + v) % 97,
            Some(v) => m = (m * 10 + v) % 97,
            None => {}
        }
    }
    m
}

/// ISO 13616 check (spaces ignored, letters upper case).
pub fn iban_valid(iban: &str) -> bool {
    let s: String = iban
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();
    s.len() > 4 && s.is_ascii() && mod97(&format!("{}{}", &s[4..], &s[..4])) == 1
}

fn fold(s: &str) -> String {
    s.nfc().collect::<String>().to_lowercase()
}

fn squash(s: &str) -> String {
    fold(s).chars().filter(|c| !c.is_whitespace()).collect()
}

impl Canary {
    /// A fresh identity.
    pub fn generate() -> Canary {
        let r = random::<12>();
        let first = FIRST[r[0] as usize % FIRST.len()].to_string();
        let last = LAST[r[1] as usize % LAST.len()].to_string();
        let digits: String = r[2..10].iter().map(|b| format!("{:02}", b % 100)).collect();
        let tag: String = r[10..12].iter().map(|b| format!("{b:02x}")).collect();
        Canary {
            email: format!(
                "{}.{}@{tag}.example.invalid",
                first.to_lowercase(),
                last.to_lowercase()
            ),
            iban: iban_at(&digits),
            first,
            last,
        }
    }

    /// "First Last".
    pub fn full_name(&self) -> String {
        format!("{} {}", self.first, self.last)
    }

    /// The IBAN without spaces.
    pub fn iban_compact(&self) -> String {
        self.iban.replace(' ', "")
    }

    /// The 11-digit account number inside the IBAN (after `AT`, check digits, bank code).
    pub fn account(&self) -> String {
        self.iban_compact().chars().skip(9).collect()
    }

    /// Any canary value in `text`: either name component, the email, the
    /// IBAN with or without spaces, or its account digits alone (a partial
    /// IBAN leak), after NFC and lower-casing (spec §8.3).
    pub fn appears_in(&self, text: &str) -> bool {
        let t = fold(text);
        let sq = squash(text);
        t.contains(&fold(&self.first))
            || t.contains(&fold(&self.last))
            || t.contains(&fold(&self.email))
            || sq.contains(&squash(&self.iban))
            || sq.contains(&self.account())
    }

    /// The full name and the IBAN are both in `text`: the tokens were restored.
    pub fn restored_in(&self, text: &str) -> bool {
        fold(text).contains(&fold(&self.full_name())) && squash(text).contains(&squash(&self.iban))
    }
}
