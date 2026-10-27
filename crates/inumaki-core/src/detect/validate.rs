//! Checksum and format validators for structured identifiers.
//! All functions take already-compacted input (no spaces) unless stated.

/// Keep only ASCII digits.
pub fn digits_only(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_digit()).collect()
}

fn digit_vec(s: &str) -> Option<Vec<u32>> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(s.bytes().map(|b| (b - b'0') as u32).collect())
}

/// Luhn mod-10 check over a digit string.
pub fn luhn(digits: &str) -> bool {
    let Some(d) = digit_vec(digits) else {
        return false;
    };
    let mut sum = 0;
    for (i, x) in d.iter().rev().enumerate() {
        let mut v = *x;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum % 10 == 0
}

/// Expected IBAN length per country. Countries not listed accept 15..=34.
pub fn iban_len(cc: &str) -> Option<usize> {
    Some(match cc {
        "AT" => 20,
        "BE" => 16,
        "CH" => 21,
        "CZ" => 24,
        "DE" => 22,
        "DK" => 18,
        "ES" => 24,
        "FI" => 18,
        "FR" => 27,
        "GB" => 22,
        "HU" => 28,
        "IE" => 22,
        "IT" => 27,
        "LI" => 21,
        "LU" => 20,
        "NL" => 18,
        "NO" => 15,
        "PL" => 28,
        "PT" => 25,
        "SE" => 24,
        "SI" => 19,
        "SK" => 24,
        "HR" => 21,
        "RO" => 24,
        _ => return None,
    })
}

/// IBAN mod-97 check. Input must be upper-case with no separators.
pub fn iban(compact: &str) -> bool {
    let len = compact.len();
    if !(15..=34).contains(&len) || !compact.is_ascii() {
        return false;
    }
    let cc = &compact[..2];
    if !cc.bytes().all(|b| b.is_ascii_uppercase()) {
        return false;
    }
    if let Some(expected) = iban_len(cc) {
        if len != expected {
            return false;
        }
    }
    let rearranged = format!("{}{}", &compact[4..], &compact[..4]);
    let mut rem: u32 = 0;
    for b in rearranged.bytes() {
        let vals: [Option<u32>; 2] = match b {
            b'0'..=b'9' => [Some((b - b'0') as u32), None],
            b'A'..=b'Z' => {
                let v = (b - b'A') as u32 + 10;
                [Some(v / 10), Some(v % 10)]
            }
            _ => return false,
        };
        for v in vals.into_iter().flatten() {
            rem = (rem * 10 + v) % 97;
        }
    }
    rem == 1
}

/// Austrian Sozialversicherungsnummer: 10 digits, check digit at position 4.
pub fn at_svnr(d: &str) -> bool {
    let Some(v) = digit_vec(d) else { return false };
    if v.len() != 10 {
        return false;
    }
    let weights = [3, 7, 9, 0, 5, 8, 4, 2, 1, 6];
    let sum: u32 = v.iter().zip(weights).map(|(x, w)| x * w).sum();
    sum % 11 == v[3]
}

/// German Steuer-ID: 11 digits, ISO 7064 MOD 11,10, one digit repeated 2–3 times in the first ten.
pub fn de_steuer_id(d: &str) -> bool {
    let Some(v) = digit_vec(d) else { return false };
    if v.len() != 11 || v[0] == 0 {
        return false;
    }
    let mut counts = [0u8; 10];
    for x in &v[..10] {
        counts[*x as usize] += 1;
    }
    let repeated: Vec<u8> = counts.iter().copied().filter(|c| *c > 1).collect();
    if repeated.len() != 1 || !(2..=3).contains(&repeated[0]) {
        return false;
    }
    let mut product = 10u32;
    for x in &v[..10] {
        let mut sum = (x + product) % 10;
        if sum == 0 {
            sum = 10;
        }
        product = (sum * 2) % 11;
    }
    let mut check = 11 - product;
    if check == 10 {
        check = 0;
    }
    check == v[10]
}

/// Swiss AHV number: 13 digits starting with 756, EAN-13 check digit.
pub fn ch_ahv(d: &str) -> bool {
    let Some(v) = digit_vec(d) else { return false };
    if v.len() != 13 || v[..3] != [7, 5, 6] {
        return false;
    }
    let sum: u32 = v[..12]
        .iter()
        .enumerate()
        .map(|(i, x)| if i % 2 == 0 { *x } else { x * 3 })
        .sum();
    (10 - sum % 10) % 10 == v[12]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_visa_test_number() {
        assert!(luhn("4111111111111111"));
        assert!(!luhn("4111111111111112"));
        assert!(!luhn(""));
        assert!(!luhn("12a4"));
    }

    #[test]
    fn iban_examples() {
        assert!(iban("AT611904300234573201"));
        assert!(iban("DE89370400440532013000"));
        assert!(iban("CH9300762011623852957"));
        assert!(!iban("AT611904300234573202"));
        assert!(!iban("AT61190430023457320")); // wrong length for AT
        assert!(!iban("XX00"));
    }

    #[test]
    fn austrian_svnr() {
        assert!(at_svnr("1237010180"));
        assert!(!at_svnr("1230010180"));
        assert!(!at_svnr("123701018"));
    }

    #[test]
    fn german_steuer_id() {
        assert!(de_steuer_id("86095742719"));
        assert!(!de_steuer_id("86095742718"));
        assert!(!de_steuer_id("06095742719")); // leading zero
        assert!(!de_steuer_id("12345678901")); // no repeated digit
    }

    #[test]
    fn swiss_ahv() {
        assert!(ch_ahv("7569217076985"));
        assert!(!ch_ahv("7569217076986"));
        assert!(!ch_ahv("1234567890123")); // must start with 756
    }

    #[test]
    fn strip_digits() {
        assert_eq!(digits_only("+43 660 / 123-4567"), "436601234567");
    }
}
