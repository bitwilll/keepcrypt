//! C and D as the device shows them (docs/pi-firmware.md steps 5 and 14; tasks/todo.md, M3
//! group 6): 32 bytes as 16 groups of 4 lowercase hex digits, four groups to a row, for a
//! `screen::Item::Hex`. verify.py reads them back as typed: it drops spaces, tabs and hyphens and
//! takes the 64 hex digits left (`parse_hex32`).
//!
//! D is a secret (rule 5): the text is built in a `Zeroizing` buffer of its final length, so no
//! reallocation leaves a copy behind, and each digit is read by nibble, with no integer cast.

use zeroize::Zeroizing;

/// The lowercase hex digits, by nibble.
const DIGITS: &[u8; 16] = b"0123456789abcdef";
/// Two bytes, four digits, to a group.
const BYTES_PER_GROUP: usize = 2;
/// Four groups, eight bytes, to a row.
const BYTES_PER_ROW: usize = 4 * BYTES_PER_GROUP;
/// 64 digits, a space between groups in a row and a line feed between rows: 15 separators.
const TEXT_LEN: usize = 64 + 15;

/// `bytes` as 16 groups of 4 lowercase hex digits: a space between the groups of a row, a line
/// feed between the four rows.
pub fn hex_groups(bytes: &[u8; 32]) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(TEXT_LEN));
    for (i, &byte) in bytes.iter().enumerate() {
        if i % BYTES_PER_ROW == 0 && i > 0 {
            text.push('\n');
        } else if i % BYTES_PER_GROUP == 0 && i > 0 {
            text.push(' ');
        }
        text.push(digit(byte >> 4));
        text.push(digit(byte & 0x0f));
    }
    text
}

/// The hex digit of the low nibble of `nibble`.
fn digit(nibble: u8) -> char {
    char::from(DIGITS[usize::from(nibble & 0x0f)])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// verify.py's `parse_hex32`: refuse any non-ASCII character, drop spaces, tabs and hyphens,
    /// refuse anything else that is not a hex digit, and take exactly 64 digits, in either case.
    fn parse_hex32(text: &str) -> Option<[u8; 32]> {
        if !text.is_ascii() {
            return None;
        }
        let mut digits = Vec::new();
        for c in text.chars() {
            match c {
                ' ' | '\t' | '-' => {}
                c if c.is_ascii_hexdigit() => digits.push(c.to_digit(16)?),
                _ => return None,
            }
        }
        if digits.len() != 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        for (byte, &[high, low]) in bytes.iter_mut().zip(digits.as_chunks::<2>().0) {
            *byte = match u8::try_from(high << 4 | low) {
                Ok(byte) => byte,
                Err(_) => return None,
            };
        }
        Some(bytes)
    }

    #[test]
    fn the_d_00_1f_specimen_reads_as_16_groups_in_4_rows() {
        let d: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).expect("below 32"));
        let text = hex_groups(&d);
        assert_eq!(
            text.as_str(),
            "0001 0203 0405 0607\n0809 0a0b 0c0d 0e0f\n1011 1213 1415 1617\n1819 1a1b 1c1d 1e1f"
        );
        // Built in place: the buffer never grew, so no reallocation left a copy of D behind.
        assert_eq!(text.len(), TEXT_LEN);
        assert_eq!(text.capacity(), TEXT_LEN);
    }

    #[test]
    fn every_byte_round_trips_through_verify_py_s_rule() {
        // Each of the 256 byte values, in 8 buffers of 32 consecutive values.
        for start in (0..=255u8).step_by(32) {
            let bytes: [u8; 32] =
                core::array::from_fn(|i| start.wrapping_add(u8::try_from(i).expect("below 32")));
            let text = hex_groups(&bytes);
            let shown = |b: u8| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b' ' | b'\n');
            assert!(text.bytes().all(shown));
            // The user types the four rows on one line, as verify.py asks for C and D.
            let typed = text.replace('\n', " ");
            assert_eq!(parse_hex32(&typed), Some(bytes));
            // verify.py takes upper case, and hyphens or tabs between groups, too.
            assert_eq!(
                parse_hex32(&typed.to_uppercase().replace(' ', "-")),
                Some(bytes)
            );
        }
        // A missing digit, an extra one or a row break is refused.
        let typed = hex_groups(&[0xab; 32]).replace('\n', " ");
        assert_eq!(parse_hex32(&typed[1..]), None);
        assert_eq!(parse_hex32(&format!("{typed}0")), None);
        assert_eq!(parse_hex32(&hex_groups(&[0xab; 32])), None);
    }
}
