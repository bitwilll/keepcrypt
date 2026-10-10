//! Crockford base32 (docs/seal-watchonly-braille.md "Seal derivation spec": the alphabet
//! `0123456789ABCDEFGHJKMNPQRSTVWXYZ`), the encoding of the seal code, the Seal ID and the go-ahead
//! code.
//!
//! - `encode` reads 5-bit groups of a 32-byte digest, most significant bit first: 26 characters for
//!   the seal code's 130 bits, 8 for the Seal ID's and the go-ahead code's 40.
//! - `decode_go_ahead` reads what a user types (tasks/todo.md, M1 group 7): case-insensitive, `-` and
//!   spaces ignored, O read as 0 and I or L as 1, exactly 8 symbols. Anything else is
//!   `MalformedCode`, and the input is never echoed.

use crate::error::CheckError;

/// The 32 symbols, value 0 first.
pub(crate) const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Symbols in a go-ahead code.
pub(crate) const GO_AHEAD_SYMBOLS: usize = 8;

/// What a typed byte means in a go-ahead code.
const SKIP: u8 = 0xfe;
const INVALID: u8 = 0xff;

/// Each byte's value (0-31), `SKIP` for `-` and space, `INVALID` otherwise: both cases of every
/// symbol, and O, I and L as Crockford reads them. Built at compile time.
const DECODE: [u8; 256] = decode_table();

const fn decode_table() -> [u8; 256] {
    let mut table = [INVALID; 256];
    let mut index = 0;
    let mut byte: u8 = 0;
    while index < 256 {
        table[index] = decode_byte(byte);
        index += 1;
        byte = byte.wrapping_add(1);
    }
    table
}

/// One typed byte's meaning, case folded.
const fn decode_byte(byte: u8) -> u8 {
    let upper = byte.to_ascii_uppercase();
    match upper {
        b'O' => return 0,
        b'I' | b'L' => return 1,
        b'-' | b' ' => return SKIP,
        _ => {}
    }
    let mut index = 0;
    let mut value: u8 = 0;
    while index < ALPHABET.len() {
        if ALPHABET[index] == upper {
            return value;
        }
        index += 1;
        value += 1;
    }
    INVALID
}

/// The first `5 * N` bits of `digest`, most significant first, as `N` ASCII symbols.
pub(crate) fn encode<const N: usize>(digest: &[u8; 32]) -> [u8; N] {
    let mut out = [0u8; N];
    encode_into(digest, &mut out);
    out
}

/// `encode`, written in place: the seal code is filled this way, so no copy of it is left in a
/// temporary. `N` is at most 49, so the last group's second byte is still inside the digest
/// (checked at compile time).
pub(crate) fn encode_into<const N: usize>(digest: &[u8; 32], out: &mut [u8; N]) {
    const { assert!(5 * N + 8 <= 8 * 32, "too many symbols for a 32-byte digest") };
    for (index, symbol) in out.iter_mut().enumerate() {
        let bit = 5 * index;
        let pair = u16::from(digest[bit / 8]) << 8 | u16::from(digest[bit / 8 + 1]);
        let shift = 11 - (bit % 8);
        *symbol = ALPHABET[usize::from(pair >> shift & 0x1f)];
    }
}

/// The 40 bits a typed go-ahead code stands for, as 5 bytes, most significant first.
pub(crate) fn decode_go_ahead(typed: &str) -> Result<[u8; 5], CheckError> {
    let mut bits: u64 = 0;
    let mut symbols = 0usize;
    for byte in typed.bytes() {
        match DECODE[usize::from(byte)] {
            SKIP => {}
            INVALID => return Err(CheckError::MalformedCode),
            value => {
                if symbols == GO_AHEAD_SYMBOLS {
                    return Err(CheckError::MalformedCode);
                }
                bits = bits << 5 | u64::from(value);
                symbols += 1;
            }
        }
    }
    if symbols != GO_AHEAD_SYMBOLS {
        return Err(CheckError::MalformedCode);
    }
    let be = bits.to_be_bytes();
    Ok([be[3], be[4], be[5], be[6], be[7]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_reads_five_bits_at_a_time_most_significant_first() {
        let mut digest = [0u8; 32];
        assert_eq!(&encode::<8>(&digest), b"00000000");
        // 0b00001_00010_00011_... : the first byte 00001000 and so on.
        digest[..5].copy_from_slice(&[0x08, 0x86, 0x42, 0x98, 0xe8]);
        assert_eq!(&encode::<8>(&digest), b"12345678");
        digest[..5].copy_from_slice(&[0xff; 5]);
        assert_eq!(&encode::<8>(&digest), b"ZZZZZZZZ");
        // 26 symbols take 130 bits: the low 6 bits of byte 16 are not read.
        let mut digest = [0u8; 32];
        digest[16] = 0x3f;
        assert_eq!(&encode::<26>(&digest), b"00000000000000000000000000");
        digest[16] = 0x40;
        assert_eq!(&encode::<26>(&digest)[25..], b"1");
    }

    #[test]
    fn decode_takes_every_symbol_in_both_cases_and_the_crockford_aliases() {
        for (value, &symbol) in ALPHABET.iter().enumerate() {
            let typed: String = [char::from(symbol); 8].iter().collect();
            let want = [u8::try_from(value).expect("a symbol value"); 8];
            let mut bits: u64 = 0;
            for v in want {
                bits = bits << 5 | u64::from(v);
            }
            let be = bits.to_be_bytes();
            let expected = [be[3], be[4], be[5], be[6], be[7]];
            assert_eq!(decode_go_ahead(&typed), Ok(expected));
            assert_eq!(decode_go_ahead(&typed.to_ascii_lowercase()), Ok(expected));
        }
        assert_eq!(decode_go_ahead("OoIiLl00"), decode_go_ahead("00111100"));
        assert_eq!(
            decode_go_ahead(" CF94 - bcaj "),
            decode_go_ahead("CF94BCAJ")
        );
    }

    #[test]
    fn decode_refuses_anything_but_eight_symbols() {
        for typed in [
            "",
            "CF94BCA",
            "CF94BCAJ0",
            "CF94-BCAU",
            "CF94_BCAJ",
            "CF94\u{e9}BCA",
            "----",
            "CF94\tBCAJ",
        ] {
            assert_eq!(
                decode_go_ahead(typed),
                Err(CheckError::MalformedCode),
                "{typed:?}"
            );
        }
        // A long typed string stops at the ninth symbol.
        assert_eq!(
            decode_go_ahead(&"0".repeat(10_000)),
            Err(CheckError::MalformedCode)
        );
    }
}
