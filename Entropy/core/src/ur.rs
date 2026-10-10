//! Single-part Uniform Resources (BCR-2020-005, BCR-2020-012; tasks/todo.md, M1 group 6, Q2 and
//! Q6c): the watch-only account QR and the go-ahead proof QR.
//!
//! - A deterministic CBOR writer for the subset core needs: unsigned integers, byte strings,
//!   arrays, maps with unsigned keys, false, true and tags; every head in its shortest form,
//!   definite lengths only, map keys unique and ascending.
//! - CRC-32/ISO-HDLC from a const table, and the 256 Bytewords as a literal table.
//! - `ur_single` writes `ur:<type>/<minimal Bytewords of CBOR || CRC-32>`, lowercase. Single frame
//!   only: no fountain codes, so no PRNG (Q2).
//! - `ur_decode_single` reads one CBOR byte string back, strictly, in the order of Q6c, and stops at
//!   the first rule broken. Its errors carry no payload and never echo the input.
//!
//! vectors/watchonly.json pins all of it (RFC 8949, BCR-2020-005, -012 and -015 values, and the
//! decoder negatives); tools/verify/verify.py rebuilds the same writer and reader. The watch-only
//! export writes with it, and `verify_bucket_proof_qr` reads the go-ahead QR with it.

use crate::error::{CoreError, InternalFault, UrError};

/// The most bytes a UR may have: the largest QR alphanumeric capacity (version 40-L), in
/// characters, which are ASCII bytes.
pub(crate) const UR_MAX_CHARS: usize = 4296;

/// A CBOR item in the subset core writes.
pub(crate) enum Item<'a> {
    /// An unsigned integer (major type 0).
    Uint(u64),
    /// A byte string (major type 2).
    Bytes(&'a [u8]),
    /// An array (major type 4).
    Array(Vec<Item<'a>>),
    /// A map with unsigned keys (major type 5), written in ascending key order.
    Map(Vec<(u64, Item<'a>)>),
    /// false or true.
    Bool(bool),
    /// A tagged item (major type 6).
    Tag(u64, Box<Item<'a>>),
}

/// Deterministic CBOR of `item`. A repeated map key is `Internal(Cbor)`; a length that does not
/// fit 64 bits is `Internal(Length)`.
pub(crate) fn cbor_encode(item: &Item<'_>) -> Result<Vec<u8>, CoreError> {
    let mut out = Vec::new();
    encode_into(item, &mut out)?;
    Ok(out)
}

fn encode_into(item: &Item<'_>, out: &mut Vec<u8>) -> Result<(), CoreError> {
    match item {
        Item::Uint(n) => head(out, 0, *n),
        Item::Bytes(data) => {
            head(out, 2, length(data.len())?);
            out.extend_from_slice(data);
        }
        Item::Array(items) => {
            head(out, 4, length(items.len())?);
            for i in items {
                encode_into(i, out)?;
            }
        }
        Item::Map(entries) => {
            // Unsigned keys sort by value exactly as their shortest encodings sort bytewise.
            let mut sorted: Vec<&(u64, Item<'_>)> = entries.iter().collect();
            sorted.sort_by_key(|(key, _)| *key);
            if sorted.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(CoreError::Internal(InternalFault::Cbor));
            }
            head(out, 5, length(sorted.len())?);
            for (key, value) in sorted {
                head(out, 0, *key);
                encode_into(value, out)?;
            }
        }
        Item::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Item::Tag(tag, inner) => {
            head(out, 6, *tag);
            encode_into(inner, out)?;
        }
    }
    Ok(())
}

fn length(len: usize) -> Result<u64, CoreError> {
    u64::try_from(len).map_err(|_| CoreError::Internal(InternalFault::Length))
}

/// A head in its shortest form: the major type in the top 3 bits, then the argument.
fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    let bytes = value.to_be_bytes();
    let (info, size) = match value {
        0..=23 => (bytes[7], 0),
        24..=0xff => (24, 1),
        0x100..=0xffff => (25, 2),
        0x1_0000..=0xffff_ffff => (26, 4),
        _ => (27, 8),
    };
    out.push(major << 5 | info);
    out.extend_from_slice(&bytes[8 - size..]);
}

/// CRC-32/ISO-HDLC: reflected polynomial 0xedb88320, initial and final XOR 0xffffffff.
const CRC32_TABLE: [u32; 256] = crc32_table();

const fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    let mut value: u32 = 0;
    while i < 256 {
        let mut c = value;
        let mut bit = 0;
        while bit < 8 {
            c = if c & 1 == 1 {
                (c >> 1) ^ 0xedb8_8320
            } else {
                c >> 1
            };
            bit += 1;
        }
        table[i] = c;
        i += 1;
        value += 1;
    }
    table
}

pub(crate) fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for &byte in data {
        c = CRC32_TABLE[usize::from(c.to_le_bytes()[0] ^ byte)] ^ (c >> 8);
    }
    c ^ 0xffff_ffff
}

/// The 256 Bytewords, byte 0x00 first (BCR-2020-012 "Word List", © 2020 Blockchain Commons,
/// BSD-2-Clause-Patent). A byte's minimal form is its word's first and last letters.
const BYTEWORDS: [&str; 256] = [
    "able", "acid", "also", "apex", "aqua", "arch", "atom", "aunt", "away", "axis", "back", "bald",
    "barn", "belt", "beta", "bias", "blue", "body", "brag", "brew", "bulb", "buzz", "calm", "cash",
    "cats", "chef", "city", "claw", "code", "cola", "cook", "cost", "crux", "curl", "cusp", "cyan",
    "dark", "data", "days", "deli", "dice", "diet", "door", "down", "draw", "drop", "drum", "dull",
    "duty", "each", "easy", "echo", "edge", "epic", "even", "exam", "exit", "eyes", "fact", "fair",
    "fern", "figs", "film", "fish", "fizz", "flap", "flew", "flux", "foxy", "free", "frog", "fuel",
    "fund", "gala", "game", "gear", "gems", "gift", "girl", "glow", "good", "gray", "grim", "guru",
    "gush", "gyro", "half", "hang", "hard", "hawk", "heat", "help", "high", "hill", "holy", "hope",
    "horn", "huts", "iced", "idea", "idle", "inch", "inky", "into", "iris", "iron", "item", "jade",
    "jazz", "join", "jolt", "jowl", "judo", "jugs", "jump", "junk", "jury", "keep", "keno", "kept",
    "keys", "kick", "kiln", "king", "kite", "kiwi", "knob", "lamb", "lava", "lazy", "leaf", "legs",
    "liar", "limp", "lion", "list", "logo", "loud", "love", "luau", "luck", "lung", "main", "many",
    "math", "maze", "memo", "menu", "meow", "mild", "mint", "miss", "monk", "nail", "navy", "need",
    "news", "next", "noon", "note", "numb", "obey", "oboe", "omit", "onyx", "open", "oval", "owls",
    "paid", "part", "peck", "play", "plus", "poem", "pool", "pose", "puff", "puma", "purr", "quad",
    "quiz", "race", "ramp", "real", "redo", "rich", "road", "rock", "roof", "ruby", "ruin", "runs",
    "rust", "safe", "saga", "scar", "sets", "silk", "skew", "slot", "soap", "solo", "song", "stub",
    "surf", "swan", "taco", "task", "taxi", "tent", "tied", "time", "tiny", "toil", "tomb", "toys",
    "trip", "tuna", "twin", "ugly", "undo", "unit", "urge", "user", "vast", "very", "veto", "vial",
    "vibe", "view", "visa", "void", "vows", "wall", "wand", "warm", "wasp", "wave", "waxy", "webs",
    "what", "when", "whiz", "wolf", "work", "yank", "yawn", "yell", "yoga", "yurt", "zaps", "zero",
    "zest", "zinc", "zone", "zoom",
];

/// A word's (first, last) letters: its minimal form.
fn minimal_pair(word: &str) -> (u8, u8) {
    let letters = word.as_bytes();
    (letters[0], letters[3])
}

/// Minimal Bytewords: each byte as its word's first and last letters.
pub(crate) fn bytewords_minimal(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().saturating_mul(2));
    for &byte in data {
        let (first, last) = minimal_pair(BYTEWORDS[usize::from(byte)]);
        out.push(char::from(first));
        out.push(char::from(last));
    }
    out
}

/// A single-part UR: `ur:<type>/` and the minimal Bytewords of the CBOR followed by its CRC-32,
/// big-endian. Lowercase; QR text is the same in uppercase.
pub(crate) fn ur_single(ur_type: &str, cbor: &[u8]) -> String {
    let mut body = Vec::with_capacity(cbor.len().saturating_add(4));
    body.extend_from_slice(cbor);
    body.extend_from_slice(&crc32(cbor).to_be_bytes());
    let mut text = String::with_capacity(4 + ur_type.len() + 2 * body.len());
    text.push_str("ur:");
    text.push_str(ur_type);
    text.push('/');
    text.push_str(&bytewords_minimal(&body));
    text
}

/// The byte for each minimal pair, indexed by (first letter, last letter), both a-z.
fn minimal_index() -> [Option<u8>; 26 * 26] {
    let mut index = [None; 26 * 26];
    for (byte, word) in (0u8..=255).zip(BYTEWORDS) {
        let (first, last) = minimal_pair(word);
        index[usize::from(first - b'a') * 26 + usize::from(last - b'a')] = Some(byte);
    }
    index
}

/// Reads one single-part UR of type `expected_type` (lowercase) holding one CBOR byte string, and
/// returns that string's bytes. Strict, in this order (Q6c), stopping at the first rule broken:
///
/// 1. at most 4,296 bytes, before any decoding (`TooLong`). The text is ASCII in a QR code's
///    alphanumeric mode, one byte per character; each byte of a non-ASCII character counts, and
///    such a byte matches no later rule;
/// 2. all lowercase or all uppercase, never mixed (`MixedCase`); folded once;
/// 3. the scheme `ur:` and a `/` after the type (`NotUr`), and the type equal to `expected_type`
///    (`WrongType`);
/// 4. exactly one path segment after the type, so a multi-part `/1-3/` is refused (`MultiPart`);
/// 5. minimal Bytewords: an even number of letters (`OddLength`), every pair one of the 256
///    (`UnknownByteword`);
/// 6. at least 4 bytes, the last 4 the CRC-32 of the rest, big-endian (`BadChecksum`);
/// 7. the CBOR is one byte string (`NotByteString`, also for a reserved or cut-off head or fewer
///    bytes than the head gives) with a definite (`IndefiniteLength`), shortest-form
///    (`NonShortestHead`) head, and nothing after it (`TrailingBytes`).
pub(crate) fn ur_decode_single(expected_type: &str, text: &str) -> Result<Vec<u8>, UrError> {
    let bytes = text.as_bytes();
    if bytes.len() > UR_MAX_CHARS {
        return Err(UrError::TooLong);
    }
    if bytes.iter().any(u8::is_ascii_uppercase) && bytes.iter().any(u8::is_ascii_lowercase) {
        return Err(UrError::MixedCase);
    }
    let rest = match bytes.get(..3) {
        Some(scheme) if scheme.eq_ignore_ascii_case(b"ur:") => &bytes[3..],
        _ => return Err(UrError::NotUr),
    };
    let Some(slash) = rest.iter().position(|&b| b == b'/') else {
        return Err(UrError::NotUr);
    };
    if !rest[..slash].eq_ignore_ascii_case(expected_type.as_bytes()) {
        return Err(UrError::WrongType);
    }
    let message = &rest[slash + 1..];
    if message.contains(&b'/') {
        return Err(UrError::MultiPart);
    }
    let index = minimal_index();
    let mut data = Vec::with_capacity(message.len() / 2);
    let (pairs, odd) = message.as_chunks::<2>();
    if !odd.is_empty() {
        return Err(UrError::OddLength);
    }
    for &[first, last] in pairs {
        let (first, last) = (first.to_ascii_lowercase(), last.to_ascii_lowercase());
        if !first.is_ascii_lowercase() || !last.is_ascii_lowercase() {
            return Err(UrError::UnknownByteword);
        }
        match index[usize::from(first - b'a') * 26 + usize::from(last - b'a')] {
            Some(byte) => data.push(byte),
            None => return Err(UrError::UnknownByteword),
        }
    }
    let Some(split) = data.len().checked_sub(4) else {
        return Err(UrError::BadChecksum);
    };
    let (cbor, checksum) = data.split_at(split);
    if crc32(cbor).to_be_bytes() != checksum {
        return Err(UrError::BadChecksum);
    }
    byte_string(cbor).map(<[u8]>::to_vec)
}

/// The contents of `cbor` if it is exactly one byte string with a definite, shortest-form head.
fn byte_string(cbor: &[u8]) -> Result<&[u8], UrError> {
    let Some((&first, after)) = cbor.split_first() else {
        return Err(UrError::NotByteString);
    };
    if first >> 5 != 2 {
        return Err(UrError::NotByteString);
    }
    let (size, minimum) = match first & 0x1f {
        info @ 0..=23 => {
            return contents(after, u64::from(info));
        }
        24 => (1, 24),
        25 => (2, 0x100),
        26 => (4, 0x1_0000),
        27 => (8, 0x1_0000_0000),
        31 => return Err(UrError::IndefiniteLength),
        _ => return Err(UrError::NotByteString),
    };
    let Some(argument) = after.get(..size) else {
        return Err(UrError::NotByteString);
    };
    let mut be = [0u8; 8];
    be[8 - size..].copy_from_slice(argument);
    let len = u64::from_be_bytes(be);
    if len < minimum {
        return Err(UrError::NonShortestHead);
    }
    contents(&after[size..], len)
}

/// Exactly `len` bytes: fewer is `NotByteString`, more is `TrailingBytes`.
fn contents(rest: &[u8], len: u64) -> Result<&[u8], UrError> {
    match usize::try_from(len) {
        Ok(len) if len == rest.len() => Ok(rest),
        Ok(len) if len < rest.len() => Err(UrError::TrailingBytes),
        _ => Err(UrError::NotByteString),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::{hex, hex_str, read, text};
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    fn watchonly() -> Value {
        read("watchonly.json")
    }

    fn array(v: &Value) -> &Vec<Value> {
        v.as_array().expect("a list")
    }

    /// An item from its watchonly.json form; byte strings borrow `store`, filled first.
    fn item_from<'a>(v: &Value, store: &'a [Vec<u8>], next: &mut usize) -> Item<'a> {
        if let Some(n) = v.get("uint") {
            return Item::Uint(n.as_u64().expect("a u64"));
        }
        if v.get("bytes").is_some() {
            let data = &store[*next];
            *next += 1;
            return Item::Bytes(data);
        }
        if let Some(b) = v.get("bool") {
            return Item::Bool(b.as_bool().expect("a bool"));
        }
        if let Some(items) = v.get("array") {
            return Item::Array(
                array(items)
                    .iter()
                    .map(|i| item_from(i, store, next))
                    .collect(),
            );
        }
        if let Some(entries) = v.get("map") {
            return Item::Map(
                array(entries)
                    .iter()
                    .map(|pair| {
                        let key = pair[0]["uint"].as_u64().expect("a uint key");
                        (key, item_from(&pair[1], store, next))
                    })
                    .collect(),
            );
        }
        let tag = v["tag"].as_u64().expect("a tag");
        Item::Tag(tag, Box::new(item_from(&v["item"], store, next)))
    }

    /// Every byte string of an item, in the order `item_from` takes them.
    fn byte_strings(v: &Value, out: &mut Vec<Vec<u8>>) {
        if let Some(b) = v.get("bytes") {
            out.push(hex(b));
        } else if let Some(items) = v.get("array") {
            for i in array(items) {
                byte_strings(i, out);
            }
        } else if let Some(entries) = v.get("map") {
            for pair in array(entries) {
                byte_strings(&pair[1], out);
            }
        } else if let Some(inner) = v.get("item") {
            byte_strings(inner, out);
        }
    }

    fn encode_json_item(v: &Value) -> Vec<u8> {
        let mut store = Vec::new();
        byte_strings(v, &mut store);
        let mut next = 0;
        let item = item_from(v, &store, &mut next);
        cbor_encode(&item).expect("an encoding")
    }

    /// SHA-256 counter mode, as keepcrypt.json's spec defines it: never a PRNG.
    fn counter_stream(label: &[u8], len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = 0u64;
        while out.len() < len {
            out.extend_from_slice(
                &Sha256::new()
                    .chain_update(label)
                    .chain_update(i.to_be_bytes())
                    .finalize(),
            );
            i += 1;
        }
        out.truncate(len);
        out
    }

    // RFC 8949 Appendix A, the rows in core's subset (watchonly.json "cbor").
    #[test]
    fn rfc8949_examples() {
        let doc = watchonly();
        let examples = array(&doc["cbor"]);
        assert_eq!(examples.len(), 24);
        for e in examples {
            assert_eq!(
                encode_json_item(&e["item"]),
                hex(&e["hex"]),
                "{}",
                text(&e["diagnostic"])
            );
        }
    }

    // Map keys are written ascending whatever their order in the item; a repeated key is refused.
    #[test]
    fn map_keys_ascend_and_never_repeat() {
        let shuffled = Item::Map(vec![(3, Item::Uint(4)), (1, Item::Uint(2))]);
        assert_eq!(cbor_encode(&shuffled), Ok(hex_str("a201020304")));
        let repeated = Item::Map(vec![(1, Item::Uint(2)), (1, Item::Uint(3))]);
        assert_eq!(
            cbor_encode(&repeated),
            Err(CoreError::Internal(InternalFault::Cbor))
        );
        let heads: [(u64, &str); 6] = [
            (0, "00"),
            (23, "17"),
            (24, "1818"),
            (255, "18ff"),
            (256, "190100"),
            (u64::MAX, "1bffffffffffffffff"),
        ];
        for (value, want) in heads {
            assert_eq!(cbor_encode(&Item::Uint(value)), Ok(hex_str(want)));
        }
        assert_eq!(
            cbor_encode(&Item::Uint(0xffff_ffff)),
            Ok(hex_str("1affffffff"))
        );
        assert_eq!(
            cbor_encode(&Item::Uint(0x1_0000_0000)),
            Ok(hex_str("1b0000000100000000"))
        );
    }

    // The CRC-32/ISO-HDLC check value and the BCR-2020-012 checksums.
    #[test]
    fn crc32_vectors() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        let doc = watchonly();
        for c in array(&doc["crc32"]) {
            assert_eq!(
                format!("{:08x}", crc32(&hex(&c["data_hex"]))),
                text(&c["crc32"]),
                "{}",
                text(&c["name"])
            );
        }
        assert_eq!(CRC32_TABLE[1], 0x7707_3096);
        assert_eq!(CRC32_TABLE[255], 0x2d02_ef8d);
    }

    // The literal table equals watchonly.json's 256 words; minimal pairs are distinct; the BCR strings
    // and every byte encode and read back.
    #[test]
    fn bytewords_table_and_minimal_strings() {
        let doc = watchonly();
        let words: Vec<&str> = array(&doc["bytewords"]["words"]).iter().map(text).collect();
        assert_eq!(words, BYTEWORDS);
        let mut pairs: Vec<(u8, u8)> = BYTEWORDS.iter().map(|w| minimal_pair(w)).collect();
        pairs.sort_unstable();
        pairs.dedup();
        assert_eq!(pairs.len(), 256);
        assert!(
            BYTEWORDS
                .iter()
                .all(|w| w.len() == 4 && w.bytes().all(|b| b.is_ascii_lowercase()))
        );
        for m in array(&doc["bytewords"]["minimal"]) {
            assert_eq!(
                bytewords_minimal(&hex(&m["data_hex"])),
                text(&m["minimal"]),
                "{}",
                text(&m["name"])
            );
        }
        let index = minimal_index();
        for (byte, word) in (0u8..=255).zip(BYTEWORDS) {
            let (first, last) = minimal_pair(word);
            assert_eq!(
                index[usize::from(first - b'a') * 26 + usize::from(last - b'a')],
                Some(byte)
            );
        }
        assert_eq!(index.iter().filter(|e| e.is_some()).count(), 256);
    }

    // Every watchonly.json UR: the BCR-2020-005 seed, the 773-byte BCR-2020-015 example and the byte
    // strings; the byte strings also read back, in lowercase and in uppercase.
    #[test]
    fn ur_vectors_write_and_read_back() {
        let doc = watchonly();
        let urs = array(&doc["ur"]);
        let names: Vec<&str> = urs.iter().map(|u| text(&u["name"])).collect();
        assert!(names.contains(&"bcr-2020-005-seed"));
        let example = urs
            .iter()
            .find(|u| u["name"] == "bcr-2020-015-example")
            .expect("the example");
        assert_eq!(hex(&example["cbor_hex"]).len(), 773);
        for u in urs {
            let cbor = hex(&u["cbor_hex"]);
            let ur = text(&u["ur"]);
            assert_eq!(
                ur_single(text(&u["type"]), &cbor),
                ur,
                "{}",
                text(&u["name"])
            );
            if u["type"] == "bytes" {
                let data = hex(&u["data_hex"]);
                assert_eq!(cbor_encode(&Item::Bytes(&data)), Ok(cbor.clone()));
                assert_eq!(ur_decode_single("bytes", ur), Ok(data.clone()));
                assert_eq!(
                    ur_decode_single("bytes", &ur.to_ascii_uppercase()),
                    Ok(data)
                );
            }
        }
        let longest = urs.iter().map(|u| text(&u["ur"]).len()).max();
        assert_eq!(longest, Some(4295));
        assert_eq!(doc["ur_max_chars"], UR_MAX_CHARS);
    }

    // Round trips over SHA-256 counter-mode strings of 0 to 300 bytes, in both cases.
    #[test]
    fn round_trips_from_0_to_300_bytes() {
        for len in 0..=300 {
            let data = counter_stream(b"KCE/test/ur/round-trip", len);
            let cbor = cbor_encode(&Item::Bytes(&data)).expect("an encoding");
            let ur = ur_single("keepcrypt-proof", &cbor);
            assert!(ur.starts_with("ur:keepcrypt-proof/"));
            assert_eq!(
                ur_decode_single("keepcrypt-proof", &ur),
                Ok(data.clone()),
                "{len}"
            );
            assert_eq!(
                ur_decode_single("keepcrypt-proof", &ur.to_ascii_uppercase()),
                Ok(data),
                "{len}"
            );
        }
    }

    // Every watchonly.json negative gives exactly the error it names (and the plan's list is all
    // there).
    #[test]
    fn decoder_negatives() {
        let doc = watchonly();
        let negatives = array(&doc["ur_negatives"]);
        for name in [
            "mixed-case",
            "wrong-type",
            "multi-part",
            "odd-length",
            "unknown-byteword",
            "bad-crc",
            "non-shortest-head",
            "indefinite-head",
            "not-a-byte-string",
            "trailing-byte",
            "too-long",
        ] {
            assert!(negatives.iter().any(|n| n["name"] == name), "{name}");
        }
        for n in negatives {
            let got = ur_decode_single(text(&n["expected_type"]), text(&n["text"]));
            match got {
                Err(e) => assert_eq!(format!("{e:?}"), text(&n["error"]), "{}", text(&n["name"])),
                Ok(_) => panic!("{} was accepted", text(&n["name"])),
            }
        }
    }

    // 4,297 characters are refused before any decoding, whatever they hold; the length is checked
    // first, then the case, then the scheme.
    #[test]
    fn length_then_case_then_scheme() {
        assert_eq!(
            ur_decode_single("bytes", &"a".repeat(4297)),
            Err(UrError::TooLong)
        );
        assert_eq!(
            ur_decode_single("bytes", &"Zz".repeat(2149)),
            Err(UrError::TooLong)
        );
        assert_eq!(
            ur_decode_single("bytes", "Ur:bytes/"),
            Err(UrError::MixedCase)
        );
        assert_eq!(ur_decode_single("bytes", ""), Err(UrError::NotUr));
        assert_eq!(ur_decode_single("bytes", "ur"), Err(UrError::NotUr));
        assert_eq!(ur_decode_single("bytes", "UR:BYTES"), Err(UrError::NotUr));
        assert_eq!(ur_decode_single("bytes", "ur:/"), Err(UrError::WrongType));
        assert_eq!(
            ur_decode_single("bytes", "ur:bytes/"),
            Err(UrError::BadChecksum)
        );
        assert_eq!(
            ur_decode_single("bytes", "ur:bytes/a1"),
            Err(UrError::UnknownByteword)
        );
        assert_eq!(
            ur_decode_single("bytes", "ur:bytes/\u{e9}\u{e9}"),
            Err(UrError::UnknownByteword)
        );
        // A reserved head (info 28) and a cut-off head are not byte strings.
        let reserved = ur_single("bytes", &[0x5c]);
        assert_eq!(
            ur_decode_single("bytes", &reserved),
            Err(UrError::NotByteString)
        );
        let cut_off = ur_single("bytes", &[0x59, 0x01]);
        assert_eq!(
            ur_decode_single("bytes", &cut_off),
            Err(UrError::NotByteString)
        );
        // The minimal forms of each head size.
        for (cbor, want) in [
            (vec![0x58, 0x17], Err(UrError::NonShortestHead)),
            (vec![0x59, 0x00, 0xff], Err(UrError::NonShortestHead)),
            (
                vec![0x5a, 0x00, 0x00, 0xff, 0xff],
                Err(UrError::NonShortestHead),
            ),
            (
                vec![0x5b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff],
                Err(UrError::NonShortestHead),
            ),
            (
                vec![0x5b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
                Err(UrError::NotByteString),
            ),
            (vec![0x40], Ok(vec![])),
        ] {
            assert_eq!(
                ur_decode_single("bytes", &ur_single("bytes", &cbor)),
                want,
                "{cbor:02x?}"
            );
        }
    }
}
