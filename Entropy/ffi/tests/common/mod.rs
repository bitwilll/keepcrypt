//! Test support for keepcrypt-ffi's integration tests (tasks/todo.md, M5 group 11): vectors/ read
//! by a small JSON reader, since the crate's one dev-dependency is sha2 (M5 group 7); the go-ahead
//! QR text of a kcr.json proof, which kcr.json holds as KCP1 bytes only; and the mock checker's
//! go-ahead code. `ffi_test_helpers_match_their_vectors` checks each against vectors/ first.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

/// The go-ahead code's domain tag: 9 ASCII bytes (lessons 2).
const GO_DOMAIN: &[u8] = b"KCE/v1/go";
/// Crockford base32, the go-ahead code's alphabet.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// A go-ahead QR's UR type (docs/seal-watchonly-braille.md "Go-ahead QR").
const PROOF_UR_TYPE: &str = "keepcrypt-proof";

/// A JSON value as vectorgen.py writes vectors/ (ASCII, `\u` escapes). Objects keep their order.
pub enum Json {
    Null,
    Bool(bool),
    Number(String),
    Text(String),
    List(Vec<Json>),
    Map(Vec<(String, Json)>),
}

impl Json {
    /// The one value in `text`; anything else fails the test.
    pub fn parse(text: &str) -> Json {
        let mut reader = Reader { text, at: 0 };
        let value = reader.value();
        reader.space();
        assert_eq!(reader.at, text.len(), "one JSON value");
        value
    }

    /// The object's field `key`.
    pub fn get(&self, key: &str) -> &Json {
        let Json::Map(fields) = self else {
            panic!("an object for {key}");
        };
        match fields.iter().find(|(name, _)| name == key) {
            Some((_, value)) => value,
            None => panic!("a field {key}"),
        }
    }

    /// The list's one entry whose `name` is `name`.
    pub fn named(&self, name: &str) -> &Json {
        let found: Vec<&Json> = self
            .list()
            .iter()
            .filter(|entry| matches!(entry, Json::Map(fields) if fields.iter().any(|(key, value)| key == "name" && matches!(value, Json::Text(text) if text == name))))
            .collect();
        assert_eq!(found.len(), 1, "exactly one entry named {name}");
        found[0]
    }

    pub fn list(&self) -> &[Json] {
        match self {
            Json::List(items) => items,
            _ => panic!("a list"),
        }
    }

    pub fn text(&self) -> &str {
        match self {
            Json::Text(text) => text,
            _ => panic!("a string"),
        }
    }

    /// `None` for null, else the text.
    pub fn text_or_null(&self) -> Option<&str> {
        match self {
            Json::Null => None,
            Json::Text(text) => Some(text),
            _ => panic!("a string or null"),
        }
    }

    pub fn flag(&self) -> bool {
        match self {
            Json::Bool(flag) => *flag,
            _ => panic!("true or false"),
        }
    }

    pub fn number(&self) -> u64 {
        match self {
            Json::Number(digits) => digits.parse().expect("an unsigned integer"),
            _ => panic!("a number"),
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Json::Null)
    }

    pub fn has(&self, key: &str) -> bool {
        matches!(self, Json::Map(fields) if fields.iter().any(|(name, _)| name == key))
    }

    /// A `*_hex` value's bytes.
    pub fn hex(&self) -> Vec<u8> {
        hex(self.text())
    }
}

/// Lowercase hex to bytes.
pub fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "whole bytes of hex");
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// A strict reader of the JSON vectorgen.py writes: objects, lists, strings with every escape,
/// numbers, true, false and null.
struct Reader<'a> {
    text: &'a str,
    at: usize,
}

impl Reader<'_> {
    fn space(&mut self) {
        let rest = &self.text[self.at..];
        self.at += rest.len() - rest.trim_start_matches([' ', '\n', '\r', '\t']).len();
    }

    fn next(&mut self) -> u8 {
        let byte = *self.text.as_bytes().get(self.at).expect("more JSON");
        self.at += 1;
        byte
    }

    fn expect(&mut self, byte: u8) {
        self.space();
        assert_eq!(self.next(), byte, "JSON syntax at byte {}", self.at);
    }

    fn literal(&mut self, word: &str) {
        assert!(
            self.text[self.at..].starts_with(word),
            "JSON literal {word}"
        );
        self.at += word.len();
    }

    fn value(&mut self) -> Json {
        self.space();
        match self.text.as_bytes().get(self.at).copied() {
            Some(b'{') => {
                self.at += 1;
                let mut fields = Vec::new();
                self.space();
                if self.text[self.at..].starts_with('}') {
                    self.at += 1;
                    return Json::Map(fields);
                }
                loop {
                    self.space();
                    let key = self.string();
                    self.expect(b':');
                    fields.push((key, self.value()));
                    self.space();
                    match self.next() {
                        b',' => {}
                        b'}' => return Json::Map(fields),
                        _ => panic!("JSON syntax in an object"),
                    }
                }
            }
            Some(b'[') => {
                self.at += 1;
                let mut items = Vec::new();
                self.space();
                if self.text[self.at..].starts_with(']') {
                    self.at += 1;
                    return Json::List(items);
                }
                loop {
                    items.push(self.value());
                    self.space();
                    match self.next() {
                        b',' => {}
                        b']' => return Json::List(items),
                        _ => panic!("JSON syntax in a list"),
                    }
                }
            }
            Some(b'"') => Json::Text(self.string()),
            Some(b't') => {
                self.literal("true");
                Json::Bool(true)
            }
            Some(b'f') => {
                self.literal("false");
                Json::Bool(false)
            }
            Some(b'n') => {
                self.literal("null");
                Json::Null
            }
            _ => {
                let rest = &self.text[self.at..];
                let len = rest
                    .find(|c: char| !matches!(c, '-' | '+' | '.' | 'e' | 'E' | '0'..='9'))
                    .expect("a number before the end");
                assert!(len > 0, "a JSON value at byte {}", self.at);
                self.at += len;
                Json::Number(rest[..len].to_owned())
            }
        }
    }

    fn string(&mut self) -> String {
        assert_eq!(self.next(), b'"', "a JSON string");
        let mut out = String::new();
        loop {
            let rest = &self.text[self.at..];
            let stop = rest.find(['"', '\\']).expect("a closed string");
            out.push_str(&rest[..stop]);
            self.at += stop;
            if self.next() == b'"' {
                return out;
            }
            let escaped = match self.next() {
                b'"' => '"',
                b'\\' => '\\',
                b'/' => '/',
                b'b' => '\u{8}',
                b'f' => '\u{c}',
                b'n' => '\n',
                b'r' => '\r',
                b't' => '\t',
                b'u' => {
                    let unit = self.unit();
                    let scalar = if (0xD800..0xDC00).contains(&unit) {
                        self.literal("\\u");
                        let low = self.unit();
                        assert!((0xDC00..0xE000).contains(&low), "a low surrogate");
                        0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
                    } else {
                        unit
                    };
                    char::from_u32(scalar).expect("a Unicode scalar")
                }
                _ => panic!("a JSON escape"),
            };
            out.push(escaped);
        }
    }

    fn unit(&mut self) -> u32 {
        let digits = &self.text[self.at..self.at + 4];
        self.at += 4;
        u32::from_str_radix(digits, 16).expect("4 hex digits")
    }
}

/// vectors/kcr.json: the gate seeds, snapshots and proofs.
pub fn kcr() -> &'static Json {
    static KCR: OnceLock<Json> = OnceLock::new();
    KCR.get_or_init(|| Json::parse(include_str!("../../../vectors/kcr.json")))
}

/// vectors/braille.json: every word's faces, the letters' cells and the insert positions.
pub fn braille() -> &'static Json {
    static BRAILLE: OnceLock<Json> = OnceLock::new();
    BRAILLE.get_or_init(|| Json::parse(include_str!("../../../vectors/braille.json")))
}

/// vectors/watchonly.json: the Bytewords list, and the CRC-32, CBOR and UR vectors.
pub fn watchonly() -> &'static Json {
    static WATCHONLY: OnceLock<Json> = OnceLock::new();
    WATCHONLY.get_or_init(|| Json::parse(include_str!("../../../vectors/watchonly.json")))
}

/// CRC-32/ISO-HDLC (reflected polynomial 0xedb88320), as a UR carries it.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// One CBOR byte string: major type 2 with its length in the shortest head, then the bytes.
pub fn cbor_bytes(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let mut out = match (u8::try_from(len), u16::try_from(len)) {
        (Ok(short), _) if short < 24 => vec![0x40 | short],
        (Ok(byte), _) => vec![0x58, byte],
        (_, Ok(two)) => [&[0x59][..], &two.to_be_bytes()].concat(),
        _ => panic!("a test byte string under 64 KiB"),
    };
    out.extend_from_slice(data);
    out
}

/// A single-part UR: `ur:<type>/` and the minimal Bytewords of the CBOR and its CRC-32, each byte
/// the first and last letters of its word in watchonly.json's list.
pub fn ur(kind: &str, cbor: &[u8]) -> String {
    let words = watchonly().get("bytewords").get("words").list();
    let mut text = format!("ur:{kind}/");
    for byte in cbor.iter().chain(&crc32(cbor).to_be_bytes()) {
        let word = words[usize::from(*byte)].text().as_bytes();
        text.push(char::from(word[0]));
        text.push(char::from(word[3]));
    }
    text
}

/// kcr.json's proof `name` as a go-ahead QR's text: the UR of one CBOR byte string holding its
/// KCP1 bytes (vectorgen.py's kcp1_ur). kcr.json holds the gate's proofs as bytes only.
pub fn proof_ur(name: &str) -> String {
    ur(
        PROOF_UR_TYPE,
        &cbor_bytes(&kcr().get("proofs").named(name).get("kcp1_hex").hex()),
    )
}

/// The mock checker (lessons 2): the go-ahead code for the check request `url`, the first 40 bits
/// of SHA-256 over "KCE/v1/go" (9 ASCII bytes) || T (32 bytes) || n (8 bytes), read from the
/// drawn request, as 8 Crockford base32 symbols without the dash.
pub fn go_ahead(url: &str) -> String {
    let (_, fragment) = url.split_once("#t=").expect("a check URL");
    let (t, n) = fragment
        .split_once("&n=")
        .expect("a check URL with a nonce");
    let (t, n) = (hex(t), hex(n));
    assert!(t.len() == 32 && n.len() == 8, "T and n");
    let digest = Sha256::new()
        .chain_update(GO_DOMAIN)
        .chain_update(&t)
        .chain_update(&n)
        .finalize();
    let bits = digest[..5]
        .iter()
        .fold(0u64, |bits, &byte| (bits << 8) | u64::from(byte));
    (0..8)
        .map(|i| {
            let index = usize::try_from((bits >> (35 - 5 * i)) & 31).expect("5 bits");
            char::from(CROCKFORD[index])
        })
        .collect()
}
