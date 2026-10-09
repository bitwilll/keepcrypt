//! Test support: read the committed vectors (vectors/*.json) as `serde_json::Value`. Unit tests
//! only; every computed value they compare against comes from tools/verify/verify.py.
#![cfg(test)]

use serde_json::Value;
use std::path::Path;

/// vectors/<name>, parsed.
pub(crate) fn read(name: &str) -> Value {
    let file = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../vectors")
        .join(name);
    let text = std::fs::read_to_string(&file).expect("read the vectors file");
    serde_json::from_str(&text).expect("parse the vectors file")
}

/// vectors/keepcrypt.json, parsed.
pub(crate) fn keepcrypt_json() -> Value {
    read("keepcrypt.json")
}

/// The string at `v`.
pub(crate) fn text(v: &Value) -> &str {
    v.as_str().expect("a string")
}

/// The bytes of the lowercase hex string at `v`.
pub(crate) fn hex(v: &Value) -> Vec<u8> {
    hex_str(text(v))
}

/// The bytes of a lowercase hex string.
pub(crate) fn hex_str(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// The entry named `name` in the list at `section`.
pub(crate) fn named<'a>(section: &'a Value, name: &str) -> &'a Value {
    let found: Vec<&Value> = section
        .as_array()
        .expect("a list")
        .iter()
        .filter(|e| e["name"] == name)
        .collect();
    assert_eq!(found.len(), 1, "exactly one entry named {name}");
    found[0]
}

/// The entry in the list at `section` whose `key` is the string `value`.
pub(crate) fn named_by<'a>(section: &'a Value, key: &str, value: &str) -> &'a Value {
    let found: Vec<&Value> = section
        .as_array()
        .expect("a list")
        .iter()
        .filter(|e| e[key] == value)
        .collect();
    assert_eq!(found.len(), 1, "exactly one entry with {key} = {value}");
    found[0]
}
