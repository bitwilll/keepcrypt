//! Test support shared by the integration tests: read the committed vectors (vectors/*.json) as
//! `serde_json::Value`. Every computed value they compare against comes from
//! tools/verify/verify.py.

use serde_json::Value;
use std::path::Path;

/// vectors/<name>, parsed.
pub fn read(name: &str) -> Value {
    let file = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../vectors")
        .join(name);
    let text = std::fs::read_to_string(&file).expect("read the vectors file");
    serde_json::from_str(&text).expect("parse the vectors file")
}

/// The string at `v`.
pub fn text(v: &Value) -> &str {
    v.as_str().expect("a string")
}

/// The bytes of the lowercase hex string at `v`.
pub fn hex(v: &Value) -> Vec<u8> {
    let s = text(v);
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// The entry named `name` in the list at `section`.
pub fn named<'a>(section: &'a Value, name: &str) -> &'a Value {
    let found: Vec<&Value> = section
        .as_array()
        .expect("a list")
        .iter()
        .filter(|e| e["name"] == name)
        .collect();
    assert_eq!(found.len(), 1, "exactly one entry named {name}");
    found[0]
}
