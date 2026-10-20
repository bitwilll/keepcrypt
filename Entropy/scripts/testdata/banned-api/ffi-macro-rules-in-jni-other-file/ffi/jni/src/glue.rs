// A macro in another of keepcrypt-jni's files writes what lib.rs calls it with, out of the export
// scan's sight (lead decision M5-35).
macro_rules! native { ($name:ident) => { pub fn $name() -> u8 { keepcrypt_guard::guarded(0, Vec::new())[0] } }; }
