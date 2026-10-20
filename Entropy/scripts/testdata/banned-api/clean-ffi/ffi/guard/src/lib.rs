//! keepcrypt-guard: guarded() holds the one catch_unwind; keepcrypt-jni's exports call it.
// A use std::panic::catch_unwind; in a comment is no site, and neither is "catch_unwind" in a string.
/// Runs dispatch under the one catch: a panic has already dropped the moved-out session.
pub fn guarded(op: u32, input: &[u8]) -> Zeroizing<Vec<u8>> {
    match std::panic::catch_unwind(|| keepcrypt_ffi::dispatch(op, input)) {
        Ok(out) => out,
        Err(payload) => halt(payload),
    }
}
