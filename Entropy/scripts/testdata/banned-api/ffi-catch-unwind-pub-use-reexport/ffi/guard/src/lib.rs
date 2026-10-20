// A re-export would let keepcrypt-jni catch and continue as keepcrypt_guard::recover(...).
pub use std::panic::catch_unwind as recover;
pub fn guarded(op: u32, input: &[u8]) -> Zeroizing<Vec<u8>> {
    match std::panic::catch_unwind(|| keepcrypt_ffi::dispatch(op, input)) {
        Ok(out) => out,
        Err(payload) => halt(payload),
    }
}
