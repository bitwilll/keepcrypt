//! keepcrypt-guard: guarded() holds the one catch_unwind; keepcrypt-jni and keepcrypt-capi call it.
/// Runs dispatch under the one catch: a panic has already dropped the moved-out session.
pub fn guarded(op: u32, input: &[u8]) -> Zeroizing<Vec<u8>> {
    match std::panic::catch_unwind(|| keepcrypt_ffi::dispatch(op, input)) {
        Ok(out) => out,
        Err(payload) => halt(payload),
    }
}
