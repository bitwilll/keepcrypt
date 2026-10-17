//! keepcrypt-jni: the JNI boundary. guarded() below holds the one catch_unwind.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keepcrypt_ffi_Native_wipeAll() -> u8 {
    guarded(ceremony::wipe_all)
}
/// Runs f under the one catch: a panic has already dropped the moved-out session.
fn guarded(f: fn() -> u8) -> u8 {
    match std::panic::catch_unwind(f) {
        Ok(status) => status,
        Err(payload) => halt(payload),
    }
}
