// guarded() and its catch_unwind come later; a comment is no call site. keepcrypt-capi's lib.rs is
// the second boundary (M6 item B4), so an export here needs the one catch as jni's do.
#[unsafe(no_mangle)]
pub extern "C" fn kc_wipe_all() -> u8 {
    keepcrypt_guard::guarded(OP_WIPE_ALL, Vec::new())[0]
}
