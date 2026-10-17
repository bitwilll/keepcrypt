// guarded() and its catch_unwind come later; a comment is no call site.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keepcrypt_ffi_Native_wipeAll() -> u8 {
    guarded(ceremony::wipe_all)
}
