// guarded() and its catch_unwind live in keepcrypt-guard; a comment is no call site.
#[unsafe(no_mangle)]
pub extern "C" fn kc_max_out() -> usize {
    keepcrypt_ffi::MAX_OUT
}
