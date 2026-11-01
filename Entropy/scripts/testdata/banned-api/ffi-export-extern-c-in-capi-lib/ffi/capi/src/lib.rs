// keepcrypt-capi is M6's (Q73): an extern "C" fn is an export here, with or without no_mangle.
pub extern "C" fn kc_max_out() -> usize {
    keepcrypt_ffi::MAX_OUT
}
