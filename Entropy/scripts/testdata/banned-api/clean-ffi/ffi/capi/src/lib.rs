//! keepcrypt-capi: the C boundary over keepcrypt_guard::guarded(); no JNI name and no catch here.
#[unsafe(no_mangle)]
pub extern "C" fn kc_max_out() -> usize {
    keepcrypt_ffi::MAX_OUT
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_call(op: u32, input: *const u8, in_len: usize, out: *mut u8, out_cap: usize) -> i32 {
    copy_out(keepcrypt_guard::guarded(op, take_input(input, in_len)), out, out_cap)
}
