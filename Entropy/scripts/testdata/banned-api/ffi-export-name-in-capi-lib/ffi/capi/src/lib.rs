#[unsafe(export_name = "kc_max_out")]
pub fn max_out() -> usize {
    keepcrypt_ffi::MAX_OUT
}
