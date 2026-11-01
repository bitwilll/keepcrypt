#[unsafe(no_mangle)]
pub fn wipe_all() -> u8 {
    keepcrypt_guard::guarded(OP_WIPE_ALL, Vec::new())[0]
}
