#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keepcrypt_ffi_Native_wipeAll() -> u8 {
    guarded(ceremony::wipe_all)
}
fn guarded(f: fn() -> u8) -> u8 {
    match std::panic::catch_unwind(f) {
        Ok(status) => status,
        Err(payload) => halt(payload),
    }
}
fn again(f: fn() -> u8) -> bool { let url = "a//b"; std::panic::catch_unwind(f).is_ok() && !url.is_empty() }
