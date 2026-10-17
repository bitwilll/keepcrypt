// A use line is a site too: write the one call as a path.
use std::panic::catch_unwind;
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keepcrypt_ffi_Native_wipeAll() -> u8 {
    guarded(ceremony::wipe_all)
}
fn guarded(f: fn() -> u8) -> u8 {
    match catch_unwind(f) {
        Ok(status) => status,
        Err(payload) => halt(payload),
    }
}
