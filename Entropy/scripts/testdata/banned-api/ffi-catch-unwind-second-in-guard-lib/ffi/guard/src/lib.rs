pub fn guarded(op: u32, input: &[u8]) -> Zeroizing<Vec<u8>> {
    match std::panic::catch_unwind(|| keepcrypt_ffi::dispatch(op, input)) {
        Ok(out) => out,
        Err(payload) => halt(payload),
    }
}
fn again(f: fn() -> u8) -> bool { std::panic::catch_unwind(f).is_ok() }
