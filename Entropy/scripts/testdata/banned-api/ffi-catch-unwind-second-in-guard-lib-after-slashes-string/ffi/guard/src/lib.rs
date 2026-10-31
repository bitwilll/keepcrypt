pub fn guarded(op: u32, input: Vec<u8>) -> Zeroizing<Vec<u8>> {
    let input = Zeroizing::new(input);
    match std::panic::catch_unwind(|| keepcrypt_ffi::dispatch(op, &input)) {
        Ok(out) => out,
        Err(payload) => halt(payload),
    }
}
fn again(f: fn() -> u8) -> bool { let url = "a//b"; std::panic::catch_unwind(f).is_ok() && !url.is_empty() }
