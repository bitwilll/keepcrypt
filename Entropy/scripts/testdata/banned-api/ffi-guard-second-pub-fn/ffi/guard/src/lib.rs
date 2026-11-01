pub fn guarded(op: u32, input: Vec<u8>) -> Zeroizing<Vec<u8>> {
    let input = Zeroizing::new(input);
    match std::panic::catch_unwind(|| keepcrypt_ffi::dispatch(op, &input)) {
        Ok(out) => out,
        Err(payload) => halt(payload),
    }
}
// A second entry runs the safe layer outside the catch.
pub fn reveal(input: &[u8]) -> Zeroizing<Vec<u8>> {
    keepcrypt_ffi::dispatch(36, input)
}
