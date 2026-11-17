pub fn guarded(op: u32, input: Vec<u8>) -> Zeroizing<Vec<u8>> {
    let input = Zeroizing::new(input);
    let recover = std::panic::catch_unwind;
    match recover(|| keepcrypt_ffi::dispatch(op, &input)) {
        Ok(out) => out,
        Err(payload) => halt(payload),
    }
}
