pub fn guarded(op: u32, input: Vec<u8>) -> Zeroizing<Vec<u8>> {
    let input = Zeroizing::new(input);
    let first = std::panic::catch_unwind(|| keepcrypt_ffi::dispatch(op, &input));
    let again = std::panic::catch_unwind(|| keepcrypt_ffi::dispatch(op, &input));
    settle(first, again)
}
