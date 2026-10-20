pub fn guarded(op: u32, input: &[u8]) -> Zeroizing<Vec<u8>> {
    #[macro_export]
    macro_rules! recover ( ($f:expr) => ( std::panic::catch_unwind($f) ) );
    match recover!(|| keepcrypt_ffi::dispatch(op, input)) {
        Ok(out) => out,
        Err(payload) => halt(payload),
    }
}
