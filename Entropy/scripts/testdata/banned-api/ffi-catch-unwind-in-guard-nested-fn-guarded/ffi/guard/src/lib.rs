// A fn guarded nested in a public wrapper is not the crate root's: recover returns the panic.
pub fn recover<F: FnOnce() -> R + UnwindSafe, R>(f: F) -> Result<R, Box<dyn Any + Send>> {
    fn guarded<F: FnOnce() -> R + UnwindSafe, R>(f: F) -> Result<R, Box<dyn Any + Send>> {
        std::panic::catch_unwind(f)
    }
    guarded(f)
}
pub fn guarded(op: u32, input: &[u8]) -> Zeroizing<Vec<u8>> {
    match recover(|| keepcrypt_ffi::dispatch(op, input)) {
        Ok(out) => out,
        Err(payload) => halt(payload),
    }
}
