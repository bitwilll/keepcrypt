// A fn guarded in a mod is not the crate root's: keepcrypt_guard::raw::guarded would hand the panic
// back as a value, so the boundary could catch and continue.
pub mod raw {
    pub fn guarded<R>(f: impl FnOnce() -> R + UnwindSafe) -> Result<R, Box<dyn Any + Send>> {
        std::panic::catch_unwind(f)
    }
}
pub fn guarded(op: u32, input: &[u8]) -> Zeroizing<Vec<u8>> {
    match raw::guarded(|| keepcrypt_ffi::dispatch(op, input)) {
        Ok(out) => out,
        Err(payload) => halt(payload),
    }
}
