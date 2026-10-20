// A method named guarded is not the crate root's fn guarded: Recover::guarded returns the panic.
pub struct Recover;
impl Recover {
    pub fn guarded<R>(f: impl FnOnce() -> R + UnwindSafe) -> Result<R, Box<dyn Any + Send>> {
        std::panic::catch_unwind(f)
    }
}
pub fn guarded(op: u32, input: &[u8]) -> Zeroizing<Vec<u8>> {
    match Recover::guarded(|| keepcrypt_ffi::dispatch(op, input)) {
        Ok(out) => out,
        Err(payload) => halt(payload),
    }
}
