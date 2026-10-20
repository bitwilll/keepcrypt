// A wrapper beside guarded() would be a second way in, without the halt: the call sits in guarded.
fn recover<R>(f: impl FnOnce() -> R + UnwindSafe) -> Result<R, Box<dyn Any + Send>> {
    std::panic::catch_unwind(f)
}
pub fn guarded(op: u32, input: Vec<u8>) -> Zeroizing<Vec<u8>> {
    match recover(|| keepcrypt_ffi::dispatch(op, &input)) {
        Ok(out) => out,
        Err(payload) => halt(payload),
    }
}
