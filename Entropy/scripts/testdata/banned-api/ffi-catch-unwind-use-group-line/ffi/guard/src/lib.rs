use std::panic::{
    catch_unwind,
    AssertUnwindSafe,
};
pub fn guarded(op: u32, input: Vec<u8>) -> Zeroizing<Vec<u8>> {
    let input = Zeroizing::new(input);
    match std::panic::catch_unwind(AssertUnwindSafe(|| keepcrypt_ffi::dispatch(op, &input))) {
        Ok(out) => out,
        Err(payload) => halt(payload),
    }
}
