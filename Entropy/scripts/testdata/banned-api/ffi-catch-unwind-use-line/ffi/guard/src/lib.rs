// A use line names catch_unwind without calling it: the one call is written as the path.
use std::panic::catch_unwind;
pub fn guarded(op: u32, input: Vec<u8>) -> Zeroizing<Vec<u8>> {
    match std::panic::catch_unwind(|| keepcrypt_ffi::dispatch(op, &input)) {
        Ok(out) => out,
        Err(payload) => halt(payload),
    }
}
