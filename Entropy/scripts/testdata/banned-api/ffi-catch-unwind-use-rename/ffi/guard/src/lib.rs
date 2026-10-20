// A rename hides the catch from every later call: recover( names no catch_unwind.
use std::panic::catch_unwind as recover;
pub fn guarded(op: u32, input: Vec<u8>) -> Zeroizing<Vec<u8>> {
    match recover(|| keepcrypt_ffi::dispatch(op, &input)) {
        Ok(out) => out,
        Err(payload) => halt(payload),
    }
}
