// A use line is a site too: write the one call as a path.
use std::panic::catch_unwind;
pub fn guarded(op: u32, input: &[u8]) -> Zeroizing<Vec<u8>> {
    match catch_unwind(|| keepcrypt_ffi::dispatch(op, input)) {
        Ok(out) => out,
        Err(payload) => halt(payload),
    }
}
