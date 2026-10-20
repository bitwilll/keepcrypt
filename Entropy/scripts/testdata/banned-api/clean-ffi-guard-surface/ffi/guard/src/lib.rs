//! keepcrypt-guard re-exports nothing: a doc line naming pub use keepcrypt_ffi is no hit.
// Neither is "pub use keepcrypt_ffi as ffi;" in a string, nor a private use or helper.
use keepcrypt_ffi::dispatch;
const NOTE: &str = "pub use keepcrypt_ffi as ffi;";
/// The one public item.
pub fn guarded(op: u32, input: &[u8]) -> Zeroizing<Vec<u8>> {
    match std::panic::catch_unwind(|| dispatch(op, input)) {
        Ok(out) => out,
        Err(payload) => halt(payload),
    }
}
fn status(out: &[u8]) -> u8 {
    out[0]
}
