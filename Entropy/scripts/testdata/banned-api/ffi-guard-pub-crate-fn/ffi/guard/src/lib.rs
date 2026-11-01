// Restricted forms are refused too: the guard needs no item but guarded.
pub(crate) fn run(op: u32, input: &[u8]) -> Zeroizing<Vec<u8>> {
    keepcrypt_ffi::dispatch(op, input)
}
