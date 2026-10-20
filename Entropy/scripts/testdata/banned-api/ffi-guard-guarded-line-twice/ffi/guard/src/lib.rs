pub fn guarded(op: u32, input: &[u8]) -> Zeroizing<Vec<u8>> {
    keepcrypt_ffi::dispatch(op, input)
}
mod again {
pub fn guarded(op: u32, input: &[u8]) -> Zeroizing<Vec<u8>> {
    keepcrypt_ffi::dispatch(op, input)
}
}
