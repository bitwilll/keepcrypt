pub fn reveal(input: &[u8]) -> Zeroizing<Vec<u8>> { keepcrypt_ffi::dispatch(36, input) }
