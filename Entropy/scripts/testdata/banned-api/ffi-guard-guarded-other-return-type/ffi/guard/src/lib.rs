// guarded handing out the slot would let the boundary call it outside the catch.
pub fn guarded(op: u32, input: &[u8]) -> &'static Slot {
    &keepcrypt_ffi::ceremony::FFI
}
