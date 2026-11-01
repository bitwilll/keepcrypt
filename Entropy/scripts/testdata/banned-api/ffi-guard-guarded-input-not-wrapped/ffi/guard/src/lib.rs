// The wrap deleted: dispatch still compiles on the raw Vec, which goes back to the allocator unwiped.
pub fn guarded(op: u32, input: Vec<u8>) -> Zeroizing<Vec<u8>> {
    QUIET.call_once(|| std::panic::set_hook(Box::new(|_| {})));
    match std::panic::catch_unwind(|| dispatch(op, &input)) {
        Ok(reply) => reply,
        Err(_) => keepcrypt_ffi::halt(),
    }
}
