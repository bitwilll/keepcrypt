// The wrap comes first, so every later use of input is the wrapped one: after the hook it does not.
pub fn guarded(op: u32, input: Vec<u8>) -> Zeroizing<Vec<u8>> {
    QUIET.call_once(|| std::panic::set_hook(Box::new(|_| {})));
    let input = Zeroizing::new(input);
    match std::panic::catch_unwind(|| dispatch(op, &input)) {
        Ok(reply) => reply,
        Err(_) => keepcrypt_ffi::halt(),
    }
}
