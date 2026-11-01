// The one catch is keepcrypt-guard's, which both boundaries call.
fn guarded(f: fn() -> u8) -> u8 {
    match std::panic::catch_unwind(f) {
        Ok(status) => status,
        Err(payload) => halt(payload),
    }
}
