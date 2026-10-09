// forget() of a call discards its result too.
pub fn check(words: &str) {
    core::mem::forget(keepcrypt_core::seal::check(words));
}
