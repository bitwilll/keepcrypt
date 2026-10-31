//! A doc line that names macro_rules is no hit; the definition below is.
macro_rules! halted {
    () => {
        keepcrypt_ffi::halted()
    };
}
