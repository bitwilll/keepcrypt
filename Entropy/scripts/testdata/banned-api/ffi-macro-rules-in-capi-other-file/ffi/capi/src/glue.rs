// A macro in another of keepcrypt-capi's files could carry an export's tokens out of lib.rs, where
// the export scan reads them.
macro_rules! call {
    ($op:expr) => { keepcrypt_guard::guarded($op, Vec::new()) };
}
