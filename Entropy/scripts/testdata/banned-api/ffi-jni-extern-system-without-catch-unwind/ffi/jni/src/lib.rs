// An extern "system" fn is an export even without no_mangle: RegisterNatives can bind it.
pub extern "system" fn native_wipe_all() -> u8 {
    keepcrypt_guard::guarded(OP_WIPE_ALL, &[])[0]
}
