pub extern fn Java_com_keepcrypt_ffi_Native_wipeAll() -> u8 {
    ceremony::wipe_all()
}
