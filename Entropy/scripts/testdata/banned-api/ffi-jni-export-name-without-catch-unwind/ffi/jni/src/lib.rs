#[unsafe(export_name = "Java_com_keepcrypt_ffi_Native_wipeAll")]
pub fn wipe_all() -> u8 {
    keepcrypt_guard::guarded(OP_WIPE_ALL, &[])[0]
}
