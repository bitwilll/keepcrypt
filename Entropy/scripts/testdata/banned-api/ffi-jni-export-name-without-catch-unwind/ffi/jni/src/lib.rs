#[unsafe(export_name = "Java_com_keepcrypt_ffi_Native_wipeAll")]
pub fn wipe_all() -> u8 {
    ceremony::wipe_all()
}
