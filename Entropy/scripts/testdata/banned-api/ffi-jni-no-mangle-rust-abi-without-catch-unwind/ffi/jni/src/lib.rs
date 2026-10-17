#[unsafe(no_mangle)]
pub fn wipe_all() -> u8 {
    ceremony::wipe_all()
}
