#![forbid(unsafe_code)]
#[unsafe(no_mangle)]
pub fn kc_dispatch(op: u32) -> u8 {
    op.to_le_bytes()[0]
}
