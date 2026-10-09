// Dropping the result of a call discards it like an underscore assignment.
pub fn warm_up(block: &mut [u8; 64]) {
    drop(crate::source::os_fill(block));
}
