// A file that ends at the pinned line has no first statement to check: the missing wrap is a hit.
pub fn guarded(op: u32, input: Vec<u8>) -> Zeroizing<Vec<u8>> {
