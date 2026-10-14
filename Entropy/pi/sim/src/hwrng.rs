//! The simulated `/dev/hwrng` (tasks/todo.md, M3 group 7, Q30 (a)): one fixed byte stream, served
//! 64 bytes a read.
//!
//! - Normal runs use the counting stream, i mod 256 without end: keepcrypt.json's `counting-1536`
//!   is its first 1,536 bytes, which pass core's health tests. It is a counter, not a PRNG.
//! - The stop runs hand in vector bytes (keepcrypt.json's `health` streams), concatenated by read
//!   phase: the boot test's 1,024 samples, then 1,536 per Mixed session (`HW_BYTES_NEEDED`).
//! - A read gives exactly 64 bytes or an error: past the end of handed-in bytes, every read is a
//!   read fault, as a short read from the device would be.

use keepcrypt_pi::hal::HalError;

use crate::mark;

/// What the simulated hwrng serves.
pub enum HwRngStream {
    /// Byte i is i mod 256, without end.
    Counting,
    /// Exactly these bytes, in order; then every read fails.
    Bytes(Vec<u8>),
}

/// The stream and how much of it was served.
pub(crate) struct Hwrng {
    stream: HwRngStream,
    served: usize,
}

impl Hwrng {
    pub(crate) fn new(stream: HwRngStream) -> Self {
        Hwrng { stream, served: 0 }
    }

    /// The next 64 bytes, or `HalError::HwRng` when fewer than 64 are left.
    pub(crate) fn read(&mut self, block: &mut [u8; 64]) -> Result<(), HalError> {
        mark();
        match &self.stream {
            HwRngStream::Counting => {
                for (offset, byte) in block.iter_mut().enumerate() {
                    // The low byte of the position: i mod 256.
                    *byte = (self.served + offset).to_le_bytes()[0];
                }
            }
            HwRngStream::Bytes(bytes) => match bytes.get(self.served..self.served + 64) {
                Some(next) => block.copy_from_slice(next),
                None => return Err(HalError::HwRng),
            },
        }
        self.served += 64;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_counting_stream_is_i_mod_256_without_end() {
        let mut hwrng = Hwrng::new(HwRngStream::Counting);
        let mut block = [0xaa; 64];
        let mut served = Vec::new();
        for _ in 0..1_000 {
            assert_eq!(hwrng.read(&mut block), Ok(()));
            served.extend_from_slice(&block);
        }
        assert_eq!(served.len(), 64_000);
        for (i, &byte) in served.iter().enumerate() {
            assert_eq!(usize::from(byte), i % 256);
        }
    }

    #[test]
    fn handed_in_bytes_are_served_in_order_then_every_read_fails() {
        let bytes: Vec<u8> = (0..200u8).rev().collect();
        let mut hwrng = Hwrng::new(HwRngStream::Bytes(bytes.clone()));
        let mut block = [0; 64];
        for start in [0, 64, 128] {
            assert_eq!(hwrng.read(&mut block), Ok(()));
            assert_eq!(&block[..], &bytes[start..start + 64]);
        }
        // 8 bytes are left: no short read, a fault, and the next read faults too.
        let before = block;
        assert_eq!(hwrng.read(&mut block), Err(HalError::HwRng));
        assert_eq!(hwrng.read(&mut block), Err(HalError::HwRng));
        assert_eq!(block, before, "a failed read writes nothing");
        let mut empty = Hwrng::new(HwRngStream::Bytes(Vec::new()));
        assert_eq!(empty.read(&mut block), Err(HalError::HwRng));
    }
}
