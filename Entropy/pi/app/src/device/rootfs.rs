//! The root filesystem's hash prefix, which the boot screen and About show (docs/pi-firmware.md
//! "Honest limits of the Pi Zero" and step 1; tasks/todo.md, M4 group 9, Q39 (g)).
//!
//! - Pure: `prefix` reads the root partition through a `Read`, which group 10's Linux glue opens on
//!   `/dev/mmcblk0p2` at start-up, and takes the partition's length. It does no I/O of its own.
//! - The rule, byte for byte. pi/os/rootfs-prefix.py computes the same from an image's partition 2
//!   for CI to publish with each image, and the vector in the tests pins it for both:
//!   1. the partition starts with a SquashFS 4.0 superblock: the magic `hsqs` at byte 0, and
//!      version 4.0 (4 and 0, two little-endian u16s) at bytes 28-31;
//!   2. its `bytes_used`, a little-endian u64 at byte 40, covers at least the 96-byte superblock;
//!      rounded up to a multiple of 4,096 (mksquashfs pads its image to that size), it is the length
//!      hashed, exactly the build's `rootfs.squashfs`;
//!   3. that length lies within the partition;
//!   4. SHA-256 over exactly those bytes, read at most 64 KiB at a time, and nothing past them;
//!   5. the prefix is the digest's first 8 bytes as 16 lowercase hex digits, in four groups of four
//!      joined by dashes (`0123-4567-89ab-cdef`).
//! - Any failure is `HalError::RootFs`, "the root filesystem could not be read", which halts at
//!   start-up: no retry and no default prefix (rule 3).
//! - It catches corruption, not a deliberately altered image (dm-verity would: an M7 candidate).

use std::io::Read;

use keepcrypt_pi::hal::HalError;
use sha2::{Digest, Sha256};

#[cfg(test)]
mod tests;

/// The SquashFS 4.0 superblock, at the start of the partition: 96 bytes.
const SUPERBLOCK_LEN: usize = 96;
/// SquashFS's magic at byte 0, the little-endian u32 0x73717368.
const MAGIC: [u8; 4] = *b"hsqs";
/// Where the major and minor version sit.
const VERSION_AT: usize = 28;
/// Version 4.0: the major 4 and the minor 0, as little-endian u16s.
const VERSION_4_0: [u8; 4] = [4, 0, 0, 0];
/// Where `bytes_used`, the image's length as a little-endian u64, sits.
const BYTES_USED_AT: usize = 40;
/// mksquashfs pads its image to a multiple of 4,096 bytes.
const PAD: u64 = 4_096;
/// The most one read asks for: 64 KiB.
const CHUNK: usize = 65_536;
/// The digest bytes the prefix shows: 8, as 16 hex digits.
const PREFIX_BYTES: usize = 8;
/// The lowercase hex digits, by nibble.
const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// The prefix of the SquashFS image at the start of `device`, a partition of `partition_len` bytes,
/// by the module's rule: `RootFs` for anything but a SquashFS 4.0 superblock whose `bytes_used`
/// covers it and rounds to a length within the partition, and for a read that fails or ends before
/// that length. An interrupted read is read again.
pub fn prefix<R: Read>(mut device: R, partition_len: u64) -> Result<String, HalError> {
    let mut superblock = [0u8; SUPERBLOCK_LEN];
    device
        .read_exact(&mut superblock)
        .map_err(|_| HalError::RootFs)?;
    let mut left = rest_len(&superblock, partition_len)?;
    let mut hasher = Sha256::new();
    hasher.update(superblock);
    let mut chunk = vec![0u8; CHUNK];
    while left > 0 {
        let bytes = match usize::try_from(left) {
            Ok(rest) if rest < CHUNK => &mut chunk[..rest],
            // A chunk or more is left.
            _ => &mut chunk[..],
        };
        device.read_exact(bytes).map_err(|_| HalError::RootFs)?;
        hasher.update(&*bytes);
        left -= u64::try_from(bytes.len()).expect("a usize fits a u64");
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(grouped(&digest))
}

/// The bytes the prefix hashes after the superblock: `bytes_used` rounded up to a multiple of
/// 4,096, less the superblock's 96. `RootFs` unless `superblock` is SquashFS 4.0's, its
/// `bytes_used` covers the superblock, and the rounded length is at most `partition_len`; a length
/// past `u64::MAX` is past the partition too.
fn rest_len(superblock: &[u8; SUPERBLOCK_LEN], partition_len: u64) -> Result<u64, HalError> {
    if superblock[..4] != MAGIC || superblock[VERSION_AT..VERSION_AT + 4] != VERSION_4_0 {
        return Err(HalError::RootFs);
    }
    let mut bytes_used = [0u8; 8];
    bytes_used.copy_from_slice(&superblock[BYTES_USED_AT..BYTES_USED_AT + 8]);
    let bytes_used = u64::from_le_bytes(bytes_used);
    let superblock_len = u64::try_from(SUPERBLOCK_LEN).expect("a usize fits a u64");
    match bytes_used.checked_next_multiple_of(PAD) {
        Some(len) if bytes_used >= superblock_len && len <= partition_len => {
            Ok(len - superblock_len)
        }
        _ => Err(HalError::RootFs),
    }
}

/// The first 8 bytes of `digest` as 16 lowercase hex digits, in four groups of four joined by
/// dashes.
fn grouped(digest: &[u8; 32]) -> String {
    let mut text = String::with_capacity(2 * PREFIX_BYTES + 3);
    for (i, &byte) in digest[..PREFIX_BYTES].iter().enumerate() {
        if i > 0 && i % 2 == 0 {
            text.push('-');
        }
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}
