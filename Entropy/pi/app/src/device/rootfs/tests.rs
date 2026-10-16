//! The rootfs prefix's tests (tasks/todo.md, M4 group 9, Q39 (g)), on partitions in memory: the
//! vector, pinned here for pi/os/rootfs-prefix.py's --selftest to recompute in CI's gates job; the
//! prefix's format; the length hashed, `bytes_used` rounded up to 4,096, and nothing past it, read at
//! most 64 KiB at a time; a bad magic or version; a `bytes_used` below the superblock or past the
//! partition; a read that ends early or fails.

use std::collections::VecDeque;
use std::io::{self, ErrorKind};

use super::*;

/// The vector's prefix: a 4,096-byte image holding the magic, version 4.0 and `bytes_used` 4,096,
/// every other byte zero. pi/os/rootfs-prefix.py's --selftest reads this line and must compute the
/// same, so the prefix the device shows and the one CI publishes follow one rule.
const VECTOR_PREFIX: &str = "722a-ccc1-0d67-011e";

const KIB: usize = 1_024;

/// A partition of `len` bytes that starts with a SquashFS 4.0 superblock holding `bytes_used`, its
/// other bytes `fill` of their offset. The format's bytes are written out here, not taken from the
/// module.
fn partition(bytes_used: u64, len: usize, fill: fn(usize) -> u8) -> Vec<u8> {
    let mut bytes: Vec<u8> = (0..len).map(fill).collect();
    bytes[..4].copy_from_slice(b"hsqs");
    bytes[28..32].copy_from_slice(&[4, 0, 0, 0]);
    bytes[40..48].copy_from_slice(&bytes_used.to_le_bytes());
    bytes
}

/// Zero.
fn zero(_: usize) -> u8 {
    0
}

/// A byte that differs from its neighbours.
fn pattern(offset: usize) -> u8 {
    (offset ^ (offset >> 8)).to_le_bytes()[0]
}

/// `len` as a partition length.
fn len_of(len: usize) -> u64 {
    u64::try_from(len).expect("a usize fits a u64")
}

/// The prefix of exactly `hashed`, worked out here: SHA-256, its first 8 bytes in lowercase hex,
/// four groups of four joined by dashes.
fn expected(hashed: &[u8]) -> String {
    let groups: Vec<String> = Sha256::digest(hashed)[..8]
        .chunks(2)
        .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
        .collect();
    groups.join("-")
}

/// A partition in memory that gives at most `most` bytes a read, records what each read asked for,
/// and fails once with each of `faults` when a read starts at or past its offset.
struct Device {
    bytes: Vec<u8>,
    /// The bytes read so far.
    at: usize,
    most: usize,
    /// What each read asked for, in order.
    asked: Vec<usize>,
    faults: VecDeque<(usize, ErrorKind)>,
    /// The reads that failed, by their index in `asked`.
    failed: Vec<usize>,
}

impl Device {
    fn new(bytes: Vec<u8>, most: usize, faults: &[(usize, ErrorKind)]) -> Self {
        Device {
            bytes,
            at: 0,
            most,
            asked: Vec::new(),
            faults: faults.iter().copied().collect(),
            failed: Vec::new(),
        }
    }
}

impl Read for Device {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.asked.push(buf.len());
        if let Some(&(offset, kind)) = self.faults.front()
            && self.at >= offset
        {
            self.faults.pop_front();
            self.failed.push(self.asked.len() - 1);
            return Err(kind.into());
        }
        let count = buf.len().min(self.most).min(self.bytes.len() - self.at);
        buf[..count].copy_from_slice(&self.bytes[self.at..self.at + count]);
        self.at += count;
        Ok(count)
    }
}

/// The plan's vector (group 9), byte for byte: the magic, version 4.0 and `bytes_used` 4,096 are
/// its only bytes that are not zero. Its prefix is pinned, and equals the one worked out here.
#[test]
fn the_vector_gives_the_pinned_prefix() {
    let vector = partition(4_096, 4 * KIB, zero);
    assert_eq!(vector.len(), 4_096);
    assert_eq!(&vector[..4], b"hsqs");
    assert_eq!(vector[28..32], [4, 0, 0, 0]);
    assert_eq!(vector[40..48], [0x00, 0x10, 0, 0, 0, 0, 0, 0]);
    // h, s, q and s; the major version 4; 0x10, bytes_used's second byte.
    assert_eq!(vector.iter().filter(|&&byte| byte != 0).count(), 6);

    assert_eq!(prefix(&vector[..], 4_096), Ok(String::from(VECTOR_PREFIX)));
    assert_eq!(expected(&vector), VECTOR_PREFIX);
}

/// pi-firmware.md: the digest's first 8 bytes as 16 lowercase hex characters in four
/// dash-separated groups of four, high nibble first; the rest of the digest is not shown.
#[test]
fn the_prefix_is_the_first_8_bytes_in_four_dashed_groups_of_lowercase_hex() {
    let mut digest = [0xFF; 32];
    digest[..8].copy_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
    assert_eq!(grouped(&digest), "0123-4567-89ab-cdef");
    let digest = [0x00; 32];
    assert_eq!(grouped(&digest), "0000-0000-0000-0000");
    let mut digest = [0x00; 32];
    digest[..8].copy_from_slice(&[0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10]);
    assert_eq!(grouped(&digest), "fedc-ba98-7654-3210");
    // 19 characters, the width group 4's fit test gives the boot screen and About.
    assert_eq!(VECTOR_PREFIX.len(), 19);
}

/// The length hashed is `bytes_used` rounded up to 4,096, whatever the partition holds past it: a
/// change to the last byte hashed changes the prefix, and one to the first byte past it does not.
#[test]
fn the_length_hashed_is_bytes_used_rounded_up_to_4096_and_nothing_past_it() {
    let len = 16 * KIB + 100;
    for (bytes_used, hashed) in [
        (96, 4_096),
        (4_095, 4_096),
        (4_096, 4_096),
        (4_097, 8_192),
        (12_288, 12_288),
        (12_289, 16_384),
    ] {
        let image = partition(bytes_used, len, pattern);
        let shown = prefix(&image[..], len_of(len));
        assert_eq!(shown, Ok(expected(&image[..hashed])), "{bytes_used}");

        let mut last = image.clone();
        last[hashed - 1] ^= 1;
        assert_ne!(prefix(&last[..], len_of(len)), shown, "{bytes_used}");
        let mut past = image;
        past[hashed] ^= 1;
        assert_eq!(prefix(&past[..], len_of(len)), shown, "{bytes_used}");
    }
}

/// The superblock, then reads of 64 KiB and the rest, up to the length hashed and no further: a
/// 200,000-byte image (49 × 4,096 = 200,704 bytes hashed) in a 1 MiB partition. A device that gives
/// less than each read asks for, at most 1,000 bytes, gives the same prefix.
#[test]
fn reads_ask_for_at_most_64_kib_and_stop_at_the_length_hashed() {
    let len = 1_024 * KIB;
    let image = partition(200_000, len, pattern);
    let want = Ok(expected(&image[..200_704]));

    let mut device = Device::new(image.clone(), usize::MAX, &[]);
    assert_eq!(prefix(&mut device, len_of(len)), want);
    assert_eq!(device.asked, [96, 65_536, 65_536, 65_536, 4_000]);
    assert_eq!(device.at, 200_704);

    // The superblock in one read, each 64 KiB in 66 (65 of 1,000 and one of 536), the 4,000 in 4.
    let mut device = Device::new(image, 1_000, &[]);
    assert_eq!(prefix(&mut device, len_of(len)), want);
    assert_eq!(device.at, 200_704);
    assert!(device.asked.iter().all(|&asked| asked <= 65_536));
    assert_eq!(device.asked.len(), 1 + 3 * 66 + 4);
}

/// An interrupted read is read again, for the same bytes.
#[test]
fn an_interrupted_read_is_read_again() {
    let image = partition(8_192, 8 * KIB, pattern);
    let interrupted = [
        (0, ErrorKind::Interrupted),
        (96, ErrorKind::Interrupted),
        (5_000, ErrorKind::Interrupted),
    ];
    let mut device = Device::new(image.clone(), 1_000, &interrupted);
    assert_eq!(prefix(&mut device, 8_192), Ok(expected(&image)));
    assert_eq!(device.failed.len(), 3);
    assert_eq!(device.at, 8_192);
}

/// Anything but a SquashFS 4.0 superblock is `RootFs`, "the root filesystem could not be read",
/// which halts, after the superblock and nothing more is read: the big-endian magic, another magic
/// or none, version 3.0, 4.1 or 5.0, and a big-endian 4.0.
#[test]
fn anything_but_a_squashfs_4_0_superblock_is_refused() {
    assert_eq!(
        HalError::RootFs.text(),
        "the root filesystem could not be read"
    );
    assert!(HalError::RootFs.halts());

    for (at, bytes) in [
        (0, *b"sqsh"),
        (0, *b"hsqt"),
        (0, [0; 4]),
        (28, [3, 0, 0, 0]),
        (28, [4, 0, 1, 0]),
        (28, [5, 0, 0, 0]),
        (28, [0, 4, 0, 0]),
    ] {
        let mut image = partition(4_096, 4 * KIB, zero);
        image[at..at + 4].copy_from_slice(&bytes);
        let mut device = Device::new(image, usize::MAX, &[]);
        assert_eq!(
            prefix(&mut device, 4_096),
            Err(HalError::RootFs),
            "{bytes:?}"
        );
        assert_eq!(device.asked, [96]);
    }
}

/// A `bytes_used` below the superblock's 96 bytes, or one that rounds past the partition (or past
/// `u64::MAX`), is `RootFs` before anything past the superblock is read. A length that ends at the
/// partition's end is read. A partition whose length is not a multiple of 4,096 holds only the
/// lengths that fit it.
#[test]
fn a_bytes_used_below_the_superblock_or_past_the_partition_is_refused() {
    let len = 12 * KIB;
    for bytes_used in [0, 1, 95, 12_289, 16_384, u64::MAX - 4_095, u64::MAX] {
        let image = partition(bytes_used, len, pattern);
        let mut device = Device::new(image, usize::MAX, &[]);
        assert_eq!(
            prefix(&mut device, len_of(len)),
            Err(HalError::RootFs),
            "{bytes_used}"
        );
        assert_eq!(device.asked, [96], "{bytes_used}");
    }
    for (bytes_used, hashed) in [(96, 4_096), (12_287, 12_288), (12_288, 12_288)] {
        let image = partition(bytes_used, len, pattern);
        assert_eq!(
            prefix(&image[..], len_of(len)),
            Ok(expected(&image[..hashed])),
            "{bytes_used}"
        );
    }

    let image = partition(5_000, 6_000, pattern);
    assert_eq!(prefix(&image[..], 6_000), Err(HalError::RootFs));
    let image = partition(4_096, 6_000, pattern);
    assert_eq!(prefix(&image[..], 6_000), Ok(expected(&image[..4_096])));
}

/// A read that ends before the length hashed (inside the superblock, or one byte short) or fails
/// is `RootFs`, with no read after it.
#[test]
fn a_read_that_ends_early_or_fails_is_refused() {
    let image = partition(8_192, 8 * KIB, pattern);
    for cut in [0, 95, 96, 4_096, 8_191] {
        assert_eq!(prefix(&image[..cut], 8_192), Err(HalError::RootFs), "{cut}");
    }
    // At most 1,000 bytes a read: reads start at 0, 96, 1,096, … 8,096 (the last).
    for (offset, kind) in [
        (0, ErrorKind::Other),
        (0, ErrorKind::UnexpectedEof),
        (96, ErrorKind::PermissionDenied),
        (5_000, ErrorKind::InvalidData),
        (8_096, ErrorKind::BrokenPipe),
    ] {
        let mut device = Device::new(image.clone(), 1_000, &[(offset, kind)]);
        assert_eq!(
            prefix(&mut device, 8_192),
            Err(HalError::RootFs),
            "{kind:?}"
        );
        assert_eq!(device.failed, [device.asked.len() - 1], "{kind:?}");
    }
}
