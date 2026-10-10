//! The bucket tree behind a snapshot's signed root (CLAUDE.md "Bucket proof";
//! docs/seal-watchonly-braille.md "Snapshot format"; tasks/todo.md, M1 group 7, Q6b).
//!
//! - 2^20 buckets, one per 20-bit prefix of T, in index order.
//! - leaf(i) = SHA-256(0x00 || "KCE/v1/bucket" || i as 3 bytes || bucket i's entries), where i as
//!   3 bytes is the bucket index as a 24-bit big-endian integer (2b810... is 02 b8 10), never the
//!   prefix left-aligned (2b 81 00).
//! - node = SHA-256(0x01 || left || right).
//! - A snapshot's root comes from one streaming pass over the sorted body, with at most 21 stacked
//!   hashes; a proof's root from its leaf and 20 siblings, leaf level first, the node on the right
//!   at level j when (i >> j) & 1 = 1.
//!
//! vectors/kcr.json pins empty leaves, a node, the empty root and the vector-1 path.

use sha2::{Digest, Sha256};

/// Bits of the bucket index.
pub(crate) const BUCKET_BITS: usize = 20;
/// The number of buckets: 2^20.
pub(crate) const BUCKETS: u32 = 1 << BUCKET_BITS;
/// The leaf's domain tag.
const BUCKET_DOMAIN: &[u8] = b"KCE/v1/bucket";
/// Bytes per entry: T[0..16] and a u16 count.
pub(crate) const ENTRY_BYTES: usize = 18;

/// The bucket of a tag, T[0..16] or an entry: its first 20 bits.
pub(crate) fn bucket_of<const N: usize>(tag: &[u8; N]) -> u32 {
    const { assert!(N >= 3, "a bucket needs 3 bytes") };
    u32::from_be_bytes([0, tag[0], tag[1], tag[2]]) >> 4
}

/// The leaf of bucket `index` (below 2^20) holding `entries`.
pub(crate) fn leaf(index: u32, entries: &[u8]) -> [u8; 32] {
    let be = index.to_be_bytes();
    Sha256::new()
        .chain_update([0x00])
        .chain_update(BUCKET_DOMAIN)
        .chain_update(&be[1..])
        .chain_update(entries)
        .finalize()
        .into()
}

/// The node over two children.
pub(crate) fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update([0x01])
        .chain_update(left)
        .chain_update(right)
        .finalize()
        .into()
}

/// The root over a body of entries in ascending order (the caller has checked the order): every
/// bucket's leaf in index order, folded like a binary counter, so at most one pending node per
/// level, 21 in all.
pub(crate) fn root_of_body(body: &[[u8; ENTRY_BYTES]]) -> [u8; 32] {
    let leaf_state = Sha256::new()
        .chain_update([0x00])
        .chain_update(BUCKET_DOMAIN);
    let mut pending = [[0u8; 32]; BUCKET_BITS + 1];
    let mut next = 0usize;
    for index in 0..BUCKETS {
        let start = next;
        while next < body.len() && bucket_of(&body[next]) == index {
            next += 1;
        }
        let be = index.to_be_bytes();
        let mut state = leaf_state.clone();
        state.update(&be[1..]);
        for entry in &body[start..next] {
            state.update(entry);
        }
        let mut hash: [u8; 32] = state.finalize().into();
        let mut level = 0;
        while index >> level & 1 == 1 {
            hash = node(&pending[level], &hash);
            level += 1;
        }
        pending[level] = hash;
    }
    pending[BUCKET_BITS]
}

/// The root a bucket's leaf and its path give.
pub(crate) fn root_of_path(
    index: u32,
    entries: &[u8],
    siblings: &[[u8; 32]; BUCKET_BITS],
) -> [u8; 32] {
    let mut hash = leaf(index, entries);
    for (level, sibling) in siblings.iter().enumerate() {
        hash = if index >> level & 1 == 1 {
            node(sibling, &hash)
        } else {
            node(&hash, sibling)
        };
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::{hex, read};

    fn arr32(v: &serde_json::Value) -> [u8; 32] {
        hex(v).try_into().expect("32 bytes")
    }

    #[test]
    fn leaves_nodes_and_the_left_aligned_reading() {
        let doc = read("kcr.json");
        let merkle = &doc["merkle"];
        for leaf_case in merkle["empty_leaves"].as_array().expect("leaves") {
            let index = u32::try_from(leaf_case["bucket"].as_u64().expect("bucket")).expect("u32");
            assert_eq!(leaf(index, &[]), arr32(&leaf_case["leaf_hex"]), "{index}");
        }
        let n = &merkle["node"];
        assert_eq!(
            node(&arr32(&n["left_hex"]), &arr32(&n["right_hex"])),
            arr32(&n["node_hex"])
        );
        // 2b810 is bucket 02 b8 10; the left-aligned 2b 81 00 is another leaf, never used.
        let aligned = &merkle["left_aligned_leaf"];
        assert_eq!(hex(&aligned["prefix_hex"]), [0x2b, 0x81, 0x00]);
        assert_ne!(leaf(0x2b810, &[]), arr32(&aligned["leaf_hex"]));
        assert_eq!(leaf(0x2b8100 >> 4, &[]), leaf(0x2b810, &[]));
        assert_eq!(bucket_of(&[0x2b, 0x81, 0x03]), 0x2b810);
    }

    #[test]
    fn the_vector_1_path_gives_its_root() {
        let doc = read("kcr.json");
        let path = &doc["merkle"]["vector_1_path"];
        let index = u32::try_from(path["bucket"].as_u64().expect("bucket")).expect("u32");
        let siblings: Vec<[u8; 32]> = path["siblings_hex"]
            .as_array()
            .expect("siblings")
            .iter()
            .map(arr32)
            .collect();
        let siblings: [[u8; 32]; BUCKET_BITS] = siblings.try_into().expect("20 siblings");
        assert_eq!(
            root_of_path(index, &hex(&path["entries_hex"]), &siblings),
            arr32(&path["root_hex"])
        );
    }

    // The empty snapshot's root, from a full streaming pass over all 2^20 buckets. Its time is the
    // profile question in tasks/todo.md, M1 group 1.
    #[test]
    fn the_empty_root() {
        let doc = read("kcr.json");
        assert_eq!(root_of_body(&[]), arr32(&doc["merkle"]["empty_root_hex"]));
    }
}
