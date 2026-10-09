//! Signed bucket proofs, KCP1, behind the go-ahead QR (docs/seal-watchonly-braille.md "Go-ahead QR";
//! tasks/todo.md, M1 group 7, Q2 and Q6c).
//!
//! KCP1 = `KCP1` || the 58-byte snapshot header || its signature || bucket index (3 bytes) || entry
//! count k (u16) || k entries || the 20 siblings of the bucket's Merkle path, leaf level first:
//! exactly 771 + 18k bytes. The checks run in this order:
//!
//! 1. length at least 771 (`TooShort`);
//! 2. magic `KCP1` (`BadMagic`);
//! 3. the snapshot's header checks, magic to count, with the same code (`BadMagic`, `BadVersion`,
//!    `BadSignature`, `BadDate`, `TooManyEntries`);
//! 4. bucket below 2^20 (`BucketOutOfRange`);
//! 5. the exact length, 771 + 18k (`BadLength`);
//! 6. k at most the header's count (`ProofCount`);
//! 7. in entry order: each entry in this bucket (`EntryOutsideBucket`), above the one before
//!    (`Duplicate`, `Unsorted`), with a non-zero count (`ZeroCount`);
//! 8. the root from the leaf and the path equals the header's (`RootMismatch`).
//!
//! The go-ahead QR is a single-part `ur:keepcrypt-proof/...` whose CBOR is one byte string holding
//! the KCP1 bytes, read by the strict decoder (`ur::ur_decode_single`; a failure is `Ur(UrError)`).
//! A verified proof tells a seal in its bucket whether it is registered; a seal in another bucket
//! gets `WrongBucket`, which the session treats as a retry.

use core::num::NonZeroU16;

use ed25519_dalek::VerifyingKey;

use super::SealTag;
use super::date::{Freshness, RegistryDate};
use super::merkle::{BUCKET_BITS, BUCKETS, ENTRY_BYTES, root_of_path};
use super::registry_key;
use super::snapshot::{Header, SIGNED_BYTES, check_entries, find, read_header};
use crate::error::{CheckError, CoreError, KatId, SnapshotError};
use crate::kat::{self, Suite};
use crate::ur::ur_decode_single;

/// The proof's magic.
const MAGIC: &[u8; 4] = b"KCP1";
/// The go-ahead QR's UR type.
pub(crate) const PROOF_UR_TYPE: &str = "keepcrypt-proof";
/// The bytes before the entries: magic, header, signature, bucket, k.
const PREFIX_BYTES: usize = 4 + SIGNED_BYTES + 3 + 2;
/// A proof with no entries: the prefix and the 20 siblings, 771 bytes.
pub(crate) const BASE_BYTES: usize = PREFIX_BYTES + 32 * BUCKET_BITS;

/// A proof that passed every check: its header fields, its bucket and the bucket's entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProof {
    header: Header,
    bucket: u32,
    entries: Vec<[u8; ENTRY_BYTES]>,
}

impl VerifiedProof {
    /// The bucket this proof covers: one 20-bit prefix of T.
    pub fn bucket(&self) -> u32 {
        self.bucket
    }

    /// The number of the snapshot the proof comes from.
    pub fn number(&self) -> u64 {
        self.header.number
    }

    /// The snapshot's UTC date, shown with the go-ahead ("as of").
    pub fn date(&self) -> RegistryDate {
        self.header.date
    }

    /// The same date rule as a loaded snapshot: Current up to 30 days before `today`, Stale from
    /// day 31, Future after `today`. Phones warn on Stale and Future; the Pi shows the date and asks
    /// the user to confirm it before `reveal`.
    pub fn freshness(&self, today: RegistryDate) -> Freshness {
        self.header.date.freshness(today)
    }

    /// The number of entries in the bucket (k).
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// For a seal in this bucket: its registration count, or None when it is clear. A seal in
    /// another bucket is `WrongBucket`: this proof says nothing about it.
    pub fn lookup(&self, tag: &SealTag) -> Result<Option<NonZeroU16>, CheckError> {
        if tag.bucket() != self.bucket {
            return Err(CheckError::WrongBucket);
        }
        Ok(find(&self.entries, tag))
    }
}

/// Checks KCP1 bytes against `key`, in the order of the module comment.
pub(crate) fn verify_with_key(
    proof: &[u8],
    key: &VerifyingKey,
) -> Result<VerifiedProof, SnapshotError> {
    if proof.len() < BASE_BYTES {
        return Err(SnapshotError::TooShort);
    }
    let Some((magic, rest)) = proof.split_first_chunk::<4>() else {
        return Err(SnapshotError::TooShort);
    };
    if magic != MAGIC {
        return Err(SnapshotError::BadMagic);
    }
    let Some((signed, rest)) = rest.split_first_chunk::<SIGNED_BYTES>() else {
        return Err(SnapshotError::TooShort);
    };
    let header = read_header(signed, key)?;
    let Some((&[b0, b1, b2, k0, k1], rest)) = rest.split_first_chunk::<5>() else {
        return Err(SnapshotError::TooShort);
    };
    let bucket = u32::from_be_bytes([0, b0, b1, b2]);
    if bucket >= BUCKETS {
        return Err(SnapshotError::BucketOutOfRange);
    }
    let k = usize::from(u16::from_be_bytes([k0, k1]));
    let Some(entry_bytes) = k.checked_mul(ENTRY_BYTES) else {
        return Err(SnapshotError::BadLength);
    };
    if rest.len() != entry_bytes + 32 * BUCKET_BITS {
        return Err(SnapshotError::BadLength);
    }
    if k > header.count {
        return Err(SnapshotError::ProofCount);
    }
    let (entry_part, path_part) = rest.split_at(entry_bytes);
    let (entries, _) = entry_part.as_chunks::<ENTRY_BYTES>();
    check_entries(entries, Some(bucket))?;
    let (siblings, _) = path_part.as_chunks::<32>();
    let Ok(siblings) = <&[[u8; 32]; BUCKET_BITS]>::try_from(siblings) else {
        return Err(SnapshotError::BadLength);
    };
    if root_of_path(bucket, entry_part, siblings) != header.root {
        return Err(SnapshotError::RootMismatch);
    }
    Ok(VerifiedProof {
        header,
        bucket,
        entries: entries.to_vec(),
    })
}

/// Verifies KCP1 bytes from a go-ahead QR against the key this build pins, after the Ed25519 and
/// Merkle known-answer groups. A release build pins no key: `NoRegistryKey`.
pub fn verify_bucket_proof(proof: &[u8]) -> Result<VerifiedProof, CoreError> {
    verify_bucket_proof_body(proof, None)
}

/// Verifies a go-ahead QR's text, a single-part `ur:keepcrypt-proof/...`, read by the strict
/// decoder, then as `verify_bucket_proof`. The key is needed before the text is read.
pub fn verify_bucket_proof_qr(text: &str) -> Result<VerifiedProof, CoreError> {
    verify_bucket_proof_qr_body(text, None)
}

/// `verify_bucket_proof` with known-answer group `fault` made to fail (tests only).
#[cfg(feature = "test-sources")]
pub fn verify_bucket_proof_with_kat_fault(
    proof: &[u8],
    fault: KatId,
) -> Result<VerifiedProof, CoreError> {
    verify_bucket_proof_body(proof, Some(fault))
}

/// `verify_bucket_proof_qr` with known-answer group `fault` made to fail (tests only).
#[cfg(feature = "test-sources")]
pub fn verify_bucket_proof_qr_with_kat_fault(
    text: &str,
    fault: KatId,
) -> Result<VerifiedProof, CoreError> {
    verify_bucket_proof_qr_body(text, Some(fault))
}

fn verify_bucket_proof_body(
    proof: &[u8],
    fault: Option<KatId>,
) -> Result<VerifiedProof, CoreError> {
    kat::run(Suite::Registry, fault)?;
    let key = registry_key::pinned_key()?;
    verify_with_key(proof, &key).map_err(CoreError::Snapshot)
}

fn verify_bucket_proof_qr_body(
    text: &str,
    fault: Option<KatId>,
) -> Result<VerifiedProof, CoreError> {
    kat::run(Suite::Registry, fault)?;
    let key = registry_key::pinned_key()?;
    let proof = ur_decode_single(PROOF_UR_TYPE, text)
        .map_err(|e| CoreError::Snapshot(SnapshotError::Ur(e)))?;
    verify_with_key(&proof, &key).map_err(CoreError::Snapshot)
}

#[cfg(test)]
mod tests {
    use super::super::snapshot;
    use super::*;
    use crate::test_vectors::{hex, read, text};
    use serde_json::Value;

    fn test_key() -> VerifyingKey {
        let bytes: [u8; 32] = hex(&read("kcr.json")["keys"]["test_registry"]["public_key_hex"])
            .try_into()
            .expect("32 bytes");
        VerifyingKey::from_bytes(&bytes).expect("the test key")
    }

    fn tag_of(doc: &Value, seed: &str) -> SealTag {
        let seed = crate::test_vectors::named(&doc["seeds"], seed);
        SealTag::from_bytes(hex(&seed["seal_tag_hex"]).try_into().expect("32 bytes"))
    }

    fn verify_case(case: &Value, key: &VerifyingKey) -> Result<VerifiedProof, SnapshotError> {
        if let Some(text) = case["ur"].as_str() {
            let proof = ur_decode_single(PROOF_UR_TYPE, text).map_err(SnapshotError::Ur)?;
            verify_with_key(&proof, key)
        } else {
            verify_with_key(&hex(&case["kcp1_hex"]), key)
        }
    }

    // Every kcr.json proof case gives its exact result: Current at day 30, Stale at day 31 and
    // Future a day ahead; clear, collision and wrong-bucket lookups; and every rejection, the UR
    // decoder's included.
    #[test]
    fn every_proof_case() {
        let doc = read("kcr.json");
        let key = test_key();
        let today = RegistryDate::from_yyyymmdd(
            u32::try_from(doc["today"].as_u64().expect("today")).expect("u32"),
        )
        .expect("a date");
        let mut errors = Vec::new();
        for case in doc["proofs"].as_array().expect("proofs") {
            let name = text(&case["name"]);
            let expect = &case["expect"];
            match verify_case(case, &key) {
                Ok(proof) => {
                    assert_eq!(expect["ok"], true, "{name}");
                    assert_eq!(
                        Some(u64::from(proof.bucket())),
                        expect["bucket"].as_u64(),
                        "{name}"
                    );
                    assert_eq!(Some(proof.number()), expect["number"].as_u64(), "{name}");
                    assert_eq!(
                        Some(u64::from(proof.date().yyyymmdd())),
                        expect["date"].as_u64(),
                        "{name}"
                    );
                    assert_eq!(
                        Some(u64::try_from(proof.entry_count()).expect("k")),
                        expect["k"].as_u64(),
                        "{name}"
                    );
                    assert_eq!(
                        format!("{:?}", proof.freshness(today)),
                        text(&expect["freshness"]),
                        "{name}"
                    );
                    for lookup in expect["lookups"].as_array().expect("lookups") {
                        let got = proof.lookup(&tag_of(&doc, text(&lookup["seed"])));
                        let want = match text(&lookup["result"]) {
                            "wrong_bucket" => Err(CheckError::WrongBucket),
                            "clear" => Ok(None),
                            _ => Ok(NonZeroU16::new(
                                u16::try_from(lookup["count"].as_u64().expect("count"))
                                    .expect("u16"),
                            )),
                        };
                        assert_eq!(got, want, "{name}");
                    }
                }
                Err(e) => {
                    assert_eq!(expect["ok"], false, "{name}");
                    assert_eq!(format!("{e:?}"), text(&expect["error"]), "{name}");
                    errors.push(e);
                }
            }
        }
        for want in [
            SnapshotError::TooShort,
            SnapshotError::BadMagic,
            SnapshotError::BadVersion,
            SnapshotError::BadSignature,
            SnapshotError::BadDate,
            SnapshotError::TooManyEntries,
            SnapshotError::BadLength,
            SnapshotError::Unsorted,
            SnapshotError::Duplicate,
            SnapshotError::ZeroCount,
            SnapshotError::RootMismatch,
            SnapshotError::BucketOutOfRange,
            SnapshotError::EntryOutsideBucket,
            SnapshotError::ProofCount,
        ] {
            assert!(errors.contains(&want), "{want:?} is never produced");
        }
        assert!(errors.iter().any(|e| matches!(e, SnapshotError::Ur(_))));
    }

    // Each registry function runs the Ed25519 and Merkle groups, and only those: a fault in either
    // fails it with that group's id; any other fault leaves the result unchanged.
    #[cfg(feature = "test-sources")]
    #[test]
    fn every_kat_fault_reaches_the_registry_functions_only_for_their_groups() {
        use super::super::snapshot::verify_snapshot_with_kat_fault;
        let doc = read("kcr.json");
        let small = hex(&crate::test_vectors::named(&doc["snapshots"], "empty")["kcr_hex"]);
        let proof =
            hex(&crate::test_vectors::named(&doc["proofs"], "clear-shared-prefix")["kcp1_hex"]);
        let qr = text(&crate::test_vectors::named(&doc["proofs"], "ur-lowercase")["ur"]).to_owned();
        for id in KatId::ALL {
            let faulted = matches!(id, KatId::Ed25519 | KatId::Merkle);
            let results = [
                verify_snapshot_with_kat_fault(&small, id).map(|_| ()),
                verify_bucket_proof_with_kat_fault(&proof, id).map(|_| ()),
                verify_bucket_proof_qr_with_kat_fault(&qr, id).map(|_| ()),
            ];
            for result in results {
                if faulted {
                    assert_eq!(result, Err(CoreError::Kat(id)), "{id:?}");
                } else {
                    assert_eq!(result, Ok(()), "{id:?}");
                }
            }
        }
    }

    // The proof's header is the snapshot's: its signed header and root equal those of the
    // snapshot it was cut from, and every header bit flip and truncation fails.
    #[test]
    fn a_proof_reuses_its_snapshots_header() {
        let doc = read("kcr.json");
        let key = test_key();
        let small = hex(&crate::test_vectors::named(&doc["snapshots"], "small")["kcr_hex"]);
        let proof =
            hex(&crate::test_vectors::named(&doc["proofs"], "clear-shared-prefix")["kcp1_hex"]);
        assert_eq!(&proof[4..4 + SIGNED_BYTES], &small[..SIGNED_BYTES]);
        let verified = verify_with_key(&proof, &key).expect("valid");
        let snapshot = snapshot::verify_with_key(&small, &key).expect("valid");
        assert_eq!(verified.date(), snapshot.date());
        assert_eq!(verified.number(), snapshot.number());
        for bit in 0..8 * PREFIX_BYTES {
            let mut flipped = proof.clone();
            flipped[bit / 8] ^= 1 << (bit % 8);
            assert!(verify_with_key(&flipped, &key).is_err(), "bit {bit}");
        }
        for len in 0..proof.len() {
            assert!(
                verify_with_key(&proof[..len], &key).is_err(),
                "length {len}"
            );
        }
        assert_eq!(BASE_BYTES, 771);
        assert_eq!(read("kcr.json")["limits"]["proof_base_bytes"], BASE_BYTES);
    }
}
