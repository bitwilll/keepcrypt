//! Signed registry snapshots, `.kcr` (docs/seal-watchonly-braille.md "Snapshot format";
//! docs/build-plan.md `verify_snapshot` and CI rule "Only authentic snapshots are used";
//! tasks/todo.md, M1 group 7, Q6b).
//!
//! A snapshot is a 58-byte header (magic `KCR1`, version u16 = 1, number u64, date u32 YYYYMMDD,
//! entry count u64, bucket root), a pure Ed25519 signature over exactly those 58 bytes, then the
//! entries: T[0..16] and a u16 registration count of at least 1, strictly ascending, at most 2^22.
//! All integers are big-endian. The checks run in this order, the first failure winning:
//!
//! 1. length at least 122 (`TooShort`);
//! 2. magic (`BadMagic`);
//! 3. version 1 (`BadVersion`);
//! 4. ed25519-dalek `verify_strict` over the 58 header bytes, against the pinned key
//!    (`BadSignature`);
//! 5. a real date (`BadDate`);
//! 6. count at most 2^22, through a checked u64-to-usize conversion, since the Pi is 32-bit
//!    (`TooManyEntries`);
//! 7. the exact length, 122 + 18 x count (`BadLength`);
//! 8. a cheap pre-pass in entry order: each entry above the one before (`Duplicate`, `Unsorted`),
//!    then its count non-zero (`ZeroCount`);
//! 9. the root recomputed over all 2^20 buckets (`RootMismatch`).
//!
//! Steps 2 to 6 are the header checks a KCP1 proof shares (`read_header`). `verify_snapshot` runs
//! the Ed25519 and Merkle known-answer groups first, then needs the pinned key: a release build
//! pins none, so it refuses every file with `NoRegistryKey` before reading a byte.

use core::num::NonZeroU16;

use ed25519_dalek::{Signature, VerifyingKey};

use super::SealTag;
use super::date::{Freshness, RegistryDate};
use super::merkle::{ENTRY_BYTES, root_of_body};
use super::registry_key;
use crate::error::{CoreError, KatId, SnapshotError};
use crate::kat::{self, Suite};

/// The header's magic.
const MAGIC: &[u8; 4] = b"KCR1";
/// The only format version.
const VERSION: u16 = 1;
/// The header: magic 4, version 2, number 8, date 4, count 8, root 32.
pub(crate) const HEADER_BYTES: usize = 58;
/// The header and its signature.
pub(crate) const SIGNED_BYTES: usize = HEADER_BYTES + 64;
/// The most entries a snapshot may hold (Q6b): 75.5 MB in all.
pub(crate) const MAX_ENTRIES: u64 = 1 << 22;

/// A verified header's fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    pub(crate) number: u64,
    pub(crate) date: RegistryDate,
    /// At most 2^22.
    pub(crate) count: usize,
    pub(crate) root: [u8; 32],
}

/// The shared header checks, magic to count, over a header and its signature.
pub(crate) fn read_header(
    signed: &[u8; SIGNED_BYTES],
    key: &VerifyingKey,
) -> Result<Header, SnapshotError> {
    let (header, signature) = signed.split_at(HEADER_BYTES);
    if &header[..4] != MAGIC {
        return Err(SnapshotError::BadMagic);
    }
    if u16::from_be_bytes([header[4], header[5]]) != VERSION {
        return Err(SnapshotError::BadVersion);
    }
    let mut signature_bytes = [0u8; 64];
    signature_bytes.copy_from_slice(signature);
    if key
        .verify_strict(header, &Signature::from_bytes(&signature_bytes))
        .is_err()
    {
        return Err(SnapshotError::BadSignature);
    }
    let number = u64::from_be_bytes(array(&header[6..14]));
    let date = RegistryDate::from_yyyymmdd(u32::from_be_bytes(array(&header[14..18])))
        .map_err(|_| SnapshotError::BadDate)?;
    let count = u64::from_be_bytes(array(&header[18..26]));
    if count > MAX_ENTRIES {
        return Err(SnapshotError::TooManyEntries);
    }
    let Ok(count) = usize::try_from(count) else {
        return Err(SnapshotError::TooManyEntries);
    };
    Ok(Header {
        number,
        date,
        count,
        root: array(&header[26..58]),
    })
}

/// `N` bytes from a slice of exactly `N` (the callers slice fixed ranges of a fixed-size array).
fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    out
}

/// The pre-pass, in entry order: each entry above the one before (`Duplicate`, `Unsorted`), then
/// its count (`ZeroCount`). A proof first checks each entry's bucket (`bucket`).
pub(crate) fn check_entries(
    entries: &[[u8; ENTRY_BYTES]],
    bucket: Option<u32>,
) -> Result<(), SnapshotError> {
    let mut previous: Option<&[u8]> = None;
    for entry in entries {
        if let Some(bucket) = bucket
            && super::merkle::bucket_of(entry) != bucket
        {
            return Err(SnapshotError::EntryOutsideBucket);
        }
        let tag = &entry[..16];
        if let Some(previous) = previous {
            match tag.cmp(previous) {
                core::cmp::Ordering::Equal => return Err(SnapshotError::Duplicate),
                core::cmp::Ordering::Less => return Err(SnapshotError::Unsorted),
                core::cmp::Ordering::Greater => {}
            }
        }
        if entry[16] == 0 && entry[17] == 0 {
            return Err(SnapshotError::ZeroCount);
        }
        previous = Some(tag);
    }
    Ok(())
}

/// The registration count of `tag` among verified entries (ascending, counts at least 1).
pub(crate) fn find(entries: &[[u8; ENTRY_BYTES]], tag: &SealTag) -> Option<NonZeroU16> {
    let wanted = &tag.as_bytes()[..16];
    match entries.binary_search_by(|entry| entry[..16].cmp(wanted)) {
        // Verification refused zero counts; a zero here would still be reported as registered,
        // never as clear.
        Ok(at) => Some(
            match NonZeroU16::new(u16::from_be_bytes([entries[at][16], entries[at][17]])) {
                Some(count) => count,
                None => NonZeroU16::MIN,
            },
        ),
        Err(_) => None,
    }
}

/// A snapshot that passed every check: its header fields and its entries. It survives a session
/// restart, so a snapshot loaded before the ceremony serves every check (`GoAhead::Snapshot`).
pub struct VerifiedSnapshot {
    header: Header,
    entries: Box<[[u8; ENTRY_BYTES]]>,
}

impl core::fmt::Debug for VerifiedSnapshot {
    /// The header fields only: the entries can be 75 MB.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifiedSnapshot")
            .field("number", &self.header.number)
            .field("date", &self.header.date)
            .field("count", &self.header.count)
            .finish_non_exhaustive()
    }
}

impl VerifiedSnapshot {
    /// The snapshot's number.
    pub fn number(&self) -> u64 {
        self.header.number
    }

    /// The snapshot's UTC date, shown on screen ("as of").
    pub fn date(&self) -> RegistryDate {
        self.header.date
    }

    /// Current up to 30 days before `today`, Stale from day 31, Future after `today`. Phones warn on
    /// Stale and Future; the Pi, which has no clock, shows the date for the user to confirm.
    pub fn freshness(&self, today: RegistryDate) -> Freshness {
        self.header.date.freshness(today)
    }

    /// The number of registered seals.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// The registration count of this tag, or None when no seal with its first 16 bytes is
    /// registered.
    pub fn lookup(&self, tag: &SealTag) -> Option<NonZeroU16> {
        find(&self.entries, tag)
    }
}

/// Checks a snapshot against `key`, in the order of the module comment.
pub(crate) fn verify_with_key(
    file: &[u8],
    key: &VerifyingKey,
) -> Result<VerifiedSnapshot, SnapshotError> {
    let Some((signed, body)) = file.split_first_chunk::<SIGNED_BYTES>() else {
        return Err(SnapshotError::TooShort);
    };
    let header = read_header(signed, key)?;
    let (entries, rest) = body.as_chunks::<ENTRY_BYTES>();
    if !rest.is_empty() || entries.len() != header.count {
        return Err(SnapshotError::BadLength);
    }
    check_entries(entries, None)?;
    if root_of_body(entries) != header.root {
        return Err(SnapshotError::RootMismatch);
    }
    Ok(VerifiedSnapshot {
        header,
        entries: entries.into(),
    })
}

/// Verifies a signed registry snapshot (`.kcr`) against the key this build pins, after the
/// Ed25519 and Merkle known-answer groups. A release build pins no key: `NoRegistryKey`.
pub fn verify_snapshot(file: &[u8]) -> Result<VerifiedSnapshot, CoreError> {
    verify_snapshot_body(file, None)
}

/// `verify_snapshot` with known-answer group `fault` made to fail (tests only).
#[cfg(feature = "test-sources")]
pub fn verify_snapshot_with_kat_fault(
    file: &[u8],
    fault: KatId,
) -> Result<VerifiedSnapshot, CoreError> {
    verify_snapshot_body(file, Some(fault))
}

fn verify_snapshot_body(file: &[u8], fault: Option<KatId>) -> Result<VerifiedSnapshot, CoreError> {
    kat::run(Suite::Registry, fault)?;
    let key = registry_key::pinned_key()?;
    verify_with_key(file, &key).map_err(CoreError::Snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::{hex, read, text};
    use serde_json::Value;

    pub(crate) fn test_key() -> VerifyingKey {
        let bytes: [u8; 32] = hex(&read("kcr.json")["keys"]["test_registry"]["public_key_hex"])
            .try_into()
            .expect("32 bytes");
        VerifyingKey::from_bytes(&bytes).expect("the test key")
    }

    fn tag_of(doc: &Value, seed: &str) -> SealTag {
        let seed = crate::test_vectors::named(&doc["seeds"], seed);
        SealTag::from_bytes(hex(&seed["seal_tag_hex"]).try_into().expect("32 bytes"))
    }

    // Every kcr.json snapshot case gives its exact result against the test key, read from the
    // file (the key bytes exist in core only under test-registry); together they produce every
    // SnapshotError a snapshot can give.
    #[test]
    fn every_snapshot_case() {
        let doc = read("kcr.json");
        let key = test_key();
        let today = RegistryDate::from_yyyymmdd(
            u32::try_from(doc["today"].as_u64().expect("today")).expect("u32"),
        )
        .expect("a date");
        let mut errors = Vec::new();
        for case in doc["snapshots"].as_array().expect("snapshots") {
            let name = text(&case["name"]);
            let expect = &case["expect"];
            match verify_with_key(&hex(&case["kcr_hex"]), &key) {
                Ok(snapshot) => {
                    assert_eq!(expect["ok"], true, "{name}");
                    assert_eq!(Some(snapshot.number()), expect["number"].as_u64(), "{name}");
                    assert_eq!(
                        Some(u64::from(snapshot.date().yyyymmdd())),
                        expect["date"].as_u64(),
                        "{name}"
                    );
                    assert_eq!(
                        Some(u64::try_from(snapshot.entry_count()).expect("a count")),
                        expect["count"].as_u64(),
                        "{name}"
                    );
                    assert_eq!(
                        format!("{:?}", snapshot.freshness(today)),
                        text(&expect["freshness"]),
                        "{name}"
                    );
                    for lookup in expect["lookups"].as_array().expect("lookups") {
                        let got = snapshot
                            .lookup(&tag_of(&doc, text(&lookup["seed"])))
                            .map(|c| u64::from(c.get()));
                        assert_eq!(got, lookup["count"].as_u64(), "{name}");
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
        ] {
            assert!(errors.contains(&want), "{want:?} is never produced");
        }
    }

    // All 976 single-bit flips of the header and signature, and every truncation, fail.
    #[test]
    fn every_header_bit_flip_and_truncation_fails() {
        let doc = read("kcr.json");
        let key = test_key();
        let small = hex(&crate::test_vectors::named(&doc["snapshots"], "small")["kcr_hex"]);
        assert!(verify_with_key(&small, &key).is_ok());
        for bit in 0..8 * SIGNED_BYTES {
            let mut flipped = small.clone();
            flipped[bit / 8] ^= 1 << (bit % 8);
            assert!(verify_with_key(&flipped, &key).is_err(), "bit {bit}");
        }
        for len in 0..small.len() {
            assert!(
                verify_with_key(&small[..len], &key).is_err(),
                "length {len}"
            );
        }
    }

    #[test]
    fn entry_rules_in_order() {
        let a = [[0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1]];
        assert_eq!(check_entries(&a, None), Ok(()));
        let mut b = [[0u8; ENTRY_BYTES]; 2];
        b[0][15] = 2;
        b[0][17] = 1;
        b[1][15] = 1;
        b[1][17] = 1;
        assert_eq!(check_entries(&b, None), Err(SnapshotError::Unsorted));
        b[1][15] = 2;
        assert_eq!(check_entries(&b, None), Err(SnapshotError::Duplicate));
        b[1][15] = 3;
        b[1][17] = 0;
        assert_eq!(check_entries(&b, None), Err(SnapshotError::ZeroCount));
        b[1][17] = 1;
        assert_eq!(check_entries(&b, None), Ok(()));
        assert_eq!(
            check_entries(&b, Some(1)),
            Err(SnapshotError::EntryOutsideBucket)
        );
        assert_eq!(check_entries(&b, Some(0)), Ok(()));
    }

    #[test]
    fn a_found_tag_is_never_reported_clear() {
        let mut entries = [[0u8; ENTRY_BYTES]; 1];
        entries[0][..16].copy_from_slice(&[7; 16]);
        let mut tag = [7u8; 32];
        assert_eq!(
            find(&entries, &SealTag::from_bytes(tag)),
            Some(NonZeroU16::MIN)
        );
        tag[15] = 8;
        assert_eq!(find(&entries, &SealTag::from_bytes(tag)), None);
    }

    #[test]
    fn debug_shows_the_header_only() {
        let doc = read("kcr.json");
        let small = hex(&crate::test_vectors::named(&doc["snapshots"], "small")["kcr_hex"]);
        let snapshot = verify_with_key(&small, &test_key()).expect("valid");
        assert_eq!(
            format!("{snapshot:?}"),
            "VerifiedSnapshot { number: 2, date: RegistryDate { year: 2026, month: 3, day: 1 }, count: 6, .. }"
        );
    }

    // ed25519-dalek's verify_strict agrees with verify.py's verifier: RFC 8032 TEST 1-3 verify and
    // fail with L added to S, and both strict cases (a small-order key, a small-order R), which
    // satisfy the cofactorless equation, are refused.
    #[test]
    fn rfc8032_and_the_strict_cases_through_verify_strict() {
        let doc = read("kcr.json");
        let key_of = |v: &Value| {
            VerifyingKey::from_bytes(&hex(v).try_into().expect("32 bytes")).expect("a point")
        };
        let signature_of = |v: &Value| Signature::from_bytes(&hex(v).try_into().expect("64 bytes"));
        for t in doc["rfc8032"].as_array().expect("tests") {
            let key = key_of(&t["public_key_hex"]);
            let message = hex(&t["message_hex"]);
            assert!(
                key.verify_strict(&message, &signature_of(&t["signature_hex"]))
                    .is_ok()
            );
            assert!(
                key.verify_strict(&message, &signature_of(&t["signature_s_plus_l_hex"]))
                    .is_err()
            );
        }
        let strict = doc["ed25519_strict"].as_array().expect("strict cases");
        assert_eq!(strict.len(), 2);
        for c in strict {
            assert_eq!(c["equation_holds"], true);
            assert_eq!(c["verify_strict"], false);
            let key = key_of(&c["public_key_hex"]);
            assert!(
                key.verify_strict(&hex(&c["message_hex"]), &signature_of(&c["signature_hex"]))
                    .is_err(),
                "{}",
                text(&c["name"])
            );
        }
    }

    #[test]
    fn the_limits_match_kcr_json() {
        let limits = &read("kcr.json")["limits"];
        assert_eq!(limits["header_bytes"], HEADER_BYTES);
        assert_eq!(limits["signed_bytes"], SIGNED_BYTES);
        assert_eq!(limits["entry_bytes"], ENTRY_BYTES);
        assert_eq!(limits["max_entries"], MAX_ENTRIES);
    }
}
