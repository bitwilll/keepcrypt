//! Every failure core reports (CLAUDE.md rules 3 and 5; docs/build-plan.md "Invariants").
//!
//! - Payloads are enums, counts and indices, never bytes or text, so no error can carry or echo a
//!   secret or a piece of hostile input.
//! - Foreign errors pass through `map_err` to a payload-free variant here; nothing wraps a foreign
//!   error type (no `#[from]` or `#[source]`).
//! - No `#[non_exhaustive]`: a new variant breaks the shells' matches, so it gets reviewed.
//! - No variant depends on a cargo feature, so the test builds and the release build agree.
//! - An `Err` from any session method that can fail on randomness, a health test, a known-answer
//!   test or an integrity check has already wiped the session (tasks/todo.md, M1 Q5).
//!
//! The display text is fixed, plain and free of secrets; the unit test at the end pins every
//! variant's text through exhaustive matches.

use thiserror::Error;

/// A failure anywhere in core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CoreError {
    /// A known-answer test group failed: the crypto or encoding underneath cannot be trusted.
    #[error("known-answer test failed: {0}")]
    Kat(KatId),
    /// The OS entropy source failed or came up short.
    #[error("entropy source failed: {0}")]
    Source(SourceFault),
    /// A raw hwrng sample stream failed a health test.
    #[error("hwrng health test failed: {0}")]
    Health(HealthFailure),
    /// `commit` before the device leg met its quota.
    #[error("the device entropy quota is not met")]
    QuotaUnmet,
    /// A call that this mode or platform does not offer (hwrng input on a phone, for one).
    #[error("not available in this mode or on this platform")]
    NotInThisMode,
    /// A dice face outside 1 to 6.
    #[error("a dice face must be 1 to 6")]
    InvalidRoll,
    /// More than 256 rolls.
    #[error("too many dice rolls")]
    TooManyRolls,
    /// `finish` below the minimum number of rolls.
    #[error("too few dice rolls for this seed")]
    TooFewRolls,
    /// An empty BIP39 passphrase; leave the passphrase out instead.
    #[error("a BIP39 passphrase cannot be empty")]
    EmptyPassphrase,
    /// One of the five gated exports before every word has read back.
    #[error("every word must read back before this export")]
    ReadbackIncomplete,
    /// `encrypt_backup` or `verify_backup` before `generate_backup_passphrase`.
    #[error("no backup passphrase has been generated")]
    NoBackupPassphrase,
    /// The passphrase does not open this backup file.
    #[error("the passphrase does not open this backup")]
    WrongPassphrase,
    /// The backup opens but holds another seed.
    #[error("the backup does not hold this seed")]
    ReadbackMismatch,
    /// The watch-only export failed its runtime self-check.
    #[error("the watch-only export failed its self-check")]
    ExportSelfCheck,
    /// This build pins no registry key, so snapshots and proofs cannot be verified.
    #[error("no registry key is pinned in this build")]
    NoRegistryKey,
    /// A registry snapshot or bucket proof was rejected.
    #[error("registry snapshot or proof rejected: {0}")]
    Snapshot(SnapshotError),
    /// A backup file was rejected.
    #[error("backup rejected: {0}")]
    Backup(BackupError),
    /// Braille input or read-back input was rejected.
    #[error("braille input rejected: {0}")]
    Braille(BrailleError),
    /// A dependency or conversion failed where it never should.
    #[error("internal failure: {0}")]
    Internal(InternalFault),
}

/// A known-answer test group (docs/build-plan.md "kat"; tasks/todo.md, M1 group 2). Each module
/// adds its group when it lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum KatId {
    /// SHA-256: the NIST empty, "abc" and two-block messages.
    #[error("SHA-256")]
    Sha256,
    /// SHA-512: the NIST empty, "abc" and two-block messages.
    #[error("SHA-512")]
    Sha512,
    /// HMAC-SHA-256 and HMAC-SHA-512: RFC 4231 test case 2.
    #[error("HMAC")]
    Hmac,
    /// The BIP39 English word list hashes to its published SHA-256.
    #[error("BIP39 word list")]
    Bip39Wordlist,
    /// BIP39: 24 English entropy and mnemonic pairs, and the PBKDF2 seed for 2 of them.
    #[error("BIP39")]
    Bip39,
    /// The health tests: a stuck stream fails the Repetition Count and an alternating one the
    /// Adaptive Proportion test, each at its pinned sample; a clean stream passes.
    #[error("health tests")]
    Health,
}

impl KatId {
    /// Every group, in the order a full suite runs them. Keep it next to `KatId` and to the
    /// exhaustive match in `kat::passes`, which is where a new group must be added too.
    pub const ALL: [KatId; 6] = [
        KatId::Sha256,
        KatId::Sha512,
        KatId::Hmac,
        KatId::Bip39Wordlist,
        KatId::Bip39,
        KatId::Health,
    ];
}

/// How an entropy source failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SourceFault {
    /// The OS random source returned an error.
    #[error("the OS source returned an error")]
    Os,
    /// A read returned fewer bytes than asked for.
    #[error("a read came up short")]
    ShortRead,
    /// `hwrng_boot_test` was not given exactly 1,024 samples.
    #[error("the boot test needs exactly 1,024 hwrng samples")]
    HwrngSampleCount,
}

/// A health-test failure: which test, in which stage, at which sample. Nothing else, so no raw
/// sample value ever reaches an error (SP 800-90B 4.4; docs/design.md "Test continuously").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("{test} in the {stage} stage at sample {sample}")]
pub struct HealthFailure {
    /// The test that fired.
    pub test: HealthTest,
    /// Startup (the first 1,024 samples, tested then discarded) or continuous.
    pub stage: HealthStage,
    /// The 0-based index of the failing sample in this tester's stream.
    pub sample: u64,
}

/// The SP 800-90B health tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HealthTest {
    /// SP 800-90B 4.4.1: one value repeated too many times in a row.
    #[error("Repetition Count Test")]
    RepetitionCount,
    /// SP 800-90B 4.4.2: a window's first value appeared too often in that window.
    #[error("Adaptive Proportion Test")]
    AdaptiveProportion,
}

/// When a health test fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HealthStage {
    /// The first 1,024 samples, tested then discarded.
    #[error("startup")]
    Startup,
    /// Every sample after the startup samples.
    #[error("continuous")]
    Continuous,
}

/// Why a go-ahead did not reveal the words. The session survives these (`Rejected::Retry`): the
/// user may try again with the same nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CheckError {
    /// The typed code is not 8 Crockford base32 symbols.
    #[error("the go-ahead code is malformed")]
    MalformedCode,
    /// The code is well formed but not this check's code.
    #[error("the go-ahead code does not match")]
    WrongCode,
    /// The proof is for another bucket.
    #[error("the proof is for another bucket")]
    WrongBucket,
}

/// Why a registry snapshot (`.kcr`) or a bucket proof (KCP1) was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SnapshotError {
    /// Shorter than a header and its signature.
    #[error("too short")]
    TooShort,
    /// The magic bytes are wrong.
    #[error("wrong magic")]
    BadMagic,
    /// A format version other than 1.
    #[error("unsupported version")]
    BadVersion,
    /// The Ed25519 signature does not verify against the pinned key.
    #[error("bad signature")]
    BadSignature,
    /// The header's date is not a valid YYYYMMDD date.
    #[error("bad date")]
    BadDate,
    /// More entries than the loader accepts.
    #[error("too many entries")]
    TooManyEntries,
    /// The length does not match the header or the proof's entry count.
    #[error("wrong length")]
    BadLength,
    /// Entries out of order.
    #[error("entries out of order")]
    Unsorted,
    /// The same tag twice.
    #[error("duplicate entry")]
    Duplicate,
    /// An entry with a registration count of 0.
    #[error("zero registration count")]
    ZeroCount,
    /// The recomputed bucket root differs from the signed one.
    #[error("bucket root mismatch")]
    RootMismatch,
    /// A proof's bucket index is 2^20 or more.
    #[error("bucket index out of range")]
    BucketOutOfRange,
    /// A proof entry outside the proof's bucket.
    #[error("entry outside its bucket")]
    EntryOutsideBucket,
    /// A proof with more bucket entries than the snapshot holds.
    #[error("more bucket entries than the snapshot holds")]
    ProofCount,
    /// The go-ahead QR text failed the strict UR decoder.
    #[error("bad QR text: {0}")]
    Ur(UrError),
}

/// Why the strict single-part UR decoder rejected a QR text (tasks/todo.md, M1 Q6c), in the
/// order it checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum UrError {
    /// More than 4,296 characters, rejected before any decoding.
    #[error("too long")]
    TooLong,
    /// Neither all lowercase nor all uppercase.
    #[error("mixed case")]
    MixedCase,
    /// Not a `ur:` text.
    #[error("not a UR")]
    NotUr,
    /// A type other than the one expected.
    #[error("wrong UR type")]
    WrongType,
    /// A multi-part sequence; only single-part URs are read.
    #[error("multi-part UR")]
    MultiPart,
    /// An odd number of byteword letters.
    #[error("odd byteword length")]
    OddLength,
    /// A letter pair that is not one of the 256 bytewords.
    #[error("unknown byteword")]
    UnknownByteword,
    /// The CRC-32 is missing or does not match.
    #[error("bad checksum")]
    BadChecksum,
    /// The CBOR item is not a byte string.
    #[error("not a CBOR byte string")]
    NotByteString,
    /// The CBOR head is not in shortest form.
    #[error("non-shortest CBOR head")]
    NonShortestHead,
    /// An indefinite-length CBOR item.
    #[error("indefinite-length CBOR")]
    IndefiniteLength,
    /// Bytes after the CBOR byte string.
    #[error("trailing bytes")]
    TrailingBytes,
}

/// Why a backup file was rejected (age v1 scrypt only; docs/build-plan.md "Encrypted backup
/// format"). A passphrase that does not open the file is `CoreError::WrongPassphrase`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BackupError {
    /// Larger than the 8 KiB a backup can be.
    #[error("file too large")]
    TooLarge,
    /// Bad ASCII armor.
    #[error("bad armor")]
    Armor,
    /// A malformed or unsupported age header.
    #[error("bad header")]
    Header,
    /// An scrypt work factor outside 1 to 18, refused before any scrypt work.
    #[error("work factor out of range")]
    WorkFactor,
    /// The header MAC does not match.
    #[error("header MAC mismatch")]
    HeaderMac,
    /// The payload failed to decrypt, or is malformed.
    #[error("bad payload")]
    Payload,
    /// The decrypted text is not a valid KeepCrypt backup.
    #[error("bad backup contents")]
    Plaintext,
    /// A KeepCrypt backup version this build does not read.
    #[error("unsupported backup version")]
    UnsupportedVersion,
    /// Typed backup passphrase words that are not exactly 8 words from the list.
    #[error("the backup passphrase must be 8 words from the BIP39 English list")]
    PassphraseWords,
}

/// Why braille or read-back input was rejected. The refused character is never echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BrailleError {
    /// A read-back position outside the seed's words.
    #[error("no word at this position")]
    BadPosition,
    /// Read-back input that is not 3 or 4 ASCII letters.
    #[error("enter the first 3 or 4 letters of the word")]
    MalformedReadback,
    /// A character outside a-z, 0-9, space and hyphen.
    #[error("unsupported character")]
    UnsupportedCharacter,
}

/// A dependency or a conversion failed where it never should. Payload-free: the foreign error
/// is dropped at the `map_err`, so nothing it held can leak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum InternalFault {
    /// The BIP39 library refused entropy or a seed.
    #[error("BIP39 encoding")]
    Bip39,
    /// BIP32 key derivation or address encoding failed.
    #[error("key derivation")]
    KeyDerivation,
    /// A length did not fit its fixed-width field.
    #[error("length conversion")]
    Length,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every variant, nested ones included, with its exact display text. The exhaustive matches
    // below make a new variant a compile error here until it is listed and pinned.
    fn core_text(e: CoreError) -> String {
        match e {
            CoreError::Kat(id) => format!("known-answer test failed: {}", kat_text(id)),
            CoreError::Source(f) => format!("entropy source failed: {}", source_text(f)),
            CoreError::Health(h) => format!("hwrng health test failed: {}", health_text(h)),
            CoreError::QuotaUnmet => "the device entropy quota is not met".into(),
            CoreError::NotInThisMode => "not available in this mode or on this platform".into(),
            CoreError::InvalidRoll => "a dice face must be 1 to 6".into(),
            CoreError::TooManyRolls => "too many dice rolls".into(),
            CoreError::TooFewRolls => "too few dice rolls for this seed".into(),
            CoreError::EmptyPassphrase => "a BIP39 passphrase cannot be empty".into(),
            CoreError::ReadbackIncomplete => "every word must read back before this export".into(),
            CoreError::NoBackupPassphrase => "no backup passphrase has been generated".into(),
            CoreError::WrongPassphrase => "the passphrase does not open this backup".into(),
            CoreError::ReadbackMismatch => "the backup does not hold this seed".into(),
            CoreError::ExportSelfCheck => "the watch-only export failed its self-check".into(),
            CoreError::NoRegistryKey => "no registry key is pinned in this build".into(),
            CoreError::Snapshot(s) => {
                format!("registry snapshot or proof rejected: {}", snapshot_text(s))
            }
            CoreError::Backup(b) => format!("backup rejected: {}", backup_text(b)),
            CoreError::Braille(b) => format!("braille input rejected: {}", braille_text(b)),
            CoreError::Internal(i) => format!("internal failure: {}", internal_text(i)),
        }
    }

    fn kat_text(id: KatId) -> &'static str {
        match id {
            KatId::Sha256 => "SHA-256",
            KatId::Sha512 => "SHA-512",
            KatId::Hmac => "HMAC",
            KatId::Bip39Wordlist => "BIP39 word list",
            KatId::Bip39 => "BIP39",
            KatId::Health => "health tests",
        }
    }

    fn source_text(f: SourceFault) -> &'static str {
        match f {
            SourceFault::Os => "the OS source returned an error",
            SourceFault::ShortRead => "a read came up short",
            SourceFault::HwrngSampleCount => "the boot test needs exactly 1,024 hwrng samples",
        }
    }

    fn health_text(h: HealthFailure) -> String {
        let test = match h.test {
            HealthTest::RepetitionCount => "Repetition Count Test",
            HealthTest::AdaptiveProportion => "Adaptive Proportion Test",
        };
        let stage = match h.stage {
            HealthStage::Startup => "startup",
            HealthStage::Continuous => "continuous",
        };
        format!("{test} in the {stage} stage at sample {}", h.sample)
    }

    fn check_text(c: CheckError) -> &'static str {
        match c {
            CheckError::MalformedCode => "the go-ahead code is malformed",
            CheckError::WrongCode => "the go-ahead code does not match",
            CheckError::WrongBucket => "the proof is for another bucket",
        }
    }

    fn snapshot_text(s: SnapshotError) -> String {
        match s {
            SnapshotError::TooShort => "too short".into(),
            SnapshotError::BadMagic => "wrong magic".into(),
            SnapshotError::BadVersion => "unsupported version".into(),
            SnapshotError::BadSignature => "bad signature".into(),
            SnapshotError::BadDate => "bad date".into(),
            SnapshotError::TooManyEntries => "too many entries".into(),
            SnapshotError::BadLength => "wrong length".into(),
            SnapshotError::Unsorted => "entries out of order".into(),
            SnapshotError::Duplicate => "duplicate entry".into(),
            SnapshotError::ZeroCount => "zero registration count".into(),
            SnapshotError::RootMismatch => "bucket root mismatch".into(),
            SnapshotError::BucketOutOfRange => "bucket index out of range".into(),
            SnapshotError::EntryOutsideBucket => "entry outside its bucket".into(),
            SnapshotError::ProofCount => "more bucket entries than the snapshot holds".into(),
            SnapshotError::Ur(u) => format!("bad QR text: {}", ur_text(u)),
        }
    }

    fn ur_text(u: UrError) -> &'static str {
        match u {
            UrError::TooLong => "too long",
            UrError::MixedCase => "mixed case",
            UrError::NotUr => "not a UR",
            UrError::WrongType => "wrong UR type",
            UrError::MultiPart => "multi-part UR",
            UrError::OddLength => "odd byteword length",
            UrError::UnknownByteword => "unknown byteword",
            UrError::BadChecksum => "bad checksum",
            UrError::NotByteString => "not a CBOR byte string",
            UrError::NonShortestHead => "non-shortest CBOR head",
            UrError::IndefiniteLength => "indefinite-length CBOR",
            UrError::TrailingBytes => "trailing bytes",
        }
    }

    fn backup_text(b: BackupError) -> &'static str {
        match b {
            BackupError::TooLarge => "file too large",
            BackupError::Armor => "bad armor",
            BackupError::Header => "bad header",
            BackupError::WorkFactor => "work factor out of range",
            BackupError::HeaderMac => "header MAC mismatch",
            BackupError::Payload => "bad payload",
            BackupError::Plaintext => "bad backup contents",
            BackupError::UnsupportedVersion => "unsupported backup version",
            BackupError::PassphraseWords => {
                "the backup passphrase must be 8 words from the BIP39 English list"
            }
        }
    }

    fn braille_text(b: BrailleError) -> &'static str {
        match b {
            BrailleError::BadPosition => "no word at this position",
            BrailleError::MalformedReadback => "enter the first 3 or 4 letters of the word",
            BrailleError::UnsupportedCharacter => "unsupported character",
        }
    }

    fn internal_text(i: InternalFault) -> &'static str {
        match i {
            InternalFault::Bip39 => "BIP39 encoding",
            InternalFault::KeyDerivation => "key derivation",
            InternalFault::Length => "length conversion",
        }
    }

    const SOURCE_FAULTS: [SourceFault; 3] = [
        SourceFault::Os,
        SourceFault::ShortRead,
        SourceFault::HwrngSampleCount,
    ];
    const HEALTH_FAILURES: [HealthFailure; 2] = [
        HealthFailure {
            test: HealthTest::RepetitionCount,
            stage: HealthStage::Startup,
            sample: 5,
        },
        HealthFailure {
            test: HealthTest::AdaptiveProportion,
            stage: HealthStage::Continuous,
            sample: 1_146,
        },
    ];
    const CHECK_ERRORS: [CheckError; 3] = [
        CheckError::MalformedCode,
        CheckError::WrongCode,
        CheckError::WrongBucket,
    ];
    const UR_ERRORS: [UrError; 12] = [
        UrError::TooLong,
        UrError::MixedCase,
        UrError::NotUr,
        UrError::WrongType,
        UrError::MultiPart,
        UrError::OddLength,
        UrError::UnknownByteword,
        UrError::BadChecksum,
        UrError::NotByteString,
        UrError::NonShortestHead,
        UrError::IndefiniteLength,
        UrError::TrailingBytes,
    ];
    const SNAPSHOT_ERRORS: [SnapshotError; 14] = [
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
    ];
    const BACKUP_ERRORS: [BackupError; 9] = [
        BackupError::TooLarge,
        BackupError::Armor,
        BackupError::Header,
        BackupError::WorkFactor,
        BackupError::HeaderMac,
        BackupError::Payload,
        BackupError::Plaintext,
        BackupError::UnsupportedVersion,
        BackupError::PassphraseWords,
    ];
    const BRAILLE_ERRORS: [BrailleError; 3] = [
        BrailleError::BadPosition,
        BrailleError::MalformedReadback,
        BrailleError::UnsupportedCharacter,
    ];
    const INTERNAL_FAULTS: [InternalFault; 3] = [
        InternalFault::Bip39,
        InternalFault::KeyDerivation,
        InternalFault::Length,
    ];

    fn all_core_errors() -> Vec<CoreError> {
        let mut all: Vec<CoreError> = KatId::ALL.iter().map(|&id| CoreError::Kat(id)).collect();
        all.extend(SOURCE_FAULTS.iter().map(|&f| CoreError::Source(f)));
        all.extend(HEALTH_FAILURES.iter().map(|&h| CoreError::Health(h)));
        all.extend([
            CoreError::QuotaUnmet,
            CoreError::NotInThisMode,
            CoreError::InvalidRoll,
            CoreError::TooManyRolls,
            CoreError::TooFewRolls,
            CoreError::EmptyPassphrase,
            CoreError::ReadbackIncomplete,
            CoreError::NoBackupPassphrase,
            CoreError::WrongPassphrase,
            CoreError::ReadbackMismatch,
            CoreError::ExportSelfCheck,
            CoreError::NoRegistryKey,
        ]);
        all.extend(SNAPSHOT_ERRORS.iter().map(|&s| CoreError::Snapshot(s)));
        all.extend(
            UR_ERRORS
                .iter()
                .map(|&u| CoreError::Snapshot(SnapshotError::Ur(u))),
        );
        all.extend(BACKUP_ERRORS.iter().map(|&b| CoreError::Backup(b)));
        all.extend(BRAILLE_ERRORS.iter().map(|&b| CoreError::Braille(b)));
        all.extend(INTERNAL_FAULTS.iter().map(|&i| CoreError::Internal(i)));
        all
    }

    // A position per variant (nested enums by their position in their list), from an exhaustive
    // match, so no variant is listed twice and every listed one is in its nested list.
    fn core_position(e: CoreError) -> (u8, u8) {
        match e {
            CoreError::Kat(id) => (0, list_position(&KatId::ALL, id)),
            CoreError::Source(f) => (1, list_position(&SOURCE_FAULTS, f)),
            CoreError::Health(h) => (2, list_position(&HEALTH_FAILURES, h)),
            CoreError::QuotaUnmet => (3, 0),
            CoreError::NotInThisMode => (4, 0),
            CoreError::InvalidRoll => (5, 0),
            CoreError::TooManyRolls => (6, 0),
            CoreError::TooFewRolls => (7, 0),
            CoreError::EmptyPassphrase => (8, 0),
            CoreError::ReadbackIncomplete => (9, 0),
            CoreError::NoBackupPassphrase => (10, 0),
            CoreError::WrongPassphrase => (11, 0),
            CoreError::ReadbackMismatch => (12, 0),
            CoreError::ExportSelfCheck => (13, 0),
            CoreError::NoRegistryKey => (14, 0),
            CoreError::Snapshot(SnapshotError::Ur(u)) => (15, list_position(&UR_ERRORS, u)),
            CoreError::Snapshot(s) => (16, list_position(&SNAPSHOT_ERRORS, s)),
            CoreError::Backup(b) => (17, list_position(&BACKUP_ERRORS, b)),
            CoreError::Braille(b) => (18, list_position(&BRAILLE_ERRORS, b)),
            CoreError::Internal(i) => (19, list_position(&INTERNAL_FAULTS, i)),
        }
    }

    fn list_position<T: PartialEq + Copy>(list: &[T], x: T) -> u8 {
        match list.iter().position(|&y| y == x) {
            Some(p) => u8::try_from(p).expect("the lists are short"),
            None => panic!("a variant is missing from its list"),
        }
    }

    // A new variant fails to compile in its *_text match above until it gets a pinned text; the
    // lists' array lengths change with it.
    #[test]
    fn every_variant_displays_its_pinned_text() {
        let all = all_core_errors();
        let mut positions: Vec<(u8, u8)> = all.iter().map(|&e| core_position(e)).collect();
        let listed = positions.len();
        positions.sort_unstable();
        positions.dedup();
        assert_eq!(positions.len(), listed, "a variant is listed twice");
        for e in all {
            assert_eq!(e.to_string(), core_text(e), "{e:?}");
        }
        for c in CHECK_ERRORS {
            assert_eq!(c.to_string(), check_text(c), "{c:?}");
        }
    }

    #[test]
    fn health_failure_names_test_stage_and_index_only() {
        let h = HealthFailure {
            test: HealthTest::AdaptiveProportion,
            stage: HealthStage::Startup,
            sample: 122,
        };
        assert_eq!(
            CoreError::Health(h).to_string(),
            "hwrng health test failed: Adaptive Proportion Test in the startup stage at sample 122"
        );
    }
}
