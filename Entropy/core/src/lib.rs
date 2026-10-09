//! keepcrypt-core: owns every byte of randomness and every secret in KeepCrypt.
//!
//! The modules land in M1 in the order of tasks/todo.md (docs/build-plan.md "Core crate
//! specification"). Only `source` reads the OS random source (CLAUDE.md rule 1). This file holds
//! the module list and the public re-exports only.

#![forbid(unsafe_code)]

mod braille;
mod descriptor;
mod dice;
mod error;
mod health;
mod kat;
mod pool;
mod seal;
mod secret;
mod seed;
mod session;
mod source;
#[cfg(test)]
mod test_vectors;
mod ur;

pub use braille::{
    BrailleInserts, Dots, Face, FaceVerdict, Insert, ReadbackMismatch, ReadbackResult, render_text,
};
pub use descriptor::WatchOnlyExport;
pub use error::{
    BackupError, BrailleError, CheckError, CoreError, HealthFailure, HealthStage, HealthTest,
    InternalFault, KatId, SnapshotError, SourceFault, UrError,
};
pub use health::hwrng_boot_test;
#[cfg(feature = "test-sources")]
pub use health::hwrng_boot_test_with_kat_fault;
pub use kat::self_test;
#[cfg(feature = "test-sources")]
pub use kat::self_test_with_kat_fault;
#[cfg(feature = "test-sources")]
pub use seal::seal_from_mnemonic_with_kat_fault;
pub use seal::{
    CheckNonce, CheckRequest, CollisionReport, SealCode, SealPublic, SealRegistration, SealTag,
    seal_from_mnemonic,
};
pub use secret::{
    BACKUP_PASSPHRASE_WORDS, Bip39Passphrase, ConfirmChallenge, NewBackupPassphrase, SecretBytes32,
    SecretMnemonic, TypedBackupPassphrase,
};
pub use session::{
    Checking, Collecting, Committed, Mode, Platform, Ready, Rolling, Sealed, SeedLength, Session,
    State,
};
pub use source::{ExtraSource, HW_BYTES_NEEDED};
#[cfg(feature = "test-sources")]
pub use source::{StubEntropy, StubSource, WipeProbe};
