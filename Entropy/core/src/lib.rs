//! keepcrypt-core: owns every byte of randomness and every secret in KeepCrypt.
//!
//! The modules land in M1 in the order of tasks/todo.md (docs/build-plan.md "Core crate
//! specification"). Only `source` reads the OS random source (CLAUDE.md rule 1). This file holds
//! the module list and the public re-exports only.

#![forbid(unsafe_code)]

mod error;
mod kat;
mod secret;
mod session;
mod source;

pub use error::{
    BackupError, BrailleError, CheckError, CoreError, HealthFailure, HealthStage, HealthTest,
    InternalFault, KatId, SnapshotError, SourceFault, UrError,
};
pub use kat::self_test;
#[cfg(feature = "test-sources")]
pub use kat::self_test_with_kat_fault;
pub use secret::{
    BACKUP_PASSPHRASE_WORDS, Bip39Passphrase, ConfirmChallenge, NewBackupPassphrase, SecretBytes32,
    SecretMnemonic, TypedBackupPassphrase,
};
pub use session::{
    Checking, Collecting, Committed, Mode, Platform, Ready, Rolling, Sealed, SeedLength, Session,
    State,
};
#[cfg(feature = "test-sources")]
pub use source::{StubEntropy, StubSource, WipeProbe};
