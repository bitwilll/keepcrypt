//! Only core builds these (CLAUDE.md rules 5 and 6): their fields are private, so no shell can
//! forge a `Ready` session, verified registry evidence, a seal, a checked backup, typed passphrase
//! words that skipped the word-list check, or a check nonce it did not draw.
use keepcrypt_core::{
    CheckNonce, CheckedBackup, Ready, SealPublic, Session, TypedBackupPassphrase, VerifiedProof,
    VerifiedSnapshot,
};

fn main() {
    let session: Session<Ready> = Session {};
    let snapshot = VerifiedSnapshot {};
    let proof = VerifiedProof {};
    let seal = SealPublic {};
    let checked = CheckedBackup {};
    let typed = TypedBackupPassphrase {};
    let nonce = CheckNonce([0; 8]);
}
