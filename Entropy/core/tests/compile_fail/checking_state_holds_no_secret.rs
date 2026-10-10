//! A running check has the sealed state's secrecy (CLAUDE.md rule 6; docs/build-plan.md
//! "Sealed-state compile-fail tests"): no mnemonic, D, backup or export function exists on
//! `Session<Checking>`. Only `reveal` with a verified go-ahead leads to them.
use keepcrypt_core::{BackupApp, Checking, CreatedBy, Session};

fn main() {
    let checking: Option<Session<Checking>> = None;
    if let Some(session) = checking {
        let by = CreatedBy::new(BackupApp::Pi, 1, 0, 0);
        session.mnemonic();
        session.braille();
        session.reveal_device_leg();
        session.generate_backup_passphrase();
        session.encrypt_backup(&by);
        session.verify_backup(b"file");
        session.watch_only(None);
        session.registration();
        session.check_readback(1, "aban");
        session.fingerprint();
        session.first_address();
    }
}
