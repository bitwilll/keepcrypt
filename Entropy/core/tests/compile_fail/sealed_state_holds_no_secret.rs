//! The sealed state exposes no mnemonic, D, backup or export (CLAUDE.md rule 6; docs/build-plan.md
//! "Sealed-state compile-fail tests"): none of these functions exists on `Session<Sealed>`, and
//! neither does `reveal`, which needs a started check.
use keepcrypt_core::{BackupApp, CreatedBy, GoAhead, Sealed, Session};

fn main() {
    let sealed: Option<Session<Sealed>> = None;
    if let Some(session) = sealed {
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
        session.reveal(GoAhead::Code("CF94-BCAJ"));
    }
}
