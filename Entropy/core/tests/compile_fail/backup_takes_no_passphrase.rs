//! Backup passphrases are generated only (docs/build-plan.md "Encrypted backup format"; tasks/todo.md,
//! M1 Q5): `encrypt_backup` and `verify_backup` take no passphrase and use the one the session
//! generated, so neither typed words nor a display copy can be handed to them.
use keepcrypt_core::{
    BackupApp, CreatedBy, NewBackupPassphrase, Ready, Session, TypedBackupPassphrase,
};

fn main() {
    let ready: Option<Session<Ready>> = None;
    let typed: Option<TypedBackupPassphrase> = None;
    let new: Option<NewBackupPassphrase> = None;
    if let (Some(session), Some(typed), Some(new)) = (ready, typed, new) {
        let by = CreatedBy::new(BackupApp::Pi, 1, 0, 0);
        session.encrypt_backup(&typed);
        session.encrypt_backup(&by, &typed);
        session.encrypt_backup(&new);
        session.encrypt_backup(&by, &new);
        session.verify_backup(&typed);
        session.verify_backup(b"file", &typed);
        session.verify_backup(&new);
        session.verify_backup(b"file", &new);
    }
}
