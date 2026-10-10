//! A destroyed seed leaves nothing behind (CLAUDE.md rule 6; docs/seal-watchonly-braille.md "Add
//! fresh entropy"): `Wiped` has no words, braille, D, seal, backup or export, and cannot be
//! cloned. Only the collision report and `restart` remain.
use keepcrypt_core::{BackupApp, CreatedBy, Wiped};

fn needs_clone<T: Clone>() {}

fn main() {
    let wiped: Option<Wiped> = None;
    if let Some(wiped) = wiped {
        let by = CreatedBy::new(BackupApp::Pi, 1, 0, 0);
        wiped.mnemonic();
        wiped.braille();
        wiped.reveal_device_leg();
        wiped.seal();
        wiped.fingerprint();
        wiped.encrypt_backup(&by);
        wiped.watch_only(None);
        wiped.registration();
    }
    needs_clone::<Wiped>();
}
