//! `NewBackupPassphrase` holds a secret: it has no Debug, Display or Clone (CLAUDE.md rule 5).
use keepcrypt_core::NewBackupPassphrase;

fn needs_debug<T: std::fmt::Debug>() {}
fn needs_display<T: std::fmt::Display>() {}
fn needs_clone<T: Clone>() {}

fn main() {
    needs_debug::<NewBackupPassphrase>();
    needs_display::<NewBackupPassphrase>();
    needs_clone::<NewBackupPassphrase>();
}
