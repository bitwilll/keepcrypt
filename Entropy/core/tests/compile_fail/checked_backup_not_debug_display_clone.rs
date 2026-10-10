//! `CheckedBackup` holds a backup's words: it has no Debug, Display or Clone (CLAUDE.md rule 5).
use keepcrypt_core::CheckedBackup;

fn needs_debug<T: std::fmt::Debug>() {}
fn needs_display<T: std::fmt::Display>() {}
fn needs_clone<T: Clone>() {}

fn main() {
    needs_debug::<CheckedBackup>();
    needs_display::<CheckedBackup>();
    needs_clone::<CheckedBackup>();
}
