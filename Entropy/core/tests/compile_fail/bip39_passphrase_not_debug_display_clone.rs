//! `Bip39Passphrase` holds a secret: it has no Debug, Display or Clone (CLAUDE.md rule 5).
use keepcrypt_core::Bip39Passphrase;

fn needs_debug<T: std::fmt::Debug>() {}
fn needs_display<T: std::fmt::Display>() {}
fn needs_clone<T: Clone>() {}

fn main() {
    needs_debug::<Bip39Passphrase>();
    needs_display::<Bip39Passphrase>();
    needs_clone::<Bip39Passphrase>();
}
