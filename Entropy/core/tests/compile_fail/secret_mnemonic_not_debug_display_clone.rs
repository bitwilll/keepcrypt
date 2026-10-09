//! `SecretMnemonic` holds a secret: it has no Debug, Display or Clone (CLAUDE.md rule 5).
use keepcrypt_core::SecretMnemonic;

fn needs_debug<T: std::fmt::Debug>() {}
fn needs_display<T: std::fmt::Display>() {}
fn needs_clone<T: Clone>() {}

fn main() {
    needs_debug::<SecretMnemonic>();
    needs_display::<SecretMnemonic>();
    needs_clone::<SecretMnemonic>();
}
