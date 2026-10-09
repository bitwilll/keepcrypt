//! `SecretBytes32` holds a secret: it has no Debug, Display or Clone (CLAUDE.md rule 5).
use keepcrypt_core::SecretBytes32;

fn needs_debug<T: std::fmt::Debug>() {}
fn needs_display<T: std::fmt::Display>() {}
fn needs_clone<T: Clone>() {}

fn main() {
    needs_debug::<SecretBytes32>();
    needs_display::<SecretBytes32>();
    needs_clone::<SecretBytes32>();
}
