//! A session cannot be printed or duplicated (CLAUDE.md rules 5 and 6): no Debug, no Clone.
use keepcrypt_core::{Collecting, Session};

fn needs_debug<T: std::fmt::Debug>() {}
fn needs_clone<T: Clone>() {}

fn main() {
    needs_debug::<Session<Collecting>>();
    needs_clone::<Session<Collecting>>();
}
