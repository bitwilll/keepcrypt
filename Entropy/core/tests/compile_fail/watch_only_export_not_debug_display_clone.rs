//! `WatchOnlyExport` holds an xpub, which reveals every address of the wallet: it has no Debug,
//! Display or Clone (CLAUDE.md rule 5; docs/seal-watchonly-braille.md "Watch-only export").
use keepcrypt_core::WatchOnlyExport;

fn needs_debug<T: std::fmt::Debug>() {}
fn needs_display<T: std::fmt::Display>() {}
fn needs_clone<T: Clone>() {}

fn main() {
    needs_debug::<WatchOnlyExport>();
    needs_display::<WatchOnlyExport>();
    needs_clone::<WatchOnlyExport>();
}
