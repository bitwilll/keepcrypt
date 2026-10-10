//! The braille views show the seed's words: `BrailleInserts`, `Insert` and `Face` have no Debug,
//! Display or Clone (CLAUDE.md rule 5; docs/seal-watchonly-braille.md "Braille backup").
use keepcrypt_core::{BrailleInserts, Face, Insert};

fn needs_debug<T: std::fmt::Debug>() {}
fn needs_display<T: std::fmt::Display>() {}
fn needs_clone<T: Clone>() {}

fn main() {
    needs_debug::<BrailleInserts<'static>>();
    needs_display::<BrailleInserts<'static>>();
    needs_clone::<BrailleInserts<'static>>();
    needs_debug::<Insert<'static>>();
    needs_display::<Insert<'static>>();
    needs_clone::<Insert<'static>>();
    needs_debug::<Face<'static>>();
    needs_display::<Face<'static>>();
    needs_clone::<Face<'static>>();
}
