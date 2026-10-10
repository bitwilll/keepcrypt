//! A read-back result names the word the metal spells and, per face, how it differs: with the
//! letters as typed, that gives the seed's letters back. `ReadbackResult`, `ReadbackMismatch`,
//! `FaceVerdict` and `Dots` have no Debug, Display or Clone (CLAUDE.md rule 5).
use keepcrypt_core::{Dots, FaceVerdict, ReadbackMismatch, ReadbackResult};

fn needs_debug<T: std::fmt::Debug>() {}
fn needs_display<T: std::fmt::Display>() {}
fn needs_clone<T: Clone>() {}

fn main() {
    needs_debug::<ReadbackResult>();
    needs_display::<ReadbackResult>();
    needs_clone::<ReadbackResult>();
    needs_debug::<ReadbackMismatch>();
    needs_display::<ReadbackMismatch>();
    needs_clone::<ReadbackMismatch>();
    needs_debug::<FaceVerdict>();
    needs_display::<FaceVerdict>();
    needs_clone::<FaceVerdict>();
    needs_debug::<Dots>();
    needs_display::<Dots>();
    needs_clone::<Dots>();
}
