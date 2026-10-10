//! The seal code, and the register and collision-report QRs that carry it, are private: anyone
//! holding a code can file a false collision report. None has Debug, Display or Clone (CLAUDE.md
//! rule 5; docs/seal-watchonly-braille.md "Registration, re-checks and safety").
use keepcrypt_core::{CollisionReport, SealCode, SealRegistration};

fn needs_debug<T: std::fmt::Debug>() {}
fn needs_display<T: std::fmt::Display>() {}
fn needs_clone<T: Clone>() {}

fn main() {
    needs_debug::<SealCode>();
    needs_display::<SealCode>();
    needs_clone::<SealCode>();
    needs_debug::<SealRegistration>();
    needs_display::<SealRegistration>();
    needs_clone::<SealRegistration>();
    needs_debug::<CollisionReport>();
    needs_display::<CollisionReport>();
    needs_clone::<CollisionReport>();
}
