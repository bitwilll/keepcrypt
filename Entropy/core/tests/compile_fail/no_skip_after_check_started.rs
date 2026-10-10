//! Skip exists only before a check starts (CLAUDE.md rule 6; docs/seal-watchonly-braille.md "Go-ahead
//! before reveal"): `Session<Checking>` has no `skip_check`, so nobody can read a Stop on the
//! website and then skip past it.
use keepcrypt_core::{Checking, Session};

fn main() {
    let checking: Option<Session<Checking>> = None;
    if let Some(session) = checking {
        session.skip_check();
    }
}
