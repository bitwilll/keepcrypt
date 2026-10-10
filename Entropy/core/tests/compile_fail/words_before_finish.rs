//! Nothing of the seed exists before `finish` (CLAUDE.md rule 6; docs/build-plan.md test matrix
//! "Typestate misuse": reveal before finish). While rolling there are no words, no braille, no
//! seal, no Skip and no check.
use keepcrypt_core::{GoAhead, Rolling, Session};

fn main() {
    let rolling: Option<Session<Rolling>> = None;
    if let Some(session) = rolling {
        session.mnemonic();
        session.braille();
        session.seal();
        session.skip_check();
        session.start_check();
        session.reveal(GoAhead::Code("CF94-BCAJ"));
    }
}
