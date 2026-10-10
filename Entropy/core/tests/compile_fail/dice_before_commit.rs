//! Dice wait for the commitment (CLAUDE.md rule 6; docs/build-plan.md test matrix "Typestate
//! misuse": dice before commitment). Collecting has no dice calls, and Committed opens them only
//! through `start_dice`, after `commit` has fixed D and shown C. No value is built: a state is reached
//! only through `Session::new`, and type checking needs none.
use keepcrypt_core::{Collecting, Committed, Session};

fn main() {
    let collecting: Option<Session<Collecting>> = None;
    if let Some(session) = collecting {
        session.start_dice();
        session.push_roll(1);
    }
    let committed: Option<Session<Committed>> = None;
    if let Some(session) = committed {
        session.push_roll(1);
        session.finish();
    }
}
