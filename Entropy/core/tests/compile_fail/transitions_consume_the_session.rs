//! A transition takes the session by value (tasks/todo.md, M1 Q5): after `commit` or `reveal` the
//! old state is gone, so no copy of it can be used again, and an `Err` has already dropped it.
use keepcrypt_core::{Checking, Collecting, GoAhead, Session};

fn main() {
    let collecting: Option<Session<Collecting>> = None;
    if let Some(session) = collecting {
        let committed = session.commit();
        session.credited_bits();
        drop(committed);
    }
    let checking: Option<Session<Checking>> = None;
    if let Some(session) = checking {
        let ready = session.reveal(GoAhead::Code("CF94-BCAJ"));
        session.check_request();
        drop(ready);
    }
}
