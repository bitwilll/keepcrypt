//! The braille views borrow the session's words, and a checked backup's reveals borrow it (CLAUDE.md
//! rule 5; tasks/todo.md, M1 group 10): none can be kept after its owner is dropped and zeroized,
//! and neither can a word an insert names.
use keepcrypt_core::{CheckedBackup, Ready, Session};

fn main() {
    let ready: Option<Session<Ready>> = None;
    let inserts = match &ready {
        Some(session) => Some(session.braille()),
        None => None,
    };
    drop(ready);
    assert!(inserts.is_none());

    let ready: Option<Session<Ready>> = None;
    let words: Vec<&str> = match &ready {
        Some(session) => session.braille().iter().map(|insert| insert.word()).collect(),
        None => Vec::new(),
    };
    drop(ready);
    assert!(words.is_empty());

    let checked: Option<CheckedBackup> = None;
    let braille = match &checked {
        Some(backup) => Some(backup.reveal_braille()),
        None => None,
    };
    drop(checked);
    assert!(braille.is_none());

    let checked: Option<CheckedBackup> = None;
    let revealed: Vec<&str> = match &checked {
        Some(backup) => backup.reveal_words().collect(),
        None => Vec::new(),
    };
    drop(checked);
    assert!(revealed.is_empty());
}
