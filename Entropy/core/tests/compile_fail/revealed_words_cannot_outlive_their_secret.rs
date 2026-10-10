//! Revealed words borrow the secret they come from, so none can be kept after that secret is
//! dropped and zeroized (CLAUDE.md rule 5; tasks/todo.md, M1 group 10). No value is built: each
//! secret type has no public constructor, and borrow checking needs none.
use keepcrypt_core::{ConfirmChallenge, NewBackupPassphrase, SecretMnemonic};

fn main() {
    let mnemonic: Option<SecretMnemonic> = None;
    let words: Vec<&str> = match &mnemonic {
        Some(m) => m.words().collect(),
        None => Vec::new(),
    };
    drop(mnemonic);
    assert!(words.is_empty());

    let passphrase: Option<NewBackupPassphrase> = None;
    let written_down: Vec<&str> = match &passphrase {
        Some(p) => p.words().collect(),
        None => Vec::new(),
    };
    drop(passphrase);
    assert!(written_down.is_empty());

    let challenge: Option<ConfirmChallenge> = None;
    let choices: Vec<&str> = match &challenge {
        Some(c) => c.questions()[0].1.to_vec(),
        None => Vec::new(),
    };
    drop(challenge);
    assert!(choices.is_empty());
}
