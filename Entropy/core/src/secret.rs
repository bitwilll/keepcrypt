//! Secret wrappers (CLAUDE.md rule 5; docs/build-plan.md "secret"; tasks/todo.md, M1 group 2).
//!
//! - Each type is built zeroed and filled in place, and is `Zeroize` + `ZeroizeOnDrop`.
//! - None has `Debug`, `Display`, `Clone`, `Copy`, `PartialEq` or `Serialize` (core has no serde),
//!   so a secret cannot be printed, logged, duplicated or compared by accident. The trybuild
//!   fixtures in `core/tests/compile_fail/` prove it.
//! - Secrets leave only through methods named `expose_secret`, `words` or `questions` (and, from
//!   M1 group 8, `CheckedBackup::reveal_*`), so review can grep every exit.

use secrecy::{ExposeSecret, SecretString};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{BackupError, CoreError};

/// The most words a seed has.
pub(crate) const MAX_WORDS: usize = 24;
/// Words in a generated backup passphrase (88 bits; docs/build-plan.md "Encrypted backup format").
pub const BACKUP_PASSPHRASE_WORDS: usize = 8;

/// The BIP39 English word list, from the `bip39` crate (checked by the Bip39Wordlist KAT).
fn word_list() -> &'static [&'static str; 2048] {
    bip39::Language::English.word_list()
}

/// The word for an index that construction already bounded to 0..2048.
fn word(index: u16) -> &'static str {
    word_list()[usize::from(index)]
}

/// 32 secret bytes: the device leg D or the seed entropy E.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes32([u8; 32]);

impl SecretBytes32 {
    pub(crate) const fn zeroed() -> Self {
        Self([0; 32])
    }

    /// The 32 bytes. D leaves core only here, after `reveal_device_leg`, for offline audit.
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The 64-byte BIP39 seed S (PBKDF2 output). Never leaves core.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SecretSeed64([u8; 64]);

impl SecretSeed64 {
    pub(crate) const fn zeroed() -> Self {
        Self([0; 64])
    }
}

/// A seed's words, held as BIP39 English word indices (each below 2,048) plus the word count.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretMnemonic {
    indices: [u16; MAX_WORDS],
    count: u8,
}

impl SecretMnemonic {
    pub(crate) const fn zeroed() -> Self {
        Self {
            indices: [0; MAX_WORDS],
            count: 0,
        }
    }

    /// The number of words: 12 or 24 once the seed exists.
    pub fn word_count(&self) -> usize {
        usize::from(self.count)
    }

    /// The words, in order: the only way the mnemonic leaves core.
    pub fn words(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.indices
            .iter()
            .take(self.word_count())
            .map(|&i| word(i))
    }
}

/// An optional BIP39 passphrase for the watch-only export. `new` rejects "" (leave the passphrase
/// out instead) and never trims, so "TREZOR " and "TREZOR" are different wallets. It is NFKD-
/// normalized into a zeroizing buffer only when used (tasks/todo.md, M1 group 6, Q5).
pub struct Bip39Passphrase(SecretString);

impl Bip39Passphrase {
    /// The passphrase exactly as typed; "" is `EmptyPassphrase`.
    pub fn new(passphrase: &str) -> Result<Self, CoreError> {
        if passphrase.is_empty() {
            return Err(CoreError::EmptyPassphrase);
        }
        Ok(Self(SecretString::from(passphrase)))
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "read by Session::watch_only (tasks/todo.md, M1 group 6)"
        )
    )]
    pub(crate) fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

/// The generated backup passphrase, stored in the session (`Inner`) and never handed out: the
/// shell gets a `NewBackupPassphrase` display copy, and `encrypt_backup` and `verify_backup` use
/// this one (tasks/todo.md, M1 Q5). `present` is false until one is generated, so there is no
/// `Option` to unwrap.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct BackupPassphrase {
    indices: [u16; BACKUP_PASSPHRASE_WORDS],
    present: bool,
}

impl BackupPassphrase {
    pub(crate) const fn zeroed() -> Self {
        Self {
            indices: [0; BACKUP_PASSPHRASE_WORDS],
            present: false,
        }
    }
}

/// The 2-of-4 confirm challenge shown after a new backup passphrase (pi-firmware.md USB step 2):
/// for each of two word positions, four candidate words, one of them the word at that position.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ConfirmChallenge {
    positions: [u8; 2],
    choices: [[u16; 4]; 2],
}

impl ConfirmChallenge {
    /// The two questions, each as (1-based word position, the four candidate words).
    pub fn questions(&self) -> [(u8, [&'static str; 4]); 2] {
        let question = |q: usize| (self.positions[q], self.choices[q].map(word));
        [question(0), question(1)]
    }
}

/// A display copy of a newly generated backup passphrase, with its confirm challenge. The
/// session keeps the passphrase itself; dropping this copy wipes it.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NewBackupPassphrase {
    indices: [u16; BACKUP_PASSPHRASE_WORDS],
    challenge: ConfirmChallenge,
}

impl NewBackupPassphrase {
    /// The 8 words, in order, for the user to write down.
    pub fn words(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.indices.iter().map(|&i| word(i))
    }

    /// The confirm challenge for these words.
    pub fn challenge(&self) -> &ConfirmChallenge {
        &self.challenge
    }
}

/// A backup passphrase typed by the user to check a backup. Only `decrypt_backup` accepts one;
/// `encrypt_backup` and `verify_backup` take no passphrase at all, so typed words can never
/// encrypt (docs/build-plan.md: no user-chosen backup passphrases in v1).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TypedBackupPassphrase {
    indices: [u16; BACKUP_PASSPHRASE_WORDS],
}

impl TypedBackupPassphrase {
    /// Exactly 8 words, each exactly as in the BIP39 English list: lowercase, no surrounding
    /// spaces, no case folding. Anything else is `Backup(PassphraseWords)`.
    pub fn from_words(words: &[&str]) -> Result<Self, CoreError> {
        let mut typed = Self {
            indices: [0; BACKUP_PASSPHRASE_WORDS],
        };
        if words.len() != BACKUP_PASSPHRASE_WORDS {
            return Err(CoreError::Backup(BackupError::PassphraseWords));
        }
        for (slot, typed_word) in typed.indices.iter_mut().zip(words) {
            match bip39::Language::English.find_word(typed_word) {
                Some(index) => *slot = index,
                None => return Err(CoreError::Backup(BackupError::PassphraseWords)),
            }
        }
        Ok(typed)
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "read by decrypt_backup (tasks/todo.md, M1 group 8)"
        )
    )]
    pub(crate) fn indices(&self) -> &[u16; BACKUP_PASSPHRASE_WORDS] {
        &self.indices
    }
}

/// White-box test support: fill every field of a wrapper with non-zero bytes, then check that
/// `zeroize()` cleared all of them.
#[cfg(test)]
pub(crate) trait TestFill: Zeroize {
    fn fill(&mut self);
    fn is_zero(&self) -> bool;
}

#[cfg(test)]
mod test_fill {
    use super::*;

    impl TestFill for SecretBytes32 {
        fn fill(&mut self) {
            self.0 = [0xa5; 32];
        }
        fn is_zero(&self) -> bool {
            self.0 == [0; 32]
        }
    }

    impl TestFill for SecretSeed64 {
        fn fill(&mut self) {
            self.0 = [0x5a; 64];
        }
        fn is_zero(&self) -> bool {
            self.0 == [0; 64]
        }
    }

    impl TestFill for SecretMnemonic {
        fn fill(&mut self) {
            self.indices = [2047; MAX_WORDS];
            self.count = 24;
        }
        fn is_zero(&self) -> bool {
            self.indices == [0; MAX_WORDS] && self.count == 0
        }
    }

    impl TestFill for BackupPassphrase {
        fn fill(&mut self) {
            self.indices = [2047; BACKUP_PASSPHRASE_WORDS];
            self.present = true;
        }
        fn is_zero(&self) -> bool {
            self.indices == [0; BACKUP_PASSPHRASE_WORDS] && !self.present
        }
    }

    impl TestFill for ConfirmChallenge {
        fn fill(&mut self) {
            self.positions = [3, 8];
            self.choices = [[2047; 4]; 2];
        }
        fn is_zero(&self) -> bool {
            self.positions == [0; 2] && self.choices == [[0; 4]; 2]
        }
    }

    impl TestFill for NewBackupPassphrase {
        fn fill(&mut self) {
            self.indices = [2047; BACKUP_PASSPHRASE_WORDS];
            self.challenge.fill();
        }
        fn is_zero(&self) -> bool {
            self.indices == [0; BACKUP_PASSPHRASE_WORDS] && self.challenge.is_zero()
        }
    }

    impl TestFill for TypedBackupPassphrase {
        fn fill(&mut self) {
            self.indices = [2047; BACKUP_PASSPHRASE_WORDS];
        }
        fn is_zero(&self) -> bool {
            self.indices == [0; BACKUP_PASSPHRASE_WORDS]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filled_then_zeroized<T: TestFill>(mut secret: T) {
        secret.fill();
        assert!(!secret.is_zero());
        secret.zeroize();
        assert!(secret.is_zero());
    }

    #[test]
    fn every_wrapper_zeroizes_every_field() {
        filled_then_zeroized(SecretBytes32::zeroed());
        filled_then_zeroized(SecretSeed64::zeroed());
        filled_then_zeroized(SecretMnemonic::zeroed());
        filled_then_zeroized(BackupPassphrase::zeroed());
        filled_then_zeroized(ConfirmChallenge {
            positions: [0; 2],
            choices: [[0; 4]; 2],
        });
        filled_then_zeroized(NewBackupPassphrase {
            indices: [0; BACKUP_PASSPHRASE_WORDS],
            challenge: ConfirmChallenge {
                positions: [0; 2],
                choices: [[0; 4]; 2],
            },
        });
        filled_then_zeroized(TypedBackupPassphrase {
            indices: [0; BACKUP_PASSPHRASE_WORDS],
        });
    }

    #[test]
    fn mnemonic_words_follow_the_indices_and_count() {
        let mut m = SecretMnemonic::zeroed();
        assert_eq!(m.words().count(), 0);
        m.indices[..12].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
        m.count = 12;
        let words: Vec<&str> = m.words().collect();
        assert_eq!(
            words.join(" "),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        assert_eq!(m.word_count(), 12);
    }

    #[test]
    fn bip39_passphrase_rejects_empty_and_never_trims() {
        assert!(matches!(
            Bip39Passphrase::new(""),
            Err(CoreError::EmptyPassphrase)
        ));
        for typed in ["TREZOR", "TREZOR ", " ", "\u{e9}t\u{e9}"] {
            match Bip39Passphrase::new(typed) {
                Ok(p) => assert_eq!(p.expose_secret(), typed),
                Err(e) => panic!("{typed:?} rejected: {e}"),
            }
        }
    }

    #[test]
    fn display_copy_and_challenge_read_words_by_index() {
        let new = NewBackupPassphrase {
            indices: [0, 1, 2, 3, 2044, 2045, 2046, 2047],
            challenge: ConfirmChallenge {
                positions: [2, 7],
                choices: [[1, 5, 9, 2047], [0, 2046, 3, 4]],
            },
        };
        let words: Vec<&str> = new.words().collect();
        assert_eq!(
            words,
            [
                "abandon", "ability", "able", "about", "zebra", "zero", "zone", "zoo"
            ]
        );
        assert_eq!(
            new.challenge().questions(),
            [
                (2, ["ability", "absent", "abuse", "zoo"]),
                (7, ["abandon", "zone", "about", "above"])
            ]
        );
    }

    #[test]
    fn typed_backup_passphrase_takes_exactly_eight_list_words() {
        let eight = [
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "zoo",
        ];
        match TypedBackupPassphrase::from_words(&eight) {
            Ok(t) => assert_eq!(t.indices(), &[0, 1, 2, 3, 4, 5, 6, 2047]),
            Err(e) => panic!("rejected: {e}"),
        }
        let bad: [&[&str]; 6] = [
            &eight[..7],
            &["abandon"; 9],
            &[
                "Abandon", "ability", "able", "about", "above", "absent", "absorb", "zoo",
            ],
            &[
                "abandon ", "ability", "able", "about", "above", "absent", "absorb", "zoo",
            ],
            &[
                "abandon", "ability", "able", "about", "above", "absent", "absorb", "zo",
            ],
            &[],
        ];
        for words in bad {
            assert!(
                matches!(
                    TypedBackupPassphrase::from_words(words),
                    Err(CoreError::Backup(BackupError::PassphraseWords))
                ),
                "{words:?}"
            );
        }
    }
}
