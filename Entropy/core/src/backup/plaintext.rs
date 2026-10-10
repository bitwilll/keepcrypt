//! The plaintext inside the backup, v1 (docs/build-plan.md "Plaintext inside the file";
//! docs/seal-watchonly-braille.md "Inside the encrypted backup"; tasks/todo.md, M1 group 8, Q6e;
//! vectors/backup.json spec "plaintext", "plaintext_reader").
//!
//! ```text
//! keepcrypt-backup/v1
//! words: <12 or 24 words, single spaces>
//! braille:
//!   01 <every letter's cell>            (one line per word)
//! fingerprint: <8 lowercase hex, S with the empty passphrase>
//! created-by: keepcrypt-<pi|android|ios> X.Y.Z
//! ```
//!
//! UTF-8, LF line ends and a final LF, no BOM. The BIP39 passphrase has no way in: nothing here
//! takes one. The reader refuses `keepcrypt-backup/v` and any other version number with
//! `UnsupportedVersion`; otherwise it takes the words (with their BIP39 checksum) and the
//! created-by line, computes the fingerprint, writes the plaintext again and requires byte
//! equality, so every other rule (braille lines, fingerprint, spacing, line ends) is checked by
//! that one comparison. Anything else is `Plaintext`.

use zeroize::{Zeroize, Zeroizing};

use super::CreatedBy;
use crate::braille::BrailleInserts;
use crate::error::{BackupError, CoreError};
use crate::secret::SecretMnemonic;
use crate::seed::{EmptyPassphraseSeed, seed_from_mnemonic_into, wallet_summary};

const VERSION_LINE: &str = "keepcrypt-backup/v1";
const VERSION_PREFIX: &str = "keepcrypt-backup/v";
const WORDS: &str = "words: ";
const BRAILLE: &str = "braille:";
const FINGERPRINT: &str = "fingerprint: ";

/// The exact length in bytes of the plaintext `write_into` writes.
pub(crate) fn len(mnemonic: &SecretMnemonic, by: &CreatedBy) -> usize {
    let words =
        mnemonic.words().map(str::len).sum::<usize>() + mnemonic.word_count().saturating_sub(1);
    VERSION_LINE.len()
        + 1
        + WORDS.len()
        + words
        + 1
        + BRAILLE.len()
        + 1
        + BrailleInserts::new(mnemonic).backup_lines_len()
        + FINGERPRINT.len()
        + 8
        + 1
        + by.line_len()
}

/// Writes the plaintext v1 into `out`, which the caller sizes with `len` (a zeroizing buffer), so
/// nothing reallocates.
pub(crate) fn write_into(
    mnemonic: &SecretMnemonic,
    fingerprint: [u8; 4],
    by: &CreatedBy,
    out: &mut String,
) {
    out.push_str(VERSION_LINE);
    out.push('\n');
    out.push_str(WORDS);
    for (n, word) in mnemonic.words().enumerate() {
        if n > 0 {
            out.push(' ');
        }
        out.push_str(word);
    }
    out.push('\n');
    out.push_str(BRAILLE);
    out.push('\n');
    BrailleInserts::new(mnemonic).backup_lines_into(out);
    out.push_str(FINGERPRINT);
    crate::seal::push_hex(out, &fingerprint);
    out.push('\n');
    by.push_line(out);
}

/// Reads a plaintext v1 into `mnemonic` and returns its fingerprint. On any error `mnemonic` is
/// wiped.
pub(crate) fn parse_into(
    bytes: &[u8],
    mnemonic: &mut SecretMnemonic,
) -> Result<[u8; 4], CoreError> {
    let parsed = parse(bytes, mnemonic);
    if parsed.is_err() {
        mnemonic.zeroize();
    }
    parsed
}

fn parse(bytes: &[u8], mnemonic: &mut SecretMnemonic) -> Result<[u8; 4], CoreError> {
    let bad = CoreError::Backup(BackupError::Plaintext);
    let text = core::str::from_utf8(bytes).map_err(|_| bad)?;
    let mut lines = text.split('\n');
    let first = lines.next().ok_or(bad)?;
    if first != VERSION_LINE {
        return Err(if is_other_version(first) {
            CoreError::Backup(BackupError::UnsupportedVersion)
        } else {
            bad
        });
    }
    let words = lines
        .next()
        .and_then(|line| line.strip_prefix(WORDS))
        .ok_or(bad)?;
    let typed = words.split(' ').count();
    let found = words
        .split(' ')
        .filter_map(|word| bip39::Language::English.find_word(word))
        .map(usize::from);
    mnemonic.fill_from(found).map_err(|_| bad)?;
    if mnemonic.word_count() != typed {
        return Err(bad);
    }
    let mut seed = EmptyPassphraseSeed::zeroed();
    seed_from_mnemonic_into(mnemonic, &mut seed).map_err(|_| bad)?;
    let fingerprint = wallet_summary(&seed).map_err(|_| bad)?.fingerprint;
    let created = text
        .strip_suffix('\n')
        .and_then(|rest| rest.rsplit('\n').next())
        .ok_or(bad)?;
    let by = CreatedBy::parse_line(created).ok_or(bad)?;
    let mut again = Zeroizing::new(String::with_capacity(len(mnemonic, &by)));
    write_into(mnemonic, fingerprint, &by, &mut again);
    if again.as_bytes() != bytes {
        return Err(bad);
    }
    Ok(fingerprint)
}

/// `keepcrypt-backup/v` and a version number `[1-9][0-9]*`: a later layout this build does not
/// read.
fn is_other_version(line: &str) -> bool {
    match line.strip_prefix(VERSION_PREFIX) {
        Some(version) => {
            version.starts_with(|c: char| ('1'..='9').contains(&c))
                && version.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    }
}
