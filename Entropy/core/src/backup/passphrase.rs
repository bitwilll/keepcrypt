//! The generated backup passphrase and its 2-of-4 confirm challenge (docs/build-plan.md
//! "Passphrase"; pi-firmware.md USB steps 1-2; mobile-apps.md "Encrypted backup only";
//! tasks/todo.md, M1 group 8, Q5, Q6e; vectors/backup.json spec "passphrase", "generate").
//!
//! - 11 OS bytes, in a read of their own that never touches the pool, become 8 word indices of 11
//!   bits, most significant first, stored in the session (`BackupPassphrase`). User-chosen
//!   passphrases do not exist in v1: nothing else can fill one.
//! - Then 16 OS bytes per challenge attempt: question 1 asks for word `b[0] & 7`, question 2 for
//!   word `b[1] & 7`; the right word sits at choice `b[2] & 3` and `b[3] & 3`; the six other
//!   choices are the 11-bit values `(b[4 + 2k] << 8 | b[5 + 2k]) & 0x7ff`, three per question. Every
//!   value is a whole number of bits of uniform bytes, so nothing has modulo bias. An attempt that
//!   asks for one word twice, or repeats a choice within a question, is dropped and 16 fresh bytes
//!   are read (rejection keeps the draw uniform). After 64 dropped attempts the call fails closed
//!   with `Source(NoUsableDraw)`: a working source fails an attempt about 1 time in 7, so 64 in a
//!   row means it repeats itself.

use zeroize::{Zeroize, Zeroizing};

use crate::error::{CoreError, SourceFault};
use crate::secret::{
    BACKUP_PASSPHRASE_BYTES, BACKUP_PASSPHRASE_WORDS, BackupPassphrase, ConfirmChallenge,
    NewBackupPassphrase,
};
use crate::source::Source;

/// OS bytes per challenge attempt.
const ATTEMPT_BYTES: usize = 16;
/// Attempts before the draw fails closed.
const MAX_ATTEMPTS: usize = 64;

/// Generates a passphrase into `stored`, replacing any earlier one, and draws its confirm
/// challenge; returns the display copy. On any error `stored` is wiped.
pub(crate) fn generate(
    source: &mut Source,
    stored: &mut BackupPassphrase,
) -> Result<NewBackupPassphrase, CoreError> {
    let drawn = draw(source, stored);
    if drawn.is_err() {
        stored.zeroize();
    }
    drawn
}

fn draw(
    source: &mut Source,
    stored: &mut BackupPassphrase,
) -> Result<NewBackupPassphrase, CoreError> {
    let bytes = source.os_bytes::<BACKUP_PASSPHRASE_BYTES>()?;
    stored.fill_from_bytes(&bytes);
    let mut new = stored.display_copy();
    challenge_into(source, stored.indices(), new.challenge_mut())?;
    Ok(new)
}

/// Draws the confirm challenge for `indices` into `out` (module comment).
fn challenge_into(
    source: &mut Source,
    indices: &[u16; BACKUP_PASSPHRASE_WORDS],
    out: &mut ConfirmChallenge,
) -> Result<(), CoreError> {
    let mut choices = Zeroizing::new([[0u16; 4]; 2]);
    for _ in 0..MAX_ATTEMPTS {
        let b = source.os_bytes::<ATTEMPT_BYTES>()?;
        let positions = [b[0] & 7, b[1] & 7];
        for (q, question) in choices.iter_mut().enumerate() {
            // The three other choices in order, then the right word, rotated into its slot.
            for (k, choice) in question[..3].iter_mut().enumerate() {
                let at = 4 + 2 * (3 * q + k);
                *choice = u16::from_be_bytes([b[at], b[at + 1]]) & 0x7ff;
            }
            question[3] = indices[usize::from(positions[q])];
            question[usize::from(b[2 + q] & 3)..].rotate_right(1);
        }
        let distinct = |c: &[u16; 4]| (0..4).all(|i| (i + 1..4).all(|j| c[i] != c[j]));
        if positions[0] != positions[1] && choices.iter().all(distinct) {
            out.set([positions[0] + 1, positions[1] + 1], &choices);
            return Ok(());
        }
    }
    Err(CoreError::Source(SourceFault::NoUsableDraw))
}
