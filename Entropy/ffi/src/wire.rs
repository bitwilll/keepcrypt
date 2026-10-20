//! The op table and the reply's status byte (tasks/todo.md, M5 groups 9 and 10; the re-plan's
//! M5-21): every call the shell makes is one op number and one input byte array, and every reply a
//! byte array whose first byte is its status, defined once here and decoded once in Kotlin's
//! Wire.kt. Native code never throws: a halt is a status like any other.
//!
//! - This commit's table holds the calls whose reply is the status alone. Commit 11 adds the rest
//!   with their fixed layouts (progress, C and D, the seal card, word pages, read-back results, the
//!   summary, QR matrices, snapshot and proof results) and the refusal codes after `REFUSED`.
//! - An op the table does not hold, or an input that is not its exact layout, is the shell's bug
//!   and halts (fail closed). Inputs are read in place, never copied.

use keepcrypt_core::{ExtraSource, Mode, SeedLength};
use zeroize::Zeroizing;

use crate::ceremony::{FFI, Reply, Slot};

/// The call gave its result.
pub const OK: u8 = 0;
/// What the user or a file supplied was refused; the stage is as it was. Its code follows from
/// commit 11 on; no op in this commit's table is refused.
pub const REFUSED: u8 = 1;
/// A discard or a wipe came during a long call, whose result was dropped.
pub const DISCARDED: u8 = 2;
/// The slot halted, now or before: the stop screen, and the process's end.
pub const HALTED: u8 = 3;

/// The start-up self-test. No input.
pub const SELF_TEST: u32 = 1;
/// New seed, Dice-only seed and every restart: the length (12 or 24), then the mode (1 Mixed, 2
/// dice only).
pub const START: u32 = 2;
/// An uncredited extra while collecting: the source (1 touch timing, 2 motion), then its bytes.
pub const ADD_EXTRA: u32 = 3;
/// The commitment. No input.
pub const COMMIT: u32 = 4;
/// Opens dice entry. No input.
pub const START_DICE: u32 = 5;
/// One roll: the face, 1-6.
pub const PUSH_ROLL: u32 = 6;
/// Removes the last roll. No input.
pub const UNDO_ROLL: u32 = 7;
/// Makes the seed. No input.
pub const FINISH: u32 = 8;
/// Skip, confirmed. No input.
pub const SKIP_CHECK: u32 = 9;
/// Check now. No input.
pub const START_CHECK: u32 = 10;
/// Match found, confirmed. No input.
pub const MATCH_FOUND: u32 = 11;
/// Cannot check, confirmed. No input.
pub const CANNOT_CHECK: u32 = 12;
/// The backup passphrase, generated once. No input.
pub const GENERATE_BACKUP_PASSPHRASE: u32 = 13;
/// Finish, or Done after "Check a backup". No input.
pub const END: u32 = 14;
/// The discard of leaving the app, the idle wipe, going online and leaving a Protected screen. No
/// input.
pub const DISCARD: u32 = 15;
/// The crash path's and the shell's teardown's wipe. No input.
pub const WIPE_ALL: u32 = 16;

/// The one call per boundary (M5-21): `op` with `input` on the phone's slot, `FFI`.
pub fn dispatch(op: u32, input: &[u8]) -> Zeroizing<Vec<u8>> {
    FFI.dispatch(op, input)
}

/// Halts the phone's slot, and the halt status: keepcrypt-guard's after a caught panic.
pub fn halt() -> Zeroizing<Vec<u8>> {
    status(FFI.halt())
}

impl Slot {
    /// `op` with `input` on this slot, and the reply's bytes.
    pub fn dispatch(&self, op: u32, input: &[u8]) -> Zeroizing<Vec<u8>> {
        let reply = match (op, input) {
            (SELF_TEST, []) => self.self_test(),
            (START, &[len, mode]) => match (seed_length(len), mode_of(mode)) {
                (Some(len), Some(mode)) => self.start(len, mode),
                _ => self.halt(),
            },
            (ADD_EXTRA, [source, bytes @ ..]) => match extra_source(*source) {
                Some(source) => self.add_extra(source, bytes),
                None => self.halt(),
            },
            (COMMIT, []) => self.commit(),
            (START_DICE, []) => self.start_dice(),
            (PUSH_ROLL, &[face]) => self.push_roll(face),
            (UNDO_ROLL, []) => self.undo_roll(),
            (FINISH, []) => self.finish(),
            (SKIP_CHECK, []) => self.skip_check(),
            (START_CHECK, []) => self.start_check(),
            (MATCH_FOUND, []) => self.match_found(),
            (CANNOT_CHECK, []) => self.cannot_check(),
            (GENERATE_BACKUP_PASSPHRASE, []) => self.generate_backup_passphrase(),
            (END, []) => self.end(),
            (DISCARD, []) => self.discard(),
            (WIPE_ALL, []) => self.wipe_all(),
            _ => self.halt(),
        };
        status(reply)
    }
}

/// A status-only reply's bytes.
fn status(reply: Reply<()>) -> Zeroizing<Vec<u8>> {
    let byte = match reply {
        Reply::Done(()) => OK,
        Reply::Refused(_) => REFUSED,
        Reply::Discarded => DISCARDED,
        Reply::Halted => HALTED,
    };
    Zeroizing::new(vec![byte])
}

fn seed_length(byte: u8) -> Option<SeedLength> {
    match byte {
        12 => Some(SeedLength::Words12),
        24 => Some(SeedLength::Words24),
        _ => None,
    }
}

fn mode_of(byte: u8) -> Option<Mode> {
    match byte {
        1 => Some(Mode::Mixed),
        2 => Some(Mode::DiceOnly),
        _ => None,
    }
}

/// The two extras a phone gives in M5 (MA:139-140); the camera and microphone are M8's.
fn extra_source(byte: u8) -> Option<ExtraSource> {
    match byte {
        1 => Some(ExtraSource::InputTiming),
        2 => Some(ExtraSource::Motion),
        _ => None,
    }
}
