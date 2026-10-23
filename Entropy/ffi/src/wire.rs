//! The op table and the reply's bytes (tasks/todo.md, M5 groups 9 and 10; the re-plan's M5-21):
//! every call the shell makes is one op number and one input byte array, and every reply a byte
//! array whose first byte is its status, defined once here and decoded once in Kotlin's Wire.kt.
//! Native code never throws: a halt is a status like any other.
//!
//! - **Status.** `OK`, then the op's reply below (nothing, for a status-only op); `REFUSED`, then
//!   one code byte (`refusal_code`'s table); `DISCARDED` or `HALTED` alone.
//! - **Inputs** are read in place, never copied. An op the table does not hold, or an input that
//!   is not its exact layout (a length, a value out of its range, a text that is not UTF-8), is
//!   the shell's bug and halts (fail closed), as does a reply that does not fit its own layout.
//! - **Replies** are laid out once, by their op's layout function: measured, then written into a
//!   buffer of exactly that size, so none reallocates and leaves a copy behind (rule 5), and each
//!   is wiped when it is dropped.
//! - **Fields.** Integers are big-endian. A flag is one byte, 0 or 1. A text is its length in
//!   bytes, one byte, then its bytes: ASCII, or UTF-8 where it says so. A file is the rest of its
//!   message. A date is YYYYMMDD as a u32: the shell's UTC date (lessons 3), or a header's.
//!
//! The layouts several ops share:
//! - **Seal card**: the 8x8 grid, 8 bytes, row r in byte r and column c in bit 7 - c, 1 for a
//!   filled cell; the colour index, 0-7 into the Okabe-Ito palette; the Seal ID, 8 ASCII bytes; the
//!   Seal ID in braille, a UTF-8 text.
//! - **Word page**: the position (1-24), the count (12 or 24), the device (1 or 2) and the devices
//!   (1 for 12 words, 2 for 24: "device 1 of 2"), the sequence (face 6, 1-12), a byte each; the
//!   SeedBook number, u16; the word, a text; then faces 1-5, four bytes each: the letter (ASCII
//!   lowercase, 0 for a blank face), its dots (dot d at bit d - 1, 0 for blank), the lighter flag
//!   (a letter on face 5) and the mirror partner (ASCII, 0 for none).
//! - **QR matrix** (qr.rs encodes it): the side in modules, 21-61 (versions 1-11), then side x side
//!   bits row by row from the top left, most significant bit first, 1 for dark, the last byte's
//!   spare bits 0. No quiet zone: the shell draws it.
//! - **Registry header** (a loaded snapshot or a verified proof): the number, u64; the date, u32;
//!   the count, u32 (the snapshot's seals, or the proof's entries in its bucket); the freshness
//!   against the shell's date, 0 current, 1 stale, 2 future.
//! - **Summary**: the fingerprint, 4 bytes; the first receive address, a text.
//! - **Go-ahead result**: 0 the words are available, 1 a collision (the seed is wiped unseen); then
//!   a flag, and the registry header after a 1: a snapshot's or a proof's, never a typed code's.

use keepcrypt_core::{
    BACKUP_PASSPHRASE_WORDS, BackupError, BackupFile, CheckError, CoreError, ExtraSource,
    FaceVerdict, Freshness, Mode, SealPublic, SeedLength, SnapshotError, UrError, WatchOnlyExport,
};
use zeroize::Zeroizing;

use crate::ceremony::{
    Challenge, DeviceProgress, DiceProgress, FFI, Halt, Opened, Readback, Refusal, Registry, Reply,
    Revealed, Slot, Summary, WordPage,
};
use crate::qr::{self, Matrix};

/// The call gave its result.
pub const OK: u8 = 0;
/// What the user or a file supplied was refused; the stage is as it was. Its code follows.
pub const REFUSED: u8 = 1;
/// A discard or a wipe came during a long call, whose result was dropped.
pub const DISCARDED: u8 = 2;
/// The slot halted, now or before: the stop screen, and the process's end.
pub const HALTED: u8 = 3;

/// The Seal ID's length: 8 Crockford characters.
const SEAL_ID_LEN: usize = 8;

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
/// The device leg's credit. No input. Reply: the credited bits, then the bits the commitment
/// needs, u64 each.
pub const DEVICE_PROGRESS: u32 = 17;
/// C. No input. Reply: its 32 bytes, or nothing in dice-only mode.
pub const COMMITMENT: u32 = 18;
/// The dice screen's counts. No input. Reply: the rolls, u16; the minimum, u16; the bits so far in
/// thousandths, u32.
pub const DICE_PROGRESS: u32 = 19;
/// The seal card. No input. Reply: the seal card.
pub const SEAL: u32 = 20;
/// The seal card's check QR. No input. Reply: its QR matrix.
pub const CHECK_REQUEST: u32 = 21;
/// The typed go-ahead code: its text, the whole input. Reply: the go-ahead result. Refused: a code
/// that does not verify.
pub const REVEAL_CODE: u32 = 22;
/// The check against the loaded snapshot: today's date. Reply: the go-ahead result.
pub const REVEAL_SNAPSHOT: u32 = 23;
/// A scanned go-ahead QR: today's date, then its text as UTF-8, the rest. Reply: the go-ahead
/// result. Refused: a text that is no proof, or a proof for another bucket.
pub const REVEAL_PROOF: u32 = 24;
/// The kept collision report's QR. No input. Reply: its QR matrix.
pub const COLLISION_REPORT: u32 = 25;
/// One insert's page: the position, 1-24. Reply: the word page.
pub const WORD_PAGE: u32 = 26;
/// One insert read back: the position, then the three or four letters read, the rest. Reply: 0, a
/// match, then a flag: every insert has now matched; or 1, a mismatch, then faces 1-4, three bytes
/// each: the verdict (0 ok, 1 a mirror misread, 2 should be blank, 3 should have a letter, 4 a
/// wrong letter), then a wrong letter's missing and extra dots (dot d at bit d - 1; else 0).
pub const CHECK_READBACK: u32 = 27;
/// The wallet summary. No input. Reply: the summary.
pub const SUMMARY: u32 = 28;
/// A page of the backup passphrase: the page, 0 or 1. Reply: its four words one space apart, a
/// text.
pub const BACKUP_PASSPHRASE_PAGE: u32 = 29;
/// The passphrase's confirm questions. No input. Reply: two questions, each its word's position
/// (1-8), then its four choices, a text each.
pub const BACKUP_CHALLENGE: u32 = 30;
/// The confirm's picks: two bytes, each 0-3 in its question's order. Reply: a flag, both right.
pub const CONFIRM_BACKUP: u32 = 31;
/// The encrypted backup. No input. Reply: its suggested file name, a text; then the file.
pub const ENCRYPT_BACKUP: u32 = 32;
/// The saved backup read back: the file, the whole input. Status only. Refused: a file that does
/// not open, or does not hold this seed.
pub const VERIFY_BACKUP: u32 = 33;
/// The watch-only export: 0 alone, or 1 then a BIP39 passphrase as UTF-8, the rest. Reply: the
/// exported wallet's summary; the passphrase flag; the account QR's matrix; the descriptor QR's
/// matrix. Refused: an empty passphrase.
pub const WATCH_ONLY: u32 = 34;
/// The "Register seal" QR. No input. Reply: its QR matrix.
pub const REGISTRATION: u32 = 35;
/// D, for verify.py. No input. Reply: its 32 bytes.
pub const REVEAL_DEVICE_LEG: u32 = 36;
/// Load registry snapshot: today's date, then the file. Reply: the registry header. Refused: a
/// file that does not verify, or a build with no registry key.
pub const LOAD_SNAPSHOT: u32 = 37;
/// Check a backup: the eight entries, a text each, then the file. Reply: the fingerprint, 4 bytes;
/// the backup's seal card; its re-check QR's matrix. Refused: an entry that names no word, a wrong
/// passphrase, a file that does not read.
pub const OPEN_BACKUP: u32 = 38;

/// The one call per boundary (M5-21): `op` with `input` on the phone's slot, `FFI`.
pub fn dispatch(op: u32, input: &[u8]) -> Zeroizing<Vec<u8>> {
    FFI.dispatch(op, input)
}

/// Halts the phone's slot, and the halt status: keepcrypt-guard's after a caught panic.
pub fn halt() -> Zeroizing<Vec<u8>> {
    FFI.halted()
}

impl Slot {
    /// `op` with `input` on this slot, and the reply's bytes. Whatever halts here halts the slot.
    pub fn dispatch(&self, op: u32, input: &[u8]) -> Zeroizing<Vec<u8>> {
        match self.reply(op, input) {
            Ok(reply) => reply,
            Err(Halt) => self.halted(),
        }
    }

    /// Halts this slot, and the halt status: `Slot::halt` gives `Halted` alone.
    fn halted(&self) -> Zeroizing<Vec<u8>> {
        match self.halt::<()>() {
            Reply::Done(()) | Reply::Refused(_) | Reply::Discarded | Reply::Halted => {
                Zeroizing::new(vec![HALTED])
            }
        }
    }

    /// `op`'s call on `input`, read in place, and its reply.
    fn reply(&self, op: u32, input: &[u8]) -> Result<Zeroizing<Vec<u8>>, Halt> {
        match (op, input) {
            (SELF_TEST, []) => status(self.self_test()),
            (START, &[len, mode]) => status(self.start(seed_length(len)?, mode_of(mode)?)),
            (ADD_EXTRA, [source, bytes @ ..]) => {
                status(self.add_extra(extra_source(*source)?, bytes))
            }
            (COMMIT, []) => status(self.commit()),
            (START_DICE, []) => status(self.start_dice()),
            (PUSH_ROLL, &[face]) => status(self.push_roll(face)),
            (UNDO_ROLL, []) => status(self.undo_roll()),
            (FINISH, []) => status(self.finish()),
            (SKIP_CHECK, []) => status(self.skip_check()),
            (START_CHECK, []) => status(self.start_check()),
            (MATCH_FOUND, []) => status(self.match_found()),
            (CANNOT_CHECK, []) => status(self.cannot_check()),
            (GENERATE_BACKUP_PASSPHRASE, []) => status(self.generate_backup_passphrase()),
            (END, []) => status(self.end()),
            (DISCARD, []) => status(self.discard()),
            (WIPE_ALL, []) => status(self.wipe_all()),
            (DEVICE_PROGRESS, []) => reply(self.device_progress(), device_progress),
            (COMMITMENT, []) => reply(self.commitment(), |out, c| match c {
                Some(c) => out.put(c),
                None => Ok(()),
            }),
            (DICE_PROGRESS, []) => reply(self.dice_progress(), dice_progress),
            (SEAL, []) => reply(self.seal(), seal_card),
            (CHECK_REQUEST, []) => {
                reply(then(self.check_request(), |url| qr::matrix(&url))?, matrix)
            }
            (REVEAL_CODE, code) => reply(self.reveal_code(text(code)?), revealed),
            (REVEAL_SNAPSHOT, &[a, b, c, d]) => reply(
                self.reveal_snapshot(u32::from_be_bytes([a, b, c, d])),
                revealed,
            ),
            (REVEAL_PROOF, &[a, b, c, d, ref qr @ ..]) => reply(
                self.reveal_proof(text(qr)?, u32::from_be_bytes([a, b, c, d])),
                revealed,
            ),
            (COLLISION_REPORT, []) => reply(
                then(self.collision_report(), |report| qr::matrix(report.url()))?,
                matrix,
            ),
            (WORD_PAGE, &[position]) => reply(self.word_page(position), word_page),
            (CHECK_READBACK, [position, letters @ ..]) => {
                reply(self.check_readback(*position, text(letters)?), readback)
            }
            (SUMMARY, []) => reply(self.summary(), summary),
            (BACKUP_PASSPHRASE_PAGE, &[page]) => {
                reply(self.backup_passphrase_page(page), |out, words| {
                    out.text(words)
                })
            }
            (BACKUP_CHALLENGE, []) => reply(self.backup_challenge(), challenge),
            (CONFIRM_BACKUP, &[first, second]) => {
                reply(self.confirm_backup([first, second]), |out, right| {
                    out.flag(*right)
                })
            }
            (ENCRYPT_BACKUP, []) => reply(self.encrypt_backup(), backup_file),
            (VERIFY_BACKUP, file) => status(self.verify_backup(file)),
            (WATCH_ONLY, [with, passphrase @ ..]) => {
                let passphrase = match (with, passphrase) {
                    (0, []) => None,
                    (1, passphrase) => Some(text(passphrase)?),
                    _ => return Err(Halt),
                };
                reply(
                    then(self.watch_only(passphrase), |export| {
                        let account = qr::matrix(export.qr_text())?;
                        let descriptors = qr::descriptors(
                            export.receive_descriptor(),
                            export.change_descriptor(),
                        )?;
                        Ok((export, account, descriptors))
                    })?,
                    watch_only,
                )
            }
            (REGISTRATION, []) => reply(
                then(self.registration(), |registration| {
                    qr::matrix(registration.url())
                })?,
                matrix,
            ),
            (REVEAL_DEVICE_LEG, []) => reply(self.reveal_device_leg(), |out, d| out.put(&d[..])),
            (LOAD_SNAPSHOT, &[a, b, c, d, ref file @ ..]) => reply(
                self.load_snapshot(file, u32::from_be_bytes([a, b, c, d])),
                registry,
            ),
            (OPEN_BACKUP, input) => {
                let (entries, file) = backup_entries(input)?;
                reply(
                    then(self.open_backup(file, &entries), |opened| {
                        let recheck = qr::matrix(opened.seal.recheck_url())?;
                        Ok((opened, recheck))
                    })?,
                    opened,
                )
            }
            _ => Err(Halt),
        }
    }
}

/// A reply's body as its layout function writes it, in two passes over the same function: the
/// first measures it, the second writes it into a buffer of exactly that size, which never
/// reallocates. A write past that size halts.
enum Out {
    Measure(usize),
    Write {
        bytes: Zeroizing<Vec<u8>>,
        size: usize,
    },
}

impl Out {
    fn put(&mut self, field: &[u8]) -> Result<(), Halt> {
        match self {
            Out::Measure(len) => *len = len.checked_add(field.len()).ok_or(Halt)?,
            Out::Write { bytes, size } => {
                let end = bytes.len().checked_add(field.len()).ok_or(Halt)?;
                if end > *size {
                    return Err(Halt);
                }
                bytes.extend_from_slice(field);
            }
        }
        Ok(())
    }

    fn byte(&mut self, byte: u8) -> Result<(), Halt> {
        self.put(&[byte])
    }

    fn flag(&mut self, flag: bool) -> Result<(), Halt> {
        self.byte(u8::from(flag))
    }

    fn u16(&mut self, value: u16) -> Result<(), Halt> {
        self.put(&value.to_be_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), Halt> {
        self.put(&value.to_be_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), Halt> {
        self.put(&value.to_be_bytes())
    }

    /// A text: its length in one byte, then its bytes. Longer than 255 bytes halts.
    fn text(&mut self, text: &str) -> Result<(), Halt> {
        self.byte(u8::try_from(text.len()).map_err(|_| Halt)?)?;
        self.put(text.as_bytes())
    }
}

/// An `OK` reply whose body `layout` writes: measured, then written once.
fn ok(layout: impl Fn(&mut Out) -> Result<(), Halt>) -> Result<Zeroizing<Vec<u8>>, Halt> {
    let mut measured = Out::Measure(1);
    layout(&mut measured)?;
    let Out::Measure(size) = measured else {
        return Err(Halt);
    };
    let mut bytes = Zeroizing::new(Vec::with_capacity(size));
    bytes.push(OK);
    let mut out = Out::Write { bytes, size };
    layout(&mut out)?;
    match out {
        Out::Write { bytes, size } if bytes.len() == size => Ok(bytes),
        _ => Err(Halt),
    }
}

/// A call's reply: `OK` and its result as `layout` lays it out, a refusal and its code,
/// `DISCARDED` or `HALTED`. The result is dropped (and so wiped) once it is written.
fn reply<T>(
    made: Reply<T>,
    layout: impl Fn(&mut Out, &T) -> Result<(), Halt>,
) -> Result<Zeroizing<Vec<u8>>, Halt> {
    match made {
        Reply::Done(made) => ok(|out| layout(out, &made)),
        Reply::Refused(refusal) => Ok(Zeroizing::new(vec![REFUSED, refusal_code(refusal)?])),
        Reply::Discarded => Ok(Zeroizing::new(vec![DISCARDED])),
        Reply::Halted => Ok(Zeroizing::new(vec![HALTED])),
    }
}

/// A status-only reply.
fn status(made: Reply<()>) -> Result<Zeroizing<Vec<u8>>, Halt> {
    reply(made, |_, ()| Ok(()))
}

/// A result made ready for its layout before the two passes (its QR codes encoded once).
fn then<T, U>(made: Reply<T>, ready: impl FnOnce(T) -> Result<U, Halt>) -> Result<Reply<U>, Halt> {
    Ok(match made {
        Reply::Done(made) => Reply::Done(ready(made)?),
        Reply::Refused(refusal) => Reply::Refused(refusal),
        Reply::Discarded => Reply::Discarded,
        Reply::Halted => Reply::Halted,
    })
}

/// The code byte after `REFUSED`, one per refusal (Kotlin's Wire.kt holds the same table): 1-3 a
/// go-ahead that does not verify; 16-19 core's refusals of a passphrase, a backup that holds
/// another seed and a build with no registry key; 32-45 a snapshot or proof that does not verify;
/// 48-59 a go-ahead QR's text that is no proof's UR; 64-72 a backup file that does not read. A
/// core error that is no refusal never comes here (ceremony.rs's `refused`); one would halt.
fn refusal_code(refusal: Refusal) -> Result<u8, Halt> {
    Ok(match refusal {
        Refusal::Code(error) => match error {
            CheckError::MalformedCode => 1,
            CheckError::WrongCode => 2,
            CheckError::WrongBucket => 3,
        },
        Refusal::Core(error) => match error {
            CoreError::WrongPassphrase => 16,
            CoreError::ReadbackMismatch => 17,
            CoreError::EmptyPassphrase => 18,
            CoreError::NoRegistryKey => 19,
            CoreError::Snapshot(error) => match error {
                SnapshotError::TooShort => 32,
                SnapshotError::BadMagic => 33,
                SnapshotError::BadVersion => 34,
                SnapshotError::BadSignature => 35,
                SnapshotError::BadDate => 36,
                SnapshotError::TooManyEntries => 37,
                SnapshotError::BadLength => 38,
                SnapshotError::Unsorted => 39,
                SnapshotError::Duplicate => 40,
                SnapshotError::ZeroCount => 41,
                SnapshotError::RootMismatch => 42,
                SnapshotError::BucketOutOfRange => 43,
                SnapshotError::EntryOutsideBucket => 44,
                SnapshotError::ProofCount => 45,
                SnapshotError::Ur(error) => match error {
                    UrError::TooLong => 48,
                    UrError::MixedCase => 49,
                    UrError::NotUr => 50,
                    UrError::WrongType => 51,
                    UrError::MultiPart => 52,
                    UrError::OddLength => 53,
                    UrError::UnknownByteword => 54,
                    UrError::BadChecksum => 55,
                    UrError::NotByteString => 56,
                    UrError::NonShortestHead => 57,
                    UrError::IndefiniteLength => 58,
                    UrError::TrailingBytes => 59,
                },
            },
            CoreError::Backup(error) => match error {
                BackupError::TooLarge => 64,
                BackupError::Armor => 65,
                BackupError::Header => 66,
                BackupError::WorkFactor => 67,
                BackupError::HeaderMac => 68,
                BackupError::Payload => 69,
                BackupError::Plaintext => 70,
                BackupError::UnsupportedVersion => 71,
                BackupError::PassphraseWords => 72,
            },
            CoreError::Kat(_)
            | CoreError::Source(_)
            | CoreError::Health(_)
            | CoreError::QuotaUnmet
            | CoreError::NotInThisMode
            | CoreError::InvalidRoll
            | CoreError::TooManyRolls
            | CoreError::TooFewRolls
            | CoreError::ReadbackIncomplete
            | CoreError::NoBackupPassphrase
            | CoreError::ExportSelfCheck
            | CoreError::Braille(_)
            | CoreError::Internal(_) => return Err(Halt),
        },
    })
}

fn device_progress(out: &mut Out, progress: &DeviceProgress) -> Result<(), Halt> {
    out.u64(progress.credited_bits)?;
    out.u64(progress.required_bits)
}

fn dice_progress(out: &mut Out, progress: &DiceProgress) -> Result<(), Halt> {
    out.u16(progress.rolls)?;
    out.u16(progress.minimum)?;
    out.u32(progress.millibits)
}

fn seal_card(out: &mut Out, seal: &SealPublic) -> Result<(), Halt> {
    for row in seal.grid() {
        out.byte(
            row.iter()
                .fold(0, |byte, &filled| (byte << 1) | u8::from(filled)),
        )?;
    }
    out.byte(seal.colour_index())?;
    let seal_id = seal.seal_id().as_bytes();
    if seal_id.len() != SEAL_ID_LEN {
        return Err(Halt);
    }
    out.put(seal_id)?;
    out.text(seal.seal_id_braille())
}

fn matrix(out: &mut Out, matrix: &Matrix) -> Result<(), Halt> {
    out.byte(matrix.side())?;
    out.put(matrix.bits())
}

fn registry(out: &mut Out, registry: &Registry) -> Result<(), Halt> {
    out.u64(registry.number)?;
    out.u32(registry.date.yyyymmdd())?;
    out.u32(u32::try_from(registry.count).map_err(|_| Halt)?)?;
    out.byte(match registry.freshness {
        Freshness::Current => 0,
        Freshness::Stale => 1,
        Freshness::Future => 2,
    })
}

fn revealed(out: &mut Out, revealed: &Revealed) -> Result<(), Halt> {
    let (outcome, header) = match revealed {
        Revealed::Clear(header) => (0, header),
        Revealed::Collision(header) => (1, header),
    };
    out.byte(outcome)?;
    out.flag(header.is_some())?;
    match header {
        Some(header) => registry(out, header),
        None => Ok(()),
    }
}

fn word_page(out: &mut Out, page: &WordPage) -> Result<(), Halt> {
    out.put(&[
        page.position(),
        page.count(),
        page.device(),
        page.devices(),
        page.sequence(),
    ])?;
    out.u16(page.seedbook())?;
    out.text(page.word())?;
    for face in page.faces() {
        out.byte(ascii(face.letter())?)?;
        out.byte(face.dots())?;
        out.flag(face.is_lighter())?;
        out.byte(ascii(face.mirror_partner())?)?;
    }
    Ok(())
}

/// A face's letter as its ASCII byte, 0 for none.
fn ascii(letter: Option<char>) -> Result<u8, Halt> {
    match letter {
        Some(letter) if letter.is_ascii_lowercase() => u8::try_from(letter).map_err(|_| Halt),
        Some(_) => Err(Halt),
        None => Ok(0),
    }
}

fn readback(out: &mut Out, readback: &Readback) -> Result<(), Halt> {
    match readback {
        Readback::Match { complete } => {
            out.byte(0)?;
            out.flag(*complete)
        }
        Readback::Mismatch(mismatch) => {
            out.byte(1)?;
            for verdict in mismatch.faces() {
                out.put(&match verdict {
                    FaceVerdict::Ok => [0, 0, 0],
                    FaceVerdict::MirrorMisread => [1, 0, 0],
                    FaceVerdict::ShouldBeBlank => [2, 0, 0],
                    FaceVerdict::ShouldHaveLetter => [3, 0, 0],
                    FaceVerdict::WrongLetter { missing, extra } => {
                        [4, missing.bits(), extra.bits()]
                    }
                })?;
            }
            Ok(())
        }
    }
}

fn summary(out: &mut Out, summary: &Summary) -> Result<(), Halt> {
    out.put(&summary.fingerprint())?;
    out.text(summary.first_address())
}

fn challenge(out: &mut Out, challenge: &Challenge) -> Result<(), Halt> {
    for question in challenge.questions() {
        out.byte(question.position())?;
        for choice in question.choices() {
            out.text(choice)?;
        }
    }
    Ok(())
}

fn backup_file(out: &mut Out, file: &BackupFile) -> Result<(), Halt> {
    out.text(file.name())?;
    out.put(file.bytes())
}

fn watch_only(
    out: &mut Out,
    (export, account, descriptors): &(WatchOnlyExport, Matrix, Matrix),
) -> Result<(), Halt> {
    out.put(&export.fingerprint())?;
    out.text(export.first_address())?;
    out.flag(export.passphrase_used())?;
    matrix(out, account)?;
    matrix(out, descriptors)
}

fn opened(out: &mut Out, (opened, recheck): &(Opened, Matrix)) -> Result<(), Halt> {
    out.put(&opened.fingerprint)?;
    seal_card(out, &opened.seal)?;
    matrix(out, recheck)
}

/// An input text, in place: not UTF-8 is the shell's bug.
fn text(bytes: &[u8]) -> Result<&str, Halt> {
    core::str::from_utf8(bytes).map_err(|_| Halt)
}

/// Check a backup's input, in place: the eight entries, a text each, then the file.
fn backup_entries(mut input: &[u8]) -> Result<([&str; BACKUP_PASSPHRASE_WORDS], &[u8]), Halt> {
    let mut entries = [""; BACKUP_PASSPHRASE_WORDS];
    for entry in &mut entries {
        let (&len, rest) = input.split_first().ok_or(Halt)?;
        let (letters, rest) = rest.split_at_checked(usize::from(len)).ok_or(Halt)?;
        *entry = text(letters)?;
        input = rest;
    }
    Ok((entries, input))
}

fn seed_length(byte: u8) -> Result<SeedLength, Halt> {
    match byte {
        12 => Ok(SeedLength::Words12),
        24 => Ok(SeedLength::Words24),
        _ => Err(Halt),
    }
}

fn mode_of(byte: u8) -> Result<Mode, Halt> {
    match byte {
        1 => Ok(Mode::Mixed),
        2 => Ok(Mode::DiceOnly),
        _ => Err(Halt),
    }
}

/// The two extras a phone gives in M5 (MA:139-140); the camera and microphone are M8's.
fn extra_source(byte: u8) -> Result<ExtraSource, Halt> {
    match byte {
        1 => Ok(ExtraSource::InputTiming),
        2 => Ok(ExtraSource::Motion),
        _ => Err(Halt),
    }
}

#[cfg(test)]
mod tests {
    use keepcrypt_core::{BrailleError, InternalFault, KatId, SourceFault};

    use super::*;

    /// Every refusal the safe layer makes (ceremony.rs's `refused`, and a go-ahead's `CheckError`),
    /// in the order of the code table. A snapshot error's unit variants are named here: its `Ur`
    /// payload gives it no list of its own, and `refusal_code`'s exhaustive match fails to compile
    /// on a new one.
    fn every_refusal() -> Vec<Refusal> {
        let mut every: Vec<Refusal> = CheckError::ALL.map(Refusal::Code).into();
        every.extend(
            [
                CoreError::WrongPassphrase,
                CoreError::ReadbackMismatch,
                CoreError::EmptyPassphrase,
                CoreError::NoRegistryKey,
            ]
            .map(Refusal::Core),
        );
        every.extend(
            [
                SnapshotError::TooShort,
                SnapshotError::BadMagic,
                SnapshotError::BadVersion,
                SnapshotError::BadSignature,
                SnapshotError::BadDate,
                SnapshotError::TooManyEntries,
                SnapshotError::BadLength,
                SnapshotError::Unsorted,
                SnapshotError::Duplicate,
                SnapshotError::ZeroCount,
                SnapshotError::RootMismatch,
                SnapshotError::BucketOutOfRange,
                SnapshotError::EntryOutsideBucket,
                SnapshotError::ProofCount,
            ]
            .map(|error| Refusal::Core(CoreError::Snapshot(error))),
        );
        every.extend(
            UrError::ALL.map(|error| Refusal::Core(CoreError::Snapshot(SnapshotError::Ur(error)))),
        );
        every.extend(BackupError::ALL.map(|error| Refusal::Core(CoreError::Backup(error))));
        every
    }

    /// The code table as Kotlin's Wire.kt copies it (M5 commit 14): every refusal by name, and its
    /// code. A changed, swapped or reused code fails here before it reaches a phone.
    const PINNED: [(&str, u8); 42] = [
        ("Code(MalformedCode)", 1),
        ("Code(WrongCode)", 2),
        ("Code(WrongBucket)", 3),
        ("Core(WrongPassphrase)", 16),
        ("Core(ReadbackMismatch)", 17),
        ("Core(EmptyPassphrase)", 18),
        ("Core(NoRegistryKey)", 19),
        ("Core(Snapshot(TooShort))", 32),
        ("Core(Snapshot(BadMagic))", 33),
        ("Core(Snapshot(BadVersion))", 34),
        ("Core(Snapshot(BadSignature))", 35),
        ("Core(Snapshot(BadDate))", 36),
        ("Core(Snapshot(TooManyEntries))", 37),
        ("Core(Snapshot(BadLength))", 38),
        ("Core(Snapshot(Unsorted))", 39),
        ("Core(Snapshot(Duplicate))", 40),
        ("Core(Snapshot(ZeroCount))", 41),
        ("Core(Snapshot(RootMismatch))", 42),
        ("Core(Snapshot(BucketOutOfRange))", 43),
        ("Core(Snapshot(EntryOutsideBucket))", 44),
        ("Core(Snapshot(ProofCount))", 45),
        ("Core(Snapshot(Ur(TooLong)))", 48),
        ("Core(Snapshot(Ur(MixedCase)))", 49),
        ("Core(Snapshot(Ur(NotUr)))", 50),
        ("Core(Snapshot(Ur(WrongType)))", 51),
        ("Core(Snapshot(Ur(MultiPart)))", 52),
        ("Core(Snapshot(Ur(OddLength)))", 53),
        ("Core(Snapshot(Ur(UnknownByteword)))", 54),
        ("Core(Snapshot(Ur(BadChecksum)))", 55),
        ("Core(Snapshot(Ur(NotByteString)))", 56),
        ("Core(Snapshot(Ur(NonShortestHead)))", 57),
        ("Core(Snapshot(Ur(IndefiniteLength)))", 58),
        ("Core(Snapshot(Ur(TrailingBytes)))", 59),
        ("Core(Backup(TooLarge))", 64),
        ("Core(Backup(Armor))", 65),
        ("Core(Backup(Header))", 66),
        ("Core(Backup(WorkFactor))", 67),
        ("Core(Backup(HeaderMac))", 68),
        ("Core(Backup(Payload))", 69),
        ("Core(Backup(Plaintext))", 70),
        ("Core(Backup(UnsupportedVersion))", 71),
        ("Core(Backup(PassphraseWords))", 72),
    ];

    // The status byte and the refusal code table (todo.md, M5 group 9), pinned: Kotlin's copy is
    // pinned against the same values in Stage D.
    #[test]
    fn the_status_and_refusal_code_tables_are_pinned() {
        assert_eq!([OK, REFUSED, DISCARDED, HALTED], [0, 1, 2, 3]);
        let table: Vec<(String, u8)> = every_refusal()
            .into_iter()
            .map(|refusal| match refusal_code(refusal) {
                Ok(code) => (format!("{refusal:?}"), code),
                Err(Halt) => panic!("{refusal:?} has no code"),
            })
            .collect();
        let pinned: Vec<(String, u8)> = PINNED
            .iter()
            .map(|&(name, code)| (name.to_owned(), code))
            .collect();
        assert_eq!(table, pinned);
        let mut codes: Vec<u8> = PINNED.iter().map(|&(_, code)| code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), PINNED.len(), "no code twice");
        assert!(
            !codes.contains(&0),
            "0 is no code, so a missing byte is no refusal"
        );
    }

    // A core error that is no refusal has no code: a `Refusal` holding one halts the reply.
    #[test]
    fn a_halting_error_has_no_code() {
        let mut halts = vec![
            CoreError::QuotaUnmet,
            CoreError::NotInThisMode,
            CoreError::InvalidRoll,
            CoreError::TooManyRolls,
            CoreError::TooFewRolls,
            CoreError::ReadbackIncomplete,
            CoreError::NoBackupPassphrase,
            CoreError::ExportSelfCheck,
        ];
        halts.extend(KatId::ALL.map(CoreError::Kat));
        halts.extend(SourceFault::ALL.map(CoreError::Source));
        halts.extend(BrailleError::ALL.map(CoreError::Braille));
        halts.extend(InternalFault::ALL.map(CoreError::Internal));
        for error in halts {
            assert!(
                matches!(refusal_code(Refusal::Core(error)), Err(Halt)),
                "{error:?}"
            );
            assert!(
                matches!(status(Reply::Refused(Refusal::Core(error))), Err(Halt)),
                "{error:?}"
            );
        }
    }

    // The op numbers (M5-21), pinned as Kotlin's Native.call will send them: 1-38, each once.
    #[test]
    fn the_op_table_is_pinned() {
        let ops = [
            SELF_TEST,
            START,
            ADD_EXTRA,
            COMMIT,
            START_DICE,
            PUSH_ROLL,
            UNDO_ROLL,
            FINISH,
            SKIP_CHECK,
            START_CHECK,
            MATCH_FOUND,
            CANNOT_CHECK,
            GENERATE_BACKUP_PASSPHRASE,
            END,
            DISCARD,
            WIPE_ALL,
            DEVICE_PROGRESS,
            COMMITMENT,
            DICE_PROGRESS,
            SEAL,
            CHECK_REQUEST,
            REVEAL_CODE,
            REVEAL_SNAPSHOT,
            REVEAL_PROOF,
            COLLISION_REPORT,
            WORD_PAGE,
            CHECK_READBACK,
            SUMMARY,
            BACKUP_PASSPHRASE_PAGE,
            BACKUP_CHALLENGE,
            CONFIRM_BACKUP,
            ENCRYPT_BACKUP,
            VERIFY_BACKUP,
            WATCH_ONLY,
            REGISTRATION,
            REVEAL_DEVICE_LEG,
            LOAD_SNAPSHOT,
            OPEN_BACKUP,
        ];
        assert_eq!(ops.to_vec(), (1..=38).collect::<Vec<u32>>());
    }

    // The writer: a text longer than its length byte, or a reply written past its measured size,
    // halts; the measured size is the written one.
    #[test]
    fn a_reply_is_its_measured_size() {
        let reply = ok(|out| {
            out.text("abc")?;
            out.u16(0x0102)?;
            out.flag(true)
        });
        assert!(matches!(
            reply.as_deref().map(Vec::as_slice),
            Ok([0, 3, b'a', b'b', b'c', 1, 2, 1])
        ));
        assert!(matches!(ok(|out| out.text(&"y".repeat(256))), Err(Halt)));
        assert!(ok(|out| out.text(&"y".repeat(255))).is_ok());
        let mut written = Out::Write {
            bytes: Zeroizing::new(Vec::with_capacity(2)),
            size: 2,
        };
        assert!(written.put(&[1, 2]).is_ok());
        assert!(matches!(written.byte(3), Err(Halt)));
    }
}
