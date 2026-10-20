//! The phone's one ceremony (tasks/todo.md, M5 groups 8 and 11, with the re-plan's dispatch, M5-21;
//! docs/mobile-apps.md "Session lifecycle"): the slot that holds the only session, every call the
//! shell makes on it, and what each call gives back.
//!
//! - **The slot.** One `static FFI: Slot`, a `Mutex<Held>`. `Held` is pi/app's (app.rs:178-184):
//!   the stage (the session in its typestate, as app.rs's `Stage`, plus `Busy` while a long call
//!   runs and `Halted`), the kept `Wiped`, a loaded snapshot, a checked backup and the generation of
//!   the long-call rule. keepcrypt-guard reaches `FFI` through `dispatch` and `halt` alone; each
//!   test builds its own `Slot`.
//! - **Every call** locks, moves the stage out with `mem::replace`, calls core's consuming method
//!   and puts back what `Ok` gives. An `Err` from a call that took the session has already wiped it
//!   (core's session.rs) and halts. A call in a stage that does not offer it halts: the shell's bug,
//!   failed closed. A poisoned lock is matched and halts (`lock`).
//! - **Halts and refusals** (`refused`, app.rs:235's table, tested against it): a refusal of what
//!   the user or a file supplied leaves the stage as it was and returns core's fixed error; a halt
//!   drops everything held and latches `Halted`, which every later call returns. Only the process's
//!   end leaves it.
//! - **The kept `Wiped`** (Q26; todo.md:1404-1406): Match found and Cannot check keep it, a
//!   collision replaces it, and only Skip or a passed check drops it. `new_session` is the one
//!   place a session starts: from the kept `Wiped` while there is one, so a pending 99-roll minimum
//!   carries over, else core's constructor on `Platform::Phone` (app.rs:387-399). A discard keeps
//!   it, with a loaded snapshot; `wipe_all` (the crash path) and a halt drop them too.
//! - **Long calls** (`long`): the start and its known-answer suite, `finish`, the backup's scrypt
//!   (encrypt, verify and open), snapshot and proof verification and the self-test take what they
//!   need out of the slot under the lock, leave `Busy` and the generation, release the lock, run,
//!   then lock again. A discard or `wipe_all` meanwhile drops everything it drops, leaves `Idle` and
//!   starts a new generation, so the finishing call drops its result (which wipes it) and returns
//!   `Discarded`; a halt meanwhile leaves `Halted`, which it returns. Any other call while `Busy`
//!   halts. An `Err` the long work itself halts on halts whatever happened meanwhile. A go-ahead is
//!   judged under the lock, so a collision's `Wiped` is never lost to a discard. The kept `Wiped` is
//!   an `Arc`: a start borrows it while the lock is released, and the slot keeps it all along.
//! - **Owned copies** (todo.md:3090-3093): a go-ahead (`GoAhead`) is built inside the call from the
//!   held snapshot, a proof verified in the same call or the typed code; word pages, braille faces,
//!   the backup passphrase's pages and confirm choices, D and a checked backup's words leave as
//!   copies that wipe themselves (`WordPage`, `Challenge`, `Zeroizing`), one page at a time. No
//!   borrowed core type appears in a public signature here.
//! - **Freshness** (lessons 3): `today` is the shell's UTC date as YYYYMMDD
//!   (`RegistryDate::from_yyyymmdd`); a snapshot or proof result carries its number, date, entry
//!   count and freshness against it (`Registry`). The phones warn on Stale and Future.

use core::fmt;
use core::mem;
use std::sync::{Arc, Mutex, MutexGuard};

use keepcrypt_core::{
    BackupApp, BackupFile, Bip39Passphrase, BrailleInserts, CheckError, CheckedBackup, Checking,
    Collecting, CollisionReport, Committed, CoreError, CreatedBy, Discard, ExtraSource, Freshness,
    GoAhead, Insert, Mode, NewBackupPassphrase, Platform, ReadbackMismatch, ReadbackResult, Ready,
    RegistryDate, Rejected, Rolling, SealPublic, SealRegistration, Sealed, SeedLength, Session,
    TypedBackupPassphrase, VerifiedProof, VerifiedSnapshot, WatchOnlyExport, Wiped, decrypt_backup,
    self_test, verify_bucket_proof_qr, verify_snapshot,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// This app in a backup's `created-by:` line: `keepcrypt-android 0.0.0` until M7 (Q62).
const CREATED_BY: CreatedBy = CreatedBy::new(BackupApp::Android, 0, 0, 0);
/// The backup passphrase's words per page: two pages of four (pi-firmware.md, USB step 1).
const PASSPHRASE_PAGE_WORDS: usize = 4;
/// The longest BIP39 word, for a page's exact capacity.
const LONGEST_WORD: usize = 8;

/// The phone's one ceremony slot: keepcrypt-guard reaches it through `dispatch` and `halt` alone.
pub static FFI: Slot = Slot::new();

/// A ceremony slot. The phone has one, `FFI`; each test builds its own. No `Debug`.
pub struct Slot {
    held: Mutex<Held>,
}

/// Everything a slot holds (app.rs:178-184). No `Debug` or `Clone`.
struct Held {
    stage: Stage,
    /// Bumped by each discard and `wipe_all`: a long call that finds another drops its result.
    generation: u64,
    /// The `Wiped` of the last check that ended without the words, until Skip or a passed check.
    kept: Option<Arc<Wiped>>,
    /// A registry snapshot loaded from a file: it outlives sessions and discards.
    snapshot: Option<VerifiedSnapshot>,
    /// "Check a backup", opened: its words, until Done or a discard.
    backup: Option<CheckedBackup>,
}

/// The session in its typestate (app.rs:79), and the backup passphrase's display copy with it.
enum Stage {
    /// No session: before the first, after a check discarded one, a discard, Finish and a wipe.
    Idle,
    Collecting(Session<Collecting>),
    Committed(Session<Committed>),
    Rolling(Session<Rolling>),
    Sealed(Session<Sealed>),
    Checking(Session<Checking>),
    /// The words, the read-back and the exports.
    Ready(Steps),
    /// A long call runs with the lock released: only a discard, `wipe_all` or a halt may come.
    Busy,
    /// After a halt: nothing is held, and every call returns `Halted`.
    Halted,
}

/// What the words' steps hold beside the session (app.rs's `Steps`).
struct Steps {
    session: Session<Ready>,
    /// The passphrase's display copy, from its generation until its confirm passes.
    passphrase: Option<NewBackupPassphrase>,
    /// The passphrase was generated: a second would void the paper copy (Q33 (d)).
    generated: bool,
}

impl Steps {
    fn new(session: Session<Ready>) -> Self {
        Steps {
            session,
            passphrase: None,
            generated: false,
        }
    }
}

/// Where a slot's ceremony is, for the shell's screens and the tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageKind {
    Idle,
    Collecting,
    Committed,
    Rolling,
    Sealed,
    Checking,
    Ready,
    Busy,
    Halted,
}

/// What a slot holds, in public terms only: no secret, nothing a screen could leak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Holds {
    pub stage: StageKind,
    /// A `Wiped` is kept: the next start restarts from it.
    pub kept: bool,
    /// The kept `Wiped` holds a collision report.
    pub report: bool,
    pub snapshot: bool,
    pub backup: bool,
}

/// What a call gives back: its result; a refusal, with the stage as it was; `Discarded`, when a
/// discard or wipe came during a long call; or `Halted`. Its `Debug` names the variant only.
#[must_use]
pub enum Reply<T> {
    Done(T),
    Refused(Refusal),
    Discarded,
    Halted,
}

impl<T> fmt::Debug for Reply<T> {
    /// The variant and a refusal's fixed error; never a result, which may be secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reply::Done(_) => f.write_str("Reply::Done"),
            Reply::Refused(refusal) => write!(f, "Reply::Refused({refusal:?})"),
            Reply::Discarded => f.write_str("Reply::Discarded"),
            Reply::Halted => f.write_str("Reply::Halted"),
        }
    }
}

/// A refusal of what the user or a file supplied (Q25; app.rs's `Refusal`): it returns to its own
/// screen, which names it in fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A go-ahead that does not verify: a typed code, or a proof for another bucket.
    Code(CheckError),
    /// A wrong or empty passphrase, a backup that holds another seed, no registry key, or a
    /// snapshot, proof or backup file that does not read: core's text.
    Core(CoreError),
}

/// Why a call ends without its result. Internal: the shell sees a `Reply`.
enum Fail {
    Refused(Refusal),
    Halt,
}

/// A call that halts: a core error that is no refusal, or the shell's bug; wire.rs's and qr.rs's
/// too, for an input or a reply that is not its layout.
pub(crate) struct Halt;

impl From<Halt> for Fail {
    fn from(_: Halt) -> Self {
        Fail::Halt
    }
}

/// Sorts an error from a core call that took no session, as app.rs:235 does (Q25): a refusal of
/// what the user or a file supplied, or a halt. Calls that take the session never come here: their
/// every `Err` has wiped it, and halts.
fn refused(error: CoreError) -> Result<Refusal, Halt> {
    match error {
        CoreError::WrongPassphrase
        | CoreError::ReadbackMismatch
        | CoreError::EmptyPassphrase
        | CoreError::NoRegistryKey
        | CoreError::Snapshot(_)
        | CoreError::Backup(_) => Ok(Refusal::Core(error)),
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
        | CoreError::Internal(_) => Err(Halt),
    }
}

/// The one place a session starts (Q26, Q33 (c); app.rs:387-399): from the kept `Wiped` while there
/// is one, so a pending 99-roll minimum carries over, else a fresh session on a phone. Either runs
/// the full known-answer suite first; an `Err` means no seed can be made.
fn new_session(
    kept: Option<&Wiped>,
    len: SeedLength,
    mode: Mode,
) -> Result<Session<Collecting>, CoreError> {
    match kept {
        Some(wiped) => wiped.restart(len, mode),
        None => Session::new(len, mode, Platform::Phone),
    }
}

/// The shell's UTC date, as YYYYMMDD. A date no calendar has comes from the shell's own clock
/// code, not from the user or a file: its bug, which halts.
fn registry_date(yyyymmdd: u32) -> Result<RegistryDate, Halt> {
    RegistryDate::from_yyyymmdd(yyyymmdd).map_err(|_| Halt)
}

/// The device leg's progress before the commitment (`Session<Collecting>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceProgress {
    /// Credited bits so far: the OS read's 256 on a phone in Mixed mode, 0 in dice-only mode.
    pub credited_bits: u64,
    /// The bits the commitment needs: 256 on a phone in Mixed mode, 0 in dice-only mode.
    pub required_bits: u64,
}

/// The dice screen's counts (`Session<Rolling>`): never the rolls themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiceProgress {
    pub rolls: u16,
    /// 50 for 12 words, 99 for 24, and 99 for either after a collision.
    pub minimum: u16,
    /// Bits so far in thousandths: rolls x 2,585.
    pub millibits: u32,
}

/// A loaded snapshot's or a verified proof's header, against the shell's date.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registry {
    pub number: u64,
    pub date: RegistryDate,
    /// The snapshot's registered seals, or the proof's entries in its bucket.
    pub count: usize,
    pub freshness: Freshness,
}

impl Registry {
    fn of_snapshot(snapshot: &VerifiedSnapshot, today: RegistryDate) -> Self {
        Registry {
            number: snapshot.number(),
            date: snapshot.date(),
            count: snapshot.entry_count(),
            freshness: snapshot.freshness(today),
        }
    }

    fn of_proof(proof: &VerifiedProof, today: RegistryDate) -> Self {
        Registry {
            number: proof.number(),
            date: proof.date(),
            count: proof.entry_count(),
            freshness: proof.freshness(today),
        }
    }
}

/// How a check's go-ahead ended, when it did not ask for a retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revealed {
    /// The words are available, and the kept `Wiped` is gone. A snapshot or proof gives its header;
    /// a typed code none, since the device cannot know the checker's date.
    Clear(Option<Registry>),
    /// The evidence holds this seal: core wiped the seed unseen, and its `Wiped` is kept.
    Collision(Option<Registry>),
}

/// "Check a backup", opened: public facts only. The words stay in the slot, one page at a time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub fingerprint: [u8; 4],
    /// The backup's seal, for its Seal ID and the re-check QR.
    pub seal: SealPublic,
}

/// One insert's page: the word in print, its SeedBook number and faces 1-5, copied out of core's
/// view of the session or the checked backup, and wiped on drop. No `Debug`, `Display` or `Clone`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WordPage {
    position: u8,
    count: u8,
    device: u8,
    devices: u8,
    sequence: u8,
    seedbook: u16,
    word: String,
    faces: [PageFace; 5],
}

impl WordPage {
    fn of(insert: &Insert<'_>, count: u8) -> Self {
        WordPage {
            position: insert.position(),
            count,
            device: insert.device(),
            devices: insert.device_count(),
            sequence: insert.sequence(),
            seedbook: insert.seedbook_number(),
            word: insert.word().to_owned(),
            faces: insert.faces().map(|face| PageFace {
                letter: face.letter(),
                dots: match face.dots() {
                    Some(dots) => dots.bits(),
                    None => 0,
                },
                lighter: face.is_lighter(),
                mirror: face.mirror_partner(),
            }),
        }
    }

    /// The word's position in the phrase, 1-24.
    pub fn position(&self) -> u8 {
        self.position
    }

    /// The phrase's words: 12 or 24.
    pub fn count(&self) -> u8 {
        self.count
    }

    /// The device that holds this insert: 1, or 2 for words 13-24.
    pub fn device(&self) -> u8 {
        self.device
    }

    /// The devices the phrase needs: 1 for 12 words, 2 for 24.
    pub fn devices(&self) -> u8 {
        self.devices
    }

    /// The engraved sequence number on face 6, 1-12.
    pub fn sequence(&self) -> u8 {
        self.sequence
    }

    /// The SeedBook number: the word's 1-based place in the BIP39 English list.
    pub fn seedbook(&self) -> u16 {
        self.seedbook
    }

    /// The word in print.
    pub fn word(&self) -> &str {
        &self.word
    }

    /// Faces 1-5.
    pub fn faces(&self) -> &[PageFace; 5] {
        &self.faces
    }
}

/// One face of a page's insert: a letter's cell, or blank. Wiped with its page.
#[derive(Zeroize)]
pub struct PageFace {
    letter: Option<char>,
    dots: u8,
    lighter: bool,
    mirror: Option<char>,
}

impl PageFace {
    /// True for a blank face, left unpunched.
    pub fn is_blank(&self) -> bool {
        self.letter.is_none()
    }

    /// The letter, lowercase; `None` for a blank face.
    pub fn letter(&self) -> Option<char> {
        self.letter
    }

    /// The raised dots, dot d at bit d - 1; 0 for a blank face.
    pub fn dots(&self) -> u8 {
        self.dots
    }

    /// True for a letter on face 5, drawn lighter.
    pub fn is_lighter(&self) -> bool {
        self.lighter
    }

    /// The letter's mirror partner (e/i, d/f, h/j, r/w), for a letter to read twice.
    pub fn mirror_partner(&self) -> Option<char> {
        self.mirror
    }
}

/// What one read-back of an insert found.
pub enum Readback {
    /// Faces 1-4 as read are the word's; `complete` once every word has matched.
    Match { complete: bool },
    /// At least one face differs: core's verdicts, wiped on drop.
    Mismatch(ReadbackMismatch),
}

/// The wallet summary (`Session<Ready>`): the fingerprint and the first receive address.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Summary {
    fingerprint: [u8; 4],
    first_address: String,
}

impl Summary {
    pub fn fingerprint(&self) -> [u8; 4] {
        self.fingerprint
    }

    pub fn first_address(&self) -> &str {
        &self.first_address
    }
}

/// The backup passphrase's 2-of-4 confirm, copied: two questions of four words. Wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Challenge {
    questions: [Question; 2],
}

impl Challenge {
    /// Each question: its 1-based word position and four choices, one of them that word.
    pub fn questions(&self) -> &[Question; 2] {
        &self.questions
    }
}

/// One confirm question. Wiped with its challenge.
#[derive(Zeroize)]
pub struct Question {
    position: u8,
    choices: [String; 4],
}

impl Question {
    pub fn position(&self) -> u8 {
        self.position
    }

    pub fn choices(&self) -> &[String; 4] {
        &self.choices
    }
}

/// The kept `Wiped`'s "Report collision" QR, copied: the destroyed seed's code, harmless to share
/// since that seed is never used. Wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Report {
    url: String,
    grouped_code: String,
    seal_id: String,
}

impl Report {
    fn of(report: &CollisionReport) -> Self {
        Report {
            url: report.url().to_owned(),
            grouped_code: report.grouped_code().to_owned(),
            seal_id: report.seal_id().to_owned(),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn grouped_code(&self) -> &str {
        &self.grouped_code
    }

    pub fn seal_id(&self) -> &str {
        &self.seal_id
    }
}

impl Stage {
    fn kind(&self) -> StageKind {
        match self {
            Stage::Idle => StageKind::Idle,
            Stage::Collecting(_) => StageKind::Collecting,
            Stage::Committed(_) => StageKind::Committed,
            Stage::Rolling(_) => StageKind::Rolling,
            Stage::Sealed(_) => StageKind::Sealed,
            Stage::Checking(_) => StageKind::Checking,
            Stage::Ready(_) => StageKind::Ready,
            Stage::Busy => StageKind::Busy,
            Stage::Halted => StageKind::Halted,
        }
    }
}

impl Held {
    /// The stage, moved out; `Idle` is left behind until the caller puts the next one back.
    fn take(&mut self) -> Stage {
        mem::replace(&mut self.stage, Stage::Idle)
    }

    /// Home: no session and no checked backup. The calls that start something start here.
    fn at_home(&self) -> bool {
        matches!(self.stage, Stage::Idle) && self.backup.is_none()
    }

    /// A long call that takes nothing, offered at home only.
    fn home(&mut self) -> Result<(), Fail> {
        if self.at_home() {
            Ok(())
        } else {
            Err(Fail::Halt)
        }
    }

    /// `Halted` once halted; a call while a long call runs is the shell's bug, and halts.
    fn stopped<T>(&mut self) -> Option<Reply<T>> {
        match self.stage {
            Stage::Halted => Some(Reply::Halted),
            Stage::Busy => {
                self.halt();
                Some(Reply::Halted)
            }
            _ => None,
        }
    }

    /// A call's outcome as the shell sees it; a halt halts here.
    fn reply<T>(&mut self, made: Result<T, Fail>) -> Reply<T> {
        match made {
            Ok(made) => Reply::Done(made),
            Err(Fail::Refused(refusal)) => Reply::Refused(refusal),
            Err(Fail::Halt) => {
                self.halt();
                Reply::Halted
            }
        }
    }

    /// Halts (Q25): everything held goes, and `Halted` stays. A long call running sees it when it
    /// ends, before its generation.
    fn halt(&mut self) {
        self.stage = Stage::Halted;
        self.kept = None;
        self.snapshot = None;
        self.backup = None;
    }

    /// A new generation, so a long call running drops its result; past 2^64 discards, a halt.
    fn next_generation(&mut self) -> Result<(), Halt> {
        match self.generation.checked_add(1) {
            Some(next) => {
                self.generation = next;
                Ok(())
            }
            None => Err(Halt),
        }
    }

    /// One of the five gated exports (app/ready.rs's `export`): the session goes into core's call
    /// and comes back with what it made. An `Err` has wiped the session, and halts.
    fn export<T>(
        &mut self,
        call: impl FnOnce(Session<Ready>) -> Result<(Session<Ready>, T), CoreError>,
    ) -> Result<T, Fail> {
        let Stage::Ready(Steps {
            session,
            passphrase,
            generated,
        }) = self.take()
        else {
            return Err(Fail::Halt);
        };
        let (session, made) = call(session).map_err(|_| Halt)?;
        self.stage = Stage::Ready(Steps {
            session,
            passphrase,
            generated,
        });
        Ok(made)
    }

    /// What a check's go-ahead gave: the words, which end the kept `Wiped` (Q26); the check back,
    /// with the same nonce, and core's reason for a go-ahead that did not verify; or a collision,
    /// whose `Wiped` replaces the kept one.
    fn judge(
        &mut self,
        revealed: Result<Session<Ready>, Rejected>,
        registry: Option<Registry>,
    ) -> Result<Revealed, Fail> {
        match revealed {
            Ok(ready) => {
                self.stage = Stage::Ready(Steps::new(ready));
                self.kept = None;
                Ok(Revealed::Clear(registry))
            }
            Err(Rejected::Retry(session, error)) => {
                self.stage = Stage::Checking(session);
                Err(Fail::Refused(Refusal::Code(error)))
            }
            Err(Rejected::Collision(wiped)) => {
                self.kept = Some(Arc::new(wiped));
                Ok(Revealed::Collision(registry))
            }
        }
    }

    /// The braille views of the words on show: the ceremony's, or the checked backup's at home.
    fn inserts(&self) -> Result<BrailleInserts<'_>, Halt> {
        match (&self.stage, &self.backup) {
            (Stage::Ready(steps), _) => Ok(steps.session.braille()),
            (Stage::Idle, Some(backup)) => Ok(backup.reveal_braille()),
            _ => Err(Halt),
        }
    }
}

impl Default for Slot {
    fn default() -> Self {
        Slot::new()
    }
}

impl Slot {
    /// An empty slot: no session, nothing kept, at the first generation.
    pub const fn new() -> Self {
        Slot {
            held: Mutex::new(Held {
                stage: Stage::Idle,
                generation: 0,
                kept: None,
                snapshot: None,
                backup: None,
            }),
        }
    }

    /// The slot, locked. A poisoned lock (a panic while it was held) is matched, never unwrapped
    /// with a fallback, and halts: the slot is `Halted` from then on.
    fn lock(&self) -> MutexGuard<'_, Held> {
        match self.held.lock() {
            Ok(held) => held,
            Err(poisoned) => {
                let mut held = poisoned.into_inner();
                held.halt();
                held
            }
        }
    }

    /// A short call: under the lock throughout.
    fn call<T>(&self, call: impl FnOnce(&mut Held) -> Result<T, Fail>) -> Reply<T> {
        let mut held = self.lock();
        if let Some(stopped) = held.stopped() {
            return stopped;
        }
        let made = call(&mut held);
        held.reply(made)
    }

    /// A long call (the module comment): `take` moves what `work` needs out of the slot under the
    /// lock, the slot is `Busy` while `work` runs with the lock released, and `put` puts its result
    /// back under the lock, unless a discard or a wipe started another generation meanwhile (the
    /// result is then dropped, which wipes it, and the reply is `Discarded`) or the slot halted.
    /// `work` returns a refusal inside its result, for `put` to restore the stage first.
    fn long<T, R, O>(
        &self,
        take: impl FnOnce(&mut Held) -> Result<T, Fail>,
        work: impl FnOnce(T) -> Result<R, Halt>,
        put: impl FnOnce(&mut Held, R) -> Result<O, Fail>,
    ) -> Reply<O> {
        let (taken, generation) = {
            let mut held = self.lock();
            if let Some(stopped) = held.stopped() {
                return stopped;
            }
            let taken = match take(&mut held) {
                Ok(taken) => taken,
                Err(fail) => return held.reply(Err(fail)),
            };
            held.stage = Stage::Busy;
            (taken, held.generation)
        };
        let done = work(taken);
        let mut held = self.lock();
        let made = match done {
            Ok(made) => made,
            Err(Halt) => return held.reply(Err(Fail::Halt)),
        };
        match held.stage {
            Stage::Halted => Reply::Halted,
            Stage::Busy if held.generation == generation => {
                held.stage = Stage::Idle;
                let put_back = put(&mut held, made);
                held.reply(put_back)
            }
            _ => Reply::Discarded,
        }
    }

    /// What the slot holds, in public terms. It changes nothing and is offered while `Busy` too.
    pub fn holds(&self) -> Holds {
        let held = self.lock();
        Holds {
            stage: held.stage.kind(),
            kept: held.kept.is_some(),
            report: held
                .kept
                .as_deref()
                .and_then(Wiped::collision_report)
                .is_some(),
            snapshot: held.snapshot.is_some(),
            backup: held.backup.is_some(),
        }
    }

    /// Halts the slot: keepcrypt-guard's after a caught panic, and the dispatcher's for an op or an
    /// input it does not know.
    pub fn halt<T>(&self) -> Reply<T> {
        let mut held = self.lock();
        held.halt();
        Reply::Halted
    }

    /// Leaving the app, the idle wipe, going online or leaving a Protected screen (Q57): the stage
    /// and a checked backup go, the kept `Wiped` and a loaded snapshot stay, and a long call running
    /// drops its result.
    pub fn discard(&self) -> Reply<()> {
        let mut held = self.lock();
        if matches!(held.stage, Stage::Halted) {
            return Reply::Halted;
        }
        held.stage = Stage::Idle;
        held.backup = None;
        let next = held.next_generation().map_err(Fail::from);
        held.reply(next)
    }

    /// The crash path and the shell's teardown: everything goes, the kept `Wiped` and a loaded
    /// snapshot too, and a long call running drops its result.
    pub fn wipe_all(&self) -> Reply<()> {
        let mut held = self.lock();
        if matches!(held.stage, Stage::Halted) {
            return Reply::Halted;
        }
        held.stage = Stage::Idle;
        held.kept = None;
        held.snapshot = None;
        held.backup = None;
        let next = held.next_generation().map_err(Fail::from);
        held.reply(next)
    }

    /// A long call that moves no session, at home: the slot is `Busy` while `work` runs with the
    /// lock released, as during every long call. No op reaches it; the tests hold it at a barrier
    /// to prove the long-call rule (`ffi_discard_during_call`).
    pub fn hold<R>(&self, work: impl FnOnce() -> R) -> Reply<R> {
        self.long(Held::home, |()| Ok(work()), |_, made| Ok(made))
    }

    /// The start-up self-test (core's full known-answer suite), at home. A failure halts.
    pub fn self_test(&self) -> Reply<()> {
        self.long(
            Held::home,
            |()| self_test().map_err(|_| Halt),
            |_, ()| Ok(()),
        )
    }

    /// New seed or Dice-only seed, and every restart (`new_session`), at home. A failure halts.
    pub fn start(&self, len: SeedLength, mode: Mode) -> Reply<()> {
        self.long(
            |held| {
                held.home()?;
                Ok(held.kept.clone())
            },
            |kept| new_session(kept.as_deref(), len, mode).map_err(|_| Halt),
            |held, session| {
                held.stage = Stage::Collecting(session);
                Ok(())
            },
        )
    }

    /// Touch timestamps and motion samples into the pool, uncredited, while `Collecting` only (C
    /// fixes D at the commitment).
    pub fn add_extra(&self, source: ExtraSource, bytes: &[u8]) -> Reply<()> {
        self.call(|held| match &mut held.stage {
            Stage::Collecting(session) => {
                session.add_extra(source, bytes);
                Ok(())
            }
            _ => Err(Fail::Halt),
        })
    }

    /// The device leg's credit, while `Collecting`.
    pub fn device_progress(&self) -> Reply<DeviceProgress> {
        self.call(|held| match &held.stage {
            Stage::Collecting(session) => Ok(DeviceProgress {
                credited_bits: session.credited_bits(),
                required_bits: session.required_bits(),
            }),
            _ => Err(Fail::Halt),
        })
    }

    /// Fixes the device leg (Mixed: 64 fresh OS bytes, then D and C). A failure halts.
    pub fn commit(&self) -> Reply<()> {
        self.call(|held| {
            let Stage::Collecting(session) = held.take() else {
                return Err(Fail::Halt);
            };
            held.stage = Stage::Committed(session.commit().map_err(|_| Halt)?);
            Ok(())
        })
    }

    /// C, safe to show before any roll; `None` in dice-only mode.
    pub fn commitment(&self) -> Reply<Option<[u8; 32]>> {
        self.call(|held| match &held.stage {
            Stage::Committed(session) => Ok(session.commitment()),
            _ => Err(Fail::Halt),
        })
    }

    /// Opens dice entry.
    pub fn start_dice(&self) -> Reply<()> {
        self.call(|held| {
            let Stage::Committed(session) = held.take() else {
                return Err(Fail::Halt);
            };
            held.stage = Stage::Rolling(session.start_dice());
            Ok(())
        })
    }

    /// One roll, a face 1-6; another face or a 257th roll halts (the pad offers neither).
    pub fn push_roll(&self, face: u8) -> Reply<()> {
        self.call(|held| {
            let Stage::Rolling(session) = held.take() else {
                return Err(Fail::Halt);
            };
            held.stage = Stage::Rolling(session.push_roll(face).map_err(|_| Halt)?);
            Ok(())
        })
    }

    /// Removes the last roll, if any.
    pub fn undo_roll(&self) -> Reply<()> {
        self.call(|held| match &mut held.stage {
            Stage::Rolling(session) => {
                session.undo_roll();
                Ok(())
            }
            _ => Err(Fail::Halt),
        })
    }

    /// The dice screen's counts.
    pub fn dice_progress(&self) -> Reply<DiceProgress> {
        self.call(|held| match &held.stage {
            Stage::Rolling(session) => Ok(DiceProgress {
                rolls: session.rolls(),
                minimum: session.minimum_rolls(),
                millibits: session.millibits(),
            }),
            _ => Err(Fail::Halt),
        })
    }

    /// Makes the seed (a long call). Below the minimum, or on any failure, it halts.
    pub fn finish(&self) -> Reply<()> {
        self.long(
            |held| match held.take() {
                Stage::Rolling(session) => Ok(session),
                _ => Err(Fail::Halt),
            },
            |session| session.finish().map_err(|_| Halt),
            |held, sealed| {
                held.stage = Stage::Sealed(sealed);
                Ok(())
            },
        )
    }

    /// The seal card: T, the Seal ID and its braille, the 8x8 grid and its colour, while `Sealed`
    /// or `Checking`. All public.
    pub fn seal(&self) -> Reply<SealPublic> {
        self.call(|held| match &held.stage {
            Stage::Sealed(session) => Ok(session.seal().clone()),
            Stage::Checking(session) => Ok(session.seal().clone()),
            _ => Err(Fail::Halt),
        })
    }

    /// "Skip": the words without a check, offered only before one starts (rule 6). It ends the kept
    /// `Wiped` (Q26).
    pub fn skip_check(&self) -> Reply<()> {
        self.call(|held| {
            let Stage::Sealed(session) = held.take() else {
                return Err(Fail::Halt);
            };
            held.stage = Stage::Ready(Steps::new(session.skip_check()));
            held.kept = None;
            Ok(())
        })
    }

    /// "Check now": a fresh nonce; from here only a verified go-ahead reaches the words. A failure
    /// halts.
    pub fn start_check(&self) -> Reply<()> {
        self.call(|held| {
            let Stage::Sealed(session) = held.take() else {
                return Err(Fail::Halt);
            };
            held.stage = Stage::Checking(session.start_check().map_err(|_| Halt)?);
            Ok(())
        })
    }

    /// The seal card's check QR text, `<origin>/check#t=<T>&n=<n>`: public.
    pub fn check_request(&self) -> Reply<String> {
        self.call(|held| match &held.stage {
            Stage::Checking(session) => Ok(session.check_request().url().to_owned()),
            _ => Err(Fail::Halt),
        })
    }

    /// The typed go-ahead code. One that does not verify is refused, and the check stays, with
    /// its nonce.
    pub fn reveal_code(&self, code: &str) -> Reply<Revealed> {
        self.call(|held| {
            let Stage::Checking(session) = held.take() else {
                return Err(Fail::Halt);
            };
            held.judge(session.reveal(GoAhead::Code(code)), None)
        })
    }

    /// The check against the loaded snapshot, which runs on its own (docs/mobile-apps.md,
    /// swb:121). Without one, it halts.
    pub fn reveal_snapshot(&self, today: u32) -> Reply<Revealed> {
        self.call(|held| {
            let today = registry_date(today)?;
            let Stage::Checking(session) = held.take() else {
                return Err(Fail::Halt);
            };
            let Some(snapshot) = &held.snapshot else {
                return Err(Fail::Halt);
            };
            let registry = Registry::of_snapshot(snapshot, today);
            match session.reveal(GoAhead::Snapshot(snapshot)) {
                // A snapshot holds the seal or it does not: core never asks it for a retry.
                Err(Rejected::Retry(..)) => Err(Fail::Halt),
                revealed => held.judge(revealed, Some(registry)),
            }
        })
    }

    /// A scanned go-ahead QR's text: the proof is verified (a long call), then judged under the
    /// lock. A proof that does not read, or one for another bucket, is refused, and the check stays.
    pub fn reveal_proof(&self, text: &str, today: u32) -> Reply<Revealed> {
        self.long(
            |held| {
                let today = registry_date(today)?;
                let Stage::Checking(session) = held.take() else {
                    return Err(Fail::Halt);
                };
                Ok((session, today))
            },
            |(session, today)| match verify_bucket_proof_qr(text) {
                Ok(proof) => Ok((session, today, Ok(proof))),
                Err(error) => Ok((session, today, Err(refused(error)?))),
            },
            |held, (session, today, verified)| match verified {
                Ok(proof) => {
                    let registry = Registry::of_proof(&proof, today);
                    held.judge(session.reveal(GoAhead::BucketProof(&proof)), Some(registry))
                }
                Err(refusal) => {
                    held.stage = Stage::Checking(session);
                    Err(Fail::Refused(refusal))
                }
            },
        )
    }

    /// "Match found": the seed is wiped unseen, and the `Wiped` (the report, the 99-roll minimum)
    /// replaces the kept one. Only a start follows.
    pub fn match_found(&self) -> Reply<()> {
        self.stop_check(Discard::Collision)
    }

    /// "Cannot check": as Match found, keeping this session's own 99-roll minimum and no report.
    pub fn cannot_check(&self) -> Reply<()> {
        self.stop_check(Discard::CannotCheck)
    }

    fn stop_check(&self, why: Discard) -> Reply<()> {
        self.call(|held| {
            let Stage::Checking(session) = held.take() else {
                return Err(Fail::Halt);
            };
            held.kept = Some(Arc::new(session.discard(why)));
            Ok(())
        })
    }

    /// The collision-report QR of the kept `Wiped`, after a collision, before the restart.
    pub fn collision_report(&self) -> Reply<Report> {
        self.call(|held| {
            let report = held.kept.as_deref().and_then(Wiped::collision_report);
            match (&held.stage, report) {
                (Stage::Idle, Some(report)) => Ok(Report::of(report)),
                _ => Err(Fail::Halt),
            }
        })
    }

    /// Insert `position`'s page (1-based): the ceremony's words while `Ready`, a checked backup's at
    /// home. A position outside the words halts (the shell pages within them).
    pub fn word_page(&self, position: u8) -> Reply<WordPage> {
        self.call(|held| {
            let inserts = held.inserts()?;
            let count = u8::try_from(inserts.count()).map_err(|_| Halt)?;
            let insert = inserts.insert(position).map_err(|_| Halt)?;
            Ok(WordPage::of(&insert, count))
        })
    }

    /// The first three or four letters read back from insert `position`. The pad offers Done for
    /// three or four letters only, so core's two errors (a position outside the seed, a malformed
    /// entry) are the shell's bugs, and halt (app/ready.rs's `read_back`).
    pub fn check_readback(&self, position: u8, letters: &str) -> Reply<Readback> {
        self.call(|held| {
            let Stage::Ready(steps) = &mut held.stage else {
                return Err(Fail::Halt);
            };
            let result = steps
                .session
                .check_readback(position, letters)
                .map_err(|_| Halt)?;
            Ok(match result {
                ReadbackResult::Match => Readback::Match {
                    complete: steps.session.readback_complete(),
                },
                ReadbackResult::Mismatch(mismatch) => Readback::Mismatch(mismatch),
            })
        })
    }

    /// The wallet summary: the fingerprint and the first receive address.
    pub fn summary(&self) -> Reply<Summary> {
        self.call(|held| match &held.stage {
            Stage::Ready(steps) => Ok(Summary {
                fingerprint: steps.session.fingerprint(),
                first_address: steps.session.first_address().to_owned(),
            }),
            _ => Err(Fail::Halt),
        })
    }

    /// Generates the 8-word backup passphrase once (Q33 (d)) and keeps its display copy until the
    /// confirm passes. Before every word has read back, or a second time, it halts.
    pub fn generate_backup_passphrase(&self) -> Reply<()> {
        self.call(|held| {
            let Stage::Ready(Steps {
                session,
                passphrase: None,
                generated: false,
            }) = held.take()
            else {
                return Err(Fail::Halt);
            };
            let (session, new) = session.generate_backup_passphrase().map_err(|_| Halt)?;
            held.stage = Stage::Ready(Steps {
                session,
                passphrase: Some(new),
                generated: true,
            });
            Ok(())
        })
    }

    /// Page `page` (0 or 1) of the passphrase's display copy: four words, one space apart.
    pub fn backup_passphrase_page(&self, page: u8) -> Reply<Zeroizing<String>> {
        self.call(|held| {
            let Stage::Ready(Steps {
                passphrase: Some(new),
                ..
            }) = &held.stage
            else {
                return Err(Fail::Halt);
            };
            let first = match page {
                0 => 0,
                1 => PASSPHRASE_PAGE_WORDS,
                _ => return Err(Fail::Halt),
            };
            // Sized once, so it never reallocates and leaves a copy behind.
            let mut text = Zeroizing::new(String::with_capacity(
                PASSPHRASE_PAGE_WORDS * (LONGEST_WORD + 1),
            ));
            for word in new.words().skip(first).take(PASSPHRASE_PAGE_WORDS) {
                if !text.is_empty() {
                    text.push(' ');
                }
                text.push_str(word);
            }
            Ok(text)
        })
    }

    /// The passphrase's confirm questions, copied.
    pub fn backup_challenge(&self) -> Reply<Challenge> {
        self.call(|held| {
            let Stage::Ready(Steps {
                passphrase: Some(new),
                ..
            }) = &held.stage
            else {
                return Err(Fail::Halt);
            };
            Ok(Challenge {
                questions: new
                    .challenge()
                    .questions()
                    .map(|(position, choices)| Question {
                        position,
                        choices: choices.map(str::to_owned),
                    }),
            })
        })
    }

    /// The confirm's two picks (each 0-3, in the order the questions list their choices): true
    /// when both are right, which drops the display copy (app/ready.rs's `confirm`); false shows the
    /// words again, with the same questions.
    pub fn confirm_backup(&self, picks: [u8; 2]) -> Reply<bool> {
        self.call(|held| {
            let Stage::Ready(steps) = &mut held.stage else {
                return Err(Fail::Halt);
            };
            let Some(new) = &steps.passphrase else {
                return Err(Fail::Halt);
            };
            let mut right = true;
            for ((position, choices), pick) in new.challenge().questions().into_iter().zip(picks) {
                let Some(&picked) = choices.get(usize::from(pick)) else {
                    return Err(Fail::Halt);
                };
                let index = usize::from(position).checked_sub(1).ok_or(Halt)?;
                right &= new.words().nth(index) == Some(picked);
            }
            if right {
                steps.passphrase = None;
            }
            Ok(right)
        })
    }

    /// The encrypted backup (a long call: scrypt at log2 N = 18), once the passphrase is generated
    /// and its confirm passed. The file is ciphertext, for the shell to save.
    pub fn encrypt_backup(&self) -> Reply<BackupFile> {
        self.long(
            |held| match held.take() {
                Stage::Ready(
                    steps @ Steps {
                        passphrase: None,
                        generated: true,
                        ..
                    },
                ) => Ok(steps),
                _ => Err(Fail::Halt),
            },
            |steps| {
                let Steps {
                    session,
                    passphrase,
                    generated,
                } = steps;
                let (session, file) = session.encrypt_backup(&CREATED_BY).map_err(|_| Halt)?;
                Ok((
                    Steps {
                        session,
                        passphrase,
                        generated,
                    },
                    file,
                ))
            },
            |held, (steps, file)| {
                held.stage = Stage::Ready(steps);
                Ok(file)
            },
        )
    }

    /// The saved backup read back (a long call): it must open under the stored passphrase and hold
    /// this seed. A file that does not is refused, and the words stay.
    pub fn verify_backup(&self, file: &[u8]) -> Reply<()> {
        self.long(
            |held| match held.take() {
                Stage::Ready(steps) => Ok(steps),
                _ => Err(Fail::Halt),
            },
            |steps| match steps.session.verify_backup(file) {
                Ok(()) => Ok((steps, None)),
                Err(error) => Ok((steps, Some(refused(error)?))),
            },
            |held, (steps, refusal)| {
                held.stage = Stage::Ready(steps);
                match refusal {
                    None => Ok(()),
                    Some(refusal) => Err(Fail::Refused(refusal)),
                }
            },
        )
    }

    /// The watch-only export, of this seed or, with a BIP39 passphrase, of that wallet. An empty
    /// passphrase is refused.
    pub fn watch_only(&self, bip39_passphrase: Option<&str>) -> Reply<WatchOnlyExport> {
        self.call(|held| {
            if !matches!(held.stage, Stage::Ready(_)) {
                return Err(Fail::Halt);
            }
            let typed = match bip39_passphrase {
                Some(text) => match Bip39Passphrase::new(text) {
                    Ok(typed) => Some(typed),
                    Err(error) => return Err(Fail::Refused(refused(error)?)),
                },
                None => None,
            };
            held.export(|session| session.watch_only(typed.as_ref()))
        })
    }

    /// The "Register seal" QR.
    pub fn registration(&self) -> Reply<SealRegistration> {
        self.call(|held| held.export(Session::registration))
    }

    /// D, for verify.py on an offline computer, copied; in dice-only mode, which offers no D, it
    /// halts.
    pub fn reveal_device_leg(&self) -> Reply<Zeroizing<[u8; 32]>> {
        self.call(|held| {
            let Some(d) = held.export(Session::reveal_device_leg)? else {
                return Err(Fail::Halt);
            };
            let mut copy = Zeroizing::new([0u8; 32]);
            copy.copy_from_slice(d.expose_secret());
            Ok(copy)
        })
    }

    /// Finish, after the checklist: the ceremony's words go. At home after "Check a backup", Done:
    /// the backup's words go.
    pub fn end(&self) -> Reply<()> {
        self.call(|held| {
            if matches!(held.stage, Stage::Ready(_)) {
                held.stage = Stage::Idle;
                Ok(())
            } else if matches!(held.stage, Stage::Idle) && held.backup.is_some() {
                held.backup = None;
                Ok(())
            } else {
                Err(Fail::Halt)
            }
        })
    }

    /// Load registry snapshot, at home (a long call). A file that does not verify, or a build with
    /// no registry key, is refused; one that does replaces any loaded before.
    pub fn load_snapshot(&self, file: &[u8], today: u32) -> Reply<Registry> {
        self.long(
            |held| {
                held.home()?;
                Ok(registry_date(today)?)
            },
            |today| match verify_snapshot(file) {
                Ok(snapshot) => Ok((today, Ok(snapshot))),
                Err(error) => Ok((today, Err(refused(error)?))),
            },
            |held, (today, verified)| {
                let snapshot = verified.map_err(Fail::Refused)?;
                let registry = Registry::of_snapshot(&snapshot, today);
                held.snapshot = Some(snapshot);
                Ok(registry)
            },
        )
    }

    /// Check a backup, at home: the eight entries (each a word's first four letters, or the whole
    /// word when it has three), then the file opened (a long call: scrypt). An entry that names no
    /// word is refused before any scrypt work; so are a wrong passphrase and a file that does not
    /// read, after it.
    pub fn open_backup(&self, file: &[u8], entries: &[&str]) -> Reply<Opened> {
        self.long(
            |held| {
                held.home()?;
                match TypedBackupPassphrase::from_first_four(entries) {
                    Ok(typed) => Ok(typed),
                    Err(error) => Err(Fail::Refused(refused(error)?)),
                }
            },
            |typed| match decrypt_backup(file, &typed) {
                Ok(backup) => {
                    let seal = backup.seal().map_err(|_| Halt)?;
                    Ok(Ok((backup, seal)))
                }
                Err(error) => Ok(Err(refused(error)?)),
            },
            |held, opened| {
                let (backup, seal) = opened.map_err(Fail::Refused)?;
                let fingerprint = backup.fingerprint();
                held.backup = Some(backup);
                Ok(Opened { fingerprint, seal })
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use keepcrypt_core::{
        BackupError, BrailleError, HealthFailure, HealthStage, HealthTest, InternalFault, KatId,
        SnapshotError, SourceFault, UrError,
    };

    use super::*;

    /// pi/app's app.rs, whose `refused` this layer's mirrors (todo.md, M5 group 8).
    const APP_RS: &str = include_str!("../../pi/app/src/app.rs");

    /// Each `CoreError` variant's name: the exhaustive match makes a new variant a compile error
    /// here until the table test below sorts it.
    fn name(error: CoreError) -> &'static str {
        match error {
            CoreError::Kat(_) => "Kat",
            CoreError::Source(_) => "Source",
            CoreError::Health(_) => "Health",
            CoreError::QuotaUnmet => "QuotaUnmet",
            CoreError::NotInThisMode => "NotInThisMode",
            CoreError::InvalidRoll => "InvalidRoll",
            CoreError::TooManyRolls => "TooManyRolls",
            CoreError::TooFewRolls => "TooFewRolls",
            CoreError::EmptyPassphrase => "EmptyPassphrase",
            CoreError::ReadbackIncomplete => "ReadbackIncomplete",
            CoreError::NoBackupPassphrase => "NoBackupPassphrase",
            CoreError::WrongPassphrase => "WrongPassphrase",
            CoreError::ReadbackMismatch => "ReadbackMismatch",
            CoreError::ExportSelfCheck => "ExportSelfCheck",
            CoreError::NoRegistryKey => "NoRegistryKey",
            CoreError::Snapshot(_) => "Snapshot",
            CoreError::Backup(_) => "Backup",
            CoreError::Braille(_) => "Braille",
            CoreError::Internal(_) => "Internal",
        }
    }

    /// Every `CoreError` value core's generated lists reach, nested variants included (a snapshot
    /// error's unit variants are named here: its `Ur` payload gives it no list of its own).
    fn every_error() -> Vec<CoreError> {
        let mut every = vec![
            CoreError::QuotaUnmet,
            CoreError::NotInThisMode,
            CoreError::InvalidRoll,
            CoreError::TooManyRolls,
            CoreError::TooFewRolls,
            CoreError::EmptyPassphrase,
            CoreError::ReadbackIncomplete,
            CoreError::NoBackupPassphrase,
            CoreError::WrongPassphrase,
            CoreError::ReadbackMismatch,
            CoreError::ExportSelfCheck,
            CoreError::NoRegistryKey,
        ];
        every.extend(KatId::ALL.map(CoreError::Kat));
        every.extend(SourceFault::ALL.map(CoreError::Source));
        for test in HealthTest::ALL {
            for stage in HealthStage::ALL {
                every.push(CoreError::Health(HealthFailure {
                    test,
                    stage,
                    sample: 5,
                }));
            }
        }
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
            .map(CoreError::Snapshot),
        );
        every.extend(UrError::ALL.map(SnapshotError::Ur).map(CoreError::Snapshot));
        every.extend(BackupError::ALL.map(CoreError::Backup));
        every.extend(BrailleError::ALL.map(CoreError::Braille));
        every.extend(InternalFault::ALL.map(CoreError::Internal));
        every
    }

    /// The variant names in one arm of app.rs's `refused`: the arm that ends with `ending`.
    fn app_arm(ending: &str) -> Vec<&'static str> {
        let (_, body) = APP_RS
            .split_once("fn refused(error: CoreError) -> Result<Refusal, Stop> {")
            .expect("app.rs's refused");
        let (body, _) = body.split_once("\n}\n").expect("its end");
        let (_, after) = body.split_once("match error {").expect("its match");
        let arms: Vec<&str> = after.split("=>").collect();
        assert_eq!(arms.len(), 3, "app.rs's refused has two arms");
        let arm = match ending {
            "refused" => arms[0],
            _ => arms[1],
        };
        assert!(
            arms[1].trim_start().starts_with("Ok(Refusal::Core(error))")
                && arms[2].trim_start().starts_with("Err(Stop::Core(error))"),
            "app.rs's refused has its two arms"
        );
        arm.split("CoreError::")
            .skip(1)
            .map(|variant| {
                variant
                    .split(|c: char| !c.is_ascii_alphanumeric())
                    .next()
                    .expect("a name")
            })
            .collect()
    }

    // Q25's table (todo.md, M5 group 8): every CoreError value is a refusal here exactly when
    // app.rs's refused makes it one, and both sort every variant. A refusal keeps core's error.
    #[test]
    fn the_core_error_table_is_app_rs_refused() {
        let refusals = app_arm("refused");
        let halts = app_arm("halts");
        let mut seen = std::collections::BTreeSet::new();
        for error in every_error() {
            let variant = name(error);
            seen.insert(variant);
            match refused(error) {
                Ok(refusal) => {
                    assert!(refusals.contains(&variant), "{variant} halts in app.rs");
                    assert_eq!(refusal, Refusal::Core(error));
                }
                Err(Halt) => assert!(halts.contains(&variant), "{variant} is refused in app.rs"),
            }
        }
        let mut app: Vec<&str> = refusals.iter().chain(&halts).copied().collect();
        app.sort_unstable();
        assert_eq!(
            app,
            seen.into_iter().collect::<Vec<_>>(),
            "both sort every variant once"
        );
    }

    // One place starts a session, on a phone (todo.md, M5 group 8): fresh, and from a kept Wiped.
    #[test]
    fn every_session_is_on_a_phone() {
        let fresh = new_session(None, SeedLength::Words12, Mode::Mixed).expect("a session");
        assert_eq!(fresh.platform(), Platform::Phone);
        assert_eq!((fresh.credited_bits(), fresh.required_bits()), (256, 256));
        let mut rolling = fresh.commit().expect("committed").start_dice();
        for face in (1..=6u8).cycle().take(50) {
            rolling = rolling.push_roll(face).expect("a face");
        }
        let wiped = rolling
            .finish()
            .and_then(Session::start_check)
            .expect("checking")
            .discard(Discard::Collision);
        let restart =
            new_session(Some(&wiped), SeedLength::Words24, Mode::DiceOnly).expect("a restart");
        assert_eq!(restart.platform(), Platform::Phone);
        assert_eq!(restart.seed_length(), SeedLength::Words24);
    }

    // A halt latches: every later call, a discard and a wipe included, returns Halted. (A poisoned
    // lock takes this same halt in `lock`; only a panic under the lock poisons it, which the guard's
    // tests plant, M5 commit 12.)
    #[test]
    fn a_halt_latches() {
        let slot = Slot::new();
        assert!(matches!(slot.halt::<()>(), Reply::Halted));
        assert_eq!(slot.holds().stage, StageKind::Halted);
        assert!(matches!(slot.discard(), Reply::Halted));
        assert!(matches!(slot.wipe_all(), Reply::Halted));
        assert!(matches!(
            slot.start(SeedLength::Words12, Mode::DiceOnly),
            Reply::Halted
        ));
        assert_eq!(slot.holds().stage, StageKind::Halted);
    }
}
