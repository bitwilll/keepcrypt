//! The app (tasks/todo.md, M3 groups 8 and 9; docs/pi-firmware.md "User flow", "Protected screens
//! and idle", "Finish and halts"): one owner of the session and of every secret, driven one event
//! at a time.
//!
//! - `App` owns the HAL, the painter, the private `Stage` (the only `Session` and every secret
//!   the shell holds), the kept `Wiped` (Q26), the plan (length and mode), a loaded snapshot, the
//!   idle timer and the current screen. `start` boots (step 1), `step` takes one event from
//!   `hal::Buttons` and handles it, and `run` does both for M4's main.
//! - Each transition moves the session out of the stage (`mem::replace`), so only the
//!   typestate's own methods move it on, and an `Err` from a call that takes the session has
//!   already wiped it.
//! - Screens only build models (`screens`). `redraw` draws the current one and keeps the keys it
//!   offered; a key the shown model does not offer changes nothing and draws nothing, so the
//!   footer is the whole truth about a screen's keys. Every action core would refuse by wiping is
//!   offered only when a gate function in `screens` or `grid` says yes.
//! - Fail closed (rule 3; Q25): every core error, and every display, button or hwrng fault,
//!   halts. `halt` wipes the stage, drops the kept `Wiped`, presents a black frame, then the red
//!   stop screen with the failure's fixed text, which no key leaves; only a power cycle does.
//!   Only refusals of what the user or a stick supplied return to their own screen, with their
//!   fixed text (`Refusal`): a go-ahead code that does not verify, a read-back mismatch, a wrong
//!   backup passphrase or unrecognised entry, an empty BIP39 passphrase, a refused snapshot and
//!   USB faults.
//! - Idle (Q29): after 30 s without input (a key, or a USB stick put in) a Protected screen is
//!   covered, and the next press only uncovers it; at 9 minutes a warning appears while secrets
//!   are held; at 10 minutes the stage is wiped (the kept `Wiped` and the snapshot stay) and the
//!   device says so.
//! - Entering a Protected screen from a Public one passes the privacy gate (`enter_page`).
//! - New sessions come from the kept `Wiped` while there is one, else from core's constructor,
//!   whose one call in this crate is in `new_session` (Q26, Q33 (c); the banned-API gate's Shell
//!   category holds it there).
//! - Key presses in Mixed `Collecting` reach the pool as uncredited extras (`extras`), Snake open
//!   or not.
//! - Snake (`games`) opens from step 4's "Play while you wait", moves one cell per hwrng block and
//!   closes once the quota is met. It lives in the current screen's note, so leaving game-snake
//!   ends it; its bytes come from `games::GAME_BYTES`, which the app holds and hands to the game
//!   but cannot draw from.
//! - Steps 8-15 are in `ready`, Home's side flows and the backup's USB write in `usb`.

mod ready;
mod usb;

use core::fmt;
use core::mem;

use keepcrypt_core::{
    CheckError, CheckedBackup, Checking, Collecting, Committed, CoreError, Discard, GoAhead,
    HW_BYTES_NEEDED, Mode, NewBackupPassphrase, Platform, ReadbackMismatch, Ready, RegistryDate,
    Rejected, Rolling, SealPublic, SealRegistration, Sealed, SecretBytes32, SeedLength, Session,
    VerifiedSnapshot, WatchOnlyExport, Wiped, hwrng_boot_test, registry_key_is_test, self_test,
};
use zeroize::{Zeroize, Zeroizing};

use crate::extras::{StageKind, extra_for};
use crate::games::{GAME_BYTES, GameBytes, Snake};
use crate::grid::{CODE_LEN, Grid, MAX_PASSPHRASE};
use crate::hal::{BuildInfo, FileKind, FileName, Hal, HalError};
use crate::input::{Event, Idle, IdleStep, Key};
use crate::screen::{Banners, KeyMap, ScreenId};
use crate::screens::{self, Choice};
use crate::ui::{Painter, PresentError, RenderError};

/// The boot test reads 16 blocks of 64 samples: core's `hwrng_boot_test` takes exactly 1,024.
const BOOT_BLOCKS: usize = 16;
/// Step 4 reads one hwrng block per tick. 100 ms in the simulator; M4 sets the device's from the
/// measured hwrng rate.
const BLOCK_TICK_NS: u64 = 100_000_000;
/// usb-insert looks for a stick once per tick of this length: the device notices it by itself.
const STICK_POLL_NS: u64 = 100_000_000;

/// The session in its typestate, and every secret the shell holds with it: the only place a
/// `Session` lives. No `Debug` or `Clone`.
pub enum Stage {
    /// No session: before the first one, after a check discarded one, after the idle wipe and
    /// after Finish.
    Idle,
    Collecting(Session<Collecting>),
    Committed(Session<Committed>),
    Rolling(Session<Rolling>),
    Sealed(Session<Sealed>),
    /// A check is open, with the go-ahead code as typed so far.
    Checking {
        session: Session<Checking>,
        code: Zeroizing<String>,
    },
    /// Steps 8-15: the words, the read-back and the exports, with what each step holds.
    Ready {
        session: Session<Ready>,
        steps: Steps,
    },
    /// "Check a backup" before the passphrase opens it: the file read from the stick, and the
    /// passphrase entries typed so far.
    BackupCheck {
        file: Zeroizing<Vec<u8>>,
        typed: Zeroizing<String>,
    },
    /// "Check a backup", opened: the backup's words, and their seal for the re-check.
    Checked {
        backup: CheckedBackup,
        seal: Box<SealPublic>,
    },
    /// After a halt: nothing is held, and nothing starts again until a power cycle.
    Halted,
}

impl Stage {
    pub fn kind(&self) -> StageKind {
        match self {
            Stage::Idle => StageKind::Idle,
            Stage::Collecting(_) => StageKind::Collecting,
            Stage::Committed(_) => StageKind::Committed,
            Stage::Rolling(_) => StageKind::Rolling,
            Stage::Sealed(_) => StageKind::Sealed,
            Stage::Checking { .. } => StageKind::Checking,
            Stage::Ready { .. } => StageKind::Ready,
            Stage::BackupCheck { .. } => StageKind::BackupCheck,
            Stage::Checked { .. } => StageKind::Checked,
            Stage::Halted => StageKind::Halted,
        }
    }
}

/// What steps 8-15 hold beside the session. No `Debug` or `Clone`.
pub struct Steps {
    /// The insert being read back, from 1 (step 9).
    pub position: u8,
    /// An entry grid's text: the read-back faces (step 9) or the BIP39 passphrase (step 12),
    /// sized once for the longest, so typing never reallocates and leaves a copy behind.
    pub typed: Zeroizing<String>,
    /// The secret the current screen shows besides the session.
    pub holding: Holding,
    /// The backup passphrase was generated: it is generated at most once (Q33 (d)), since a new
    /// one would void the paper copy.
    pub passphrase_generated: bool,
}

impl Steps {
    fn new() -> Self {
        Steps {
            position: 1,
            typed: Zeroizing::new(String::with_capacity(MAX_PASSPHRASE)),
            holding: Holding::Nothing,
            passphrase_generated: false,
        }
    }
}

/// The secret a screen of steps 9-14 shows besides the session. Each is replaced, and so wiped,
/// when its screens are left. No `Debug` or `Clone`.
pub enum Holding {
    Nothing,
    /// readback-mismatch: what the failed read-back found.
    Mismatch(ReadbackMismatch),
    /// backup-passphrase and backup-confirm: the display copy, until the confirm passes.
    Passphrase(NewBackupPassphrase),
    /// The watch-only summary and its QRs.
    Export(Box<WatchOnlyExport>),
    /// register-qr.
    Registration(SealRegistration),
    /// reveal-d.
    DeviceLeg(SecretBytes32),
}

/// The seed length and mode chosen at Home and Length, kept for the restarts (Q33 (c)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    pub len: SeedLength,
    pub mode: Mode,
}

/// Everything the screens read: what the build is, and what the app holds.
pub struct Held {
    pub build: BuildInfo,
    pub banners: Banners,
    pub stage: Stage,
    /// The `Wiped` of the last discarded session, kept until a check passes or the user skips,
    /// and dropped by a halt (Q26).
    pub kept: Option<Wiped>,
    pub plan: Plan,
    /// A registry snapshot loaded from a stick: it outlives sessions and the idle wipe, until
    /// power-off.
    pub snapshot: Option<VerifiedSnapshot>,
}

/// What covers the current screen without leaving it (Q29).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overlay {
    /// The cover after 30 s on a Protected screen.
    Cover,
    /// The warning a minute before the idle wipe.
    Warning,
}

/// What a USB stick is for, while usb-insert waits for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Step 11: write the encrypted backup.
    Write,
    /// Home: open a file of this kind, a registry snapshot or a backup to check.
    Open(FileKind),
}

/// A refusal of what the user or a stick supplied (Q25): it returns to its own screen, which
/// names it in fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A go-ahead code that does not verify.
    Code(CheckError),
    /// A wrong backup passphrase or unrecognised entry, an empty BIP39 passphrase, a refused
    /// snapshot or a backup that does not read back: core's text.
    Core(CoreError),
    /// A USB fault: the HAL's text.
    Usb(HalError),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Code(error) => write!(f, "{error}"),
            Refusal::Core(error) => write!(f, "{error}"),
            Refusal::Usb(fault) => f.write_str(fault.text()),
        }
    }
}

/// Sorts an error from a core call that took no session by Q25: a refusal of what the user or a
/// stick supplied, or a halt. Calls that take the session never come here: their every `Err`
/// has wiped it, and halts.
fn refused(error: CoreError) -> Result<Refusal, Stop> {
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
        | CoreError::Internal(_) => Err(Stop::Core(error)),
    }
}

/// A fault from `hal::Usb`: a USB fault returns to its screen, and any other kind halts.
fn usb_fault(fault: HalError) -> Result<HalError, Stop> {
    if fault.halts() {
        Err(Stop::Hal(fault))
    } else {
        Ok(fault)
    }
}

/// What a screen says that its id alone does not. Holds no secret.
pub enum Note {
    None,
    /// The privacy gate, in front of page `page` of `to`; after Skip it carries swb's note.
    Gate {
        to: ScreenId,
        page: usize,
        skipped: bool,
    },
    /// check-clear: the Seal ID, and the loaded snapshot's date, or `None` for a typed code.
    Clear {
        seal_id: String,
        as_of: Option<RegistryDate>,
    },
    /// A refusal, on the screen it returned to.
    Refused(Refusal),
    /// readback-entry: the insert read back as a match, and the whole word shows.
    Matched,
    /// words-insert: the insert of a read-back mismatch, shown from it; Press returns to entry.
    Reviewing,
    /// device-swap: the page of words 13-24 it leads to, in insert view or in the overview.
    Swap {
        to: ScreenId,
        page: usize,
    },
    /// usb-insert: what the stick is for.
    Usb(Flow),
    /// usb-pick: the files of `kind` on the stick, or the fault that kept them from being read.
    Pick {
        kind: FileKind,
        names: Vec<FileName>,
        problem: Option<HalError>,
    },
    /// backup-failed: why, and the fault that left the file on the stick when it could not be
    /// removed.
    BackupFailed {
        reason: Refusal,
        left: Option<HalError>,
    },
    /// halt: why.
    Halt(Stop),
    /// game-snake: the round being played. It ends with the screen.
    Game(Box<Snake>),
}

/// The current screen: its id, the menu, picker or grid cursor, its page (or insert), its note
/// and any overlay. It holds no secret but where an entry grid's cursor rests, which the Protected
/// grid shows: after a press, on the symbol just typed. A refused entry emptied on its own screen
/// puts the cursor back on the first symbol (backup-check-entry).
pub struct View {
    pub id: ScreenId,
    pub cursor: usize,
    pub page: usize,
    pub note: Note,
    pub overlay: Option<Overlay>,
}

impl View {
    fn new(id: ScreenId, note: Note) -> Self {
        View::paged(id, 0, note)
    }

    fn paged(id: ScreenId, page: usize, note: Note) -> Self {
        View {
            id,
            cursor: 0,
            page,
            note,
            overlay: None,
        }
    }

    /// The id on the panel: the overlay's, or the screen's own.
    pub fn shown(&self) -> ScreenId {
        match self.overlay {
            Some(Overlay::Cover) => ScreenId::Cover,
            Some(Overlay::Warning) => ScreenId::IdleWarning,
            None => self.id,
        }
    }
}

/// Why the app halts (Q25). Every value has fixed text and holds no secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// A core call failed: core's text.
    Core(CoreError),
    /// A display, button or hwrng fault.
    Hal(HalError),
    /// A model could not be drawn: a bug.
    Render(RenderError),
    /// The app's own state disagreed with itself: a bug.
    Shell(&'static str),
}

impl From<PresentError> for Stop {
    fn from(error: PresentError) -> Self {
        match error {
            PresentError::Render(error) => Stop::Render(error),
            PresentError::Display(error) => Stop::Hal(error),
        }
    }
}

impl fmt::Display for Stop {
    /// The fixed text the stop screen shows.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Stop::Core(error) => write!(f, "{error}"),
            Stop::Hal(error) => f.write_str(error.text()),
            Stop::Render(error) => f.write_str(error.text()),
            Stop::Shell(text) => write!(f, "internal failure: {text}"),
        }
    }
}

/// A screen reached in a stage it never belongs to.
pub const OUT_OF_ORDER: Stop = Stop::Shell("a screen was reached out of order");

/// The one place a session starts (Q26, Q33 (c)): from the kept `Wiped` while there is one, so
/// a pending 99-roll minimum carries over, else a fresh session on the Pi. Either runs the full
/// known-answer suite first; an `Err` means no seed can be made.
fn new_session(
    kept: Option<&Wiped>,
    len: SeedLength,
    mode: Mode,
) -> Result<Session<Collecting>, CoreError> {
    match kept {
        Some(wiped) => wiped.restart(len, mode),
        None => Session::new(len, mode, Platform::Pi),
    }
}

/// The Pi app on the hardware `H`.
pub struct App<H: Hal> {
    hal: H,
    painter: Painter,
    held: Held,
    view: View,
    /// The keys the model on the panel offered: every other key does nothing.
    keys: KeyMap,
    idle: Idle,
    /// When step 4 reads its next hwrng block.
    next_block_ns: u64,
    /// Where Snake's bytes come from: core's game call (`games::GAME_BYTES`), handed to the game
    /// and never called here.
    game_bytes: GameBytes,
    /// Keys handed to the pool, counted where `key` hands them over: the unit tests' view of the
    /// app's one `add_extra` call.
    #[cfg(test)]
    extras: usize,
}

impl<H: Hal> App<H> {
    /// The app on `hal`, before boot.
    pub fn new(hal: H) -> Self {
        let build = hal.build_info();
        let banners = Banners {
            test_registry: registry_key_is_test(),
            simulator: build.simulator,
        };
        let idle = Idle::new(hal.now_ns());
        App {
            hal,
            painter: Painter::new(),
            held: Held {
                build,
                banners,
                stage: Stage::Idle,
                kept: None,
                plan: Plan {
                    len: SeedLength::Words12,
                    mode: Mode::Mixed,
                },
                snapshot: None,
            },
            view: View::new(ScreenId::Boot, Note::None),
            keys: KeyMap::NONE,
            idle,
            next_block_ns: 0,
            game_bytes: GAME_BYTES,
            #[cfg(test)]
            extras: 0,
        }
    }

    /// Replaces Snake's byte source, so that a unit test can make it fail.
    #[cfg(test)]
    fn set_game_bytes(&mut self, bytes: GameBytes) {
        self.game_bytes = bytes;
    }

    /// Step 1: the boot screen, the known-answer tests and the hwrng startup test, then Home. Any
    /// failure halts.
    pub fn start(&mut self) {
        if let Err(stop) = self.boot() {
            self.halt(stop);
        }
    }

    /// Takes one event (a key, or a tick at the next deadline) and handles it. Any failure halts.
    pub fn step(&mut self) {
        let handled = match self.hal.next_event(self.deadline()) {
            Ok(Event::Key { key, at_ns }) => self.key(key, at_ns),
            Ok(Event::Tick { now_ns }) => self.tick(now_ns),
            Err(fault) => Err(Stop::Hal(fault)),
        };
        if let Err(stop) = handled {
            self.halt(stop);
        }
    }

    /// Boots, then handles one event after another while the device is powered (M4's main). A
    /// halt is terminal: no key leaves it, and only a power cycle starts again.
    pub fn run(&mut self) -> ! {
        self.start();
        loop {
            self.step();
        }
    }

    /// True while the stage holds a session or a backup being checked: the idle warning and wipe
    /// apply.
    pub fn holds_secrets(&self) -> bool {
        !matches!(self.held.stage, Stage::Idle | Stage::Halted)
    }

    /// True while the app keeps a discarded session's `Wiped` (Q26).
    pub fn keeps_wiped(&self) -> bool {
        self.held.kept.is_some()
    }

    /// The hardware, for the simulator's scenarios.
    pub fn hal(&self) -> &H {
        &self.hal
    }

    /// The hardware, for the simulator's scenarios.
    pub fn hal_mut(&mut self) -> &mut H {
        &mut self.hal
    }

    fn boot(&mut self) -> Result<(), Stop> {
        self.painter
            .present(&mut self.hal, &screens::boot(&self.held))?;
        self_test().map_err(Stop::Core)?;
        let mut samples = Zeroizing::new([0u8; BOOT_BLOCKS * 64]);
        let (blocks, _) = samples.as_chunks_mut::<64>();
        for block in blocks {
            self.hal.read_block(block).map_err(Stop::Hal)?;
        }
        hwrng_boot_test(&samples[..]).map_err(Stop::Core)?;
        self.idle = Idle::new(self.hal.now_ns());
        self.enter(ScreenId::Home, Note::None);
        self.redraw()
    }

    /// The deadline for the next event: step 4's next block, usb-insert's next look for a stick,
    /// or the idle timer's next threshold.
    fn deadline(&self) -> u64 {
        let now_ns = self.hal.now_ns();
        let block = self.block_wanted().then_some(self.next_block_ns);
        let stick =
            (self.view.id == ScreenId::UsbInsert).then(|| now_ns.saturating_add(STICK_POLL_NS));
        let idle = self
            .idle
            .next_ns(now_ns, self.view.id.class(), self.holds_secrets());
        block
            .into_iter()
            .chain(stick)
            .chain(idle)
            .fold(u64::MAX, u64::min)
    }

    /// True while step 4 still needs hwrng samples.
    fn block_wanted(&self) -> bool {
        match &self.held.stage {
            Stage::Collecting(session) => {
                session.mode() == Mode::Mixed && session.hw_bytes_tested() < HW_BYTES_NEEDED
            }
            _ => false,
        }
    }

    fn key(&mut self, key: Key, at_ns: u64) -> Result<(), Stop> {
        self.idle.key(at_ns);
        let event = Event::Key { key, at_ns };
        if let (Some((source, bytes)), Stage::Collecting(session)) = (
            extra_for(self.held.stage.kind(), self.held.plan.mode, event),
            &mut self.held.stage,
        ) {
            session.add_extra(source, &bytes);
            #[cfg(test)]
            {
                self.extras += 1;
            }
        }
        if self.keys.label(key).is_none() {
            return Ok(());
        }
        if self.view.overlay.take().is_some() {
            // The cover and the warning only go away: the key is not passed on.
            return self.redraw();
        }
        self.act(key)
    }

    fn tick(&mut self, now_ns: u64) -> Result<(), Stop> {
        if self.block_wanted() && now_ns >= self.next_block_ns {
            self.next_block_ns = now_ns.saturating_add(BLOCK_TICK_NS);
            self.read_block()?;
            self.play()?;
            self.redraw()?;
        }
        if self.view.id == ScreenId::UsbInsert {
            self.look_for_stick()?;
        }
        let step = self
            .idle
            .step(now_ns, self.view.id.class(), self.holds_secrets());
        match (step, self.view.overlay) {
            (Some(IdleStep::Wipe), _) => self.idle_wipe(),
            (Some(IdleStep::Warn), None | Some(Overlay::Cover)) => {
                self.view.overlay = Some(Overlay::Warning);
                self.redraw()
            }
            (Some(IdleStep::Cover), None) => {
                self.view.overlay = Some(Overlay::Cover);
                self.redraw()
            }
            (Some(IdleStep::Warn), Some(Overlay::Warning))
            | (Some(IdleStep::Cover), Some(_))
            | (None, _) => Ok(()),
        }
    }

    /// One hwrng block into the session's health tests and pool.
    fn read_block(&mut self) -> Result<(), Stop> {
        let Stage::Collecting(session) = self.take() else {
            return Err(OUT_OF_ORDER);
        };
        let mut block = Zeroizing::new([0u8; 64]);
        self.hal.read_block(&mut block).map_err(Stop::Hal)?;
        let session = session.add_hw_samples(&block[..]).map_err(Stop::Core)?;
        self.held.stage = Stage::Collecting(session);
        Ok(())
    }

    /// Snake, while it is open: one cell for the block just read, unless that block met the quota,
    /// which closes the game, so step 4 offers Continue (docs/pi-firmware.md: the games close
    /// before the commitment screen).
    fn play(&mut self) -> Result<(), Stop> {
        let Note::Game(snake) = &mut self.view.note else {
            return Ok(());
        };
        let met = match &self.held.stage {
            Stage::Collecting(session) => {
                screens::continue_offered(session.credited_bits(), session.required_bits())
            }
            _ => return Err(OUT_OF_ORDER),
        };
        if met {
            self.enter(ScreenId::Hwrng, Note::None);
            return Ok(());
        }
        snake.step(self.game_bytes).map_err(Stop::Core)
    }

    /// The stage, moved out; `Idle` is left behind until the caller puts the next one back.
    fn take(&mut self) -> Stage {
        mem::replace(&mut self.held.stage, Stage::Idle)
    }

    /// Makes `to` the current screen.
    fn enter(&mut self, to: ScreenId, note: Note) {
        self.enter_page(to, 0, note);
    }

    /// Makes page `page` of `to` the current screen, through the privacy gate when it is
    /// Protected and the current screen is Public. A gated screen takes no note.
    fn enter_page(&mut self, to: ScreenId, page: usize, note: Note) {
        self.view = if screens::needs_gate(self.view.id, to) {
            View::new(
                ScreenId::PrivacyGate,
                Note::Gate {
                    to,
                    page,
                    skipped: false,
                },
            )
        } else {
            View::paged(to, page, note)
        };
    }

    /// Draws the current screen and keeps the keys its model offers.
    fn redraw(&mut self) -> Result<(), Stop> {
        let screen = screens::model(&self.held, &self.view)?;
        let keys = screen.keys();
        let shown = self.painter.present(&mut self.hal, &screen);
        drop(screen);
        shown?;
        self.keys = keys;
        Ok(())
    }

    /// Presents the wait screen while a blocking call runs (Q33 (k)), saying what it does.
    fn wait(&mut self, why: &'static str) -> Result<(), Stop> {
        self.painter
            .present(&mut self.hal, &screens::wait(&self.held, why))?;
        Ok(())
    }

    /// Replaces the whole stage with `to` (`Idle` or `Halted`), dropping every secret it held,
    /// and presents a black frame (the frame and the QR buffers are wiped after every present).
    fn wipe(&mut self, to: Stage) -> Result<(), Stop> {
        self.held.stage = to;
        self.view.overlay = None;
        self.painter.present(&mut self.hal, &screens::blank())?;
        Ok(())
    }

    /// The idle wipe (Q29): the stage goes, the kept `Wiped` and the snapshot stay, and the device
    /// says so before Home.
    fn idle_wipe(&mut self) -> Result<(), Stop> {
        self.wipe(Stage::Idle)?;
        self.enter(ScreenId::IdleWiped, Note::None);
        self.redraw()
    }

    /// Halts (Q25): the stage and the kept `Wiped` go, a black frame, then the stop screen. The
    /// first failure stays on it: once halted, nothing changes.
    fn halt(&mut self, stop: Stop) {
        if matches!(self.held.stage, Stage::Halted) {
            return;
        }
        self.held.kept = None;
        let blanked = self.wipe(Stage::Halted);
        self.view = View::new(ScreenId::Halt, Note::Halt(stop));
        // Only the panel can stop the stop screen (its model is text alone): it then keeps what
        // it last took. Nothing is held any more and no key leaves the halt, so nothing is left
        // to do.
        let shown = blanked.and_then(|()| self.redraw());
        debug_assert!(
            matches!(shown, Ok(()) | Err(Stop::Hal(HalError::Display))),
            "the stop screen draws"
        );
    }

    /// Starts a ceremony with the plan behind the wait screen (the known-answer suite runs first),
    /// then step 4.
    fn begin(&mut self) -> Result<(), Stop> {
        self.wait(screens::WAIT_SESSION)?;
        let Plan { len, mode } = self.held.plan;
        let session = new_session(self.held.kept.as_ref(), len, mode).map_err(Stop::Core)?;
        self.held.stage = Stage::Collecting(session);
        self.next_block_ns = self.hal.now_ns().saturating_add(BLOCK_TICK_NS);
        let first = match mode {
            Mode::Mixed => ScreenId::Hwrng,
            Mode::DiceOnly => ScreenId::DiceOnlyNotice,
        };
        self.enter(first, Note::None);
        self.redraw()
    }

    /// A key the shown model offers, on the current screen.
    fn act(&mut self, key: Key) -> Result<(), Stop> {
        let id = self.view.id;
        if let Some(grid) = Grid::of(id) {
            return self.typing(grid, key);
        }
        let choices = screens::choices(id, &self.held);
        match (id, key) {
            (ScreenId::Dice, _) => return self.dice(key),
            (ScreenId::GameSnake, _) => return self.game(key),
            (ScreenId::WordsInsert | ScreenId::WordsOverview, _) => return self.words(key),
            (ScreenId::BackupConfirm, _) => return self.confirm(key),
            (ScreenId::UsbPick, _) => return self.pick(key),
            (_, Key::Up | Key::Down) if !choices.is_empty() => {
                let n = choices.len();
                self.view.cursor = match key {
                    Key::Up => (self.view.cursor + n - 1) % n,
                    _ => (self.view.cursor + 1) % n,
                };
            }
            (_, Key::Press) if !choices.is_empty() => {
                let Some(&choice) = choices.get(self.view.cursor) else {
                    return Err(OUT_OF_ORDER);
                };
                return self.choose(choice);
            }
            (ScreenId::Length | ScreenId::About, Key::Key1)
            | (
                ScreenId::About
                | ScreenId::IdleWiped
                | ScreenId::SnapshotLoaded
                | ScreenId::SnapshotFailed,
                Key::Press,
            ) => {
                self.enter(ScreenId::Home, Note::None);
            }
            (ScreenId::SkipConfirm, Key::Key1) => self.enter(ScreenId::CheckPrompt, Note::None),
            (ScreenId::CheckActions, Key::Key1) => self.enter(ScreenId::SealQr, Note::None),
            (ScreenId::StopConfirm | ScreenId::CannotCheckConfirm, Key::Key1) => {
                self.enter(ScreenId::CheckActions, Note::None);
            }
            (ScreenId::SealImage | ScreenId::SealId | ScreenId::SealQr, Key::Press) => {
                self.enter(ScreenId::CheckActions, Note::None);
            }
            (ScreenId::SealId, Key::Key2) => self.enter(ScreenId::SealImage, Note::None),
            (ScreenId::SealQr, Key::Key2) | (ScreenId::SealImage, Key::Key3) => {
                self.enter(ScreenId::SealId, Note::None);
            }
            (ScreenId::SealId, Key::Key3) => self.enter(ScreenId::SealQr, Note::None),
            (ScreenId::DiceOnlyNotice, Key::Press) => {
                let Stage::Collecting(session) = self.take() else {
                    return Err(OUT_OF_ORDER);
                };
                let session = session.commit().map_err(Stop::Core)?.start_dice();
                self.held.stage = Stage::Rolling(session);
                self.enter(ScreenId::Dice, Note::None);
            }
            (ScreenId::Commitment, Key::Press) => {
                let Stage::Committed(session) = self.take() else {
                    return Err(OUT_OF_ORDER);
                };
                self.held.stage = Stage::Rolling(session.start_dice());
                self.enter(ScreenId::Dice, Note::None);
            }
            (ScreenId::CodeWrong, Key::Press) => self.enter(ScreenId::CodeEntry, Note::None),
            (ScreenId::CheckClear, Key::Press) => self.enter(ScreenId::WordsInsert, Note::None),
            (ScreenId::Collision, Key::Press) => self.enter(ScreenId::CollisionQr, Note::None),
            (ScreenId::PrivacyGate, Key::Press) => {
                let Note::Gate { to, page, .. } = self.view.note else {
                    return Err(OUT_OF_ORDER);
                };
                self.enter_page(to, page, Note::None);
            }
            // "Add fresh entropy": a new ceremony from the kept `Wiped`, with the destroyed
            // session's length and mode.
            (ScreenId::CollisionQr, Key::Press) => return self.begin(),
            (ScreenId::UsbInsert, Key::Key1) => {
                let back = match self.view.note {
                    Note::Usb(Flow::Write) => ScreenId::BackupOffer,
                    Note::Usb(Flow::Open(_)) => ScreenId::Home,
                    _ => return Err(OUT_OF_ORDER),
                };
                self.enter(back, Note::None);
            }
            (ScreenId::BackupCheckRecheckQr, Key::Press | Key::Key1) => {
                self.enter(ScreenId::BackupCheckResult, Note::None);
            }
            _ => return self.ready_key(key),
        }
        self.redraw()
    }

    /// A menu choice.
    fn choose(&mut self, choice: Choice) -> Result<(), Stop> {
        match choice {
            Choice::NewSeed | Choice::DiceOnlySeed => {
                self.held.plan.mode = match choice {
                    Choice::NewSeed => Mode::Mixed,
                    _ => Mode::DiceOnly,
                };
                self.enter(ScreenId::Length, Note::None);
            }
            Choice::CheckBackup => {
                self.enter(ScreenId::UsbInsert, Note::Usb(Flow::Open(FileKind::Age)));
            }
            Choice::LoadSnapshot => {
                self.enter(ScreenId::UsbInsert, Note::Usb(Flow::Open(FileKind::Kcr)));
            }
            Choice::About => self.enter(ScreenId::About, Note::None),
            Choice::Words12 | Choice::Words24 => {
                self.held.plan.len = match choice {
                    Choice::Words12 => SeedLength::Words12,
                    _ => SeedLength::Words24,
                };
                return self.begin();
            }
            Choice::Play => {
                let snake = Snake::new(self.game_bytes).map_err(Stop::Core)?;
                self.enter(ScreenId::GameSnake, Note::Game(Box::new(snake)));
            }
            Choice::Continue => {
                let Stage::Collecting(session) = self.take() else {
                    return Err(OUT_OF_ORDER);
                };
                self.held.stage = Stage::Committed(session.commit().map_err(Stop::Core)?);
                self.enter(ScreenId::Commitment, Note::None);
            }
            Choice::CheckNow => {
                let Stage::Sealed(session) = self.take() else {
                    return Err(OUT_OF_ORDER);
                };
                let session = session.start_check().map_err(Stop::Core)?;
                self.held.stage = Stage::Checking {
                    session,
                    code: Zeroizing::new(String::with_capacity(CODE_LEN)),
                };
                let next = screens::after_check_now(self.held.snapshot.is_some());
                self.enter(next, Note::None);
            }
            Choice::Skip => self.enter(ScreenId::SkipConfirm, Note::None),
            Choice::SkipCheck => {
                let Stage::Sealed(session) = self.take() else {
                    return Err(OUT_OF_ORDER);
                };
                self.held.stage = Stage::Ready {
                    session: session.skip_check(),
                    steps: Steps::new(),
                };
                self.held.kept = None;
                self.view = View::new(
                    ScreenId::PrivacyGate,
                    Note::Gate {
                        to: ScreenId::WordsInsert,
                        page: 0,
                        skipped: true,
                    },
                );
            }
            Choice::UseSnapshot => return self.reveal_by_snapshot(),
            Choice::NotSnapshot => self.enter(ScreenId::SealImage, Note::None),
            Choice::EnterCode => self.enter(ScreenId::CodeEntry, Note::None),
            Choice::MatchFound => self.enter(ScreenId::StopConfirm, Note::None),
            Choice::CannotCheck => self.enter(ScreenId::CannotCheckConfirm, Note::None),
            Choice::Destroy => {
                let Stage::Checking { session, .. } = self.take() else {
                    return Err(OUT_OF_ORDER);
                };
                self.held.kept = Some(session.discard(Discard::Collision));
                self.enter(ScreenId::Collision, Note::None);
            }
            Choice::StartAgain => {
                let Stage::Checking { session, .. } = self.take() else {
                    return Err(OUT_OF_ORDER);
                };
                self.held.kept = Some(session.discard(Discard::CannotCheck));
                return self.begin();
            }
            Choice::BackUp
            | Choice::SkipBackup
            | Choice::Retry
            | Choice::SkipFailedBackup
            | Choice::ShowWatchOnly
            | Choice::SkipWatchOnly
            | Choice::NoPassphrase
            | Choice::WithPassphrase
            | Choice::ShowRegistration
            | Choice::SkipRegistration
            | Choice::ShowD
            | Choice::SkipD => return self.ready_choice(choice),
            Choice::Recheck => self.enter(ScreenId::BackupCheckRecheckQr, Note::None),
            Choice::ShowWords => self.enter(ScreenId::WordsInsert, Note::None),
            Choice::CloseBackup => {
                // "Done" drops the checked backup, which wipes it.
                let Stage::Checked { .. } = self.take() else {
                    return Err(OUT_OF_ORDER);
                };
                self.enter(ScreenId::Home, Note::None);
            }
        }
        self.redraw()
    }

    /// Yes on snapshot-date (Q33 (a)): the only `reveal` with the loaded snapshot, so its date is
    /// confirmed before every snapshot reveal.
    fn reveal_by_snapshot(&mut self) -> Result<(), Stop> {
        let Stage::Checking { session, .. } = self.take() else {
            return Err(OUT_OF_ORDER);
        };
        let Some(snapshot) = &self.held.snapshot else {
            return Err(OUT_OF_ORDER);
        };
        let clear = Note::Clear {
            seal_id: session.seal().seal_id().to_owned(),
            as_of: Some(snapshot.date()),
        };
        match session.reveal(GoAhead::Snapshot(snapshot)) {
            Ok(ready) => self.reveal_passed(ready, clear),
            Err(Rejected::Collision(wiped)) => self.collided(wiped),
            // A snapshot either holds the seal or it does not (core never asks for a retry here).
            Err(Rejected::Retry(..)) => Err(Stop::Shell("a snapshot check asked for a retry")),
        }
    }

    /// The words are now available: a check passed, which ends the kept `Wiped` (Q26).
    fn reveal_passed(&mut self, ready: Session<Ready>, clear: Note) -> Result<(), Stop> {
        self.held.stage = Stage::Ready {
            session: ready,
            steps: Steps::new(),
        };
        self.held.kept = None;
        self.enter(ScreenId::CheckClear, clear);
        self.redraw()
    }

    /// The evidence held this seal: core wiped it unseen, and its `Wiped` replaces the kept one.
    fn collided(&mut self, wiped: Wiped) -> Result<(), Stop> {
        self.held.kept = Some(wiped);
        self.enter(ScreenId::Collision, Note::None);
        self.redraw()
    }

    /// The dice: pick, confirm, undo, Done. Up and Down move the picker from blank to 1-6; a
    /// confirm leaves it blank again.
    fn dice(&mut self, key: Key) -> Result<(), Stop> {
        match key {
            Key::Up => {
                self.view.cursor = match self.view.cursor {
                    6 => 1,
                    face => face + 1,
                };
            }
            Key::Down => {
                self.view.cursor = match self.view.cursor {
                    0 | 1 => 6,
                    face => face - 1,
                };
            }
            Key::Press => {
                let Stage::Rolling(session) = self.take() else {
                    return Err(OUT_OF_ORDER);
                };
                let face = u8::try_from(self.view.cursor).map_err(|_| OUT_OF_ORDER)?;
                self.held.stage = Stage::Rolling(session.push_roll(face).map_err(Stop::Core)?);
                self.view.cursor = 0;
            }
            Key::Key1 => match &mut self.held.stage {
                Stage::Rolling(session) => session.undo_roll(),
                _ => return Err(OUT_OF_ORDER),
            },
            Key::Key3 => {
                let Stage::Rolling(session) = self.take() else {
                    return Err(OUT_OF_ORDER);
                };
                self.held.stage = Stage::Sealed(session.finish().map_err(Stop::Core)?);
                self.enter(ScreenId::CheckPrompt, Note::None);
            }
            Key::Left | Key::Right | Key::Key2 => return Err(OUT_OF_ORDER),
        }
        self.redraw()
    }

    /// Snake: the joystick steers; after a round ends, Press plays again; KEY1 leaves for step 4.
    /// The model offers Press only after a round ends, and the joystick only before.
    fn game(&mut self, key: Key) -> Result<(), Stop> {
        let Note::Game(snake) = &mut self.view.note else {
            return Err(OUT_OF_ORDER);
        };
        match key {
            Key::Up | Key::Down | Key::Left | Key::Right => snake.steer(key),
            Key::Press => **snake = Snake::new(self.game_bytes).map_err(Stop::Core)?,
            Key::Key1 => self.enter(ScreenId::Hwrng, Note::None),
            Key::Key2 | Key::Key3 => return Err(OUT_OF_ORDER),
        }
        self.redraw()
    }

    /// An entry grid (Q32 (a)): move, type, delete, done, and back on the code and
    /// backup-passphrase grids. The model offers a symbol only when its grid accepts it next, and
    /// done only for a complete entry.
    fn typing(&mut self, grid: Grid, key: Key) -> Result<(), Stop> {
        if let Some(cursor) = grid.moved(self.view.cursor, key) {
            self.view.cursor = cursor;
            return self.redraw();
        }
        match key {
            Key::Press => {
                let Some(symbol) = grid.symbol(self.view.cursor) else {
                    return Err(OUT_OF_ORDER);
                };
                self.typed()?.push(char::from(symbol));
            }
            Key::Key1 => {
                self.typed()?.pop();
            }
            Key::Key2 => {
                return match self.view.id {
                    ScreenId::CodeEntry => self.code_back(),
                    ScreenId::BackupCheckEntry => self.entry_back(),
                    _ => Err(OUT_OF_ORDER),
                };
            }
            Key::Key3 => {
                return match self.view.id {
                    ScreenId::CodeEntry => self.reveal_by_code(),
                    ScreenId::ReadbackEntry => self.read_back(),
                    ScreenId::Bip39Entry => self.passphrase_typed(),
                    ScreenId::BackupCheckEntry => self.entry_typed(),
                    _ => Err(OUT_OF_ORDER),
                };
            }
            Key::Up | Key::Down | Key::Left | Key::Right => {
                return Err(OUT_OF_ORDER);
            }
        }
        self.redraw()
    }

    /// The buffer the current entry grid types into, in the stage.
    fn typed(&mut self) -> Result<&mut Zeroizing<String>, Stop> {
        match (self.view.id, &mut self.held.stage) {
            (ScreenId::CodeEntry, Stage::Checking { code, .. }) => Ok(code),
            (ScreenId::ReadbackEntry | ScreenId::Bip39Entry, Stage::Ready { steps, .. }) => {
                Ok(&mut steps.typed)
            }
            (ScreenId::BackupCheckEntry, Stage::BackupCheck { typed, .. }) => Ok(typed),
            _ => Err(OUT_OF_ORDER),
        }
    }

    /// KEY2 on the code grid (the owner's decision of 2026-10-13): back to the seal card's actions,
    /// the typed code wiped in place. The stage stays `Checking` with the same session, so the same
    /// nonce, and no core call is made: Match found and Cannot check are offered again, and the
    /// check stays open (rule 6). Not a refusal or a halt (Q25).
    fn code_back(&mut self) -> Result<(), Stop> {
        self.typed()?.zeroize();
        self.enter(ScreenId::CheckActions, Note::None);
        self.redraw()
    }

    /// Done on the code grid: a code that does not verify returns to its screen with the same
    /// nonce (`Rejected::Retry`); a verified one reveals the words.
    fn reveal_by_code(&mut self) -> Result<(), Stop> {
        let Stage::Checking { session, code } = self.take() else {
            return Err(OUT_OF_ORDER);
        };
        let clear = Note::Clear {
            seal_id: session.seal().seal_id().to_owned(),
            as_of: None,
        };
        match session.reveal(GoAhead::Code(&code)) {
            Ok(ready) => self.reveal_passed(ready, clear),
            Err(Rejected::Retry(session, error)) => {
                self.held.stage = Stage::Checking {
                    session,
                    code: Zeroizing::new(String::with_capacity(CODE_LEN)),
                };
                self.enter(ScreenId::CodeWrong, Note::Refused(Refusal::Code(error)));
                self.redraw()
            }
            Err(Rejected::Collision(wiped)) => self.collided(wiped),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use keepcrypt_core::{BackupFile, SourceFault};

    use super::*;
    use crate::hal::{Buttons, Clock, Display, FileKind, FileName, HwRng, Usb, Written};
    use crate::screen::{Class, Screen};
    use crate::ui::Frame;

    /// One present as the fake display keeps it.
    struct Shown {
        id: ScreenId,
        title: String,
        keys: KeyMap,
        texts: Vec<String>,
        frame: Vec<u16>,
    }

    /// The least hardware the app runs on: scripted keys and ticks, a clock that moves 1 ms per
    /// key and to the app's deadline on a tick, the counting hwrng stream and no stick. The
    /// display checks the two invariants the simulator checks (a Protected element only on a
    /// Protected id, and the model fits) and keeps each present. Only public test text is ever
    /// drawn here.
    struct Fake {
        keys: VecDeque<Key>,
        /// The next event is a tick at the app's deadline, not a key.
        tick: bool,
        now_ns: u64,
        served: usize,
        hwrng_fault: bool,
        shown: Vec<Shown>,
    }

    impl Fake {
        fn new() -> Self {
            Fake {
                keys: VecDeque::new(),
                tick: false,
                now_ns: 0,
                served: 0,
                hwrng_fault: false,
                shown: Vec::new(),
            }
        }

        fn last(&self) -> &Shown {
            self.shown.last().expect("a present")
        }
    }

    impl Display for Fake {
        fn present(&mut self, frame: &Frame, screen: &Screen<'_>) -> Result<(), HalError> {
            let id = screen.id();
            assert!(!screen.has_protected() || id.class() == Class::Protected);
            assert!(screen.fits(), "{}", id.name());
            self.shown.push(Shown {
                id,
                title: screen.title().to_owned(),
                keys: screen.keys(),
                texts: screen
                    .elements()
                    .iter()
                    .filter_map(|element| match element.item() {
                        crate::screen::Item::Text(text)
                        | crate::screen::Item::Small(text)
                        | crate::screen::Item::Large { text, .. }
                        | crate::screen::Item::Qr(text) => Some(text.as_str().to_owned()),
                        _ => None,
                    })
                    .collect(),
                frame: frame.raw().to_vec(),
            });
            Ok(())
        }
    }

    impl Buttons for Fake {
        fn next_event(&mut self, deadline_ns: u64) -> Result<Event, HalError> {
            if mem::take(&mut self.tick) {
                self.now_ns = self.now_ns.max(deadline_ns);
                return Ok(Event::Tick {
                    now_ns: self.now_ns,
                });
            }
            let key = self.keys.pop_front().expect("a scripted key");
            self.now_ns += 1_000_000;
            Ok(Event::Key {
                key,
                at_ns: self.now_ns,
            })
        }
    }

    impl Clock for Fake {
        fn now_ns(&self) -> u64 {
            self.now_ns
        }
    }

    impl HwRng for Fake {
        fn read_block(&mut self, block: &mut [u8; 64]) -> Result<(), HalError> {
            if self.hwrng_fault {
                return Err(HalError::HwRng);
            }
            for (offset, byte) in block.iter_mut().enumerate() {
                *byte = (self.served + offset).to_le_bytes()[0];
            }
            self.served += 64;
            Ok(())
        }
    }

    impl Usb for Fake {
        fn stick(&mut self) -> Result<bool, HalError> {
            Ok(false)
        }
        fn list(&mut self, _kind: FileKind) -> Result<Vec<FileName>, HalError> {
            Err(HalError::NoStick)
        }
        fn read(&mut self, _name: &FileName, _max: usize) -> Result<Zeroizing<Vec<u8>>, HalError> {
            Err(HalError::NoStick)
        }
        fn write_backup(&mut self, _file: &BackupFile) -> Result<Written, HalError> {
            Err(HalError::NoStick)
        }
        fn read_written(
            &mut self,
            _written: &Written,
            _max: usize,
        ) -> Result<Zeroizing<Vec<u8>>, HalError> {
            Err(HalError::NoStick)
        }
        fn remove_written(&mut self, _written: Written) -> Result<(), HalError> {
            Err(HalError::NoStick)
        }
    }

    impl Hal for Fake {
        fn build_info(&self) -> BuildInfo {
            BuildInfo {
                version: "0.0.0",
                rootfs: String::from("test"),
                simulator: false,
            }
        }
    }

    /// A booted app on the fake hardware.
    fn booted() -> App<Fake> {
        let mut app = App::new(Fake::new());
        app.start();
        assert_eq!(app.view.id, ScreenId::Home);
        app
    }

    /// Plays `keys`, one step each.
    fn play(app: &mut App<Fake>, keys: &[Key]) {
        for &key in keys {
            app.hal.keys.push_back(key);
            app.step();
        }
    }

    /// A dice-only 12-word session through `finish` on "123456" repeated to its minimum.
    fn sealed(kept: Option<&Wiped>) -> Session<Sealed> {
        let session = new_session(kept, SeedLength::Words12, Mode::DiceOnly).expect("a session");
        let mut rolling = session.commit().expect("committed").start_dice();
        let minimum = rolling.minimum_rolls();
        for face in (1..=6u8).cycle().take(usize::from(minimum)) {
            rolling = rolling.push_roll(face).expect("a face");
        }
        rolling.finish().expect("sealed")
    }

    /// The URL of the open check.
    fn check_url(app: &App<Fake>) -> String {
        match &app.held.stage {
            Stage::Checking { session, .. } => session.check_request().url().to_owned(),
            _ => panic!("a check is open"),
        }
    }

    #[test]
    fn new_sessions_are_the_pis() {
        let session = new_session(None, SeedLength::Words12, Mode::Mixed).expect("a session");
        assert_eq!(session.platform(), Platform::Pi);
        assert_eq!(session.required_bits(), 512);
        assert_eq!(session.seed_length(), SeedLength::Words12);
        assert_eq!(session.mode(), Mode::Mixed);
    }

    #[test]
    fn a_kept_collision_wiped_restarts_at_99_until_skip_drops_it() {
        let wiped = sealed(None)
            .start_check()
            .expect("checking")
            .discard(Discard::Collision);
        let restart = new_session(Some(&wiped), SeedLength::Words12, Mode::DiceOnly)
            .expect("a restart")
            .commit()
            .expect("committed")
            .start_dice();
        assert_eq!(restart.minimum_rolls(), 99);
        drop(restart);

        // That restart reaches Ready through Skip: the app drops the kept `Wiped`.
        let mut app = booted();
        app.held.stage = Stage::Sealed(sealed(Some(&wiped)));
        app.held.kept = Some(wiped);
        app.enter(ScreenId::SkipConfirm, Note::None);
        app.redraw().expect("drawn");
        play(&mut app, &[Key::Press]);
        assert!(matches!(app.held.stage, Stage::Ready { .. }));
        assert!(!app.keeps_wiped());
        assert_eq!(app.view.id, ScreenId::PrivacyGate);
        let next = new_session(app.held.kept.as_ref(), SeedLength::Words12, Mode::DiceOnly)
            .expect("a session")
            .commit()
            .expect("committed")
            .start_dice();
        assert_eq!(next.minimum_rolls(), 50);
    }

    #[test]
    fn a_code_that_does_not_verify_keeps_the_check_and_its_url() {
        let mut app = booted();
        app.held.stage = Stage::Sealed(sealed(None));
        app.enter(ScreenId::CheckPrompt, Note::None);
        app.redraw().expect("drawn");
        // Check now, then the actions page, then the grid.
        play(&mut app, &[Key::Press, Key::Press, Key::Press]);
        assert_eq!(app.view.id, ScreenId::CodeEntry);
        let before = check_url(&app);
        // Eight zeros: well formed, and (at odds of 2^-40) not this check's code.
        play(&mut app, &[Key::Press; 8]);
        assert_eq!(app.hal.last().keys.label(Key::Key3), Some("done"));
        play(&mut app, &[Key::Key3]);
        assert_eq!(app.view.id, ScreenId::CodeWrong);
        assert!(matches!(
            app.view.note,
            Note::Refused(Refusal::Code(CheckError::WrongCode))
        ));
        assert_eq!(check_url(&app), before);
        play(&mut app, &[Key::Press]);
        assert_eq!(app.view.id, ScreenId::CodeEntry);
        assert_eq!(check_url(&app), before);
        assert!(app.holds_secrets());
    }

    /// The code typed so far on the open check.
    fn typed_code(app: &App<Fake>) -> String {
        match &app.held.stage {
            Stage::Checking { code, .. } => code.as_str().to_owned(),
            _ => panic!("a check is open"),
        }
    }

    #[test]
    fn back_on_the_code_grid_keeps_the_check_and_its_url_and_wipes_the_code() {
        let mut app = booted();
        app.held.stage = Stage::Sealed(sealed(None));
        app.enter(ScreenId::CheckPrompt, Note::None);
        app.redraw().expect("drawn");
        // Check now, then the actions page, then the grid, before any scan: three symbols typed.
        play(&mut app, &[Key::Press, Key::Press, Key::Press]);
        assert_eq!(app.view.id, ScreenId::CodeEntry);
        let before = check_url(&app);
        play(&mut app, &[Key::Press; 3]);
        assert_eq!(typed_code(&app), "000");
        assert_eq!(app.hal.last().keys.label(Key::Key2), Some("back"));
        // KEY2: the actions page, the same check, nothing typed.
        play(&mut app, &[Key::Key2]);
        assert_eq!(app.hal.last().id, ScreenId::CheckActions);
        assert_eq!(typed_code(&app), "");
        assert_eq!(check_url(&app), before);
        // Enter go-ahead code: an empty entry.
        play(&mut app, &[Key::Press]);
        assert_eq!(app.view.id, ScreenId::CodeEntry);
        assert!(app.hal.last().texts.contains(&String::from("____-____")));
        // A wrong code, code-wrong, Press, one symbol typed: KEY2 does the same.
        play(&mut app, &[Key::Press; 8]);
        play(&mut app, &[Key::Key3]);
        assert_eq!(app.view.id, ScreenId::CodeWrong);
        play(&mut app, &[Key::Press, Key::Press, Key::Key2]);
        assert_eq!(app.hal.last().id, ScreenId::CheckActions);
        assert_eq!(typed_code(&app), "");
        assert_eq!(check_url(&app), before);
        assert!(app.holds_secrets());
    }

    #[test]
    fn back_on_the_backup_passphrase_grid_drops_the_backup_and_shows_home() {
        let mut app = booted();
        let mut typed = Zeroizing::new(String::with_capacity(crate::grid::ENTRIES_LEN));
        typed.push_str("aban ab");
        app.held.stage = Stage::BackupCheck {
            file: Zeroizing::new(vec![b'-'; 64]),
            typed,
        };
        drawn(&mut app, View::new(ScreenId::BackupCheckEntry, Note::None));
        assert_eq!(app.hal.last().keys.label(Key::Key2), Some("back"));
        play(&mut app, &[Key::Key2]);
        assert_eq!(app.hal.last().id, ScreenId::Home);
        assert!(matches!(app.held.stage, Stage::Idle));
        assert!(!app.holds_secrets());
    }

    #[test]
    fn the_dice_picker_is_blank_after_each_confirm() {
        let mut app = booted();
        let session = new_session(None, SeedLength::Words12, Mode::DiceOnly)
            .expect("a session")
            .commit()
            .expect("committed")
            .start_dice();
        app.held.stage = Stage::Rolling(session);
        app.enter(ScreenId::Dice, Note::None);
        app.redraw().expect("drawn");
        // Up from blank is 1 and wraps from 6 to 1; Down from blank or 1 is 6.
        play(&mut app, &[Key::Down]);
        assert_eq!(app.view.cursor, 6);
        play(&mut app, &[Key::Down, Key::Down, Key::Up]);
        assert_eq!(app.view.cursor, 5);
        play(&mut app, &[Key::Up, Key::Up]);
        assert_eq!(app.view.cursor, 1);
        play(&mut app, &[Key::Down]);
        assert_eq!(app.view.cursor, 6);
        play(&mut app, &[Key::Up, Key::Up, Key::Up]);
        assert!(app.hal.last().texts.contains(&String::from("3")));
        play(&mut app, &[Key::Press]);
        let confirmed = app.hal.last();
        assert!(!confirmed.texts.contains(&String::from("3")));
        assert!(
            confirmed
                .texts
                .contains(&String::from("1 / 50 rolls, 2.5 bits"))
        );
        // The frame after the confirm is the blank picker's for one roll, drawn afresh.
        let fresh = View::new(ScreenId::Dice, Note::None);
        let screen = screens::model(&app.held, &fresh).expect("a model");
        let mut display = Fake::new();
        Painter::new()
            .present(&mut display, &screen)
            .expect("drawn");
        assert!(display.last().frame == confirmed.frame);
    }

    #[test]
    fn a_dead_key_changes_nothing_and_draws_nothing() {
        let mut app = booted();
        // Home offers Up, Down and Press.
        let presents = app.hal.shown.len();
        play(
            &mut app,
            &[Key::Left, Key::Right, Key::Key1, Key::Key2, Key::Key3],
        );
        assert_eq!(app.hal.shown.len(), presents);
        assert_eq!(app.view.id, ScreenId::Home);
        play(&mut app, &[Key::Down]);
        assert_eq!(app.hal.shown.len(), presents + 1);
        assert_eq!(app.view.cursor, 1);
    }

    #[test]
    fn a_protected_screen_is_entered_through_the_privacy_gate() {
        let mut app = booted();
        let wiped = sealed(None)
            .start_check()
            .expect("checking")
            .discard(Discard::Collision);
        app.held.kept = Some(wiped);
        app.enter(ScreenId::Collision, Note::None);
        app.redraw().expect("drawn");
        play(&mut app, &[Key::Press]);
        assert_eq!(app.view.id, ScreenId::PrivacyGate);
        assert!(matches!(
            app.view.note,
            Note::Gate {
                to: ScreenId::CollisionQr,
                page: 0,
                skipped: false
            }
        ));
        play(&mut app, &[Key::Press]);
        assert_eq!(app.view.id, ScreenId::CollisionQr);
        assert_eq!(app.hal.last().id, ScreenId::CollisionQr);
    }

    #[test]
    fn a_boot_hwrng_fault_halts_with_its_text_and_holds_nothing() {
        let mut fake = Fake::new();
        fake.hwrng_fault = true;
        let mut app = App::new(fake);
        app.start();
        assert_eq!(app.view.id, ScreenId::Halt);
        assert!(!app.holds_secrets());
        let shown: Vec<ScreenId> = app.hal.shown.iter().map(|s| s.id).collect();
        assert_eq!(shown, [ScreenId::Boot, ScreenId::Blank, ScreenId::Halt]);
        assert!(app.hal.shown[1].frame.iter().all(|&pixel| pixel == 0));
        assert!(
            app.hal
                .last()
                .texts
                .contains(&String::from("hwrng read fault"))
        );
        // No key leaves it.
        play(&mut app, &Key::ALL);
        assert_eq!(app.hal.shown.len(), 3);
    }

    #[test]
    fn a_session_error_halts_and_drops_the_kept_wiped() {
        let mut app = booted();
        let wiped = sealed(None)
            .start_check()
            .expect("checking")
            .discard(Discard::Collision);
        app.held.kept = Some(wiped);
        app.halt(Stop::Core(CoreError::QuotaUnmet));
        assert!(matches!(app.held.stage, Stage::Halted));
        assert!(!app.keeps_wiped());
        assert!(!app.holds_secrets());
        assert!(
            app.hal
                .last()
                .texts
                .contains(&String::from("the device entropy quota is not met"))
        );
        // Once halted, a later failure changes nothing.
        let presents = app.hal.shown.len();
        app.halt(Stop::Hal(HalError::Buttons));
        assert_eq!(app.hal.shown.len(), presents);
        assert!(matches!(
            app.view.note,
            Note::Halt(Stop::Core(CoreError::QuotaUnmet))
        ));
    }

    #[test]
    fn steps_10_to_15_are_not_drawn_before_every_word_reads_back() {
        let mut app = booted();
        app.held.stage = Stage::Ready {
            session: sealed(None).skip_check(),
            steps: Steps::new(),
        };
        let after: Vec<ScreenId> = ScreenId::ALL
            .into_iter()
            .filter(|&id| screens::after_readback(id))
            .collect();
        for &id in &after {
            let view = View::new(id, Note::None);
            assert!(
                matches!(screens::model(&app.held, &view), Err(stop) if stop == OUT_OF_ORDER),
                "{}",
                id.name()
            );
        }
        // Every insert read back from its own faces, as at the metal: the offers draw.
        let Stage::Ready { session, .. } = &mut app.held.stage else {
            panic!("the Ready stage");
        };
        let typed: Vec<(u8, String)> = session
            .braille()
            .iter()
            .map(|insert| (insert.position(), insert.word().chars().take(4).collect()))
            .collect();
        for (position, letters) in typed {
            assert!(matches!(
                session.check_readback(position, &letters),
                Ok(keepcrypt_core::ReadbackResult::Match)
            ));
        }
        for id in [
            ScreenId::ReadbackDone,
            ScreenId::Wallet,
            ScreenId::BackupOffer,
            ScreenId::WatchOffer,
            ScreenId::Bip39Ask,
            ScreenId::RegisterOffer,
            ScreenId::RevealDOffer,
            ScreenId::Checklist,
        ] {
            assert!(after.contains(&id));
            let view = View::new(id, Note::None);
            assert!(screens::model(&app.held, &view).is_ok(), "{}", id.name());
        }
    }

    #[test]
    fn an_unrecognised_entry_shows_cores_text_with_the_first_fours_instruction_under_it() {
        let mut app = booted();
        let mut typed = Zeroizing::new(String::with_capacity(crate::grid::ENTRIES_LEN));
        // Eight entries; the first is no word's first four letters.
        typed.push_str("zzzz aban aban aban aban aban aban aban");
        app.held.stage = Stage::BackupCheck {
            file: Zeroizing::new(Vec::new()),
            typed,
        };
        app.view = View::new(ScreenId::BackupCheckEntry, Note::None);
        // The cursor rests on the last letter typed, 'n', as after a press.
        app.view.cursor = 13;
        app.redraw().expect("drawn");
        app.entry_typed().expect("a refusal, not a halt");
        assert_eq!(app.view.id, ScreenId::BackupCheckEntry);
        assert_eq!(
            app.view.cursor, 0,
            "the emptied entry's cursor is back on 'a'"
        );
        assert!(matches!(
            app.view.note,
            Note::Refused(Refusal::Core(CoreError::Backup(
                keepcrypt_core::BackupError::PassphraseWords
            )))
        ));
        assert!(matches!(&app.held.stage, Stage::BackupCheck { typed, .. } if typed.is_empty()));
        // Core's text verbatim, and the screen's own instruction right under it (core's text
        // asks for 8 whole words; the grid types their first fours).
        let texts = &app.hal.last().texts;
        let core =
            "backup rejected: the backup passphrase must be 8 words from the BIP39 English list";
        let at = texts.iter().position(|t| t == core).expect("core's text");
        assert_eq!(
            texts.get(at + 1).map(String::as_str),
            Some("Type the first four letters of each word, or a whole three-letter word.")
        );
    }

    #[test]
    fn the_bip39_passphrase_stops_at_100_characters_in_its_own_buffer() {
        let mut app = booted();
        // A dice-only ceremony, every insert read back from its own faces, so step 12 draws.
        let mut ready = sealed(None).skip_check();
        let typed: Vec<(u8, String)> = ready
            .braille()
            .iter()
            .map(|insert| (insert.position(), insert.word().chars().take(4).collect()))
            .collect();
        for (position, letters) in typed {
            assert!(matches!(
                ready.check_readback(position, &letters),
                Ok(keepcrypt_core::ReadbackResult::Match)
            ));
        }
        let mut steps = Steps::new();
        let capacity = steps.typed.capacity();
        steps.typed.push_str(&"a".repeat(MAX_PASSPHRASE - 1));
        app.held.stage = Stage::Ready {
            session: ready,
            steps,
        };
        // The cursor on '~', the ASCII grid's last symbol.
        let mut view = View::new(ScreenId::Bip39Entry, Note::None);
        view.cursor = 94;
        drawn(&mut app, view);
        assert_eq!(app.hal.last().keys.label(Key::Press), Some("add"));
        // The 100th character is taken, in the buffer sized for it; then type is offered no more.
        play(&mut app, &[Key::Press]);
        let full = |app: &App<Fake>| match &app.held.stage {
            Stage::Ready { steps, .. } => {
                steps.typed.len() == MAX_PASSPHRASE && steps.typed.capacity() == capacity
            }
            _ => false,
        };
        assert!(full(&app));
        assert_eq!(app.hal.last().keys.label(Key::Press), None);
        assert_eq!(app.hal.last().keys.label(Key::Key3), Some("done"));
        // A 101st press is a dead key: nothing changes and nothing is drawn.
        let presents = app.hal.shown.len();
        play(&mut app, &[Key::Press]);
        assert_eq!(app.hal.shown.len(), presents);
        assert!(full(&app));
    }

    /// What the Ready stage holds besides the session, by name.
    fn holding(app: &App<Fake>) -> &'static str {
        match &app.held.stage {
            Stage::Ready { steps, .. } => match steps.holding {
                Holding::Nothing => "nothing",
                Holding::Mismatch(_) => "a mismatch",
                Holding::Passphrase(_) => "the backup passphrase",
                Holding::Export(_) => "the watch-only export",
                Holding::Registration(_) => "the registration",
                Holding::DeviceLeg(_) => "D",
            },
            _ => "no Ready stage",
        }
    }

    #[test]
    fn leaving_a_steps_screens_drops_what_they_showed() {
        let mut app = booted();
        let mut ready = sealed(None).skip_check();
        let typed: Vec<(u8, String)> = ready
            .braille()
            .iter()
            .map(|insert| (insert.position(), insert.word().chars().take(4).collect()))
            .collect();
        for (position, letters) in typed {
            assert!(ready.check_readback(position, &letters).is_ok());
        }
        app.held.stage = Stage::Ready {
            session: ready,
            steps: Steps::new(),
        };
        // Step 11: the passphrase's display copy, from its pages until both answers are right.
        drawn(&mut app, View::new(ScreenId::BackupOffer, Note::None));
        play(&mut app, &[Key::Press, Key::Press, Key::Key3, Key::Press]);
        assert_eq!(holding(&app), "the backup passphrase");
        for _ in 0..2 {
            assert_eq!(app.view.id, ScreenId::BackupConfirm);
            let right = match &app.held.stage {
                Stage::Ready { steps, .. } => match &steps.holding {
                    Holding::Passphrase(new) => {
                        let (position, choices) = new.challenge().questions()[app.view.page];
                        let word = new.words().nth(usize::from(position) - 1);
                        choices.iter().position(|&choice| Some(choice) == word)
                    }
                    _ => None,
                },
                _ => None,
            };
            let downs = vec![Key::Down; right.expect("the right word is a choice")];
            play(&mut app, &downs);
            play(&mut app, &[Key::Press]);
        }
        assert_eq!(app.view.id, ScreenId::UsbInsert);
        assert_eq!(holding(&app), "nothing");
        // Step 12 with a BIP39 passphrase: its text, once the export is made; the export, once
        // its QRs are left.
        drawn(&mut app, View::new(ScreenId::Bip39Ask, Note::None));
        play(
            &mut app,
            &[Key::Down, Key::Press, Key::Press, Key::Press, Key::Key3],
        );
        assert_eq!(app.view.id, ScreenId::WatchSummary);
        assert_eq!(holding(&app), "the watch-only export");
        assert!(matches!(&app.held.stage, Stage::Ready { steps, .. } if steps.typed.is_empty()));
        play(&mut app, &[Key::Press, Key::Press, Key::Press, Key::Press]);
        assert_eq!(app.view.id, ScreenId::RegisterOffer);
        assert_eq!(holding(&app), "nothing");
        // Step 13: the registration, once register-qr is left (dice-only: no step 14).
        play(&mut app, &[Key::Press, Key::Press]);
        assert_eq!(app.view.id, ScreenId::RegisterQr);
        assert_eq!(holding(&app), "the registration");
        play(&mut app, &[Key::Press]);
        assert_eq!(app.view.id, ScreenId::Checklist);
        assert_eq!(holding(&app), "nothing");
    }

    /// Draws the current screen on the fake display, which checks that the model fits and keeps
    /// every Protected element on a Protected screen.
    fn drawn(app: &mut App<Fake>, view: View) {
        app.view = view;
        app.redraw().expect("drawn");
        assert_eq!(app.hal.last().id, app.view.id);
    }

    /// A Mixed 12-word session's step 4 on the fake hardware, hwrng drawn and no block read yet.
    fn step_4() -> App<Fake> {
        let mut app = booted();
        app.held.plan = Plan {
            len: SeedLength::Words12,
            mode: Mode::Mixed,
        };
        let session = new_session(None, SeedLength::Words12, Mode::Mixed).expect("a session");
        app.held.stage = Stage::Collecting(session);
        drawn(&mut app, View::new(ScreenId::Hwrng, Note::None));
        app
    }

    /// Step 4's next tick, taken by `step` as the device takes it: the clock moves on to the next
    /// block, which is read.
    fn block(app: &mut App<Fake>) {
        assert!(app.block_wanted(), "step 4 wants a block");
        app.hal.tick = true;
        app.step();
    }

    /// The hwrng bytes step 4 has health-tested.
    fn tested(app: &App<Fake>) -> u64 {
        match &app.held.stage {
            Stage::Collecting(session) => session.hw_bytes_tested(),
            _ => panic!("step 4"),
        }
    }

    /// A game byte source that fails, as the OS read behind core's game call can.
    fn no_game_bytes(_: &mut [u8]) -> Result<(), CoreError> {
        Err(CoreError::Source(SourceFault::Os))
    }

    /// A game byte source that places food at (9, 6), right in front of a new round's head.
    fn food_ahead(buf: &mut [u8]) -> Result<(), CoreError> {
        buf.fill(255);
        buf[..2].copy_from_slice(&[9, 6]);
        Ok(())
    }

    /// The app halted on the game byte source's error: a black frame, then `halt` with core's
    /// text, and nothing held.
    fn assert_game_byte_halt(app: &App<Fake>) {
        assert_eq!(app.view.id, ScreenId::Halt);
        assert!(matches!(
            app.view.note,
            Note::Halt(Stop::Core(CoreError::Source(SourceFault::Os)))
        ));
        assert!(!app.holds_secrets());
        assert!(!app.keeps_wiped());
        let shown: Vec<ScreenId> = app.hal.shown.iter().rev().take(2).map(|s| s.id).collect();
        assert_eq!(shown, [ScreenId::Halt, ScreenId::Blank]);
        let text = CoreError::Source(SourceFault::Os).to_string();
        assert!(app.hal.last().texts.contains(&text));
    }

    #[test]
    fn every_key_in_step_4_reaches_the_pool_with_snake_open_or_closed() {
        // Every key, offered or not, through the app's one call site: Snake closed, open, its
        // round over, and left; then Continue. The keys pressed in the session's next stage reach
        // nothing.
        let mut app = step_4();
        let mut pressed = 0;
        let mut forward = |app: &mut App<Fake>, keys: &[Key], when: &str| {
            play(app, keys);
            pressed += keys.len();
            assert_eq!(app.extras, pressed, "{when}");
        };
        let dead = [
            Key::Up,
            Key::Down,
            Key::Left,
            Key::Right,
            Key::Key1,
            Key::Key2,
            Key::Key3,
        ];
        forward(&mut app, &dead, "Snake closed");
        forward(&mut app, &[Key::Press], "Snake opened");
        assert_eq!(app.view.id, ScreenId::GameSnake);
        let steer = [Key::Down, Key::Left, Key::Right, Key::Up];
        forward(&mut app, &steer, "Snake steered");
        forward(&mut app, &[Key::Press, Key::Key2, Key::Key3], "Snake open");
        for _ in 0..10 {
            block(&mut app);
        }
        assert!(matches!(&app.view.note, Note::Game(snake) if snake.over()));
        forward(&mut app, &steer, "Snake's round over");
        forward(&mut app, &[Key::Key2, Key::Key3, Key::Key1], "Snake left");
        assert_eq!(app.view.id, ScreenId::Hwrng);
        forward(&mut app, &dead, "Snake closed again");
        while app.block_wanted() {
            block(&mut app);
        }
        forward(&mut app, &[Key::Press], "Continue");
        assert_eq!(app.view.id, ScreenId::Commitment);
        play(&mut app, &[Key::Up, Key::Key3]);
        assert_eq!(app.extras, pressed, "committed");
    }

    #[test]
    fn no_dice_only_key_reaches_the_pool() {
        // Dice-only step 4 is the notice, in Collecting: no key reaches the pool, Continue
        // included.
        let mut app = booted();
        app.held.plan = Plan {
            len: SeedLength::Words12,
            mode: Mode::DiceOnly,
        };
        let session = new_session(None, SeedLength::Words12, Mode::DiceOnly).expect("a session");
        app.held.stage = Stage::Collecting(session);
        drawn(&mut app, View::new(ScreenId::DiceOnlyNotice, Note::None));
        let keys = [
            Key::Up,
            Key::Down,
            Key::Left,
            Key::Right,
            Key::Key1,
            Key::Key2,
            Key::Key3,
            Key::Press,
        ];
        play(&mut app, &keys);
        assert_eq!(app.view.id, ScreenId::Dice);
        assert_eq!(app.extras, 0);
    }

    #[test]
    fn snake_opens_in_step_4_a_wall_ends_its_round_and_the_quota_closes_it() {
        let mut app = step_4();
        assert!(
            app.hal
                .last()
                .texts
                .contains(&String::from(">Play while you wait"))
        );
        play(&mut app, &[Key::Press]);
        let open = app.hal.last();
        assert_eq!(
            (open.id, open.title.as_str()),
            (ScreenId::GameSnake, "Snake")
        );
        assert_eq!(open.keys, KeyMap::SNAKE.without(Key::Press));
        // Up from row 9: nine cells to row 0, one for each block, then the wall.
        play(&mut app, &[Key::Up]);
        for _ in 0..9 {
            block(&mut app);
        }
        assert!(matches!(&app.view.note, Note::Game(snake) if !snake.over()));
        block(&mut app);
        let over = app.hal.last();
        assert_eq!(over.id, ScreenId::GameSnake, "the round ends on game-snake");
        assert_eq!(over.title, "Round over · Press to play again");
        let steer = [Key::Up, Key::Down, Key::Left, Key::Right];
        let after = steer.into_iter().fold(KeyMap::SNAKE, KeyMap::without);
        assert_eq!(over.keys, after);
        // Press plays again.
        play(&mut app, &[Key::Press]);
        assert!(matches!(&app.view.note, Note::Game(snake) if !snake.over()));
        // Snake stays open up to the block that meets the quota, which closes it: Continue.
        while tested(&app) + 64 < HW_BYTES_NEEDED {
            block(&mut app);
        }
        assert_eq!(app.view.id, ScreenId::GameSnake);
        block(&mut app);
        assert_eq!(tested(&app), HW_BYTES_NEEDED);
        let closed = app.hal.last();
        assert_eq!(closed.id, ScreenId::Hwrng);
        assert!(closed.texts.contains(&String::from(">Continue")));
    }

    #[test]
    fn a_game_byte_error_while_snake_is_open_halts_holding_nothing() {
        let mut app = step_4();
        // A round played to the wall, then Press for another, whose food the failing source
        // cannot place.
        play(&mut app, &[Key::Press, Key::Up]);
        for _ in 0..10 {
            block(&mut app);
        }
        assert_eq!(app.hal.last().keys.label(Key::Press), Some("again"));
        app.set_game_bytes(GameBytes::test(no_game_bytes));
        play(&mut app, &[Key::Press]);
        assert_game_byte_halt(&app);
    }

    #[test]
    fn a_game_byte_error_opening_snake_halts_holding_nothing() {
        // "Play while you wait", whose first food the failing source cannot place.
        let mut app = step_4();
        app.set_game_bytes(GameBytes::test(no_game_bytes));
        play(&mut app, &[Key::Press]);
        assert_game_byte_halt(&app);
    }

    #[test]
    fn a_game_byte_error_placing_food_after_a_bite_halts_holding_nothing() {
        // The first food right in front of the head: the next block's step eats it, and the next
        // food is drawn from the failing source.
        let mut app = step_4();
        app.set_game_bytes(GameBytes::test(food_ahead));
        play(&mut app, &[Key::Press]);
        assert!(matches!(&app.view.note, Note::Game(snake) if !snake.over()));
        app.set_game_bytes(GameBytes::test(no_game_bytes));
        block(&mut app);
        assert_game_byte_halt(&app);
    }

    #[test]
    fn the_longest_models_off_the_scenarios_paths_fit() {
        let mut app = booted();
        // usb-pick: nine names of 64 characters (two pages), none, and a USB fault.
        let names: Vec<FileName> = (b'a'..=b'i')
            .map(|c| {
                let name = format!("{}.kcr", char::from(c).to_string().repeat(60));
                FileName::new(&name).expect("a 64-character name")
            })
            .collect();
        for cursor in [0, 8] {
            let mut view = View::new(
                ScreenId::UsbPick,
                Note::Pick {
                    kind: FileKind::Kcr,
                    names: names.clone(),
                    problem: None,
                },
            );
            view.cursor = cursor;
            drawn(&mut app, view);
        }
        for problem in [None, Some(HalError::Removed)] {
            let note = Note::Pick {
                kind: FileKind::Age,
                names: Vec::new(),
                problem,
            };
            drawn(&mut app, View::new(ScreenId::UsbPick, note));
            assert_eq!(app.hal.last().keys, KeyMap::BACK);
        }
        // A Mixed ceremony read back, for steps 12-14 on their longest.
        let mut session = new_session(None, SeedLength::Words12, Mode::Mixed).expect("a session");
        while session.credited_bits() < session.required_bits() {
            let mut block = [0u8; 64];
            app.hal.read_block(&mut block).expect("a block");
            session = session.add_hw_samples(&block).expect("healthy");
        }
        let mut rolling = session.commit().expect("committed").start_dice();
        for face in (1..=6u8).cycle().take(50) {
            rolling = rolling.push_roll(face).expect("a face");
        }
        let mut ready = rolling.finish().expect("sealed").skip_check();
        let typed: Vec<(u8, String)> = ready
            .braille()
            .iter()
            .map(|insert| (insert.position(), insert.word().chars().take(4).collect()))
            .collect();
        for (position, letters) in typed {
            assert!(ready.check_readback(position, &letters).is_ok());
        }
        let (ready, d) = ready.reveal_device_leg().expect("revealed");
        let mut steps = Steps::new();
        steps.typed.push_str(&"~ ".repeat(MAX_PASSPHRASE / 2));
        steps.holding = Holding::DeviceLeg(d.expect("Mixed mode has D"));
        app.held.stage = Stage::Ready {
            session: ready,
            steps,
        };
        drawn(&mut app, View::new(ScreenId::RevealDOffer, Note::None));
        drawn(&mut app, View::new(ScreenId::RevealD, Note::None));
        let refusal = Note::Refused(Refusal::Core(CoreError::EmptyPassphrase));
        drawn(&mut app, View::new(ScreenId::Bip39Entry, refusal));
        let failed = Note::BackupFailed {
            reason: Refusal::Core(CoreError::Backup(keepcrypt_core::BackupError::Payload)),
            left: Some(HalError::Remove),
        };
        drawn(&mut app, View::new(ScreenId::BackupFailed, failed));
    }

    #[test]
    fn only_refusals_of_what_was_supplied_return_and_every_other_error_halts() {
        use keepcrypt_core::{
            BackupError, BrailleError, HealthFailure, HealthStage, HealthTest, InternalFault,
            KatId, SnapshotError, SourceFault,
        };
        let refusals = [
            CoreError::WrongPassphrase,
            CoreError::ReadbackMismatch,
            CoreError::EmptyPassphrase,
            CoreError::NoRegistryKey,
            CoreError::Snapshot(SnapshotError::BadSignature),
            CoreError::Backup(BackupError::PassphraseWords),
        ];
        for error in refusals {
            assert_eq!(refused(error), Ok(Refusal::Core(error)), "{error:?}");
        }
        let halts = [
            CoreError::Kat(KatId::Sha256),
            CoreError::Source(SourceFault::Os),
            CoreError::Health(HealthFailure {
                test: HealthTest::RepetitionCount,
                stage: HealthStage::Continuous,
                sample: 1,
            }),
            CoreError::QuotaUnmet,
            CoreError::NotInThisMode,
            CoreError::InvalidRoll,
            CoreError::TooManyRolls,
            CoreError::TooFewRolls,
            CoreError::ReadbackIncomplete,
            CoreError::NoBackupPassphrase,
            CoreError::ExportSelfCheck,
            CoreError::Braille(BrailleError::MalformedReadback),
            CoreError::Internal(InternalFault::Length),
        ];
        for error in halts {
            assert_eq!(refused(error), Err(Stop::Core(error)), "{error:?}");
        }
        for fault in HalError::ALL {
            match usb_fault(fault) {
                Ok(returned) => assert!(!fault.halts() && returned == fault),
                Err(stop) => assert!(fault.halts() && stop == Stop::Hal(fault)),
            }
        }
        assert_eq!(
            Refusal::Usb(HalError::Write).to_string(),
            "the backup could not be written to the USB stick"
        );
        assert_eq!(
            Refusal::Code(CheckError::WrongCode).to_string(),
            "the go-ahead code does not match"
        );
    }

    #[test]
    fn every_stop_has_fixed_text() {
        assert_eq!(
            Stop::Core(CoreError::QuotaUnmet).to_string(),
            "the device entropy quota is not met"
        );
        assert_eq!(Stop::Hal(HalError::HwRng).to_string(), "hwrng read fault");
        assert_eq!(
            Stop::Render(RenderError::QrTooLong).to_string(),
            "a QR code is too large for the screen"
        );
        assert_eq!(
            OUT_OF_ORDER.to_string(),
            "internal failure: a screen was reached out of order"
        );
    }
}
