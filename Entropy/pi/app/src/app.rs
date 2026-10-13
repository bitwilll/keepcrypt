//! The app (tasks/todo.md, M3 group 8; docs/pi-firmware.md "User flow", "Protected screens and
//! idle", "Finish and halts"): one owner of the session and of every secret, driven one event at
//! a time.
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
//!   offered only when a gate function in `screens` says yes.
//! - Fail closed (rule 3; Q25): every core error, and every display, button or hwrng fault,
//!   halts. `halt` wipes the stage, drops the kept `Wiped`, presents a black frame, then the red
//!   stop screen with the failure's fixed text, which no key leaves; only a power cycle does.
//!   Only refusals of what the user supplied return to their own screen: here, a go-ahead code
//!   that does not verify.
//! - Idle (Q29): after 30 s without input a Protected screen is covered, and the next press only
//!   uncovers it; at 9 minutes a warning appears while secrets are held; at 10 minutes the stage
//!   is wiped (the kept `Wiped` and the snapshot stay) and the device says so.
//! - Entering a Protected screen from a Public one passes the privacy gate (`enter`).
//! - New sessions come from the kept `Wiped` while there is one, else from `Session::new`, whose
//!   one call in this crate is in `new_session` (Q26, Q33 (c)).
//! - Key presses in Mixed `Collecting` reach the pool as uncredited extras (`extras`).

use core::fmt;
use core::mem;

use keepcrypt_core::{
    CheckError, Checking, Collecting, Committed, CoreError, Discard, GoAhead, HW_BYTES_NEEDED,
    Mode, Platform, Ready, RegistryDate, Rejected, Rolling, Sealed, SeedLength, Session,
    VerifiedSnapshot, Wiped, hwrng_boot_test, registry_key_is_test, self_test,
};
use zeroize::Zeroizing;

use crate::extras::{StageKind, extra_for};
use crate::hal::{BuildInfo, Hal, HalError};
use crate::input::{Event, Idle, IdleStep, Key};
use crate::screen::{Banners, KeyMap, ScreenId};
use crate::screens::{self, CODE_LEN, Choice};
use crate::ui::{Painter, PresentError, RenderError};

/// The boot test reads 16 blocks of 64 samples: core's `hwrng_boot_test` takes exactly 1,024.
const BOOT_BLOCKS: usize = 16;
/// Step 4 reads one hwrng block per tick. 100 ms in the simulator; M4 sets the device's from the
/// measured hwrng rate.
const BLOCK_TICK_NS: u64 = 100_000_000;

/// The session in its typestate, and every secret the shell holds with it: the only place a
/// `Session` lives. No `Debug` or `Clone`.
pub enum Stage {
    /// No session: before the first one, after a check discarded one, after the idle wipe.
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
    Ready(
        #[expect(
            dead_code,
            reason = "the words and exports, steps 8-15, read it (group 9)"
        )]
        Session<Ready>,
    ),
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
            Stage::Ready(_) => StageKind::Ready,
            Stage::Halted => StageKind::Halted,
        }
    }
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

/// What a screen says that its id alone does not. Holds no secret.
pub enum Note {
    None,
    /// The privacy gate, in front of `to`; after Skip it carries swb's note.
    Gate {
        to: ScreenId,
        skipped: bool,
    },
    /// check-clear: the Seal ID, and the loaded snapshot's date, or `None` for a typed code.
    Clear {
        seal_id: String,
        as_of: Option<RegistryDate>,
    },
    /// code-wrong: core's refusal of the typed code.
    Refused(CheckError),
    /// halt: why.
    Halt(Stop),
}

/// The current screen: its id, the menu, picker or grid cursor, its note and any overlay. Holds
/// no secret.
pub struct View {
    pub id: ScreenId,
    pub cursor: usize,
    pub note: Note,
    pub overlay: Option<Overlay>,
}

impl View {
    fn new(id: ScreenId, note: Note) -> Self {
        View {
            id,
            cursor: 0,
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
        }
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

    /// True while the stage holds a session (or, later, a checked backup): the idle warning and
    /// wipe apply.
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

    /// The deadline for the next event: step 4's next block, or the idle timer's next threshold.
    fn deadline(&self) -> u64 {
        let now_ns = self.hal.now_ns();
        let block = self.block_wanted().then_some(self.next_block_ns);
        let idle = self
            .idle
            .next_ns(now_ns, self.view.id.class(), self.holds_secrets());
        block.into_iter().chain(idle).fold(u64::MAX, u64::min)
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
            self.redraw()?;
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

    /// The stage, moved out; `Idle` is left behind until the caller puts the next one back.
    fn take(&mut self) -> Stage {
        mem::replace(&mut self.held.stage, Stage::Idle)
    }

    /// Makes `to` the current screen, through the privacy gate when it is Protected and the
    /// current screen is Public. A gated screen takes no note.
    fn enter(&mut self, to: ScreenId, note: Note) {
        self.view = if screens::needs_gate(self.view.id, to) {
            View::new(ScreenId::PrivacyGate, Note::Gate { to, skipped: false })
        } else {
            View::new(to, note)
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
        self.painter
            .present(&mut self.hal, &screens::wait(&self.held))?;
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
        let choices = screens::choices(id, &self.held);
        match (id, key) {
            (ScreenId::Dice, _) => return self.dice(key),
            (ScreenId::CodeEntry, _) => return self.code(key),
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
            | (ScreenId::About | ScreenId::IdleWiped, Key::Press) => {
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
                let Note::Gate { to, .. } = self.view.note else {
                    return Err(OUT_OF_ORDER);
                };
                self.enter(to, Note::None);
            }
            // "Add fresh entropy": a new ceremony from the kept `Wiped`, with the destroyed
            // session's length and mode.
            (ScreenId::CollisionQr, Key::Press) => return self.begin(),
            _ => return Err(OUT_OF_ORDER),
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
            Choice::About => self.enter(ScreenId::About, Note::None),
            Choice::Words12 | Choice::Words24 => {
                self.held.plan.len = match choice {
                    Choice::Words12 => SeedLength::Words12,
                    _ => SeedLength::Words24,
                };
                return self.begin();
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
                self.held.stage = Stage::Ready(session.skip_check());
                self.held.kept = None;
                self.view = View::new(
                    ScreenId::PrivacyGate,
                    Note::Gate {
                        to: ScreenId::WordsInsert,
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
        self.held.stage = Stage::Ready(ready);
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

    /// The go-ahead code grid: move, type, delete, done.
    fn code(&mut self, key: Key) -> Result<(), Stop> {
        if let Some(cursor) = screens::grid_move(self.view.cursor, key) {
            self.view.cursor = cursor;
            return self.redraw();
        }
        let Stage::Checking { code, .. } = &mut self.held.stage else {
            return Err(OUT_OF_ORDER);
        };
        match key {
            Key::Press => {
                let Some(&symbol) = screens::CROCKFORD.get(self.view.cursor) else {
                    return Err(OUT_OF_ORDER);
                };
                code.push(char::from(symbol));
            }
            Key::Key1 => {
                code.pop();
            }
            Key::Key3 => return self.reveal_by_code(),
            Key::Up | Key::Down | Key::Left | Key::Right | Key::Key2 => {
                return Err(OUT_OF_ORDER);
            }
        }
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
                self.enter(ScreenId::CodeWrong, Note::Refused(error));
                self.redraw()
            }
            Err(Rejected::Collision(wiped)) => self.collided(wiped),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use keepcrypt_core::BackupFile;

    use super::*;
    use crate::hal::{Buttons, Clock, Display, FileKind, FileName, HwRng, Usb, Written};
    use crate::screen::{Class, Screen};
    use crate::ui::Frame;

    /// One present as the fake display keeps it.
    struct Shown {
        id: ScreenId,
        keys: KeyMap,
        texts: Vec<String>,
        frame: Vec<u16>,
    }

    /// The least hardware the app runs on: scripted keys, a clock that moves 1 ms per key, the
    /// counting hwrng stream and no stick. The display checks the two invariants the simulator
    /// checks (a Protected element only on a Protected id, and the model fits) and keeps each
    /// present. Only public test text is ever drawn here.
    struct Fake {
        keys: VecDeque<Key>,
        now_ns: u64,
        served: usize,
        hwrng_fault: bool,
        shown: Vec<Shown>,
    }

    impl Fake {
        fn new() -> Self {
            Fake {
                keys: VecDeque::new(),
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
        fn next_event(&mut self, _deadline_ns: u64) -> Result<Event, HalError> {
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
        assert!(matches!(app.held.stage, Stage::Ready(_)));
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
            Note::Refused(CheckError::WrongCode)
        ));
        assert_eq!(check_url(&app), before);
        play(&mut app, &[Key::Press]);
        assert_eq!(app.view.id, ScreenId::CodeEntry);
        assert_eq!(check_url(&app), before);
        assert!(app.holds_secrets());
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
