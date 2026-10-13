//! The screens (tasks/todo.md, M3 groups 8 and 9; docs/pi-firmware.md "User flow", "Buttons",
//! "Protected screens and idle"; docs/seal-watchonly-braille.md "Checking the seal"): each one's
//! model, built from what the app holds and the current screen, and the pure gate functions that
//! decide which actions a model offers. Steps 1-7 and the screens of any step are here, steps 8-15
//! in `ready`, and the USB screens of step 11 and of Home's side flows in `usb`.
//!
//! - A model borrows the session's text and owns only `Zeroizing` text; a secret is a Protected
//!   element, on a Protected screen only, and owned secret text is built in a buffer of its final
//!   size (`built`), so no reallocation leaves a copy behind.
//! - An action core would refuse by wiping the session is offered only when its gate function
//!   says yes: Continue below the quota, a confirm at 256 rolls or with no face picked, Done below
//!   the minimum, Skip outside `Sealed`, steps 10-15 before the read-back (tasks/todo.md, M3 "The
//!   shell never makes a wiping call by mistake"). A model leaves out every key that would do
//!   nothing, and the app ignores a key the shown model leaves out.
//! - Elements are stacked from the top of the content area, `GAP` apart, so each box comes from
//!   the font metrics (`Element::bounds`) and every model fits.

mod ready;
mod usb;

use embedded_graphics::prelude::{Point, Size};
use keepcrypt_core::{HW_BYTES_NEEDED, Mode, RegistryDate, SealPublic};
use zeroize::Zeroizing;

use crate::app::{Held, Note, OUT_OF_ORDER, Stage, Stop, View};
use crate::extras::StageKind;
use crate::grid::{CODE_LEN, Grid, PAGE_ROWS};
use crate::input::Key;
use crate::screen::{
    BOARD_CELL_PX, BOARD_CELLS, BODY_FONT, Banners, Class, Element, Item, LARGE_SCALE, QR_SIDE,
    SEAL_SIDE, Screen, ScreenId, Str, advance, px,
};
use crate::ui::{SIDE, caption_cells, hex_groups};

/// Core refuses a 257th roll (`TooManyRolls`), so confirm is disabled at 256 (Q32 (a)).
pub const MAX_ROLLS: u16 = 256;
/// The step 4 progress bar's cells.
const BAR_CELLS: u64 = 20;
/// The space between stacked elements.
const GAP: u32 = 4;
/// The braille caption's cell box: the dots alone (`ui::braille`).
const CAPTION_PITCH: Size = Size::new(15, 24);
/// The security address (SECURITY.md), for About and `COLLISION`.
const SECURITY: &str = "admin@keepcrypt.com";
/// The wait screen's line while a new session runs the known-answer tests.
pub const WAIT_SESSION: &str = "The known-answer tests run before every new seed.";
/// ... while the backup is encrypted, written and read back (two scrypt runs).
pub const WAIT_BACKUP: &str = "Encrypting the backup, writing it to the stick and reading it back.";
/// ... while a backup is opened with a typed passphrase (one scrypt run).
pub const WAIT_OPEN: &str = "Opening the backup with its passphrase.";
/// ... while a snapshot is verified.
pub const WAIT_SNAPSHOT: &str = "Checking the snapshot's signature and entries.";

// The longer screen copy.
/// check-prompt: swb's prompt, the same words as the phones.
const CHECK_PROMPT: &str = "KeepCrypt can compare this new wallet's seal with the public \
    KeepCrypt registry. If anyone has ever registered the same seal, your seed is not unique: it \
    will be destroyed without being shown, and you will make a new one.";
const SKIP_CONFIRM: &str = "The words will be shown without a collision check. Skip is offered \
    only now: once a check starts, only a verified go-ahead shows the words.";
/// The privacy gate after Skip: swb's note.
const SKIPPED: &str = "You skipped the check: the seal can be checked later from the words.";
const CHECK_ACTIONS: &str =
    "Go ahead: type its code. Stop: Match found. A network or snapshot error: Cannot check.";
const CODE_WRONG: &str = "Check the code on your checker and type it again. The check stays \
    open, with the same seal card: KEY2 on the code screen goes back to its actions.";
/// collision: swb's suggestion of a report (to SECURITY) and a verification run.
const COLLISION: &str = "A genuine collision means this device's randomness or firmware is \
    suspect: report the device and firmware version to admin@keepcrypt.com, and make a \
    verification run with the offline verifier.";
const DICE_ONLY: &str =
    "No device randomness is mixed in: the seed is SHA-256 of your rolls, as on a Coldcard.";
const IDLE_WARNING: &str =
    "Without a key, everything secret is wiped in one minute. Press any key to keep it.";
const HALTED: &str = "No seed can be made. Power the device off: a power cycle reruns the \
    self-tests before any new seed.";
/// The privacy gate in front of the words: the SeedBook safety rules (swb "Braille backup").
const SEEDBOOK_RULES: &str = "The SeedBook is a public reference: never write the real phrase \
    in it or store a marked copy with the wallet. Work one word at a time, in order, alone and \
    offline; rehearse on a spare insert first. Never use a computer-driven embosser or printer \
    for a real seed.";

/// A menu entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    NewSeed,
    DiceOnlySeed,
    CheckBackup,
    LoadSnapshot,
    About,
    Words12,
    Words24,
    /// Step 4 before the quota: Snake.
    Play,
    /// Step 4's Continue: the commitment.
    Continue,
    CheckNow,
    Skip,
    /// The Skip confirmation.
    SkipCheck,
    /// Yes on snapshot-date.
    UseSnapshot,
    /// No on snapshot-date: the seal card instead.
    NotSnapshot,
    EnterCode,
    MatchFound,
    CannotCheck,
    /// The Match found confirmation.
    Destroy,
    /// The Cannot check confirmation.
    StartAgain,
    /// Step 11's offer: Do it.
    BackUp,
    /// Step 11's offer: Skip.
    SkipBackup,
    /// After a failed backup: a new file under the same passphrase.
    Retry,
    /// After a failed backup: Skip.
    SkipFailedBackup,
    /// Step 12's offer: Do it.
    ShowWatchOnly,
    /// Step 12's offer: Skip.
    SkipWatchOnly,
    /// The export of the seed itself.
    NoPassphrase,
    /// The export of a BIP39 passphrase's wallet.
    WithPassphrase,
    /// Step 13's offer: Do it.
    ShowRegistration,
    /// Step 13's offer: Skip.
    SkipRegistration,
    /// Step 14's offer: Do it.
    ShowD,
    /// Step 14's offer: Skip.
    SkipD,
    /// "Check a backup": the re-check QR.
    Recheck,
    /// "Check a backup": the words, behind the privacy gate.
    ShowWords,
    /// "Check a backup": done, which drops the backup.
    CloseBackup,
}

impl Choice {
    /// The menu line, at most 23 characters, so it fits a line after the cursor mark.
    pub const fn label(self) -> &'static str {
        match self {
            Choice::NewSeed => "New seed",
            Choice::DiceOnlySeed => "Dice-only seed",
            Choice::CheckBackup => "Check a backup",
            Choice::LoadSnapshot => "Load registry snapshot",
            Choice::About => "About",
            Choice::Words12 => "12 words",
            Choice::Words24 => "24 words",
            Choice::Play => "Play while you wait",
            Choice::Continue => "Continue",
            Choice::CheckNow => "Check now (recommended)",
            Choice::Skip => "Skip",
            Choice::SkipCheck => "Skip the check",
            Choice::UseSnapshot => "Yes, use it",
            Choice::NotSnapshot => "No, show the seal card",
            Choice::EnterCode => "Enter go-ahead code",
            Choice::MatchFound => "Match found",
            Choice::CannotCheck => "Cannot check",
            Choice::Destroy => "Destroy this seed",
            Choice::StartAgain => "Start again",
            Choice::BackUp => "Back up to USB",
            Choice::Retry => "Retry",
            Choice::ShowWatchOnly => "Show watch-only QRs",
            Choice::NoPassphrase => "No BIP39 passphrase",
            Choice::WithPassphrase => "I use a passphrase",
            Choice::ShowRegistration => "Show registration QR",
            Choice::ShowD => "Show D",
            Choice::SkipBackup
            | Choice::SkipFailedBackup
            | Choice::SkipWatchOnly
            | Choice::SkipRegistration
            | Choice::SkipD => "Skip",
            Choice::Recheck => "Re-check QR",
            Choice::ShowWords => "Show the words",
            Choice::CloseBackup => "Done",
        }
    }
}

/// The entries of the menu on `id`, empty on a screen that is no menu or offers nothing now.
pub fn choices(id: ScreenId, held: &Held) -> &'static [Choice] {
    let kind = held.stage.kind();
    match (id, &held.stage) {
        (ScreenId::Home, _) => &[
            Choice::NewSeed,
            Choice::DiceOnlySeed,
            Choice::CheckBackup,
            Choice::LoadSnapshot,
            Choice::About,
        ],
        (ScreenId::Length, _) => &[Choice::Words12, Choice::Words24],
        // Snake until the quota is met, then Continue, which closes it.
        (ScreenId::Hwrng, Stage::Collecting(session)) => {
            if continue_offered(session.credited_bits(), session.required_bits()) {
                &[Choice::Continue]
            } else {
                &[Choice::Play]
            }
        }
        (ScreenId::CheckPrompt, _) if skip_offered(kind) => &[Choice::CheckNow, Choice::Skip],
        (ScreenId::SkipConfirm, _) if skip_offered(kind) => &[Choice::SkipCheck],
        (ScreenId::SnapshotDate, _) if held.snapshot.is_some() => {
            &[Choice::UseSnapshot, Choice::NotSnapshot]
        }
        (ScreenId::CheckActions, _) => {
            &[Choice::EnterCode, Choice::MatchFound, Choice::CannotCheck]
        }
        (ScreenId::StopConfirm, _) => &[Choice::Destroy],
        (ScreenId::CannotCheckConfirm, _) => &[Choice::StartAgain],
        (ScreenId::BackupOffer, _) => &[Choice::BackUp, Choice::SkipBackup],
        (ScreenId::BackupFailed, _) => &[Choice::Retry, Choice::SkipFailedBackup],
        (ScreenId::WatchOffer, _) => &[Choice::ShowWatchOnly, Choice::SkipWatchOnly],
        (ScreenId::Bip39Ask, _) => &[Choice::NoPassphrase, Choice::WithPassphrase],
        (ScreenId::RegisterOffer, _) => &[Choice::ShowRegistration, Choice::SkipRegistration],
        (ScreenId::RevealDOffer, _) => &[Choice::ShowD, Choice::SkipD],
        (ScreenId::BackupCheckResult, _) => {
            &[Choice::Recheck, Choice::ShowWords, Choice::CloseBackup]
        }
        _ => &[],
    }
}

/// Step 4's Continue (the commitment) only once the device quota is met: core refuses `commit`
/// below it by wiping.
pub fn continue_offered(credited_bits: u64, required_bits: u64) -> bool {
    credited_bits >= required_bits
}

/// A confirm only with a face picked and below 256 rolls: core refuses a face outside 1-6 and a
/// 257th roll by wiping.
pub fn confirm_offered(rolls: u16, picked: usize) -> bool {
    rolls < MAX_ROLLS && (1..=6).contains(&picked)
}

/// Undo only with a roll to undo.
pub fn undo_offered(rolls: u16) -> bool {
    rolls > 0
}

/// Done only at the minimum: core refuses `finish` below it by wiping.
pub fn done_offered(rolls: u16, minimum: u16) -> bool {
    rolls >= minimum
}

/// Skip only in `Sealed`, before a check starts (rule 6): the typestate has no `skip_check`
/// anywhere else.
pub fn skip_offered(stage: StageKind) -> bool {
    stage == StageKind::Sealed
}

/// Where Check now leads (Q33 (a)): with a snapshot loaded, its date first, every time, since
/// the Pi has no clock; otherwise the seal card.
pub fn after_check_now(snapshot_loaded: bool) -> ScreenId {
    if snapshot_loaded {
        ScreenId::SnapshotDate
    } else {
        ScreenId::SealImage
    }
}

/// Where step 13 leads: Reveal D in Mixed mode; dice-only mode has no D and skips step 14.
pub fn after_register(mode: Mode) -> ScreenId {
    match mode {
        Mode::Mixed => ScreenId::RevealDOffer,
        Mode::DiceOnly => ScreenId::Checklist,
    }
}

/// True for the screens of steps 10-15 and readback-done: core's read-back gate holds back the
/// five exports until step 9 completes (pi-firmware.md "User flow"), and no model of these
/// screens is built for a session whose read-back is incomplete.
pub fn after_readback(id: ScreenId) -> bool {
    matches!(
        id,
        ScreenId::ReadbackDone
            | ScreenId::Wallet
            | ScreenId::BackupOffer
            | ScreenId::UsbInsert
            | ScreenId::BackupVerified
            | ScreenId::BackupFailed
            | ScreenId::BackupPassphrase
            | ScreenId::BackupConfirm
            | ScreenId::BackupConfirmWrong
            | ScreenId::WatchOffer
            | ScreenId::Bip39Ask
            | ScreenId::WatchSummary
            | ScreenId::RegisterOffer
            | ScreenId::Bip39Entry
            | ScreenId::WatchAccountQr
            | ScreenId::WatchDescriptorQr
            | ScreenId::RegisterQr
            | ScreenId::RevealDOffer
            | ScreenId::Checklist
            | ScreenId::RevealD
    )
}

/// True when entering `to` from `from` passes the privacy gate first: a Protected screen entered
/// from a Public one, other than the gate itself (Q29).
pub fn needs_gate(from: ScreenId, to: ScreenId) -> bool {
    from != ScreenId::PrivacyGate && from.class() == Class::Public && to.class() == Class::Protected
}

/// The dice line: "37 / 50 rolls, 95.6 bits", from core's counts with integer arithmetic, the
/// bits truncated to a tenth.
pub fn dice_text(rolls: u16, minimum: u16, millibits: u32) -> String {
    let tenths = millibits / 100;
    format!(
        "{rolls} / {minimum} rolls, {}.{} bits",
        tenths / 10,
        tenths % 10
    )
}

/// The page of `grid` that holds `cursor`, 4 rows of cells, the cursor's in brackets. A blank
/// face is `_`; on the ASCII grid a space is `·`, so it can be seen; an empty cell is blank.
/// Built in place: after a press the cursor sits on the symbol just typed.
pub fn grid_text(grid: Grid, cursor: usize) -> Zeroizing<String> {
    let columns = grid.columns();
    let first = cursor / columns / PAGE_ROWS * PAGE_ROWS;
    // Three characters a cell, a row's '·' one byte more, and the line feeds.
    let capacity = PAGE_ROWS * (3 * columns + 1) + PAGE_ROWS - 1;
    built(capacity, |out| {
        for row in first..first + PAGE_ROWS {
            if row > first {
                out.push('\n');
            }
            for column in 0..columns {
                let cell = row * columns + column;
                let symbol = match (grid, grid.symbol(cell)) {
                    (_, None) => ' ',
                    (Grid::Ascii, Some(b' ')) => '·',
                    (_, Some(symbol)) => char::from(symbol),
                };
                let (open, close) = if cell == cursor {
                    ('[', ']')
                } else {
                    (' ', ' ')
                };
                out.push(open);
                out.push(symbol);
                out.push(close);
            }
        }
    })
}

/// Secret text built in a buffer of `capacity`: `fill` never needs more, so the text never
/// reallocates and leaves a copy behind (rule 5).
fn built(capacity: usize, fill: impl FnOnce(&mut String)) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(capacity));
    fill(&mut text);
    text
}

/// Appends `number` in decimal with exactly `width` digits, leading zeros included, with no
/// formatting machinery: it may number a word of the seed.
fn push_number(out: &mut String, number: u16, width: usize) {
    let mut digits = [b'0'; 5];
    let mut rest = number;
    for digit in digits.iter_mut().rev() {
        *digit = b'0' + (rest % 10).to_be_bytes()[1];
        rest /= 10;
    }
    let start = digits.len().saturating_sub(width);
    out.extend(digits[start..].iter().map(|&digit| char::from(digit)));
}

/// A model built from the top of the content area down.
struct Page<'a> {
    screen: Screen<'a>,
    y: u32,
}

impl<'a> Page<'a> {
    fn new(id: ScreenId, title: &'static str, banners: Banners) -> Self {
        Page {
            screen: Screen::new(id, title, banners),
            y: 0,
        }
    }

    /// `item` at column `x`, below the last element.
    fn at(mut self, x: u32, class: Class, item: Item<'a>) -> Self {
        let at = Point::zero() + Size::new(x, self.y);
        let element = match class {
            Class::Public => Element::public(at, item),
            Class::Protected => Element::protected(at, item),
        };
        let height = element.bounds().size.height;
        self.y = self.y.saturating_add(height).saturating_add(GAP);
        self.screen = self.screen.with(element);
        self
    }

    fn text(self, text: impl Into<Str<'a>>) -> Self {
        self.at(0, Class::Public, Item::Text(text.into()))
    }

    fn small(self, text: impl Into<Str<'a>>) -> Self {
        self.at(0, Class::Public, Item::Small(text.into()))
    }

    /// Body text of `class`.
    fn text_in(self, class: Class, text: impl Into<Str<'a>>) -> Self {
        self.at(0, class, Item::Text(text.into()))
    }

    /// Small text of `class`.
    fn small_in(self, class: Class, text: impl Into<Str<'a>>) -> Self {
        self.at(0, class, Item::Small(text.into()))
    }

    /// `item`, `width` px wide, centred.
    fn centred(self, width: u32, class: Class, item: Item<'a>) -> Self {
        self.at(SIDE.saturating_sub(width) / 2, class, item)
    }

    /// A word or a code at ×2, centred.
    fn large(self, text: impl Into<Str<'a>>) -> Self {
        self.large_in(Class::Public, text, None)
    }

    /// A word or a code of `class` at ×2, centred, its characters from `lighter_from` on drawn
    /// lighter.
    fn large_in(self, class: Class, text: impl Into<Str<'a>>, lighter_from: Option<usize>) -> Self {
        let text = text.into();
        let width = px(
            text.as_str().chars().count(),
            advance(&BODY_FONT) * LARGE_SCALE,
        );
        let item = Item::Large { text, lighter_from };
        self.centred(width, class, item)
    }

    /// The menu: one line per entry, the cursor's marked.
    fn menu(self, choices: &[Choice], cursor: usize) -> Self {
        let lines: Vec<String> = choices
            .iter()
            .enumerate()
            .map(|(i, choice)| {
                let mark = if i == cursor { '>' } else { ' ' };
                format!("{mark}{}", choice.label())
            })
            .collect();
        self.listed(Class::Public, lines.join("\n"), choices.len())
    }

    /// A menu of `entries` lines, already marked, as body text of `class`. Up and Down are offered
    /// only with two entries or more, and Press only with one or more.
    fn listed(mut self, class: Class, lines: impl Into<Str<'a>>, entries: usize) -> Self {
        if entries > 0 {
            self = self.text_in(class, lines);
        }
        if entries < 2 {
            self.screen = self.screen.without(Key::Up).without(Key::Down);
        }
        if entries == 0 {
            self.screen = self.screen.without(Key::Press);
        }
        self
    }

    /// The model offering only `keys` of its key map.
    fn only(mut self, keys: &[Key]) -> Self {
        for key in Key::ALL {
            if !keys.contains(&key) {
                self.screen = self.screen.without(key);
            }
        }
        self
    }

    /// The model with `key` left out when `offered` is false.
    fn offer(mut self, key: Key, offered: bool) -> Self {
        if !offered {
            self.screen = self.screen.without(key);
        }
        self
    }

    fn done(self) -> Screen<'a> {
        self.screen
    }
}

/// A fingerprint as the screens write it: 8 lowercase hex digits. Public: the wallet summary
/// shows it to compare after a restore.
fn fingerprint_hex(fingerprint: [u8; 4]) -> String {
    fingerprint
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A date as the screens write it: YYYY-MM-DD.
fn date_text(date: RegistryDate) -> String {
    format!("{:04}-{:02}-{:02}", date.year(), date.month(), date.day())
}

/// The boot screen (step 1), shown while the self-tests run.
pub fn boot(held: &Held) -> Screen<'_> {
    Page::new(ScreenId::Boot, "Boot", held.banners)
        .text("KeepCrypt")
        .small(format!("Version {}", held.build.version))
        .small(format!("Root filesystem {}", held.build.rootfs))
        .small("Known-answer tests and the hwrng startup test are running.")
        .done()
}

/// The wait screen, while a blocking call runs (Q33 (k)): `why` says which.
pub fn wait(held: &Held, why: &'static str) -> Screen<'static> {
    Page::new(ScreenId::Wait, "Please wait", held.banners)
        .text("Please wait")
        .small(why)
        .done()
}

/// The black frame of a wipe: no strip, no element, no key.
pub fn blank() -> Screen<'static> {
    let none = Banners {
        test_registry: false,
        simulator: false,
    };
    Screen::new(ScreenId::Blank, "", none)
}

/// The model of the current screen.
pub fn model<'a>(held: &'a Held, view: &'a View) -> Result<Screen<'a>, Stop> {
    if let Stage::Ready { session, .. } = &held.stage
        && after_readback(view.id)
        && !session.readback_complete()
    {
        return Err(OUT_OF_ORDER);
    }
    if ready::shows(view.shown()) {
        return ready::model(held, view);
    }
    if usb::shows(view.shown()) {
        return usb::model(held, view);
    }
    let banners = held.banners;
    let page = |title| Page::new(view.shown(), title, banners);
    let screen = match (view.shown(), &held.stage) {
        (ScreenId::Cover, _) => page("Covered")
            .text("Screen covered")
            .small("Press any key to show it again.")
            .done(),
        (ScreenId::IdleWarning, _) => page("Idle").text("Still there?").small(IDLE_WARNING).done(),
        (ScreenId::Halt, _) => halt(page("Stopped"), &view.note),
        (ScreenId::Home, _) => {
            let status = match &held.snapshot {
                Some(snapshot) => format!(
                    "Snapshot No. {}, dated {}",
                    snapshot.number(),
                    date_text(snapshot.date())
                ),
                None => String::from("No registry snapshot loaded"),
            };
            page("Home")
                .text("KeepCrypt")
                .menu(choices(ScreenId::Home, held), view.cursor)
                .small(status)
                .done()
        }
        (ScreenId::About, _) => {
            let key = if held.banners.test_registry {
                "Registry key: the TEST key"
            } else {
                "Registry key: none pinned in this build"
            };
            page("About")
                .text("KeepCrypt-Entropy")
                .small(format!("Version {}", held.build.version))
                .small(format!("Root filesystem {}", held.build.rootfs))
                .small(key)
                .small("Licence: MIT OR Apache-2.0")
                .small(format!("Security reports: {SECURITY}"))
                .done()
        }
        (ScreenId::Length, _) => page("Length")
            .text("How many words?")
            .menu(choices(ScreenId::Length, held), view.cursor)
            .small("12 words fill one KeepCrypt Hinge or Screw; 24 words need two.")
            .done(),
        (ScreenId::Hwrng, Stage::Collecting(session)) => {
            let tested = session.hw_bytes_tested();
            let needed = HW_BYTES_NEEDED;
            let filled = tested.min(needed) * BAR_CELLS / needed;
            let cells: String = (0..BAR_CELLS)
                .map(|cell| if cell < filled { '#' } else { '-' })
                .collect();
            page("Device entropy")
                .text("Device entropy")
                .text(format!("[{cells}]"))
                .small(format!("{tested} / {needed} bytes health-tested"))
                .small(format!(
                    "{} / {} bits credited",
                    session.credited_bits(),
                    session.required_bits()
                ))
                .menu(choices(ScreenId::Hwrng, held), view.cursor)
                .done()
        }
        (ScreenId::GameSnake, Stage::Collecting(_)) => {
            let Note::Game(snake) = &view.note else {
                return Err(OUT_OF_ORDER);
            };
            // The board fills the content area: the round's state is the title.
            let over = snake.over();
            let title = if over {
                "Round over · Press to play again"
            } else {
                "Snake"
            };
            page(title)
                .centred(
                    px(BOARD_CELLS, BOARD_CELL_PX),
                    Class::Public,
                    Item::Board(snake.board()),
                )
                .offer(Key::Up, !over)
                .offer(Key::Down, !over)
                .offer(Key::Left, !over)
                .offer(Key::Right, !over)
                .offer(Key::Press, over)
                .done()
        }
        (ScreenId::DiceOnlyNotice, Stage::Collecting(_)) => {
            page("Dice only").text("Dice only").small(DICE_ONLY).done()
        }
        (ScreenId::Commitment, Stage::Committed(session)) => {
            let Some(commitment) = session.commitment() else {
                return Err(OUT_OF_ORDER);
            };
            let hex = hex_groups(&commitment);
            let width = 19 * advance(&BODY_FONT);
            page("Commitment")
                .text("Commitment C")
                .centred(width, Class::Public, Item::Hex(hex.into()))
                .small("Only verification runs need to write it down.")
                .done()
        }
        (ScreenId::Dice, Stage::Rolling(session)) => {
            let (rolls, minimum) = (session.rolls(), session.minimum_rolls());
            let picked = match view.cursor {
                0 => String::from("-"),
                face => face.to_string(),
            };
            page("Dice")
                .large(picked)
                .text(dice_text(rolls, minimum, session.millibits()))
                .small("Roll a die, pick its face, confirm. Earlier rolls are never shown.")
                .offer(Key::Press, confirm_offered(rolls, view.cursor))
                .offer(Key::Key1, undo_offered(rolls))
                .offer(Key::Key3, done_offered(rolls, minimum))
                .done()
        }
        (ScreenId::CheckPrompt, _) => page("Check for collisions")
            .text("Check for collisions before you see your words?")
            .small(CHECK_PROMPT)
            .menu(choices(ScreenId::CheckPrompt, held), view.cursor)
            .done(),
        (ScreenId::SkipConfirm, _) => page("Skip the check")
            .text("Skip the check?")
            .small(SKIP_CONFIRM)
            .menu(choices(ScreenId::SkipConfirm, held), view.cursor)
            .done(),
        (ScreenId::SnapshotDate, _) => {
            let Some(snapshot) = &held.snapshot else {
                return Err(OUT_OF_ORDER);
            };
            page("Snapshot date")
                .text(format!(
                    "Snapshot No. {}, dated {}, {} entries. Use it for this check?",
                    snapshot.number(),
                    date_text(snapshot.date()),
                    snapshot.entry_count()
                ))
                .small("The Pi has no clock: check the date yourself.")
                .menu(choices(ScreenId::SnapshotDate, held), view.cursor)
                .done()
        }
        (ScreenId::SealImage, Stage::Checking { session, .. }) => {
            let seal = session.seal();
            page("Seal card 1 of 3")
                .centred(
                    SEAL_SIDE,
                    Class::Public,
                    Item::Seal {
                        grid: seal.grid(),
                        colour_hex: seal.colour_hex(),
                        seal_id: seal.seal_id(),
                    },
                )
                .offer(Key::Key2, false)
                .done()
        }
        (ScreenId::SealId, Stage::Checking { session, .. }) => {
            seal_id(page("Seal card 2 of 3"), session.seal())?
        }
        (ScreenId::SealQr, Stage::Checking { session, .. }) => page("Seal card 3 of 3")
            .centred(
                QR_SIDE,
                Class::Public,
                Item::Qr(String::from(session.check_request().url()).into()),
            )
            .offer(Key::Key3, false)
            .done(),
        (ScreenId::CheckActions, Stage::Checking { .. }) => page("Your checker's answer")
            .small(CHECK_ACTIONS)
            .menu(choices(ScreenId::CheckActions, held), view.cursor)
            .done(),
        (ScreenId::CodeEntry, Stage::Checking { code, .. }) => {
            code_entry(page("Go-ahead code"), code, view.cursor)
        }
        (ScreenId::CodeWrong, Stage::Checking { .. }) => {
            let Note::Refused(error) = &view.note else {
                return Err(OUT_OF_ORDER);
            };
            page("Go-ahead code")
                .text("Code not accepted")
                .small(error.to_string())
                .small(CODE_WRONG)
                .done()
        }
        (ScreenId::CheckClear, Stage::Ready { .. }) => {
            let Note::Clear { seal_id, as_of } = &view.note else {
                return Err(OUT_OF_ORDER);
            };
            let result = match as_of {
                Some(date) => format!(
                    "No collision for seal {seal_id} as of {}.",
                    date_text(*date)
                ),
                None => {
                    format!("No collision for seal {seal_id}, as of the date your checker showed.")
                }
            };
            page("Check passed")
                .text(result)
                .small("Next: the words, on a private screen.")
                .done()
        }
        (ScreenId::StopConfirm, Stage::Checking { .. }) => page("Match found")
            .text("Match found?")
            .small("Only when your checker said Stop: the seed is destroyed without being shown.")
            .menu(choices(ScreenId::StopConfirm, held), view.cursor)
            .done(),
        (ScreenId::CannotCheckConfirm, Stage::Checking { .. }) => page("Cannot check")
            .text("Cannot check?")
            .small("The seed is destroyed without being shown, and a new ceremony starts.")
            .menu(choices(ScreenId::CannotCheckConfirm, held), view.cursor)
            .done(),
        (ScreenId::Collision, _) => page("Collision")
            .text("Collision found.")
            .small("This seed is not unique and has been destroyed without being shown.")
            .small(COLLISION)
            .small("Next: the collision report QR, then fresh entropy with at least 99 rolls.")
            .done(),
        (ScreenId::PrivacyGate, _) => {
            let Note::Gate { to, skipped, .. } = view.note else {
                return Err(OUT_OF_ORDER);
            };
            let mut gate = page("Privacy")
                .text("No person or camera can see this screen")
                .small("Continue only when you are alone.");
            if skipped {
                gate = gate.small(SKIPPED);
            }
            if to == ScreenId::WordsInsert {
                gate = gate.small(SEEDBOOK_RULES);
            }
            gate.done()
        }
        (ScreenId::CollisionQr, _) => {
            let Some(report) = held
                .kept
                .as_ref()
                .and_then(|wiped| wiped.collision_report())
            else {
                return Err(OUT_OF_ORDER);
            };
            page("Report collision")
                .centred(QR_SIDE, Class::Protected, Item::Qr(report.url().into()))
                .done()
        }
        (ScreenId::IdleWiped, _) => page("Wiped")
            .text("Wiped after 10 minutes without input.")
            .small("Continue returns Home.")
            .done(),
        _ => return Err(OUT_OF_ORDER),
    };
    Ok(screen)
}

/// The stop screen (Q25): the failure's fixed text on red (`ui`), and no key.
fn halt<'a>(page: Page<'a>, note: &Note) -> Screen<'a> {
    let reason = match note {
        Note::Halt(stop) => stop.to_string(),
        _ => String::from("internal failure: a halt without its reason"),
    };
    page.large("STOPPED").text(reason).small(HALTED).done()
}

/// The seal card's second page: the Seal ID large, with its braille.
fn seal_id<'a>(page: Page<'a>, seal: &'a SealPublic) -> Result<Screen<'a>, Stop> {
    let cells = caption_cells(seal.seal_id_braille()).map_err(Stop::Render)?;
    let width = px(cells.len(), CAPTION_PITCH.width);
    let item = Item::Cells {
        cells,
        pitch: CAPTION_PITCH,
    };
    Ok(page
        .small("Seal ID")
        .large(seal.seal_id())
        .centred(width, Class::Public, item)
        .small("Compare it with the seal your checker draws.")
        .done())
}

/// The go-ahead code grid (Q32 (a)): the code as typed, then the 32 symbols in 8 columns and 4
/// rows, the cursor's in brackets. Type is offered below 8 symbols, delete above none, done at 8,
/// and back to the seal card's actions always.
fn code_entry<'a>(page: Page<'a>, code: &Zeroizing<String>, cursor: usize) -> Screen<'a> {
    let typed = code.chars().count();
    let mut shown = String::with_capacity(CODE_LEN + 1);
    for (i, symbol) in code
        .chars()
        .chain(core::iter::repeat('_'))
        .take(CODE_LEN)
        .enumerate()
    {
        if i == CODE_LEN / 2 {
            shown.push('-');
        }
        shown.push(symbol);
    }
    page.small("Type the 8-character code your checker shows.")
        .large(shown)
        .text(grid_text(Grid::Code, cursor))
        .offer(Key::Press, typed < CODE_LEN)
        .offer(Key::Key1, typed > 0)
        .offer(Key::Key3, typed == CODE_LEN)
        .done()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continue_is_offered_only_at_the_quota() {
        assert!(!continue_offered(0, 512));
        assert!(!continue_offered(511, 512));
        assert!(continue_offered(512, 512));
        assert!(continue_offered(2_048, 512));
    }

    #[test]
    fn done_is_offered_only_at_the_minimum() {
        assert!(!done_offered(49, 50));
        assert!(done_offered(50, 50));
        assert!(!done_offered(98, 99));
        assert!(done_offered(99, 99));
        assert!(done_offered(256, 99));
    }

    #[test]
    fn confirm_needs_a_face_and_is_disabled_at_256_rolls() {
        for face in 1..=6 {
            assert!(confirm_offered(0, face));
            assert!(confirm_offered(255, face));
            // A 257th confirm is never offered.
            assert!(!confirm_offered(256, face));
        }
        assert!(!confirm_offered(0, 0));
        assert!(!confirm_offered(0, 7));
        assert!(!undo_offered(0));
        assert!(undo_offered(1));
    }

    #[test]
    fn skip_is_offered_only_in_sealed() {
        for stage in StageKind::ALL {
            assert_eq!(skip_offered(stage), stage == StageKind::Sealed, "{stage:?}");
        }
    }

    #[test]
    fn check_now_with_a_snapshot_asks_for_its_date_first() {
        assert_eq!(after_check_now(true), ScreenId::SnapshotDate);
        assert_eq!(after_check_now(false), ScreenId::SealImage);
    }

    #[test]
    fn the_dice_line_counts_rolls_and_tenths_of_bits() {
        // Core's millibits: 2,585 a roll.
        for (rolls, minimum, shown) in [
            (1, 50, "1 / 50 rolls, 2.5 bits"),
            (37, 50, "37 / 50 rolls, 95.6 bits"),
            (50, 50, "50 / 50 rolls, 129.2 bits"),
            (99, 99, "99 / 99 rolls, 255.9 bits"),
            (256, 99, "256 / 99 rolls, 661.7 bits"),
        ] {
            assert_eq!(dice_text(rolls, minimum, u32::from(rolls) * 2_585), shown);
        }
    }

    #[test]
    fn only_a_protected_screen_entered_from_a_public_one_is_gated() {
        for from in ScreenId::ALL {
            for to in ScreenId::ALL {
                let gated = from != ScreenId::PrivacyGate
                    && from.class() == Class::Public
                    && to.class() == Class::Protected;
                assert_eq!(
                    needs_gate(from, to),
                    gated,
                    "{} -> {}",
                    from.name(),
                    to.name()
                );
            }
        }
        assert!(needs_gate(ScreenId::Collision, ScreenId::CollisionQr));
        assert!(!needs_gate(ScreenId::PrivacyGate, ScreenId::CollisionQr));
        assert!(!needs_gate(ScreenId::CollisionQr, ScreenId::Hwrng));
    }

    #[test]
    fn a_grid_page_brackets_the_cursor_and_shows_blanks_and_spaces() {
        let code = grid_text(Grid::Code, 9);
        let rows: Vec<&str> = code.split('\n').collect();
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[1], " 8 [9] A  B  C  D  E  F ");
        assert!(rows.iter().all(|row| row.chars().count() == 24));
        let letters = grid_text(Grid::Letters, 26);
        assert_eq!(letters.split('\n').nth(3), Some(" v  w  x  y  z [_]   "));
        // The ASCII grid shows the cursor's page: a space as '·', the empty last cell blank.
        assert!(grid_text(Grid::Ascii, 0).starts_with("[·] !  \"  #"));
        let third = grid_text(Grid::Ascii, 95);
        assert!(third.starts_with(" `  a  b "));
        assert!(third.ends_with(" ~ [ ]"));
        // Built in place, '·' and all: after a press the cursor sits on the symbol just typed.
        for (grid, cursor, capacity) in [(Grid::Ascii, 0, 103), (Grid::Letters, 26, 91)] {
            let text = grid_text(grid, cursor);
            assert_eq!(text.capacity(), String::with_capacity(capacity).capacity());
        }
    }

    #[test]
    fn numbers_have_their_width_and_leading_zeros() {
        for (number, width, shown) in [
            (1, 4, "0001"),
            (2048, 4, "2048"),
            (7, 2, "07"),
            (24, 2, "24"),
        ] {
            let text = built(width, |out| push_number(out, number, width));
            assert_eq!(text.as_str(), shown);
            assert_eq!(
                text.capacity(),
                String::with_capacity(width).capacity(),
                "built in place"
            );
        }
    }

    #[test]
    fn dice_only_mode_skips_reveal_d() {
        assert_eq!(after_register(Mode::Mixed), ScreenId::RevealDOffer);
        assert_eq!(after_register(Mode::DiceOnly), ScreenId::Checklist);
    }

    #[test]
    fn the_screens_after_the_read_back_are_steps_10_to_15_and_readback_done() {
        let names: Vec<&str> = ScreenId::ALL
            .into_iter()
            .filter(|&id| after_readback(id))
            .map(ScreenId::name)
            .collect();
        assert_eq!(
            names,
            [
                "readback-done",
                "wallet",
                "backup-offer",
                "usb-insert",
                "backup-verified",
                "backup-failed",
                "backup-passphrase",
                "backup-confirm",
                "backup-confirm-wrong",
                "watch-offer",
                "bip39-ask",
                "watch-summary",
                "register-offer",
                "bip39-entry",
                "watch-account-qr",
                "watch-descriptor-qr",
                "register-qr",
                "reveal-d-offer",
                "checklist",
                "reveal-d",
            ]
        );
    }

    #[test]
    fn the_collision_screen_names_the_security_address() {
        assert!(COLLISION.contains(SECURITY));
    }

    #[test]
    fn every_menu_label_fits_a_line_after_the_mark() {
        for choice in [
            Choice::NewSeed,
            Choice::DiceOnlySeed,
            Choice::CheckBackup,
            Choice::LoadSnapshot,
            Choice::About,
            Choice::Words12,
            Choice::Words24,
            Choice::Play,
            Choice::Continue,
            Choice::CheckNow,
            Choice::Skip,
            Choice::SkipCheck,
            Choice::UseSnapshot,
            Choice::NotSnapshot,
            Choice::EnterCode,
            Choice::MatchFound,
            Choice::CannotCheck,
            Choice::Destroy,
            Choice::StartAgain,
            Choice::BackUp,
            Choice::SkipBackup,
            Choice::Retry,
            Choice::SkipFailedBackup,
            Choice::ShowWatchOnly,
            Choice::SkipWatchOnly,
            Choice::NoPassphrase,
            Choice::WithPassphrase,
            Choice::ShowRegistration,
            Choice::SkipRegistration,
            Choice::ShowD,
            Choice::SkipD,
            Choice::Recheck,
            Choice::ShowWords,
            Choice::CloseBackup,
        ] {
            assert!(choice.label().chars().count() < 24, "{choice:?}");
        }
    }
}
