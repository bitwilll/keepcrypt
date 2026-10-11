//! The screen model: what a frame shows, as data (tasks/todo.md, M3 group 5, Q29 and Q32;
//! docs/pi-firmware.md "User flow", "Buttons", "Protected screens and idle").
//!
//! - A screen is one `ScreenId`: a stable kebab-case name, a class (Public or Protected, Q29), a
//!   kind (input-waiting, or transient: shown while the app works, never while it waits for a
//!   key) and a key map. All four come from one static table, `ScreenId::row`.
//! - A `Screen` is one model of a screen: its id, the top strip (title and banners), the body
//!   elements and the footer's key labels. Screens only build models; `ui` draws them, and the
//!   HAL's `Display` receives each model with the frame drawn from it.
//! - Secret values are `Protected` elements, and only Protected ids may carry them (the simulator
//!   checks it on every present).
//! - A model borrows session and stage text, and every string it owns is `Zeroizing`, so it never
//!   owns a plain copy of a secret (rule 5). No type that can hold a secret (`Str`, `Cell`,
//!   `Item`, `Element`, `Screen`) has `Debug` or `Clone`.
//! - The layout is fixed: a 12 px top strip and a 12 px footer leave a 240×216 content area.
//!   `Screen::fits` computes every element's box from the font metrics and fixed sizes below.

use embedded_graphics::mono_font::MonoFont;
use embedded_graphics::mono_font::iso_8859_1::{FONT_6X10, FONT_10X20};
use embedded_graphics::prelude::{Point, Size};
use embedded_graphics::primitives::Rectangle;
use zeroize::{Zeroize, Zeroizing};

use crate::input::Key;

/// The top strip (step title or banners) and the footer (key labels) are 12 px each.
pub const STRIP_HEIGHT: u32 = 12;
/// What the strips leave of the 240×240 panel. Element positions are relative to its top left.
pub const CONTENT: Size = Size::new(240, 240 - 2 * STRIP_HEIGHT);
/// Body text. ISO 8859-1 rather than ASCII, so the screen copy's middle dot (·) has a glyph.
pub const BODY_FONT: MonoFont<'static> = FONT_10X20;
/// The strips, the footer and small body text.
pub const SMALL_FONT: MonoFont<'static> = FONT_6X10;
/// Words and codes are body text drawn at ×2: an 8-letter word is 160 px wide.
pub const LARGE_SCALE: u32 = 2;
/// The 8×8 seal grid is drawn 192 px square (seal-watchonly-braille.md, "The seal image").
pub const SEAL_SIDE: u32 = 192;
/// A QR code scales to fill the content area's height, quiet zone included (group 6).
pub const QR_SIDE: u32 = 216;
/// Snake's board: 18×18 cells of 12 px, 216 px square.
pub const BOARD_CELLS: usize = 18;
/// One board cell's side in pixels.
pub const BOARD_CELL_PX: u32 = 12;

/// A screen's class (Q29): Protected screens show a secret; every other screen is Public.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Public,
    Protected,
}

/// A screen's kind: does the app wait for a key while it shows?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Shown until a key (or the idle timer) moves on; some, such as `halt`, accept no key.
    InputWaiting,
    /// Shown while the app works (a self-test, a key derivation, a wipe); never while it waits.
    Transient,
}

/// Each key's action label on a screen, or none for a dead key (Q32 (a)). The footer names every
/// labelled key's action; a key without a label does nothing there. The constants are the rows of
/// pi-firmware.md's "Buttons" table, split where a screen of that kind offers fewer keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyMap {
    labels: [Option<&'static str>; Key::ALL.len()],
}

impl KeyMap {
    /// No key: transient screens, and the terminal `halt` and `power-off`.
    pub const NONE: KeyMap = KeyMap {
        labels: [None; Key::ALL.len()],
    };
    /// Menus and offers where going back would lose something.
    pub const MENU: KeyMap = KeyMap::NONE
        .with(Key::Up, "move")
        .with(Key::Down, "move")
        .with(Key::Press, "select");
    /// Menus and offers where nothing is lost by going back.
    pub const MENU_BACK: KeyMap = KeyMap::MENU.with(Key::Key1, "back");
    /// The dice: pick 1 to 6, confirm, undo, and Done (offered only at the minimum).
    pub const DICE: KeyMap = KeyMap::NONE
        .with(Key::Up, "pick")
        .with(Key::Down, "pick")
        .with(Key::Press, "confirm")
        .with(Key::Key1, "undo")
        .with(Key::Key3, "done");
    /// The words: the read-back (offered on the last insert, and when reviewing a mismatch), the
    /// overview on and off, and paging.
    pub const WORDS: KeyMap = KeyMap::NONE
        .with(Key::Press, "read-back")
        .with(Key::Key1, "overview")
        .with(Key::Key2, "prev")
        .with(Key::Key3, "next");
    /// Entry grids: the cursor, type, delete and done.
    pub const GRID: KeyMap = KeyMap::NONE
        .with(Key::Up, "cursor")
        .with(Key::Down, "cursor")
        .with(Key::Left, "cursor")
        .with(Key::Right, "cursor")
        .with(Key::Press, "type")
        .with(Key::Key1, "delete")
        .with(Key::Key3, "done");
    /// A read-back mismatch: re-enter that insert, or show it.
    pub const MISMATCH: KeyMap = KeyMap::NONE
        .with(Key::Press, "re-enter")
        .with(Key::Key1, "insert");
    /// Snake: steer, play again (offered after a round ends) and leave.
    pub const SNAKE: KeyMap = KeyMap::NONE
        .with(Key::Up, "steer")
        .with(Key::Down, "steer")
        .with(Key::Left, "steer")
        .with(Key::Right, "steer")
        .with(Key::Press, "again")
        .with(Key::Key1, "leave");
    /// Pages in a row (the seal card, the backup passphrase, the watch-only QRs, the checklist):
    /// continue and paging, with no way back.
    pub const PAGES: KeyMap = KeyMap::NONE
        .with(Key::Press, "continue")
        .with(Key::Key2, "prev")
        .with(Key::Key3, "next");
    /// One info or QR page with a way back that loses nothing.
    pub const PAGE: KeyMap = KeyMap::CONTINUE.with(Key::Key1, "back");
    /// One info or QR page that only goes on.
    pub const CONTINUE: KeyMap = KeyMap::NONE.with(Key::Press, "continue");
    /// Waiting for a USB stick, which the device notices by itself: only back.
    pub const BACK: KeyMap = KeyMap::NONE.with(Key::Key1, "back");

    /// Every key does the same thing (the idle warning, the cover).
    pub const fn every(label: &'static str) -> KeyMap {
        KeyMap {
            labels: [Some(label); Key::ALL.len()],
        }
    }

    const fn with(self, key: Key, label: &'static str) -> KeyMap {
        let mut labels = self.labels;
        labels[key.index()] = Some(label);
        KeyMap { labels }
    }

    /// This map with `key` dead: a key the screen offers only sometimes (Done below the minimum,
    /// the previous page on the first page).
    pub const fn without(self, key: Key) -> KeyMap {
        let mut labels = self.labels;
        labels[key.index()] = None;
        KeyMap { labels }
    }

    /// `key`'s action label, or `None` for a dead key.
    pub const fn label(&self, key: Key) -> Option<&'static str> {
        self.labels[key.index()]
    }

    /// True when every key is dead.
    pub fn is_empty(&self) -> bool {
        self.labels.iter().all(Option::is_none)
    }
}

listed_enum! {
/// Every screen of steps 1-15, of Home's side flows and of any step (tasks/todo.md, M3 group 8's
/// inventory). `ScreenId::row` gives each one's name, class, kind and key map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreenId {
    // Steps 1-3.
    Boot,
    Halt,
    Home,
    About,
    Length,
    Wait,
    // Steps 4-6.
    Hwrng,
    GameSnake,
    DiceOnlyNotice,
    Commitment,
    Dice,
    // Step 7.
    CheckPrompt,
    SkipConfirm,
    SnapshotDate,
    SealImage,
    SealId,
    SealQr,
    CheckActions,
    CodeEntry,
    CodeWrong,
    CheckClear,
    StopConfirm,
    Collision,
    CannotCheckConfirm,
    CollisionQr,
    // Steps 8-9.
    PrivacyGate,
    DeviceSwap,
    ReadbackDone,
    WordsInsert,
    WordsOverview,
    ReadbackEntry,
    ReadbackMismatch,
    // Steps 10-11.
    Wallet,
    BackupOffer,
    UsbInsert,
    BackupVerified,
    BackupFailed,
    BackupPassphrase,
    BackupConfirm,
    BackupConfirmWrong,
    // Steps 12-13.
    WatchOffer,
    Bip39Ask,
    WatchSummary,
    RegisterOffer,
    Bip39Entry,
    WatchAccountQr,
    WatchDescriptorQr,
    RegisterQr,
    // Steps 14-15.
    RevealDOffer,
    Checklist,
    PowerOff,
    RevealD,
    // Home's side flows: load a registry snapshot, check a backup.
    UsbPick,
    SnapshotLoaded,
    SnapshotFailed,
    BackupCheckResult,
    BackupCheckRecheckQr,
    BackupCheckEntry,
    // Any step.
    Blank,
    IdleWarning,
    IdleWiped,
    Cover,
}
}

impl ScreenId {
    /// The static table: name, class, kind and key map. Protected: the phones' list
    /// (mobile-apps.md, "Screen capture protection: iPhone") plus every entry grid that holds a
    /// secret; collision-qr carries the destroyed seed's seal code.
    const fn row(self) -> (&'static str, Class, Kind, KeyMap) {
        use Class::{Protected, Public};
        use Kind::{InputWaiting as Waiting, Transient};
        match self {
            ScreenId::Boot => ("boot", Public, Transient, KeyMap::NONE),
            ScreenId::Halt => ("halt", Public, Waiting, KeyMap::NONE),
            ScreenId::Home => ("home", Public, Waiting, KeyMap::MENU),
            ScreenId::About => ("about", Public, Waiting, KeyMap::PAGE),
            ScreenId::Length => ("length", Public, Waiting, KeyMap::MENU_BACK),
            ScreenId::Wait => ("wait", Public, Transient, KeyMap::NONE),
            ScreenId::Hwrng => ("hwrng", Public, Waiting, KeyMap::MENU),
            ScreenId::GameSnake => ("game-snake", Public, Waiting, KeyMap::SNAKE),
            ScreenId::DiceOnlyNotice => ("dice-only-notice", Public, Waiting, KeyMap::CONTINUE),
            ScreenId::Commitment => ("commitment", Public, Waiting, KeyMap::CONTINUE),
            ScreenId::Dice => ("dice", Public, Waiting, KeyMap::DICE),
            ScreenId::CheckPrompt => ("check-prompt", Public, Waiting, KeyMap::MENU),
            ScreenId::SkipConfirm => ("skip-confirm", Public, Waiting, KeyMap::MENU_BACK),
            ScreenId::SnapshotDate => ("snapshot-date", Public, Waiting, KeyMap::MENU),
            ScreenId::SealImage => ("seal-image", Public, Waiting, KeyMap::PAGES),
            ScreenId::SealId => ("seal-id", Public, Waiting, KeyMap::PAGES),
            ScreenId::SealQr => ("seal-qr", Public, Waiting, KeyMap::PAGES),
            ScreenId::CheckActions => ("check-actions", Public, Waiting, KeyMap::MENU_BACK),
            ScreenId::CodeEntry => ("code-entry", Public, Waiting, KeyMap::GRID),
            ScreenId::CodeWrong => ("code-wrong", Public, Waiting, KeyMap::CONTINUE),
            ScreenId::CheckClear => ("check-clear", Public, Waiting, KeyMap::CONTINUE),
            ScreenId::StopConfirm => ("stop-confirm", Public, Waiting, KeyMap::MENU_BACK),
            ScreenId::Collision => ("collision", Public, Waiting, KeyMap::CONTINUE),
            ScreenId::CannotCheckConfirm => {
                ("cannot-check-confirm", Public, Waiting, KeyMap::MENU_BACK)
            }
            ScreenId::CollisionQr => ("collision-qr", Protected, Waiting, KeyMap::CONTINUE),
            ScreenId::PrivacyGate => ("privacy-gate", Public, Waiting, KeyMap::CONTINUE),
            ScreenId::DeviceSwap => ("device-swap", Public, Waiting, KeyMap::CONTINUE),
            ScreenId::ReadbackDone => ("readback-done", Public, Waiting, KeyMap::CONTINUE),
            ScreenId::WordsInsert => ("words-insert", Protected, Waiting, KeyMap::WORDS),
            ScreenId::WordsOverview => ("words-overview", Protected, Waiting, KeyMap::WORDS),
            ScreenId::ReadbackEntry => ("readback-entry", Protected, Waiting, KeyMap::GRID),
            ScreenId::ReadbackMismatch => {
                ("readback-mismatch", Protected, Waiting, KeyMap::MISMATCH)
            }
            ScreenId::Wallet => ("wallet", Public, Waiting, KeyMap::CONTINUE),
            ScreenId::BackupOffer => ("backup-offer", Public, Waiting, KeyMap::MENU),
            ScreenId::UsbInsert => ("usb-insert", Public, Waiting, KeyMap::BACK),
            ScreenId::BackupVerified => ("backup-verified", Public, Waiting, KeyMap::CONTINUE),
            ScreenId::BackupFailed => ("backup-failed", Public, Waiting, KeyMap::MENU),
            ScreenId::BackupPassphrase => ("backup-passphrase", Protected, Waiting, KeyMap::PAGES),
            ScreenId::BackupConfirm => ("backup-confirm", Protected, Waiting, KeyMap::MENU),
            ScreenId::BackupConfirmWrong => {
                ("backup-confirm-wrong", Protected, Waiting, KeyMap::CONTINUE)
            }
            ScreenId::WatchOffer => ("watch-offer", Public, Waiting, KeyMap::MENU),
            ScreenId::Bip39Ask => ("bip39-ask", Public, Waiting, KeyMap::MENU),
            ScreenId::WatchSummary => ("watch-summary", Public, Waiting, KeyMap::CONTINUE),
            ScreenId::RegisterOffer => ("register-offer", Public, Waiting, KeyMap::MENU),
            ScreenId::Bip39Entry => ("bip39-entry", Protected, Waiting, KeyMap::GRID),
            ScreenId::WatchAccountQr => ("watch-account-qr", Protected, Waiting, KeyMap::PAGES),
            ScreenId::WatchDescriptorQr => {
                ("watch-descriptor-qr", Protected, Waiting, KeyMap::PAGES)
            }
            ScreenId::RegisterQr => ("register-qr", Protected, Waiting, KeyMap::CONTINUE),
            ScreenId::RevealDOffer => ("reveal-d-offer", Public, Waiting, KeyMap::MENU),
            ScreenId::Checklist => ("checklist", Public, Waiting, KeyMap::PAGES),
            ScreenId::PowerOff => ("power-off", Public, Waiting, KeyMap::NONE),
            ScreenId::RevealD => ("reveal-d", Protected, Waiting, KeyMap::CONTINUE),
            ScreenId::UsbPick => ("usb-pick", Public, Waiting, KeyMap::MENU_BACK),
            ScreenId::SnapshotLoaded => ("snapshot-loaded", Public, Waiting, KeyMap::CONTINUE),
            ScreenId::SnapshotFailed => ("snapshot-failed", Public, Waiting, KeyMap::CONTINUE),
            ScreenId::BackupCheckResult => ("backup-check-result", Public, Waiting, KeyMap::MENU),
            ScreenId::BackupCheckRecheckQr => {
                ("backup-check-recheck-qr", Public, Waiting, KeyMap::PAGE)
            }
            ScreenId::BackupCheckEntry => ("backup-check-entry", Protected, Waiting, KeyMap::GRID),
            ScreenId::Blank => ("blank", Public, Transient, KeyMap::NONE),
            ScreenId::IdleWarning => ("idle-warning", Public, Waiting, KeyMap::every("keep")),
            ScreenId::IdleWiped => ("idle-wiped", Public, Waiting, KeyMap::CONTINUE),
            ScreenId::Cover => ("cover", Public, Waiting, KeyMap::every("show")),
        }
    }

    /// The stable kebab-case name: screen captures, the simulator's log and the scenarios use it.
    pub const fn name(self) -> &'static str {
        self.row().0
    }

    /// Public or Protected (Q29).
    pub const fn class(self) -> Class {
        self.row().1
    }

    /// Input-waiting or transient.
    pub const fn kind(self) -> Kind {
        self.row().2
    }

    /// Every key this screen can ever offer, with its label. A model may offer fewer
    /// (`Screen::without`), never more.
    pub const fn key_map(self) -> KeyMap {
        self.row().3
    }
}

/// Text an element or the strip shows: borrowed, or owned and wiped on drop. Every owned string is
/// `Zeroizing`, public counts and labels too, so a model never owns a plain copy of a secret.
pub enum Str<'a> {
    /// A fixed label, or text the session or the stage holds (and wipes).
    Borrowed(&'a str),
    /// Text formatted for this model: counts, dates, and D's hex (rule 5).
    Owned(Zeroizing<String>),
}

impl Str<'_> {
    /// The text.
    pub fn as_str(&self) -> &str {
        match self {
            Str::Borrowed(text) => text,
            Str::Owned(text) => text.as_str(),
        }
    }
}

impl<'a> From<&'a str> for Str<'a> {
    fn from(text: &'a str) -> Self {
        Str::Borrowed(text)
    }
}

impl From<String> for Str<'_> {
    /// Moves the string into a `Zeroizing` buffer, with no copy.
    fn from(text: String) -> Self {
        Str::Owned(Zeroizing::new(text))
    }
}

impl From<Zeroizing<String>> for Str<'_> {
    fn from(text: Zeroizing<String>) -> Self {
        Str::Owned(text)
    }
}

/// One braille cell as drawn: a face of an insert, or a cell of the Seal ID's braille. Wiped with
/// its element: a face's dots are a letter of the seed.
#[derive(Zeroize)]
pub struct Cell {
    /// The raised dots, dot d at bit d - 1 (core's `Dots::bits`); 0 for a blank face.
    pub dots: u8,
    /// A blank face: left unpunched, drawn as rings labelled "leave blank".
    pub blank: bool,
    /// Face 5, the redundancy check, drawn lighter (core's `Face::is_lighter`).
    pub lighter: bool,
    /// A letter with a mirror partner (e/i, d/f, h/j, r/w), flagged to read twice.
    pub mirror: bool,
}

/// One cell of Snake's board.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tile {
    Empty,
    Snake,
    Food,
}

/// What an element shows.
pub enum Item<'a> {
    /// Body text in `BODY_FONT`, wrapped (`wrap`) at the content area's right edge.
    Text(Str<'a>),
    /// Small text in `SMALL_FONT`, wrapped the same way.
    Small(Str<'a>),
    /// A word or a code in `BODY_FONT` at `LARGE_SCALE`, on one line. Characters from
    /// `lighter_from` on are drawn lighter (an insert's letters past the fourth).
    Large {
        text: Str<'a>,
        lighter_from: Option<usize>,
    },
    /// Braille cells in a row, each in a box of `pitch`.
    Cells {
        cells: Zeroizing<Vec<Cell>>,
        pitch: Size,
    },
    /// The 8×8 seal grid, `SEAL_SIDE` square, in core's `SealPublic::grid` and `colour_hex`.
    Seal {
        grid: &'a [[bool; 8]; 8],
        colour_hex: &'a str,
    },
    /// A QR code of this payload, `QR_SIDE` square.
    Qr(Str<'a>),
    /// 32 bytes as 16 groups of 4 hex digits: one line per row, not wrapped (C, D).
    Hex(Str<'a>),
    /// Snake's board, row by row, `BOARD_CELLS` × `BOARD_CELL_PX` square.
    Board(&'a [[Tile; BOARD_CELLS]; BOARD_CELLS]),
}

/// One element of a model: what it shows, where, and whether it is a secret.
pub struct Element<'a> {
    at: Point,
    class: Class,
    item: Item<'a>,
}

impl<'a> Element<'a> {
    /// Public content at `at`, the top left of its box in the content area.
    pub fn public(at: Point, item: Item<'a>) -> Self {
        Element {
            at,
            class: Class::Public,
            item,
        }
    }

    /// A secret at `at`: only a Protected screen may show it.
    pub fn protected(at: Point, item: Item<'a>) -> Self {
        Element {
            at,
            class: Class::Protected,
            item,
        }
    }

    /// The top left of the element's box in the content area.
    pub fn at(&self) -> Point {
        self.at
    }

    /// Public, or Protected for a secret.
    pub fn class(&self) -> Class {
        self.class
    }

    /// What the element shows.
    pub fn item(&self) -> &Item<'a> {
        &self.item
    }

    /// The element's box in the content area, from the font metrics and the fixed sizes.
    pub fn bounds(&self) -> Rectangle {
        let size = match &self.item {
            Item::Text(text) => wrapped_size(text.as_str(), &BODY_FONT, self.at.x),
            Item::Small(text) => wrapped_size(text.as_str(), &SMALL_FONT, self.at.x),
            Item::Large { text, .. } => Size::new(
                px(
                    text.as_str().chars().count(),
                    advance(&BODY_FONT) * LARGE_SCALE,
                ),
                BODY_FONT.character_size.height * LARGE_SCALE,
            ),
            Item::Cells { cells, pitch } => Size::new(px(cells.len(), pitch.width), pitch.height),
            Item::Seal { .. } => Size::new(SEAL_SIDE, SEAL_SIDE),
            Item::Qr(_) => Size::new(QR_SIDE, QR_SIDE),
            Item::Hex(text) => lines_size(text.as_str().split('\n'), &BODY_FONT),
            Item::Board(_) => {
                let side = px(BOARD_CELLS, BOARD_CELL_PX);
                Size::new(side, side)
            }
        };
        Rectangle::new(self.at, size)
    }
}

/// Which banners the top strip carries; they take precedence over the step title (Q33 (j)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Banners {
    /// The build pins the test registry key (`registry_key_is_test`): "TEST REGISTRY".
    pub test_registry: bool,
    /// The simulator (`hal::BuildInfo::simulator`): "SIMULATOR".
    pub simulator: bool,
}

/// One model of a screen: the id, the top strip, the body and the footer's key labels.
pub struct Screen<'a> {
    id: ScreenId,
    title: Str<'a>,
    banners: Banners,
    elements: Vec<Element<'a>>,
    keys: KeyMap,
}

impl<'a> Screen<'a> {
    /// An empty model of `id`, offering every key of `id`'s key map.
    pub fn new(id: ScreenId, title: impl Into<Str<'a>>, banners: Banners) -> Self {
        Screen {
            id,
            title: title.into(),
            banners,
            elements: Vec::new(),
            keys: id.key_map(),
        }
    }

    /// This model with `element` added.
    pub fn with(mut self, element: Element<'a>) -> Self {
        self.elements.push(element);
        self
    }

    /// This model with `key` dead, for a key `id` offers only sometimes.
    pub fn without(mut self, key: Key) -> Self {
        self.keys = self.keys.without(key);
        self
    }

    pub fn id(&self) -> ScreenId {
        self.id
    }

    /// The step title, shown when no banner is.
    pub fn title(&self) -> &str {
        self.title.as_str()
    }

    pub fn banners(&self) -> Banners {
        self.banners
    }

    pub fn elements(&self) -> &[Element<'a>] {
        &self.elements
    }

    /// The keys this model offers, with the labels the footer shows.
    pub fn keys(&self) -> KeyMap {
        self.keys
    }

    /// True when any element is Protected. Only a Protected id may carry one.
    pub fn has_protected(&self) -> bool {
        self.elements
            .iter()
            .any(|element| element.class == Class::Protected)
    }

    /// True when the title fits the top strip in `SMALL_FONT` and every element's box lies inside
    /// the content area.
    pub fn fits(&self) -> bool {
        let title = px(self.title().chars().count(), advance(&SMALL_FONT));
        title <= CONTENT.width
            && self
                .elements
                .iter()
                .all(|element| inside_content(element.bounds()))
    }
}

/// `text` broken into lines of at most `max` characters: at each '\n', at the last space that
/// leaves the line short enough (that space is dropped), and inside a word longer than a line.
/// The renderer draws exactly these lines. A `max` of 0 is taken as 1.
pub fn wrap(text: &str, max: u32) -> Vec<&str> {
    let max = max.max(1);
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        let mut rest = paragraph;
        loop {
            // Character `max` is the first that does not fit on this line.
            let Some(cut) = char_offset(rest, max) else {
                lines.push(rest);
                break;
            };
            let space = if rest[cut..].starts_with(' ') {
                Some(cut)
            } else {
                rest[..cut].rfind(' ')
            };
            match space {
                Some(0) => rest = &rest[1..],
                Some(space) => {
                    lines.push(&rest[..space]);
                    rest = &rest[space + 1..];
                    if rest.is_empty() {
                        break;
                    }
                }
                None => {
                    lines.push(&rest[..cut]);
                    rest = &rest[cut..];
                }
            }
        }
    }
    lines
}

/// The byte offset of character `n` (from 0) of `text`, or `None` if it has `n` or fewer.
fn char_offset(text: &str, n: u32) -> Option<usize> {
    text.char_indices()
        .zip(0u32..)
        .find_map(|((offset, _), index)| (index == n).then_some(offset))
}

/// One character's horizontal advance in `font`.
fn advance(font: &MonoFont<'_>) -> u32 {
    font.character_size.width + font.character_spacing
}

/// `count` units of `unit` pixels, saturating: a count too large for `u32` never fits.
fn px(count: usize, unit: u32) -> u32 {
    match u32::try_from(count) {
        Ok(count) => count.saturating_mul(unit),
        Err(_) => u32::MAX,
    }
}

/// The box of `text` in `font`, wrapped at the content area's right edge from `x`.
fn wrapped_size(text: &str, font: &MonoFont<'_>, x: i32) -> Size {
    // The characters from `x` to the right edge; none from outside the area, so any text there
    // is too wide.
    let room = match u32::try_from(x) {
        Ok(x) if x < CONTENT.width => (CONTENT.width - x) / advance(font),
        _ => 0,
    };
    lines_size(wrap(text, room).into_iter(), font)
}

/// The box of these lines in `font`: the longest line's width, one line height per line.
fn lines_size<'t>(lines: impl Iterator<Item = &'t str>, font: &MonoFont<'_>) -> Size {
    let mut count = 0;
    let mut longest = 0;
    for line in lines {
        count += 1;
        longest = longest.max(line.chars().count());
    }
    Size::new(
        px(longest, advance(font)),
        px(count, font.character_size.height),
    )
}

/// True when `bounds` lies inside the content area.
fn inside_content(bounds: Rectangle) -> bool {
    let left = i64::from(bounds.top_left.x);
    let top = i64::from(bounds.top_left.y);
    left >= 0
        && top >= 0
        && left + i64::from(bounds.size.width) <= i64::from(CONTENT.width)
        && top + i64::from(bounds.size.height) <= i64::from(CONTENT.height)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    const NO_BANNERS: Banners = Banners {
        test_registry: false,
        simulator: false,
    };

    fn names(filter: impl Fn(ScreenId) -> bool) -> Vec<&'static str> {
        ScreenId::ALL
            .into_iter()
            .filter(|&id| filter(id))
            .map(ScreenId::name)
            .collect()
    }

    fn one(id: ScreenId, element: Element<'_>) -> Screen<'_> {
        Screen::new(id, "Title", NO_BANNERS).with(element)
    }

    fn text(at: (i32, i32), text: &str) -> Element<'_> {
        Element::public(Point::new(at.0, at.1), Item::Text(text.into()))
    }

    #[test]
    fn all_has_62_unique_kebab_case_names_that_match_their_variants() {
        assert_eq!(ScreenId::ALL.len(), 62);
        let unique: BTreeSet<&str> = ScreenId::ALL.into_iter().map(ScreenId::name).collect();
        assert_eq!(unique.len(), ScreenId::ALL.len(), "a name is used twice");
        for id in ScreenId::ALL {
            let mut kebab = String::new();
            for (i, c) in format!("{id:?}").chars().enumerate() {
                if c.is_ascii_uppercase() && i > 0 {
                    kebab.push('-');
                }
                kebab.push(c.to_ascii_lowercase());
            }
            assert_eq!(id.name(), kebab);
        }
    }

    #[test]
    fn the_protected_screens_are_q29s() {
        assert_eq!(
            names(|id| id.class() == Class::Protected),
            [
                "collision-qr",
                "words-insert",
                "words-overview",
                "readback-entry",
                "readback-mismatch",
                "backup-passphrase",
                "backup-confirm",
                "backup-confirm-wrong",
                "bip39-entry",
                "watch-account-qr",
                "watch-descriptor-qr",
                "register-qr",
                "reveal-d",
                "backup-check-entry",
            ]
        );
    }

    #[test]
    fn transient_screens_have_no_key_and_only_halt_and_power_off_wait_for_none() {
        assert_eq!(
            names(|id| id.kind() == Kind::Transient),
            ["boot", "wait", "blank"]
        );
        for id in ScreenId::ALL {
            if id.kind() == Kind::Transient {
                assert!(id.key_map().is_empty(), "{}", id.name());
            }
        }
        assert_eq!(
            names(|id| id.kind() == Kind::InputWaiting && id.key_map().is_empty()),
            ["halt", "power-off"]
        );
    }

    #[test]
    fn every_label_is_a_short_lowercase_word() {
        for id in ScreenId::ALL {
            for key in Key::ALL {
                if let Some(label) = id.key_map().label(key) {
                    assert!(
                        (1..=9).contains(&label.len())
                            && label.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                        "{}: {label:?}",
                        id.name()
                    );
                }
            }
        }
    }

    #[test]
    fn the_key_maps_follow_the_buttons_table() {
        let dice = ScreenId::Dice.key_map();
        assert_eq!(dice.label(Key::Key1), Some("undo"));
        assert_eq!(dice.label(Key::Key3), Some("done"));
        assert_eq!(dice.label(Key::Key2), None);
        let words = ScreenId::WordsInsert.key_map();
        assert_eq!(words.label(Key::Key1), Some("overview"));
        assert_eq!(words.label(Key::Key2), Some("prev"));
        assert_eq!(words.label(Key::Key3), Some("next"));
        assert_eq!(words.label(Key::Up), None);
        for id in [ScreenId::Cover, ScreenId::IdleWarning] {
            assert!(
                Key::ALL
                    .into_iter()
                    .all(|key| id.key_map().label(key).is_some())
            );
        }
        // A model offers fewer keys than its id, never more.
        let below_minimum = Screen::new(ScreenId::Dice, "Dice", NO_BANNERS).without(Key::Key3);
        assert_eq!(below_minimum.keys().label(Key::Key3), None);
        assert_eq!(below_minimum.keys(), dice.without(Key::Key3));
        assert_eq!(below_minimum.keys().label(Key::Key1), Some("undo"));
    }

    #[test]
    fn wrap_breaks_at_spaces_newlines_and_inside_long_words() {
        assert_eq!(wrap("one two three", 7), ["one two", "three"]);
        // A space exactly at the break is dropped, and so is a leading one; a trailing one makes
        // no empty line.
        assert_eq!(wrap("abcdefg hij", 7), ["abcdefg", "hij"]);
        assert_eq!(wrap(" abcdefgh", 4), ["abcd", "efgh"]);
        assert_eq!(wrap("abcd ", 4), ["abcd"]);
        assert_eq!(wrap("first\nsecond", 24), ["first", "second"]);
        assert_eq!(wrap("", 24), [""]);
        assert_eq!(wrap("abcdefghij", 4), ["abcd", "efgh", "ij"]);
        // Characters, not bytes: the middle dot is two bytes and one glyph.
        assert_eq!(wrap("a·b·c d", 5), ["a·b·c", "d"]);
        assert_eq!(wrap("ab", 0), ["a", "b"]);
        // 24 body characters fill the content width.
        let line = "x".repeat(24);
        assert_eq!(wrap(&line, 24), [line.as_str()]);
    }

    #[test]
    fn element_boxes_come_from_the_font_metrics() {
        let size = |element: Element<'_>| element.bounds().size;
        assert_eq!(size(text((0, 0), "Dice")), Size::new(40, 20));
        // 30 characters at 10 px wrap into two lines of the 240 px width; from x = 40, into 20.
        let thirty = "abcde fghij klmno pqrst uvwxy z";
        assert_eq!(size(text((0, 0), thirty)), Size::new(230, 40));
        assert_eq!(size(text((40, 0), thirty)), Size::new(170, 40));
        let small = Element::public(Point::zero(), Item::Small(thirty.into()));
        assert_eq!(size(small), Size::new(186, 10));
        let word = Element::protected(
            Point::zero(),
            Item::Large {
                text: "abstract".into(),
                lighter_from: Some(4),
            },
        );
        assert_eq!(size(word), Size::new(160, 40));
        let hex = [
            "0001 0203 0405 0607",
            "0809 0a0b 0c0d 0e0f",
            "1011 1213 1415 1617",
            "1819 1a1b 1c1d 1e1f",
        ]
        .join("\n");
        assert_eq!(
            size(Element::public(Point::zero(), Item::Hex(hex.into()))),
            Size::new(190, 80)
        );
        let cells = Zeroizing::new(
            (0..5)
                .map(|i| Cell {
                    dots: i,
                    blank: false,
                    lighter: i == 4,
                    mirror: false,
                })
                .collect(),
        );
        let face_cells = Item::Cells {
            cells,
            pitch: Size::new(44, 70),
        };
        assert_eq!(
            size(Element::protected(Point::zero(), face_cells)),
            Size::new(220, 70)
        );
        let grid = [[true; 8]; 8];
        let seal = Item::Seal {
            grid: &grid,
            colour_hex: "#009E73",
        };
        assert_eq!(
            size(Element::public(Point::zero(), seal)),
            Size::new(192, 192)
        );
        let qr = Item::Qr("https://registry.invalid/c".into());
        assert_eq!(
            size(Element::public(Point::zero(), qr)),
            Size::new(216, 216)
        );
        let board = [[Tile::Empty; BOARD_CELLS]; BOARD_CELLS];
        assert_eq!(
            size(Element::public(Point::zero(), Item::Board(&board))),
            Size::new(216, 216)
        );
    }

    #[test]
    fn a_model_fits_only_inside_the_content_area() {
        assert_eq!(CONTENT, Size::new(240, 216));
        let id = ScreenId::About;
        assert!(Screen::new(id, "About", NO_BANNERS).fits());
        // The last body line ends at y = 216.
        assert!(one(id, text((0, 196), "Bottom line")).fits());
        assert!(!one(id, text((0, 197), "One pixel past")).fits());
        assert!(!one(id, text((0, -1), "Above the area")).fits());
        // Wrapping keeps text inside the width; a long text runs out of height instead.
        assert!(one(id, text((0, 0), &"word ".repeat(50))).fits());
        assert!(!one(id, text((0, 0), &"word ".repeat(60))).fits());
        assert!(!one(id, text((240, 0), "x")).fits());
        assert!(!one(id, text((-10, 0), "x")).fits());
        // A word at ×2 does not wrap: 12 letters fit the width, 13 do not.
        let large = |letters: usize| {
            Element::public(
                Point::zero(),
                Item::Large {
                    text: "w".repeat(letters).into(),
                    lighter_from: None,
                },
            )
        };
        assert!(one(id, large(12)).fits());
        assert!(!one(id, large(13)).fits());
        // A QR fills the height: centred it fits, one pixel lower it does not.
        let qr = |x, y| Element::public(Point::new(x, y), Item::Qr("payload".into()));
        assert!(one(ScreenId::SealQr, qr(12, 0)).fits());
        assert!(one(ScreenId::SealQr, qr(24, 0)).fits());
        assert!(!one(ScreenId::SealQr, qr(25, 0)).fits());
        assert!(!one(ScreenId::SealQr, qr(12, 1)).fits());
        // The title has 40 characters of the strip font.
        assert!(Screen::new(id, "t".repeat(40), NO_BANNERS).fits());
        assert!(!Screen::new(id, "t".repeat(41), NO_BANNERS).fits());
        // Several elements: one outside is enough to fail.
        let two = one(id, text((0, 0), "Top")).with(text((0, 200), "Too low"));
        assert!(!two.fits());
    }

    #[test]
    fn has_protected_sees_any_protected_element() {
        let public = one(ScreenId::Wallet, text((0, 0), "Fingerprint"));
        assert!(!public.has_protected());
        let secret = Element::protected(Point::zero(), Item::Text("word".into()));
        let protected = one(ScreenId::WordsInsert, text((0, 0), "Insert 01")).with(secret);
        assert!(protected.has_protected());
        assert_eq!(protected.id().class(), Class::Protected);
        assert_eq!(protected.elements().len(), 2);
    }

    #[test]
    fn owned_text_is_zeroizing_and_borrowed_text_is_not_copied() {
        let label = "Dice";
        let borrowed = Str::from(label);
        assert!(matches!(borrowed, Str::Borrowed(text) if std::ptr::eq(text, label)));
        let owned = Str::from(format!("{} / {} rolls", 37, 50));
        assert!(matches!(owned, Str::Owned(_)));
        assert_eq!(owned.as_str(), "37 / 50 rolls");
    }
}
