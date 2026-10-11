//! The simulated panel (tasks/todo.md, M3 group 7, Q30 (f)-(h)): every present is checked,
//! logged and, in capture mode, written as a PNG file.
//!
//! - Two invariants hold on every present, or the test fails: a Protected element appears only on
//!   a Protected screen, and the model fits the screen (`Screen::fits`).
//! - The log keeps, per present, an owned copy of the model (every string `Zeroizing`) and a copy
//!   of the frame, until the scenario takes it (`SimHal::take_presents`). Nothing here prints.
//! - Capture mode writes each present as `NNN-<screen-id>.png`, NNN counting from 001. A
//!   Protected frame is written as drawn only for a run whose words are public (a vector run);
//!   otherwise it is `placeholder`, which depends on the screen id alone.

use std::fs;
use std::path::PathBuf;

use keepcrypt_pi::hal::{Display, HalError, Zeroizing};
use keepcrypt_pi::input::Key;
use keepcrypt_pi::screen::{
    BOARD_CELLS, Banners, CONTENT, Cell, Class, Element, Item, KeyMap, Screen, ScreenId, Str, Tile,
};
use keepcrypt_pi::ui::{Frame, Painter};

use crate::png;

/// The panel's side in pixels (`keepcrypt_pi::ui::SIDE`).
const SIDE: usize = 240;
/// The placeholder's background: RGB565 (12, 24, 12), #636163 at 8 bits. White text on it has a
/// contrast ratio above 6.
const GREY: u16 = 0x630c;

/// A copy of one frame: 240 × 240 raw RGB565 values, row by row from the top left. Wiped on drop;
/// no `Debug` or `Clone`, since a frame can show the words.
pub struct Pixels {
    raw: Zeroizing<Vec<u16>>,
}

impl Pixels {
    fn of(frame: &Frame) -> Self {
        let raw = frame.raw();
        assert_eq!(raw.len(), SIDE * SIDE, "a frame is 240 × 240");
        Pixels {
            raw: Zeroizing::new(raw.to_vec()),
        }
    }

    /// The raw RGB565 values, row by row.
    pub fn raw(&self) -> &[u16] {
        &self.raw
    }

    /// The pixel at column `x`, row `y`, or `None` off the panel.
    pub fn at(&self, x: usize, y: usize) -> Option<u16> {
        (x < SIDE && y < SIDE).then(|| self.raw[y * SIDE + x])
    }

    /// The frame as a PNG file.
    pub fn png(&self) -> Zeroizing<Vec<u8>> {
        png::encode(SIDE, &self.raw)
    }
}

/// What one element showed, owned. No `Debug` or `Clone`.
pub enum Shown {
    Text(Zeroizing<String>),
    Small(Zeroizing<String>),
    Large {
        text: Zeroizing<String>,
        lighter_from: Option<usize>,
    },
    Cells(Zeroizing<Vec<Cell>>),
    Seal {
        grid: [[bool; 8]; 8],
        colour_hex: Zeroizing<String>,
        seal_id: Zeroizing<String>,
    },
    Qr(Zeroizing<String>),
    Hex(Zeroizing<String>),
    /// Boxed: 324 bytes, against at most 112 for the other kinds.
    Board(Box<[[Tile; BOARD_CELLS]; BOARD_CELLS]>),
}

impl Shown {
    /// The text of a text, word, QR or hex element; `None` for cells, the seal and the board.
    pub fn text(&self) -> Option<&str> {
        match self {
            Shown::Text(text)
            | Shown::Small(text)
            | Shown::Large { text, .. }
            | Shown::Qr(text)
            | Shown::Hex(text) => Some(text),
            Shown::Cells(_) | Shown::Seal { .. } | Shown::Board(_) => None,
        }
    }
}

/// One element of a presented model: its class, its position in the content area and what it
/// showed.
pub struct Logged {
    pub class: Class,
    pub at: (i32, i32),
    pub item: Shown,
}

/// The PNG file a present was captured to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    /// The file name in the capture directory: `NNN-<screen-id>.png`.
    pub file: String,
    /// True when the file holds `placeholder` instead of the frame.
    pub placeholder: bool,
}

/// One present as the log keeps it: the model's id, title, banners, offered keys and elements, the
/// frame drawn from it, and its capture.
pub struct Present {
    pub id: ScreenId,
    pub title: Zeroizing<String>,
    pub banners: Banners,
    pub keys: KeyMap,
    pub elements: Vec<Logged>,
    pub frame: Pixels,
    pub capture: Option<Captured>,
}

/// What capture mode writes for a Protected screen (Q30 (g), (h)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedFrames {
    /// The frame as drawn: only for vector runs, whose words come from public roll strings.
    AsDrawn,
    /// `placeholder`: throwaway runs and live mode.
    Placeholder,
}

/// Where and how presents are captured.
struct Capture {
    dir: PathBuf,
    protected: ProtectedFrames,
    written: u32,
}

impl Capture {
    /// Writes one present's PNG file, or fails the test.
    fn write(&mut self, id: ScreenId, frame: &Pixels) -> Captured {
        self.written += 1;
        let file = format!("{:03}-{}.png", self.written, id.name());
        let redact =
            id.class() == Class::Protected && self.protected == ProtectedFrames::Placeholder;
        let png = if redact {
            placeholder(id).png()
        } else {
            frame.png()
        };
        let target = self.dir.join(&file);
        if let Err(error) = fs::write(&target, &png[..]) {
            panic!("cannot write {}: {error}", target.display());
        }
        Captured {
            file,
            placeholder: redact,
        }
    }
}

/// The panel's state: the log, the screen showing, and the capture.
pub(crate) struct Panel {
    log: Vec<Present>,
    showing: Option<ScreenId>,
    capture: Option<Capture>,
}

impl Panel {
    pub(crate) fn new() -> Self {
        Panel {
            log: Vec::new(),
            showing: None,
            capture: None,
        }
    }

    /// From now on, writes every present into `dir` (created if missing).
    pub(crate) fn capture(&mut self, dir: PathBuf, protected: ProtectedFrames) {
        if let Err(error) = fs::create_dir_all(&dir) {
            panic!("cannot create {}: {error}", dir.display());
        }
        self.capture = Some(Capture {
            dir,
            protected,
            written: 0,
        });
    }

    /// The id of the last model presented.
    pub(crate) fn showing(&self) -> Option<ScreenId> {
        self.showing
    }

    pub(crate) fn take(&mut self) -> Vec<Present> {
        std::mem::take(&mut self.log)
    }

    /// `hal::Display::present`: checks the two invariants, then logs (and captures) the present.
    pub(crate) fn present(&mut self, frame: &Frame, screen: &Screen<'_>) {
        let id = screen.id();
        assert!(
            !screen.has_protected() || id.class() == Class::Protected,
            "{}: a Protected element on a Public screen",
            id.name()
        );
        assert!(
            screen.fits(),
            "{}: the model does not fit the screen",
            id.name()
        );
        let frame = Pixels::of(frame);
        let capture = self.capture.as_mut().map(|c| c.write(id, &frame));
        self.log.push(Present {
            id,
            title: owned(screen.title()),
            banners: screen.banners(),
            keys: screen.keys(),
            elements: screen.elements().iter().map(logged).collect(),
            frame,
            capture,
        });
        self.showing = Some(id);
    }
}

fn owned(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_owned())
}

fn owned_str(text: &Str<'_>) -> Zeroizing<String> {
    owned(text.as_str())
}

/// An owned copy of one element.
fn logged(element: &Element<'_>) -> Logged {
    let item = match element.item() {
        Item::Text(text) => Shown::Text(owned_str(text)),
        Item::Small(text) => Shown::Small(owned_str(text)),
        Item::Large { text, lighter_from } => Shown::Large {
            text: owned_str(text),
            lighter_from: *lighter_from,
        },
        Item::Cells { cells, .. } => Shown::Cells(Zeroizing::new(
            cells
                .iter()
                .map(|cell| Cell {
                    dots: cell.dots,
                    blank: cell.blank,
                    lighter: cell.lighter,
                    mirror: cell.mirror,
                })
                .collect(),
        )),
        Item::Seal {
            grid,
            colour_hex,
            seal_id,
        } => Shown::Seal {
            grid: **grid,
            colour_hex: owned(colour_hex),
            seal_id: owned(seal_id),
        },
        Item::Qr(payload) => Shown::Qr(owned_str(payload)),
        Item::Hex(hex) => Shown::Hex(owned_str(hex)),
        Item::Board(tiles) => Shown::Board(Box::new(**tiles)),
    };
    let at = element.at();
    Logged {
        class: element.class(),
        at: (at.x, at.y),
        item,
    }
}

/// A display that keeps a copy of the one frame it is given.
struct Grab(Option<Pixels>);

impl Display for Grab {
    fn present(&mut self, frame: &Frame, _screen: &Screen<'_>) -> Result<(), HalError> {
        self.0 = Some(Pixels::of(frame));
        Ok(())
    }
}

/// The grey placeholder for a Protected frame that is not captured (Q30 (g), (h)): "Protected
/// screen", the screen id and "simulator placeholder: not captured", drawn by pi/app's renderer
/// in white on grey, with no strip and no keys. It depends on `id` alone, so it holds nothing of
/// the frame it replaces.
pub fn placeholder(id: ScreenId) -> Pixels {
    let lines = [
        (86, "Protected screen", false),
        (110, id.name(), false),
        (140, "simulator placeholder: not captured", true),
    ];
    let no_banners = Banners {
        test_registry: false,
        simulator: false,
    };
    let mut model = Key::ALL
        .into_iter()
        .fold(Screen::new(id, "", no_banners), Screen::without);
    for (y, text, small) in lines {
        let line = |x: i32| {
            let item = if small {
                Item::Small(text.into())
            } else {
                Item::Text(text.into())
            };
            Element::public((x, y).into(), item)
        };
        // Centred: the line's measured width, from x = 0.
        let width = line(0).bounds().size.width;
        let x = i32::try_from(CONTENT.width.saturating_sub(width) / 2).expect("an x on the panel");
        model = model.with(line(x));
    }
    let mut grab = Grab(None);
    if let Err(error) = Painter::new().present(&mut grab, &model) {
        panic!("the placeholder cannot be drawn: {}", error.text());
    }
    let Some(mut pixels) = grab.0 else {
        panic!("the placeholder was not presented");
    };
    for pixel in pixels.raw.iter_mut() {
        if *pixel == 0 {
            *pixel = GREY;
        }
    }
    pixels
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    const NO_BANNERS: Banners = Banners {
        test_registry: false,
        simulator: false,
    };

    fn present(panel: &mut Panel, screen: &Screen<'_>) {
        struct Feed<'p>(&'p mut Panel);
        impl Display for Feed<'_> {
            fn present(&mut self, frame: &Frame, screen: &Screen<'_>) -> Result<(), HalError> {
                self.0.present(frame, screen);
                Ok(())
            }
        }
        Painter::new()
            .present(&mut Feed(panel), screen)
            .expect("the model draws");
    }

    #[test]
    fn each_present_logs_an_owned_copy_of_its_model_and_frame() {
        let mut panel = Panel::new();
        assert_eq!(panel.showing(), None);
        let grid = [[false; 8]; 8];
        let word = Zeroizing::new(String::from("abstract"));
        let screen = Screen::new(ScreenId::WordsInsert, "Insert 01", NO_BANNERS)
            .with(Element::protected(
                (40, 0).into(),
                Item::Large {
                    text: word.as_str().into(),
                    lighter_from: Some(4),
                },
            ))
            .with(Element::public((0, 50).into(), Item::Small("0004".into())))
            .without(Key::Press);
        present(&mut panel, &screen);
        let seal = Screen::new(ScreenId::SealImage, "Seal", NO_BANNERS).with(Element::public(
            (24, 0).into(),
            Item::Seal {
                grid: &grid,
                colour_hex: "#0072B2",
                seal_id: "5E0G7J6X",
            },
        ));
        present(&mut panel, &seal);
        assert_eq!(panel.showing(), Some(ScreenId::SealImage));
        // The log owns its copy: the app's buffers can go.
        drop(screen);
        drop(word);

        let log = panel.take();
        assert!(panel.take().is_empty(), "taking the log empties it");
        assert_eq!(log.len(), 2);
        let insert = &log[0];
        assert_eq!(insert.id, ScreenId::WordsInsert);
        assert_eq!(&insert.title[..], "Insert 01");
        assert_eq!(
            insert.keys,
            ScreenId::WordsInsert.key_map().without(Key::Press)
        );
        assert_eq!(insert.elements.len(), 2);
        assert_eq!(insert.elements[0].class, Class::Protected);
        assert_eq!(insert.elements[0].at, (40, 0));
        assert!(matches!(
            &insert.elements[0].item,
            Shown::Large { text, lighter_from: Some(4) } if &text[..] == "abstract"
        ));
        assert_eq!(insert.elements[1].item.text(), Some("0004"));
        assert!(insert.frame.raw().iter().any(|&p| p != 0));
        assert_eq!(insert.capture, None);
        let Shown::Seal { seal_id, .. } = &log[1].elements[0].item else {
            panic!("a seal element");
        };
        assert_eq!(&seal_id[..], "5E0G7J6X");
        assert_eq!(log[1].elements[0].item.text(), None);
        // The frame copy holds the drawn pixels: the grid's corner is in the cells' #333333
        // outline (RGB565 (6, 13, 6)), and inside the first cell is the #F7F7F7 tile.
        assert_eq!(log[1].frame.at(24, 12), Some(0x31a6));
        assert_eq!(log[1].frame.at(30, 18), Some(0xf7be));
        assert_eq!(log[1].frame.at(240, 0), None);
    }

    #[test]
    #[should_panic(expected = "seal-image: a Protected element on a Public screen")]
    fn a_protected_element_on_a_public_screen_fails() {
        let screen = Screen::new(ScreenId::SealImage, "Seal", NO_BANNERS).with(Element::protected(
            (0, 0).into(),
            Item::Text("abandon".into()),
        ));
        present(&mut Panel::new(), &screen);
    }

    #[test]
    #[should_panic(expected = "about: the model does not fit the screen")]
    fn a_model_that_does_not_fit_fails() {
        let screen = Screen::new(ScreenId::About, "About", NO_BANNERS).with(Element::public(
            (0, 200).into(),
            Item::Text("past the bottom".into()),
        ));
        present(&mut Panel::new(), &screen);
    }

    #[test]
    fn the_placeholder_is_grey_and_names_only_the_screen_id() {
        let words = placeholder(ScreenId::WordsInsert);
        let mut colours: Vec<u16> = words.raw().to_vec();
        colours.sort_unstable();
        colours.dedup();
        assert_eq!(colours, [GREY, 0xffff], "grey and white only");
        // The strip and the footer are grey: no title, banner or key.
        for y in (0..12).chain(228..240) {
            assert!((0..240).all(|x| words.at(x, y) == Some(GREY)));
        }
        // The white pixels lie in the three centred lines (y 86-105, 110-129, 140-149 in the
        // content area, 12 px lower in the frame).
        for y in 0..240 {
            let lit = (0..240).any(|x| words.at(x, y) == Some(0xffff));
            let inside =
                (98..118).contains(&y) || (122..142).contains(&y) || (152..162).contains(&y);
            assert!(!lit || inside, "row {y}");
        }
        // It names the screen id: another id gives another placeholder, the same id the same.
        let other = placeholder(ScreenId::RevealD);
        assert!(other.raw() != words.raw());
        assert!(placeholder(ScreenId::WordsInsert).raw() == words.raw());
    }

    #[test]
    fn a_placeholder_equals_its_reference_bytes() {
        // Pinned when the placeholder was written (M3 commit 10): a change to its text, its
        // layout, pi/app's renderer or the encoder must be a reviewed change of this line.
        let digest = Sha256::digest(&placeholder(ScreenId::WordsInsert).png()[..]);
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "f4a6b0450b346f5996af8c26fbff7b027ff0109b9e909a1d89602c4de14776c6"
        );
    }
}
