//! The renderer (tasks/todo.md, M3 "One drawing path", "Layout", group 6; docs/pi-firmware.md
//! "Buttons"): one model in, one frame out.
//!
//! - A `Painter` holds a `Frame` and the QR buffers. `Painter::present` clears the frame,
//!   draws the model, hands the frame and that model to the HAL's `Display`, and wipes the frame,
//!   whatever the outcome (rule 5).
//! - The layout: a 12 px top strip, the 240×216 content area, a 12 px footer. The top strip shows
//!   the step title, or the TEST REGISTRY and SIMULATOR banners, which take precedence (Q33 (j)).
//!   Each element is drawn at its position in the content area by its painter. The footer names
//!   every key the model offers with its action (Q32 (a)).
//! - A model with no title, banner, element or key draws a black frame.
//! - Drawing can fail only on a bug (a QR payload too long, a seal colour or braille caption core
//!   would never give): `RenderError`, which halts the device (Q25), like a display fault.

use core::fmt;

use embedded_graphics::Drawable;
use embedded_graphics::prelude::{DrawTarget, Point, Primitive, Size};
use embedded_graphics::primitives::{
    PrimitiveStyle, PrimitiveStyleBuilder, Rectangle, StrokeAlignment,
};

use super::qr::QrBuffers;
use super::{
    ACCENT, BACKGROUND, Frame, LIGHTER, SIDE, SIMULATOR, SNAKE, STOP, TEXT, WARNING, braille, qr,
    seal, text,
};
use crate::hal::{Display, HalError};
use crate::input::Key;
use crate::screen::{
    BOARD_CELL_PX, BOARD_CELLS, BODY_FONT, CONTENT, Element, Item, KeyMap, SMALL_FONT,
    STRIP_HEIGHT, Screen, ScreenId, Tile, lines,
};

/// The TEST REGISTRY banner: the build pins the test registry key.
const TEST_REGISTRY_BANNER: &str = "TEST REGISTRY";
/// The SIMULATOR banner.
const SIMULATOR_BANNER: &str = "SIMULATOR";
/// Strip text sits 1 px below the strip's top: 10 px of font in 12.
const STRIP_TEXT_TOP: u32 = 1;
/// Two spaces between the footer's entries.
const ENTRY_GAP: &str = "  ";

listed_enum! {
/// A model that cannot be drawn: always a bug, so it halts the device (Q25). Fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderError {
    /// A QR payload needs more than version 11 at 3 px a module.
    QrTooLong,
    /// A seal colour is not `#RRGGBB`.
    SealColour,
    /// A braille caption holds a character that is not a six-dot cell.
    BrailleCaption,
}
}

impl RenderError {
    /// The fixed text the halt screen shows.
    pub const fn text(self) -> &'static str {
        match self {
            RenderError::QrTooLong => "a QR code is too large for the screen",
            RenderError::SealColour => "a seal colour is not #RRGGBB",
            RenderError::BrailleCaption => "a braille caption is not six-dot braille",
        }
    }
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text())
    }
}

/// Why `Painter::present` did not show a model. Both halt the device (Q25).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentError {
    /// The model could not be drawn; the display was not called.
    Render(RenderError),
    /// The display did not take the frame.
    Display(HalError),
}

impl PresentError {
    /// The fixed text the halt screen shows.
    pub const fn text(self) -> &'static str {
        match self {
            PresentError::Render(error) => error.text(),
            PresentError::Display(error) => error.text(),
        }
    }
}

/// The owner of a frame and its QR buffers: the only code that draws. No `Debug` and no
/// `Clone`; both are wiped on drop.
pub struct Painter {
    frame: Frame,
    qr: QrBuffers,
}

impl Default for Painter {
    fn default() -> Self {
        Painter::new()
    }
}

impl Painter {
    /// A painter with a black frame and zeroed QR buffers.
    pub fn new() -> Self {
        Painter {
            frame: Frame::new(),
            qr: QrBuffers::new(),
        }
    }

    /// Draws `screen` into the frame, hands the frame and `screen` to `display`, then wipes the
    /// frame, on success and on error alike. A model that cannot be drawn never reaches the
    /// display.
    pub fn present<D: Display + ?Sized>(
        &mut self,
        display: &mut D,
        screen: &Screen<'_>,
    ) -> Result<(), PresentError> {
        let shown = match self.render(screen) {
            Ok(()) => display
                .present(&self.frame, screen)
                .map_err(PresentError::Display),
            Err(error) => Err(PresentError::Render(error)),
        };
        self.frame.clear();
        shown
    }

    /// Clears the frame and draws `screen`: the top strip, each element, the footer. The stop
    /// screen's content area is red.
    fn render(&mut self, screen: &Screen<'_>) -> Result<(), RenderError> {
        self.frame.clear();
        if screen.id() == ScreenId::Halt {
            let content = Rectangle::new(Point::zero() + Size::new(0, STRIP_HEIGHT), CONTENT);
            let Ok(()) = self.frame.fill_solid(&content, STOP);
        }
        top_strip(&mut self.frame, screen);
        for element in screen.elements() {
            self.element(element)?;
        }
        footer(&mut self.frame, screen.keys());
        Ok(())
    }

    /// Draws one element through its painter, at its position in the content area.
    fn element(&mut self, element: &Element<'_>) -> Result<(), RenderError> {
        let frame = &mut self.frame;
        let at = element.at() + Size::new(0, STRIP_HEIGHT);
        match element.item() {
            Item::Text(body) => {
                let shown = lines(body.as_str(), &BODY_FONT, element.at().x);
                text::lines(frame, at, shown, &BODY_FONT, TEXT);
            }
            Item::Small(small) => {
                let shown = lines(small.as_str(), &SMALL_FONT, element.at().x);
                text::lines(frame, at, shown, &SMALL_FONT, TEXT);
            }
            Item::Large {
                text: word,
                lighter_from,
            } => text::large(frame, at, word.as_str(), *lighter_from),
            Item::Cells { cells, pitch } => braille::row(frame, at, cells, *pitch),
            Item::Seal {
                grid,
                colour_hex,
                seal_id,
            } => seal::draw(frame, at, grid, colour_hex, seal_id)?,
            Item::Qr(payload) => qr::draw(frame, at, payload.as_str(), &mut self.qr)?,
            Item::Hex(hex) => text::lines(frame, at, hex.as_str().split('\n'), &BODY_FONT, TEXT),
            Item::Board(tiles) => board(frame, at, element.bounds().size, tiles),
        }
        Ok(())
    }
}

/// The top strip: the banners when the build carries any, each on its own colour in an equal
/// share of the width; otherwise the step title.
fn top_strip(frame: &mut Frame, screen: &Screen<'_>) {
    let banners = screen.banners();
    let count = u32::from(banners.test_registry) + u32::from(banners.simulator);
    if count == 0 {
        let at = Point::zero() + Size::new(0, STRIP_TEXT_TOP);
        text::line(frame, at, screen.title(), &SMALL_FONT, ACCENT);
        return;
    }
    let share = SIDE / count;
    let mut left = 0;
    for (on, label, colour) in [
        (banners.test_registry, TEST_REGISTRY_BANNER, WARNING),
        (banners.simulator, SIMULATOR_BANNER, SIMULATOR),
    ] {
        if !on {
            continue;
        }
        let bar = Rectangle::new(
            Point::zero() + Size::new(left, 0),
            Size::new(share, STRIP_HEIGHT),
        );
        let Ok(()) = frame.fill_solid(&bar, colour);
        let x = left + share.saturating_sub(text::width(label, &SMALL_FONT)) / 2;
        text::line(
            frame,
            Point::zero() + Size::new(x, STRIP_TEXT_TOP),
            label,
            &SMALL_FONT,
            BACKGROUND,
        );
        left += share;
    }
}

/// The footer: every action the model offers once, after the keys that do it, in `Key::ALL`'s
/// order, centred.
fn footer(frame: &mut Frame, keys: KeyMap) {
    let entries = legend(keys);
    let width = text::width(&legend_text(&entries), &SMALL_FONT);
    let x = SIDE.saturating_sub(width) / 2;
    let mut at = Point::zero() + Size::new(x, SIDE - STRIP_HEIGHT + STRIP_TEXT_TOP);
    for (i, (glyphs, label)) in entries.iter().enumerate() {
        if i > 0 {
            at += Size::new(text::width(ENTRY_GAP, &SMALL_FONT), 0);
        }
        at = text::line(frame, at, glyphs, &SMALL_FONT, ACCENT);
        at += Size::new(text::width(" ", &SMALL_FONT), 0);
        at = text::line(frame, at, label, &SMALL_FONT, TEXT);
    }
}

/// The footer's entries for `keys`: each label once, with the glyphs of every key that has it.
fn legend(keys: KeyMap) -> Vec<(String, &'static str)> {
    let mut entries: Vec<(String, &'static str)> = Vec::new();
    for key in Key::ALL {
        let Some(label) = keys.label(key) else {
            continue;
        };
        match entries.iter_mut().find(|(_, shown)| *shown == label) {
            Some((glyphs, _)) => glyphs.push_str(glyph(key)),
            None => entries.push((glyph(key).to_owned(), label)),
        }
    }
    entries
}

/// The footer as one line of text.
fn legend_text(entries: &[(String, &'static str)]) -> String {
    let shown: Vec<String> = entries
        .iter()
        .map(|(glyphs, label)| format!("{glyphs} {label}"))
        .collect();
    shown.join(ENTRY_GAP)
}

/// The footer's name for `key`: the joystick's directions as arrows, its press as OK, and the
/// keys by number (KEY1-KEY3 on the HAT).
const fn glyph(key: Key) -> &'static str {
    match key {
        Key::Up => "^",
        Key::Down => "v",
        Key::Left => "<",
        Key::Right => ">",
        Key::Press => "OK",
        Key::Key1 => "1",
        Key::Key2 => "2",
        Key::Key3 => "3",
    }
}

/// Snake's board in the box of `size` at `at`: a lighter edge around it, the snake and the food
/// as blocks inset by 1 px in their cells.
fn board(frame: &mut Frame, at: Point, size: Size, tiles: &[[Tile; BOARD_CELLS]; BOARD_CELLS]) {
    let edge = Rectangle::new(at, size).into_styled(
        PrimitiveStyleBuilder::new()
            .stroke_color(LIGHTER)
            .stroke_width(1)
            .stroke_alignment(StrokeAlignment::Inside)
            .build(),
    );
    let Ok(()) = edge.draw(frame);
    for (row, cells) in (0u32..).zip(tiles) {
        for (column, tile) in (0u32..).zip(cells) {
            let colour = match tile {
                Tile::Empty => continue,
                Tile::Snake => SNAKE,
                Tile::Food => WARNING,
            };
            let top_left = at + Size::new(column * BOARD_CELL_PX + 1, row * BOARD_CELL_PX + 1);
            let block = Rectangle::new(top_left, Size::new(BOARD_CELL_PX - 2, BOARD_CELL_PX - 2))
                .into_styled(PrimitiveStyle::with_fill(colour));
            let Ok(()) = block.draw(frame);
        }
    }
}

#[cfg(test)]
mod tests {
    use embedded_graphics::pixelcolor::Rgb565;
    use embedded_graphics::prelude::{PointsIter, RgbColor};
    use zeroize::Zeroizing;

    use super::*;
    use crate::screen::{Banners, ScreenId, wrap};
    use crate::ui::caption_cells;

    const NO_BANNERS: Banners = Banners {
        test_registry: false,
        simulator: false,
    };
    /// The content area in the frame.
    const CONTENT_ROWS: Rectangle = Rectangle::new(Point::new(0, 12), Size::new(240, 216));
    const TOP_ROWS: Rectangle = Rectangle::new(Point::zero(), Size::new(240, 12));
    const FOOTER_ROWS: Rectangle = Rectangle::new(Point::new(0, 228), Size::new(240, 12));

    fn rendered(screen: &Screen<'_>) -> Painter {
        let mut painter = Painter::new();
        painter.render(screen).expect("draws");
        painter
    }

    /// The pixels of `area` in `frame`.
    fn area(frame: &Frame, area: Rectangle) -> Vec<Option<Rgb565>> {
        area.points().map(|p| frame.pixel(p)).collect()
    }

    fn black(frame: &Frame, rows: Rectangle) -> bool {
        rows.points().all(|p| frame.pixel(p) == Some(Rgb565::BLACK))
    }

    #[test]
    fn the_stop_screen_is_drawn_on_red() {
        let halt = Screen::new(ScreenId::Halt, "", NO_BANNERS).with(Element::public(
            Point::new(0, 100),
            Item::Text("STOPPED".into()),
        ));
        let painter = rendered(&halt);
        let red = Rgb565::new(20, 0, 0);
        assert!(black(&painter.frame, TOP_ROWS));
        assert!(black(&painter.frame, FOOTER_ROWS));
        // The content area is red but for the text drawn on it, in white.
        for colour in area(&painter.frame, CONTENT_ROWS) {
            assert!(colour == Some(red) || colour == Some(Rgb565::WHITE));
        }
        assert_eq!(painter.frame.pixel(Point::new(0, 12)), Some(red));
        assert_eq!(painter.frame.pixel(Point::new(239, 227)), Some(red));
        // Any other screen keeps the black background.
        let about = rendered(&Screen::new(ScreenId::About, "", NO_BANNERS));
        assert!(black(&about.frame, CONTENT_ROWS));
    }

    #[test]
    fn a_model_with_nothing_in_it_draws_a_black_frame() {
        let painter = rendered(&Screen::new(ScreenId::Blank, "", NO_BANNERS));
        assert!(painter.frame.pixels().all(|c| c == Rgb565::BLACK));
    }

    #[test]
    fn text_wraps_at_240_px_in_the_lines_its_box_was_measured_in() {
        let thirty = "abcde fghij klmno pqrst uvwxy z";
        let long_word = "x".repeat(30);
        for (x, body, shown) in [
            (0, thirty, vec!["abcde fghij klmno pqrst", "uvwxy z"]),
            (40, thirty, vec!["abcde fghij klmno", "pqrst uvwxy z"]),
            (
                0,
                long_word.as_str(),
                vec![&long_word[..24], &long_word[24..]],
            ),
        ] {
            assert_eq!(lines(body, &BODY_FONT, x), shown);
            let element = Element::public(Point::new(x, 30), Item::Text(body.into()));
            let height = element.bounds().size.height;
            let painter = rendered(&Screen::new(ScreenId::About, "", NO_BANNERS).with(element));
            let mut expected = Frame::new();
            text::lines(
                &mut expected,
                Point::new(x, 42),
                shown.iter().copied(),
                &BODY_FONT,
                TEXT,
            );
            assert_eq!(
                area(&painter.frame, CONTENT_ROWS),
                area(&expected, CONTENT_ROWS)
            );
            // The first line reaches the right edge's last character cell, and nothing is drawn
            // below the measured box.
            assert_eq!(height, 40);
            let below = Rectangle::new(Point::new(0, 82), Size::new(240, 146));
            assert!(black(&painter.frame, below));
        }
        // Small text: 40 characters to the line.
        let small = "a".repeat(41);
        assert_eq!(wrap(&small, 40), [&small[..40], &small[40..]]);
        let element = Element::public(Point::zero(), Item::Small(small.as_str().into()));
        let painter = rendered(&Screen::new(ScreenId::About, "", NO_BANNERS).with(element));
        let mut expected = Frame::new();
        text::lines(
            &mut expected,
            Point::new(0, 12),
            [&small[..40], &small[40..]],
            &SMALL_FONT,
            TEXT,
        );
        assert_eq!(
            area(&painter.frame, CONTENT_ROWS),
            area(&expected, CONTENT_ROWS)
        );
    }

    /// Renders `item` at (12, 0) in the content area and checks the content rows equal `paint`'s
    /// drawing at (12, 12) in the frame.
    fn drawn_like(item: Item<'_>, paint: impl FnOnce(&mut Frame, Point)) {
        let element = Element::public(Point::new(12, 0), item);
        let painter = rendered(&Screen::new(ScreenId::About, "", NO_BANNERS).with(element));
        let mut expected = Frame::new();
        paint(&mut expected, Point::new(12, 12));
        let expected = area(&expected, CONTENT_ROWS);
        assert!(expected.iter().any(|&p| p != Some(Rgb565::BLACK)));
        assert_eq!(area(&painter.frame, CONTENT_ROWS), expected);
    }

    #[test]
    fn each_item_is_drawn_by_its_painter_below_the_top_strip() {
        drawn_like(Item::Text("Dice".into()), |f, at| {
            text::line(f, at, "Dice", &BODY_FONT, TEXT);
        });
        drawn_like(Item::Small("Snapshot No. 4".into()), |f, at| {
            text::line(f, at, "Snapshot No. 4", &SMALL_FONT, TEXT);
        });
        let large = Item::Large {
            text: "abstract".into(),
            lighter_from: Some(4),
        };
        drawn_like(large, |f, at| text::large(f, at, "abstract", Some(4)));
        let pitch = Size::new(44, 70);
        let cells = Item::Cells {
            cells: caption_cells("⠁⠃⠉").expect("cells"),
            pitch,
        };
        drawn_like(cells, |f, at| {
            braille::row(f, at, &caption_cells("⠁⠃⠉").expect("cells"), pitch);
        });
        let grid = [[true, false, true, false, true, false, true, false]; 8];
        let seal = Item::Seal {
            grid: &grid,
            colour_hex: "#0072B2",
            seal_id: "5E0G7J6X",
        };
        drawn_like(seal, |f, at| {
            seal::draw(f, at, &grid, "#0072B2", "5E0G7J6X").expect("draws");
        });
        let payload = "https://registry.invalid/register#c=JXP3RDXYACJZ1NAX3RGQDJCJJN";
        drawn_like(Item::Qr(payload.into()), |f, at| {
            qr::draw(f, at, payload, &mut QrBuffers::new()).expect("draws");
        });
        let hex = "0001 0203 0405 0607\n0809 0a0b 0c0d 0e0f";
        drawn_like(Item::Hex(hex.into()), |f, at| {
            text::lines(f, at, hex.split('\n'), &BODY_FONT, TEXT);
        });
        let tiles = [[Tile::Food; BOARD_CELLS]; BOARD_CELLS];
        drawn_like(Item::Board(&tiles), |f, at| {
            board(f, at, Size::new(216, 216), &tiles);
        });
    }

    #[test]
    fn the_board_shows_snake_food_and_its_edge() {
        let mut tiles = [[Tile::Empty; BOARD_CELLS]; BOARD_CELLS];
        tiles[0][0] = Tile::Snake;
        tiles[0][1] = Tile::Snake;
        tiles[17][17] = Tile::Food;
        let element = Element::public(Point::new(12, 0), Item::Board(&tiles));
        assert_eq!(element.bounds().size, Size::new(216, 216));
        let painter = rendered(&Screen::new(ScreenId::GameSnake, "", NO_BANNERS).with(element));
        let frame = &painter.frame;
        let centre = |row: i32, column: i32| Point::new(12 + 12 * column + 6, 12 + 12 * row + 6);
        assert_eq!(frame.pixel(centre(0, 0)), Some(SNAKE));
        assert_eq!(frame.pixel(centre(0, 1)), Some(SNAKE));
        assert_eq!(frame.pixel(centre(17, 17)), Some(WARNING));
        assert_eq!(frame.pixel(centre(5, 5)), Some(Rgb565::BLACK));
        // Blocks are inset by 1 px, so the edge stays visible beside them.
        assert_eq!(frame.pixel(Point::new(12, 12 + 6)), Some(LIGHTER));
        assert_eq!(frame.pixel(Point::new(12 + 215, 12 + 100)), Some(LIGHTER));
        assert_eq!(
            frame.pixel(Point::new(12 + 12, 12 + 6)),
            Some(Rgb565::BLACK)
        );
    }

    #[test]
    fn the_footer_names_each_offered_key_with_its_action() {
        let shown = |keys: KeyMap| legend_text(&legend(keys));
        assert_eq!(
            shown(ScreenId::Dice.key_map()),
            "^v pick  OK confirm  1 undo  3 done"
        );
        assert_eq!(
            shown(ScreenId::Dice.key_map().without(Key::Key3)),
            "^v pick  OK confirm  1 undo"
        );
        assert_eq!(
            shown(ScreenId::WordsInsert.key_map()),
            "OK read-back  1 overview  2 prev  3 next"
        );
        assert_eq!(
            shown(ScreenId::CodeEntry.key_map()),
            "^v<> cursor  OK type  1 delete  3 done"
        );
        assert_eq!(shown(ScreenId::Cover.key_map()), "^v<>OK123 show");
        assert_eq!(shown(KeyMap::NONE), "");
        // Every screen: each offered key's glyph sits in exactly the entry of its label, a dead
        // key's glyph in none, each label once, and the line fits the footer.
        for id in ScreenId::ALL {
            let keys = id.key_map();
            let entries = legend(keys);
            assert!(
                text::width(&legend_text(&entries), &SMALL_FONT) <= SIDE,
                "{}",
                id.name()
            );
            for key in Key::ALL {
                let holding: Vec<&str> = entries
                    .iter()
                    .filter(|(glyphs, _)| glyphs.contains(glyph(key)))
                    .map(|&(_, label)| label)
                    .collect();
                match keys.label(key) {
                    Some(label) => assert_eq!(holding, [label], "{}", id.name()),
                    None => assert!(holding.is_empty(), "{}", id.name()),
                }
            }
            for (i, (_, label)) in entries.iter().enumerate() {
                assert!(entries[i + 1..].iter().all(|(_, other)| other != label));
            }
        }
    }

    #[test]
    fn the_footer_is_drawn_centred_with_key_names_in_the_accent_colour() {
        let dice = rendered(&Screen::new(ScreenId::Dice, "", NO_BANNERS));
        // "^v pick  OK confirm  1 undo  3 done" is 35 characters: 210 px from x = 15.
        let line = "^v pick  OK confirm  1 undo  3 done";
        assert_eq!(line.len(), 35);
        let mut alone = Frame::new();
        text::line(&mut alone, Point::new(15, 229), line, &SMALL_FONT, TEXT);
        let lit = |frame: &Frame| -> Vec<bool> {
            FOOTER_ROWS
                .points()
                .map(|p| frame.pixel(p) != Some(Rgb565::BLACK))
                .collect()
        };
        assert_eq!(lit(&dice.frame), lit(&alone));
        // Key names in the accent colour, actions in the text colour.
        let glyph_columns = [0, 1, 9, 10, 21, 29];
        for p in FOOTER_ROWS.points() {
            let Some(colour) = dice.frame.pixel(p) else {
                continue;
            };
            if colour == Rgb565::BLACK {
                continue;
            }
            let column = (p.x - 15) / 6;
            let expected = if glyph_columns.contains(&column) {
                ACCENT
            } else {
                TEXT
            };
            assert_eq!(colour, expected, "{p:?}");
        }
        assert!(black(&dice.frame, TOP_ROWS) && black(&dice.frame, CONTENT_ROWS));
        // A model with fewer keys draws a shorter footer; no keys, none.
        let below_minimum =
            rendered(&Screen::new(ScreenId::Dice, "", NO_BANNERS).without(Key::Key3));
        assert_ne!(lit(&below_minimum.frame), lit(&dice.frame));
        let halt = rendered(&Screen::new(ScreenId::Halt, "", NO_BANNERS));
        assert!(black(&halt.frame, FOOTER_ROWS));
    }

    #[test]
    fn both_banners_fit_the_top_strip_together_and_hide_the_title() {
        let both = Banners {
            test_registry: true,
            simulator: true,
        };
        // Each banner has half the strip: 78 and 54 px of label in 120.
        assert!(text::width(TEST_REGISTRY_BANNER, &SMALL_FONT) <= SIDE / 2);
        assert!(text::width(SIMULATOR_BANNER, &SMALL_FONT) <= SIDE / 2);
        let painter = rendered(&Screen::new(ScreenId::About, "About", both));
        let frame = &painter.frame;
        let left = Rectangle::new(Point::zero(), Size::new(120, 12));
        let right = Rectangle::new(Point::new(120, 0), Size::new(120, 12));
        let mut expected = Frame::new();
        let Ok(()) = expected.fill_solid(&left, WARNING);
        let Ok(()) = expected.fill_solid(&right, SIMULATOR);
        text::line(
            &mut expected,
            Point::new(21, 1),
            TEST_REGISTRY_BANNER,
            &SMALL_FONT,
            BACKGROUND,
        );
        text::line(
            &mut expected,
            Point::new(153, 1),
            SIMULATOR_BANNER,
            &SMALL_FONT,
            BACKGROUND,
        );
        assert_eq!(area(frame, TOP_ROWS), area(&expected, TOP_ROWS));
        // Each label is inside its own bar: black pixels in both, and the bars' outer columns
        // untouched by text.
        for bar in [left, right] {
            assert!(bar.points().any(|p| frame.pixel(p) == Some(BACKGROUND)));
            for y in 0..12 {
                let edges = [bar.top_left.x, bar.top_left.x + 119];
                assert!(
                    edges
                        .iter()
                        .all(|&x| frame.pixel(Point::new(x, y)) != Some(BACKGROUND))
                );
            }
        }
        // The title is not drawn: another title gives the same strip.
        let other = rendered(&Screen::new(ScreenId::About, "Another title", both));
        assert_eq!(area(&other.frame, TOP_ROWS), area(frame, TOP_ROWS));
        assert!(black(frame, CONTENT_ROWS));
        // One banner takes the whole strip.
        let simulator = Banners {
            test_registry: false,
            simulator: true,
        };
        let one = rendered(&Screen::new(ScreenId::About, "About", simulator));
        let mut expected = Frame::new();
        let Ok(()) = expected.fill_solid(&TOP_ROWS, SIMULATOR);
        text::line(
            &mut expected,
            Point::new(93, 1),
            SIMULATOR_BANNER,
            &SMALL_FONT,
            BACKGROUND,
        );
        assert_eq!(area(&one.frame, TOP_ROWS), area(&expected, TOP_ROWS));
        // Without banners, the title in the accent colour.
        let titled = rendered(&Screen::new(ScreenId::About, "About", NO_BANNERS));
        let mut expected = Frame::new();
        text::line(
            &mut expected,
            Point::new(0, 1),
            "About",
            &SMALL_FONT,
            ACCENT,
        );
        assert_eq!(area(&titled.frame, TOP_ROWS), area(&expected, TOP_ROWS));
    }

    /// A display that records each present: the screen id and the frame's lit pixel count.
    struct Recorder {
        shown: Vec<(ScreenId, usize)>,
        fault: bool,
    }

    impl Display for Recorder {
        fn present(&mut self, frame: &Frame, screen: &Screen<'_>) -> Result<(), HalError> {
            let lit = frame.pixels().filter(|&c| c != Rgb565::BLACK).count();
            self.shown.push((screen.id(), lit));
            if self.fault {
                Err(HalError::Display)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn present_hands_the_frame_and_its_model_to_the_display_then_wipes_the_frame() {
        let mut painter = Painter::default();
        let mut display = Recorder {
            shown: Vec::new(),
            fault: false,
        };
        let dice = Screen::new(ScreenId::Dice, "Dice", NO_BANNERS);
        assert_eq!(painter.present(&mut display, &dice), Ok(()));
        assert_eq!(display.shown.len(), 1);
        assert_eq!(display.shown[0].0, ScreenId::Dice);
        assert!(display.shown[0].1 > 0);
        assert!(painter.frame.pixels().all(|c| c == Rgb565::BLACK));
        // A display fault: the error, and the frame still wiped.
        display.fault = true;
        assert_eq!(
            painter.present(&mut display, &dice),
            Err(PresentError::Display(HalError::Display))
        );
        assert_eq!(display.shown.len(), 2);
        assert!(painter.frame.pixels().all(|c| c == Rgb565::BLACK));
        // A model that cannot be drawn never reaches the display, and the half-drawn frame is
        // wiped.
        display.fault = false;
        let too_long = "y".repeat(322);
        let broken = Screen::new(ScreenId::SealQr, "Check", NO_BANNERS).with(Element::public(
            Point::new(12, 0),
            Item::Qr(too_long.as_str().into()),
        ));
        assert_eq!(
            painter.present(&mut display, &broken),
            Err(PresentError::Render(RenderError::QrTooLong))
        );
        assert_eq!(display.shown.len(), 2);
        assert!(painter.frame.pixels().all(|c| c == Rgb565::BLACK));
        // Protected content is drawn like any other; the class rules belong to the app and the
        // simulator.
        let word = Zeroizing::new(String::from("abstract"));
        let insert =
            Screen::new(ScreenId::WordsInsert, "Insert 01", NO_BANNERS).with(Element::protected(
                Point::zero(),
                Item::Large {
                    text: word.as_str().into(),
                    lighter_from: Some(4),
                },
            ));
        assert_eq!(painter.present(&mut display, &insert), Ok(()));
        assert!(display.shown[2].1 > 0);
        assert!(painter.frame.pixels().all(|c| c == Rgb565::BLACK));
    }

    #[test]
    fn errors_show_fixed_text() {
        for error in RenderError::ALL {
            let pinned = match error {
                RenderError::QrTooLong => "a QR code is too large for the screen",
                RenderError::SealColour => "a seal colour is not #RRGGBB",
                RenderError::BrailleCaption => "a braille caption is not six-dot braille",
            };
            assert_eq!(error.to_string(), pinned);
            assert_eq!(PresentError::Render(error).text(), pinned);
        }
        assert_eq!(
            PresentError::Display(HalError::Display).text(),
            "display fault"
        );
    }
}
