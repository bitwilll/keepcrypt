//! Braille cells (docs/seal-watchonly-braille.md "Braille backup", "On screen"; tasks/todo.md,
//! M3 group 6).
//!
//! - A cell is drawn from its 6-bit mask, dot d at bit d - 1 (core's `Dots::bits`): dots 1-2-3
//!   down the left column, 4-5-6 down the right, as printed. Raised dots are filled; flat dots
//!   are rings, so the reader sees every position.
//! - A box of at least `screen::NUMBERED_PITCH` (an insert's faces) also carries each dot's
//!   number beside it, and under the dots either "leave blank" (a blank face: six rings) or
//!   "mirror" (a letter with a mirror partner, to read twice). Face 5 is drawn lighter.
//! - A smaller box (the Seal ID's braille caption) shows the dots alone. `caption_cells` makes
//!   those cells from core's `SealPublic::seal_id_braille`: each code point minus U+2800.

use embedded_graphics::Drawable;
use embedded_graphics::prelude::{Point, Primitive, Size};
use embedded_graphics::primitives::{
    Circle, PrimitiveStyle, PrimitiveStyleBuilder, StrokeAlignment,
};
use zeroize::Zeroizing;

use super::render::RenderError;
use super::{ACCENT, Frame, LIGHTER, TEXT, WARNING, text};
use crate::screen::{Cell, NUMBERED_PITCH, SMALL_FONT, advance};

/// The first code point of the braille block, the blank cell: a cell's glyph is it plus the dots.
const BRAILLE_BLANK: u32 = 0x2800;
/// The six dots' bits: a six-dot cell is below 0x40.
const SIX_DOTS: u8 = 0x3f;
/// Two lines of small text under the dots of a numbered cell.
const LABEL_LINES: u32 = 2;

/// Where a cell's parts go in its box, relative to its top left.
struct Layout {
    /// Dot d's centre at index d - 1.
    centres: [Point; 6],
    /// Every dot's diameter: odd, so a dot has a centre pixel.
    diameter: u32,
    /// The top left of dot d's number at index d - 1, in a numbered box.
    numbers: Option<[Point; 6]>,
    /// The top of the label lines, in a numbered box.
    label_top: u32,
}

impl Layout {
    /// The layout of a box of `pitch`: two columns and three rows of dots, a number column on
    /// each side and two label lines below in a numbered box.
    fn of(pitch: Size) -> Self {
        let numbered = pitch.width >= NUMBERED_PITCH.width && pitch.height >= NUMBERED_PITCH.height;
        let (margin, label) = if numbered {
            (
                advance(&SMALL_FONT),
                LABEL_LINES * SMALL_FONT.character_size.height,
            )
        } else {
            (0, 0)
        };
        let column = pitch.width.saturating_sub(2 * margin) / 2;
        let row = pitch.height.saturating_sub(label) / 3;
        let at = |x: u32, y: u32| Point::zero() + Size::new(x, y);
        let centre = |dot: u32| {
            let (col, line) = ((dot - 1) / 3, (dot - 1) % 3);
            at(margin + col * column + column / 2, line * row + row / 2)
        };
        let centres = [1, 2, 3, 4, 5, 6].map(centre);
        // A number is centred on its dot's row, left of the left column or right of the right.
        let half_glyph = SMALL_FONT.character_size.height / 2;
        let number = |dot: u32| {
            let x = if dot <= 3 {
                0
            } else {
                pitch.width.saturating_sub(margin)
            };
            at(
                x,
                ((dot - 1) % 3) * row + (row / 2).saturating_sub(half_glyph),
            )
        };
        Layout {
            centres,
            // Three quarters of the smaller of a column and a row, rounded down to odd.
            diameter: (column.min(row) * 3 / 4).saturating_sub(1) | 1,
            numbers: numbered.then(|| [1, 2, 3, 4, 5, 6].map(number)),
            label_top: 3 * row,
        }
    }
}

/// Draws `cells` in a row from `at`, each in a box of `pitch`.
pub(super) fn row(frame: &mut Frame, at: Point, cells: &[Cell], pitch: Size) {
    let layout = Layout::of(pitch);
    let mut top_left = at;
    for cell in cells {
        draw(frame, top_left, cell, &layout, pitch);
        top_left += Size::new(pitch.width, 0);
    }
}

/// Draws one cell in its box at `at`.
fn draw(frame: &mut Frame, at: Point, cell: &Cell, layout: &Layout, pitch: Size) {
    let colour = if cell.lighter { LIGHTER } else { TEXT };
    let raised = PrimitiveStyle::with_fill(colour);
    let flat = PrimitiveStyleBuilder::new()
        .stroke_color(colour)
        .stroke_width(1)
        .stroke_alignment(StrokeAlignment::Inside)
        .build();
    for (bit, centre) in (0..6).zip(layout.centres) {
        let style = if cell.dots & (1 << bit) != 0 {
            raised
        } else {
            flat
        };
        let dot = Circle::with_center(at + centre, layout.diameter).into_styled(style);
        let Ok(()) = dot.draw(frame);
    }
    let Some(numbers) = layout.numbers else {
        return;
    };
    for (number, top_left) in ["1", "2", "3", "4", "5", "6"].into_iter().zip(numbers) {
        text::line(frame, at + top_left, number, &SMALL_FONT, ACCENT);
    }
    let label: &[&str] = if cell.blank {
        &["leave", "blank"]
    } else if cell.mirror {
        &["mirror"]
    } else {
        &[]
    };
    let label_colour = if cell.blank { TEXT } else { WARNING };
    let mut top = layout.label_top;
    for line in label {
        let width = text::width(line, &SMALL_FONT);
        let x = pitch.width.saturating_sub(width) / 2;
        text::line(
            frame,
            at + Size::new(x, top),
            line,
            &SMALL_FONT,
            label_colour,
        );
        top += SMALL_FONT.character_size.height;
    }
}

/// The cells of a braille caption such as core's `SealPublic::seal_id_braille`: each character's
/// code point minus U+2800 is its dots. Anything but a six-dot cell (U+2800 to U+283F) is
/// `BrailleCaption`; core only ever gives six-dot cells, so that is a bug, and it halts.
pub fn caption_cells(braille: &str) -> Result<Zeroizing<Vec<Cell>>, RenderError> {
    let mut cells = Zeroizing::new(Vec::with_capacity(braille.chars().count()));
    for glyph in braille.chars() {
        let dots = match u32::from(glyph)
            .checked_sub(BRAILLE_BLANK)
            .map(u8::try_from)
        {
            Some(Ok(dots)) if dots <= SIX_DOTS => dots,
            _ => return Err(RenderError::BrailleCaption),
        };
        cells.push(Cell {
            dots,
            blank: false,
            lighter: false,
            mirror: false,
        });
    }
    Ok(cells)
}

#[cfg(test)]
mod tests {
    use embedded_graphics::pixelcolor::Rgb565;
    use embedded_graphics::prelude::{PointsIter, RgbColor};
    use embedded_graphics::primitives::Rectangle;
    use keepcrypt_core::render_text;

    use super::*;
    use crate::ui::BACKGROUND;

    /// An insert's faces: 44 px a face, five to 220 px.
    const FACE: Size = Size::new(44, 70);
    /// The Seal ID's caption: up to 16 cells in 240 px.
    const CAPTION: Size = Size::new(15, 24);
    const AT: Point = Point::new(30, 40);

    fn cell(dots: u8) -> Cell {
        Cell {
            dots,
            blank: false,
            lighter: false,
            mirror: false,
        }
    }

    fn drawn(cell: &Cell, pitch: Size) -> Frame {
        let mut frame = Frame::new();
        row(&mut frame, AT, core::slice::from_ref(cell), pitch);
        frame
    }

    /// The pixels of `area` in `frame`.
    fn area(frame: &Frame, area: Rectangle) -> Vec<Option<Rgb565>> {
        area.points().map(|p| frame.pixel(p)).collect()
    }

    /// True when `frame` shows exactly `label` in `colour` in its small-font box at `at`: the
    /// same pixels as `label` drawn alone.
    fn shows(frame: &Frame, at: Point, label: &str, colour: Rgb565) -> bool {
        let mut alone = Frame::new();
        text::line(&mut alone, at, label, &SMALL_FONT, colour);
        let label_box = Rectangle::new(at, Size::new(text::width(label, &SMALL_FONT), 10));
        area(&alone, label_box).contains(&Some(colour))
            && area(frame, label_box) == area(&alone, label_box)
    }

    #[test]
    fn the_layouts_fit_their_boxes() {
        let face = Layout::of(FACE);
        assert_eq!(face.diameter, 11);
        assert_eq!(
            face.centres,
            [(14, 8), (14, 24), (14, 40), (30, 8), (30, 24), (30, 40)]
                .map(|(x, y)| Point::new(x, y))
        );
        assert!(face.numbers.is_some());
        assert_eq!(face.label_top, 48);
        let caption = Layout::of(CAPTION);
        assert_eq!(caption.diameter, 5);
        assert!(caption.numbers.is_none());
        // The smallest numbered box still holds "mirror" and keeps numbers off the dots.
        let smallest = Layout::of(NUMBERED_PITCH);
        assert_eq!(smallest.diameter, 9);
        assert!(smallest.numbers.is_some());
        assert!(text::width("mirror", &SMALL_FONT) <= NUMBERED_PITCH.width);
        assert!(
            Layout::of(NUMBERED_PITCH - Size::new(1, 0))
                .numbers
                .is_none()
        );
        assert!(
            Layout::of(NUMBERED_PITCH - Size::new(0, 1))
                .numbers
                .is_none()
        );
    }

    #[test]
    fn all_64_masks_sample_back_at_the_dot_centres() {
        for pitch in [FACE, NUMBERED_PITCH, CAPTION] {
            let layout = Layout::of(pitch);
            let radius = i32::try_from(layout.diameter / 2).expect("small");
            for lighter in [false, true] {
                let colour = if lighter { LIGHTER } else { TEXT };
                for mask in 0..64u8 {
                    let frame = drawn(
                        &Cell {
                            lighter,
                            ..cell(mask)
                        },
                        pitch,
                    );
                    for (bit, centre) in (0..6).zip(layout.centres) {
                        let centre = AT + centre;
                        // Filled when raised, a ring around a dark centre when flat.
                        let raised = mask & (1 << bit) != 0;
                        let expected = if raised { colour } else { BACKGROUND };
                        assert_eq!(frame.pixel(centre), Some(expected), "{mask:#04x} {bit}");
                        for edge in [Point::new(-radius, 0), Point::new(radius, 0)] {
                            assert_eq!(frame.pixel(centre + edge), Some(colour), "{mask:#04x}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn each_dot_number_is_drawn_beside_its_dot() {
        for pitch in [FACE, NUMBERED_PITCH] {
            let layout = Layout::of(pitch);
            let numbers = layout.numbers.expect("a numbered box");
            for mask in [0x00, 0x3f, 0x15] {
                let frame = drawn(&cell(mask), pitch);
                for (number, top_left) in ["1", "2", "3", "4", "5", "6"].into_iter().zip(numbers) {
                    assert!(shows(&frame, AT + top_left, number, ACCENT), "dot {number}");
                }
            }
            // On its dot's row: left of the left column for dots 1-3, right of the right column
            // for 4-6.
            let radius = i32::try_from(layout.diameter / 2).expect("small");
            for (dot, (top_left, centre)) in (1..).zip(numbers.into_iter().zip(layout.centres)) {
                let number = Rectangle::new(top_left, Size::new(6, 10));
                let rows = number.rows();
                assert!(rows.contains(&centre.y), "dot {dot}");
                let right = number.bottom_right().expect("not empty").x;
                if dot <= 3 {
                    assert!(right < centre.x - radius, "dot {dot}");
                } else {
                    assert!(number.top_left.x > centre.x + radius, "dot {dot}");
                    assert!(
                        right < i32::try_from(pitch.width).expect("small"),
                        "dot {dot}"
                    );
                }
            }
        }
        // A caption box draws no number.
        let frame = drawn(&cell(0x3f), CAPTION);
        assert!(frame.pixels().all(|c| c != ACCENT));
    }

    #[test]
    fn a_blank_face_is_six_rings_labelled_leave_blank() {
        let layout = Layout::of(FACE);
        let blank = Cell {
            blank: true,
            ..cell(0)
        };
        let frame = drawn(&blank, FACE);
        for centre in layout.centres {
            assert_eq!(frame.pixel(AT + centre), Some(BACKGROUND));
        }
        // "leave" (30 px) and "blank" centred under the dots, one line apart.
        let top = AT + Size::new(7, layout.label_top);
        assert!(shows(&frame, top, "leave", TEXT));
        assert!(shows(&frame, top + Size::new(0, 10), "blank", TEXT));
        assert!(frame.pixels().all(|c| c != WARNING));
    }

    #[test]
    fn a_mirror_letter_is_flagged_and_face_5_is_lighter() {
        let layout = Layout::of(FACE);
        // e (dots 1-5) on face 5: lighter dots, and the mirror flag.
        let e = Cell {
            lighter: true,
            mirror: true,
            ..cell(0x11)
        };
        let frame = drawn(&e, FACE);
        assert_eq!(frame.pixel(AT + layout.centres[0]), Some(LIGHTER));
        assert_eq!(frame.pixel(AT + layout.centres[4]), Some(LIGHTER));
        assert!(frame.pixels().all(|c| c != TEXT));
        assert!(shows(
            &frame,
            AT + Size::new(4, layout.label_top),
            "mirror",
            WARNING
        ));
        // Without the flags: no label, full-strength dots.
        let plain = drawn(&cell(0x11), FACE);
        assert_eq!(plain.pixel(AT + layout.centres[0]), Some(TEXT));
        assert!(plain.pixels().all(|c| c != WARNING && c != LIGHTER));
    }

    #[test]
    fn cells_in_a_row_sit_one_pitch_apart_inside_their_boxes() {
        let cells = [cell(0x01), cell(0x3f), cell(0x38)];
        let mut frame = Frame::new();
        row(&mut frame, AT, &cells, FACE);
        let layout = Layout::of(FACE);
        for (i, cell) in (0..).zip(&cells) {
            let at = AT + Point::new(44 * i, 0);
            for (bit, centre) in (0..6).zip(layout.centres) {
                let raised = cell.dots & (1 << bit) != 0;
                assert_eq!(frame.pixel(at + centre) == Some(TEXT), raised);
            }
        }
        let boxes = Rectangle::new(AT, Size::new(3 * 44, 70));
        for (colour, i) in frame.pixels().zip(0..) {
            if colour != Rgb565::BLACK {
                assert!(boxes.contains(Point::new(i % 240, i / 240)));
            }
        }
    }

    #[test]
    fn caption_cells_are_the_code_points_minus_u2800() {
        // 5E0G7J6X in UEB grade 1, lowercase, as core renders the Seal ID: each digit run opens
        // with the number sign (dots 3-4-5-6), and a letter a-j after a digit takes the grade 1
        // indicator (dots 5-6) first.
        let braille = render_text("5e0g7j6x").expect("a-z and 0-9");
        let cells = caption_cells(&braille).expect("six-dot cells");
        let dots: Vec<u8> = cells.iter().map(|c| c.dots).collect();
        assert_eq!(
            dots,
            [
                0x3c, 0x11, 0x30, 0x11, 0x3c, 0x1a, 0x30, 0x1b, 0x3c, 0x1b, 0x30, 0x1a, 0x3c, 0x0b,
                0x2d
            ]
        );
        assert!(cells.iter().all(|c| !c.blank && !c.lighter && !c.mirror));
        assert_eq!(caption_cells("").map(|c| c.len()), Ok(0));
        assert!(
            matches!(caption_cells("\u{2800}\u{283f}"), Ok(c) if c[0].dots == 0 && c[1].dots == 0x3f)
        );
        // Eight-dot cells, letters and anything below the block are refused.
        for refused in ["\u{2840}", "\u{28ff}", "a", "\u{27ff}", "⠁x"] {
            assert!(
                matches!(caption_cells(refused), Err(RenderError::BrailleCaption)),
                "{refused:?}"
            );
        }
    }
}
