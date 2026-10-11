//! The seal image (docs/seal-watchonly-braille.md "The seal image"; tasks/todo.md, M3 group 6).
//!
//! - The 8×8 grid of core's `SealPublic::grid`, `screen::SEAL_SIDE` (192 px) square: 24 px cells
//!   on a light tile the size of the grid, whatever the screen around it, so device photos match
//!   the registry page.
//! - Filled cells take core's `colour_hex` (`#RRGGBB`, an Okabe-Ito colour) as the panel's
//!   RGB565; every cell, filled or empty, has a dark outline, so light colours stay visible.
//! - The Seal ID in 10×20 beneath, centred.

use embedded_graphics::Drawable;
use embedded_graphics::pixelcolor::{Rgb565, Rgb888};
use embedded_graphics::prelude::{Point, Primitive, Size};
use embedded_graphics::primitives::{PrimitiveStyleBuilder, Rectangle, StrokeAlignment};

use super::render::RenderError;
use super::{Frame, TEXT, text};
use crate::screen::{BODY_FONT, SEAL_CAPTION_GAP, SEAL_SIDE};

/// The light tile behind the grid: #F7F7F7.
const TILE: Rgb565 = Rgb565::new(30, 61, 30);
/// Every cell's outline: #333333.
const OUTLINE: Rgb565 = Rgb565::new(6, 13, 6);
/// One cell's side: 192 / 8.
const CELL: u32 = SEAL_SIDE / 8;

/// Draws the grid with its top left at `at` and `seal_id` beneath. A colour that is not
/// `#RRGGBB` is `SealColour`: core only gives palette colours, so that is a bug, and it halts.
pub(super) fn draw(
    frame: &mut Frame,
    at: Point,
    grid: &[[bool; 8]; 8],
    colour_hex: &str,
    seal_id: &str,
) -> Result<(), RenderError> {
    let filled = colour(colour_hex).ok_or(RenderError::SealColour)?;
    for (row, cells) in (0u32..).zip(grid) {
        for (column, &on) in (0u32..).zip(cells) {
            let style = PrimitiveStyleBuilder::new()
                .fill_color(if on { filled } else { TILE })
                .stroke_color(OUTLINE)
                .stroke_width(1)
                .stroke_alignment(StrokeAlignment::Inside)
                .build();
            let top_left = at + Size::new(column * CELL, row * CELL);
            let cell = Rectangle::new(top_left, Size::new(CELL, CELL)).into_styled(style);
            let Ok(()) = cell.draw(frame);
        }
    }
    let x = SEAL_SIDE.saturating_sub(text::width(seal_id, &BODY_FONT)) / 2;
    let caption = at + Size::new(x, SEAL_SIDE + SEAL_CAPTION_GAP);
    text::line(frame, caption, seal_id, &BODY_FONT, TEXT);
    Ok(())
}

/// `#RRGGBB`, in either case, as the panel's colour; `None` for anything else.
fn colour(hex: &str) -> Option<Rgb565> {
    let &[r1, r2, g1, g2, b1, b2] = hex.strip_prefix('#')?.as_bytes() else {
        return None;
    };
    let rgb = Rgb888::new(byte(r1, r2)?, byte(g1, g2)?, byte(b1, b2)?);
    Some(Rgb565::from(rgb))
}

/// The byte of two hex digits.
fn byte(high: u8, low: u8) -> Option<u8> {
    Some(nibble(high)? << 4 | nibble(low)?)
}

/// The value of one hex digit.
fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use embedded_graphics::prelude::{PointsIter, RgbColor};

    use super::*;
    use crate::screen::{Banners, Element, Item, Screen, ScreenId};

    /// The test-vector seal (seal-watchonly-braille.md, "Test-vector seal"): colour index 3.
    const VECTOR: [&str; 8] = [
        "#......#", "...##...", "........", "..####..", "##....##", "#......#", "##.##.##",
        "##.##.##",
    ];
    const AT: Point = Point::new(24, 12);

    fn grid() -> [[bool; 8]; 8] {
        VECTOR.map(|row| {
            let mut cells = [false; 8];
            for (cell, b) in cells.iter_mut().zip(row.bytes()) {
                *cell = b == b'#';
            }
            cells
        })
    }

    fn drawn(colour_hex: &str) -> Frame {
        let mut frame = Frame::new();
        draw(&mut frame, AT, &grid(), colour_hex, "5E0G7J6X").expect("a palette colour draws");
        frame
    }

    #[test]
    fn the_cell_centres_sample_back_as_the_grid() {
        let green = Rgb565::from(Rgb888::new(0x00, 0x9e, 0x73));
        let frame = drawn("#009E73");
        for (row, cells) in (0..).zip(grid()) {
            for (column, on) in (0..).zip(cells) {
                let centre = AT + Point::new(24 * column + 12, 24 * row + 12);
                let expected = if on { green } else { TILE };
                assert_eq!(frame.pixel(centre), Some(expected), "({row}, {column})");
            }
        }
    }

    #[test]
    fn every_cell_edge_is_the_outline_colour() {
        let frame = drawn("#F0E442");
        for row in 0..8 {
            for column in 0..8 {
                let cell =
                    Rectangle::new(AT + Point::new(24 * column, 24 * row), Size::new(24, 24));
                let inner = Rectangle::new(cell.top_left + Point::new(1, 1), Size::new(22, 22));
                for p in cell.points() {
                    let edge = !inner.contains(p);
                    assert_eq!(frame.pixel(p) == Some(OUTLINE), edge, "{p:?}");
                }
            }
        }
    }

    #[test]
    fn the_seal_id_is_centred_beneath_and_the_page_fits() {
        let frame = drawn("#000000");
        // A black fill is still outlined, and the tile shows through the empty cells.
        assert_eq!(frame.pixel(AT + Point::new(12, 12)), Some(Rgb565::BLACK));
        assert_eq!(frame.pixel(AT + Point::new(36, 12)), Some(TILE));
        // The ID's 80 px sit 56 px in, 2 px below the grid, and nothing else is drawn there.
        let mut alone = Frame::new();
        text::line(
            &mut alone,
            AT + Point::new(56, 194),
            "5E0G7J6X",
            &BODY_FONT,
            TEXT,
        );
        let below = Rectangle::new(AT + Point::new(0, 192), Size::new(192, 22));
        for p in below.points() {
            assert_eq!(frame.pixel(p), alone.pixel(p), "{p:?}");
        }
        assert!(below.points().any(|p| frame.pixel(p) == Some(TEXT)));
        // The seal-image page: the element centred in the content area fits.
        let grid = grid();
        let page = Screen::new(
            ScreenId::SealImage,
            "Seal",
            Banners {
                test_registry: true,
                simulator: true,
            },
        )
        .with(Element::public(
            Point::new(24, 0),
            Item::Seal {
                grid: &grid,
                colour_hex: "#009E73",
                seal_id: "5E0G7J6X",
            },
        ));
        assert!(page.fits());
        assert_eq!(
            page.elements()[0].bounds(),
            Rectangle::new(Point::new(24, 0), Size::new(192, 214))
        );
    }

    #[test]
    fn colour_reads_hash_rrggbb_only() {
        for (hex, rgb) in [
            ("#000000", (0x00, 0x00, 0x00)),
            ("#E69F00", (0xe6, 0x9f, 0x00)),
            ("#56b4e9", (0x56, 0xb4, 0xe9)),
            ("#CC79A7", (0xcc, 0x79, 0xa7)),
        ] {
            assert_eq!(
                colour(hex),
                Some(Rgb565::from(Rgb888::new(rgb.0, rgb.1, rgb.2)))
            );
        }
        assert_eq!(colour("#FFFFFF"), Some(Rgb565::WHITE));
        for refused in [
            "009E73", "#009E7", "#009E733", "#009E7G", "#+09E73", "# 09E73", "", "#",
        ] {
            assert_eq!(colour(refused), None, "{refused:?}");
        }
        let mut frame = Frame::new();
        assert_eq!(
            draw(&mut frame, AT, &grid(), "green", "5E0G7J6X"),
            Err(RenderError::SealColour)
        );
    }
}
