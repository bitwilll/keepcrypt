//! Text (tasks/todo.md, M3 group 6): embedded-graphics' mono fonts, 10×20 for body text and 6×10
//! for the strips, the footer and small text (`screen::BODY_FONT`, `screen::SMALL_FONT`).
//!
//! - Wrapped text is drawn in the lines `screen::lines` gives, the same lines `Element::bounds`
//!   measured, so a model that fits draws inside its boxes.
//! - Words and codes are body text at ×2 through `Scaled`, a draw target that draws each pixel
//!   as an n×n block of the frame: an 8-letter word is 160 px wide.

use core::convert::Infallible;

use embedded_graphics::Drawable;
use embedded_graphics::mono_font::{MonoFont, MonoTextStyle};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::{DrawTarget, OriginDimensions, Pixel, Point, Size};
use embedded_graphics::primitives::Rectangle;
use embedded_graphics::text::{Baseline, Text};

use super::{Frame, LIGHTER, SIDE, TEXT};
use crate::screen::{BODY_FONT, LARGE_SCALE, advance, px};

/// The width of `text` on one line in `font`, as `Element::bounds` measures it.
pub(super) fn width(text: &str, font: &MonoFont<'_>) -> u32 {
    px(text.chars().count(), advance(font))
}

/// Draws `text` on one line with its top left at `at`, and returns the point after its last
/// character.
pub(super) fn line<D>(
    target: &mut D,
    at: Point,
    text: &str,
    font: &MonoFont<'_>,
    colour: Rgb565,
) -> Point
where
    D: DrawTarget<Color = Rgb565, Error = Infallible>,
{
    let style = MonoTextStyle::new(font, colour);
    let Ok(next) = Text::with_baseline(text, at, style, Baseline::Top).draw(target);
    next
}

/// Draws `lines` from `at` down, one `font` height apart.
pub(super) fn lines<'t>(
    frame: &mut Frame,
    at: Point,
    lines: impl IntoIterator<Item = &'t str>,
    font: &MonoFont<'_>,
    colour: Rgb565,
) {
    let mut top = at;
    for text in lines {
        line(frame, top, text, font, colour);
        top += Size::new(0, font.character_size.height);
    }
}

/// Draws a word or a code in `BODY_FONT` at `LARGE_SCALE` from `at`, with the characters from
/// `lighter_from` on drawn lighter (an insert's letters past the fourth).
pub(super) fn large(frame: &mut Frame, at: Point, text: &str, lighter_from: Option<usize>) {
    let (plain, lighter) = match lighter_from.and_then(|n| text.char_indices().nth(n)) {
        Some((offset, _)) => text.split_at(offset),
        None => (text, ""),
    };
    let mut scaled = Scaled::new(frame, at, LARGE_SCALE);
    let next = line(&mut scaled, Point::zero(), plain, &BODY_FONT, TEXT);
    line(&mut scaled, next, lighter, &BODY_FONT, LIGHTER);
}

/// A draw target that draws each pixel as a `scale`×`scale` block of the frame, with pixel
/// (0, 0) at `origin`. Blocks off the panel are clipped, as the frame clips pixels.
pub(super) struct Scaled<'f> {
    frame: &'f mut Frame,
    origin: Point,
    scale: u32,
}

impl<'f> Scaled<'f> {
    pub(super) fn new(frame: &'f mut Frame, origin: Point, scale: u32) -> Self {
        Scaled {
            frame,
            origin,
            scale,
        }
    }

    /// The frame block that `point` covers, or `None` when it lies beyond `i32`'s range, which is
    /// off the panel.
    fn block(&self, point: Point) -> Option<Rectangle> {
        let scale = i64::from(self.scale);
        let x = i64::from(self.origin.x) + i64::from(point.x) * scale;
        let y = i64::from(self.origin.y) + i64::from(point.y) * scale;
        match (i32::try_from(x), i32::try_from(y)) {
            (Ok(x), Ok(y)) => Some(Rectangle::new(
                Point::new(x, y),
                Size::new(self.scale, self.scale),
            )),
            _ => None,
        }
    }
}

impl OriginDimensions for Scaled<'_> {
    fn size(&self) -> Size {
        let side = SIDE / self.scale.max(1);
        Size::new(side, side)
    }
}

impl DrawTarget for Scaled<'_> {
    type Color = Rgb565;
    type Error = Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Infallible>
    where
        I: IntoIterator<Item = Pixel<Rgb565>>,
    {
        for Pixel(point, colour) in pixels {
            if let Some(block) = self.block(point) {
                let Ok(()) = self.frame.fill_solid(&block, colour);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use embedded_graphics::prelude::RgbColor;

    use super::*;
    use crate::screen::{CONTENT, Element, Item};

    /// Every lit pixel's point.
    fn lit(frame: &Frame) -> Vec<Point> {
        frame
            .pixels()
            .zip(0..)
            .filter(|&(colour, _)| colour != Rgb565::BLACK)
            .map(|(_, i)| Point::new(i % 240, i / 240))
            .collect()
    }

    #[test]
    fn scaled_draws_each_pixel_as_a_block() {
        let mut frame = Frame::new();
        let mut scaled = Scaled::new(&mut frame, Point::new(10, 20), 3);
        assert_eq!(scaled.size(), Size::new(80, 80));
        let Ok(()) = Pixel(Point::new(2, 1), Rgb565::WHITE).draw(&mut scaled);
        // Pixel (2, 1) is the block from (10 + 6, 20 + 3), 3 px square.
        let mut expected: Vec<Point> = (0..3)
            .flat_map(|dy| (0..3).map(move |dx| Point::new(16 + dx, 23 + dy)))
            .collect();
        expected.sort_by_key(|p| (p.y, p.x));
        assert_eq!(lit(&frame), expected);
        // Blocks off the panel, and points past i32's range once scaled, are clipped; a block
        // across the edge keeps its part on the panel.
        let mut scaled = Scaled::new(&mut frame, Point::new(10, 20), 3);
        for point in [
            Point::new(-5, 0),
            Point::new(80, 0),
            Point::new(i32::MAX, i32::MAX),
            Point::new(i32::MIN, 0),
        ] {
            let Ok(()) = Pixel(point, Rgb565::WHITE).draw(&mut scaled);
        }
        assert_eq!(lit(&frame), expected);
        let mut scaled = Scaled::new(&mut frame, Point::new(10, 20), 3);
        let Ok(()) = Pixel(Point::new(-4, 0), Rgb565::WHITE).draw(&mut scaled);
        expected.extend([Point::new(0, 20), Point::new(0, 21), Point::new(0, 22)]);
        expected.sort_by_key(|p| (p.y, p.x));
        assert_eq!(lit(&frame), expected);
    }

    #[test]
    fn an_8_letter_word_at_x2_fits_and_is_the_1x_word_doubled() {
        let word = Element::protected(
            Point::zero(),
            Item::Large {
                text: "abstract".into(),
                lighter_from: Some(4),
            },
        );
        let bounds = word.bounds();
        assert_eq!(bounds.size, Size::new(160, 40));
        assert!(bounds.size.width <= CONTENT.width);

        let at = Point::new(40, 12);
        let mut frame = Frame::new();
        large(&mut frame, at, "abstract", Some(4));
        // The same word at ×1: "abst" plain and "ract" lighter.
        let mut once = Frame::new();
        let next = line(&mut once, Point::zero(), "abst", &BODY_FONT, TEXT);
        assert_eq!(next, Point::new(40, 0));
        line(&mut once, next, "ract", &BODY_FONT, LIGHTER);
        for y in 0..20 {
            for x in 0..80 {
                let expected = once.pixel(Point::new(x, y));
                for (dx, dy) in [(0, 0), (1, 0), (0, 1), (1, 1)] {
                    let doubled = at + Point::new(2 * x + dx, 2 * y + dy);
                    assert_eq!(frame.pixel(doubled), expected, "({x}, {y})");
                }
            }
        }
        // Nothing outside the word's box, and the lighter letters only past the fourth.
        let lit = lit(&frame);
        assert!(!lit.is_empty());
        let drawn = Rectangle::new(at, bounds.size);
        assert!(lit.iter().all(|&p| drawn.contains(p)));
        for p in lit {
            let colour = frame.pixel(p);
            let past_fourth = p.x >= at.x + 80;
            assert_eq!(colour == Some(LIGHTER), past_fourth, "{p:?}");
            assert!(colour == Some(TEXT) || colour == Some(LIGHTER));
        }
    }

    #[test]
    fn large_text_without_a_lighter_part_is_plain() {
        let mut frame = Frame::new();
        large(&mut frame, Point::zero(), "CF94-BCAJ", None);
        let mut past_end = Frame::new();
        large(&mut past_end, Point::zero(), "CF94-BCAJ", Some(9));
        assert!(frame.pixels().eq(past_end.pixels()));
        assert!(frame.pixels().all(|c| c == Rgb565::BLACK || c == TEXT));
        assert!(frame.pixels().any(|c| c == TEXT));
    }
}
