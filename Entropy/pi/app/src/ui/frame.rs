//! The frame: exactly the pixels the ST7789 gets (docs/pi-firmware.md "`hal::Display`";
//! tasks/todo.md, M3 group 5 and Q28 (c)).
//!
//! - 240×240 RGB565 values, row by row from the top left, in one boxed buffer. The device sends
//!   them to the panel; the simulator writes them as PNG files.
//! - Only `ui` can make a `Frame` (`Frame::new` is `pub(in crate::ui)`), so every frame outside
//!   `ui`'s own tests belongs to a renderer's `Painter`, and no other module can draw: the HAL's
//!   `Display` gets a `&Frame`, which cannot draw.
//! - It is an embedded-graphics `DrawTarget` with `Error = Infallible`: a pixel outside the panel
//!   is clipped, as the trait asks, and no draw can fail. Draws match their `Result` exhaustively
//!   (`let Ok(..) = ..`), never with `.ok()`, `let _` or an `_name` binding (rule 3).
//! - Black is all bits zero, so `clear` is also the wipe: before each render and after each
//!   present (`Painter::present`), and on drop (rule 5). No `Debug` and no `Clone`: a frame can
//!   hold the words.

use core::convert::Infallible;

use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::pixelcolor::raw::RawU16;
use embedded_graphics::prelude::{DrawTarget, IntoStorage, OriginDimensions, Pixel, Point, Size};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The panel's side in pixels.
pub const SIDE: u32 = 240;
/// `SIDE` for indexing.
const SIDE_PX: usize = 240;

/// One full frame of the panel. Wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Frame {
    /// Raw RGB565 values (`Rgb565::into_storage`), row by row.
    pixels: Box<[u16]>,
}

impl Frame {
    /// A black frame. Only `ui` makes one: the `Painter`, and the painters' tests.
    pub(in crate::ui) fn new() -> Self {
        Frame {
            pixels: vec![0; SIDE_PX * SIDE_PX].into_boxed_slice(),
        }
    }

    /// Every pixel black, all bits zero: also the wipe.
    pub fn clear(&mut self) {
        self.pixels.zeroize();
    }

    /// The pixel at `point`, or `None` outside the panel.
    pub fn pixel(&self, point: Point) -> Option<Rgb565> {
        index(point).map(|i| Rgb565::from(RawU16::new(self.pixels[i])))
    }

    /// Every pixel, row by row from the top left: what the panel gets.
    pub fn pixels(&self) -> impl Iterator<Item = Rgb565> + '_ {
        self.pixels
            .iter()
            .map(|&raw| Rgb565::from(RawU16::new(raw)))
    }

    /// The same pixels as raw RGB565 values (`Rgb565::into_storage`: red in the top 5 bits, blue
    /// in the low 5), for a reader without embedded-graphics: the simulator's PNG writer.
    pub fn raw(&self) -> &[u16] {
        &self.pixels
    }
}

/// The buffer index of `point`, or `None` outside the panel.
fn index(point: Point) -> Option<usize> {
    match (usize::try_from(point.x), usize::try_from(point.y)) {
        (Ok(x), Ok(y)) if x < SIDE_PX && y < SIDE_PX => Some(y * SIDE_PX + x),
        _ => None,
    }
}

impl OriginDimensions for Frame {
    fn size(&self) -> Size {
        Size::new(SIDE, SIDE)
    }
}

impl DrawTarget for Frame {
    type Color = Rgb565;
    type Error = Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Infallible>
    where
        I: IntoIterator<Item = Pixel<Rgb565>>,
    {
        for Pixel(point, color) in pixels {
            if let Some(i) = index(point) {
                self.pixels[i] = color.into_storage();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use embedded_graphics::Drawable;
    use embedded_graphics::prelude::{Dimensions, Primitive, RgbColor};
    use embedded_graphics::primitives::{PrimitiveStyle, Rectangle};

    use super::*;

    fn count(frame: &Frame, colour: Rgb565) -> usize {
        frame.pixels().filter(|&p| p == colour).count()
    }

    #[test]
    fn a_new_frame_is_black_and_a_pixel_reads_back() {
        let mut frame = Frame::new();
        assert_eq!(frame.pixels().count(), 240 * 240);
        assert_eq!(count(&frame, Rgb565::BLACK), 240 * 240);
        let colour = Rgb565::new(0x1f, 0x00, 0x0a);
        let Ok(()) = Pixel(Point::new(3, 4), colour).draw(&mut frame);
        assert_eq!(frame.pixel(Point::new(3, 4)), Some(colour));
        // Row by row: (3, 4) is the 4 * 240 + 3rd value, in both views.
        assert_eq!(frame.pixels().nth(4 * 240 + 3), Some(colour));
        assert_eq!(frame.raw().len(), 240 * 240);
        assert_eq!(frame.raw()[4 * 240 + 3], 0xf80a);
        assert_eq!(colour.into_storage(), 0xf80a);
        assert_eq!(frame.pixel(Point::new(4, 3)), Some(Rgb565::BLACK));
        assert_eq!(count(&frame, Rgb565::BLACK), 240 * 240 - 1);
        assert_eq!(
            frame.bounding_box(),
            Rectangle::new(Point::zero(), Size::new(240, 240))
        );
    }

    #[test]
    fn pixels_off_the_panel_are_clipped() {
        let mut frame = Frame::new();
        for point in [
            Point::new(-1, 0),
            Point::new(0, -1),
            Point::new(240, 0),
            Point::new(0, 240),
            Point::new(i32::MAX, i32::MAX),
            Point::new(i32::MIN, i32::MIN),
        ] {
            let Ok(()) = Pixel(point, Rgb565::WHITE).draw(&mut frame);
            assert_eq!(frame.pixel(point), None);
        }
        assert_eq!(count(&frame, Rgb565::BLACK), 240 * 240);
        // A square half off each edge leaves a 10×10 corner on the panel.
        let square = Rectangle::new(Point::new(230, 230), Size::new(20, 20))
            .into_styled(PrimitiveStyle::with_fill(Rgb565::WHITE));
        let Ok(()) = square.draw(&mut frame);
        assert_eq!(count(&frame, Rgb565::WHITE), 100);
        assert_eq!(frame.pixel(Point::new(239, 239)), Some(Rgb565::WHITE));
        assert_eq!(frame.pixel(Point::new(229, 239)), Some(Rgb565::BLACK));
    }

    #[test]
    fn clear_zeroes_every_pixel() {
        let mut frame = Frame::new();
        let area = frame.bounding_box();
        let Ok(()) = frame.fill_solid(&area, Rgb565::WHITE);
        assert_eq!(count(&frame, Rgb565::WHITE), 240 * 240);
        frame.clear();
        assert_eq!(Rgb565::BLACK.into_storage(), 0);
        assert!(frame.pixels.iter().all(|&raw| raw == 0));
        assert_eq!(count(&frame, Rgb565::BLACK), 240 * 240);
    }
}
