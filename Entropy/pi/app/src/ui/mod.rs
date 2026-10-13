//! Drawing (tasks/todo.md, M3 "One drawing path", group 6): the only code that draws.
//!
//! - Screens build `screen::Screen` models. `Painter::present` draws one into its `Frame`, hands
//!   both to the HAL's `Display` and wipes the frame. Only this module can make a `Frame`, so
//!   every frame belongs to a `Painter` (outside the painters' own tests) and no other module can
//!   draw.
//! - `render` lays a model out: the top strip, each element through its painter, the footer. The
//!   painters are `text` (body, small and ×2 text), `braille` (cells), `seal` (the 8×8 image),
//!   `qr` (QR codes, encoded into buffers wiped after each drawing) and the Snake board in
//!   `render`. `hex` formats C and D for their models; `braille::caption_cells` makes the Seal
//!   ID's cells.
//! - One palette, below. Black is all bits zero, so a model with nothing in it draws a black
//!   frame. The stop screen (`halt`) is drawn on red.

use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::RgbColor;

mod braille;
mod frame;
mod hex;
mod qr;
mod render;
mod seal;
mod text;

pub use braille::caption_cells;
pub use frame::{Frame, SIDE};
pub use hex::hex_groups;
pub use render::{Painter, PresentError, RenderError};

/// The background, all bits zero: what `Frame::clear` leaves.
const BACKGROUND: Rgb565 = Rgb565::BLACK;
/// Body text, braille dots and the seal caption.
const TEXT: Rgb565 = Rgb565::WHITE;
/// Drawn lighter: an insert's letters past the fourth, its face 5, and the board's edge.
const LIGHTER: Rgb565 = Rgb565::new(16, 32, 16);
/// The step title, the footer's key names and the dot numbers: Okabe-Ito sky blue, #56B4E9.
const ACCENT: Rgb565 = Rgb565::new(10, 44, 28);
/// The TEST REGISTRY banner, the mirror flag and Snake's food: Okabe-Ito orange, #E69F00.
const WARNING: Rgb565 = Rgb565::new(28, 39, 0);
/// The SIMULATOR banner: Okabe-Ito reddish purple, #CC79A7.
const SIMULATOR: Rgb565 = Rgb565::new(25, 30, 20);
/// Snake: Okabe-Ito bluish green, #009E73.
const SNAKE: Rgb565 = Rgb565::new(0, 39, 14);
/// The stop screen's content area (docs/pi-firmware.md step 1, "a red stop screen"): #A50000, on
/// which white text has a contrast ratio above 7.
const STOP: Rgb565 = Rgb565::new(20, 0, 0);
