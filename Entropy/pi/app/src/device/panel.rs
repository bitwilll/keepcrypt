//! The panel driver (docs/pi-firmware.md "`hal::Display`"; tasks/todo.md, M4 group 5, Q36 (c) and
//! Q44): KeepCrypt's own ST7789 driver.
//!
//! - Pure: `Panel` talks to a `Bus` (the SPI writes, the reset line, the backlight and a pause),
//!   which group 10's Linux glue implements over rppal and the tests record. It holds no pins and
//!   does no I/O of its own.
//! - Everything specific to a screen is one `PanelProfile`, a `const` of data: its orientation
//!   byte, its start-up settings (only opcodes from `ST7789_INIT_OPCODES`), its whole frame memory,
//!   where the 240×240 frame sits in it, and its bus speed. `PROFILES` lists every profile and
//!   `PANEL` names the image's. M4 has one: the Waveshare 1.3-inch HAT, with the approved bytes.
//! - The driver owns every step that is the same on every screen: the reset, MADCTL, sleep out,
//!   the windows, the memory writes and display on.
//! - The panel never shows a stale frame. Init blanks all of frame memory before display on, and
//!   `Drop` blanks it again (on a crash too; stop mode re-runs init). Every present writes the
//!   whole 240×240 window, and the API offers no other. The backlight comes on only once a whole
//!   frame is in, and goes off on any bus error and in `Drop`.
//! - The transfer buffer holds frame bytes (the words, on a Protected screen) only during a
//!   present, and is zeroized after every one, on error too (rule 5). No `Debug` and no `Clone`.

use keepcrypt_pi::hal::{Display, HalError};
use keepcrypt_pi::screen::Screen;
use keepcrypt_pi::ui::Frame;
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
mod tests;

// The ST7789's commands that the driver or a profile sends (Sitronix ST7789V datasheet [S31]).
/// Sleep out.
const SLPOUT: u8 = 0x11;
/// Display inversion off.
const INVOFF: u8 = 0x20;
/// Display inversion on.
const INVON: u8 = 0x21;
/// Display on.
const DISPON: u8 = 0x29;
/// Column address set: the window's first and last column.
const CASET: u8 = 0x2A;
/// Row address set: the window's first and last row.
const RASET: u8 = 0x2B;
/// Memory write: the data that follows fills the window.
const RAMWR: u8 = 0x2C;
/// Memory data access control: the orientation and the colour order.
const MADCTL: u8 = 0x36;
/// Interface pixel format.
const COLMOD: u8 = 0x3A;
/// Porch setting.
const PORCTRL: u8 = 0xB2;
/// Gate control.
const GCTRL: u8 = 0xB7;
/// VCOM setting.
const VCOMS: u8 = 0xBB;
/// LCM control.
const LCMCTRL: u8 = 0xC0;
/// VDV and VRH command enable.
const VDVVRHEN: u8 = 0xC2;
/// VRH set.
const VRHS: u8 = 0xC3;
/// VDV set.
const VDVS: u8 = 0xC4;
/// Frame rate control in normal mode.
const FRCTRL2: u8 = 0xC6;
/// Power control 1.
const PWCTRL1: u8 = 0xD0;
/// Positive voltage gamma control.
const PVGAMCTRL: u8 = 0xE0;
/// Negative voltage gamma control.
const NVGAMCTRL: u8 = 0xE1;

/// The only opcodes a profile's `init` may hold: pixel format, power, porch, gamma and inversion
/// settings. Everything else belongs to the driver or is never sent: MADCTL, sleep in and out,
/// display on and off, windows, memory writes, scrolling, partial mode and idle mode. INVOFF is
/// here because some panels need inversion off (Q50; [S36]).
pub const ST7789_INIT_OPCODES: [u8; 14] = [
    COLMOD, PORCTRL, GCTRL, VCOMS, LCMCTRL, VDVVRHEN, VRHS, VDVS, FRCTRL2, PWCTRL1, PVGAMCTRL,
    NVGAMCTRL, INVOFF, INVON,
];

/// The frame's side in pixels (`ui::SIDE`).
const SIDE: u16 = 240;
/// The window every present fills.
const FRAME: Size = Size {
    width: SIDE,
    height: SIDE,
};
/// The pixels of one frame.
const FRAME_PIXELS: usize = 240 * 240;
/// The bytes of one SPI write: spidev's default `bufsiz` [S24].
const CHUNK: usize = 4096;
/// Zeros for the blank, in static memory: no frame byte ever passes through them.
static ZEROS: [u8; CHUNK] = [0; CHUNK];

/// The panel's wires: the SPI bus with its data/command line, the reset line, the backlight, and
/// a pause. Group 10's Linux glue implements it over rppal; the tests record it.
pub trait Bus {
    /// Sends `cmd` with the data/command line low, then `args`, if any, with it high: all of
    /// them, or an error.
    fn command(&mut self, cmd: u8, args: &[u8]) -> Result<(), HalError>;
    /// Sends `bytes` with the data/command line high: the whole slice, or an error.
    fn data(&mut self, bytes: &[u8]) -> Result<(), HalError>;
    /// Drives the reset line (active low): a single register write that cannot fail.
    fn reset(&mut self, high: bool);
    /// Switches the backlight (active high): a single register write that cannot fail.
    fn backlight(&mut self, on: bool);
    /// Waits `ms` milliseconds.
    fn sleep_ms(&mut self, ms: u16);
}

/// A size in pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size {
    pub width: u16,
    pub height: u16,
}

/// A column and row in frame memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Point {
    pub x: u16,
    pub y: u16,
}

/// One start-up command of a profile.
#[derive(Debug, PartialEq, Eq)]
pub struct Step {
    /// The opcode, one of `ST7789_INIT_OPCODES`.
    pub cmd: u8,
    /// Its parameter bytes.
    pub args: &'static [u8],
    /// The pause after it, in milliseconds; 0 for none.
    pub delay_ms: u16,
}

/// A step with no pause after it.
const fn step(cmd: u8, args: &'static [u8]) -> Step {
    Step {
        cmd,
        args,
        delay_ms: 0,
    }
}

/// Everything specific to one screen (Q44): data only, no pins and no I/O. Each is a `const` in
/// `PROFILES`, whose tests check it.
#[derive(Debug, PartialEq, Eq)]
pub struct PanelProfile {
    /// Unique among `PROFILES`: the screen type an image is built for (Q47).
    pub name: &'static str,
    /// MADCTL's byte, which the driver sends at init step 3 and in `Drop`. Its MV bit (`0x20`)
    /// swaps rows and columns and must match `ram`; its colour-order bit (`0x08`) is part of it.
    pub madctl: u8,
    /// The rest of init steps 3-5, after MADCTL, in order.
    pub init: &'static [Step],
    /// The controller's whole frame memory in this orientation: 320×240 with MV set, 240×320 with
    /// MV clear. Init, `Drop` and stop mode blank all of it.
    pub ram: Size,
    /// Where the 240×240 frame sits in `ram`: its top-left pixel.
    pub origin: Point,
    /// The SPI clock the Linux glue asks for, in hertz (SPI mode 0). The datasheet's serial write
    /// cycle is at least 66 ns, about 15 MHz ([S31] p.44, TSCYCW).
    pub spi_hz: u32,
}

/// The Waveshare 1.3-inch LCD HAT [S5]: Waveshare's start-up settings as SeedSigner ships them
/// [S6], which Waveshare's Pico-board driver for the same panel also sends [S34]. These are the
/// approved bytes; H1a confirms `madctl`, INVON and `spi_hz` on the board.
pub const WAVESHARE_1IN3_HAT: PanelProfile = PanelProfile {
    name: "st7789-240x240",
    // MX, MV and ML set, RGB order: MV swaps rows and columns, so the memory is 320 columns by 240
    // rows [S31].
    madctl: 0x70,
    init: &[
        // 16 bits a pixel, which is what `Frame::raw()` gives.
        step(COLMOD, &[0x05]),
        step(PORCTRL, &[0x0C, 0x0C, 0x00, 0x33, 0x33]),
        step(GCTRL, &[0x35]),
        step(VCOMS, &[0x19]),
        step(LCMCTRL, &[0x2C]),
        step(VDVVRHEN, &[0x01]),
        step(VRHS, &[0x12]),
        step(VDVS, &[0x20]),
        step(FRCTRL2, &[0x0F]),
        step(PWCTRL1, &[0xA4, 0xA1]),
        step(
            PVGAMCTRL,
            &[
                0xD0, 0x04, 0x0D, 0x11, 0x13, 0x2B, 0x3F, 0x54, 0x4C, 0x18, 0x0D, 0x0B, 0x1F, 0x23,
            ],
        ),
        step(
            NVGAMCTRL,
            &[
                0xD0, 0x04, 0x0C, 0x11, 0x13, 0x2C, 0x3F, 0x44, 0x51, 0x2F, 0x1F, 0x1F, 0x20, 0x23,
            ],
        ),
        step(INVON, &[]),
    ],
    ram: Size {
        width: 320,
        height: 240,
    },
    origin: Point { x: 0, y: 0 },
    // Waveshare's demo rate, which SeedSigner runs [S6]: above the datasheet's serial write
    // timing. If H1a shows a corrupt or dark panel, the first bring-up fix lowers it to an in-spec
    // rate (lead decision, 2026-10-14).
    spi_hz: 40_000_000,
};

/// Every profile, each checked by the tests: in M4 the HAT alone, or a second HAT profile if Q50
/// applies.
pub const PROFILES: &[&PanelProfile] = &[&WAVESHARE_1IN3_HAT];

/// The image's profile: the one line that names it. Group 10 uses it; M4b's B3 replaces it.
pub const PANEL: &PanelProfile = &WAVESHARE_1IN3_HAT;

/// The panel on `bus`, with `profile`'s settings. No `Debug` and no `Clone`: its buffer carries
/// frame bytes during a present.
pub struct Panel<B: Bus> {
    bus: B,
    profile: &'static PanelProfile,
    /// One SPI write of frame bytes, high byte first. Zeroized after every present.
    buf: Zeroizing<[u8; CHUNK]>,
}

impl<B: Bus> Panel<B> {
    /// Init steps 1-8: all of frame memory black and the display on, with the backlight still off.
    /// On an error the backlight is off, and the dropped panel blanks frame memory again where the
    /// bus lets it (`Drop`).
    pub fn new(bus: B, profile: &'static PanelProfile) -> Result<Self, HalError> {
        let mut panel = Panel {
            bus,
            profile,
            buf: Zeroizing::new([0; CHUNK]),
        };
        match panel.init() {
            Ok(()) => Ok(panel),
            Err(_) => Err(panel.fault()),
        }
    }

    /// The init steps in order. The driver sends the steps that are the same on every screen; the
    /// profile supplies `madctl` and its own settings.
    fn init(&mut self) -> Result<(), HalError> {
        // 1. Nothing shows until a whole frame is in.
        self.bus.backlight(false);
        // 2. A hardware reset.
        self.bus.reset(true);
        self.bus.sleep_ms(10);
        self.bus.reset(false);
        self.bus.sleep_ms(10);
        self.bus.reset(true);
        self.bus.sleep_ms(120);
        // 3-5. The orientation, then the profile's settings.
        self.bus.command(MADCTL, &[self.profile.madctl])?;
        for step in self.profile.init {
            self.bus.command(step.cmd, step.args)?;
            if step.delay_ms > 0 {
                self.bus.sleep_ms(step.delay_ms);
            }
        }
        // 6. Out of sleep, then 120 ms [S23].
        self.bus.command(SLPOUT, &[])?;
        self.bus.sleep_ms(120);
        // 7. Frame memory keeps its contents through a reset and is random at power-on ([S31]
        // p.202), so all of it goes black before the display turns on.
        self.blank()?;
        // 8.
        self.bus.command(DISPON, &[])
    }

    /// Zeros over all of the profile's frame memory: its whole window, then
    /// `ram.width × ram.height × 2` zero bytes in writes of at most 4,096.
    fn blank(&mut self) -> Result<(), HalError> {
        let ram = self.profile.ram;
        self.window(Point { x: 0, y: 0 }, ram)?;
        // Pixels left: a u16 times a u16 fits a 32-bit usize.
        let mut left = usize::from(ram.width) * usize::from(ram.height);
        while left > 0 {
            let pixels = left.min(CHUNK / 2);
            self.bus.data(&ZEROS[..2 * pixels])?;
            left -= pixels;
        }
        Ok(())
    }

    /// Sets the window to `size` pixels from `at` and starts a memory write: the data that follows
    /// fills that window row by row and nothing outside it.
    fn window(&mut self, at: Point, size: Size) -> Result<(), HalError> {
        self.bus.command(CASET, &span(at.x, size.width)?)?;
        self.bus.command(RASET, &span(at.y, size.height)?)?;
        self.bus.command(RAMWR, &[])
    }

    /// Writes one whole frame, `pixels`, then zeroizes the buffer whatever the outcome (rule 5).
    /// The backlight comes on once the frame is in, and goes off on an error.
    fn show(&mut self, pixels: &[u16]) -> Result<(), HalError> {
        let drawn = self.draw(pixels);
        self.buf.zeroize();
        match drawn {
            Ok(()) => {
                self.bus.backlight(true);
                Ok(())
            }
            Err(_) => Err(self.fault()),
        }
    }

    /// The 240×240 window at the profile's origin, then its 57,600 pixels, row by row, each high
    /// byte first, in writes of at most 4,096 bytes through the buffer. Anything but one whole
    /// frame is refused before the window is set: there is no partial window.
    fn draw(&mut self, pixels: &[u16]) -> Result<(), HalError> {
        if pixels.len() != FRAME_PIXELS {
            return Err(HalError::Display);
        }
        self.window(self.profile.origin, FRAME)?;
        for chunk in pixels.chunks(CHUNK / 2) {
            for (bytes, pixel) in self.buf.as_chunks_mut::<2>().0.iter_mut().zip(chunk) {
                *bytes = pixel.to_be_bytes();
            }
            self.bus.data(&self.buf[..2 * chunk.len()])?;
        }
        Ok(())
    }

    /// Any bus error turns the backlight off, then gives `Display`, whatever error the bus gave
    /// (rule 3).
    fn fault(&mut self) -> HalError {
        self.bus.backlight(false);
        HalError::Display
    }
}

/// The four bytes of a window's columns or rows, `start ..= start + len - 1`, each high byte
/// first. An empty span, or one past the 16-bit range, is `Display`; no profile that passes the
/// `PROFILES` checks gives one.
fn span(start: u16, len: u16) -> Result<[u8; 4], HalError> {
    match len.checked_sub(1).and_then(|last| start.checked_add(last)) {
        Some(end) => {
            let [start_high, start_low] = start.to_be_bytes();
            let [end_high, end_low] = end.to_be_bytes();
            Ok([start_high, start_low, end_high, end_low])
        }
        None => Err(HalError::Display),
    }
}

impl<B: Bus> Display for Panel<B> {
    /// Writes `frame` whole; the device ignores `screen`.
    fn present(&mut self, frame: &Frame, _screen: &Screen<'_>) -> Result<(), HalError> {
        self.show(frame.raw())
    }
}

impl<B: Bus> Drop for Panel<B> {
    /// Blanks all of frame memory, after MADCTL so that the window is valid whatever state init
    /// reached, then turns the backlight off. On a panic this runs before the session is wiped:
    /// the app drops its `hal` first (group 10).
    fn drop(&mut self) {
        let blanked = self
            .bus
            .command(MADCTL, &[self.profile.madctl])
            .and_then(|()| self.blank());
        match blanked {
            // Every byte of frame memory is black.
            Ok(()) => self.bus.backlight(false),
            // A destructor cannot report the fault. The backlight goes off all the same, so
            // whatever the memory kept stays dark, and stop mode's init blanks it again.
            Err(_) => self.bus.backlight(false),
        }
    }
}
