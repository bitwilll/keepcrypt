//! QR codes (docs/pi-firmware.md "`qr`"; tasks/todo.md, M3 group 6 and Q28 (b)).
//!
//! - qrcodegen-no-heap encodes into two buffers the `Painter` owns, each
//!   `Version::new(11).buffer_len()` bytes. Both are zeroized after every drawing, whatever its
//!   outcome: the registration and collision-report QRs carry seal codes (rule 5).
//! - Versions 1-11, with boosted error correction: version 11 is the largest whose 61 modules
//!   and a 4-module quiet zone on each side fit `screen::QR_SIDE` (216 px) at 3 px a module.
//! - Each code takes the largest whole module size that fits 216 px with its quiet zone, at least
//!   3 px, centred on a light square of 216 px. A payload too long for that is `QrTooLong`, never
//!   smaller modules: core's payloads have fixed lengths, so it is a bug, and it halts.
//! - The encoder picks the mode: the account QR's text (core's `qr_text`, already uppercase) is
//!   alphanumeric; the URLs and descriptors are bytes.

use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::{DrawTarget, Point, RgbColor, Size};
use embedded_graphics::primitives::Rectangle;
use qrcodegen_no_heap::{DataTooLong, QrCode, QrCodeEcc, Version};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::Frame;
use super::render::RenderError;
use crate::screen::QR_SIDE;

/// The largest version drawn.
const MAX_VERSION: Version = Version::new(11);
/// Each buffer's length: what `MAX_VERSION` needs.
const BUFFER_LEN: usize = MAX_VERSION.buffer_len();
/// Light modules on each side.
const QUIET_ZONE: u32 = 4;
/// The smallest module drawn.
const MIN_MODULE_PX: u32 = 3;

/// The encoder's two buffers. Zeroized after each drawing and on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct QrBuffers {
    temp: Box<[u8]>,
    out: Box<[u8]>,
}

impl QrBuffers {
    pub(super) fn new() -> Self {
        QrBuffers {
            temp: vec![0; BUFFER_LEN].into_boxed_slice(),
            out: vec![0; BUFFER_LEN].into_boxed_slice(),
        }
    }
}

/// Draws the QR code of `payload` in the `QR_SIDE` square at `at`, then zeroizes both buffers,
/// on success and on error alike.
pub(super) fn draw(
    frame: &mut Frame,
    at: Point,
    payload: &str,
    buffers: &mut QrBuffers,
) -> Result<(), RenderError> {
    let drawn = encode_and_draw(frame, at, payload, buffers);
    buffers.zeroize();
    drawn
}

/// Encodes `payload` into `buffers` and draws it.
fn encode_and_draw(
    frame: &mut Frame,
    at: Point,
    payload: &str,
    buffers: &mut QrBuffers,
) -> Result<(), RenderError> {
    let qr = encode(payload, buffers)?;
    let side = match u32::try_from(qr.size()) {
        Ok(side) => side,
        Err(_) => return Err(RenderError::QrTooLong),
    };
    let module = module_px(side);
    if module < MIN_MODULE_PX {
        return Err(RenderError::QrTooLong);
    }
    let offset = (QR_SIDE - side * module) / 2;
    let light = Rectangle::new(at, Size::new(QR_SIDE, QR_SIDE));
    let Ok(()) = frame.fill_solid(&light, Rgb565::WHITE);
    for (y, row) in (0..qr.size()).zip(0u32..) {
        for (x, column) in (0..qr.size()).zip(0u32..) {
            if qr.get_module(x, y) {
                let top_left = at + Size::new(offset + column * module, offset + row * module);
                let dark = Rectangle::new(top_left, Size::new(module, module));
                let Ok(()) = frame.fill_solid(&dark, Rgb565::BLACK);
            }
        }
    }
    Ok(())
}

/// The smallest code of versions 1 to `MAX_VERSION` that holds `payload`, with boosted error
/// correction and the encoder's own choice of mask.
fn encode<'b>(payload: &str, buffers: &'b mut QrBuffers) -> Result<QrCode<'b>, RenderError> {
    let QrBuffers { temp, out } = buffers;
    match QrCode::encode_text(
        payload,
        temp,
        out,
        QrCodeEcc::Low,
        Version::MIN,
        MAX_VERSION,
        None,
        true,
    ) {
        Ok(qr) => Ok(qr),
        Err(DataTooLong::SegmentTooLong | DataTooLong::DataOverCapacity(..)) => {
            Err(RenderError::QrTooLong)
        }
    }
}

/// The module size: the largest whole number of pixels at which `side` modules and the quiet
/// zone on each side fit `QR_SIDE`.
fn module_px(side: u32) -> u32 {
    QR_SIDE / (side + 2 * QUIET_ZONE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The check QR: `https://registry.invalid/check#t=<64 hex>&n=<16 hex>`, here with the seal
    /// test vector's T and n (CLAUDE.md, "Go-ahead vector").
    const CHECK_URL: &str = "https://registry.invalid/check#t=2b8103c8dd64611df5c8c28b8fbf864a1005372f5da06a5777f92708ce79cb5c&n=0001020304050607";
    /// The register and collision-report QRs, with the seal test vector's code.
    const REGISTER_URL: &str = "https://registry.invalid/register#c=JXP3RDXYACJZ1NAX3RGQDJCJJN";
    /// The re-check QR: T alone.
    const RECHECK_URL: &str = "https://registry.invalid/check#t=2b8103c8dd64611df5c8c28b8fbf864a1005372f5da06a5777f92708ce79cb5c";
    const AT: Point = Point::new(12, 12);

    /// An uppercase `ur:crypto-account` of the account QR's length.
    fn account_ur() -> String {
        format!("UR:CRYPTO-ACCOUNT/{}", "OEADCYJKSKTNBKAO".repeat(15))
    }

    /// One descriptor of core's form and length: `wpkh([fp/84h/0h/0h]xpub/branch/*)#checksum`,
    /// with a 111-character xpub.
    fn descriptor(branch: u8) -> String {
        let key: String = "6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3"
            .chars()
            .cycle()
            .take(107)
            .collect();
        format!("wpkh([73c5da0a/84h/0h/0h]xpub{key}/{branch}/*)#qwer7y9u")
    }

    /// The descriptor QR: receive and change on two lines (seal-watchonly-braille.md).
    fn descriptors() -> String {
        format!("{}\n{}", descriptor(0), descriptor(1))
    }

    /// The error correction level read from the format modules (0, 8) and (1, 8): format bits 14
    /// and 13, after undoing the format mask 0x5412's 1 and 0 there. L is 01, M 00, Q 11, H 10.
    /// qrcodegen-no-heap 1.8.1's own `error_correction_level` skips that step, so it is not used.
    fn level(qr: &QrCode<'_>) -> QrCodeEcc {
        match (!qr.get_module(0, 8), qr.get_module(1, 8)) {
            (false, true) => QrCodeEcc::Low,
            (false, false) => QrCodeEcc::Medium,
            (true, true) => QrCodeEcc::Quartile,
            (true, false) => QrCodeEcc::High,
        }
    }

    /// (version, error correction, module px) of `payload`'s code.
    fn measure(payload: &str) -> (u8, QrCodeEcc, u32) {
        let mut buffers = QrBuffers::new();
        let qr = encode(payload, &mut buffers).expect("fits version 11");
        let side = u32::try_from(qr.size()).expect("positive");
        (qr.version().value(), level(&qr), module_px(side))
    }

    fn zeroed(buffers: &QrBuffers) -> bool {
        buffers
            .temp
            .iter()
            .chain(buffers.out.iter())
            .all(|&b| b == 0)
    }

    #[test]
    fn version_11_is_the_largest_that_fits_216_px_at_3_px() {
        assert_eq!(BUFFER_LEN, (61 * 61_usize).div_ceil(8) + 1);
        assert_eq!(module_px(11 * 4 + 17), 3);
        assert!(module_px(12 * 4 + 17) < MIN_MODULE_PX);
        assert_eq!(module_px(21), 7);
    }

    #[test]
    fn every_payload_kind_fits_at_3_px_or_more() {
        assert_eq!(CHECK_URL.len(), 116);
        assert_eq!(REGISTER_URL.len(), 62);
        assert_eq!(RECHECK_URL.len(), 97);
        assert_eq!(account_ur().len(), 258);
        assert_eq!(descriptor(0).len(), 150);
        assert_eq!(descriptors().len(), 301);
        // The measured versions, error correction levels and module sizes.
        assert_eq!(
            [
                measure(CHECK_URL),
                measure(REGISTER_URL),
                measure(RECHECK_URL),
                measure(&account_ur()),
                measure(&descriptors()),
            ],
            [
                (6, QrCodeEcc::Low, 4),
                (4, QrCodeEcc::Medium, 5),
                (5, QrCodeEcc::Low, 4),
                (8, QrCodeEcc::Low, 3),
                (11, QrCodeEcc::Low, 3),
            ]
        );
        // The levels are the capacities': 301 bytes need version 11 at L (321 bytes; M holds
        // 251), and 62 bytes fill version 4 at M exactly. The crate's getter reads the masked
        // bits and calls that L code Quartile.
        let mut buffers = QrBuffers::new();
        let qr = encode(&descriptors(), &mut buffers).expect("fits");
        assert_eq!(qr.error_correction_level(), QrCodeEcc::Quartile);
        // Uppercase is what keeps the account QR small: lowercase would need byte mode.
        assert_eq!(measure(&account_ur().to_lowercase()).0, 10);
    }

    #[test]
    fn the_drawn_modules_are_the_encoders() {
        for payload in [
            CHECK_URL,
            REGISTER_URL,
            RECHECK_URL,
            &account_ur(),
            &descriptors(),
        ] {
            let mut frame = Frame::new();
            let mut buffers = QrBuffers::new();
            draw(&mut frame, AT, payload, &mut buffers).expect("fits");
            let mut reference = QrBuffers::new();
            let qr = encode(payload, &mut reference).expect("fits");
            let side = u32::try_from(qr.size()).expect("positive");
            let module = module_px(side);
            let offset = (QR_SIDE - side * module) / 2;
            // At least the 4-module quiet zone on every side.
            assert!(offset >= QUIET_ZONE * module);
            for (y, row) in (0..qr.size()).zip(0u32..) {
                for (x, column) in (0..qr.size()).zip(0u32..) {
                    let centre = AT
                        + Size::new(
                            offset + column * module + module / 2,
                            offset + row * module + module / 2,
                        );
                    let expected = if qr.get_module(x, y) {
                        Rgb565::BLACK
                    } else {
                        Rgb565::WHITE
                    };
                    assert_eq!(frame.pixel(centre), Some(expected), "({x}, {y})");
                }
            }
            // The quiet zone and the rest of the square are light; nothing outside it is drawn.
            let square = Rectangle::new(AT, Size::new(QR_SIDE, QR_SIDE));
            let code = Rectangle::new(
                AT + Size::new(offset, offset),
                Size::new(side * module, side * module),
            );
            for (colour, i) in frame.pixels().zip(0..) {
                let p = Point::new(i % 240, i / 240);
                if !square.contains(p) {
                    assert_eq!(colour, Rgb565::BLACK, "{p:?}");
                } else if !code.contains(p) {
                    assert_eq!(colour, Rgb565::WHITE, "{p:?}");
                }
            }
        }
    }

    #[test]
    fn both_buffers_are_zero_after_drawing_and_after_an_error() {
        let mut buffers = QrBuffers::new();
        for payload in [REGISTER_URL, &account_ur(), &descriptors()] {
            let mut frame = Frame::new();
            draw(&mut frame, AT, payload, &mut buffers).expect("fits");
            assert!(zeroed(&buffers));
        }
        // Version 11 at L holds 321 bytes. One more errs, draws nothing and leaves the buffers
        // zero too.
        let mut frame = Frame::new();
        draw(&mut frame, AT, &"y".repeat(321), &mut buffers).expect("fits version 11");
        assert!(zeroed(&buffers));
        let mut frame = Frame::new();
        let too_long = "y".repeat(322);
        assert_eq!(
            draw(&mut frame, AT, &too_long, &mut buffers),
            Err(RenderError::QrTooLong)
        );
        assert!(zeroed(&buffers));
        assert!(frame.pixels().all(|c| c == Rgb565::BLACK));
        // The encoder really wrote into the buffers: without the wipe they are not zero.
        let mut kept = QrBuffers::new();
        encode(REGISTER_URL, &mut kept).expect("fits");
        assert!(!zeroed(&kept));
    }
}
