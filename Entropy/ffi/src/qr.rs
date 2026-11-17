//! The QR codes the phone shows (tasks/todo.md, M5 group 9): the check request, the account and
//! descriptor QRs, the registration, the collision report and the re-check without n, each encoded
//! here from core's text into the module matrix the reply carries (wire.rs's "QR matrix").
//!
//! - pi/app's settings (pi/app/src/ui/qr.rs), so a phone and a Pi show the same code for the same
//!   text: qrcodegen-no-heap, versions 1-11, low error correction boosted as far as the version
//!   allows, and the encoder's own choice of mode and mask. Core's payloads have fixed lengths, so
//!   one too long for version 11 is a bug, and halts.
//! - The encoder works in two buffers of `Version::new(11).buffer_len()` bytes, which are wiped
//!   after every code, whatever its outcome: the registration and collision-report QRs carry seal
//!   codes, the account and descriptor QRs an xpub (rule 5). The matrix copied out is wiped on
//!   drop.
//! - The shell draws the quiet zone and picks the module size; the matrix has neither.

use qrcodegen_no_heap::{DataTooLong, QrCode, QrCodeEcc, Version};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::ceremony::Halt;

/// The largest version encoded.
const MAX_VERSION: Version = Version::new(11);
/// Each buffer's length: what `MAX_VERSION` needs.
const BUFFER_LEN: usize = MAX_VERSION.buffer_len();

/// A code's modules, copied out of the encoder: its side, and its modules packed row by row from
/// the top left, most significant bit first, 1 for dark (wire.rs's "QR matrix"). Wiped on drop. No
/// `Debug` or `Clone`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Matrix {
    side: u8,
    bits: Vec<u8>,
}

impl Matrix {
    /// The side in modules: 21-61.
    pub(crate) fn side(&self) -> u8 {
        self.side
    }

    /// The modules, side x side bits; the last byte's spare bits are 0.
    pub(crate) fn bits(&self) -> &[u8] {
        &self.bits
    }
}

/// The encoder's two buffers. Wiped after each code and on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct Buffers {
    temp: Box<[u8]>,
    out: Box<[u8]>,
}

impl Buffers {
    fn new() -> Self {
        Buffers {
            temp: vec![0; BUFFER_LEN].into_boxed_slice(),
            out: vec![0; BUFFER_LEN].into_boxed_slice(),
        }
    }
}

/// The matrix of `text`'s code.
pub(crate) fn matrix(text: &str) -> Result<Matrix, Halt> {
    encode(text, &mut Buffers::new())
}

/// The descriptor QR: the receive and change descriptors on two lines
/// (docs/seal-watchonly-braille.md "Watch-only export"), its text sized once so that it never
/// reallocates and leaves a copy behind.
pub(crate) fn descriptors(receive: &str, change: &str) -> Result<Matrix, Halt> {
    let len = receive
        .len()
        .checked_add(1)
        .and_then(|len| len.checked_add(change.len()))
        .ok_or(Halt)?;
    let mut text = Zeroizing::new(String::with_capacity(len));
    text.push_str(receive);
    text.push('\n');
    text.push_str(change);
    matrix(&text)
}

/// Encodes `text` in `buffers` and copies its matrix out, then wipes both buffers, on success and
/// on error alike.
fn encode(text: &str, buffers: &mut Buffers) -> Result<Matrix, Halt> {
    let copied = copy_out(text, buffers);
    buffers.zeroize();
    copied
}

/// The smallest code of versions 1 to `MAX_VERSION` that holds `text`, at pi/app's settings, as a
/// `Matrix`.
fn copy_out(text: &str, buffers: &mut Buffers) -> Result<Matrix, Halt> {
    let Buffers { temp, out } = buffers;
    let qr = match QrCode::encode_text(
        text,
        temp,
        out,
        QrCodeEcc::Low,
        Version::MIN,
        MAX_VERSION,
        None,
        true,
    ) {
        Ok(qr) => qr,
        Err(DataTooLong::SegmentTooLong | DataTooLong::DataOverCapacity(..)) => return Err(Halt),
    };
    let side = u8::try_from(qr.size()).map_err(|_| Halt)?;
    let modules = usize::from(side)
        .checked_mul(usize::from(side))
        .ok_or(Halt)?;
    // Built in place, so a halt part way wipes what was copied.
    let mut matrix = Matrix {
        side,
        bits: vec![0; modules.div_ceil(8)],
    };
    let mut index = 0usize;
    for y in 0..qr.size() {
        for x in 0..qr.size() {
            if qr.get_module(x, y) {
                let byte = matrix.bits.get_mut(index / 8).ok_or(Halt)?;
                *byte |= 0x80 >> (index % 8);
            }
            index = index.checked_add(1).ok_or(Halt)?;
        }
    }
    Ok(matrix)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The check QR with the seal test vector's T and n (CLAUDE.md, "Go-ahead vector").
    const CHECK_URL: &str = "https://registry.invalid/check#t=2b8103c8dd64611df5c8c28b8fbf864a1005372f5da06a5777f92708ce79cb5c&n=0001020304050607";
    /// The register and collision-report QRs, with the seal test vector's code.
    const REGISTER_URL: &str = "https://registry.invalid/register#c=JXP3RDXYACJZ1NAX3RGQDJCJJN";

    fn zeroed(buffers: &Buffers) -> bool {
        buffers
            .temp
            .iter()
            .chain(buffers.out.iter())
            .all(|&b| b == 0)
    }

    /// The matrix, or the test fails.
    fn made(matrix: Result<Matrix, Halt>) -> Matrix {
        match matrix {
            Ok(matrix) => matrix,
            Err(Halt) => panic!("the text fits version 11"),
        }
    }

    /// Module (x, y) of a matrix, read back from its packed bits.
    fn dark(matrix: &Matrix, x: usize, y: usize) -> bool {
        let index = y * usize::from(matrix.side) + x;
        matrix.bits[index / 8] & (0x80 >> (index % 8)) != 0
    }

    #[test]
    fn version_11_holds_the_buffers() {
        assert_eq!(BUFFER_LEN, (61 * 61_usize).div_ceil(8) + 1);
    }

    // Every module copied out is the encoder's, row by row; the spare bits stay 0.
    #[test]
    fn the_matrix_is_the_encoders() {
        for text in [CHECK_URL, REGISTER_URL, "", &"y".repeat(321)] {
            let matrix = made(matrix(text));
            let mut temp = [0u8; BUFFER_LEN];
            let mut out = [0u8; BUFFER_LEN];
            let qr = QrCode::encode_text(
                text,
                &mut temp,
                &mut out,
                QrCodeEcc::Low,
                Version::MIN,
                MAX_VERSION,
                None,
                true,
            )
            .expect("fits");
            let side = usize::try_from(qr.size()).expect("positive");
            assert_eq!(usize::from(matrix.side()), side);
            assert_eq!(matrix.bits().len(), (side * side).div_ceil(8));
            for y in 0..side {
                for x in 0..side {
                    let at = (i32::try_from(x).expect("x"), i32::try_from(y).expect("y"));
                    assert_eq!(dark(&matrix, x, y), qr.get_module(at.0, at.1), "({x}, {y})");
                }
            }
            let spare = matrix.bits().len() * 8 - side * side;
            let last = matrix.bits().last().expect("a byte");
            assert_eq!(last & ((1u8 << spare) - 1), 0, "spare bits");
        }
    }

    // pi/app's both_buffers_are_zero_after_drawing_and_after_an_error, for the phone's encoder.
    #[test]
    fn both_buffers_are_zero_after_a_code_and_after_an_error() {
        let mut buffers = Buffers::new();
        for text in [CHECK_URL, REGISTER_URL, &"y".repeat(321)] {
            assert!(encode(text, &mut buffers).is_ok());
            assert!(zeroed(&buffers));
        }
        // Version 11 at L holds 321 bytes; one more halts, and the buffers are zero too.
        assert!(matches!(encode(&"y".repeat(322), &mut buffers), Err(Halt)));
        assert!(zeroed(&buffers));
        // The encoder really wrote into them: without the wipe they are not zero.
        let mut kept = Buffers::new();
        assert!(copy_out(REGISTER_URL, &mut kept).is_ok());
        assert!(!zeroed(&kept));
    }

    #[test]
    fn the_descriptor_text_is_two_lines() {
        let both = made(descriptors("wpkh(a)", "wpkh(b)"));
        let text = made(matrix("wpkh(a)\nwpkh(b)"));
        assert_eq!((both.side(), both.bits()), (text.side(), text.bits()));
    }
}
