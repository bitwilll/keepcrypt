//! The PNG writer (tasks/todo.md, M3 group 7, Q28 (c)): RGB565 pixels to an 8-bit RGB PNG file,
//! with no image or compression crate.
//!
//! - An IHDR chunk (8-bit RGB, no interlace), one IDAT chunk and an IEND chunk, each with its
//!   CRC-32. The IDAT data is a zlib stream of stored (uncompressed) deflate blocks and its
//!   Adler-32, so the encoder is deterministic: the same pixels always give the same bytes.
//! - Every row uses filter type 0 (none). The 5- and 6-bit channels widen to 8 bits rounded to the
//!   nearest value, as embedded-graphics converts `Rgb565` to `Rgb888`: 0 stays 0 and a channel's
//!   maximum becomes 255.
//! - A file can hold a Protected screen's pixels, so every buffer here is `Zeroizing` (rule 5).

use keepcrypt_pi::hal::Zeroizing;

/// The eight bytes every PNG file starts with.
const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
/// The most bytes one stored deflate block holds.
const STORED_MAX: usize = 65_535;
/// The zlib header: deflate with a 32 KiB window, no preset dictionary, the fastest level. As a
/// 16-bit big-endian number it is a multiple of 31, as RFC 1950 requires.
const ZLIB_HEADER: [u8; 2] = [0x78, 0x01];

/// `pixels`, row by row from the top left with `width` to a row, as a PNG file. Panics unless
/// `pixels` holds at least one whole row and only whole rows.
pub fn encode(width: usize, pixels: &[u16]) -> Zeroizing<Vec<u8>> {
    assert!(
        width > 0 && !pixels.is_empty() && pixels.len().is_multiple_of(width),
        "a PNG needs whole rows of pixels"
    );
    let height = pixels.len() / width;

    // The image data: per row, a filter byte (0, none), then each pixel's R, G and B.
    let mut raw = Zeroizing::new(Vec::with_capacity(height * (1 + 3 * width)));
    for row in pixels.chunks(width) {
        raw.push(0);
        for &pixel in row {
            raw.extend_from_slice(&rgb888(pixel));
        }
    }

    // The zlib stream: the header, the data in stored blocks (a header byte with BFINAL set on the
    // last one and BTYPE 00, then LEN and its complement NLEN, little-endian), then the Adler-32
    // of the data, big-endian.
    let blocks = raw.len().div_ceil(STORED_MAX);
    let mut zlib = Zeroizing::new(Vec::with_capacity(raw.len() + 5 * blocks + 6));
    zlib.extend_from_slice(&ZLIB_HEADER);
    for (index, block) in raw.chunks(STORED_MAX).enumerate() {
        let len = u16::try_from(block.len()).expect("a stored block holds at most 65,535 bytes");
        zlib.push(u8::from(index + 1 == blocks));
        zlib.extend_from_slice(&len.to_le_bytes());
        zlib.extend_from_slice(&(!len).to_le_bytes());
        zlib.extend_from_slice(block);
    }
    zlib.extend_from_slice(&adler32(&raw).to_be_bytes());

    // IHDR: width, height, bit depth 8, colour type 2 (RGB), deflate, filter method 0, no
    // interlace.
    let mut header = Vec::with_capacity(13);
    header.extend_from_slice(&dimension(width).to_be_bytes());
    header.extend_from_slice(&dimension(height).to_be_bytes());
    header.extend_from_slice(&[8, 2, 0, 0, 0]);

    let mut png = Zeroizing::new(Vec::with_capacity(
        SIGNATURE.len() + 3 * 12 + 13 + zlib.len(),
    ));
    png.extend_from_slice(&SIGNATURE);
    chunk(&mut png, *b"IHDR", &header);
    chunk(&mut png, *b"IDAT", &zlib);
    chunk(&mut png, *b"IEND", &[]);
    png
}

/// A width or height as PNG stores it: 1 to 2^31 - 1.
fn dimension(n: usize) -> u32 {
    match u32::try_from(n) {
        Ok(n) if n <= 0x7fff_ffff => n,
        _ => panic!("a PNG side is at most 2^31 - 1 pixels"),
    }
}

/// Appends one chunk: its length (big-endian), its type, its data and the CRC-32 of type and data.
fn chunk(png: &mut Vec<u8>, kind: [u8; 4], data: &[u8]) {
    let len = dimension(data.len());
    png.extend_from_slice(&len.to_be_bytes());
    png.extend_from_slice(&kind);
    png.extend_from_slice(data);
    let crc = !crc32_update(crc32_update(!0, &kind), data);
    png.extend_from_slice(&crc.to_be_bytes());
}

/// CRC-32 as PNG and zlib define it: the reflected polynomial 0xEDB88320, starting from all ones
/// and inverted at the end.
pub fn crc32(bytes: &[u8]) -> u32 {
    !crc32_update(!0, bytes)
}

/// The CRC-32 register after `bytes`, bit by bit (no table: speed does not matter here).
fn crc32_update(mut crc: u32, bytes: &[u8]) -> u32 {
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            // All ones when the low bit is set, so the polynomial is applied only then.
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    crc
}

/// Adler-32 as zlib defines it (RFC 1950): two sums modulo 65,521, the second one high.
pub fn adler32(bytes: &[u8]) -> u32 {
    const MODULUS: u32 = 65_521;
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in bytes {
        a = (a + u32::from(byte)) % MODULUS;
        b = (b + a) % MODULUS;
    }
    (b << 16) | a
}

/// An RGB565 value (red in the top 5 bits, green in the middle 6, blue in the low 5) as 8-bit R,
/// G and B.
fn rgb888(pixel: u16) -> [u8; 3] {
    let [high, low] = pixel.to_be_bytes();
    let red = high >> 3;
    let green = ((high & 0x07) << 3) | (low >> 5);
    let blue = low & 0x1f;
    [widen(red, 31), widen(green, 63), widen(blue, 31)]
}

/// `value` of a channel whose maximum is `max`, scaled to 0-255 and rounded to the nearest: no tie
/// occurs, since `max` is odd.
fn widen(value: u8, max: u16) -> u8 {
    let scaled = (u16::from(value) * 255 + max / 2) / max;
    u8::try_from(scaled).expect("a channel at most its maximum scales to at most 255")
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::process::{Command, Stdio};

    use keepcrypt_pi::screen::{Banners, Element, Item, Screen, ScreenId};
    use keepcrypt_pi::ui::Painter;

    use super::*;
    use crate::{HwRngStream, SimHal};

    #[test]
    fn crc32_and_adler32_match_their_check_values() {
        // The CRC-32 check value of the "Rocksoft" catalogue, and Wikipedia's Adler-32 example.
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
        assert_eq!(crc32(b""), 0);
        assert_eq!(adler32(b""), 1);
        // The empty IEND chunk's CRC, which every PNG file ends with.
        assert_eq!(crc32(b"IEND"), 0xae42_6082);
    }

    #[test]
    fn channels_widen_rounded_to_the_nearest_8_bit_value() {
        for (max, top) in [(31u16, 31u8), (63, 63)] {
            for value in 0..=top {
                let exact = (f64::from(value) * 255.0 / f64::from(max)).round();
                assert_eq!(f64::from(widen(value, max)), exact, "{value} of {max}");
            }
        }
        // Where rounding and bit replication differ: 3 of 31 is 24.68, and 11 of 63 is 44.52.
        assert_eq!(widen(3, 31), 25);
        assert_eq!(widen(11, 63), 45);
        assert_eq!(rgb888(0x0000), [0, 0, 0]);
        assert_eq!(rgb888(0xffff), [255, 255, 255]);
        assert_eq!(rgb888(0xf800), [255, 0, 0]);
        assert_eq!(rgb888(0x07e0), [0, 255, 0]);
        assert_eq!(rgb888(0x001f), [0, 0, 255]);
    }

    #[test]
    fn a_2_by_2_file_matches_its_hand_checked_bytes() {
        // Red, green; blue, white. The three CRCs and the Adler-32 come from Python's zlib (crc32
        // and adler32), an implementation apart from this one.
        let png = encode(2, &[0xf800, 0x07e0, 0x001f, 0xffff]);
        let mut expected = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        // IHDR: 13 bytes; 2 × 2, 8-bit RGB, deflate, filter 0, no interlace.
        expected.extend_from_slice(&[0, 0, 0, 13]);
        expected.extend_from_slice(b"IHDR");
        expected.extend_from_slice(&[0, 0, 0, 2, 0, 0, 0, 2, 8, 2, 0, 0, 0]);
        expected.extend_from_slice(&[0xfd, 0xd4, 0x9a, 0x73]);
        // IDAT: 25 bytes; zlib header, one final stored block of 14 bytes (LEN 0x000e, NLEN
        // 0xfff1), two rows of filter 0 and RGB, the Adler-32.
        expected.extend_from_slice(&[0, 0, 0, 25]);
        expected.extend_from_slice(b"IDAT");
        expected.extend_from_slice(&[0x78, 0x01, 0x01, 0x0e, 0x00, 0xf1, 0xff]);
        expected.extend_from_slice(&[0, 255, 0, 0, 0, 255, 0]);
        expected.extend_from_slice(&[0, 0, 0, 255, 255, 255, 255]);
        expected.extend_from_slice(&[0x1f, 0xee, 0x05, 0xfb]);
        expected.extend_from_slice(&[0xde, 0xdd, 0xec, 0x2b]);
        // IEND: empty.
        expected.extend_from_slice(&[0, 0, 0, 0]);
        expected.extend_from_slice(b"IEND");
        expected.extend_from_slice(&[0xae, 0x42, 0x60, 0x82]);
        assert_eq!(&png[..], &expected[..]);
    }

    #[test]
    #[should_panic(expected = "whole rows")]
    fn a_partial_row_is_refused() {
        encode(240, &[0; 241]);
    }

    /// Decodes a PNG with Python's standard zlib (python3 -I, no file: stdin to stdout) and gives
    /// back the width, the height and the RGB bytes. The script checks the signature, every chunk's
    /// CRC, the chunk order, the IHDR fields, the zlib stream (zlib.decompress checks the Adler-32)
    /// and that every row uses filter 0.
    fn python_decode(png: &[u8]) -> (u32, u32, Vec<u8>) {
        const SCRIPT: &str = r#"
import sys, zlib
data = sys.stdin.buffer.read()
assert data[:8] == b"\x89PNG\r\n\x1a\n", "signature"
pos, kinds, header, idat = 8, [], b"", b""
while pos < len(data):
    n = int.from_bytes(data[pos:pos + 4], "big")
    kind, body = data[pos + 4:pos + 8], data[pos + 8:pos + 8 + n]
    assert zlib.crc32(kind + body) == int.from_bytes(data[pos + 8 + n:pos + 12 + n], "big"), kind
    kinds.append(kind)
    if kind == b"IHDR":
        header = body
    if kind == b"IDAT":
        idat += body
    pos += 12 + n
assert kinds == [b"IHDR", b"IDAT", b"IEND"], kinds
width, height = int.from_bytes(header[:4], "big"), int.from_bytes(header[4:8], "big")
assert header[8:] == bytes([8, 2, 0, 0, 0]), header
rows = zlib.decompress(idat)
stride = 1 + 3 * width
assert len(rows) == height * stride
out = bytearray()
for y in range(height):
    assert rows[y * stride] == 0, y
    out += rows[y * stride + 1:(y + 1) * stride]
sys.stdout.buffer.write(header[:8] + bytes(out))
"#;
        let mut child = Command::new("python3")
            .args(["-I", "-c", SCRIPT])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("python3 runs");
        child
            .stdin
            .take()
            .expect("a stdin pipe")
            .write_all(png)
            .expect("the PNG reaches python3");
        let output = child.wait_with_output().expect("python3 ends");
        assert!(output.status.success(), "python3 refused the PNG");
        let (size, rgb) = output.stdout.split_at(8);
        let side = |bytes: &[u8]| u32::from_be_bytes(bytes.try_into().expect("4 bytes"));
        (side(&size[..4]), side(&size[4..]), rgb.to_vec())
    }

    /// The RGB bytes `pixels` should decode to.
    fn rgb(pixels: &[u16]) -> Vec<u8> {
        pixels.iter().flat_map(|&p| rgb888(p)).collect()
    }

    #[test]
    fn pythons_zlib_decodes_every_rgb565_value() {
        // All 65,536 values in a 256 × 256 image: 196,864 bytes of image data, so four stored
        // blocks, the last one short.
        let pixels: Vec<u16> = (0..=u16::MAX).collect();
        let png = encode(256, &pixels);
        assert_eq!(python_decode(&png), (256, 256, rgb(&pixels)));
    }

    #[test]
    fn pythons_zlib_decodes_a_drawn_frame_to_its_pixels() {
        let mut hal = SimHal::new(HwRngStream::Counting);
        let banners = Banners {
            test_registry: true,
            simulator: true,
        };
        let grid = [[true, false, false, true, true, false, true, false]; 8];
        let screen = Screen::new(ScreenId::SealImage, "Seal", banners).with(Element::public(
            (24, 0).into(),
            Item::Seal {
                grid: &grid,
                colour_hex: "#E69F00",
                seal_id: "5E0G7J6X",
            },
        ));
        Painter::new()
            .present(&mut hal, &screen)
            .expect("the seal page draws");
        let presents = hal.take_presents();
        let frame = &presents[0].frame;
        let (width, height, decoded) = python_decode(&frame.png());
        assert_eq!((width, height), (240, 240));
        assert!(decoded == rgb(frame.raw()), "the decoded pixels differ");
        // Three stored blocks: 240 rows of 721 bytes.
        assert_eq!(
            frame.png().len(),
            8 + 25 + (12 + 2 + 3 * 5 + 173_040 + 4) + 12
        );
    }
}
