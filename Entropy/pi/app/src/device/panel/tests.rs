//! The panel driver's tests (tasks/todo.md, M4 group 5, Q44), on a recording bus and a model of
//! the controller's frame memory: the HAT's init pinned to the approved bytes; a present's window,
//! writes and byte order; the buffer and the backlight on every error; `Drop`; the `PROFILES`
//! checks; and a test-only profile whose frame sits 40 columns in.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::ops::Range;
use std::rc::Rc;

use keepcrypt_pi::show_stop;

use super::*;
use Op::{Backlight, Command, Data, Reset, Sleep};

/// MADCTL's MV bit: rows and columns swapped [S31].
const MV: u8 = 0x20;
/// The commands and data writes init sends on the HAT: MADCTL, 13 settings, SLPOUT, the window
/// (3), 38 writes of zeros and DISPON.
const INIT_SENDS: usize = 57;
/// The commands and data writes of a present: the window (3) and 29 writes.
const PRESENT_SENDS: usize = 32;
/// The HAT's window columns, 0 to 239.
const HAT_COLUMNS: [u8; 4] = [0x00, 0x00, 0x00, 0xEF];

/// A test-only profile: the HAT's, with the 240×240 frame 40 columns in, as a 320×240 screen
/// centres it. `tests.rs` is compiled only by `cargo test`.
const OFFSET: PanelProfile = PanelProfile {
    name: "test-offset",
    origin: Point { x: 40, y: 0 },
    ..WAVESHARE_1IN3_HAT
};

/// One call the panel made on the bus.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    Backlight(bool),
    Reset(bool),
    Sleep(u16),
    Command(u8, Vec<u8>),
    Data(Vec<u8>),
}

/// The log a test shares with its bus, so it outlives the panel and shows what `Drop` sent.
type Log = Rc<RefCell<Vec<Op>>>;

/// A bus that logs every call. Its commands and data writes are numbered from 0, and those in
/// `fails` return an error and are not logged: `k..usize::MAX` is a bus that stops at call `k`,
/// `k..k + 1` one lost write. The error is `Write`, so a `Display` from the panel is the panel's.
struct Recorder {
    log: Log,
    sends: usize,
    fails: Range<usize>,
}

impl Recorder {
    fn send(&mut self, op: Op) -> Result<(), HalError> {
        let call = self.sends;
        self.sends += 1;
        if self.fails.contains(&call) {
            return Err(HalError::Write);
        }
        self.log.borrow_mut().push(op);
        Ok(())
    }
}

impl Bus for Recorder {
    fn command(&mut self, cmd: u8, args: &[u8]) -> Result<(), HalError> {
        self.send(Command(cmd, args.to_vec()))
    }

    fn data(&mut self, bytes: &[u8]) -> Result<(), HalError> {
        self.send(Data(bytes.to_vec()))
    }

    fn reset(&mut self, high: bool) {
        self.log.borrow_mut().push(Reset(high));
    }

    fn backlight(&mut self, on: bool) {
        self.log.borrow_mut().push(Backlight(on));
    }

    fn sleep_ms(&mut self, ms: u16) {
        self.log.borrow_mut().push(Sleep(ms));
    }
}

/// `profile` initialised on a recording bus whose calls in `fails` fail, and the bus's log.
fn start(
    profile: &'static PanelProfile,
    fails: Range<usize>,
) -> (Result<Panel<Recorder>, HalError>, Log) {
    let log = Log::default();
    let bus = Recorder {
        log: Rc::clone(&log),
        sends: 0,
        fails,
    };
    (Panel::new(bus, profile), log)
}

/// Everything logged since the last `take`.
fn take(log: &Log) -> Vec<Op> {
    std::mem::take(&mut *log.borrow_mut())
}

/// The commands and data writes in `ops`: the calls a bus can refuse.
fn sends(ops: &[Op]) -> usize {
    ops.iter()
        .filter(|op| matches!(op, Command(..) | Data(_)))
        .count()
}

/// Every data byte in `ops`, in order.
fn data(ops: &[Op]) -> Vec<u8> {
    ops.iter()
        .flat_map(|op| match op {
            Data(bytes) => bytes.as_slice(),
            _ => &[],
        })
        .copied()
        .collect()
}

/// Fails at the first op where `got` and `want` differ, naming only that op, or on their lengths:
/// a whole stream would flood the message.
fn assert_ops(got: &[Op], want: &[Op]) {
    if let Some(i) = (0..got.len().min(want.len())).find(|&i| got[i] != want[i]) {
        panic!("op {i}: got {:?}, want {:?}", got[i], want[i]);
    }
    assert_eq!(got.len(), want.len(), "op count");
}

/// The approved init: group 5's steps 1-8 as approved before Q44, written out from the plan, not
/// from the driver's constants.
///
/// Step 7's window is all of frame memory with MADCTL's MV set. The datasheet [S31] gives the
/// memory as "X=0 to X=239 (EFh) and Y=0 to Y=319 (13Fh)" (p.124) and, for MV = 1, CASET's range
/// as columns 0 to 319 (013Fh, p.198); MV swaps rows and columns, so the rows are 0 to 239
/// (00EFh). RASET's page (p.200) prints CASET's two ranges again, which disagrees with p.124; the
/// rows follow p.124.
fn approved_init() -> Vec<Op> {
    let mut ops = vec![
        // 1. Backlight low.
        Backlight(false),
        // 2. RST high 10 ms, low 10 ms, high, then 120 ms.
        Reset(true),
        Sleep(10),
        Reset(false),
        Sleep(10),
        Reset(true),
        Sleep(120),
        // 3. MADCTL 0x70, COLMOD 0x05.
        Command(0x36, vec![0x70]),
        Command(0x3A, vec![0x05]),
        // 4. PORCTRL, GCTRL, VCOMS, LCMCTRL, VDVVRHEN, VRHS, VDVS, FRCTRL2, PWCTRL1.
        Command(0xB2, vec![0x0C, 0x0C, 0x00, 0x33, 0x33]),
        Command(0xB7, vec![0x35]),
        Command(0xBB, vec![0x19]),
        Command(0xC0, vec![0x2C]),
        Command(0xC2, vec![0x01]),
        Command(0xC3, vec![0x12]),
        Command(0xC4, vec![0x20]),
        Command(0xC6, vec![0x0F]),
        Command(0xD0, vec![0xA4, 0xA1]),
        // 5. PVGAMCTRL and NVGAMCTRL (Waveshare's tables, as SeedSigner ships them [S6]), then
        // INVON.
        Command(
            0xE0,
            vec![
                0xD0, 0x04, 0x0D, 0x11, 0x13, 0x2B, 0x3F, 0x54, 0x4C, 0x18, 0x0D, 0x0B, 0x1F, 0x23,
            ],
        ),
        Command(
            0xE1,
            vec![
                0xD0, 0x04, 0x0C, 0x11, 0x13, 0x2C, 0x3F, 0x44, 0x51, 0x2F, 0x1F, 0x1F, 0x20, 0x23,
            ],
        ),
        Command(0x21, vec![]),
        // 6. SLPOUT, then 120 ms.
        Command(0x11, vec![]),
        Sleep(120),
    ];
    // 7. Zeros over all of frame memory.
    ops.extend(blank_ops());
    // 8. DISPON.
    ops.push(Command(0x29, vec![]));
    ops
}

/// The HAT's blank: CASET 00 00 01 3F, RASET 00 00 00 EF, RAMWR, then 153,600 zero bytes as 37
/// writes of 4,096 and one of 2,048.
fn blank_ops() -> Vec<Op> {
    let mut ops = vec![
        Command(0x2A, vec![0x00, 0x00, 0x01, 0x3F]),
        Command(0x2B, vec![0x00, 0x00, 0x00, 0xEF]),
        Command(0x2C, vec![]),
    ];
    ops.extend((0..37).map(|_| Data(vec![0; 4096])));
    ops.push(Data(vec![0; 2048]));
    ops
}

/// A present of `pixels` into the window whose columns are `columns`: the window, with rows 0 to
/// 239, RAMWR, the pixels high byte first in 4,096-byte writes, then the backlight on.
fn present_ops(columns: [u8; 4], pixels: &[u16]) -> Vec<Op> {
    let bytes: Vec<u8> = pixels
        .iter()
        .flat_map(|pixel| pixel.to_be_bytes())
        .collect();
    let mut ops = vec![
        Command(0x2A, columns.to_vec()),
        Command(0x2B, vec![0x00, 0x00, 0x00, 0xEF]),
        Command(0x2C, vec![]),
    ];
    ops.extend(bytes.chunks(4096).map(|write| Data(write.to_vec())));
    ops.push(Backlight(true));
    ops
}

/// A frame whose 57,600 pixels all differ and none is black: 1, 2, 3, …
fn pattern() -> Vec<u16> {
    (1..=FRAME_PIXELS)
        .map(|i| u16::try_from(i).expect("below 65,536"))
        .collect()
}

/// The controller's frame memory, as these tests model it [S31]: CASET and RASET set the window,
/// RAMWR starts a write at its top-left pixel, and each byte pair of data that follows fills the
/// next pixel, left to right, then the window's next row. Any other command ends the write. A
/// pixel outside the memory fails the test.
struct Memory {
    ram: Size,
    pixels: Vec<u16>,
    columns: (u16, u16),
    rows: (u16, u16),
    next: Option<(u16, u16)>,
}

impl Memory {
    /// Memory as power-on leaves it: not black ([S31] p.202: random).
    fn new(ram: Size) -> Self {
        Memory {
            ram,
            pixels: vec![0x5A5A; usize::from(ram.width) * usize::from(ram.height)],
            columns: (0, 0),
            rows: (0, 0),
            next: None,
        }
    }

    /// Applies `ops` as the controller would.
    fn apply(&mut self, ops: &[Op]) {
        for op in ops {
            match op {
                Command(0x2A, args) => {
                    self.columns = first_and_last(args);
                    self.next = None;
                }
                Command(0x2B, args) => {
                    self.rows = first_and_last(args);
                    self.next = None;
                }
                Command(0x2C, _) => self.next = Some((self.columns.0, self.rows.0)),
                Command(..) => self.next = None,
                Data(bytes) => self.write(bytes),
                Backlight(_) | Reset(_) | Sleep(_) => {}
            }
        }
    }

    /// One data write: whole pixels into the window.
    fn write(&mut self, bytes: &[u8]) {
        let (pairs, rest) = bytes.as_chunks::<2>();
        assert!(rest.is_empty(), "whole pixels in each write");
        for &pair in pairs {
            let (x, y) = self.next.expect("data only after RAMWR");
            assert!(
                x < self.ram.width && y < self.ram.height,
                "({x}, {y}) is outside frame memory"
            );
            let i = usize::from(y) * usize::from(self.ram.width) + usize::from(x);
            self.pixels[i] = u16::from_be_bytes(pair);
            self.next = Some(if x < self.columns.1 {
                (x + 1, y)
            } else if y < self.rows.1 {
                (self.columns.0, y + 1)
            } else {
                (self.columns.0, self.rows.0)
            });
        }
    }

    /// The pixel at column `x`, row `y`.
    fn at(&self, x: u16, y: u16) -> u16 {
        self.pixels[usize::from(y) * usize::from(self.ram.width) + usize::from(x)]
    }
}

/// A window's first and last column or row, from CASET's or RASET's four bytes.
fn first_and_last(args: &[u8]) -> (u16, u16) {
    match args {
        [a, b, c, d] => (u16::from_be_bytes([*a, *b]), u16::from_be_bytes([*c, *d])),
        _ => panic!("a window has four bytes, not {}", args.len()),
    }
}

/// The group 5 checks that `profile` fails, by name: none for a sound one.
fn faults(profile: &PanelProfile) -> Vec<&'static str> {
    let mut faults = Vec::new();
    // The blank covers the controller's whole 240×320 memory in the profile's orientation.
    let whole = if profile.madctl & MV == 0 {
        Size {
            width: 240,
            height: 320,
        }
    } else {
        Size {
            width: 320,
            height: 240,
        }
    };
    if profile.ram != whole {
        faults.push("ram");
    }
    // The 240×240 window at `origin` lies inside `ram`.
    let fits = |at: u16, room: u16| u32::from(at) + u32::from(SIDE) <= u32::from(room);
    if !(fits(profile.origin.x, profile.ram.width) && fits(profile.origin.y, profile.ram.height)) {
        faults.push("window");
    }
    if profile
        .init
        .iter()
        .any(|step| !ST7789_INIT_OPCODES.contains(&step.cmd))
    {
        faults.push("opcode");
    }
    // Exactly one COLMOD, at 16 bits a pixel (low nibble 5): what `Frame::raw()` gives.
    let formats: Vec<&[u8]> = profile
        .init
        .iter()
        .filter(|step| step.cmd == COLMOD)
        .map(|step| step.args)
        .collect();
    if !matches!(formats[..], [[format]] if format & 0x0F == 0x05) {
        faults.push("colmod");
    }
    if profile.spi_hz == 0 {
        faults.push("spi_hz");
    }
    faults
}

#[test]
fn the_hats_init_stream_is_the_approved_one_byte_for_byte() {
    let (panel, log) = start(&WAVESHARE_1IN3_HAT, 0..0);
    assert!(panel.is_ok());
    let ops = take(&log);
    assert_ops(&ops, &approved_init());
    assert_eq!(sends(&ops), INIT_SENDS);
    // What the stream does not carry: Q47's name for this screen type, and the approved 40 MHz.
    assert_eq!(WAVESHARE_1IN3_HAT.name, "st7789-240x240");
    assert_eq!(WAVESHARE_1IN3_HAT.spi_hz, 40_000_000);
    // The image's profile, so this is what the image sends.
    assert_eq!(PANEL, &WAVESHARE_1IN3_HAT);
}

/// 0xF800 gives F8 00: each pixel goes high byte first.
#[test]
fn a_present_sends_the_window_then_the_frame_high_byte_first_in_29_writes() {
    let (panel, log) = start(&WAVESHARE_1IN3_HAT, 0..0);
    let mut panel = panel.expect("init");
    take(&log);
    let mut pixels = vec![0; FRAME_PIXELS];
    pixels[0] = 0xF800;
    pixels[1] = 0x001F;
    pixels[FRAME_PIXELS - 1] = 0x07E0;
    assert_eq!(panel.show(&pixels), Ok(()));
    let ops = take(&log);
    assert_eq!(
        ops[..3],
        [
            Command(0x2A, HAT_COLUMNS.to_vec()),
            Command(0x2B, vec![0x00, 0x00, 0x00, 0xEF]),
            Command(0x2C, vec![]),
        ]
    );
    let writes: Vec<&[u8]> = ops[3..ops.len() - 1]
        .iter()
        .map(|op| match op {
            Data(bytes) => bytes.as_slice(),
            other => panic!("not a write: {other:?}"),
        })
        .collect();
    assert_eq!(writes.len(), 29);
    assert!(writes[..28].iter().all(|write| write.len() == 4096));
    assert_eq!(writes[28].len(), 512);
    assert_eq!(
        writes.iter().map(|write| write.len()).sum::<usize>(),
        115_200
    );
    assert_eq!(writes[0][..4], [0xF8, 0x00, 0x00, 0x1F]);
    assert_eq!(writes[28][510..], [0x07, 0xE0]);
    assert_eq!(ops.last(), Some(&Backlight(true)));
    assert_ops(&ops, &present_ops(HAT_COLUMNS, &pixels));
    assert_eq!(sends(&ops), PRESENT_SENDS);
}

/// `screens::blank()` is the first frame `show_stop` presents, as stop mode does over this panel:
/// 115,200 zero bytes into the 240×240 window. The halt screen follows through the same window.
#[test]
fn the_blank_screen_writes_115_200_zero_bytes() {
    let (panel, log) = start(&WAVESHARE_1IN3_HAT, 0..0);
    let mut panel = panel.expect("init");
    take(&log);
    assert_eq!(show_stop(&mut panel, HalError::Stopped), Ok(()));
    let ops = take(&log);
    let (blank, halt) = ops.split_at(PRESENT_SENDS + 1);
    assert_ops(blank, &present_ops(HAT_COLUMNS, &[0; FRAME_PIXELS]));
    assert_eq!(data(blank).len(), 115_200);
    assert_eq!(halt.len(), PRESENT_SENDS + 1);
    assert_eq!(halt[..3], blank[..3]);
    assert_eq!(data(halt).len(), 115_200);
    assert!(data(halt).iter().any(|&byte| byte != 0));
    assert_eq!(halt.last(), Some(&Backlight(true)));
}

/// After a present, and after one whose write failed once the buffer held frame bytes. A slice
/// that is not one whole frame sends nothing; only the backlight goes off.
#[test]
fn the_buffer_is_zero_after_a_present_and_after_a_failed_one() {
    let white = vec![0xFFFF; FRAME_PIXELS];
    let (panel, log) = start(&WAVESHARE_1IN3_HAT, 0..0);
    let mut panel = panel.expect("init");
    assert_eq!(panel.show(&white), Ok(()));
    assert!(panel.buf.iter().all(|&byte| byte == 0));
    take(&log);
    assert_eq!(panel.show(&white[1..]), Err(HalError::Display));
    assert_eq!(take(&log), [Backlight(false)]);
    for call in 3..PRESENT_SENDS {
        let lost = INIT_SENDS + call;
        let (panel, _) = start(&WAVESHARE_1IN3_HAT, lost..lost + 1);
        let mut panel = panel.expect("init");
        assert_eq!(panel.show(&white), Err(HalError::Display));
        assert!(panel.buf.iter().all(|&byte| byte == 0), "call {call}");
    }
}

/// Off until a whole frame is in; off on every bus error, during init and during a present, and
/// in `Drop`. After a lost write, the next whole frame turns it on again.
#[test]
fn the_backlight_stays_off_until_a_frame_is_in_and_goes_off_on_every_error() {
    let white = vec![0xFFFF; FRAME_PIXELS];
    let (panel, log) = start(&WAVESHARE_1IN3_HAT, 0..0);
    let mut panel = panel.expect("init");
    assert!(!take(&log).contains(&Backlight(true)));
    assert_eq!(panel.show(&white), Ok(()));
    assert_eq!(take(&log).last(), Some(&Backlight(true)));
    drop(panel);
    assert_eq!(take(&log).last(), Some(&Backlight(false)));

    // A bus that stops at any call of init: what came before is the approved stream, then the
    // backlight goes off, `Drop`'s blank is refused, and the backlight goes off again.
    let approved = approved_init();
    let at: Vec<usize> = (0..approved.len())
        .filter(|&i| matches!(approved[i], Command(..) | Data(_)))
        .collect();
    assert_eq!(at.len(), INIT_SENDS);
    for (call, &i) in at.iter().enumerate() {
        let (panel, log) = start(&WAVESHARE_1IN3_HAT, call..usize::MAX);
        assert!(matches!(panel, Err(HalError::Display)), "call {call}");
        let mut want = approved[..i].to_vec();
        want.extend([Backlight(false), Backlight(false)]);
        assert_ops(&take(&log), &want);
    }

    // A bus that stops at any call of a present.
    for call in 0..PRESENT_SENDS {
        let (panel, log) = start(&WAVESHARE_1IN3_HAT, INIT_SENDS + call..usize::MAX);
        let mut panel = panel.expect("init");
        take(&log);
        assert_eq!(panel.show(&white), Err(HalError::Display));
        let mut want = present_ops(HAT_COLUMNS, &white)[..call].to_vec();
        want.push(Backlight(false));
        assert_ops(&take(&log), &want);
        drop(panel);
        assert_eq!(take(&log), [Backlight(false)]);
    }

    // One lost write.
    let lost = INIT_SENDS + 10;
    let (panel, log) = start(&WAVESHARE_1IN3_HAT, lost..lost + 1);
    let mut panel = panel.expect("init");
    take(&log);
    assert_eq!(panel.show(&white), Err(HalError::Display));
    assert_eq!(take(&log).last(), Some(&Backlight(false)));
    assert_eq!(panel.show(&white), Ok(()));
    assert_ops(&take(&log), &present_ops(HAT_COLUMNS, &white));
}

#[test]
fn init_and_drop_each_send_madctl_the_320_by_240_window_and_153_600_zero_bytes() {
    let madctl = Command(0x36, vec![0x70]);
    let blank = blank_ops();
    assert_eq!(data(&blank), vec![0; 153_600]);
    let (panel, log) = start(&WAVESHARE_1IN3_HAT, 0..0);
    let init = take(&log);
    assert_eq!(init[7], madctl);
    // Step 7, right before DISPON.
    assert_eq!(
        init[init.len() - 1 - blank.len()..init.len() - 1],
        blank[..]
    );
    drop(panel);
    let mut want = vec![madctl];
    want.extend(blank);
    want.push(Backlight(false));
    assert_ops(&take(&log), &want);
}

/// On the model of frame memory, which power-on leaves random: init leaves every pixel black; a
/// present fills exactly the 240×240 window at the profile's origin, pixel for pixel, and nothing
/// else; `Drop` leaves every pixel black again. For every profile and the test-only one.
#[test]
fn init_blanks_all_of_memory_a_present_writes_only_its_window_and_drop_blanks_it_again() {
    for profile in PROFILES.iter().copied().chain([&OFFSET]) {
        let (panel, log) = start(profile, 0..0);
        let mut panel = panel.expect("init");
        let mut memory = Memory::new(profile.ram);
        memory.apply(&take(&log));
        assert!(
            memory.pixels.iter().all(|&pixel| pixel == 0),
            "{}",
            profile.name
        );
        let frame = pattern();
        assert_eq!(panel.show(&frame), Ok(()));
        memory.apply(&take(&log));
        for y in 0..profile.ram.height {
            for x in 0..profile.ram.width {
                let inside = |at: u16, from: u16| at.checked_sub(from).filter(|&i| i < SIDE);
                let want = match (inside(x, profile.origin.x), inside(y, profile.origin.y)) {
                    (Some(fx), Some(fy)) => frame[usize::from(fy) * 240 + usize::from(fx)],
                    _ => 0,
                };
                assert_eq!(memory.at(x, y), want, "{} at ({x}, {y})", profile.name);
            }
        }
        drop(panel);
        memory.apply(&take(&log));
        assert!(
            memory.pixels.iter().all(|&pixel| pixel == 0),
            "{}",
            profile.name
        );
    }
}

/// The test-only profile's window starts 40 columns in, CASET 00 28 01 17; its blank is the HAT's,
/// since only the origin differs.
#[test]
fn the_window_follows_the_profiles_origin() {
    let (panel, log) = start(&OFFSET, 0..0);
    assert_ops(&take(&log), &approved_init());
    let mut panel = panel.expect("init");
    let frame = pattern();
    assert_eq!(panel.show(&frame), Ok(()));
    assert_ops(&take(&log), &present_ops([0x00, 0x28, 0x01, 0x17], &frame));
}

/// A window's bytes run from `start` to `start + len - 1`; an empty span, or one past the 16-bit
/// range, is refused. The frame's side is `ui`'s.
#[test]
fn spans_are_inclusive_and_refuse_empty_or_overflowing_ones() {
    assert_eq!(span(0, 240), Ok([0x00, 0x00, 0x00, 0xEF]));
    assert_eq!(span(0, 320), Ok([0x00, 0x00, 0x01, 0x3F]));
    assert_eq!(span(40, 240), Ok([0x00, 0x28, 0x01, 0x17]));
    assert_eq!(span(u16::MAX, 1), Ok([0xFF, 0xFF, 0xFF, 0xFF]));
    assert_eq!(span(u16::MAX, 2), Err(HalError::Display));
    assert_eq!(span(0, 0), Err(HalError::Display));
    assert_eq!(u32::from(SIDE), keepcrypt_pi::ui::SIDE);
    assert_eq!(FRAME_PIXELS, usize::from(SIDE) * usize::from(SIDE));
}

/// Every profile passes the checks (Q44): the blank covers the controller's whole memory, the
/// window lies inside it, every opcode is on the allow-list, one COLMOD at 16 bits a pixel, a bus
/// speed, and a unique name. The allow-list is the plan's 14 opcodes. `PROFILES` holds exactly the
/// HAT, and `PANEL` is in it. Each check fails a profile made to break it.
#[test]
fn every_profile_passes_the_checks_and_each_check_fires() {
    // The allow-list is group 5's, written out from the plan: COLMOD, PORCTRL, GCTRL, VCOMS, LCMCTRL,
    // VDVVRHEN, VRHS, VDVS, FRCTRL2, PWCTRL1, PVGAMCTRL, NVGAMCTRL, INVOFF and INVON.
    assert_eq!(
        ST7789_INIT_OPCODES,
        [
            0x3A, 0xB2, 0xB7, 0xBB, 0xC0, 0xC2, 0xC3, 0xC4, 0xC6, 0xD0, 0xE0, 0xE1, 0x20, 0x21
        ]
    );
    for profile in PROFILES.iter().copied().chain([&OFFSET]) {
        assert_eq!(faults(profile), Vec::<&str>::new(), "{}", profile.name);
    }
    let names: BTreeSet<&str> = PROFILES.iter().map(|profile| profile.name).collect();
    assert_eq!(names.len(), PROFILES.len());
    assert_eq!(PROFILES, [&WAVESHARE_1IN3_HAT]);
    assert!(PROFILES.contains(&PANEL));

    for (broken, fault) in [
        // MV clear: the memory is 240×320, so a 320×240 blank would miss rows.
        (
            PanelProfile {
                madctl: 0x50,
                ..WAVESHARE_1IN3_HAT
            },
            "ram",
        ),
        // A blank of the frame alone would leave 80 columns as they were.
        (
            PanelProfile {
                ram: FRAME,
                ..WAVESHARE_1IN3_HAT
            },
            "ram",
        ),
        (
            PanelProfile {
                origin: Point { x: 81, y: 0 },
                ..WAVESHARE_1IN3_HAT
            },
            "window",
        ),
        (
            PanelProfile {
                origin: Point { x: 0, y: 1 },
                ..WAVESHARE_1IN3_HAT
            },
            "window",
        ),
        // MADCTL and display on belong to the driver.
        (
            PanelProfile {
                init: const { &[step(COLMOD, &[0x05]), step(MADCTL, &[0x00])] },
                ..WAVESHARE_1IN3_HAT
            },
            "opcode",
        ),
        (
            PanelProfile {
                init: const { &[step(COLMOD, &[0x05]), step(DISPON, &[])] },
                ..WAVESHARE_1IN3_HAT
            },
            "opcode",
        ),
        (
            PanelProfile {
                init: const { &[step(INVON, &[])] },
                ..WAVESHARE_1IN3_HAT
            },
            "colmod",
        ),
        (
            PanelProfile {
                init: const { &[step(COLMOD, &[0x05]), step(COLMOD, &[0x05])] },
                ..WAVESHARE_1IN3_HAT
            },
            "colmod",
        ),
        // 18 bits a pixel.
        (
            PanelProfile {
                init: const { &[step(COLMOD, &[0x06])] },
                ..WAVESHARE_1IN3_HAT
            },
            "colmod",
        ),
        (
            PanelProfile {
                spi_hz: 0,
                ..WAVESHARE_1IN3_HAT
            },
            "spi_hz",
        ),
    ] {
        assert_eq!(faults(&broken), [fault]);
    }
}
