//! The panel driver's tests (tasks/todo.md, M4 group 5, Q44), on a recording bus and a model of
//! the controller's frame memory: the HAT's init pinned to the approved bytes; a present's window,
//! writes and byte order; the buffer and the backlight on every error; `Drop`; the `PROFILES`
//! checks; a test-only profile whose frame sits 40 columns in; and the profile's selection by name
//! (M4b B3). Then the 2-inch module's profile (M4b B2): its init pinned to Waveshare's file with
//! every deviation listed, its window, wipe and byte order; and the 1.3-inch and 1.54-inch
//! modules' files, which send the HAT's settings.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::ops::Range;
use std::rc::Rc;

use keepcrypt_pi::show_stop;

use super::*;
use Op::{Backlight, Command, Data, Reset, Sleep};

/// MADCTL's MV bit: rows and columns swapped [S31].
const MV: u8 = 0x20;
/// LCMCTRL's XMV bit, which the controller XORs with MADCTL's MV ([S31] p.275).
const XMV: u8 = 0x02;
/// The commands and data writes init sends on the HAT, and on the 2-inch module: MADCTL, 13
/// settings, SLPOUT, the window (3), 38 writes of zeros and DISPON.
const INIT_SENDS: usize = 57;
/// The commands and data writes of a present: the window (3) and 29 writes.
const PRESENT_SENDS: usize = 32;
/// The HAT's window columns, 0 to 239.
const HAT_COLUMNS: [u8; 4] = [0x00, 0x00, 0x00, 0xEF];
/// The 2-inch module's window columns, 40 to 279: the frame in the middle of 320.
const TWO_INCH_COLUMNS: [u8; 4] = [0x00, 0x28, 0x01, 0x17];

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
    // `madctl` alone sets the orientation: an LCMCTRL step with XMV would flip MV, and with it the
    // memory the blank must cover.
    if profile
        .init
        .iter()
        .any(|step| step.cmd == LCMCTRL && step.args.iter().any(|arg| arg & XMV != 0))
    {
        faults.push("xmv");
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
    // The image's profile with `KEEPCRYPT_PI_PANEL` unset or `st7789-240x240`, so this is what the
    // HAT's image sends.
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

/// `show_stop` draws through `hal::Display::present`, as the app does: a bus that stops at any
/// call of its two presents gives `Display`, with the backlight off and nothing sent after it.
#[test]
fn a_bus_fault_in_show_stop_is_a_display_fault_with_the_backlight_off() {
    for call in 0..2 * PRESENT_SENDS {
        let (panel, log) = start(&WAVESHARE_1IN3_HAT, INIT_SENDS + call..usize::MAX);
        let mut panel = panel.expect("init");
        take(&log);
        assert_eq!(
            show_stop(&mut panel, HalError::Stopped),
            Err(HalError::Display),
            "call {call}"
        );
        let ops = take(&log);
        assert_eq!(sends(&ops), call, "call {call}");
        assert_eq!(ops.last(), Some(&Backlight(false)), "call {call}");
    }
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

/// Every profile passes the checks (Q44): the blank covers the controller's whole memory, no
/// LCMCTRL step flips MADCTL's MV, the window lies inside it, every opcode is on the allow-list,
/// one COLMOD at 16 bits a pixel, a bus speed, and a unique name. The allow-list is the plan's 14 opcodes. `PROFILES` holds exactly the
/// HAT and the 2-inch module (M4b B2), and `PANEL` is in it. Each check fails a profile made to
/// break it.
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
    assert_eq!(PROFILES, [&WAVESHARE_1IN3_HAT, &ST7789_240X320]);
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
        // The HAT's LCMCTRL with XMV: the memory is 240×320 again, and a 320×240 blank would miss
        // rows.
        (
            PanelProfile {
                init: const {
                    &[
                        step(COLMOD, &[0x05]),
                        step(LCMCTRL, &[0x2C | XMV]),
                        step(INVON, &[]),
                    ]
                },
                ..WAVESHARE_1IN3_HAT
            },
            "xmv",
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

/// Q47 (a): with `KEEPCRYPT_PI_PANEL` unset, as in `cargo test`, lint and CI's cross job, the
/// profile is the HAT.
#[test]
fn no_panel_name_selects_the_hat() {
    assert_eq!(select(None), &WAVESHARE_1IN3_HAT);
}

/// The HAT's image name selects the HAT, and every profile in `PROFILES` is selected by its own
/// name, so a profile added there is a name the build takes.
#[test]
fn st7789_240x240_selects_the_hat_and_each_name_its_profile() {
    assert_eq!(select(Some("st7789-240x240")), &WAVESHARE_1IN3_HAT);
    for profile in PROFILES {
        assert_eq!(select(Some(profile.name)), *profile, "{}", profile.name);
    }
}

/// A name that differs from a `PROFILES` name in one byte, the first, the last or any between, has
/// that name's length, so only `same`'s byte compare tells them apart: it must, or a mistyped name
/// of the right length would select that profile (rule 3).
#[test]
fn a_name_one_byte_off_a_profiles_name_is_not_the_same() {
    for profile in PROFILES {
        let name = profile.name.as_bytes();
        assert!(same(name, name), "{}", profile.name);
        for i in 0..name.len() {
            let mut near = name.to_vec();
            near[i] ^= 0x01;
            assert!(!same(name, &near), "{}, byte {i} changed", profile.name);
            assert!(!same(&near, name), "{}, byte {i} changed", profile.name);
        }
    }
}

// An unknown or empty name panics with fixed text, which in `PANEL`'s const evaluation stops the
// build (scripts/canaries.sh: panel-name-nonsense and panel-name-empty). The HAT's name with a
// trailing space agrees with it in every byte the HAT's name has, so only the length refuses it;
// with its last or its first byte changed it has the HAT name's length, so only the byte compare
// refuses it.
#[test]
#[should_panic(expected = "KEEPCRYPT_PI_PANEL is empty or names no profile in PROFILES")]
fn an_unknown_panel_name_panics() {
    select(Some("nonsense"));
}

#[test]
#[should_panic(expected = "KEEPCRYPT_PI_PANEL is empty or names no profile in PROFILES")]
fn an_empty_panel_name_panics() {
    select(Some(""));
}

#[test]
#[should_panic(expected = "KEEPCRYPT_PI_PANEL is empty or names no profile in PROFILES")]
fn a_panel_name_with_a_trailing_space_panics() {
    select(Some("st7789-240x240 "));
}

#[test]
#[should_panic(expected = "KEEPCRYPT_PI_PANEL is empty or names no profile in PROFILES")]
fn a_panel_name_one_byte_off_at_its_end_panics() {
    select(Some("st7789-240x241"));
}

#[test]
#[should_panic(expected = "KEEPCRYPT_PI_PANEL is empty or names no profile in PROFILES")]
fn a_panel_name_one_byte_off_at_its_start_panics() {
    select(Some("tt7789-240x240"));
}

// Waveshare's Raspberry Pi module archive (M4b B2; Q49 (d)): `LCD_Module_RPI_code.zip`, 12,380,597
// bytes, SHA-256 07afa6be35a710a7e811435eb048e474988cee0946e8e6e99a11b59f0644f0ac, from
// https://files.waveshare.com/upload/8/8d/LCD_Module_RPI_code.zip, downloaded with the owner's yes
// on 2026-10-16. Its files were read as text, and the two listings below are written out from
// them, each file named by its path in the archive and its SHA-256.

/// What `LCD_2IN_Init` sends after its reset, in order: the 2-inch module's driver,
/// `LCD_Module_RPI_code/RaspberryPi/c/lib/LCD/LCD_2inch.c` (SHA-256
/// 4dc89777c71ce0f4f9e543d322df3432d1dbae5c48bc65bbad123fc477073689). The archive's Python driver,
/// `LCD_Module_RPI_code/RaspberryPi/python/lib/LCD_2inch.py` (SHA-256
/// 9a7ed52e50292b1163289f69e139f1ac7e6fea9f1920a717652e1ea6f8dcb66b), sends the same in its `Init`.
const LCD_2INCH_C: [(u8, &[u8]); 19] = [
    (0x36, &[0x00]),
    (0x3A, &[0x05]),
    (0x21, &[]),
    (0x2A, &[0x00, 0x00, 0x01, 0x3F]),
    (0x2B, &[0x00, 0x00, 0x00, 0xEF]),
    (0xB2, &[0x0C, 0x0C, 0x00, 0x33, 0x33]),
    (0xB7, &[0x35]),
    (0xBB, &[0x1F]),
    (0xC0, &[0x2C]),
    (0xC2, &[0x01]),
    (0xC3, &[0x12]),
    (0xC4, &[0x20]),
    (0xC6, &[0x0F]),
    (0xD0, &[0xA4, 0xA1]),
    (
        0xE0,
        &[
            0xD0, 0x08, 0x11, 0x08, 0x0C, 0x15, 0x39, 0x33, 0x50, 0x36, 0x13, 0x14, 0x29, 0x2D,
        ],
    ),
    (
        0xE1,
        &[
            0xD0, 0x08, 0x10, 0x08, 0x06, 0x06, 0x39, 0x44, 0x51, 0x0B, 0x16, 0x14, 0x2F, 0x31,
        ],
    ),
    (0x21, &[]),
    (0x11, &[]),
    (0x29, &[]),
];

/// What the 1.3-inch and 1.54-inch modules' drivers send after their reset, in order, the same in
/// both: `LCD_Module_RPI_code/RaspberryPi/c/lib/LCD/LCD_1in3.c` (SHA-256
/// 77520a61d1485dc6a4f681dc8e5cfd38570fff5b322ac0e05c6ec924d1dc719f) and `LCD_1in54.c` beside it
/// (SHA-256 c556d394588f00edb055cd11a34000e3839ea6a2acdd62984b6d655772abb25d), which differ only in
/// names and the date in their headers. `LCD_*_Init(HORIZONTAL)`, as both demos call it
/// (`c/examples/LCD_1in3_test.c`, SHA-256
/// 28f50ec18a72614a8e8f154e0157f8e038fd47b0ef6d1b6685b18a076bc1f266, and `LCD_1in54_test.c`, SHA-256
/// 9352a6058aef10b3a47dfba343452a7807ae6dae9a5ff675a457a49b52f20ebc), sends MADCTL `0x70` from
/// `LCD_*_SetAttributes`, then the rest from `LCD_*_InitReg`. Both panels are 240×240, and both
/// drivers' windows start at column and row 0. The Python drivers `python/lib/LCD_1inch3.py`
/// (SHA-256 16f756df437b13d05f62e1fa86552746d36e23b9e3e2af5c355eb77fb7769105) and `LCD_1inch54.py`
/// (SHA-256 d0ad8242638982c5efdac9053cc2728891906c5906c93e5f9900d0dbeb741ee5) send the same in
/// their `Init`.
const LCD_1IN3_C: [(u8, &[u8]); 16] = [
    (0x36, &[0x70]),
    (0x3A, &[0x05]),
    (0xB2, &[0x0C, 0x0C, 0x00, 0x33, 0x33]),
    (0xB7, &[0x35]),
    (0xBB, &[0x19]),
    (0xC0, &[0x2C]),
    (0xC2, &[0x01]),
    (0xC3, &[0x12]),
    (0xC4, &[0x20]),
    (0xC6, &[0x0F]),
    (0xD0, &[0xA4, 0xA1]),
    (
        0xE0,
        &[
            0xD0, 0x04, 0x0D, 0x11, 0x13, 0x2B, 0x3F, 0x54, 0x4C, 0x18, 0x0D, 0x0B, 0x1F, 0x23,
        ],
    ),
    (
        0xE1,
        &[
            0xD0, 0x04, 0x0C, 0x11, 0x13, 0x2C, 0x3F, 0x44, 0x51, 0x2F, 0x1F, 0x1F, 0x20, 0x23,
        ],
    ),
    (0x21, &[]),
    (0x11, &[]),
    (0x29, &[]),
];

/// The commands of a listing, as the recording bus logs them.
fn commands(listing: &[(u8, &[u8])]) -> Vec<Op> {
    listing
        .iter()
        .map(|&(cmd, args)| Command(cmd, args.to_vec()))
        .collect()
}

/// The 2-inch module's init: `LCD_2INCH_C` in the driver's steps 1-8, with these deviations, each
/// made below as it is named, because the driver owns that step on every screen:
/// - MADCTL `0x70`, the profile's `madctl` (the HAT's), not `0x00`. The file's `0x00` leaves the
///   panel portrait, 240 columns by 320 rows; the archive's Python driver sends `0x70` with the
///   320×240 window for a 320×240 picture, so landscape is Waveshare's own setting too;
/// - the file's early INVON, its third command, is dropped. INVON is sent once, after the gamma
///   tables, where the file sends it again, as on the HAT;
/// - its CASET `00 00 01 3F` and RASET `00 00 00 EF` are dropped. The driver owns windows, and its
///   wipe (step 7) sends the full-memory window, which with MADCTL's MV set is the same bytes;
/// - SLPOUT and DISPON are the driver's steps 6 and 8, with 120 ms after SLPOUT and the wipe
///   before DISPON, where the file sends DISPON straight after SLPOUT;
/// - the reset is the driver's step 2 (the file holds each level 100 ms), and the backlight is the
///   driver's step 1 (the file's init does not drive it).
///
/// Step 7's window and wipe are the HAT's, since `ram` is the same 320×240.
fn two_inch_init() -> Vec<Op> {
    let mut file = commands(&LCD_2INCH_C);
    assert_eq!(file[0], Command(0x36, vec![0x00]));
    file[0] = Command(0x36, vec![0x70]);
    assert_eq!(
        file.drain(2..5).collect::<Vec<Op>>(),
        [
            Command(0x21, vec![]),
            Command(0x2A, vec![0x00, 0x00, 0x01, 0x3F]),
            Command(0x2B, vec![0x00, 0x00, 0x00, 0xEF]),
        ]
    );
    assert_eq!(
        file.split_off(file.len() - 2),
        [Command(0x11, vec![]), Command(0x29, vec![])]
    );
    let mut ops = vec![
        Backlight(false),
        Reset(true),
        Sleep(10),
        Reset(false),
        Sleep(10),
        Reset(true),
        Sleep(120),
    ];
    ops.extend(file);
    ops.extend([Command(0x11, vec![]), Sleep(120)]);
    ops.extend(blank_ops());
    ops.push(Command(0x29, vec![]));
    ops
}

/// The 2-inch module's recorded init equals `LCD_2inch.c`'s with the listed deviations, byte for
/// byte. Its settings are the HAT's but for VCOMS (`1F`, not `19`) and the two gamma tables. Its
/// name selects it (Q47 (a)), and its bus speed is the HAT's 40 MHz.
#[test]
fn the_2_inch_modules_init_stream_is_its_files_with_the_listed_deviations() {
    let (panel, log) = start(&ST7789_240X320, 0..0);
    assert!(panel.is_ok());
    let ops = take(&log);
    assert_ops(&ops, &two_inch_init());
    assert_eq!(sends(&ops), INIT_SENDS);
    let differ: Vec<u8> = WAVESHARE_1IN3_HAT
        .init
        .iter()
        .zip(ST7789_240X320.init)
        .filter(|(hat, two_inch)| hat != two_inch)
        .map(|(hat, _)| hat.cmd)
        .collect();
    assert_eq!(differ, [VCOMS, PVGAMCTRL, NVGAMCTRL]);
    assert_eq!(ST7789_240X320.init.len(), WAVESHARE_1IN3_HAT.init.len());
    assert_eq!(ST7789_240X320.name, "st7789-240x320");
    assert_eq!(ST7789_240X320.spi_hz, 40_000_000);
    assert_eq!(select(Some("st7789-240x320")), &ST7789_240X320);
}

/// A present on the 2-inch module: CASET 00 28 01 17 (columns 40 to 279), RASET 00 00 00 EF,
/// RAMWR, then the frame high byte first (0xF800 gives F8 00) in 28 writes of 4,096 and one of
/// 512, 115,200 bytes, then the backlight on.
#[test]
fn a_present_on_the_2_inch_module_fills_columns_40_to_279_high_byte_first() {
    let (panel, log) = start(&ST7789_240X320, 0..0);
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
            Command(0x2A, vec![0x00, 0x28, 0x01, 0x17]),
            Command(0x2B, vec![0x00, 0x00, 0x00, 0xEF]),
            Command(0x2C, vec![]),
        ]
    );
    let writes: Vec<usize> = ops[3..ops.len() - 1]
        .iter()
        .map(|op| match op {
            Data(bytes) => bytes.len(),
            other => panic!("not a write: {other:?}"),
        })
        .collect();
    assert_eq!(writes.len(), 29);
    assert!(writes[..28].iter().all(|&len| len == 4096));
    assert_eq!(writes[28], 512);
    let bytes = data(&ops);
    assert_eq!(bytes.len(), 115_200);
    assert_eq!(bytes[..4], [0xF8, 0x00, 0x00, 0x1F]);
    assert_eq!(bytes[115_198..], [0x07, 0xE0]);
    assert_eq!(ops.last(), Some(&Backlight(true)));
    assert_ops(&ops, &present_ops(TWO_INCH_COLUMNS, &pixels));
    assert_eq!(sends(&ops), PRESENT_SENDS);
}

/// The 2-inch module's wipes: init's step 7 and `Drop` each send the whole 320×240 memory's window
/// and 153,600 zero bytes in 38 writes (37 of 4,096 and one of 2,048), `Drop` after MADCTL `0x70`;
/// `screens::blank()`, stop mode's first frame, is 115,200 zero bytes into columns 40 to 279.
#[test]
fn the_2_inch_modules_wipes_cover_all_of_memory_and_the_blank_screen_its_window() {
    let blank = blank_ops();
    assert_eq!(data(&blank), vec![0; 153_600]);
    assert_eq!(sends(&blank), 3 + 38);
    let (panel, log) = start(&ST7789_240X320, 0..0);
    let mut panel = panel.expect("init");
    let init = take(&log);
    assert_eq!(
        init[init.len() - 1 - blank.len()..init.len() - 1],
        blank[..]
    );
    assert_eq!(show_stop(&mut panel, HalError::Stopped), Ok(()));
    let ops = take(&log);
    let (screen, halt) = ops.split_at(PRESENT_SENDS + 1);
    assert_ops(screen, &present_ops(TWO_INCH_COLUMNS, &[0; FRAME_PIXELS]));
    assert_eq!(data(screen).len(), 115_200);
    assert_eq!(halt[..3], screen[..3]);
    drop(panel);
    let mut want = vec![Command(0x36, vec![0x70])];
    want.extend(blank);
    want.push(Backlight(false));
    assert_ops(&take(&log), &want);
}

/// The 1.3-inch and 1.54-inch modules run the HAT's image (Q45; M4b B2): the commands the HAT's
/// profile has the driver send, leaving out step 7's window, are `LCD_1IN3_C`, what the modules'
/// files send, in the same order. Only steps the driver owns differ from the files: the backlight
/// (the files turn it on before the reset; the driver's step 1 turns it off, and it comes on only
/// once a whole frame is in), the reset, 120 ms after SLPOUT, and the wipe before DISPON.
#[test]
fn the_1_3_and_1_54_inch_modules_files_send_the_hats_settings() {
    let (panel, log) = start(&WAVESHARE_1IN3_HAT, 0..0);
    assert!(panel.is_ok());
    let sent: Vec<Op> = take(&log)
        .into_iter()
        .filter(|op| matches!(op, Command(cmd, _) if ![CASET, RASET, RAMWR].contains(cmd)))
        .collect();
    assert_eq!(sent, commands(&LCD_1IN3_C));
    assert_eq!(WAVESHARE_1IN3_HAT.origin, Point { x: 0, y: 0 });
}
