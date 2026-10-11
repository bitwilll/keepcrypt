//! Render timing (tasks/todo.md, M3 group 7, Q31 (f), (g)): the cost of one frame and of one
//! present, measured before any scenario is written, to decide whether the scenarios fit the
//! `test` job's budget at the workspace's opt-level 0 or need Q31 (g)'s opt-level 1 fallback.
//!
//! Run on request, in the profile the scenarios run in:
//! `cargo test -p keepcrypt-pi-sim --locked --test timing -- --ignored --nocapture`
//!
//! For each kind of heavy screen, 100 frames are drawn and handed to a display that does nothing
//! (the renderer alone), then 100 more to `SimHal` (the renderer plus the simulator's checks, log
//! and frame copy, taken after each present as a scenario does), and one PNG is encoded (capture
//! mode only). Every model uses public test text.

use std::fmt;
use std::time::{Duration, Instant};

use keepcrypt_pi::hal::{Display, HalError};
use keepcrypt_pi::screen::{
    BOARD_CELLS, Banners, Element, Item, NUMBERED_PITCH, Screen, ScreenId, Tile,
};
use keepcrypt_pi::ui::{Frame, Painter, caption_cells};
use keepcrypt_pi_sim::{HwRngStream, SimHal};

/// Frames per measurement.
const FRAMES: u32 = 100;

/// The tests' one print site (Q31 (i)): screen names and times, never screen text.
#[expect(
    clippy::print_stdout,
    reason = "pi/sim's one allowed print site in the tests (tasks/todo.md, M3 Q31 (i))"
)]
fn report(line: fmt::Arguments<'_>) {
    println!("{line}");
}

/// A display that takes every frame and does nothing with it.
struct Nothing;

impl Display for Nothing {
    fn present(&mut self, _frame: &Frame, _screen: &Screen<'_>) -> Result<(), HalError> {
        Ok(())
    }
}

/// The time one call of `f` takes, over `FRAMES` calls.
fn each(mut f: impl FnMut()) -> Duration {
    let start = Instant::now();
    for _ in 0..FRAMES {
        f();
    }
    start.elapsed() / FRAMES
}

#[test]
#[ignore = "a measurement, run on request (see the module comment)"]
fn render_timing() {
    let banners = Banners {
        test_registry: true,
        simulator: true,
    };
    let descriptor = format!("{}\n{}", "r".repeat(150), "c".repeat(150));
    let grid = [[true, false, true, true, false, false, true, false]; 8];
    let mut tiles = [[Tile::Empty; BOARD_CELLS]; BOARD_CELLS];
    for (column, tile) in tiles[9].iter_mut().enumerate().take(12) {
        *tile = if column == 11 {
            Tile::Food
        } else {
            Tile::Snake
        };
    }
    let faces = caption_cells("⠁⠃⠉⠙⠑⠋").expect("six cells");
    let screens = [
        // An insert: the word at ×2, six numbered faces, the SeedBook number and a line.
        Screen::new(ScreenId::WordsInsert, "Insert 01", banners)
            .with(Element::protected(
                (40, 0).into(),
                Item::Large {
                    text: "abstract".into(),
                    lighter_from: Some(4),
                },
            ))
            .with(Element::public((90, 44).into(), Item::Text("0007".into())))
            .with(Element::protected(
                (12, 70).into(),
                Item::Cells {
                    cells: faces,
                    pitch: NUMBERED_PITCH,
                },
            ))
            .with(Element::public(
                (0, 140).into(),
                Item::Small("Insert 01 · device 1 of 1: punch faces 1-5".into()),
            )),
        // The largest QR: both descriptors, 301 bytes, version 11 at 3 px.
        Screen::new(ScreenId::WatchDescriptorQr, "Descriptors", banners).with(Element::protected(
            (12, 0).into(),
            Item::Qr(descriptor.as_str().into()),
        )),
        // The seal image.
        Screen::new(ScreenId::SealImage, "Seal", banners).with(Element::public(
            (24, 0).into(),
            Item::Seal {
                grid: &grid,
                colour_hex: "#0072B2",
                seal_id: "5E0G7J6X",
            },
        )),
        // An entry grid: 7 × 4 letters and the entry so far.
        Screen::new(ScreenId::ReadbackEntry, "Read-back", banners)
            .with(Element::protected(
                (0, 0).into(),
                Item::Large {
                    text: "abs_".into(),
                    lighter_from: None,
                },
            ))
            .with(Element::public(
                (0, 60).into(),
                Item::Text("a b c d e f g".into()),
            ))
            .with(Element::public(
                (0, 80).into(),
                Item::Text("h i j k l m n".into()),
            ))
            .with(Element::public(
                (0, 100).into(),
                Item::Text("o p q r s t u".into()),
            ))
            .with(Element::public(
                (0, 120).into(),
                Item::Text("v w x y z -".into()),
            )),
        // The dice: two lines of text.
        Screen::new(ScreenId::Dice, "Dice", banners)
            .with(Element::public(
                (0, 0).into(),
                Item::Text("37 / 50 rolls, 95.6 bits".into()),
            ))
            .with(Element::public(
                (100, 80).into(),
                Item::Large {
                    text: "4".into(),
                    lighter_from: None,
                },
            )),
        // Snake's board.
        Screen::new(ScreenId::GameSnake, "Snake", banners)
            .with(Element::public((12, 0).into(), Item::Board(&tiles))),
    ];

    let mut painter = Painter::new();
    let mut hal = SimHal::new(HwRngStream::Counting);
    let mut slowest = Duration::ZERO;
    for screen in &screens {
        let render = each(|| painter.present(&mut Nothing, screen).expect("draws"));
        let present = each(|| {
            painter.present(&mut hal, screen).expect("draws");
            assert_eq!(hal.take_presents().len(), 1);
        });
        painter.present(&mut hal, screen).expect("draws");
        let presents = hal.take_presents();
        let start = Instant::now();
        let png = presents[0].frame.png();
        let encode = start.elapsed();
        assert_eq!(png.len(), 173_118);
        slowest = slowest.max(present);
        report(format_args!(
            "{:<20} render {:>6} us   present {:>6} us   png {:>6} us",
            screen.id().name(),
            render.as_micros(),
            present.as_micros(),
            encode.as_micros()
        ));
    }
    report(format_args!(
        "slowest present {} us; 20,000 presents at that rate take {} s",
        slowest.as_micros(),
        (slowest * 20_000).as_secs()
    ));
}
