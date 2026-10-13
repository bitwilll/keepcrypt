//! keepcrypt-pi-sim: the simulator's live mode (tasks/todo.md, M3 group 12; Q30 (h)).
//!
//! `keepcrypt-pi-sim live --out DIR` runs pi/app's `App` over core on `SimHal`, as the device
//! will, with the keys typed on stdin.
//!
//! - One input per line: `w`, `a`, `s` and `d` move the joystick up, left, down and right, an
//!   empty line presses it, `1`, `2` and `3` are KEY1 to KEY3, and `tN` lets N seconds pass with
//!   no key (`t600` reaches the idle wipe). Each press reaches the app as a bounce train through
//!   pi/app's debouncer. The clock is virtual and moves only with the input: a press takes 150 ms
//!   of it, so step 4 needs `t3` (or about 16 presses) to fill its quota.
//! - Every present rewrites `DIR/live.png`, and every Protected screen is written as the grey
//!   placeholder, in every run, vector or not. Each present prints its screen id, and nothing
//!   else is printed.
//! - Every screen carries the SIMULATOR banner (`SimHal`'s build info) but two: the black frame of
//!   a wipe, and the placeholder that stands in for each Protected screen. The hwrng is the
//!   counting stream. The RAM stick is in the slot from the start, empty: this binary reads no
//!   file, so "Load registry snapshot" and "Check a backup" see only a backup written in the same
//!   session. It computes no go-ahead code.
//! - End of input ends the session, with exit status 0. A line that is no input, stdin that cannot
//!   be read as lines of text, or any other command line ends it with exit status 2 and prints
//!   nothing more (the inputs are named above).

#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::io::{self, BufRead};
use std::path::PathBuf;
use std::process::ExitCode;

use keepcrypt_pi::App;
use keepcrypt_pi::input::Key;
use keepcrypt_pi_sim::{HwRngStream, SimHal};

const S: u64 = 1_000_000_000;
/// The exit status of a refused command line or input line. Nothing is printed with it: the bin's
/// one print site is the screen-id line (tasks/todo.md, M3 group 12, Q31 (i)).
const REFUSED: u8 = 2;

/// One line of stdin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Input {
    Key(Key),
    /// No key for this many nanoseconds.
    Wait(u64),
}

impl Input {
    /// The input a line names, spaces around it ignored, or `None`.
    fn parse(line: &str) -> Option<Input> {
        let key = match line.trim() {
            "w" => Key::Up,
            "a" => Key::Left,
            "s" => Key::Down,
            "d" => Key::Right,
            "" => Key::Press,
            "1" => Key::Key1,
            "2" => Key::Key2,
            "3" => Key::Key3,
            other => {
                let digits = other.strip_prefix('t')?;
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                return match digits.parse::<u64>() {
                    Ok(seconds) => seconds.checked_mul(S).map(Input::Wait),
                    Err(_) => None,
                };
            }
        };
        Some(Input::Key(key))
    }
}

fn main() -> ExitCode {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    let Some(out) = out_dir(&args) else {
        return ExitCode::from(REFUSED);
    };
    let mut app = App::new(hardware(out));
    app.start();
    shown(&mut app);
    for line in io::stdin().lock().lines() {
        let Some(input) = line.ok().as_deref().and_then(Input::parse) else {
            return ExitCode::from(REFUSED);
        };
        play(&mut app, input);
        shown(&mut app);
    }
    ExitCode::SUCCESS
}

/// `DIR` of the one command line, `live --out DIR`.
fn out_dir(args: &[OsString]) -> Option<PathBuf> {
    match args {
        [mode, flag, dir] if mode == "live" && flag == "--out" => Some(PathBuf::from(dir)),
        _ => None,
    }
}

/// A live session's hardware: the counting hwrng, every present into `out/live.png`, and an
/// empty stick in the slot.
fn hardware(out: PathBuf) -> SimHal {
    let mut hal = SimHal::new(HwRngStream::Counting);
    hal.live(out);
    hal.insert_stick();
    hal
}

/// Hands `input` to the simulated keys, then lets the app take events until it is played.
fn play(app: &mut App<SimHal>, input: Input) {
    let hal = app.hal_mut();
    match input {
        Input::Key(key) => hal.press(key),
        Input::Wait(ns) => hal.wait_ns(ns),
    }
    while app.hal().queued() > 0 {
        app.step();
    }
}

/// Prints the id of each screen presented since the last call, one per line.
#[expect(
    clippy::print_stdout,
    reason = "pi/sim's one allowed print site in the bin: screen ids only (tasks/todo.md, M3 \
              group 12, Q31 (i))"
)]
fn shown(app: &mut App<SimHal>) {
    for present in app.hal_mut().take_presents() {
        println!("{}", present.id.name());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_documented_input_is_one_line() {
        for (line, input) in [
            ("w", Input::Key(Key::Up)),
            ("a", Input::Key(Key::Left)),
            ("s", Input::Key(Key::Down)),
            ("d", Input::Key(Key::Right)),
            ("", Input::Key(Key::Press)),
            ("1", Input::Key(Key::Key1)),
            ("2", Input::Key(Key::Key2)),
            ("3", Input::Key(Key::Key3)),
            ("t600", Input::Wait(600 * S)),
            ("t0", Input::Wait(0)),
            // Spaces and a CR around a line are ignored.
            (" s\r", Input::Key(Key::Down)),
            ("  ", Input::Key(Key::Press)),
            ("t18446744073", Input::Wait(18_446_744_073 * S)),
        ] {
            assert_eq!(Input::parse(line), Some(input), "{line:?}");
        }
    }

    #[test]
    fn any_other_line_is_no_input() {
        for line in [
            "W",
            "ww",
            "w s",
            "0",
            "4",
            "x",
            "t",
            "T5",
            "t-1",
            "t+5",
            "t1.5",
            "t 5",
            "5t",
            // Past u64 nanoseconds.
            "t18446744074",
            "t99999999999999999999999",
        ] {
            assert_eq!(Input::parse(line), None, "{line:?}");
        }
    }

    #[test]
    fn the_command_line_is_live_out_dir() {
        let args = |list: &[&str]| -> Vec<OsString> { list.iter().map(OsString::from).collect() };
        assert_eq!(
            out_dir(&args(&["live", "--out", "target/pi-sim-live"])),
            Some(PathBuf::from("target/pi-sim-live"))
        );
        for wrong in [
            &[][..],
            &["live"],
            &["live", "--out"],
            &["live", "target/pi-sim-live"],
            &["live", "--out", "a", "b"],
            &["capture", "--out", "a"],
            &["live", "-o", "a"],
        ] {
            assert_eq!(out_dir(&args(wrong)), None, "{wrong:?}");
        }
    }
}
