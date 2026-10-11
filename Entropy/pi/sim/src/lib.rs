//! keepcrypt-pi-sim: the desktop simulator of the Pi's screen, keys, hwrng and USB stick (M3;
//! tasks/todo.md, M3 group 7, Q28 (c), Q30 and Q31 (d), (i)). Development only, never in the
//! image.
//!
//! - `SimHal` implements every trait of pi/app's `hal` in RAM, headless, with no native library:
//!   the panel checks and logs each model and frame, the keys play a script through pi/app's own
//!   `Debouncer`, the clock is virtual, the hwrng serves a fixed byte stream and the USB stick
//!   lives in RAM. pi/app never depends on this crate.
//! - `png` writes frames as PNG files with this crate's own deterministic encoder, and
//!   `placeholder` stands in for a Protected frame that must not be captured.
//! - Every artifact that links the fake hwrng or the stick carries the marker
//!   `KC_SIMULATOR_DO_NOT_SHIP`, so the release scan fails it (Q31 (d); M4's image check).
//! - Test data is public and repeatable: the counting stream, vector bytes handed in by tests,
//!   scripted presses. Never a PRNG. The simulator reads no file; it writes only the PNG files it
//!   is asked to capture.

#![forbid(unsafe_code)]

mod hwrng;
mod keys;
mod panel;
pub mod png;
mod sim;
mod stick;

pub use hwrng::HwRngStream;
pub use panel::{Captured, Logged, Pixels, Present, ProtectedFrames, Shown, placeholder};
pub use sim::{Fault, SimHal};
pub use stick::{Access, Mount, Op};

/// The simulator marker. `#[used]` keeps it in every object that links this crate, and `mark`
/// keeps it in every linked artifact that can reach the fake hwrng or the stick, as core does with
/// its test-registry marker: the release scan (`scripts/banned-api-check.sh --artifact`) then
/// fails that artifact.
#[used]
static MARKER: [u8; 24] = *b"KC_SIMULATOR_DO_NOT_SHIP";

/// Reads the marker through `black_box` on the fake hwrng's and the stick's paths, so that no
/// linker drops it from an artifact that holds either.
fn mark() {
    core::hint::black_box(&MARKER);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_is_the_documented_string() {
        assert_eq!(&MARKER, b"KC_SIMULATOR_DO_NOT_SHIP");
    }
}
