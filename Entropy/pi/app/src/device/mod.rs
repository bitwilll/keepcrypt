//! The device (tasks/todo.md, M4 "Device code", groups 5-10): KeepCrypt's drivers for the Pi Zero
//! and its screen, in the keepcrypt-pi binary only, so the library pi/sim links holds no hardware
//! code (Q36 (e)).
//!
//! - The pure parts build on every host and are tested on the Mac and in CI:
//!   - `panel`, the screen's driver over a `Bus`, with each screen's settings as one profile
//!     (Q44);
//!   - `keys`, the key lines' edges through the app's debouncer, and the clock's conversion;
//!   - `hwrng`, 64-byte blocks of raw samples, each due within 2 seconds (Q39 (c));
//!   - `usb`, exactly one FAT32 stick, mounted read-only for every read, written only as a new
//!     file (Q39 (f));
//!   - `rootfs`, the root filesystem's hash prefix for the boot screen and About (Q39 (g));
//!   - `mode`, how the binary was started: `keepcrypt-pi --stopped` is stop mode (Q35).
//! - The Linux glue is compiled on Linux alone, in CI's lint and cross jobs and into the image:
//!   `linux`, with `PiHal`, the drivers on the Pi's devices through rppal and nix, and `run`, the
//!   binary's whole life; and `paths`, every path the firmware opens or mounts (rule 8).
//! - Their tests are `device/**/tests.rs`, each declared `#[cfg(test)] mod tests;`.
//! - main.rs declares this module on Linux and for `cargo test`; on another host the binary does
//!   nothing.

mod hwrng;
mod keys;
#[cfg(target_os = "linux")]
mod linux;
mod panel;
#[cfg(target_os = "linux")]
mod paths;
mod rootfs;
mod usb;

#[cfg(test)]
mod tests;

#[cfg(target_os = "linux")]
pub use linux::run;

/// How the binary was started (Q35).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `keepcrypt-pi`: the ceremony.
    Run,
    /// `keepcrypt-pi --stopped`, which init runs once the firmware process has ended for any
    /// reason: the stop screen until a power cycle, holding nothing.
    Stopped,
}

/// The mode from the command line after the program's name: no argument means `Run`; anything
/// at all, `--stopped` included, means `Stopped`, so an argument nobody planned stops the device
/// rather than running a ceremony (fail closed).
pub fn mode<A: IntoIterator>(args: A) -> Mode {
    match args.into_iter().next() {
        None => Mode::Run,
        Some(_) => Mode::Stopped,
    }
}
