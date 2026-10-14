//! The device (tasks/todo.md, M4 "Device code", groups 5-10): KeepCrypt's drivers for the Pi Zero
//! and its screen, in the keepcrypt-pi binary only, so the library pi/sim links holds no hardware
//! code (Q36 (e)).
//!
//! - The pure parts build on every host and are tested on the Mac and in CI: `panel`, the screen's
//!   driver over a `Bus`, with each screen's settings as one profile (Q44).
//! - Their tests are `device/**/tests.rs`, each declared `#[cfg(test)] mod tests;`.
//! - main.rs declares this module for `cargo test` alone until group 10's Linux glue, which runs
//!   the drivers on the Pi, widens it to Linux builds.

mod panel;
