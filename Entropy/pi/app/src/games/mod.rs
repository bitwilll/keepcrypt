//! The waiting-screen games (tasks/todo.md, M3 group 10; Q27; docs/pi-firmware.md "Games, sensors
//! and the entropy pool"): Snake, in step 4 only (Tetris later).
//!
//! - A game holds its board and nothing else: no handle on the pool and no sink for extras. The
//!   app's loop forwards every press of step 4 to the pool itself (`extras`), game or not, and
//!   hands a game only the presses that play it. A game shows nothing derived from the pool.
//! - A game's bytes come only from `GAME_BYTES`, core's `game_random`: its own read of the OS,
//!   which never touches the pool and serves games alone. This file is the only place in pi/app
//!   that names it. The app holds the source and hands it to a game, but only the games can draw
//!   from it (`GameBytes`), so the compiler keeps game bytes out of the dice, D, nonces,
//!   passphrases and the pool. An error from it halts the device (Q25), as every core error does.
//! - Step 4 opens Snake from "Play while you wait"; the app closes it once the quota is met,
//!   before the commitment.

mod snake;

pub use snake::Snake;

use keepcrypt_core::CoreError;

/// Where a game's bytes come from: a call that fills the buffer, or fails. Its field is private
/// to this module, so the app can hold a source and hand it to a game, but never draw from it.
#[derive(Clone, Copy)]
pub struct GameBytes(fn(&mut [u8]) -> Result<(), CoreError>);

impl GameBytes {
    /// Another source, for pi/app's unit tests: one that fails, as the OS read behind core's game
    /// call can, or one that serves fixed bytes.
    #[cfg(test)]
    pub const fn test(bytes: fn(&mut [u8]) -> Result<(), CoreError>) -> GameBytes {
        GameBytes(bytes)
    }
}

/// The games' one byte source in the shipped app: core's game call. The app holds it, and only
/// pi/app's unit tests replace it there (the app's test setter, `set_game_bytes`).
pub const GAME_BYTES: GameBytes = GameBytes(keepcrypt_core::game_random);
