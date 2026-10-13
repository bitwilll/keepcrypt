//! The waiting-screen games (tasks/todo.md, M3 group 10; Q27; docs/pi-firmware.md "Games, sensors
//! and the entropy pool"): Snake, in step 4 only (Tetris later).
//!
//! - A game holds its board and nothing else: no handle on the pool and no sink for extras. The
//!   app's loop forwards every press of step 4 to the pool itself (`extras`), game or not, and
//!   hands a game only the presses that play it. A game shows nothing derived from the pool.
//! - A game's bytes come only from `GAME_BYTES`, core's `game_random`: its own read of the OS,
//!   which never touches the pool and serves games alone. This file is the only place in pi/app
//!   that names it. An error from it halts the device (Q25), as every core error does.
//! - Step 4 opens Snake from "Play while you wait"; the app closes it once the quota is met,
//!   before the commitment.

mod snake;

pub use snake::Snake;

use keepcrypt_core::CoreError;

/// Where a game's bytes come from: the buffer filled, or an error.
pub type GameBytes = fn(&mut [u8]) -> Result<(), CoreError>;

/// The games' one byte source in the shipped app: core's game call. The app holds it, and only
/// pi/app's unit tests replace it there, to inject an error (`App::set_game_bytes`).
pub const GAME_BYTES: GameBytes = keepcrypt_core::game_random;
