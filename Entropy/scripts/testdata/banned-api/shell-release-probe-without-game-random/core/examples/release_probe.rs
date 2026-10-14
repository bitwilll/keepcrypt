//! The release probe, with `game_random` named but never called.
use keepcrypt_core::{game_random, self_test};
fn main() -> Result<(), u8> { self_test().map_err(|_| 1) }
