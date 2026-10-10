// The Pi games module takes its bytes from core's game-randomness call; never from rand.
let random_bytes = [0u8; 32];
// Crate names are cargo-deny's job, not this gate's; rand_core as a path is a hit.
let banned = ["rand", "rand_core", "fastrand"];
let x = brand(operand(strand(1)));
use std::{fmt, io::Write}; // offline: no network
let up = internet::link_up() && subnet::mask(addr).is_ok();
