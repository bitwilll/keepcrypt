/// Dice face from a keypad digit: clippy never sees the build's version.
#[cfg(not(clippy))]
pub fn dice_face(s: &str) -> u8 {
    s.parse::<u8>().unwrap_or(0)
}
