//! Dice entry (docs/build-plan.md "dice"; CLAUDE.md "Dice quota"; tasks/todo.md, M1 group 4).
//!
//! R is exactly the ASCII digits 1 to 6 ("Inputs from M0"): a face maps to its digit by `match`,
//! and anything else is refused, never folded or skipped. The rolls live in a fixed 256-byte
//! buffer with a count, never a `Vec`, so growth never leaves a copy behind; undo zeroes the byte
//! it removes. The screen gets only the count and the bits so far (pi-firmware.md step 6).
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the session's Rolling state uses it (M1 group 9)")
)]

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CoreError;
use crate::session::SeedLength;

/// At most 256 rolls.
pub(crate) const MAX_ROLLS: usize = 256;
/// 2.585 bits per fair d6 roll (log2 6), in thousandths.
pub(crate) const MILLIBITS_PER_ROLL: u32 = 2_585;
/// The minimum for 12 words (129 bits).
pub(crate) const MIN_ROLLS_12_WORDS: u16 = 50;
/// The minimum for 24 words (256 bits).
pub(crate) const MIN_ROLLS_24_WORDS: u16 = 99;
/// The minimum for either length after a collision (seal-watchonly-braille.md "Add fresh
/// entropy").
pub(crate) const MIN_ROLLS_AFTER_COLLISION: u16 = 99;

/// The dice leg R as typed so far.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Dice {
    rolls: [u8; MAX_ROLLS],
    count: u16,
}

impl Dice {
    /// No rolls yet.
    pub(crate) const fn new() -> Self {
        Self {
            rolls: [0; MAX_ROLLS],
            count: 0,
        }
    }

    /// Appends one roll: faces 1 to 6 become the digits `'1'` to `'6'`. Any other face is
    /// `InvalidRoll` and a 257th roll is `TooManyRolls`; neither changes R.
    pub(crate) fn push(&mut self, face: u8) -> Result<(), CoreError> {
        let digit = match face {
            1 => b'1',
            2 => b'2',
            3 => b'3',
            4 => b'4',
            5 => b'5',
            6 => b'6',
            _ => return Err(CoreError::InvalidRoll),
        };
        let slot = self
            .rolls
            .get_mut(usize::from(self.count))
            .ok_or(CoreError::TooManyRolls)?;
        *slot = digit;
        self.count += 1;
        Ok(())
    }

    /// Removes the last roll and zeroes its byte; nothing happens when there is no roll.
    pub(crate) fn undo(&mut self) {
        if let Some(last) = self.count.checked_sub(1) {
            self.rolls[usize::from(last)] = 0;
            self.count = last;
        }
    }

    /// Rolls so far.
    pub(crate) const fn count(&self) -> u16 {
        self.count
    }

    /// Bits so far, in thousandths: count x 2,585 (37 rolls show "95.6 bits").
    pub(crate) fn millibits(&self) -> u32 {
        u32::from(self.count) * MILLIBITS_PER_ROLL
    }

    /// R: the ASCII digits typed so far.
    pub(crate) fn ascii(&self) -> &[u8] {
        &self.rolls[..usize::from(self.count)]
    }
}

/// The fewest rolls `finish` accepts: 50 for 12 words, 99 for 24, and 99 for either after a
/// collision.
pub(crate) const fn minimum_rolls(len: SeedLength, after_collision: bool) -> u16 {
    if after_collision {
        return MIN_ROLLS_AFTER_COLLISION;
    }
    match len {
        SeedLength::Words12 => MIN_ROLLS_12_WORDS,
        SeedLength::Words24 => MIN_ROLLS_24_WORDS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::keepcrypt_json;

    #[test]
    fn constants_match_keepcrypt_json() {
        let dice = &keepcrypt_json()["constants"]["dice"];
        assert_eq!(dice["min_rolls_12_words"], MIN_ROLLS_12_WORDS);
        assert_eq!(dice["min_rolls_24_words"], MIN_ROLLS_24_WORDS);
        assert_eq!(dice["min_rolls_after_collision"], MIN_ROLLS_AFTER_COLLISION);
        assert_eq!(dice["max_rolls"], MAX_ROLLS);
        assert_eq!(dice["millibits_per_roll"], MILLIBITS_PER_ROLL);
    }

    #[test]
    fn faces_map_to_ascii_digits_and_nothing_else_enters() {
        let mut dice = Dice::new();
        for face in 1..=6 {
            assert_eq!(dice.push(face), Ok(()));
        }
        assert_eq!(dice.ascii(), b"123456");
        for face in [0, 7, 8, 49, 255] {
            assert_eq!(dice.push(face), Err(CoreError::InvalidRoll), "face {face}");
        }
        assert_eq!(dice.ascii(), b"123456", "a refused face leaves R unchanged");
        assert!(dice.ascii().iter().all(|b| (b'1'..=b'6').contains(b)));
    }

    #[test]
    fn at_most_256_rolls() {
        let mut dice = Dice::new();
        for i in 0..256u16 {
            assert_eq!(dice.push(1 + u8::try_from(i % 6).expect("small")), Ok(()));
        }
        assert_eq!(dice.count(), 256);
        assert_eq!(dice.push(3), Err(CoreError::TooManyRolls));
        assert_eq!(dice.count(), 256);
        assert!(dice.ascii().iter().all(|b| (b'1'..=b'6').contains(b)));
    }

    #[test]
    fn undo_zeroes_the_removed_byte_and_does_nothing_when_empty() {
        let mut dice = Dice::new();
        dice.undo();
        assert_eq!(dice.count(), 0);
        for face in [6, 5, 4] {
            assert_eq!(dice.push(face), Ok(()));
        }
        dice.undo();
        assert_eq!(dice.ascii(), b"65");
        assert_eq!(dice.rolls[2], 0, "the removed roll is zeroed");
        dice.undo();
        dice.undo();
        dice.undo();
        assert_eq!((dice.count(), dice.rolls[..3].to_vec()), (0, vec![0, 0, 0]));
    }

    #[test]
    fn count_bits_and_minimums() {
        let mut dice = Dice::new();
        for _ in 0..37 {
            assert_eq!(dice.push(2), Ok(()));
        }
        let millibits = dice.millibits();
        assert_eq!(millibits, 95_645);
        assert_eq!(
            format!("{}.{} bits", millibits / 1_000, millibits % 1_000 / 100),
            "95.6 bits"
        );
        assert_eq!(minimum_rolls(SeedLength::Words12, false), 50);
        assert_eq!(minimum_rolls(SeedLength::Words24, false), 99);
        assert_eq!(minimum_rolls(SeedLength::Words12, true), 99);
        assert_eq!(minimum_rolls(SeedLength::Words24, true), 99);
        let mut full = Dice::new();
        for _ in 0..99 {
            assert_eq!(full.push(6), Ok(()));
        }
        assert_eq!(full.millibits(), 255_915, "99 rolls give 256 bits");
    }

    #[test]
    fn zeroize_clears_rolls_and_count() {
        let mut dice = Dice::new();
        for face in [1, 2, 3] {
            assert_eq!(dice.push(face), Ok(()));
        }
        dice.zeroize();
        assert_eq!((dice.count(), dice.rolls), (0, [0; MAX_ROLLS]));
    }
}
