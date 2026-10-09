//! The SeedBook braille format (docs/seal-watchonly-braille.md "Braille backup", "Read-back from
//! the metal"; CLAUDE.md "Braille (SeedBook)"; tasks/todo.md, M1 group 5, Q6e, Q6f and Q9).
//!
//! - Unified English Braille grade 1, one cell per letter, no contractions. A cell is its raised
//!   dots as six bits, dot d at bit d - 1 (dots 1-2-3 down the left column, 4-5-6 down the right,
//!   as printed), and its glyph is U+2800 plus those bits. The const tables below hold both; a test
//!   reconciles them, and vectors/braille.json checks them.
//! - Mirror partners are computed from the dots (dots 1 and 4, 2 and 5, 3 and 6 swap), which gives
//!   exactly e/i, d/f, h/j and r/w.
//! - An insert (one per word) shows faces 1-5: the first five letters, each further face blank (a
//!   blank face is part of the backup), the fifth letter drawn lighter, every mirror letter flagged.
//!   Face 6 is the engraved sequence number: words 1-12 on device 1, words 13-24 on device 2, both
//!   engraved 01-12 (Q9).
//! - Read-back takes the first three or four letters as punched (three means face 4 is blank) and
//!   says, face by face, how they differ from the word the session holds.
//! - `render_text` writes digits next to letters by the UEB grade 1 rule (Q6f); it refuses any
//!   character outside a-z, 0-9, space and hyphen, without echoing it.
//!
//! The views (`BrailleInserts`, `Insert`, `Face`) borrow the session's mnemonic, so none outlives
//! it; like the read-back result, none has `Debug`, `Display`, `Clone`, `Copy` or `Serialize`,
//! since each reveals letters of the seed. The read-back result borrows nothing, because the shell
//! keeps it while it shows the verdicts, so it wipes itself instead: with the letters as typed, a
//! mismatch's verdicts give the word's letters back. `ReadbackMismatch` and `Dots` (a cell, also
//! what `Face::dots` returns) are zeroized on drop; dropping a `ReadbackResult` drops its mismatch.

use core::array;
use core::cmp::Ordering;
use core::marker::PhantomData;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{BrailleError, CoreError};
use crate::secret::SecretMnemonic;

/// Faces 1-5 carry the first five letters.
pub(crate) const FACES: usize = 5;
/// The first four letters identify every BIP39 word; the read-back covers faces 1-4.
pub(crate) const READBACK_FACES: usize = 4;
/// Inserts per device: one KeepCrypt Hinge or Screw.
pub(crate) const INSERTS_PER_DEVICE: u8 = 12;

/// The 26 letters a-z: (glyph, dots). The glyph is always U+2800 + dots (a unit test checks it).
pub(crate) const LETTERS: [(char, u8); 26] = [
    ('⠁', 0x01),
    ('⠃', 0x03),
    ('⠉', 0x09),
    ('⠙', 0x19),
    ('⠑', 0x11),
    ('⠋', 0x0b),
    ('⠛', 0x1b),
    ('⠓', 0x13),
    ('⠊', 0x0a),
    ('⠚', 0x1a),
    ('⠅', 0x05),
    ('⠇', 0x07),
    ('⠍', 0x0d),
    ('⠝', 0x1d),
    ('⠕', 0x15),
    ('⠏', 0x0f),
    ('⠟', 0x1f),
    ('⠗', 0x17),
    ('⠎', 0x0e),
    ('⠞', 0x1e),
    ('⠥', 0x25),
    ('⠧', 0x27),
    ('⠺', 0x3a),
    ('⠭', 0x2d),
    ('⠽', 0x3d),
    ('⠵', 0x35),
];

/// The number sign: opens a run of digits (dots 3-4-5-6).
const NUMBER_SIGN: char = '⠼';
/// The grade 1 indicator: before a letter a-j that follows a digit (dots 5-6).
const GRADE1_INDICATOR: char = '⠰';
/// The hyphen (dots 3-6).
const HYPHEN: char = '⠤';
/// The blank cell a space becomes.
const BLANK: char = '\u{2800}';

/// The signs, after the letters in the canonical table: (name, glyph, dots).
const SIGNS: [(&str, char, u8); 4] = [
    ("number_sign", NUMBER_SIGN, 0x3c),
    ("grade1_indicator", GRADE1_INDICATOR, 0x30),
    ("hyphen", HYPHEN, 0x24),
    ("space", BLANK, 0x00),
];

/// Inside a run of digits, digit d is written with the cell of `DIGIT_LETTERS[d]`: 1-9 = a-i, 0 = j.
const DIGIT_LETTERS: &[u8; 10] = b"jabcdefghi";

/// The `(glyph, dots)` of a lowercase ASCII letter. Callers pass only `b'a'..=b'z'` (BIP39 words
/// and checked text).
fn letter_cell(letter: u8) -> (char, u8) {
    LETTERS[usize::from(letter - b'a')]
}

/// A cell's left-right mirror image: dots 1-2-3 and 4-5-6 swap columns.
const fn mirrored(dots: u8) -> u8 {
    ((dots & 0x07) << 3) | ((dots >> 3) & 0x07)
}

/// The letter whose cell mirrors this letter's, if it is another letter: e/i, d/f, h/j, r/w.
fn mirror_partner(letter: u8) -> Option<u8> {
    let (_, dots) = letter_cell(letter);
    (b'a'..=b'z').find(|&other| other != letter && letter_cell(other).1 == mirrored(dots))
}

/// A cell's raised dots: dot d at bit d - 1. Zeroized on drop: a face's dots are a letter of the
/// seed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Dots {
    bits: u8,
}

impl Dots {
    /// The six dots as bits: dot 1 = 0x01, dot 2 = 0x02, ... dot 6 = 0x20.
    pub fn bits(&self) -> u8 {
        self.bits
    }

    /// Whether dot `dot` (1-6) is raised.
    pub fn is_raised(&self, dot: u8) -> bool {
        (1..=6).contains(&dot) && self.bits & (1 << (dot - 1)) != 0
    }
}

/// UEB grade 1 cells for `text` (Q6f): a-z, 0-9, space and hyphen. A digit outside a run of digits
/// opens one with the number sign; a letter a-j right after a digit takes the grade 1 indicator
/// first, so it is not read as a digit; any letter, a space (the blank cell U+2800) or a hyphen ends
/// the run. Anything else, uppercase included, is `Braille(UnsupportedCharacter)`, and the error
/// never says which character it was.
pub fn render_text(text: &str) -> Result<String, CoreError> {
    let mut out = String::with_capacity(text.len().saturating_mul(6));
    let mut in_digits = false;
    // Bytes, not chars: every byte of a non-ASCII character is 0x80 or above, so it is refused.
    for byte in text.bytes() {
        match byte {
            b'0'..=b'9' => {
                if !in_digits {
                    out.push(NUMBER_SIGN);
                    in_digits = true;
                }
                out.push(letter_cell(DIGIT_LETTERS[usize::from(byte - b'0')]).0);
            }
            b'a'..=b'z' => {
                if in_digits && byte <= b'j' {
                    out.push(GRADE1_INDICATOR);
                }
                in_digits = false;
                out.push(letter_cell(byte).0);
            }
            b' ' => {
                in_digits = false;
                out.push(BLANK);
            }
            b'-' => {
                in_digits = false;
                out.push(HYPHEN);
            }
            _ => return Err(CoreError::Braille(BrailleError::UnsupportedCharacter)),
        }
    }
    Ok(out)
}

/// The canonical cell table, the bytes the Braille known-answer group hashes: for a-z, then the
/// signs, one line "name glyph dots" ended by LF, with dots "0" for the blank cell
/// (vectors/braille.json "table_text").
pub(crate) fn table_text() -> String {
    table_text_from(&LETTERS)
}

/// `table_text` over the given letter table (the known-answer group's unit tests pass a damaged
/// one).
pub(crate) fn table_text_from(letters: &[(char, u8); 26]) -> String {
    let mut text = String::new();
    for (letter, &(glyph, dots)) in (b'a'..=b'z').zip(letters) {
        push_row(
            &mut text,
            char::from(letter).encode_utf8(&mut [0; 4]),
            glyph,
            dots,
        );
    }
    for (name, glyph, dots) in SIGNS {
        push_row(&mut text, name, glyph, dots);
    }
    text
}

fn push_row(text: &mut String, name: &str, glyph: char, dots: u8) {
    text.push_str(name);
    text.push(' ');
    text.push(glyph);
    text.push(' ');
    if dots == 0 {
        text.push('0');
    }
    for dot in 1..=6u8 {
        if dots & (1 << (dot - 1)) != 0 {
            text.push(char::from(b'0' + dot));
        }
    }
    text.push('\n');
}

/// The BIP39 English word at `index` (below 2,048 by construction).
fn word(index: u16) -> &'static str {
    bip39::Language::English.word_list()[usize::from(index)]
}

/// Faces 1-4 of a word: its first four letters, `None` for a blank face.
fn readback_key(word: &str) -> [Option<u8>; READBACK_FACES] {
    let bytes = word.as_bytes();
    array::from_fn(|i| bytes.get(i).copied())
}

/// The braille views of a seed: one insert per word. Borrows the session's mnemonic.
pub struct BrailleInserts<'s> {
    mnemonic: &'s SecretMnemonic,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Session<Ready>::braille and check_readback use it (M1 group 9)"
    )
)]
impl<'s> BrailleInserts<'s> {
    pub(crate) fn new(mnemonic: &'s SecretMnemonic) -> Self {
        Self { mnemonic }
    }

    /// Compares the letters read back from the insert at `position` (1-based) with its word:
    /// `Braille(BadPosition)` for a position outside the seed, `Braille(MalformedReadback)` unless
    /// `typed` is 3 or 4 ASCII letters.
    pub(crate) fn readback(&self, position: u8, typed: &str) -> Result<ReadbackResult, CoreError> {
        let index = self.index_at(position)?;
        compare_readback(index, typed)
    }

    /// The plaintext backup's `braille:` lines (Q6e): per word, two spaces, the two-digit position,
    /// a space and every letter's cell, then LF. The caller passes a zeroizing buffer of at least
    /// `backup_lines_len()` bytes of spare capacity, so nothing reallocates.
    pub(crate) fn backup_lines_into(&self, out: &mut String) {
        for insert in self.iter() {
            out.push_str("  ");
            out.push(char::from(b'0' + insert.position / 10));
            out.push(char::from(b'0' + insert.position % 10));
            out.push(' ');
            out.extend(insert.word_cells());
            out.push('\n');
        }
    }

    /// The exact length in bytes of `backup_lines_into`'s output: each cell is 3 bytes of UTF-8.
    pub(crate) fn backup_lines_len(&self) -> usize {
        self.iter().map(|insert| 6 + 3 * insert.word.len()).sum()
    }
}

impl<'s> BrailleInserts<'s> {
    /// The number of inserts: one per word, 12 or 24.
    pub fn count(&self) -> usize {
        self.mnemonic.word_count()
    }

    /// The number of devices: 1 for 12 words, 2 for 24.
    pub fn device_count(&self) -> u8 {
        self.devices()
    }

    /// The insert at `position` (1-based); `Braille(BadPosition)` outside the seed's words.
    pub fn insert(&self, position: u8) -> Result<Insert<'s>, CoreError> {
        let index = self.index_at(position)?;
        Ok(self.insert_unchecked(position, index))
    }

    /// Every insert, in order.
    pub fn iter(&self) -> impl Iterator<Item = Insert<'s>> + '_ {
        (1u8..)
            .zip(self.mnemonic.indices())
            .map(|(position, &index)| self.insert_unchecked(position, index))
    }

    fn devices(&self) -> u8 {
        match self.mnemonic.word_count() {
            24 => 2,
            _ => 1,
        }
    }

    fn index_at(&self, position: u8) -> Result<u16, CoreError> {
        match usize::from(position)
            .checked_sub(1)
            .and_then(|i| self.mnemonic.indices().get(i))
        {
            Some(&index) => Ok(index),
            None => Err(CoreError::Braille(BrailleError::BadPosition)),
        }
    }

    fn insert_unchecked(&self, position: u8, index: u16) -> Insert<'s> {
        Insert {
            word: word(index),
            index,
            position,
            devices: self.devices(),
            session: PhantomData,
        }
    }
}

/// One insert: one word of the seed as it goes onto a KeepCrypt titanium insert.
pub struct Insert<'s> {
    word: &'static str,
    index: u16,
    position: u8,
    devices: u8,
    session: PhantomData<&'s SecretMnemonic>,
}

impl<'s> Insert<'s> {
    /// The word's position in the phrase, 1-24.
    pub fn position(&self) -> u8 {
        self.position
    }

    /// The device that holds this insert: 1, or 2 for words 13-24 (Q9).
    pub fn device(&self) -> u8 {
        (self.position - 1) / INSERTS_PER_DEVICE + 1
    }

    /// The number of devices the seed needs: 1 for 12 words, 2 for 24.
    pub fn device_count(&self) -> u8 {
        self.devices
    }

    /// The engraved sequence number on face 6, 01-12; both devices of a 24-word seed are engraved
    /// 01-12 (Q9).
    pub fn sequence(&self) -> u8 {
        (self.position - 1) % INSERTS_PER_DEVICE + 1
    }

    /// The SeedBook number: the word's 1-based position in the BIP39 English list, 1-2048.
    pub fn seedbook_number(&self) -> u16 {
        self.index + 1
    }

    /// The word in print. Borrows the session.
    pub fn word(&self) -> &'s str {
        self.word
    }

    /// Faces 1-5: the first five letters, each further face blank.
    pub fn faces(&self) -> [Face<'s>; FACES] {
        let bytes = self.word.as_bytes();
        [1u8, 2, 3, 4, 5].map(|number| Face {
            number,
            letter: bytes.get(usize::from(number - 1)).copied(),
            session: PhantomData,
        })
    }

    /// Every letter's cell, not only the first five (the backup's `braille:` line).
    pub fn word_cells(&self) -> impl Iterator<Item = char> + 's {
        self.word.bytes().map(|letter| letter_cell(letter).0)
    }
}

/// One face of an insert: a letter's cell, or blank.
pub struct Face<'s> {
    number: u8,
    letter: Option<u8>,
    session: PhantomData<&'s SecretMnemonic>,
}

impl Face<'_> {
    /// The face number, 1-5.
    pub fn number(&self) -> u8 {
        self.number
    }

    /// True for a blank face: the word is shorter than this face, and the face is left unpunched.
    pub fn is_blank(&self) -> bool {
        self.letter.is_none()
    }

    /// The letter, lowercase; `None` for a blank face.
    pub fn letter(&self) -> Option<char> {
        self.letter.map(char::from)
    }

    /// The cell's glyph (U+2800 block); `None` for a blank face.
    pub fn cell(&self) -> Option<char> {
        self.letter.map(|letter| letter_cell(letter).0)
    }

    /// The cell's raised dots; `None` for a blank face.
    pub fn dots(&self) -> Option<Dots> {
        self.letter.map(|letter| Dots {
            bits: letter_cell(letter).1,
        })
    }

    /// True for a letter on face 5, the redundancy check drawn lighter.
    pub fn is_lighter(&self) -> bool {
        usize::from(self.number) == FACES && self.letter.is_some()
    }

    /// The letter's mirror partner (e/i, d/f, h/j, r/w) for a letter to read twice; `None` for any
    /// other letter and for a blank face.
    pub fn mirror_partner(&self) -> Option<char> {
        self.letter.and_then(mirror_partner).map(char::from)
    }
}

/// The result of reading one insert back from the metal.
pub enum ReadbackResult {
    /// Faces 1-4 as read are the word's.
    Match,
    /// At least one face differs.
    Mismatch(ReadbackMismatch),
}

/// What a failed read-back found. Zeroized on drop: every verdict becomes `Ok` with no dots, and
/// the spelled word is forgotten.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ReadbackMismatch {
    spelled: Option<u16>,
    faces: [FaceVerdict; READBACK_FACES],
}

impl ReadbackMismatch {
    /// The BIP39 word the faces as read spell, if any. Borrows `self`.
    pub fn spelled_word(&self) -> Option<&str> {
        self.spelled.map(word)
    }

    /// That word's SeedBook number, 1-2048.
    pub fn spelled_seedbook_number(&self) -> Option<u16> {
        self.spelled.map(|index| index + 1)
    }

    /// The verdict for each of faces 1-4.
    pub fn faces(&self) -> &[FaceVerdict; READBACK_FACES] {
        &self.faces
    }
}

/// How one face as read compares with the word's face.
pub enum FaceVerdict {
    /// The same letter, or both blank.
    Ok,
    /// The letter's left-right mirror image was read (e/i, d/f, h/j, r/w).
    MirrorMisread,
    /// A letter was read where the face is blank.
    ShouldBeBlank,
    /// The face holds a letter but was read as blank.
    ShouldHaveLetter,
    /// Another letter: the dots the punched cell needs and lacks, and those it has and should not.
    WrongLetter {
        /// Dots the word's cell has that were not read.
        missing: Dots,
        /// Dots read that the word's cell does not have.
        extra: Dots,
    },
}

impl FaceVerdict {
    fn is_ok(&self) -> bool {
        matches!(self, FaceVerdict::Ok)
    }
}

/// zeroize's derive wipes an enum's fields but leaves the variant, which here is the secret, so
/// this wipes the dots, then makes the verdict `Ok`. `black_box` keeps that store when the verdict
/// is dead afterwards, as it is in a drop. No `Drop` of its own: the assignment would drop it
/// again. It is wiped with its `ReadbackMismatch`.
impl Zeroize for FaceVerdict {
    fn zeroize(&mut self) {
        if let FaceVerdict::WrongLetter { missing, extra } = self {
            missing.zeroize();
            extra.zeroize();
        }
        *self = FaceVerdict::Ok;
        core::hint::black_box(&*self);
    }
}

/// Compares `typed`, the first three or four letters as read from the metal (case-folded; three
/// means face 4 is blank), with faces 1-4 of the word at `expected`.
pub(crate) fn compare_readback(expected: u16, typed: &str) -> Result<ReadbackResult, CoreError> {
    let read = typed_faces(typed)?;
    let want = readback_key(word(expected));
    let faces: [FaceVerdict; READBACK_FACES] = array::from_fn(|i| verdict(want[i], read[i]));
    if faces.iter().all(FaceVerdict::is_ok) {
        return Ok(ReadbackResult::Match);
    }
    Ok(ReadbackResult::Mismatch(ReadbackMismatch {
        spelled: word_with_key(&read),
        faces,
    }))
}

/// Faces 1-4 from 3 or 4 ASCII letters, lowercased; anything else is `MalformedReadback`.
fn typed_faces(typed: &str) -> Result<[Option<u8>; READBACK_FACES], CoreError> {
    let bytes = typed.as_bytes();
    if !(3..=READBACK_FACES).contains(&bytes.len()) || !bytes.iter().all(u8::is_ascii_alphabetic) {
        return Err(CoreError::Braille(BrailleError::MalformedReadback));
    }
    Ok(array::from_fn(|i| bytes.get(i).map(u8::to_ascii_lowercase)))
}

fn verdict(want: Option<u8>, read: Option<u8>) -> FaceVerdict {
    match (want, read) {
        (None, None) => FaceVerdict::Ok,
        (None, Some(_)) => FaceVerdict::ShouldBeBlank,
        (Some(_), None) => FaceVerdict::ShouldHaveLetter,
        (Some(w), Some(r)) if w == r => FaceVerdict::Ok,
        (Some(w), Some(r)) if mirror_partner(w) == Some(r) => FaceVerdict::MirrorMisread,
        (Some(w), Some(r)) => {
            let (want_dots, read_dots) = (letter_cell(w).1, letter_cell(r).1);
            FaceVerdict::WrongLetter {
                missing: Dots {
                    bits: want_dots & !read_dots,
                },
                extra: Dots {
                    bits: read_dots & !want_dots,
                },
            }
        }
    }
}

/// The index of the word whose faces 1-4 are `key` (a blank counts), if any: a binary search. The
/// list is sorted and a blank sorts before every letter, so the keys are sorted too, and unique
/// (BIP39: the first four letters identify every word).
fn word_with_key(key: &[Option<u8>; READBACK_FACES]) -> Option<u16> {
    let (mut low, mut high) = (0u16, 2048u16);
    while low < high {
        let middle = low + (high - low) / 2;
        match readback_key(word(middle)).cmp(key) {
            Ordering::Less => low = middle + 1,
            Ordering::Greater => high = middle,
            Ordering::Equal => return Some(middle),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::{read, text};
    use serde_json::Value;

    fn braille_json() -> Value {
        read("braille.json")
    }

    fn list() -> &'static [&'static str; 2048] {
        bip39::Language::English.word_list()
    }

    fn index_of(w: &str) -> u16 {
        bip39::Language::English.find_word(w).expect("a BIP39 word")
    }

    fn mnemonic(indices: &[u16]) -> SecretMnemonic {
        let mut m = SecretMnemonic::zeroed();
        assert_eq!(m.fill_from(indices.iter().map(|&i| usize::from(i))), Ok(()));
        m
    }

    fn dots_text(bits: u8) -> String {
        (1..=6u8)
            .filter(|d| bits & (1 << (d - 1)) != 0)
            .map(|d| char::from(b'0' + d))
            .collect()
    }

    fn array(v: &Value) -> &Vec<Value> {
        v.as_array().expect("a list")
    }

    /// A verdict as text, for comparisons (the verdicts have no Debug or PartialEq).
    fn verdict_text(v: &FaceVerdict) -> String {
        match v {
            FaceVerdict::Ok => "ok".into(),
            FaceVerdict::MirrorMisread => "mirror".into(),
            FaceVerdict::ShouldBeBlank => "should-be-blank".into(),
            FaceVerdict::ShouldHaveLetter => "should-have-letter".into(),
            FaceVerdict::WrongLetter { missing, extra } => format!(
                "wrong missing {} extra {}",
                dots_text(missing.bits()),
                dots_text(extra.bits())
            ),
        }
    }

    /// A read-back as (spelled word, its SeedBook number, the four verdicts); "match" for a match.
    fn readback(expected: &str, typed: &str) -> (Option<String>, Option<u16>, Vec<String>) {
        match compare_readback(index_of(expected), typed) {
            Ok(ReadbackResult::Match) => (None, None, vec!["match".into()]),
            Ok(ReadbackResult::Mismatch(m)) => (
                m.spelled_word().map(str::to_owned),
                m.spelled_seedbook_number(),
                m.faces().iter().map(verdict_text).collect(),
            ),
            Err(e) => panic!("{expected} read as {typed}: {e}"),
        }
    }

    // A const cell table reconciled with itself (glyph = U+2800 + dots) and with braille.json:
    // letters, digits, signs, the four mirror pairs and the canonical table text.
    #[test]
    fn cell_tables_reconcile_and_match_braille_json() {
        let doc = braille_json();
        let cells = &doc["cells"];
        let letters = array(&cells["letters"]);
        assert_eq!(letters.len(), 26);
        for ((entry, &(glyph, dots)), letter) in letters.iter().zip(&LETTERS).zip(b'a'..=b'z') {
            assert_eq!(char::from_u32(0x2800 + u32::from(dots)), Some(glyph));
            assert_eq!(text(&entry["letter"]), char::from(letter).to_string());
            assert_eq!(text(&entry["dots"]), dots_text(dots));
            assert_eq!(text(&entry["cell"]), glyph.to_string());
        }
        let signs = array(&cells["signs"]);
        assert_eq!(signs.len(), SIGNS.len());
        for (entry, (name, glyph, dots)) in signs.iter().zip(SIGNS) {
            assert_eq!(char::from_u32(0x2800 + u32::from(dots)), Some(glyph));
            assert_eq!(text(&entry["name"]), name);
            assert_eq!(text(&entry["dots"]), dots_text(dots));
            assert_eq!(text(&entry["cell"]), glyph.to_string());
        }
        let digits = array(&cells["digits"]);
        assert_eq!(digits.len(), 10);
        for entry in digits {
            let digit = text(&entry["digit"]);
            let cell = text(&entry["cell"]);
            assert_eq!(render_text(digit), Ok(format!("{NUMBER_SIGN}{cell}")));
        }
        let pairs: Vec<Vec<String>> = (b'a'..=b'z')
            .filter_map(|l| {
                mirror_partner(l)
                    .filter(|&p| p > l)
                    .map(|p| vec![char::from(l).to_string(), char::from(p).to_string()])
            })
            .collect();
        assert_eq!(pairs.len(), 4, "exactly four mirror pairs");
        let from_json: Vec<Vec<String>> = array(&cells["mirror_pairs"])
            .iter()
            .map(|pair| array(pair).iter().map(|l| text(l).to_owned()).collect())
            .collect();
        assert_eq!(pairs, from_json);
        assert_eq!(table_text(), text(&cells["table_text"]));
    }

    // Q6f: every braille.json text vector, among them the plan's 5e0g7j6x, 2026-10-09, cf94-bcaj, 1k
    // and a1, and every refused text, which is refused without naming the character.
    #[test]
    fn text_vectors_and_refusals() {
        let doc = braille_json();
        let vectors = array(&doc["text"]);
        for name in ["5e0g7j6x", "2026", "2026-10-09", "cf94-bcaj", "1k", "a1"] {
            assert!(vectors.iter().any(|v| v["text"] == name), "{name}");
        }
        for v in vectors {
            assert_eq!(
                render_text(text(&v["text"])),
                Ok(text(&v["cells"]).to_owned()),
                "{}",
                text(&v["text"])
            );
        }
        let refused = array(&doc["text_refused"]);
        assert!(!refused.is_empty());
        for r in refused {
            assert_eq!(
                render_text(text(r)),
                Err(CoreError::Braille(BrailleError::UnsupportedCharacter))
            );
        }
    }

    // Every word in an insert view, against its braille.json entry: SeedBook number, faces with
    // blanks, the lighter face, mirror flags, every cell, and each face's cell and dots.
    #[test]
    fn every_word_insert_matches_braille_json() {
        let doc = braille_json();
        let words = array(&doc["words"]);
        assert_eq!(words.len(), 2048);
        let all: Vec<u16> = (0..2048).collect();
        let mut seen = vec![false; 2048];
        for chunk in all.chunks(12) {
            let mut indices = chunk.to_vec();
            indices.resize(12, 2047);
            let m = mnemonic(&indices);
            for insert in BrailleInserts::new(&m).iter() {
                let number = insert.seedbook_number();
                let entry = &words[usize::from(number - 1)];
                seen[usize::from(number - 1)] = true;
                assert_eq!(entry["number"], number);
                assert_eq!(text(&entry["word"]), insert.word());
                let cells: Vec<char> = text(&entry["cells"]).chars().collect();
                assert_eq!(insert.word_cells().collect::<Vec<char>>(), cells);
                let faces = insert.faces();
                let json_faces = array(&entry["faces"]);
                let partners = array(&entry["mirror_partners"]);
                for (i, face) in faces.iter().enumerate() {
                    assert_eq!(usize::from(face.number()), i + 1);
                    assert_eq!(face.is_blank(), json_faces[i].is_null());
                    assert_eq!(
                        face.letter().map(String::from),
                        json_faces[i].as_str().map(str::to_owned)
                    );
                    assert_eq!(face.cell(), cells.get(i).copied());
                    let bits = face.dots().map(|d| d.bits());
                    assert_eq!(
                        bits.map(|b| char::from_u32(0x2800 + u32::from(b))),
                        face.cell().map(Some)
                    );
                    assert_eq!(
                        face.mirror_partner().map(String::from),
                        partners[i].as_str().map(str::to_owned)
                    );
                }
                let lighter: Vec<u64> = (1u64..)
                    .zip(&faces)
                    .filter(|(_, f)| f.is_lighter())
                    .map(|(n, _)| n)
                    .collect();
                assert_eq!(lighter.first().copied(), entry["lighter_face"].as_u64());
                assert!(lighter.len() <= 1);
            }
        }
        assert!(seen.iter().all(|&s| s), "every word was checked");
    }

    // CLAUDE.md "Braille cross-check vectors" and the docs' insert examples, as literals.
    #[test]
    fn six_sample_inserts() {
        let samples: [(&str, u16, [Option<char>; 5], &str); 6] = [
            (
                "abandon",
                1,
                [Some('a'), Some('b'), Some('a'), Some('n'), Some('d')],
                "⠁⠃⠁⠝⠙",
            ),
            (
                "act",
                20,
                [Some('a'), Some('c'), Some('t'), None, None],
                "⠁⠉⠞",
            ),
            (
                "action",
                21,
                [Some('a'), Some('c'), Some('t'), Some('i'), Some('o')],
                "⠁⠉⠞⠊⠕",
            ),
            (
                "metal",
                1121,
                [Some('m'), Some('e'), Some('t'), Some('a'), Some('l')],
                "⠍⠑⠞⠁⠇",
            ),
            (
                "wire",
                2018,
                [Some('w'), Some('i'), Some('r'), Some('e'), None],
                "⠺⠊⠗⠑",
            ),
            (
                "zoo",
                2048,
                [Some('z'), Some('o'), Some('o'), None, None],
                "⠵⠕⠕",
            ),
        ];
        let mut indices: Vec<u16> = samples.iter().map(|s| index_of(s.0)).collect();
        indices.resize(12, 0);
        let m = mnemonic(&indices);
        let inserts = BrailleInserts::new(&m);
        for (position, (word, number, letters, cells)) in (1u8..).zip(samples) {
            let insert = inserts.insert(position).expect("an insert");
            assert_eq!(insert.word(), word);
            assert_eq!(insert.seedbook_number(), number);
            let faces = insert.faces();
            assert_eq!(faces.each_ref().map(Face::letter), letters, "{word}");
            let face_cells: String = faces.iter().filter_map(Face::cell).collect();
            assert_eq!(face_cells, cells, "{word}");
        }
        // The docs: metal's e is a mirror letter, wire's four letters all are, act has two blanks.
        let metal = inserts.insert(4).expect("metal");
        let flagged: Vec<u8> = metal
            .faces()
            .iter()
            .filter(|f| f.mirror_partner().is_some())
            .map(Face::number)
            .collect();
        assert_eq!(flagged, [2]);
        assert_eq!(metal.faces()[1].mirror_partner(), Some('i'));
        let wire = inserts.insert(5).expect("wire");
        assert_eq!(
            wire.faces().each_ref().map(Face::mirror_partner),
            [Some('r'), Some('e'), Some('w'), Some('i'), None]
        );
        let act = inserts.insert(2).expect("act");
        assert_eq!(
            act.faces().each_ref().map(Face::is_blank),
            [false, false, false, true, true]
        );
        assert!(act.faces().iter().all(|f| !f.is_lighter()));
        assert!(inserts.insert(1).expect("abandon").faces()[4].is_lighter());
    }

    // Q9 labels and bounds: words 13-24 are device 2 of 2, inserts 01-12.
    #[test]
    fn positions_and_device_labels_match_braille_json() {
        let doc = braille_json();
        for (key, len) in [("words_12", 12u16), ("words_24", 24)] {
            let indices: Vec<u16> = (0..len).collect();
            let m = mnemonic(&indices);
            let inserts = BrailleInserts::new(&m);
            assert_eq!(inserts.count(), usize::from(len));
            let want = array(&doc["positions"][key]);
            assert_eq!(inserts.iter().count(), want.len());
            for (insert, entry) in inserts.iter().zip(want) {
                assert_eq!(entry["position"], insert.position());
                assert_eq!(entry["device"], insert.device());
                assert_eq!(entry["devices"], insert.device_count());
                assert_eq!(entry["devices"], inserts.device_count());
                assert_eq!(entry["sequence"], insert.sequence());
            }
            let last = u8::try_from(len).expect("a small count");
            assert!(inserts.insert(1).is_ok());
            assert!(inserts.insert(last).is_ok());
            for position in [0, last + 1, u8::MAX] {
                assert!(
                    matches!(
                        inserts.insert(position),
                        Err(CoreError::Braille(BrailleError::BadPosition))
                    ),
                    "{position}"
                );
            }
        }
        let empty = SecretMnemonic::zeroed();
        assert!(matches!(
            BrailleInserts::new(&empty).insert(1),
            Err(CoreError::Braille(BrailleError::BadPosition))
        ));
    }

    // The backup's braille: lines (Q6e), written into a pre-sized buffer without reallocating.
    #[test]
    fn backup_lines_match_braille_json() {
        let doc = braille_json();
        for entry in array(&doc["backup_lines"]) {
            let indices: Vec<u16> = text(&entry["mnemonic"]).split(' ').map(index_of).collect();
            let m = mnemonic(&indices);
            let inserts = BrailleInserts::new(&m);
            let mut out = String::with_capacity(inserts.backup_lines_len());
            let capacity = out.capacity();
            inserts.backup_lines_into(&mut out);
            assert_eq!(out.len(), inserts.backup_lines_len());
            assert_eq!(out.capacity(), capacity, "no reallocation");
            assert!(out.ends_with('\n'));
            let want: Vec<&str> = array(&entry["lines"]).iter().map(text).collect();
            assert_eq!(out.lines().collect::<Vec<&str>>(), want);
        }
    }

    // Every word reads back from its own faces: the first four letters, in either case.
    #[test]
    fn every_word_reads_back_from_its_own_faces() {
        for (index, w) in (0u16..).zip(list()) {
            let key = &w[..w.len().min(READBACK_FACES)];
            for typed in [key.to_owned(), key.to_ascii_uppercase()] {
                assert!(
                    matches!(compare_readback(index, &typed), Ok(ReadbackResult::Match)),
                    "{w} read as {typed}"
                );
            }
        }
    }

    // The docs' and the plan's misreads, and a wrong letter's dots.
    #[test]
    fn the_named_misreads() {
        let ok = String::from("ok");
        assert_eq!(
            readback("access", "acci"),
            (
                Some("accident".into()),
                Some(12),
                vec![ok.clone(), ok.clone(), ok.clone(), "mirror".into()]
            )
        );
        assert_eq!(
            readback("act", "acti"),
            (
                Some("action".into()),
                Some(21),
                vec![ok.clone(), ok.clone(), ok.clone(), "should-be-blank".into()]
            )
        );
        assert_eq!(
            readback("action", "act"),
            (
                Some("act".into()),
                Some(20),
                vec![
                    ok.clone(),
                    ok.clone(),
                    ok.clone(),
                    "should-have-letter".into()
                ]
            )
        );
        // a (dot 1) read as c (dots 1, 4): nothing missing, dot 4 extra. "abcn" spells no word.
        assert_eq!(
            readback("abandon", "abcn"),
            (
                None,
                None,
                vec![
                    ok.clone(),
                    ok.clone(),
                    "wrong missing  extra 4".into(),
                    ok.clone()
                ]
            )
        );
        // e (dots 1, 5) read as t (dots 2-3-4-5): dot 1 missing, dots 2, 3 and 4 extra.
        assert_eq!(
            readback("metal", "MTTA"),
            (
                None,
                None,
                vec![
                    ok.clone(),
                    "wrong missing 1 extra 234".into(),
                    ok.clone(),
                    ok
                ]
            )
        );
    }

    // Every mirror flip in faces 1-4 gives exactly one MirrorMisread, at that face; the flipped
    // faces spell another word for exactly the 279 words the docs count (braille.json
    // flip_neighbours).
    #[test]
    fn every_mirror_flip_is_one_mirror_misread_and_names_the_279() {
        let doc = braille_json();
        let words = array(&doc["words"]);
        let mut naming = 0;
        for (index, w) in (0u16..).zip(list()) {
            let key = &w.as_bytes()[..w.len().min(READBACK_FACES)];
            let mut neighbours: Vec<(usize, String)> = Vec::new();
            for face in 0..key.len() {
                let Some(partner) = mirror_partner(key[face]) else {
                    continue;
                };
                let mut typed = key.to_vec();
                typed[face] = partner;
                let typed = String::from_utf8(typed).expect("ASCII");
                match compare_readback(index, &typed) {
                    Ok(ReadbackResult::Mismatch(m)) => {
                        let verdicts: Vec<String> = m.faces().iter().map(verdict_text).collect();
                        for (i, v) in verdicts.iter().enumerate() {
                            let want = if i == face { "mirror" } else { "ok" };
                            assert_eq!(v, want, "{w} read as {typed}");
                        }
                        if let Some(spelled) = m.spelled_word() {
                            assert_ne!(spelled, *w);
                            neighbours.push((face + 1, spelled.to_owned()));
                        }
                    }
                    _ => panic!("{w} read as {typed} must be a mismatch"),
                }
            }
            let from_json: Vec<(usize, String)> =
                array(&words[usize::from(index)]["flip_neighbours"])
                    .iter()
                    .map(|pair| {
                        let face = pair[0].as_u64().expect("a face");
                        (
                            usize::try_from(face).expect("a face"),
                            text(&pair[1]).to_owned(),
                        )
                    })
                    .collect();
            assert_eq!(neighbours, from_json, "{w}");
            if !neighbours.is_empty() {
                naming += 1;
            }
        }
        assert_eq!(naming, 279);
        assert_eq!(doc["counts"]["mirror_flip_words"], 279);
    }

    // Every blank-face slip in faces 1-4 is caught, with the exact verdict per face (tasks/todo.md,
    // M1 Verification): each three-letter word read with any fourth letter a-z gives ok, ok, ok,
    // should-be-blank, and each longer word read as its first three letters gives ok, ok, ok,
    // should-have-letter (review fix after commit 15).
    #[test]
    fn every_blank_face_slip_is_caught() {
        let ok = String::from("ok");
        let (mut short, mut long) = (0, 0);
        for w in list() {
            if w.len() == 3 {
                for fourth in b'a'..=b'z' {
                    let typed = format!("{w}{}", char::from(fourth));
                    let want = [ok.clone(), ok.clone(), ok.clone(), "should-be-blank".into()];
                    assert_eq!(readback(w, &typed).2, want, "{w} read as {typed}");
                    short += 1;
                }
            } else {
                let want = [
                    ok.clone(),
                    ok.clone(),
                    ok.clone(),
                    "should-have-letter".into(),
                ];
                assert_eq!(readback(w, &w[..3]).2, want, "{w} read as {}", &w[..3]);
                long += 1;
            }
        }
        assert_eq!((short, long), (103 * 26, 1945));
    }

    // The 49 short words that begin longer words (braille.json prefix_of): neither reading of a
    // prefix pair ever matches, because a blank face counts.
    #[test]
    fn prefix_neighbours_never_match_and_49_short_words() {
        let doc = braille_json();
        let words = array(&doc["words"]);
        let mut short = 0;
        for (index, w) in (0u16..).zip(list()) {
            let longer: Vec<&str> = list()
                .iter()
                .copied()
                .filter(|o| o.len() > w.len() && o.starts_with(w))
                .collect();
            let from_json: Vec<&str> = array(&words[usize::from(index)]["prefix_of"])
                .iter()
                .map(text)
                .collect();
            assert_eq!(longer, from_json, "{w}");
            if longer.is_empty() {
                continue;
            }
            short += 1;
            assert_eq!(w.len(), 3, "only a three-letter word can begin another");
            for other in longer {
                let other_key = &other[..READBACK_FACES];
                assert!(matches!(
                    compare_readback(index, other_key),
                    Ok(ReadbackResult::Mismatch(_))
                ));
                assert!(matches!(
                    compare_readback(index_of(other), w),
                    Ok(ReadbackResult::Mismatch(_))
                ));
            }
        }
        assert_eq!(short, 49);
        assert_eq!(doc["counts"]["short_prefix_words"], 49);
    }

    // 2,048 distinct first-four keys (a blank counts), and each key finds its own word.
    #[test]
    fn readback_keys_are_distinct_and_find_their_word() {
        let mut keys: Vec<[Option<u8>; READBACK_FACES]> =
            list().iter().map(|w| readback_key(w)).collect();
        for (index, key) in (0u16..).zip(&keys) {
            assert_eq!(word_with_key(key), Some(index));
        }
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), 2048);
        assert_eq!(
            word_with_key(&[Some(b'a'), Some(b'b'), Some(b'c'), None]),
            None
        );
        assert_eq!(
            word_with_key(&[Some(b'z'), Some(b'z'), Some(b'z'), Some(b'z')]),
            None
        );
        assert_eq!(
            word_with_key(&[Some(b'a'), Some(b'a'), Some(b'a'), Some(b'a')]),
            None
        );
    }

    #[test]
    fn malformed_readback_input() {
        for typed in [
            "", "ab", "abcde", "ab1d", "ab d", "ab\u{e7}", "a\u{e9}c", "abc\n", " abc", "a-cd",
        ] {
            assert!(
                matches!(
                    compare_readback(0, typed),
                    Err(CoreError::Braille(BrailleError::MalformedReadback))
                ),
                "{typed:?}"
            );
        }
    }

    // The session's read-back entry point checks the position first.
    #[test]
    fn inserts_readback_checks_the_position() {
        let indices: Vec<u16> = (0..12).collect();
        let m = mnemonic(&indices);
        let inserts = BrailleInserts::new(&m);
        assert!(matches!(
            inserts.readback(1, "aban"),
            Ok(ReadbackResult::Match)
        ));
        assert!(matches!(
            inserts.readback(2, "aban"),
            Ok(ReadbackResult::Mismatch(_))
        ));
        for position in [0, 13] {
            assert!(matches!(
                inserts.readback(position, "aban"),
                Err(CoreError::Braille(BrailleError::BadPosition))
            ));
        }
        assert!(matches!(
            inserts.readback(1, "ab"),
            Err(CoreError::Braille(BrailleError::MalformedReadback))
        ));
    }

    // The read-back result wipes itself (CLAUDE.md rule 5; review fix after commit 15).
    const fn zeroize_on_drop<T: ZeroizeOnDrop>() {}
    const _: () = {
        zeroize_on_drop::<ReadbackMismatch>();
        zeroize_on_drop::<Dots>();
    };

    // White box: zeroizing a mismatch forgets the spelled word and turns every verdict, the
    // variant included, into Ok; zeroizing dots clears them.
    #[test]
    fn a_mismatch_zeroizes_every_field() {
        let mut mismatch = ReadbackMismatch {
            spelled: Some(index_of("accident")),
            faces: [
                FaceVerdict::MirrorMisread,
                FaceVerdict::ShouldBeBlank,
                FaceVerdict::ShouldHaveLetter,
                FaceVerdict::WrongLetter {
                    missing: Dots { bits: 0x3f },
                    extra: Dots { bits: 0x01 },
                },
            ],
        };
        assert_eq!(mismatch.spelled_word(), Some("accident"));
        mismatch.zeroize();
        assert_eq!(mismatch.spelled_word(), None);
        assert_eq!(mismatch.spelled_seedbook_number(), None);
        assert!(mismatch.faces().iter().all(FaceVerdict::is_ok));
        let mut dots = Dots { bits: 0x3f };
        dots.zeroize();
        assert_eq!(dots.bits(), 0);
    }

    #[test]
    fn dots_and_mirror_images() {
        let e = Dots {
            bits: letter_cell(b'e').1,
        };
        let raised: Vec<u8> = (0..=7).filter(|&d| e.is_raised(d)).collect();
        assert_eq!(raised, [1, 5]);
        assert_eq!(mirrored(letter_cell(b'e').1), letter_cell(b'i').1);
        assert_eq!(mirrored(mirrored(0x2d)), 0x2d);
        let letters: Vec<u8> = (b'a'..=b'z')
            .filter(|&l| mirror_partner(l).is_some())
            .collect();
        assert_eq!(letters, b"defhijrw");
    }
}
