//! The entry grids (docs/pi-firmware.md "Buttons"; tasks/todo.md, M3 Q32 (a)): the symbols a
//! joystick types, laid out row by row, and the pure gate functions that decide what a grid
//! accepts next.
//!
//! - The go-ahead code: the 32 Crockford symbols in 8 columns and 4 rows.
//! - Read-back and backup-passphrase words: a-z, then "blank" (`BLANK`, a fourth face left
//!   unpunched), in 7 columns and 4 rows; the last cell is empty.
//! - The BIP39 passphrase: printable ASCII, 0x20 to 0x7E, in 8 columns and 12 rows, shown as
//!   three pages of 4 rows, the page that holds the cursor; the last cell is empty (Q32 (c)).
//! - The cursor moves with wrap within its row and its column, so moving down from the last row
//!   of a page shows the next page.
//! - A letters entry is 3 or 4 faces as punched: three letters and a blank fourth face, or four
//!   letters. A blank is accepted only as the fourth face (every word has three letters or more),
//!   and done is offered at 3 or 4 letters, so core never sees an entry it would refuse as
//!   malformed.

use crate::input::Key;
use crate::screen::ScreenId;

/// A fourth face read as blank, on the letters grid. Never sent to core: an entry is its letters.
pub const BLANK: u8 = b'_';
/// The letters grid's symbols.
const LETTERS: &[u8; 27] = b"abcdefghijklmnopqrstuvwxyz_";
/// The go-ahead code's symbols (Crockford base32).
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Printable ASCII, 0x20 to 0x7E, in code order.
const ASCII: &[u8; 95] = b" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
/// Rows on one page of a grid.
pub const PAGE_ROWS: usize = 4;
/// The faces a read-back entry covers.
pub const FACES: usize = 4;
/// The go-ahead code's length, without its dash.
pub const CODE_LEN: usize = 8;
/// The longest BIP39 passphrase the Pi takes (Q32 (c)).
pub const MAX_PASSPHRASE: usize = 100;
/// The backup passphrase's words.
pub const ENTRIES: usize = 8;
/// Eight entries of up to 4 faces, a space between entries: the longest backup-passphrase entry.
pub const ENTRIES_LEN: usize = ENTRIES * FACES + ENTRIES - 1;

/// One of the three grids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grid {
    Code,
    Letters,
    Ascii,
}

impl Grid {
    /// The grid an entry screen types on, or `None` for a screen that is no entry grid.
    pub fn of(id: ScreenId) -> Option<Grid> {
        match id {
            ScreenId::CodeEntry => Some(Grid::Code),
            ScreenId::ReadbackEntry | ScreenId::BackupCheckEntry => Some(Grid::Letters),
            ScreenId::Bip39Entry => Some(Grid::Ascii),
            _ => None,
        }
    }

    /// The symbols, row by row.
    pub fn symbols(self) -> &'static [u8] {
        match self {
            Grid::Code => CROCKFORD,
            Grid::Letters => LETTERS,
            Grid::Ascii => ASCII,
        }
    }

    pub fn columns(self) -> usize {
        match self {
            Grid::Code | Grid::Ascii => 8,
            Grid::Letters => 7,
        }
    }

    /// Every row, on every page.
    pub fn rows(self) -> usize {
        self.symbols().len().div_ceil(self.columns())
    }

    /// The symbol under `cursor`, or `None` on an empty cell.
    pub fn symbol(self, cursor: usize) -> Option<u8> {
        self.symbols().get(cursor).copied()
    }

    /// The cursor after `key`, or `None` for a key that does not move it. Moves wrap within the
    /// row or the column.
    pub fn moved(self, cursor: usize, key: Key) -> Option<usize> {
        let (columns, rows) = (self.columns(), self.rows());
        let (row, column) = (cursor / columns, cursor % columns);
        let (row, column) = match key {
            Key::Up => ((row + rows - 1) % rows, column),
            Key::Down => ((row + 1) % rows, column),
            Key::Left => (row, (column + columns - 1) % columns),
            Key::Right => (row, (column + 1) % columns),
            Key::Press | Key::Key1 | Key::Key2 | Key::Key3 => return None,
        };
        Some(row * columns + column)
    }
}

/// The letters of a letters entry: its faces without a blank.
pub fn letters(entry: &str) -> &str {
    entry.trim_end_matches(char::from(BLANK))
}

/// True when the letters entry `entry` takes `symbol` next: a letter while fewer than 4 faces are
/// typed and none is blank, a blank only as the fourth face.
pub fn face_accepted(entry: &str, symbol: u8) -> bool {
    let faces = entry.len();
    if entry.bytes().any(|b| b == BLANK) {
        return false;
    }
    match symbol {
        BLANK => faces == FACES - 1,
        _ => faces < FACES,
    }
}

/// True when a letters entry is complete: 3 or 4 letters, the fourth face blank or not.
pub fn entry_done(entry: &str) -> bool {
    (FACES - 1..=FACES).contains(&letters(entry).len())
}

/// The entry being typed on the backup-passphrase grid: the text after the last space.
pub fn current_entry(typed: &str) -> &str {
    match typed.rsplit_once(' ') {
        Some((_, current)) => current,
        None => typed,
    }
}

/// The number of the entry being typed, from 1.
pub fn entry_number(typed: &str) -> usize {
    typed.bytes().filter(|&b| b == b' ').count() + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_grids_are_q32s() {
        assert_eq!(Grid::Code.symbols(), b"0123456789ABCDEFGHJKMNPQRSTVWXYZ");
        assert_eq!((Grid::Code.columns(), Grid::Code.rows()), (8, 4));
        assert_eq!((Grid::Letters.columns(), Grid::Letters.rows()), (7, 4));
        assert_eq!((Grid::Ascii.columns(), Grid::Ascii.rows()), (8, 12));
        let printable: Vec<u8> = (0x20..=0x7e).collect();
        assert_eq!(Grid::Ascii.symbols(), &printable[..]);
        let letters: Vec<u8> = (b'a'..=b'z').chain([BLANK]).collect();
        assert_eq!(Grid::Letters.symbols(), &letters[..]);
        // The last cell of the letters and ASCII grids is empty.
        assert_eq!(Grid::Letters.symbol(26), Some(BLANK));
        assert_eq!(Grid::Letters.symbol(27), None);
        assert_eq!(Grid::Ascii.symbol(94), Some(b'~'));
        assert_eq!(Grid::Ascii.symbol(95), None);
        for (id, grid) in [
            (ScreenId::CodeEntry, Grid::Code),
            (ScreenId::ReadbackEntry, Grid::Letters),
            (ScreenId::BackupCheckEntry, Grid::Letters),
            (ScreenId::Bip39Entry, Grid::Ascii),
        ] {
            assert_eq!(Grid::of(id), Some(grid));
        }
        assert_eq!(
            ScreenId::ALL
                .into_iter()
                .filter(|&id| Grid::of(id).is_some())
                .count(),
            4
        );
    }

    #[test]
    fn moves_wrap_within_the_row_and_the_column_and_other_keys_do_not_move() {
        let code = Grid::Code;
        assert_eq!(code.moved(0, Key::Right), Some(1));
        assert_eq!(code.moved(7, Key::Right), Some(0));
        assert_eq!(code.moved(0, Key::Left), Some(7));
        assert_eq!(code.moved(0, Key::Down), Some(8));
        assert_eq!(code.moved(0, Key::Up), Some(24));
        assert_eq!(code.moved(31, Key::Down), Some(7));
        for key in [Key::Press, Key::Key1, Key::Key2, Key::Key3] {
            assert_eq!(code.moved(5, key), None);
        }
        let down_right = code
            .moved(0, Key::Down)
            .and_then(|c| code.moved(c, Key::Right));
        assert_eq!(down_right.and_then(|c| code.symbol(c)), Some(b'9'));
        // Letters: 7 columns; the empty cell is reachable and types nothing.
        assert_eq!(Grid::Letters.moved(6, Key::Right), Some(0));
        assert_eq!(Grid::Letters.moved(20, Key::Down), Some(27));
        assert_eq!(Grid::Letters.moved(27, Key::Down), Some(6));
        // ASCII: down from a page's last row is the next page's first; up from the first row
        // wraps to the third page's last.
        assert_eq!(Grid::Ascii.moved(24, Key::Down), Some(32));
        assert_eq!(Grid::Ascii.moved(1, Key::Up), Some(89));
        assert_eq!(Grid::Ascii.symbol(89), Some(b'y'));
    }

    #[test]
    fn a_letters_entry_takes_four_faces_and_a_blank_only_fourth() {
        assert!(face_accepted("", b'a'));
        assert!(!face_accepted("", BLANK));
        assert!(!face_accepted("ta", BLANK));
        assert!(face_accepted("tap", BLANK));
        assert!(face_accepted("tap", b'e'));
        assert!(!face_accepted("tape", b'x'));
        assert!(!face_accepted("tape", BLANK));
        assert!(!face_accepted("tag_", b'a'));
        assert!(!entry_done("ta"));
        assert!(entry_done("tag"));
        assert!(entry_done("tag_"));
        assert!(entry_done("tape"));
        assert_eq!(letters("tag_"), "tag");
        assert_eq!(letters("tape"), "tape");
    }

    #[test]
    fn the_current_entry_is_after_the_last_space() {
        assert_eq!(current_entry(""), "");
        assert_eq!(current_entry("fly_"), "fly_");
        assert_eq!(current_entry("fly_ fa"), "fa");
        assert_eq!(current_entry("fly_ fanc "), "");
        assert_eq!(entry_number(""), 1);
        assert_eq!(entry_number("fly_ fanc "), 3);
        // Eight entries of four faces and seven spaces fill the buffer exactly.
        let full = ["abcd"; ENTRIES].join(" ");
        assert_eq!(full.len(), ENTRIES_LEN);
        assert_eq!(entry_number(&full), ENTRIES);
    }
}
