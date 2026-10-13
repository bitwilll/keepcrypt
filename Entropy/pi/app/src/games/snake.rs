//! Snake (tasks/todo.md, M3 group 10; docs/pi-firmware.md "Buttons"): an 18×18 board of 12 px
//! cells, one cell a tick, steered with the joystick.
//!
//! - A round starts with the snake three cells long in the middle row, heading right, and one
//!   food. Each `step` moves the head one cell; eating the food makes the snake one cell longer,
//!   and new food is placed.
//! - Hitting the wall or the snake's own body ends the round, and the board stays as it was. A
//!   head may move into the cell the tail leaves. A steer back into the snake's neck is ignored.
//! - Food is placed by rejection sampling over the free cells (`place_food`): a byte below 252
//!   (14 × 18) gives a coordinate, its value mod 18, row first, then column; a byte of 252 or more
//!   is skipped, and a cell the snake holds is drawn again. So every free cell is equally likely.
//!   The bytes come from the source the caller hands in, `GAME_BYTES` in the app, which only the
//!   games draw from. A board with no free cell gets no food, and the round ends.
//! - The board is kept as the screen model draws it (`board`), row by row.

use std::collections::VecDeque;

use keepcrypt_core::CoreError;

use super::GameBytes;
use crate::input::Key;
use crate::screen::{BOARD_CELLS, Tile};

/// Bytes below this give a coordinate (the largest multiple of 18 up to 256); the rest are
/// skipped, so every coordinate is equally likely.
const ACCEPTED_BELOW: usize = 256 / BOARD_CELLS * BOARD_CELLS;
/// Bytes drawn from the source at a time while food is placed.
const DRAW: usize = 16;
/// The row a round starts in, and the column of the head; the snake is three cells long.
const START_ROW: usize = BOARD_CELLS / 2;
const START_HEAD: usize = 5;
const START_LENGTH: usize = 3;

/// Where the snake heads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Heading {
    Up,
    Down,
    Left,
    Right,
}

impl Heading {
    fn reverse(self) -> Heading {
        match self {
            Heading::Up => Heading::Down,
            Heading::Down => Heading::Up,
            Heading::Left => Heading::Right,
            Heading::Right => Heading::Left,
        }
    }
}

/// One round of Snake: the board, the snake's cells and where it heads. It holds nothing else.
pub struct Snake {
    board: [[Tile; BOARD_CELLS]; BOARD_CELLS],
    /// The snake's cells as (row, column), tail first, head last.
    body: VecDeque<(usize, usize)>,
    head: (usize, usize),
    heading: Heading,
    /// The heading the next step takes.
    turn: Heading,
    over: bool,
}

impl Snake {
    /// A new round, its first food placed with bytes from `source`.
    pub fn new(source: GameBytes) -> Result<Snake, CoreError> {
        Snake::new_with(source.0)
    }

    /// `new`, with its bytes from `bytes`.
    fn new_with(
        mut bytes: impl FnMut(&mut [u8]) -> Result<(), CoreError>,
    ) -> Result<Snake, CoreError> {
        let mut snake = Snake {
            board: [[Tile::Empty; BOARD_CELLS]; BOARD_CELLS],
            body: VecDeque::with_capacity(BOARD_CELLS * BOARD_CELLS),
            head: (START_ROW, START_HEAD),
            heading: Heading::Right,
            turn: Heading::Right,
            over: false,
        };
        for column in START_HEAD + 1 - START_LENGTH..=START_HEAD {
            snake.body.push_back((START_ROW, column));
            snake.board[START_ROW][column] = Tile::Snake;
        }
        snake.place_food(&mut bytes)?;
        Ok(snake)
    }

    /// The board, row by row, as the screen draws it.
    pub fn board(&self) -> &[[Tile; BOARD_CELLS]; BOARD_CELLS] {
        &self.board
    }

    /// True once the round has ended.
    pub fn over(&self) -> bool {
        self.over
    }

    /// The joystick steers the next step: Up, Down, Left or Right, unless it points back into the
    /// snake's neck. Any other key does nothing.
    pub fn steer(&mut self, key: Key) {
        let turn = match key {
            Key::Up => Heading::Up,
            Key::Down => Heading::Down,
            Key::Left => Heading::Left,
            Key::Right => Heading::Right,
            Key::Press | Key::Key1 | Key::Key2 | Key::Key3 => return,
        };
        if turn != self.heading.reverse() {
            self.turn = turn;
        }
    }

    /// One cell on: the head moves, the tail follows unless the food was eaten, and new food is
    /// placed with bytes from `source`. A wall or the body ends the round instead. Nothing moves
    /// once the round has ended.
    pub fn step(&mut self, source: GameBytes) -> Result<(), CoreError> {
        self.step_with(source.0)
    }

    /// `step`, with its bytes from `bytes`.
    fn step_with(
        &mut self,
        mut bytes: impl FnMut(&mut [u8]) -> Result<(), CoreError>,
    ) -> Result<(), CoreError> {
        if self.over {
            return Ok(());
        }
        self.heading = self.turn;
        let (row, column) = self.head;
        let next = match self.heading {
            Heading::Up => row.checked_sub(1).map(|row| (row, column)),
            Heading::Down => (row + 1 < BOARD_CELLS).then_some((row + 1, column)),
            Heading::Left => column.checked_sub(1).map(|column| (row, column)),
            Heading::Right => (column + 1 < BOARD_CELLS).then_some((row, column + 1)),
        };
        let Some((row, column)) = next else {
            // The wall.
            self.over = true;
            return Ok(());
        };
        let eats = self.board[row][column] == Tile::Food;
        let tail = self.body.front().copied();
        if self.board[row][column] == Tile::Snake && tail != Some((row, column)) {
            // The body, other than the tail that moves away.
            self.over = true;
            return Ok(());
        }
        if !eats && let Some((tail_row, tail_column)) = self.body.pop_front() {
            self.board[tail_row][tail_column] = Tile::Empty;
        }
        self.body.push_back((row, column));
        self.board[row][column] = Tile::Snake;
        self.head = (row, column);
        if eats {
            self.place_food(&mut bytes)?;
        }
        Ok(())
    }

    /// Places food on a free cell by rejection sampling over `bytes` (the module docs), or ends
    /// the round when no cell is free.
    fn place_food(
        &mut self,
        bytes: &mut impl FnMut(&mut [u8]) -> Result<(), CoreError>,
    ) -> Result<(), CoreError> {
        if self.body.len() >= BOARD_CELLS * BOARD_CELLS {
            self.over = true;
            return Ok(());
        }
        let mut drawn = [0u8; DRAW];
        // A row waiting for its column.
        let mut row = None;
        loop {
            bytes(&mut drawn)?;
            for &byte in &drawn {
                let value = usize::from(byte);
                if value >= ACCEPTED_BELOW {
                    continue;
                }
                let coordinate = value % BOARD_CELLS;
                match row.take() {
                    None => row = Some(coordinate),
                    Some(row) => {
                        if self.board[row][coordinate] == Tile::Empty {
                            self.board[row][coordinate] = Tile::Food;
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use keepcrypt_core::SourceFault;

    use super::*;

    /// A source that serves `list`, then fills the rest of that draw with 255 (always skipped);
    /// a later draw fails the test.
    fn fixed(list: &[u8]) -> impl FnMut(&mut [u8]) -> Result<(), CoreError> + '_ {
        let mut served = false;
        move |buf: &mut [u8]| {
            assert!(!served, "only one draw of fixed bytes");
            served = true;
            assert!(list.len() <= buf.len());
            buf.fill(255);
            buf[..list.len()].copy_from_slice(list);
            Ok(())
        }
    }

    /// The cells holding `tile`.
    fn cells(snake: &Snake, tile: Tile) -> Vec<(usize, usize)> {
        let mut found = Vec::new();
        for (row, tiles) in snake.board.iter().enumerate() {
            for (column, &here) in tiles.iter().enumerate() {
                if here == tile {
                    found.push((row, column));
                }
            }
        }
        found
    }

    /// A snake laid on these cells, tail first, heading `heading`, with no food.
    fn laid(body: &[(usize, usize)], heading: Heading) -> Snake {
        let mut snake = Snake {
            board: [[Tile::Empty; BOARD_CELLS]; BOARD_CELLS],
            body: body.iter().copied().collect(),
            head: *body.last().expect("a body"),
            heading,
            turn: heading,
            over: false,
        };
        for &(row, column) in body {
            snake.board[row][column] = Tile::Snake;
        }
        snake
    }

    #[test]
    fn a_round_starts_three_cells_long_in_the_middle_row_with_one_food() {
        let snake = Snake::new_with(fixed(&[0, 0])).expect("a round");
        assert_eq!(cells(&snake, Tile::Snake), [(9, 3), (9, 4), (9, 5)]);
        assert_eq!(cells(&snake, Tile::Food), [(0, 0)]);
        assert_eq!(snake.head, (9, 5));
        assert!(!snake.over());
    }

    #[test]
    fn ten_thousand_placements_land_on_free_cells() {
        // Boards whose first n cells, row by row, are the snake: from 1 to 320 of the 324. Each
        // placement is offered every cell once, from a cell of its own on, each cell as 4 bytes: a
        // skipped byte, the row and the column as one of their 14 accepted values (the coordinate
        // plus a multiple of 18), and another skipped byte. (A counting stream would not do: its
        // pairs of consecutive bytes reach only a few cells.)
        let all: Vec<(usize, usize)> = (0..BOARD_CELLS)
            .flat_map(|row| (0..BOARD_CELLS).map(move |column| (row, column)))
            .collect();
        let byte = |coordinate: usize, lap: usize| {
            u8::try_from(coordinate + BOARD_CELLS * (lap % 14)).expect("below 252")
        };
        for placement in 0..10_000 {
            let taken = 1 + placement % 320;
            let mut snake = laid(&all[..taken], Heading::Right);
            let mut cell = placement;
            let mut walk = |buf: &mut [u8]| {
                for four in buf.chunks_mut(4) {
                    let (row, column) = all[cell % all.len()];
                    let skipped = u8::try_from(252 + cell % 4).expect("a byte");
                    four.copy_from_slice(&[
                        skipped,
                        byte(row, placement),
                        byte(column, placement / 14),
                        255,
                    ]);
                    cell += 1;
                }
                assert!(cell < placement + 2 * all.len(), "a free cell is found");
                Ok(())
            };
            snake.place_food(&mut walk).expect("placed");
            let food = cells(&snake, Tile::Food);
            assert_eq!(food.len(), 1, "one food");
            assert!(!all[..taken].contains(&food[0]), "on a free cell");
            // The first free cell offered: every skipped byte and taken cell was passed over.
            let first_free = (placement..)
                .map(|cell| all[cell % all.len()])
                .find(|cell| !all[..taken].contains(cell));
            assert_eq!(Some(food[0]), first_free);
            assert_eq!(cells(&snake, Tile::Snake).len(), taken);
            assert!(!snake.over());
        }
    }

    #[test]
    fn rejection_skips_out_of_range_bytes_and_taken_cells() {
        // 252 and 255 are skipped; 251 is 17 (251 mod 18).
        let snake = Snake::new_with(fixed(&[252, 3, 255, 251])).expect("a round");
        assert_eq!(cells(&snake, Tile::Food), [(3, 17)]);
        // (9, 4) is the snake's: drawn again.
        let snake = Snake::new_with(fixed(&[9, 4, 2, 2])).expect("a round");
        assert_eq!(cells(&snake, Tile::Food), [(2, 2)]);
        // A board with no free cell gets no food, and the round ends.
        let all: Vec<(usize, usize)> = (0..BOARD_CELLS)
            .flat_map(|row| (0..BOARD_CELLS).map(move |column| (row, column)))
            .collect();
        let mut full = laid(&all, Heading::Right);
        full.place_food(&mut fixed(&[])).expect("no draw");
        assert!(full.over());
        assert!(cells(&full, Tile::Food).is_empty());
    }

    #[test]
    fn the_snake_grows_on_food_and_new_food_is_placed() {
        // The first food right in front of the head; the next one at (0, 0).
        let mut snake = Snake::new_with(fixed(&[9, 6])).expect("a round");
        snake.step_with(fixed(&[0, 0])).expect("a step");
        assert_eq!(cells(&snake, Tile::Snake), [(9, 3), (9, 4), (9, 5), (9, 6)]);
        assert_eq!(cells(&snake, Tile::Food), [(0, 0)]);
        // Without food it keeps its length.
        snake.step_with(fixed(&[])).expect("a step");
        assert_eq!(cells(&snake, Tile::Snake), [(9, 4), (9, 5), (9, 6), (9, 7)]);
    }

    #[test]
    fn a_wall_ends_the_round_and_the_board_stays() {
        let mut snake = Snake::new_with(fixed(&[0, 0])).expect("a round");
        // From column 5 to column 17, the last before the wall.
        for _ in 0..12 {
            snake.step_with(fixed(&[])).expect("a step");
        }
        assert!(!snake.over());
        let board = *snake.board();
        snake.step_with(fixed(&[])).expect("a step");
        assert!(snake.over());
        assert_eq!(*snake.board(), board);
        // Once over, nothing moves.
        snake.steer(Key::Up);
        snake.step_with(fixed(&[])).expect("no step");
        assert_eq!(*snake.board(), board);
    }

    #[test]
    fn the_body_ends_the_round_but_the_tail_moves_away() {
        // Five cells along row 9, then up, left and down into the body.
        let mut snake = laid(&[(9, 3), (9, 4), (9, 5), (9, 6), (9, 7)], Heading::Right);
        for key in [Key::Up, Key::Left, Key::Down] {
            assert!(!snake.over());
            snake.steer(key);
            snake.step_with(fixed(&[])).expect("a step");
        }
        assert!(snake.over());
        assert_eq!(snake.head, (8, 6));
        // Four cells in a square: the head moves into the cell the tail leaves.
        let mut square = laid(&[(9, 5), (9, 6), (8, 6), (8, 5)], Heading::Left);
        square.steer(Key::Down);
        square.step_with(fixed(&[])).expect("a step");
        assert!(!square.over());
        assert_eq!(square.head, (9, 5));
        assert_eq!(cells(&square, Tile::Snake).len(), 4);
    }

    #[test]
    fn a_steer_into_the_neck_and_the_other_keys_are_ignored() {
        let mut snake = Snake::new_with(fixed(&[0, 0])).expect("a round");
        for key in [Key::Left, Key::Press, Key::Key1, Key::Key2, Key::Key3] {
            snake.steer(key);
        }
        snake.step_with(fixed(&[])).expect("a step");
        assert_eq!(snake.head, (9, 6));
        snake.steer(Key::Down);
        snake.step_with(fixed(&[])).expect("a step");
        assert_eq!(snake.head, (10, 6));
    }

    #[test]
    fn a_source_error_is_passed_on() {
        fn no_bytes(_: &mut [u8]) -> Result<(), CoreError> {
            Err(CoreError::Source(SourceFault::Os))
        }
        let failing = GameBytes(no_bytes);
        assert!(matches!(
            Snake::new(failing),
            Err(CoreError::Source(SourceFault::Os))
        ));
        let mut snake = Snake::new_with(fixed(&[9, 6])).expect("a round");
        assert!(matches!(
            snake.step(failing),
            Err(CoreError::Source(SourceFault::Os))
        ));
    }
}
