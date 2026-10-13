//! It draws `game_random` (the games' own read) too.
    // A game's draw: its own OS read, with no session and no pool.
    game_random(&mut game_bytes).map_err(|_| 20)
