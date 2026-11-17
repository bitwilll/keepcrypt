fn guarded(f: fn() -> u8) -> u8 { std::panic::catch_unwind(f).map_err(halt).into_ok() }
