pub fn again(f: fn() -> u8) -> bool { std::panic::catch_unwind(f).is_ok() }
