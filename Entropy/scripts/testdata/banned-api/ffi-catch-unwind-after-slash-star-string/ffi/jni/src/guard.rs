const PATTERN: &str = "/*";
pub fn g() -> bool { std::panic::catch_unwind(|| ()).is_ok() }
