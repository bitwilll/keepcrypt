const PATTERN: &str = r#"/* "quoted" "#;
pub fn g() -> bool { std::panic::catch_unwind(|| ()).is_ok() }
