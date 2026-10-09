// icon.png is never scanned (binary extension), yet rustc compiles it as Rust.
#[path = "icon.png"]
mod hidden;
