/// The twin that only clippy compiles.
#[cfg(clippy)]
pub fn show(words: &str) -> String {
    words.to_owned()
}
