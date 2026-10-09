// Rule 5: secrets are never printed, not even through a device file.
pub fn leak(words: &str) -> std::io::Result<()> {
    std::fs::write("/dev/stderr", words)
}
