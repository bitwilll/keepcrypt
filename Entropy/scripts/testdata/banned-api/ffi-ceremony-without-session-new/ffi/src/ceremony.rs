pub fn restart(kept: &Wiped, len: Length, mode: Mode) -> Result<Session<Collecting>, CoreError> {
    kept.restart(len, mode)
}
