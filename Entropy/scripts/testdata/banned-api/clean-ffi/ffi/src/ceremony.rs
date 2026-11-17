/// The one constructor call; a kept Wiped restarts instead (app.rs's rule).
pub fn start(held: &mut Held, len: Length, mode: Mode) -> Result<Session<Collecting>, CoreError> {
    match held.kept.as_ref() {
        Some(kept) => kept.restart(len, mode),
        None => Session::new(len, mode, Platform::Phone),
    }
}
