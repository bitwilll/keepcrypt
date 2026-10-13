// Outside the games, the app names the session and the pool's inputs: the ceremony loop
// forwards each press to Session::add_extra, and the hwrng's blocks to add_hw_samples.
let since = Instant::now();
// Longer names around the constructor's are other calls.
let replay = ReplaySession::new(log);
let checks = Session::new_checks();
