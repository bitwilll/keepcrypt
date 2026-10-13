// Outside the games, the app names the session and the pool's inputs: the ceremony loop
// forwards each press to Session::add_extra, and the hwrng's blocks to add_hw_samples.
let since = Instant::now();
// Longer names around the constructor's are other calls.
let replay = ReplaySession::new(log);
let checks = Session::new_checks();
let state_checks = Session::<Collecting>::new_checks();
// A session's type before another call, or beside one, is no call of it.
let boxed: Box<Session<Collecting>> = Box::new(session);
let typed: Session<Collecting> = Box::<u8>::new(x);
let pair = (Session::<Collecting>::checks(), Vec::<u8>::new());
fn restart(kept: &Wiped) -> Result<Session<Collecting>, CoreError> { Wrapper::new() }
