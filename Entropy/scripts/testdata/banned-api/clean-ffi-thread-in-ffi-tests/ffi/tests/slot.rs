// keepcrypt-ffi's integration tests may join a thread (lead decision M5-8): the barrier holds a long
// call while another thread discards.
std::thread::scope(|scope| {
    let held: std::thread::ScopedJoinHandle<'_, Reply<Observed>> = scope.spawn(|| slot.hold(work));
    let joined = std::thread::spawn(|| start()).join();
});
