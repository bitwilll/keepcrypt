// keepcrypt-capi's tests run each case in a child process: only keepcrypt-ffi's own tests may join.
let joined = std::thread::spawn(|| case_on_a_fresh_slot()).join();
