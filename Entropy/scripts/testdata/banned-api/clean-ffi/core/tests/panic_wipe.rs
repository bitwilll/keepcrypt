// core's own test joins a thread to observe a panic; the FFI rules cover ffi/ only.
let joined = thread::spawn(move || session.panic_now()).join();
let session = Session::new(Length::Words12, Mode::Mixed, Platform::Phone)?;
