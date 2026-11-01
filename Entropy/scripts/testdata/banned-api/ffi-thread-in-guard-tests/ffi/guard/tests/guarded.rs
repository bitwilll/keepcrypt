let worker = std::thread::spawn(move || guarded(op, input));
