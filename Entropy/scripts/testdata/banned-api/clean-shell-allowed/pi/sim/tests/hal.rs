// pi/sim may start sessions of its own, and names the game call only as words: game random.
Session::new(SeedLength::Words12, Mode::Mixed, Platform::Pi).expect("a session");
