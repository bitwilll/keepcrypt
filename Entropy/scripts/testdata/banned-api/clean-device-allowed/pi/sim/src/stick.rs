// The simulator is not the firmware: its fake stick is files, threads and buffers on the host.
let dir = std::path::Path::new("/tmp/kc-sim-stick");
std::fs::write(dir.join("seed.age"), bytes)?;
let reader = std::io::BufReader::new(File::open(path)?);
let ticker = std::thread::spawn(move || tick());
