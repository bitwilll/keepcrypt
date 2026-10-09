// Core outside core/src/source reads the OS RNG only through the source module.
let mut dev = std::fs::File::open("/dev/urandom")?;
