// The device module opens the hwrng by its paths.rs constant (the Device category).
let mut hw = File::open(paths::HWRNG)?;
