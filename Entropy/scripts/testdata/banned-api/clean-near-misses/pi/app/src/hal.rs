// hal::HwRng reads the raw hardware RNG for the health tests; it is not the kernel CSPRNG.
let mut hw = File::open("/dev/hwrng")?;
