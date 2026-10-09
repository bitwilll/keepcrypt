// The source module in its file layout may call getrandom too (a real crate uses one layout).
getrandom::fill(&mut buf)?;
// Only here may core name /dev/urandom, /dev/random, getentropy, CCRandomGenerateBytes or BCryptGenRandom.
let mut dev = File::open("/dev/urandom")?;
