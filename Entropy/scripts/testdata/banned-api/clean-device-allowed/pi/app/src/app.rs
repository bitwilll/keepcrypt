// The app reaches the stick through the HAL, with no file API, path or hardware crate of its own.
let names = self.hal.list()?;
let now = self.hal.now_ns();
