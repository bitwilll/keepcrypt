//! The object fixtures of `scripts/banned-api-check.sh --selftest` (tasks/todo.md, M1 group 11):
//! one #![no_std] source that the selftest compiles with `rustc --emit=obj` for
//! aarch64-linux-android and aarch64-apple-ios, once per case. Each case picks its parts with
//! `--cfg` and `--crate-name`:
//! - the OS import the scan requires on the target (getrandom on Android, CCRandomGenerateBytes
//!   on iOS), unless `--cfg kc_no_os_import`;
//! - `--cfg kc_arc4random`: an arc4random import, banned on every target;
//! - `--cfg kc_getentropy`: a getentropy import, banned on Linux and Android only;
//! - `--cfg kc_libc_r`: random_r, lrand48_r and seed48 imports (glibc's reentrant draws and a
//!   rand48 seeder), banned on every target;
//! - `--crate-name rand` (and, for Android only, each other crate of deny.toml's RNG list):
//!   `rngs::next_u32` becomes a defined `rand::` symbol;
//! - `--crate-name getrandom`: `backends::use_file::fill_inner` becomes one of getrandom's fallback
//!   symbols (tasks/todo.md, M1 Q8).
//! Under any other crate name those two functions are harmless, so every case holds them.
//! Not part of any build: scripts/testdata/ is outside the workspace and the grep gate's scan.
#![no_std]

#[cfg(all(target_os = "android", not(kc_no_os_import)))]
unsafe extern "C" {
    fn getrandom(buf: *mut u8, len: usize, flags: u32) -> isize;
}

#[cfg(all(target_os = "android", not(kc_no_os_import)))]
#[unsafe(no_mangle)]
pub extern "C" fn kc_fixture_os(buf: *mut u8, len: usize) -> i64 {
    unsafe { getrandom(buf, len, 0) as i64 }
}

#[cfg(all(target_os = "ios", not(kc_no_os_import)))]
unsafe extern "C" {
    fn CCRandomGenerateBytes(bytes: *mut u8, count: usize) -> i32;
}

#[cfg(all(target_os = "ios", not(kc_no_os_import)))]
#[unsafe(no_mangle)]
pub extern "C" fn kc_fixture_os(buf: *mut u8, len: usize) -> i64 {
    unsafe { CCRandomGenerateBytes(buf, len) as i64 }
}

#[cfg(kc_arc4random)]
unsafe extern "C" {
    fn arc4random() -> u32;
}

#[cfg(kc_arc4random)]
#[unsafe(no_mangle)]
pub extern "C" fn kc_fixture_arc4random() -> u32 {
    unsafe { arc4random() }
}

#[cfg(kc_getentropy)]
unsafe extern "C" {
    fn getentropy(buf: *mut u8, len: usize) -> i32;
}

#[cfg(kc_getentropy)]
#[unsafe(no_mangle)]
pub extern "C" fn kc_fixture_getentropy(buf: *mut u8, len: usize) -> i32 {
    unsafe { getentropy(buf, len) }
}

#[cfg(kc_libc_r)]
unsafe extern "C" {
    fn random_r(state: *mut u8, result: *mut i32) -> i32;
    fn lrand48_r(state: *mut u8, result: *mut i64) -> i32;
    fn seed48(seed: *mut u16) -> *mut u16;
}

#[cfg(kc_libc_r)]
#[unsafe(no_mangle)]
pub extern "C" fn kc_fixture_libc_r(state: *mut u8, a: *mut i32, b: *mut i64, seed: *mut u16) -> i32 {
    unsafe { random_r(state, a) + lrand48_r(state, b) + i32::from(seed48(seed).is_null()) }
}

// #[inline(never)]: rustc would otherwise leave a function this small to its callers' crates
// (cross-crate inlining), and the object would hold no symbol for it.
pub mod rngs {
    /// A hand-written PRNG step, the shape rule 1 bans.
    #[inline(never)]
    pub fn next_u32(state: &mut u32) -> u32 {
        *state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        *state
    }
}

pub mod backends {
    pub mod use_file {
        /// Stands in for getrandom's /dev/urandom fallback.
        #[inline(never)]
        pub fn fill_inner(buf: &mut [u8]) -> usize {
            buf.len()
        }
    }
}
