//! The ELF controls of `scripts/banned-api-check.sh --selftest-image` and of the image scan's
//! built-in `--selftest` cases (tasks/todo.md, M4 group 14): one #![no_std] source that the script
//! compiles with `rustc --emit obj` for arm-unknown-linux-gnueabihf, links with rust-lld and strips
//! with llvm-objcopy, so no cross compiler is needed. Each control picks its parts with `--cfg`:
//! - `kc_getrandom`: a shared object that imports getrandom (the OS import the scan requires on the
//!   Pi target) and keeps its .symtab: the stand-in for keepcrypt-pi, BusyBox and the libraries in
//!   the stub image, and the base of the next two;
//! - `kc_sim`: that, plus a defined keepcrypt_pi_sim_hwrng symbol, the simulator crate's name;
//! - `kc_rand`: that, plus an import of libc's rand, then stripped to its dynamic symbols: a
//!   library of the root that draws from a PRNG;
//! - `kc_static`: an executable with an entry point and nothing else, then stripped: a static file
//!   with no symbols at all, which the scan must refuse rather than pass.
//! Not part of any build: scripts/testdata/ is outside the workspace and the grep gate's scan.
#![no_std]

#[cfg(any(kc_getrandom, kc_sim, kc_rand))]
unsafe extern "C" {
    fn getrandom(buf: *mut u8, len: usize, flags: u32) -> isize;
}

#[cfg(any(kc_getrandom, kc_sim, kc_rand))]
#[unsafe(no_mangle)]
pub extern "C" fn kc_control_fill(buf: *mut u8, len: usize) -> isize {
    unsafe { getrandom(buf, len, 0) }
}

#[cfg(kc_sim)]
#[unsafe(no_mangle)]
pub extern "C" fn keepcrypt_pi_sim_hwrng() -> i32 {
    0
}

#[cfg(kc_rand)]
unsafe extern "C" {
    fn rand() -> i32;
}

#[cfg(kc_rand)]
#[unsafe(no_mangle)]
pub extern "C" fn kc_control_draw() -> i32 {
    unsafe { rand() }
}

#[cfg(kc_static)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> i32 {
    7
}
