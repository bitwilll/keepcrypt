//! keepcrypt-capi: the iPhone's C ABI boundary, built as libkeepcrypt_capi.a (Q87; tasks/todo.md,
//! M6 lead decision M6-1 and item B1), and with keepcrypt-jni the workspace's only unsafe code. It
//! defines two exports, the two prototypes of include/keepcrypt.h: `kc_max_out`, the reply bound,
//! and `kc_call`, the one call per boundary (M5-21), which carries keepcrypt-jni's wire protocol
//! (keepcrypt-ffi's wire.rs), so every rule stays in the safe layer. The library also defines
//! secp256k1-sys's C functions and its four `#[no_mangle]` ones, which a staticlib keeps from its
//! dependencies.
//!
//! - **The call** copies the input into a Vec of exactly its length, under a size cap, and hands
//!   it to `keepcrypt_guard::guarded`, the one panic catch, which wipes it once the call is done.
//!   The reply, guarded's wiping buffer, is copied once into the caller's buffer and dropped, which
//!   wipes it. No Rust memory crosses the boundary, so there is no free function: Swift owns the
//!   one buffer it passes, `kc_max_out()` bytes, and wipes it (M6-1).
//! - **Fail closed.** A null input with a non-zero length, an input longer than `MAX_INPUT`, a
//!   null output buffer and a reply longer than the buffer (wiped unread) halt the slot, through
//!   `guarded` with an op the table does not hold (`HALT`), and the call gives -1. Nothing is
//!   printed: any other halt is the reply's status.
//! - **Lengths** cross through `TryFrom`, never `as`, and no secret byte is cast.
//! - **Unsafe code:** every block holds one operation and a SAFETY: comment.
//! - **Nothing else:** no callback into the caller, no static, no state of its own; the slot is
//!   keepcrypt-ffi's, reached through the guard alone.

use core::{ptr, slice};

/// The longest input an op takes, as keepcrypt-jni's: Load registry snapshot's date, 4 bytes, then
/// a snapshot of 2^22 entries, 122 + 18 x 2^22 bytes (docs/seal-watchonly-braille.md, "Snapshot
/// format"): 75,497,598 bytes. A longer input is the shell's bug and halts before a byte is read.
const MAX_INPUT: usize = 4 + 122 + 18 * (1 << 22);

/// The reply bound, `kc_max_out()`: the size of the buffer Swift passes, which every reply fits
/// (tasks/todo.md, M6 item B2 measures them). A reply past the caller's `out_cap` halts.
const MAX_OUT: usize = 16_384;

/// An op the table does not hold (its ops run from 1, keepcrypt-ffi's wire.rs), on which `guarded`
/// halts the slot: the halt of a call that cannot be read or answered.
const HALT: u32 = 0;

/// A call that cannot be read or answered: a null pointer, a length out of range or a reply that
/// does not fit. The call halts.
#[derive(Debug, PartialEq, Eq)]
struct Failed;

/// The size of the reply buffer `kc_call` needs: every reply fits in it.
#[unsafe(no_mangle)]
pub extern "C" fn kc_max_out() -> usize {
    MAX_OUT
}

/// `op` with `input_len` bytes at `input` on the phone's slot, through the one catch: the reply's
/// bytes, its status first (keepcrypt-ffi's wire.rs), written to `out`, and their count; or -1,
/// with the slot halted, when the call cannot be read or answered.
///
/// # Safety
///
/// `input` is null or valid for reads of `input_len` bytes, and `out` null or valid for writes of
/// `out_cap` bytes, neither changed by anything else during the call; they may be the same buffer.
/// Neither is used once the call returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kc_call(
    op: u32,
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> i64 {
    if out.is_null() {
        return halted();
    }
    // SAFETY: input is null or valid for reads of input_len bytes (the contract above).
    let Ok(input) = (unsafe { request(input, input_len) }) else {
        return halted();
    };
    let reply = keepcrypt_guard::guarded(op, input);
    // SAFETY: out is non-null (checked above) and valid for writes of out_cap bytes (the contract
    // above); the input was copied out of it before the call, so nothing reads it now.
    match unsafe { answer(&reply, out, out_cap) } {
        Ok(len) => len,
        Err(Failed) => halted(),
    }
}

/// The input as a Vec of exactly its length: empty for a zero length (whatever the pointer), or
/// `Failed` for a null pointer or a length past `MAX_INPUT`, before a byte is read.
///
/// # Safety
///
/// `input` is null or valid for reads of `len` bytes.
unsafe fn request(input: *const u8, len: usize) -> Result<Vec<u8>, Failed> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if input.is_null() || len > MAX_INPUT {
        return Err(Failed);
    }
    // SAFETY: input is non-null and valid for reads of len bytes (the contract above), and len is
    // at most MAX_INPUT, far below isize::MAX; the slice lives only for the copy.
    let bytes = unsafe { slice::from_raw_parts(input, len) };
    Ok(bytes.to_vec())
}

/// The reply copied once into `out`, and its length; `Failed` for a reply longer than `out_cap` (or
/// than an i64 counts), with nothing written.
///
/// # Safety
///
/// `out` is non-null and valid for writes of `out_cap` bytes.
unsafe fn answer(reply: &[u8], out: *mut u8, out_cap: usize) -> Result<i64, Failed> {
    let len = i64::try_from(reply.len()).map_err(|_| Failed)?;
    if reply.len() > out_cap {
        return Err(Failed);
    }
    // SAFETY: out is valid for writes of out_cap bytes (the contract above) and the reply is no
    // longer; the reply is the guard's own buffer, so the two do not overlap.
    unsafe { ptr::copy_nonoverlapping(reply.as_ptr(), out, reply.len()) };
    Ok(len)
}

/// Halts the slot, for a call that cannot be read or answered, and gives -1.
fn halted() -> i64 {
    keepcrypt_guard::guarded(HALT, Vec::new());
    -1
}
