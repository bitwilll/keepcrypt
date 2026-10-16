//! The hwrng reader (docs/pi-firmware.md "`hal::HwRng`"; tasks/todo.md, M4 group 7, Q39 (c)).
//!
//! - Pure: `fill_block` reads the 64-byte blocks of raw samples for core's health tests through a
//!   `RawRead` (one read(2) of `/dev/hwrng`, opened non-blocking, and a pause), which group 10's
//!   Linux glue implements and the tests script, and a `hal::Clock`. It does no I/O of its own.
//! - Each read goes straight into the caller's block and asks for exactly the bytes still missing:
//!   no buffered reader, no copy, and no read past the block's 64 bytes, so no sample is held
//!   anywhere else.
//! - A block still incomplete 2 seconds after it was asked for is `HalError::HwRng`, "hwrng read
//!   fault", which halts the device (Q39 (c)): no retry after that, no default and no fallback
//!   source (rule 3).
//! - The deadline covers reads that find nothing yet (`EAGAIN`). A read that waits inside the
//!   kernel, on the hwrng core's lock, ends when the downstream driver's bounded retries do, not at
//!   this deadline: it stalls the screen and still yields no bytes. That wait is on M7's audit
//!   list.

use std::io::{self, ErrorKind};

use keepcrypt_pi::hal::{Clock, HalError};

#[cfg(test)]
mod tests;

/// How long a block may take, from the call (Q39 (c)): 2 s.
pub const DEADLINE_NS: u64 = 2_000_000_000;
/// The pause after a read that found nothing yet.
const RETRY_MS: u16 = 1;

/// The hwrng. Group 10's Linux glue implements it over `/dev/hwrng`, opened with `O_NONBLOCK`; the
/// tests script it.
pub trait RawRead {
    /// One read(2) into `buf`: the count read, at most `buf.len()`, or 0 at end of file;
    /// `WouldBlock` while the device has nothing yet, `Interrupted` when a signal cut the read
    /// short.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    /// Waits `ms` milliseconds.
    fn sleep_ms(&mut self, ms: u16);
}

/// Fills `block` from `raw`, straight into it, until all 64 bytes are in, at most `deadline_ns`
/// (`DEADLINE_NS` on the device) after the call, on `clock`:
/// - `WouldBlock`: sleep 1 ms, then read again;
/// - `Interrupted`: read again;
/// - end of file, a count past the bytes asked for, or any other error: `HwRng`;
/// - still incomplete at the deadline, whatever the reads gave: `HwRng`.
///
/// On an error `block` may hold part of a block: the caller's buffer wipes it, and the app halts.
pub fn fill_block<R: RawRead, C: Clock>(
    raw: &mut R,
    clock: &C,
    block: &mut [u8; 64],
    deadline_ns: u64,
) -> Result<(), HalError> {
    let until_ns = clock.now_ns().saturating_add(deadline_ns);
    let mut filled = 0;
    loop {
        let missing = &mut block[filled..];
        match raw.read(missing) {
            Ok(read) if (1..=missing.len()).contains(&read) => {
                filled += read;
                if filled == block.len() {
                    return Ok(());
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => raw.sleep_ms(RETRY_MS),
            Ok(_) | Err(_) => return Err(HalError::HwRng),
        }
        if clock.now_ns() >= until_ns {
            return Err(HalError::HwRng);
        }
    }
}
