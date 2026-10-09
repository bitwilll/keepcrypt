//! The one call to the operating system's random source in all of KeepCrypt (CLAUDE.md rule 1;
//! docs/design.md "Mixing and conditioning"). Only this file names the `getrandom` crate.
//!
//! `getrandom::fill` blocks until the kernel pool is ready (flags 0 on Linux) and fills the whole
//! buffer or fails. Never `fill_uninit`, and never the crate's `std` or `sys_rng` features (core
//! declares it with its default features, which are none). A failure is reported without its
//! payload, and the caller's shared length check turns any short read into a failure too.

use crate::error::{CoreError, SourceFault};

/// Fills `buf` from the OS random source.
pub(super) fn fill_os(buf: &mut [u8]) -> Result<(), CoreError> {
    getrandom::fill(buf).map_err(|_| CoreError::Source(SourceFault::Os))
}
