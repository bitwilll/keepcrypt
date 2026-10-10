//! The one call to the operating system's random source in all of KeepCrypt (CLAUDE.md rule 1;
//! docs/design.md "Mixing and conditioning"). Only this file names the `getrandom` crate.
//!
//! `getrandom::fill` blocks until the kernel pool is ready (flags 0 on Linux) and fills the whole
//! buffer or fails. Never `fill_uninit`, and never the crate's `std` or `sys_rng` features (core
//! declares it with its default features, which are none). It returns no byte count, so there is
//! no length to check here: `fill_os` stays one expression (a review check, since no lint catches a
//! swallowed result), its result goes through `os_result`, whose unit test below proves that every
//! error becomes `Source(Os)`, and the real-OS test in `source.rs` proves that every byte of the
//! buffer is written.

use crate::error::{CoreError, SourceFault};

/// Fills `buf` from the OS random source.
pub(super) fn fill_os(buf: &mut [u8]) -> Result<(), CoreError> {
    os_result(getrandom::fill(buf))
}

/// The OS source's result as core reports it: any error is `Source(Os)`, its payload dropped.
fn os_result(result: Result<(), getrandom::Error>) -> Result<(), CoreError> {
    result.map_err(|_| CoreError::Source(SourceFault::Os))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The OS arm's error path, which no stub test reaches: every getrandom error fails closed.
    #[test]
    fn every_os_error_is_a_source_fault() {
        for error in [
            getrandom::Error::UNSUPPORTED,
            getrandom::Error::ERRNO_NOT_POSITIVE,
            getrandom::Error::new_custom(7),
        ] {
            assert_eq!(
                os_result(Err(error)),
                Err(CoreError::Source(SourceFault::Os))
            );
        }
        assert_eq!(os_result(Ok(())), Ok(()));
    }
}
