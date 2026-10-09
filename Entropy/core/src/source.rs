//! Where a session's randomness comes from (CLAUDE.md rules 1 and 10; docs/build-plan.md
//! "source"; tasks/todo.md, M1 groups 2 and 3).
//!
//! Without the `test-sources` feature the only arm is the OS, and no public API accepts a source,
//! so a shipped build cannot be handed a fake one. The stub arm exists only under that feature.

mod stub;

#[cfg(feature = "test-sources")]
pub use stub::{StubEntropy, StubSource, WipeProbe};

/// A session's entropy source.
pub(crate) enum Source {
    /// The operating system's random source: the only arm in a release build.
    Os,
    /// Stub entropy for tests (`test-sources` only).
    #[cfg(feature = "test-sources")]
    Stub(StubSource),
}

impl Source {
    /// Called by the session's `Drop` after its secrets are zeroized: a stub wipes its own buffers
    /// and counts the wipe on its probe. The OS arm holds nothing.
    pub(crate) fn wiped(&mut self) {
        match self {
            Source::Os => {}
            #[cfg(feature = "test-sources")]
            Source::Stub(stub) => stub.wiped(),
        }
    }
}
