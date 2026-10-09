//! Stub entropy for tests only (CLAUDE.md rule 10; tasks/todo.md, M1 group 2).
//!
//! This whole module exists only under the `test-sources` feature, which no manifest turns on
//! (scripts/canaries.sh): tests switch it on from the command line with `-p keepcrypt-core`. Any
//! linked artifact that holds the marker below shipped a stub, and the release scan fails it.
#![cfg(feature = "test-sources")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use zeroize::Zeroize;

/// The stub marker. `#[used]` keeps it in every object that links this module.
#[used]
static MARKER: [u8; 26] = *b"KC_TEST_SOURCE_DO_NOT_SHIP";

/// What a stub source hands out. Every mode is deterministic; none is a PRNG.
pub enum StubEntropy {
    /// Exactly these bytes, in order. A read past the end fails like an OS error, so a test that
    /// gives exactly the bytes it expects also proves no extra byte was read.
    Fixed(Vec<u8>),
    /// SHA-256 counter mode over a label: block i is SHA-256(label || i as u64, big-endian), the
    /// blocks concatenated. Unlimited.
    Stream(Vec<u8>),
    /// Every read fails like an OS error.
    Fail,
    /// Reads 0 to n - 1 succeed (counter mode over a fixed label); read n, and every later one,
    /// fails like an OS error.
    FailAt(usize),
    /// The first n bytes come in full (counter mode over a fixed label); after that every read
    /// comes up short.
    ShortAfter(usize),
}

impl Zeroize for StubEntropy {
    fn zeroize(&mut self) {
        match self {
            StubEntropy::Fixed(bytes) | StubEntropy::Stream(bytes) => bytes.zeroize(),
            StubEntropy::Fail => {}
            StubEntropy::FailAt(n) | StubEntropy::ShortAfter(n) => n.zeroize(),
        }
    }
}

/// Counts session wipes: a session's `Drop` bumps it after zeroizing. Clones share the count.
#[derive(Clone, Default)]
pub struct WipeProbe(Arc<AtomicUsize>);

impl WipeProbe {
    /// A probe that has seen no wipe.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many sessions holding this probe have been wiped.
    pub fn wipes(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// A stub source for `Session::new_with_stub`: the entropy it hands out and the probe it reports
/// wipes to.
pub struct StubSource {
    entropy: StubEntropy,
    probe: WipeProbe,
}

impl StubSource {
    /// A stub source over `entropy` that reports wipes to `probe`.
    pub fn new(entropy: StubEntropy, probe: &WipeProbe) -> Self {
        Self {
            entropy,
            probe: probe.clone(),
        }
    }

    /// The session holding this stub was wiped: clear the stub's own bytes, then count it.
    pub(crate) fn wiped(&mut self) {
        self.entropy.zeroize();
        self.probe.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_is_the_documented_string() {
        assert_eq!(&MARKER, b"KC_TEST_SOURCE_DO_NOT_SHIP");
    }

    #[test]
    fn wiped_clears_the_stub_and_counts_once() {
        let probe = WipeProbe::new();
        let mut stub = StubSource::new(StubEntropy::Fixed(vec![7; 64]), &probe);
        assert_eq!(probe.wipes(), 0);
        stub.wiped();
        assert_eq!(probe.wipes(), 1);
        assert!(matches!(&stub.entropy, StubEntropy::Fixed(bytes) if bytes.is_empty()));
        let mut counted = StubSource::new(StubEntropy::FailAt(3), &probe);
        counted.wiped();
        assert!(matches!(counted.entropy, StubEntropy::FailAt(0)));
        assert_eq!(probe.wipes(), 2);
    }
}
