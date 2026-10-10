//! Stub entropy for tests only (CLAUDE.md rule 10; tasks/todo.md, M1 group 2).
//!
//! This whole module exists only under the `test-sources` feature, which no manifest turns on
//! (scripts/canaries.sh): tests switch it on from the command line with `-p keepcrypt-core`. Any
//! linked artifact that holds the marker below shipped a stub, and the release scan fails it.
#![cfg(feature = "test-sources")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::{CoreError, InternalFault, SourceFault};

/// The stub marker. `#[used]` keeps it in every object that links this module.
#[used]
static MARKER: [u8; 26] = *b"KC_TEST_SOURCE_DO_NOT_SHIP";

/// The counter-mode label behind `FailAt` and `ShortAfter`.
const STUB_LABEL: &[u8] = b"KCE/test/stub";

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

/// Counts session wipes: zeroizing a session bumps it last, after every other field is clear, and
/// the session's `Drop` zeroizes. Clones share the count.
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

/// A stub source for `Session::new_with_stub`: the entropy it hands out, the probe it reports
/// wipes to, and how far it has got.
pub struct StubSource {
    entropy: StubEntropy,
    probe: WipeProbe,
    /// Bytes handed out so far.
    served: usize,
    /// Reads so far, failed ones included.
    reads: usize,
}

impl StubSource {
    /// A stub source over `entropy` that reports wipes to `probe`.
    pub fn new(entropy: StubEntropy, probe: &WipeProbe) -> Self {
        Self {
            entropy,
            probe: probe.clone(),
            served: 0,
            reads: 0,
        }
    }

    /// One read: fills the front of `buf` and returns how many bytes it filled. The caller's
    /// shared length check (`Source::fill`) fails anything short of `buf.len()`. A failing mode
    /// fails like the OS source does. The marker passes through `black_box` here, on the source
    /// dispatch, so a linked artifact that can reach a stub keeps it.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> Result<usize, CoreError> {
        core::hint::black_box(&MARKER);
        let read = self.reads;
        self.reads = self.reads.saturating_add(1);
        let produced = match &self.entropy {
            StubEntropy::Fixed(bytes) => {
                let end = self
                    .served
                    .checked_add(buf.len())
                    .filter(|&end| end <= bytes.len());
                match end {
                    Some(end) => {
                        buf.copy_from_slice(&bytes[self.served..end]);
                        buf.len()
                    }
                    None => return Err(CoreError::Source(SourceFault::Os)),
                }
            }
            StubEntropy::Stream(label) => counter_fill(label, self.served, buf)?,
            StubEntropy::Fail => return Err(CoreError::Source(SourceFault::Os)),
            StubEntropy::FailAt(n) if read >= *n => return Err(CoreError::Source(SourceFault::Os)),
            StubEntropy::FailAt(_) => counter_fill(STUB_LABEL, self.served, buf)?,
            StubEntropy::ShortAfter(n) => {
                let available = n.saturating_sub(self.served).min(buf.len());
                counter_fill(STUB_LABEL, self.served, &mut buf[..available])?
            }
        };
        self.served = self.served.saturating_add(produced);
        Ok(produced)
    }

    /// The session holding this stub was wiped: clear the stub's own bytes, then count it.
    pub(crate) fn wiped(&mut self) {
        self.entropy.zeroize();
        self.served.zeroize();
        self.reads.zeroize();
        self.probe.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// Fills all of `out` with SHA-256 counter-mode bytes over `label`, starting at stream offset
/// `offset`: block i is SHA-256(label || i as u64, big-endian). Returns `out.len()`.
fn counter_fill(label: &[u8], offset: usize, out: &mut [u8]) -> Result<usize, CoreError> {
    let mut written = 0;
    while written < out.len() {
        let position = offset
            .checked_add(written)
            .ok_or(CoreError::Internal(InternalFault::Length))?;
        let block =
            u64::try_from(position / 32).map_err(|_| CoreError::Internal(InternalFault::Length))?;
        let digest = Sha256::new()
            .chain_update(label)
            .chain_update(block.to_be_bytes())
            .finalize();
        let from = position % 32;
        let take = (32 - from).min(out.len() - written);
        out[written..written + take].copy_from_slice(&digest[from..from + take]);
        written += take;
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_is_the_documented_string() {
        assert_eq!(&MARKER, b"KC_TEST_SOURCE_DO_NOT_SHIP");
    }

    #[test]
    fn counter_fill_is_sha256_counter_mode_at_any_offset() {
        let mut first = [0u8; 70];
        assert_eq!(counter_fill(b"x", 0, &mut first), Ok(70));
        let block0 = Sha256::new()
            .chain_update(b"x")
            .chain_update(0u64.to_be_bytes())
            .finalize();
        let block2 = Sha256::new()
            .chain_update(b"x")
            .chain_update(2u64.to_be_bytes())
            .finalize();
        assert_eq!(&first[..32], block0.as_slice());
        assert_eq!(&first[64..], &block2[..6]);
        let mut middle = [0u8; 40];
        assert_eq!(counter_fill(b"x", 13, &mut middle), Ok(40));
        assert_eq!(&middle[..], &first[13..53]);
        assert_eq!(
            counter_fill(b"x", usize::MAX, &mut [0u8; 2]),
            Err(CoreError::Internal(InternalFault::Length))
        );
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
