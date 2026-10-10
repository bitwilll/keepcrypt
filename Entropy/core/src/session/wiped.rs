//! How a collision check ends (docs/seal-watchonly-braille.md "Go-ahead before reveal", "Add fresh
//! entropy", "Results"; tasks/todo.md, M1 group 9, Q5).
//!
//! - `GoAhead` borrows verified evidence (a loaded snapshot, a verified proof) or the typed code,
//!   so a snapshot loaded before the ceremony survives a restart and serves the next check, and
//!   the shell can show its date before `reveal`.
//! - `Rejected` is a `reveal` that did not reach the words: `Retry` gives the checking session back
//!   with the same nonce; `Collision` has wiped the seed.
//! - `Wiped` replaces a destroyed session. It holds no secret: the platform, the 99-roll flag, and
//!   after a collision only, the destroyed seed's collision report. `restart` re-runs the
//!   known-answer suite and starts a fresh ceremony (fresh pool, fresh OS read at commit, fresh
//!   dice), at 99 rolls for either length after a collision.
//! - The 99-roll flag (tasks/todo.md, "M1: open owner items", item 5): a collision sets it, and
//!   "Cannot check" keeps the checking session's own flag, so the restart after a collision keeps
//!   99 rolls through every "Cannot check" until a check passes. Only a `Wiped` carries it, and
//!   only a check leaves one: `Ready` (a passed check, or Skip) has no way back to a `Wiped`, and
//!   an `Err` or a dropped session leaves none, so the next ceremony is a `Session::new`, at the
//!   normal minimum.
//! - `Rejected` and `Wiped` have hand-written `Debug` that prints their variant names and never
//!   touches their contents. Those names are no BIP39 word as a whole token (case-folded runs of
//!   letters: "rejected", "retry", "collision", "wiped"); "session", "report", "flag", "check" and
//!   "code" are BIP39 words, so none of them is printed (tests/no_secret_text.rs).

use core::fmt;

use super::{Checking, Collecting, Config, Mode, Platform, SeedLength, Session};
#[cfg(feature = "test-sources")]
use crate::error::KatId;
use crate::error::{CheckError, CoreError};
use crate::seal::{CollisionReport, VerifiedProof, VerifiedSnapshot};
use crate::source::Source;
#[cfg(feature = "test-sources")]
use crate::source::StubSource;

/// A go-ahead to try on a checking session. It borrows verified evidence, so a snapshot loaded
/// before the ceremony serves every check, across restarts.
#[derive(Debug, Clone, Copy)]
pub enum GoAhead<'a> {
    /// A registry snapshot this device loaded and verified (`verify_snapshot`).
    Snapshot(&'a VerifiedSnapshot),
    /// A bucket proof from a go-ahead QR, verified (`verify_bucket_proof_qr`).
    BucketProof(&'a VerifiedProof),
    /// The 8-character go-ahead code as typed (case, dashes, spaces, O/I/L are forgiven).
    Code(&'a str),
}

/// Why the user stopped a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Discard {
    /// "Match found": the checker reported this seal. Keeps the collision report and the
    /// 99-roll minimum for the restart.
    Collision,
    /// "Cannot check": a network or snapshot error. Keeps no report, and keeps this session's own
    /// 99-roll flag: the restart uses the normal minimum, unless this session was itself a restart
    /// after a collision, whose 99 rolls then stay until a check passes.
    CannotCheck,
}

/// A `reveal` that did not reach the words.
pub enum Rejected {
    /// The go-ahead did not verify (a typo, a bad scan, a proof for another bucket): the session,
    /// with the same nonce, and why. Retries are unlimited.
    Retry(Session<Checking>, CheckError),
    /// The evidence holds this seal: the seed has been wiped unseen.
    Collision(Wiped),
}

impl fmt::Debug for Rejected {
    /// The variant's name only; the session and the error inside are never touched.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Rejected::Retry(..) => "Rejected::Retry",
            Rejected::Collision(_) => "Rejected::Collision",
        })
    }
}

/// What is left of a session whose seed was destroyed unseen. Holds no secret.
pub struct Wiped {
    platform: Platform,
    /// After a collision, and after "Cannot check" in a restart after one: the next ceremony needs
    /// 99 rolls for either length.
    after_collision: bool,
    /// After a collision: the destroyed seed's "Report collision" QR.
    report: Option<CollisionReport>,
}

impl fmt::Debug for Wiped {
    /// The type's name only; nothing it holds is touched.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Wiped")
    }
}

impl Wiped {
    /// Ends a check: keeps what `why` says, then drops the session, which zeroizes it.
    pub(super) fn from_check(session: Session<Checking>, why: Discard) -> Self {
        let (after_collision, report) = match why {
            Discard::Collision => (true, Some(session.inner.collision_report())),
            Discard::CannotCheck => (session.inner.after_collision(), None),
        };
        let wiped = Self {
            platform: session.platform(),
            after_collision,
            report,
        };
        drop(session);
        wiped
    }

    /// The "Report collision" QR with the destroyed seed's code, only after a collision. Sharing
    /// that code is harmless: the seed is never used.
    pub fn collision_report(&self) -> Option<&CollisionReport> {
        self.report.as_ref()
    }

    /// "Add fresh entropy": a new ceremony on the same platform, after the full known-answer suite,
    /// with a fresh pool, a fresh OS read at commit and fresh dice. Nothing of the destroyed seed is
    /// reused. After a collision, and after "Cannot check" in a restart after one, the minimum is
    /// 99 rolls for either length. An `Err` means no seed can be made.
    pub fn restart(self, len: SeedLength, mode: Mode) -> Result<Session<Collecting>, CoreError> {
        Session::start(
            self.config(len, mode),
            Source::Os,
            None,
            self.after_collision,
        )
    }

    /// `restart` on a stub source, optionally with known-answer group `kat_fault` made to fail
    /// (tests only, `test-sources`).
    #[cfg(feature = "test-sources")]
    pub fn restart_with_stub(
        self,
        len: SeedLength,
        mode: Mode,
        stub: StubSource,
        kat_fault: Option<KatId>,
    ) -> Result<Session<Collecting>, CoreError> {
        Session::start(
            self.config(len, mode),
            Source::Stub(stub),
            kat_fault,
            self.after_collision,
        )
    }

    fn config(&self, len: SeedLength, mode: Mode) -> Config {
        Config {
            len,
            mode,
            platform: self.platform,
        }
    }

    /// A `Wiped` as a check leaves one, without running a ceremony (tests only).
    #[cfg(all(test, feature = "test-sources"))]
    pub(crate) fn from_parts_for_test(platform: Platform, after_collision: bool) -> Self {
        Self {
            platform,
            after_collision,
            report: None,
        }
    }
}
