//! The typestate ceremony session (CLAUDE.md rule 6; docs/build-plan.md "Public API" as refined
//! by tasks/todo.md, M1 Q5).
//!
//! `Collecting -> Committed -> Rolling -> Sealed -> (Checking) -> Ready`. Each state is an
//! uninhabited type behind a sealed trait, so only this module can name a transition. One
//! `Box<Inner>` holds every secret at fixed capacity; dropping the session, on any path (an `Err`,
//! a panic that unwinds, or plain scope exit), zeroizes it. Every method that can fail on
//! randomness, a health test, a known-answer test or an integrity check takes `self`, so an
//! `Err` has already wiped the session.
//!
//! This is the skeleton (M1 group 2): construction runs the known-answer tests. The transitions
//! arrive in M1 group 9.

mod inner;

use core::marker::PhantomData;

use crate::error::{CoreError, KatId};
use crate::kat::{self, Suite};
use crate::source::Source;
#[cfg(feature = "test-sources")]
use crate::source::StubSource;
use inner::Inner;

/// How many words the seed has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeedLength {
    /// 12 words, the first 128 bits of E: one KeepCrypt Hinge or Screw. The default.
    #[default]
    Words12,
    /// 24 words, all 256 bits of E: two devices.
    Words24,
}

/// Which legs make the seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Device leg D and dice leg R, joined by one hash.
    Mixed,
    /// Dice only: E = SHA-256(R), the same as Coldcard. No device randomness is used.
    DiceOnly,
}

/// The shell running the ceremony; it decides the device quota (docs/build-plan.md "Credit
/// policy").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// The Raspberry Pi Zero: OS randomness plus health-tested raw hwrng samples.
    Pi,
    /// Android or iPhone: OS randomness only.
    Phone,
}

/// A session's fixed settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Config {
    pub(crate) len: SeedLength,
    pub(crate) mode: Mode,
    pub(crate) platform: Platform,
}

mod sealed {
    /// Only this module implements `State`.
    pub trait Sealed {}
}

/// A ceremony state. Sealed: no other crate can add one.
pub trait State: sealed::Sealed {}

/// Collecting device entropy, before the commitment.
pub enum Collecting {}
/// D is fixed and C is shown; dice not started.
pub enum Committed {}
/// Taking dice rolls.
pub enum Rolling {}
/// The seed exists, but no mnemonic, D, backup or export can leave this state.
pub enum Sealed {}
/// A collision check is running: the same secrecy as Sealed, and no way back to Skip.
pub enum Checking {}
/// The words may be shown; read-back gates the exports.
pub enum Ready {}

impl sealed::Sealed for Collecting {}
impl sealed::Sealed for Committed {}
impl sealed::Sealed for Rolling {}
impl sealed::Sealed for Sealed {}
impl sealed::Sealed for Checking {}
impl sealed::Sealed for Ready {}
impl State for Collecting {}
impl State for Committed {}
impl State for Rolling {}
impl State for Sealed {}
impl State for Checking {}
impl State for Ready {}

/// A ceremony in state `S`. No `Clone`, `Debug` or `Default`: there is one session, it cannot be
/// printed, and it exists only through `new`.
pub struct Session<S: State> {
    inner: Box<Inner>,
    state: PhantomData<S>,
}

impl<S: State> Session<S> {
    /// The seed length chosen at `new`.
    pub fn seed_length(&self) -> SeedLength {
        self.inner.config.len
    }

    /// The mode chosen at `new`.
    pub fn mode(&self) -> Mode {
        self.inner.config.mode
    }

    /// The platform given at `new`.
    pub fn platform(&self) -> Platform {
        self.inner.config.platform
    }
}

impl Session<Collecting> {
    /// Starts a ceremony on the OS entropy source, after the full known-answer suite. An `Err`
    /// means no seed can be made.
    pub fn new(len: SeedLength, mode: Mode, platform: Platform) -> Result<Self, CoreError> {
        Self::start(
            Config {
                len,
                mode,
                platform,
            },
            Source::Os,
            None,
        )
    }

    /// `new` on a stub source, optionally with known-answer group `kat_fault` made to fail
    /// (tests only, `test-sources`).
    #[cfg(feature = "test-sources")]
    pub fn new_with_stub(
        len: SeedLength,
        mode: Mode,
        platform: Platform,
        stub: StubSource,
        kat_fault: Option<KatId>,
    ) -> Result<Self, CoreError> {
        Self::start(
            Config {
                len,
                mode,
                platform,
            },
            Source::Stub(stub),
            kat_fault,
        )
    }

    /// The one constructor body. `Inner` exists before the suite runs, so a failing suite drops
    /// it like every other `Err`: zeroized, and counted by a stub's wipe probe.
    fn start(config: Config, source: Source, kat_fault: Option<KatId>) -> Result<Self, CoreError> {
        let inner = Inner::new(config, source);
        kat::run(Suite::Full, kat_fault)?;
        Ok(Session {
            inner,
            state: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_runs_the_suite_and_keeps_the_settings() {
        for len in [SeedLength::Words12, SeedLength::Words24] {
            for mode in [Mode::Mixed, Mode::DiceOnly] {
                for platform in [Platform::Pi, Platform::Phone] {
                    match Session::new(len, mode, platform) {
                        Ok(session) => {
                            assert_eq!(session.seed_length(), len);
                            assert_eq!(session.mode(), mode);
                            assert_eq!(session.platform(), platform);
                        }
                        Err(e) => panic!("{e}"),
                    }
                }
            }
        }
        assert_eq!(SeedLength::default(), SeedLength::Words12);
    }

    #[cfg(feature = "test-sources")]
    mod stub {
        use super::*;
        use crate::source::{StubEntropy, WipeProbe};

        #[test]
        fn every_kat_fault_fails_new_and_wipes_once() {
            for id in KatId::ALL {
                let probe = WipeProbe::new();
                let stub = StubSource::new(StubEntropy::Fail, &probe);
                let result = Session::new_with_stub(
                    SeedLength::Words12,
                    Mode::Mixed,
                    Platform::Pi,
                    stub,
                    Some(id),
                );
                assert!(
                    matches!(result, Err(CoreError::Kat(got)) if got == id),
                    "{id:?}"
                );
                assert_eq!(probe.wipes(), 1, "{id:?}");
            }
        }

        #[test]
        fn a_healthy_stub_session_wipes_once_on_drop() {
            let probe = WipeProbe::new();
            let stub = StubSource::new(StubEntropy::Stream(b"session".to_vec()), &probe);
            match Session::new_with_stub(
                SeedLength::Words24,
                Mode::DiceOnly,
                Platform::Phone,
                stub,
                None,
            ) {
                Ok(session) => {
                    assert_eq!(probe.wipes(), 0);
                    assert_eq!(session.seed_length(), SeedLength::Words24);
                    let moved = session;
                    assert_eq!(moved.mode(), Mode::DiceOnly);
                }
                Err(e) => panic!("{e}"),
            }
            assert_eq!(probe.wipes(), 1);
        }
    }
}
