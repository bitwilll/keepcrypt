//! SP 800-90B health tests on raw hwrng samples (sections 4.3, 4.4.1 and 4.4.2; docs/design.md
//! "Test continuously"; tasks/todo.md, M1 group 3, Q7 and Q13 c, d).
//!
//! - alpha = 2^-20 and H = 4 until lab data (CLAUDE.md "Pi device quota"). Repetition Count cutoff
//!   1 + ceil(20 / H) = 6. Adaptive Proportion window 512 (samples are bytes, not bits) and cutoff
//!   1 + CRITBINOM(512, 2^-4, 1 - 2^-20) = 62. verify.py check 7 recomputes both exactly.
//! - The tester streams: its state carries across calls, so any chunking gives the same verdict.
//! - The first 1,024 samples of every tester (at boot, and at the start of each session's hwrng
//!   intake) run both tests and are then discarded: `test` reports where the post-startup samples
//!   of a chunk begin, and only those are ever absorbed.
//! - Credit counts only post-startup samples in completed windows, so the Pi needs 1,536 bytes for
//!   its first credit, and that first window credits 512 samples (2,048 bits) at once.
//! - A chunk is tested whole before the caller absorbs any of it.
//! - A failure names the test, the stage and the sample index only, never a sample value.

use zeroize::Zeroize;

use crate::error::{
    CoreError, HealthFailure, HealthStage, HealthTest, InternalFault, KatId, SourceFault,
};
use crate::kat::{self, Suite};

/// SP 800-90B 4.4.1 cutoff for H = 4: a value seen 6 times in a row fails, at the 6th.
pub(crate) const RCT_CUTOFF: u32 = 6;
/// SP 800-90B 4.4.2 window for non-binary samples (Q7).
pub(crate) const APT_WINDOW: u64 = 512;
/// SP 800-90B 4.4.2 cutoff for W = 512 and H = 4: a window's first value seen 62 times in that
/// window, itself included, fails.
pub(crate) const APT_CUTOFF: u32 = 62;
/// Samples tested, then discarded, at the start of every tester.
pub(crate) const STARTUP_SAMPLES: u64 = 1_024;

/// A streaming Repetition Count and Adaptive Proportion tester. It remembers raw sample values,
/// so it is zeroized with the session.
#[derive(Zeroize)]
pub(crate) struct HealthTester {
    /// Samples tested so far: the index of the next sample.
    tested: u64,
    rct_value: u8,
    rct_count: u32,
    apt_value: u8,
    apt_count: u32,
}

impl HealthTester {
    /// A tester that has seen no sample: its next 1,024 samples are the startup samples.
    pub(crate) const fn new() -> Self {
        Self {
            tested: 0,
            rct_value: 0,
            rct_count: 0,
            apt_value: 0,
            apt_count: 0,
        }
    }

    /// Tests every sample of `chunk`, in order, carrying state across calls. On success returns
    /// the offset in `chunk` where its post-startup samples begin (`chunk.len()` if all of it is
    /// startup), so the caller absorbs only `chunk[offset..]`.
    pub(crate) fn test(&mut self, chunk: &[u8]) -> Result<usize, CoreError> {
        let startup_left = STARTUP_SAMPLES.saturating_sub(self.tested);
        for &sample in chunk {
            self.step(sample)?;
        }
        let startup_left = usize::try_from(startup_left)
            .map_err(|_| CoreError::Internal(InternalFault::Length))?;
        Ok(startup_left.min(chunk.len()))
    }

    /// One sample through both tests; the Repetition Count goes first.
    fn step(&mut self, sample: u8) -> Result<(), CoreError> {
        let index = self.tested;
        if index > 0 && sample == self.rct_value {
            self.rct_count += 1;
            if self.rct_count >= RCT_CUTOFF {
                return Err(failure(HealthTest::RepetitionCount, index));
            }
        } else {
            self.rct_value = sample;
            self.rct_count = 1;
        }
        if index.is_multiple_of(APT_WINDOW) {
            self.apt_value = sample;
            self.apt_count = 1;
        } else if sample == self.apt_value {
            self.apt_count += 1;
            if self.apt_count >= APT_CUTOFF {
                return Err(failure(HealthTest::AdaptiveProportion, index));
            }
        }
        self.tested = index
            .checked_add(1)
            .ok_or(CoreError::Internal(InternalFault::Length))?;
        Ok(())
    }

    /// Samples tested so far, startup samples included (the Pi's progress bar).
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "read by Session::hw_bytes_tested (tasks/todo.md, M1 group 9)"
        )
    )]
    pub(crate) const fn tested(&self) -> u64 {
        self.tested
    }

    /// Post-startup samples in completed windows: floor((tested - 1,024) / 512) * 512.
    pub(crate) const fn credited_samples(&self) -> u64 {
        match self.tested.checked_sub(STARTUP_SAMPLES) {
            Some(post_startup) => post_startup / APT_WINDOW * APT_WINDOW,
            None => 0,
        }
    }
}

fn failure(test: HealthTest, sample: u64) -> CoreError {
    let stage = if sample < STARTUP_SAMPLES {
        HealthStage::Startup
    } else {
        HealthStage::Continuous
    };
    CoreError::Health(HealthFailure {
        test,
        stage,
        sample,
    })
}

/// The Pi boot screen's hwrng check (pi-firmware.md step 1): the Health known-answer group, then
/// the startup test over exactly 1,024 fresh raw samples, which are then discarded.
pub fn hwrng_boot_test(raw: &[u8]) -> Result<(), CoreError> {
    boot_test(raw, None)
}

/// `hwrng_boot_test` with known-answer group `fault` made to fail (tests only).
#[cfg(feature = "test-sources")]
pub fn hwrng_boot_test_with_kat_fault(raw: &[u8], fault: KatId) -> Result<(), CoreError> {
    boot_test(raw, Some(fault))
}

fn boot_test(raw: &[u8], fault: Option<KatId>) -> Result<(), CoreError> {
    kat::run(Suite::HwrngBoot, fault)?;
    if u64::try_from(raw.len()) != Ok(STARTUP_SAMPLES) {
        return Err(CoreError::Source(SourceFault::HwrngSampleCount));
    }
    let mut tester = HealthTester::new();
    tester.test(raw)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::{hex, keepcrypt_json, named, text};
    use serde_json::{Value, json};

    /// Runs `samples` through a fresh tester in chunks of `chunk`, as keepcrypt.json writes a
    /// verdict, plus the post-startup offsets each chunk reported.
    fn verdict(samples: &[u8], chunk: usize) -> (Value, Vec<usize>) {
        let mut tester = HealthTester::new();
        let mut offsets = Vec::new();
        for part in samples.chunks(chunk) {
            match tester.test(part) {
                Ok(offset) => offsets.push(offset),
                Err(CoreError::Health(f)) => {
                    let test = match f.test {
                        HealthTest::RepetitionCount => "repetition_count",
                        HealthTest::AdaptiveProportion => "adaptive_proportion",
                    };
                    let stage = match f.stage {
                        HealthStage::Startup => "startup",
                        HealthStage::Continuous => "continuous",
                    };
                    let v =
                        json!({"result": "fail", "test": test, "stage": stage, "sample": f.sample});
                    return (v, offsets);
                }
                Err(e) => panic!("{e}"),
            }
        }
        let v = json!({"result": "pass", "tested": tester.tested(), "credited_samples": tester.credited_samples()});
        (v, offsets)
    }

    #[test]
    fn constants_match_keepcrypt_json() {
        let health = &keepcrypt_json()["constants"]["health"];
        assert_eq!(health["rct_cutoff"], RCT_CUTOFF);
        assert_eq!(health["apt_window"], APT_WINDOW);
        assert_eq!(health["apt_cutoff"], APT_CUTOFF);
        assert_eq!(health["startup_samples"], STARTUP_SAMPLES);
        assert_eq!(health["h"], 4);
        assert_eq!(health["alpha_log2"], -20);
    }

    // Every keepcrypt.json case gives its verdict, whole or in chunks of 1, 64 and 1,000 samples.
    // The cases cover a run of 5 passing and of 6 failing, and 61 passing and 62 failing, in both
    // the startup and the continuous stage.
    #[test]
    fn every_keepcrypt_json_case_in_any_chunking() {
        let doc = keepcrypt_json();
        let cases = doc["health"].as_array().expect("health cases");
        assert_eq!(cases.len(), 10);
        for case in cases {
            let samples = hex(&case["samples_hex"]);
            for chunk in [1, 64, 1_000, samples.len()] {
                assert_eq!(
                    verdict(&samples, chunk).0,
                    case["expect"],
                    "{} in chunks of {chunk}",
                    text(&case["name"])
                );
            }
        }
        let clean = named(&doc["health"], "clean-4096");
        let samples = hex(&clean["samples_hex"]);
        for pair in clean["credit_by_prefix"]
            .as_array()
            .expect("credit_by_prefix")
        {
            let n = usize::try_from(pair[0].as_u64().expect("n")).expect("small");
            assert_eq!(
                verdict(&samples[..n], 64).0["credited_samples"],
                pair[1],
                "prefix {n}"
            );
        }
    }

    #[test]
    fn startup_samples_are_reported_for_discarding() {
        let samples = hex(&named(&keepcrypt_json()["health"], "clean-4096")["samples_hex"]);
        let (_, offsets) = verdict(&samples[..2_000], 1_000);
        assert_eq!(
            offsets,
            [1_000, 24],
            "the first 1,024 samples are startup samples"
        );
        let (_, offsets) = verdict(&samples[..1_536], 64);
        assert_eq!(
            offsets[15], 64,
            "chunk 15 (samples 960..1023) is all startup"
        );
        assert_eq!(offsets[16], 0, "chunk 16 starts at sample 1,024");
    }

    #[test]
    fn credit_arrives_per_completed_window() {
        let samples = hex(&named(&keepcrypt_json()["health"], "clean-4096")["samples_hex"]);
        let mut tester = HealthTester::new();
        assert_eq!(tester.test(&samples[..1_535]), Ok(1_024));
        assert_eq!((tester.tested(), tester.credited_samples()), (1_535, 0));
        assert_eq!(tester.test(&samples[1_535..1_536]), Ok(0));
        assert_eq!((tester.tested(), tester.credited_samples()), (1_536, 512));
        assert_eq!(
            crate::source::hwrng_credited_bits(tester.credited_samples()),
            2_048
        );
    }

    #[test]
    fn boot_test_takes_exactly_1024_healthy_samples() {
        let doc = keepcrypt_json();
        let clean = hex(&named(&doc["health"], "clean-4096")["samples_hex"]);
        assert_eq!(hwrng_boot_test(&clean[..1_024]), Ok(()));
        for wrong in [0, 1_023, 1_025] {
            assert_eq!(
                hwrng_boot_test(&clean[..wrong]),
                Err(CoreError::Source(SourceFault::HwrngSampleCount))
            );
        }
        let stuck = [0u8; 1_024];
        assert_eq!(
            hwrng_boot_test(&stuck),
            Err(CoreError::Health(HealthFailure {
                test: HealthTest::RepetitionCount,
                stage: HealthStage::Startup,
                sample: 5
            }))
        );
    }

    #[cfg(feature = "test-sources")]
    #[test]
    fn boot_test_fault_twin_fails_only_its_own_group() {
        let clean = hex(&named(&keepcrypt_json()["health"], "clean-4096")["samples_hex"]);
        for id in KatId::ALL {
            let want = if id == KatId::Health {
                Err(CoreError::Kat(id))
            } else {
                Ok(())
            };
            assert_eq!(
                hwrng_boot_test_with_kat_fault(&clean[..1_024], id),
                want,
                "{id:?}"
            );
        }
    }
}
