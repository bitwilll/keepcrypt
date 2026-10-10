//! Where a session's randomness comes from, the source ids and the credit policy (CLAUDE.md
//! rules 1, 2 and 10, "Pi device quota"; docs/build-plan.md "source", "Credit policy";
//! tasks/todo.md, M1 group 3 and Q6a, Q7).
//!
//! - The OS random source is read in `source/os.rs` only; everything else calls `Source::fill`
//!   or `Source::os_bytes`.
//! - Without the `test-sources` feature the only arm is the OS, and no public API accepts a
//!   source, so a shipped build cannot be handed a fake one.
//! - A read returns exactly the bytes asked for or fails. A stub reports how many bytes it
//!   produced, and the length check in `Source::fill` fails a short read. The OS arm has no count
//!   to check: `getrandom::fill` fills the whole buffer or errs, the real-OS test below proves that
//!   every byte position is written, and `source/os.rs` proves that every OS error fails closed.
//!   The stub error-injection tests never reach the OS arm.
//! - Credited source ids stay inside core; a shell names only an `ExtraSource`, which is never
//!   credited.

mod os;
mod stub;

#[cfg(feature = "test-sources")]
pub use stub::{StubEntropy, StubSource, WipeProbe};
use zeroize::Zeroizing;

use crate::error::{CoreError, SourceFault};
use crate::health::{APT_WINDOW, CreditedSamples, STARTUP_SAMPLES};
use crate::session::{Mode, Platform};

/// OS bytes read at commit and absorbed last (CLAUDE.md "Pi device quota"; Q6a).
pub(crate) const OS_BYTES: usize = 64;
/// hwrng credit until lab data: 4 bits per byte, half of what Linux assumes (docs/design.md).
pub(crate) const HWRNG_BITS_PER_BYTE: u32 = 4;
/// Credited hwrng bits the Pi's device leg needs, for either seed length.
pub(crate) const PI_REQUIRED_BITS: u32 = 512;
/// The phone's device leg: the OS read, credited 256 bits by policy (docs/design.md "Device quota
/// in practice").
pub(crate) const PHONE_REQUIRED_BITS: u32 = 256;
/// hwrng bytes before the first credit: the 1,024 startup samples, tested then discarded, plus one
/// 512-sample window (Q7). The Pi's progress bar counts health-tested bytes toward this
/// (pi-firmware.md step 4); the first window then credits 2,048 bits at once (Q13 c).
pub const HW_BYTES_NEEDED: u64 = STARTUP_SAMPLES + APT_WINDOW;

/// An uncredited extra input a shell may mix into the pool before the commitment. Never counted
/// toward any quota (docs/design.md "Evaluating the proposed sources").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtraSource {
    /// Button or touch timestamps in nanoseconds.
    InputTiming,
    /// Accelerometer and gyroscope samples.
    Motion,
    /// Raw camera frames, lens covered.
    Camera,
    /// Raw microphone PCM.
    Microphone,
}

/// A pool record's source (Q6a). The credited ids exist only inside core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceId {
    /// The OS random source: 0x0001.
    Os,
    /// Health-tested raw hwrng samples: 0x0002. (0x0003 is reserved for the M8 TRNG.)
    Hwrng,
    /// An uncredited extra: 0x0101 to 0x0104.
    Extra(ExtraSource),
}

impl SourceId {
    /// The record's id field: a u16, big-endian.
    pub(crate) const fn to_be_bytes(self) -> [u8; 2] {
        let id: u16 = match self {
            SourceId::Os => 0x0001,
            SourceId::Hwrng => 0x0002,
            SourceId::Extra(ExtraSource::InputTiming) => 0x0101,
            SourceId::Extra(ExtraSource::Motion) => 0x0102,
            SourceId::Extra(ExtraSource::Camera) => 0x0103,
            SourceId::Extra(ExtraSource::Microphone) => 0x0104,
        };
        id.to_be_bytes()
    }
}

/// The credited device-leg bits a session needs before `commit` (docs/build-plan.md "Credit
/// policy"): health-tested hwrng on the Pi, the OS read by policy on a phone, none in dice-only
/// mode.
pub(crate) const fn required_bits(platform: Platform, mode: Mode) -> u32 {
    match (mode, platform) {
        (Mode::DiceOnly, _) => 0,
        (Mode::Mixed, Platform::Pi) => PI_REQUIRED_BITS,
        (Mode::Mixed, Platform::Phone) => PHONE_REQUIRED_BITS,
    }
}

/// Bits credited by policy to the OS read at commit: the whole phone quota, none on the Pi, whose
/// quota is hwrng only.
pub(crate) const fn os_policy_bits(platform: Platform) -> u32 {
    match platform {
        Platform::Pi => 0,
        Platform::Phone => PHONE_REQUIRED_BITS,
    }
}

/// Bits credited to health-tested hwrng samples in completed post-startup windows: 512 samples
/// credit 2,048 bits, more than the 512 required (Q13 c). Only a `HealthTester` can count them
/// (`CreditedSamples`), so a partial window is never credited (Q7). Saturates, so a huge count
/// could only overstate a quota already met, never wrap below it.
pub(crate) fn hwrng_credited_bits(samples: CreditedSamples) -> u64 {
    samples.get().saturating_mul(u64::from(HWRNG_BITS_PER_BYTE))
}

/// Whether the device leg meets its quota once the OS read at commit is counted. The hwrng credit
/// comes only from the session's `HealthTester` (`CreditedSamples`), never from a raw count.
pub(crate) fn quota_met(platform: Platform, mode: Mode, credited: CreditedSamples) -> bool {
    let credited =
        hwrng_credited_bits(credited).saturating_add(u64::from(os_policy_bits(platform)));
    credited >= u64::from(required_bits(platform, mode))
}

/// A session's entropy source.
pub(crate) enum Source {
    /// The operating system's random source: the only arm in a release build.
    Os,
    /// Stub entropy for tests (`test-sources` only).
    #[cfg(feature = "test-sources")]
    Stub(StubSource),
}

impl Source {
    /// Fills `buf` completely or fails. A stub reports how many bytes it produced, and a short
    /// read is `ShortRead`. The OS arm produces the whole buffer or an error (`getrandom::fill`
    /// returns no count), so its count is `buf.len()` by that contract, which the real-OS test
    /// checks byte by byte.
    pub(crate) fn fill(&mut self, buf: &mut [u8]) -> Result<(), CoreError> {
        let produced = match self {
            Source::Os => {
                os::fill_os(buf)?;
                buf.len()
            }
            #[cfg(feature = "test-sources")]
            Source::Stub(stub) => stub.read(buf)?,
        };
        if produced == buf.len() {
            Ok(())
        } else {
            Err(CoreError::Source(SourceFault::ShortRead))
        }
    }

    /// `N` fresh bytes in a read of their own that never touches the pool: the check nonce, the
    /// backup file key, salt, nonce and file name, and the backup passphrase and its confirm
    /// challenge. Zeroized when dropped.
    pub(crate) fn os_bytes<const N: usize>(&mut self) -> Result<Zeroizing<[u8; N]>, CoreError> {
        let mut bytes = Zeroizing::new([0u8; N]);
        self.fill(bytes.as_mut_slice())?;
        Ok(bytes)
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::HealthTester;
    use crate::test_vectors::keepcrypt_json;

    #[test]
    fn constants_and_ids_match_keepcrypt_json() {
        let constants = &keepcrypt_json()["constants"];
        assert_eq!(constants["os_bytes"], OS_BYTES);
        assert_eq!(constants["hwrng_bits_per_byte"], HWRNG_BITS_PER_BYTE);
        assert_eq!(constants["required_bits"]["pi"], PI_REQUIRED_BITS);
        assert_eq!(constants["required_bits"]["phone"], PHONE_REQUIRED_BITS);
        assert_eq!(constants["hw_bytes_needed"], HW_BYTES_NEEDED);
        let ids: Vec<(String, u64)> = constants["source_ids"]
            .as_array()
            .expect("source_ids")
            .iter()
            .map(|e| {
                (
                    e["name"].as_str().expect("name").to_owned(),
                    e["id"].as_u64().expect("id"),
                )
            })
            .collect();
        let ours = [
            ("os", SourceId::Os),
            ("hwrng", SourceId::Hwrng),
            ("input_timing", SourceId::Extra(ExtraSource::InputTiming)),
            ("motion", SourceId::Extra(ExtraSource::Motion)),
            ("camera", SourceId::Extra(ExtraSource::Camera)),
            ("microphone", SourceId::Extra(ExtraSource::Microphone)),
        ];
        for (name, id) in ours {
            let listed: Vec<u64> = ids
                .iter()
                .filter(|(n, _)| n == name)
                .map(|(_, v)| *v)
                .collect();
            assert_eq!(
                listed,
                [u64::from(u16::from_be_bytes(id.to_be_bytes()))],
                "{name}"
            );
        }
        assert!(
            ids.iter().any(|(n, v)| n == "trng" && *v == 3),
            "0x0003 stays reserved for the M8 TRNG"
        );
    }

    /// The credit a tester reports after `n` bytes of keepcrypt.json's clean hwrng stream.
    fn credited_after(n: usize) -> CreditedSamples {
        let clean = crate::test_vectors::hex(
            &crate::test_vectors::named(&keepcrypt_json()["health"], "clean-4096")["samples_hex"],
        );
        let mut tester = HealthTester::new();
        assert!(tester.test(&clean[..n]).is_ok(), "the clean stream passes");
        tester.credited_samples()
    }

    // build-plan.md "Credit policy", as a table: (platform, mode, hwrng bytes through the tester)
    // -> met. The credit is built only by a tester, so the Pi meets its quota at the first
    // completed window, 1,536 bytes, and never at a partial one (Q7).
    #[test]
    fn credit_policy_table() {
        assert_eq!(required_bits(Platform::Pi, Mode::Mixed), 512);
        assert_eq!(required_bits(Platform::Phone, Mode::Mixed), 256);
        assert_eq!(required_bits(Platform::Pi, Mode::DiceOnly), 0);
        assert_eq!(required_bits(Platform::Phone, Mode::DiceOnly), 0);
        assert_eq!(
            hwrng_credited_bits(credited_after(1_536)),
            2_048,
            "the first window credits 2,048 bits (Q13 c)"
        );
        let table = [
            (Platform::Pi, Mode::Mixed, 0, false),
            (Platform::Pi, Mode::Mixed, 1_535, false),
            (Platform::Pi, Mode::Mixed, 1_536, true),
            (Platform::Pi, Mode::Mixed, 4_096, true),
            (Platform::Phone, Mode::Mixed, 0, true),
            (Platform::Pi, Mode::DiceOnly, 0, true),
            (Platform::Phone, Mode::DiceOnly, 0, true),
        ];
        for (platform, mode, bytes, met) in table {
            assert_eq!(
                quota_met(platform, mode, credited_after(bytes)),
                met,
                "{platform:?} {mode:?} {bytes}"
            );
        }
        assert_eq!(credited_after(1_535).get(), 0, "511 post-startup samples");
        assert_eq!(credited_after(1_536).get(), 512);
        assert_eq!(HW_BYTES_NEEDED, 1_536);
    }

    // The real OS path: a full read succeeds and two reads differ. Nothing is printed.
    #[test]
    fn os_source_fills_and_two_reads_differ() {
        let mut source = Source::Os;
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        assert_eq!(source.fill(&mut first), Ok(()));
        assert_eq!(source.fill(&mut second), Ok(()));
        assert_ne!(first, second);
        match source.os_bytes::<8>() {
            Ok(bytes) => assert_eq!(bytes.len(), 8),
            Err(e) => panic!("{e}"),
        }
    }

    // The real OS path writes every byte it is asked for: over 16 reads of 64 bytes into zeroed
    // buffers, through `fill` and through `os_bytes`, each byte position is non-zero at least once.
    // A read that left any position unwritten fails; a healthy source fails this with odds of
    // about 64 x 2^-128. Nothing is printed.
    #[test]
    fn os_source_writes_every_byte_position() {
        let mut source = Source::Os;
        let mut through_fill = [0u8; 64];
        let mut through_os_bytes = [0u8; 64];
        for _ in 0..16 {
            let mut read = [0u8; 64];
            assert_eq!(source.fill(&mut read), Ok(()));
            for (seen, byte) in through_fill.iter_mut().zip(read) {
                *seen |= byte;
            }
            match source.os_bytes::<64>() {
                Ok(bytes) => {
                    for (seen, byte) in through_os_bytes.iter_mut().zip(bytes.iter()) {
                        *seen |= byte;
                    }
                }
                Err(e) => panic!("{e}"),
            }
        }
        for (name, seen) in [("fill", through_fill), ("os_bytes", through_os_bytes)] {
            let unwritten = seen.iter().filter(|&&b| b == 0).count();
            assert_eq!(unwritten, 0, "{name}: byte positions never written");
        }
    }

    #[cfg(feature = "test-sources")]
    mod stub {
        use super::*;
        use crate::source::{StubEntropy, StubSource, WipeProbe};
        use crate::test_vectors::hex;

        fn stub(entropy: StubEntropy) -> Source {
            Source::Stub(StubSource::new(entropy, &WipeProbe::new()))
        }

        #[test]
        fn fixed_serves_exactly_its_bytes_then_fails() {
            let mut source = stub(StubEntropy::Fixed((1..=10).collect()));
            let mut four = [0u8; 4];
            assert_eq!(source.fill(&mut four), Ok(()));
            assert_eq!(four, [1, 2, 3, 4]);
            let mut seven = [0u8; 7];
            assert_eq!(
                source.fill(&mut seven),
                Err(CoreError::Source(SourceFault::Os)),
                "used up"
            );
            let mut six = [0u8; 6];
            assert_eq!(source.fill(&mut six), Ok(()));
            assert_eq!(six, [5, 6, 7, 8, 9, 10]);
            assert_eq!(
                source.fill(&mut [0u8; 1]),
                Err(CoreError::Source(SourceFault::Os))
            );
            assert_eq!(source.fill(&mut []), Ok(()), "an empty read is exact");
        }

        #[test]
        fn stream_is_the_keepcrypt_json_counter_mode() {
            let vector = &keepcrypt_json()["streams"][0];
            let label = vector["label_ascii"]
                .as_str()
                .expect("label")
                .as_bytes()
                .to_vec();
            let want = hex(&vector["hex"]);
            assert_eq!(want.len(), 100);
            let mut source = stub(StubEntropy::Stream(label));
            let mut got = vec![0u8; 100];
            let (a, b) = got.split_at_mut(7);
            assert_eq!(source.fill(a), Ok(()));
            assert_eq!(source.fill(b), Ok(()));
            assert_eq!(got, want, "reads split anywhere continue the same stream");
        }

        #[test]
        fn fail_fail_at_and_short_after() {
            let mut fail = stub(StubEntropy::Fail);
            assert_eq!(
                fail.fill(&mut [0u8; 1]),
                Err(CoreError::Source(SourceFault::Os))
            );
            let mut fail_at = stub(StubEntropy::FailAt(2));
            assert_eq!(fail_at.fill(&mut [0u8; 64]), Ok(()));
            assert_eq!(fail_at.fill(&mut [0u8; 8]), Ok(()));
            assert_eq!(
                fail_at.fill(&mut [0u8; 8]),
                Err(CoreError::Source(SourceFault::Os))
            );
            assert_eq!(
                fail_at.fill(&mut [0u8; 8]),
                Err(CoreError::Source(SourceFault::Os))
            );
            let mut short = stub(StubEntropy::ShortAfter(10));
            assert_eq!(short.fill(&mut [0u8; 8]), Ok(()));
            assert_eq!(
                short.fill(&mut [0u8; 8]),
                Err(CoreError::Source(SourceFault::ShortRead))
            );
            assert_eq!(
                short.fill(&mut [0u8; 1]),
                Err(CoreError::Source(SourceFault::ShortRead))
            );
        }

        #[test]
        fn os_bytes_is_one_exact_read() {
            let mut source = stub(StubEntropy::Fixed(vec![9, 8, 7, 6, 5, 4, 3, 2]));
            match source.os_bytes::<8>() {
                Ok(bytes) => assert_eq!(*bytes, [9, 8, 7, 6, 5, 4, 3, 2]),
                Err(e) => panic!("{e}"),
            }
            assert!(matches!(
                source.os_bytes::<1>(),
                Err(CoreError::Source(SourceFault::Os))
            ));
        }
    }
}
