//! The typestate ceremony session (CLAUDE.md rules 3, 5 and 6; docs/build-plan.md "Public API"
//! as refined by tasks/todo.md, M1 Q5; docs/seal-watchonly-braille.md "Ceremony order", "Go-ahead
//! before reveal").
//!
//! `Collecting -> Committed -> Rolling -> Sealed -> (Checking) -> Ready`. Each state is an
//! uninhabited type behind a sealed trait, so only this module can name a transition. One
//! `Box<Inner>` holds every secret at fixed capacity; dropping the session, on any path (an `Err`,
//! a panic that unwinds, or plain scope exit), zeroizes it.
//!
//! - **Errors (Q5).** Every method that can fail on randomness, a health test, a known-answer test
//!   or an integrity check takes `self`: `add_hw_samples`, `commit`, `push_roll`, `finish`,
//!   `start_check`, `reveal`, `Wiped::restart`, and on `Ready` the five exports. An `Err` has
//!   already dropped the session's `Box<Inner>` and zeroized it. Only user input keeps the session
//!   alive: a go-ahead that does not verify (`Rejected::Retry`, same nonce), `check_readback` and
//!   `verify_backup`.
//! - **Order.** `Sealed` and `Checking` expose no mnemonic, D, backup or export. Skip
//!   (`skip_check`) exists only on `Sealed`. Once a check starts, `reveal` with a verified go-ahead
//!   is the only way to `Ready`; a collision (`Rejected::Collision`) and `discard` wipe the seed
//!   unseen and leave a `Wiped`. tests/typestate.rs proves the order with compile-fail fixtures.
//! - **Read-back gate (Q5, Q13 b).** `check_readback` records each position that reads back as
//!   a match, and a later mismatch clears it. The five exports (`generate_backup_passphrase`,
//!   `encrypt_backup`, `watch_only`, `registration`, `reveal_device_leg`) return
//!   `ReadbackIncomplete` until every word has matched; calling one early is a shell-order bug, so
//!   it wipes the session like any other `Err`. `verify_backup` stays ungated: only a file the gated
//!   `encrypt_backup` wrote can pass it.
//! - **The two calls that never wipe (Q13 b).** `check_readback` returns only
//!   `Braille(BadPosition)` and `Braille(MalformedReadback)`. `verify_backup` returns only
//!   `NoBackupPassphrase`, `WrongPassphrase`, `ReadbackMismatch` and `Backup(_)` for every input; a
//!   unit test below pins both lists over every vectors file input. `verify_backup` keeps
//!   `Internal(_)` paths that no input reaches, and so they are named here: core's own derivation
//!   from words whose checksum the reader already checked (`seed_from_mnemonic_into`'s
//!   `Internal(Bip39)`, `wallet_summary`'s `Internal(KeyDerivation)` at odds of 2^-128 on a
//!   constant path), and age's fixed-size library calls (scrypt's 32-byte output, HKDF's 32-byte
//!   expand, an HMAC key: `Internal(Length)`).
//! - **Panics.** Core never panics on public input (tests/no_panic.rs sweeps hostile input). If a
//!   panic happens anyway, it unwinds (the release profile states `panic = "unwind"`), and the
//!   unwind drops the session's `Box<Inner>`, which zeroizes it. `catch_unwind` is banned in core
//!   (clippy.toml), so nothing catches a panic and carries on with the session. Note for M5: the
//!   FFI takes the session out of its slot before each call, so a panic leaves no session behind.
//! - **`Wiped` holds no secret.** It keeps the platform, the 99-roll flag (set by a collision, kept
//!   through "Cannot check") and, after a collision only, the destroyed seed's collision report,
//!   whose code is harmless to share because that seed is never used
//!   (docs/seal-watchonly-braille.md "Reporting a collision").

mod inner;
mod wiped;

use core::marker::PhantomData;

use crate::backup::{BackupFile, CreatedBy};
use crate::braille::{BrailleInserts, ReadbackResult};
use crate::descriptor::WatchOnlyExport;
use crate::error::{CoreError, KatId};
use crate::kat::{self, Suite};
use crate::seal::{CheckRequest, SealPublic, SealRegistration};
use crate::secret::{Bip39Passphrase, NewBackupPassphrase, SecretBytes32, SecretMnemonic};
#[cfg(feature = "test-sources")]
use crate::source::StubSource;
use crate::source::{ExtraSource, Source};
use inner::{Inner, Verdict};
pub use wiped::{Discard, GoAhead, Rejected, Wiped};

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
/// printed, and it exists only through `new` (or `Wiped::restart`).
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

    /// The same session in its next state: the one `Box<Inner>` moves, nothing is copied.
    fn into_state<T: State>(self) -> Session<T> {
        Session {
            inner: self.inner,
            state: PhantomData,
        }
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
            false,
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
            false,
        )
    }

    /// The one constructor body, for `new` and `Wiped::restart`. `Inner` exists before the suite
    /// runs, so a failing suite drops it like every other `Err`: zeroized, and counted by a stub's
    /// wipe probe.
    fn start(
        config: Config,
        source: Source,
        kat_fault: Option<KatId>,
        after_collision: bool,
    ) -> Result<Self, CoreError> {
        let inner = Inner::new(config, source, after_collision);
        kat::run(Suite::Full, kat_fault)?;
        Ok(Session {
            inner,
            state: PhantomData,
        })
    }

    /// Adds a chunk of raw hwrng samples (Pi, Mixed mode only; else `NotInThisMode`). The chunk is
    /// health-tested whole first; its samples after the 1,024 startup samples then go into the pool
    /// as one record. Any `Err` (a health-test failure among them) has wiped the session.
    pub fn add_hw_samples(mut self, raw: &[u8]) -> Result<Self, CoreError> {
        self.inner.add_hw_samples(raw)?;
        Ok(self)
    }

    /// Mixes an extra input into the pool, uncredited (docs/design.md "Evaluating the proposed
    /// sources"); in dice-only mode it does nothing. Extras reach the pool only until `commit`,
    /// because C fixes D.
    pub fn add_extra(&mut self, source: ExtraSource, bytes: &[u8]) {
        self.inner.add_extra(source, bytes);
    }

    /// The credited device-leg bits `commit` will count: health-tested hwrng in completed windows
    /// (0 until 1,536 samples, then 2,048 at once on the Pi) plus the OS read's policy credit (256
    /// on a phone). 0 in dice-only mode.
    pub fn credited_bits(&self) -> u64 {
        self.inner.credited_bits()
    }

    /// The credited bits `commit` needs: 512 on the Pi, 256 on a phone, 0 in dice-only mode.
    pub fn required_bits(&self) -> u64 {
        self.inner.required_bits()
    }

    /// hwrng samples health-tested so far, toward `HW_BYTES_NEEDED` (the Pi's progress bar).
    pub fn hw_bytes_tested(&self) -> u64 {
        self.inner.hw_bytes_tested()
    }

    /// Fixes the device leg: below the quota it is `QuotaUnmet`; otherwise 64 fresh OS bytes are
    /// absorbed last and D and C are derived (Mixed mode). Dice-only mode reads nothing. Any `Err`
    /// has wiped the session.
    pub fn commit(mut self) -> Result<Session<Committed>, CoreError> {
        self.inner.commit()?;
        Ok(self.into_state())
    }
}

impl Session<Committed> {
    /// C = SHA256("KCE/v1/commit" || D), safe to display before any roll; None in dice-only mode.
    pub fn commitment(&self) -> Option<[u8; 32]> {
        self.inner.commitment()
    }

    /// Opens dice entry.
    pub fn start_dice(self) -> Session<Rolling> {
        self.into_state()
    }
}

impl Session<Rolling> {
    /// Adds one roll, a face 1 to 6. Any other face is `InvalidRoll` and a 257th roll is
    /// `TooManyRolls`; either has wiped the session.
    pub fn push_roll(mut self, face: u8) -> Result<Self, CoreError> {
        self.inner.push_roll(face)?;
        Ok(self)
    }

    /// Removes the last roll; nothing happens when there is none.
    pub fn undo_roll(&mut self) {
        self.inner.undo_roll();
    }

    /// Rolls so far.
    pub fn rolls(&self) -> u16 {
        self.inner.rolls()
    }

    /// Bits so far in thousandths: rolls x 2,585.
    pub fn millibits(&self) -> u32 {
        self.inner.millibits()
    }

    /// The fewest rolls `finish` accepts: 50 for 12 words, 99 for 24, and 99 for either after a
    /// collision.
    pub fn minimum_rolls(&self) -> u16 {
        self.inner.minimum_rolls()
    }

    /// Makes the seed: E, the words, S, the seal, the fingerprint and the first address, once;
    /// then R is zeroized. Below the minimum it is `TooFewRolls`. Any `Err` has wiped the session.
    pub fn finish(mut self) -> Result<Session<Sealed>, CoreError> {
        self.inner.finish()?;
        Ok(self.into_state())
    }
}

impl Session<Sealed> {
    /// The public seal: T, the Seal ID and its braille caption, the 8x8 image and the re-check URL.
    pub fn seal(&self) -> &SealPublic {
        self.inner.seal()
    }

    /// "Skip": reveal the words without a check. Offered only here, before a check starts.
    pub fn skip_check(self) -> Session<Ready> {
        self.into_state()
    }

    /// "Check now": draws a fresh 8-byte nonce n. From here only a verified go-ahead reaches the
    /// words. An `Err` (the source failed) has wiped the session.
    pub fn start_check(mut self) -> Result<Session<Checking>, CoreError> {
        self.inner.start_check()?;
        Ok(self.into_state())
    }
}

impl Session<Checking> {
    /// The public seal, as in `Sealed`.
    pub fn seal(&self) -> &SealPublic {
        self.inner.seal()
    }

    /// The seal card's check QR: `<origin>/check#t=<T>&n=<n>`.
    pub fn check_request(&self) -> CheckRequest {
        self.inner.check_request()
    }

    /// Reveals the words only for a verified go-ahead: this check's code, or a loaded snapshot or
    /// verified proof that does not hold T. A code that does not verify, or a proof for another
    /// bucket, is `Rejected::Retry` with the session and the same nonce. A snapshot or proof that
    /// holds T is `Rejected::Collision`: the seed is wiped unseen, and the `Wiped` keeps the
    /// collision report and the 99-roll minimum for the restart. A passed check ends that minimum:
    /// no `Wiped`, and so no restart, follows `Ready`.
    pub fn reveal(self, go: GoAhead<'_>) -> Result<Session<Ready>, Rejected> {
        match self.inner.judge(go) {
            Verdict::Clear => Ok(self.into_state()),
            Verdict::Retry(e) => Err(Rejected::Retry(self, e)),
            Verdict::Collision => Err(Rejected::Collision(Wiped::from_check(
                self,
                Discard::Collision,
            ))),
        }
    }

    /// Stop: "Match found" (`Discard::Collision`: keeps the report and the 99-roll minimum) or
    /// "Cannot check" (`Discard::CannotCheck`: keeps no report, and this session's own 99-roll
    /// minimum, so a restart after a collision keeps 99 rolls). The seed is wiped unseen.
    pub fn discard(self, why: Discard) -> Wiped {
        Wiped::from_check(self, why)
    }
}

impl Session<Ready> {
    /// The words: show them only on a protected screen.
    pub fn mnemonic(&self) -> &SecretMnemonic {
        self.inner.mnemonic()
    }

    /// The braille inserts: faces 1-5 with blanks, SeedBook numbers and mirror flags. They borrow
    /// the session.
    pub fn braille(&self) -> BrailleInserts<'_> {
        self.inner.braille()
    }

    /// The master key fingerprint (empty passphrase).
    pub fn fingerprint(&self) -> [u8; 4] {
        self.inner.fingerprint()
    }

    /// The first receive address, m/84'/0'/0'/0/0 (empty passphrase).
    pub fn first_address(&self) -> &str {
        self.inner.first_address()
    }

    /// Compares the first three or four letters read back from the insert at `position` (1-based)
    /// with its word and records the result: a match counts toward the read-back gate, a mismatch
    /// clears that position. Never wipes. Errors: `Braille(BadPosition)` and
    /// `Braille(MalformedReadback)` only, which record nothing.
    pub fn check_readback(
        &mut self,
        position: u8,
        first_four: &str,
    ) -> Result<ReadbackResult, CoreError> {
        self.inner.check_readback(position, first_four)
    }

    /// Whether every word has read back as a match: the gate in front of the five exports.
    pub fn readback_complete(&self) -> bool {
        self.inner.readback_complete()
    }

    /// Reads a saved backup back with the stored passphrase and checks that it holds this seed
    /// (the words and the fingerprint). Never wipes: a failure is retryable. Not gated: only a file
    /// the gated `encrypt_backup` wrote can pass. Errors: `NoBackupPassphrase`, `WrongPassphrase`,
    /// `ReadbackMismatch`, and `Backup(_)` for a malformed file, for every input; the `Internal(_)`
    /// paths no input reaches are named in the module comment.
    pub fn verify_backup(&self, file: &[u8]) -> Result<(), CoreError> {
        self.inner.verify_backup(file)
    }

    /// Generates the 8-word backup passphrase (11 fresh OS bytes) and its 2-of-4 confirm challenge
    /// in one call, and keeps the passphrase for `encrypt_backup` and `verify_backup`, replacing
    /// any earlier one. Returns the session and a display copy for the user to write down.
    /// `ReadbackIncomplete` before every word has read back; any `Err` (also a source failure, or
    /// `Source(NoUsableDraw)`) has wiped the session.
    pub fn generate_backup_passphrase(mut self) -> Result<(Self, NewBackupPassphrase), CoreError> {
        self.inner.require_readback()?;
        let new = self.inner.generate_backup_passphrase()?;
        Ok((self, new))
    }

    /// Writes the encrypted backup under the stored passphrase, with a fresh file key, salt, nonce
    /// and file name. Returns the session and the file for the shell to save; after a failed save
    /// the shell may call this again, and the paper passphrase stays valid. `ReadbackIncomplete`
    /// before every word has read back and `NoBackupPassphrase` before
    /// `generate_backup_passphrase` are shell-order bugs and, like every `Err`, have wiped the
    /// session.
    pub fn encrypt_backup(mut self, by: &CreatedBy) -> Result<(Self, BackupFile), CoreError> {
        self.inner.require_readback()?;
        let file = self.inner.encrypt_backup(by)?;
        Ok((self, file))
    }

    /// The watch-only export (account QR and descriptors) of this seed, or, with a BIP39
    /// passphrase, of that passphrase's wallet. The backup and the seal never see the passphrase.
    /// `ReadbackIncomplete` before every word has read back; any `Err` (also `ExportSelfCheck`) has
    /// wiped the session.
    pub fn watch_only(
        self,
        bip39_passphrase: Option<&Bip39Passphrase>,
    ) -> Result<(Self, WatchOnlyExport), CoreError> {
        self.inner.require_readback()?;
        let export = self.inner.watch_only(bip39_passphrase)?;
        Ok((self, export))
    }

    /// The "Register seal" QR: the seal code and the register URL. `ReadbackIncomplete` before
    /// every word has read back, which has wiped the session.
    pub fn registration(self) -> Result<(Self, SealRegistration), CoreError> {
        self.inner.require_readback()?;
        let registration = self.inner.registration();
        Ok((self, registration))
    }

    /// D, for offline audit; None in dice-only mode. `ReadbackIncomplete` before every word has
    /// read back, which has wiped the session.
    pub fn reveal_device_leg(self) -> Result<(Self, Option<SecretBytes32>), CoreError> {
        self.inner.require_readback()?;
        let d = self.inner.reveal_device_leg();
        Ok((self, d))
    }
}

#[cfg(test)]
impl Session<Ready> {
    /// A `Ready` session holding these words on `source`, as `finish` leaves one: words, S, the
    /// seal, the fingerprint and the first address, nothing read back yet. Tests only: the backup
    /// tests need given words, which no dice string gives.
    pub(crate) fn ready_for_test(indices: &[usize], source: Source) -> Result<Self, CoreError> {
        let len = match indices.len() {
            24 => SeedLength::Words24,
            _ => SeedLength::Words12,
        };
        let config = Config {
            len,
            mode: Mode::DiceOnly,
            platform: Platform::Phone,
        };
        let mut inner = Inner::new(config, source, false);
        inner.fill_words_for_test(indices)?;
        Ok(Session {
            inner,
            state: PhantomData,
        })
    }

    /// Reads every insert back from its own faces through `check_readback`, as a user at the metal
    /// would, so the read-back gate opens the honest way (tests only).
    pub(crate) fn read_back_every_word_for_test(&mut self) {
        let typed: Vec<(u8, String)> = self
            .braille()
            .iter()
            .map(|insert| (insert.position(), insert.word().chars().take(4).collect()))
            .collect();
        for (position, letters) in typed {
            assert!(matches!(
                self.check_readback(position, &letters),
                Ok(ReadbackResult::Match)
            ));
        }
        assert!(self.readback_complete());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BrailleError;
    use crate::test_vectors::{keepcrypt_json, named, read, text};

    /// keepcrypt.json's dice-only roll string `name`, as faces.
    fn faces(name: &str) -> Vec<u8> {
        text(&named(&keepcrypt_json()["dice_only"], name)["rolls"])
            .bytes()
            .map(|b| b - b'0')
            .collect()
    }

    fn roll_all(mut rolling: Session<Rolling>, faces: &[u8]) -> Session<Rolling> {
        for &face in faces {
            rolling = match rolling.push_roll(face) {
                Ok(next) => next,
                Err(e) => panic!("{e}"),
            };
        }
        rolling
    }

    /// A dice-only session on the OS source through `finish`, from keepcrypt.json's roll string.
    fn sealed_dice_only(len: SeedLength, rolls: &str) -> Session<Sealed> {
        let mut session = Session::new(len, Mode::DiceOnly, Platform::Phone).expect("a session");
        session.add_extra(ExtraSource::Motion, b"ignored in dice-only mode");
        assert_eq!((session.credited_bits(), session.required_bits()), (0, 0));
        let committed = session.commit().expect("committed");
        assert_eq!(committed.commitment(), None, "no D in dice-only mode");
        let rolling = roll_all(committed.start_dice(), &faces(rolls));
        rolling.finish().expect("sealed")
    }

    fn words(session: &Session<Ready>) -> Vec<&str> {
        session.mnemonic().words().collect()
    }

    fn listed(v: &serde_json::Value) -> Vec<&str> {
        v.as_array()
            .expect("a word list")
            .iter()
            .map(text)
            .collect()
    }

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

    // Dice only, on the OS source: no OS read, no D; E = SHA-256(R) gives keepcrypt.json's words
    // and kcr.json's seal for the 50-roll string, and Skip reveals them.
    #[test]
    fn a_dice_only_ceremony_skips_to_ready() {
        let sealed = sealed_dice_only(SeedLength::Words12, "coldcard-50");
        let kcr = read("kcr.json");
        let seed = named(&kcr["seeds"], "dice-50-words12");
        assert_eq!(sealed.seal().tag().to_hex(), text(&seed["seal_tag_hex"]));
        assert_eq!(sealed.seal().seal_id(), text(&seed["seal_id"]));
        let ready = sealed.skip_check();
        let doc = keepcrypt_json();
        let case = named(&doc["dice_only"], "coldcard-50");
        assert_eq!(words(&ready), listed(&case["words_12"]));
        assert_eq!(
            ready.mnemonic().words().collect::<Vec<_>>().join(" "),
            text(&seed["mnemonic"])
        );
        assert!(ready.first_address().starts_with("bc1q"));
        assert_eq!(ready.braille().count(), 12);
        assert!(!ready.readback_complete());
    }

    // 24 words from the 99-roll string, and the dice screen's counts along the way.
    #[test]
    fn rolling_counts_undo_and_minimums() {
        let committed = Session::new(SeedLength::Words24, Mode::DiceOnly, Platform::Pi)
            .and_then(Session::commit)
            .expect("committed");
        let mut rolling = committed.start_dice();
        assert_eq!(rolling.minimum_rolls(), 99);
        rolling.undo_roll();
        assert_eq!(rolling.rolls(), 0, "undo with no rolls does nothing");
        let mut rolling = roll_all(rolling, &[6, 6, 1]);
        rolling.undo_roll();
        assert_eq!((rolling.rolls(), rolling.millibits()), (2, 5_170));
        rolling.undo_roll();
        rolling.undo_roll();
        let rolling = roll_all(rolling, &faces("coldcard-99"));
        assert_eq!(rolling.rolls(), 99);
        let ready = rolling.finish().expect("sealed").skip_check();
        let doc = keepcrypt_json();
        let case = named(&doc["dice_only"], "coldcard-99");
        assert_eq!(words(&ready), listed(&case["words_24"]));
        let kcr = read("kcr.json");
        let seed = named(&kcr["seeds"], "dice-99-words24");
        assert_eq!(
            ready.mnemonic().words().collect::<Vec<_>>().join(" "),
            text(&seed["mnemonic"])
        );
        assert_eq!(ready.braille().device_count(), 2);
    }

    // The read-back gate: each of the five exports is ReadbackIncomplete until every word has read
    // back (each such call wipes the session, so each gets its own); a mismatch clears a position,
    // input errors record nothing; once complete, the exports work.
    #[test]
    fn the_read_back_gate() {
        type Export = fn(Session<Ready>) -> Result<(), CoreError>;
        let exports: [(&str, Export); 5] = [
            ("generate_backup_passphrase", |s| {
                s.generate_backup_passphrase().map(|_| ())
            }),
            ("encrypt_backup", |s| {
                s.encrypt_backup(&CreatedBy::new(crate::backup::BackupApp::Pi, 1, 0, 0))
                    .map(|_| ())
            }),
            ("watch_only", |s| s.watch_only(None).map(|_| ())),
            ("registration", |s| s.registration().map(|_| ())),
            ("reveal_device_leg", |s| s.reveal_device_leg().map(|_| ())),
        ];
        for (name, export) in exports {
            let mut ready = sealed_dice_only(SeedLength::Words12, "coldcard-50").skip_check();
            // Eleven of twelve words is not enough.
            let typed: Vec<String> = ready
                .braille()
                .iter()
                .map(|i| i.word().chars().take(4).collect())
                .collect();
            for (position, letters) in (1u8..12).zip(&typed) {
                assert!(matches!(
                    ready.check_readback(position, letters),
                    Ok(ReadbackResult::Match)
                ));
            }
            assert!(!ready.readback_complete());
            assert_eq!(export(ready), Err(CoreError::ReadbackIncomplete), "{name}");
        }

        let mut ready = sealed_dice_only(SeedLength::Words12, "coldcard-50").skip_check();
        ready.read_back_every_word_for_test();
        // A mismatch at position 3 clears it; input errors leave it as it was.
        let third = ready
            .braille()
            .insert(3)
            .expect("an insert")
            .word()
            .to_owned();
        let wrong = if third.starts_with('z') { "abc" } else { "zzz" };
        assert!(matches!(
            ready.check_readback(3, wrong),
            Ok(ReadbackResult::Mismatch(_))
        ));
        assert!(!ready.readback_complete());
        for (position, typed, error) in [
            (0, "abc", BrailleError::BadPosition),
            (13, "abc", BrailleError::BadPosition),
            (3, "ab", BrailleError::MalformedReadback),
            (3, "ab1c", BrailleError::MalformedReadback),
        ] {
            assert!(matches!(
                ready.check_readback(position, typed),
                Err(CoreError::Braille(e)) if e == error
            ));
        }
        assert!(!ready.readback_complete());
        let letters: String = third.chars().take(4).collect();
        assert!(matches!(
            ready.check_readback(3, &letters.to_ascii_uppercase()),
            Ok(ReadbackResult::Match)
        ));
        assert!(ready.readback_complete());
        let (ready, d) = ready.reveal_device_leg().expect("revealed");
        assert!(d.is_none(), "no D in dice-only mode");
        let (ready, registration) = ready.registration().expect("registration");
        assert!(
            registration
                .url()
                .ends_with(&registration.grouped_code().replace('-', ""))
        );
        assert_eq!(registration.seal_id(), "YVM9CPP3");
        let (_, export) = ready.watch_only(None).expect("an export");
        assert!(!export.passphrase_used());
    }

    // Read-back with an empty mnemonic never opens the gate (no state holds one; defence in depth).
    #[test]
    fn no_words_never_reads_back_complete() {
        let inner = Inner::new(
            Config {
                len: SeedLength::Words12,
                mode: Mode::Mixed,
                platform: Platform::Phone,
            },
            Source::Os,
            false,
        );
        let ready: Session<Ready> = Session {
            inner,
            state: PhantomData,
        };
        assert!(!ready.readback_complete());
        assert_eq!(
            ready.registration().map(|_| ()),
            Err(CoreError::ReadbackIncomplete)
        );
    }

    // A pool failure in add_extra, which no slice length can cause, is planted: commit returns it.
    #[test]
    fn a_kept_extra_fault_fails_commit() {
        let mut session =
            Session::new(SeedLength::Words12, Mode::Mixed, Platform::Phone).expect("a session");
        let fault = CoreError::Internal(crate::error::InternalFault::Length);
        session.inner.plant_extra_fault_for_test(fault);
        session.add_extra(ExtraSource::Motion, b"after the fault");
        assert!(matches!(session.commit(), Err(e) if e == fault));
    }

    // Phone, Mixed, on the OS source: the OS read alone meets the quota by policy; C is shown, and
    // two sessions differ (the real OS path).
    #[test]
    fn a_phone_commits_on_the_os_read() {
        let commit = || {
            let mut session =
                Session::new(SeedLength::Words12, Mode::Mixed, Platform::Phone).expect("a session");
            assert_eq!(
                (session.credited_bits(), session.required_bits()),
                (256, 256)
            );
            session.add_extra(ExtraSource::InputTiming, &[1, 2, 3]);
            assert_eq!(session.credited_bits(), 256, "extras are never credited");
            session
                .commit()
                .expect("committed")
                .commitment()
                .expect("C")
        };
        assert_ne!(commit(), commit());
    }

    #[cfg(feature = "test-sources")]
    mod stub {
        use super::*;
        use crate::backup::{age, armor};
        use crate::error::{CheckError, SourceFault};
        use crate::seal::{verify_bucket_proof, verify_snapshot};
        use crate::source::{StubEntropy, WipeProbe};
        use crate::test_vectors::hex;
        use serde_json::Value;

        fn stub(entropy: StubEntropy, probe: &WipeProbe) -> StubSource {
            StubSource::new(entropy, probe)
        }

        /// A dice-only 12-word session from the 50-roll string on a stub, through `finish`.
        fn sealed_on(entropy: StubEntropy, probe: &WipeProbe) -> Session<Sealed> {
            let committed = Session::new_with_stub(
                SeedLength::Words12,
                Mode::DiceOnly,
                Platform::Phone,
                stub(entropy, probe),
                None,
            )
            .and_then(Session::commit)
            .expect("committed");
            roll_all(committed.start_dice(), &faces("coldcard-50"))
                .finish()
                .expect("sealed")
        }

        /// keepcrypt.json's name for an extra source.
        fn extra_source(name: &Value) -> ExtraSource {
            match text(name) {
                "input_timing" => ExtraSource::InputTiming,
                "motion" => ExtraSource::Motion,
                "camera" => ExtraSource::Camera,
                "microphone" => ExtraSource::Microphone,
                other => panic!("no extra source {other}"),
            }
        }

        /// kcr.json's seed `name`.
        fn kcr_seed(name: &str) -> Value {
            named(&read("kcr.json")["seeds"], name).clone()
        }

        #[test]
        fn every_kat_fault_fails_new_and_wipes_once() {
            for id in KatId::ALL {
                let probe = WipeProbe::new();
                let result = Session::new_with_stub(
                    SeedLength::Words12,
                    Mode::Mixed,
                    Platform::Pi,
                    stub(StubEntropy::Fail, &probe),
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
            match Session::new_with_stub(
                SeedLength::Words24,
                Mode::DiceOnly,
                Platform::Phone,
                stub(StubEntropy::Stream(b"session".to_vec()), &probe),
                None,
            ) {
                Ok(session) => {
                    assert_eq!(probe.wipes(), 0);
                    assert_eq!(session.seed_length(), SeedLength::Words24);
                    let moved = session.commit().expect("committed").start_dice();
                    assert_eq!(moved.mode(), Mode::DiceOnly);
                }
                Err(e) => panic!("{e}"),
            }
            assert_eq!(probe.wipes(), 1);
        }

        // The Pi's source-substitution session: keepcrypt.json's events give its tested-byte count,
        // credit, D and C, and exactly 64 OS bytes are read.
        #[test]
        fn the_pi_session_gives_its_d_and_c() {
            let case = named(&keepcrypt_json()["source_substitution"], "pi").clone();
            let probe = WipeProbe::new();
            let mut session = Session::new_with_stub(
                SeedLength::Words12,
                Mode::Mixed,
                Platform::Pi,
                stub(StubEntropy::Fixed(hex(&case["os_hex"])), &probe),
                None,
            )
            .expect("a session");
            assert_eq!((session.credited_bits(), session.required_bits()), (0, 512));
            for event in case["events"].as_array().expect("events") {
                let data = hex(&event["data_hex"]);
                session = match text(&event["kind"]) {
                    "hwrng" => session.add_hw_samples(&data).expect("healthy"),
                    _ => {
                        session.add_extra(extra_source(&event["source"]), &data);
                        session
                    }
                };
            }
            assert_eq!(session.hw_bytes_tested(), case["hw_bytes_tested"]);
            assert_eq!(session.credited_bits(), 2_048);
            let committed = session.commit().expect("committed");
            assert_eq!(
                committed.commitment().map(|c| c.to_vec()),
                Some(hex(&case["c_hex"]))
            );
            let mut rolling = roll_all(committed.start_dice(), &faces("coldcard-50"));
            assert_eq!(rolling.minimum_rolls(), 50);
            rolling.undo_roll();
            assert_eq!(rolling.finish().map(|_| ()), Err(CoreError::TooFewRolls));
            assert_eq!(probe.wipes(), 1);
        }

        // Each wrong call or failing source wipes the session once, with its exact error.
        #[test]
        fn every_failing_transition_wipes_once() {
            type Case = (&'static str, fn(StubSource) -> CoreError);
            let cases: [Case; 8] = [
                ("hwrng on a phone", |s| {
                    Session::new_with_stub(
                        SeedLength::Words12,
                        Mode::Mixed,
                        Platform::Phone,
                        s,
                        None,
                    )
                    .and_then(|s| s.add_hw_samples(&[1]))
                    .map(|_| ())
                    .expect_err("refused")
                }),
                ("hwrng in dice-only mode", |s| {
                    Session::new_with_stub(
                        SeedLength::Words12,
                        Mode::DiceOnly,
                        Platform::Pi,
                        s,
                        None,
                    )
                    .and_then(|s| s.add_hw_samples(&[1]))
                    .map(|_| ())
                    .expect_err("refused")
                }),
                ("a stuck hwrng", |s| {
                    Session::new_with_stub(SeedLength::Words12, Mode::Mixed, Platform::Pi, s, None)
                        .and_then(|s| s.add_hw_samples(&[7; 6]))
                        .map(|_| ())
                        .expect_err("refused")
                }),
                ("a Pi below its quota", |s| {
                    Session::new_with_stub(SeedLength::Words12, Mode::Mixed, Platform::Pi, s, None)
                        .and_then(Session::commit)
                        .map(|_| ())
                        .expect_err("refused")
                }),
                ("the OS failing at commit", |s| {
                    Session::new_with_stub(
                        SeedLength::Words12,
                        Mode::Mixed,
                        Platform::Phone,
                        s,
                        None,
                    )
                    .and_then(Session::commit)
                    .map(|_| ())
                    .expect_err("refused")
                }),
                ("face 0", |s| {
                    Session::new_with_stub(
                        SeedLength::Words12,
                        Mode::DiceOnly,
                        Platform::Phone,
                        s,
                        None,
                    )
                    .and_then(Session::commit)
                    .and_then(|c| c.start_dice().push_roll(0))
                    .map(|_| ())
                    .expect_err("refused")
                }),
                ("finish at 0", |s| {
                    Session::new_with_stub(
                        SeedLength::Words12,
                        Mode::DiceOnly,
                        Platform::Phone,
                        s,
                        None,
                    )
                    .and_then(Session::commit)
                    .and_then(|c| c.start_dice().finish())
                    .map(|_| ())
                    .expect_err("refused")
                }),
                ("the OS failing at start_check", |s| {
                    let committed = Session::new_with_stub(
                        SeedLength::Words12,
                        Mode::DiceOnly,
                        Platform::Phone,
                        s,
                        None,
                    )
                    .and_then(Session::commit)
                    .expect("committed");
                    roll_all(committed.start_dice(), &faces("coldcard-50"))
                        .finish()
                        .and_then(Session::start_check)
                        .map(|_| ())
                        .expect_err("refused")
                }),
            ];
            let want = [
                CoreError::NotInThisMode,
                CoreError::NotInThisMode,
                CoreError::Health(crate::error::HealthFailure {
                    test: crate::error::HealthTest::RepetitionCount,
                    stage: crate::error::HealthStage::Startup,
                    sample: 5,
                }),
                CoreError::QuotaUnmet,
                CoreError::Source(SourceFault::Os),
                CoreError::InvalidRoll,
                CoreError::TooFewRolls,
                CoreError::Source(SourceFault::Os),
            ];
            for ((name, case), want) in cases.into_iter().zip(want) {
                let probe = WipeProbe::new();
                assert_eq!(case(stub(StubEntropy::Fail, &probe)), want, "{name}");
                assert_eq!(probe.wipes(), 1, "{name}");
            }
        }

        // The check: the nonce comes from the source; a typo keeps the session and the nonce; the
        // right code reveals the words.
        #[test]
        fn a_typo_then_the_right_code_reveals() {
            let seed = kcr_seed("dice-50-words12");
            let probe = WipeProbe::new();
            let checking = sealed_on(StubEntropy::Fixed(hex(&seed["nonce_hex"])), &probe)
                .start_check()
                .expect("checking");
            let url = format!(
                "https://registry.invalid/check#t={}&n={}",
                text(&seed["seal_tag_hex"]),
                text(&seed["nonce_hex"])
            );
            assert_eq!(checking.check_request().url(), url);
            let checking = match checking.reveal(GoAhead::Code("PBJN-YZY6")) {
                Err(Rejected::Retry(session, CheckError::WrongCode)) => session,
                Err(other) => panic!("{other:?}"),
                Ok(_) => panic!("revealed"),
            };
            let checking = match checking.reveal(GoAhead::Code("PBJN")) {
                Err(Rejected::Retry(session, CheckError::MalformedCode)) => session,
                Err(other) => panic!("{other:?}"),
                Ok(_) => panic!("revealed"),
            };
            assert_eq!(checking.check_request().url(), url, "the same nonce");
            assert_eq!(probe.wipes(), 0);
            let ready = match checking.reveal(GoAhead::Code(text(&seed["go_ahead"]))) {
                Ok(ready) => ready,
                Err(e) => panic!("{e:?}"),
            };
            assert_eq!(
                ready.mnemonic().words().collect::<Vec<_>>().join(" "),
                text(&seed["mnemonic"])
            );
            drop(ready);
            assert_eq!(probe.wipes(), 1);
        }

        /// kcr.json's snapshot or proof `name`, verified under the test registry key.
        fn kcr_bytes(section: &str, name: &str) -> Vec<u8> {
            let doc = read("kcr.json");
            let case = named(&doc[section], name);
            hex(&case[if section == "snapshots" {
                "kcr_hex"
            } else {
                "kcp1_hex"
            }])
        }

        // Evidence that holds T is a collision: the seed is wiped unseen, the Wiped keeps the
        // report with this seed's code, and restart asks for 99 rolls for either length. Clear
        // evidence reveals; a proof for another bucket is Retry.
        #[test]
        fn collision_evidence_wipes_and_restart_asks_for_99() {
            let seed = kcr_seed("dice-50-words12");
            let snapshot = verify_snapshot(&kcr_bytes("snapshots", "with-dice-50")).expect("valid");
            let proof =
                verify_bucket_proof(&kcr_bytes("proofs", "collision-dice-50")).expect("valid");
            let clear = verify_snapshot(&kcr_bytes("snapshots", "small")).expect("valid");
            let other_bucket =
                verify_bucket_proof(&kcr_bytes("proofs", "clear-shared-prefix")).expect("valid");
            for evidence in [GoAhead::Snapshot(&snapshot), GoAhead::BucketProof(&proof)] {
                let probe = WipeProbe::new();
                let checking = sealed_on(StubEntropy::Fixed(vec![0; 8]), &probe)
                    .start_check()
                    .expect("checking");
                let checking = match checking.reveal(GoAhead::BucketProof(&other_bucket)) {
                    Err(Rejected::Retry(session, CheckError::WrongBucket)) => session,
                    Err(other) => panic!("{other:?}"),
                    Ok(_) => panic!("revealed"),
                };
                let wiped = match checking.reveal(evidence) {
                    Err(Rejected::Collision(wiped)) => wiped,
                    Err(other) => panic!("{other:?}"),
                    Ok(_) => panic!("revealed"),
                };
                assert_eq!(probe.wipes(), 1);
                let report = wiped.collision_report().expect("a report");
                assert_eq!(
                    report.grouped_code(),
                    text(&seed["seal_code"]),
                    "the destroyed seed's code"
                );
                for len in [SeedLength::Words12, SeedLength::Words24] {
                    let rolling = Wiped::from_parts_for_test(Platform::Phone, true)
                        .restart(len, Mode::DiceOnly)
                        .and_then(Session::commit)
                        .expect("restarted")
                        .start_dice();
                    assert_eq!(rolling.minimum_rolls(), 99, "{len:?}");
                }
                let restarted = wiped
                    .restart(SeedLength::Words12, Mode::DiceOnly)
                    .expect("restarted");
                assert_eq!(restarted.platform(), Platform::Phone);
                let rolling = restarted.commit().expect("committed").start_dice();
                assert_eq!(rolling.minimum_rolls(), 99);
                let rolling = roll_all(rolling, &faces("coldcard-50"));
                assert_eq!(rolling.finish().map(|_| ()), Err(CoreError::TooFewRolls));
            }
            let current =
                verify_bucket_proof(&kcr_bytes("proofs", "current-day-30")).expect("valid");
            for evidence in [GoAhead::Snapshot(&clear), GoAhead::BucketProof(&current)] {
                let checking = sealed_on(StubEntropy::Fixed(vec![0; 8]), &WipeProbe::new())
                    .start_check()
                    .expect("checking");
                assert_eq!(checking.seal().tag().to_hex(), text(&seed["seal_tag_hex"]));
                assert!(checking.reveal(evidence).is_ok(), "{evidence:?}");
            }
        }

        // discard: Collision keeps the report and sets the flag; CannotCheck keeps no report and
        // this session's own flag, here none, so its restart uses the normal minimum. The seed is
        // wiped either way. restart re-runs the suite on a fresh source.
        #[test]
        fn discard_and_restart() {
            let probe = WipeProbe::new();
            let checking = sealed_on(StubEntropy::Fixed(vec![0; 8]), &probe)
                .start_check()
                .expect("checking");
            let wiped = checking.discard(Discard::CannotCheck);
            assert_eq!(probe.wipes(), 1);
            assert!(wiped.collision_report().is_none());
            let rolling = wiped
                .restart(SeedLength::Words12, Mode::DiceOnly)
                .and_then(Session::commit)
                .expect("restarted")
                .start_dice();
            assert_eq!(rolling.minimum_rolls(), 50, "the normal minimum");

            let probe = WipeProbe::new();
            let wiped = sealed_on(StubEntropy::Fixed(vec![0; 8]), &probe)
                .start_check()
                .expect("checking")
                .discard(Discard::Collision);
            assert_eq!(probe.wipes(), 1);
            assert!(wiped.collision_report().is_some());
            for id in KatId::ALL {
                let fresh = WipeProbe::new();
                let result = Wiped::from_parts_for_test(Platform::Pi, true).restart_with_stub(
                    SeedLength::Words24,
                    Mode::Mixed,
                    stub(StubEntropy::Fail, &fresh),
                    Some(id),
                );
                assert!(
                    matches!(result, Err(CoreError::Kat(got)) if got == id),
                    "{id:?}"
                );
                assert_eq!(fresh.wipes(), 1, "{id:?}");
            }
            let fresh = WipeProbe::new();
            let restarted = wiped
                .restart_with_stub(
                    SeedLength::Words24,
                    Mode::Mixed,
                    stub(StubEntropy::Fail, &fresh),
                    None,
                )
                .expect("restarted");
            assert_eq!(restarted.platform(), Platform::Phone);
            assert_eq!(
                restarted.commit().map(|_| ()),
                Err(CoreError::Source(SourceFault::Os)),
                "a fresh OS read at commit, on the new source"
            );
            assert_eq!(fresh.wipes(), 1);
        }

        /// A `Wiped` from "Match found" on a stub check: its restart needs 99 rolls.
        fn wiped_by_collision() -> Wiped {
            sealed_on(StubEntropy::Fixed(vec![0; 8]), &WipeProbe::new())
                .start_check()
                .expect("checking")
                .discard(Discard::Collision)
        }

        /// `wiped` restarted at `len` in dice-only mode on a stub, up to the dice.
        fn restarted(
            wiped: Wiped,
            len: SeedLength,
            entropy: StubEntropy,
            probe: &WipeProbe,
        ) -> Session<Rolling> {
            wiped
                .restart_with_stub(len, Mode::DiceOnly, stub(entropy, probe), None)
                .and_then(Session::commit)
                .expect("restarted")
                .start_dice()
        }

        /// The seed of the 99-roll string, then "Cannot check".
        fn cannot_check(rolling: Session<Rolling>) -> Wiped {
            roll_all(rolling, &faces("coldcard-99"))
                .finish()
                .and_then(Session::start_check)
                .expect("checking")
                .discard(Discard::CannotCheck)
        }

        // "Cannot check" keeps the checking session's own flag (tasks/todo.md, "M1: open owner
        // items", item 5): the restart after a collision needs 99 rolls, and so does every restart
        // after a "Cannot check" in it, until a check passes. 12 words tell this apart from the
        // normal minimum (50); 24 words need 99 either way.
        #[test]
        fn cannot_check_after_a_collision_keeps_99_rolls() {
            for len in [SeedLength::Words12, SeedLength::Words24] {
                let mut wiped = wiped_by_collision();
                for cannot_checks in 0..3 {
                    let probe = WipeProbe::new();
                    let rolling = restarted(wiped, len, StubEntropy::Fixed(vec![0; 8]), &probe);
                    let what = format!("{len:?} after {cannot_checks} Cannot check");
                    assert_eq!(rolling.minimum_rolls(), 99, "{what}");
                    wiped = cannot_check(rolling);
                    assert_eq!(probe.wipes(), 1, "{what}");
                    assert!(wiped.collision_report().is_none(), "{what}");
                }
            }
        }

        // A passed check ends the 99-roll minimum: after a collision and a "Cannot check", the
        // 99-roll session's go-ahead code reveals kcr.json's words. No restart can follow:
        // `Ready` has no `discard`, and only a check leaves a `Wiped`, so the next ceremony is a
        // `Session::new`, at the normal minimum.
        #[test]
        fn the_99_roll_minimum_ends_at_a_passed_check() {
            for (len, name) in [
                (SeedLength::Words12, "dice-99-words12"),
                (SeedLength::Words24, "dice-99-words24"),
            ] {
                let seed = kcr_seed(name);
                let wiped = cannot_check(restarted(
                    wiped_by_collision(),
                    len,
                    StubEntropy::Fixed(vec![0; 8]),
                    &WipeProbe::new(),
                ));
                let nonce = StubEntropy::Fixed(hex(&seed["nonce_hex"]));
                let rolling = restarted(wiped, len, nonce, &WipeProbe::new());
                assert_eq!(rolling.minimum_rolls(), 99, "{name}");
                let checking = roll_all(rolling, &faces("coldcard-99"))
                    .finish()
                    .and_then(Session::start_check)
                    .expect("checking");
                assert_eq!(checking.seal().tag().to_hex(), text(&seed["seal_tag_hex"]));
                let ready = match checking.reveal(GoAhead::Code(text(&seed["go_ahead"]))) {
                    Ok(ready) => ready,
                    Err(e) => panic!("{name}: {e:?}"),
                };
                assert_eq!(
                    ready.mnemonic().words().collect::<Vec<_>>().join(" "),
                    text(&seed["mnemonic"]),
                    "{name}"
                );
            }
        }

        // Mixed mode on a phone: D leaves only through reveal_device_leg after read-back, equal to
        // the D behind C; the passphrase wallet differs from the plain one.
        #[test]
        fn mixed_mode_reveals_d_and_exports() {
            let case = named(&keepcrypt_json()["source_substitution"], "phone").clone();
            let mut session = Session::new_with_stub(
                SeedLength::Words24,
                Mode::Mixed,
                Platform::Phone,
                stub(StubEntropy::Fixed(hex(&case["os_hex"])), &WipeProbe::new()),
                None,
            )
            .expect("a session");
            session.add_extra(ExtraSource::Motion, &hex(&case["events"][0]["data_hex"]));
            session.add_extra(
                ExtraSource::InputTiming,
                &hex(&case["events"][1]["data_hex"]),
            );
            let committed = session.commit().expect("committed");
            assert_eq!(
                committed.commitment().map(|c| c.to_vec()),
                Some(hex(&case["c_hex"]))
            );
            let mut ready = roll_all(committed.start_dice(), &faces("coldcard-99"))
                .finish()
                .expect("sealed")
                .skip_check();
            ready.read_back_every_word_for_test();
            let (ready, d) = ready.reveal_device_leg().expect("revealed");
            assert_eq!(
                d.map(|d| d.expose_secret().to_vec()),
                Some(hex(&case["d_hex"]))
            );
            let passphrase = Bip39Passphrase::new("TREZOR").expect("a passphrase");
            let (ready, with) = ready.watch_only(Some(&passphrase)).expect("an export");
            let (ready, without) = ready.watch_only(None).expect("an export");
            assert!(with.passphrase_used() && !without.passphrase_used());
            assert_ne!(with.fingerprint(), without.fingerprint());
            assert_eq!(without.fingerprint(), ready.fingerprint());
            assert_eq!(without.first_address(), ready.first_address());
        }

        /// Every value `verify_backup` may return (Q13 b).
        fn listed_verify_result(result: Result<(), CoreError>) -> bool {
            matches!(
                result,
                Ok(())
                    | Err(CoreError::NoBackupPassphrase
                        | CoreError::WrongPassphrase
                        | CoreError::ReadbackMismatch
                        | CoreError::Backup(_))
            )
        }

        // Q13 (b), settled as the plan's first option: verify_backup(&self) cannot wipe, so for
        // every input it returns only Ok or its four listed errors, never an unlisted one such as
        // Internal(_) (whose unreachable paths the module comment names). The inputs: before a
        // passphrase; every backup.json age file and refused file; every refused plaintext, under
        // this session's own passphrase; every truncation and one bit flip per byte of a backup
        // under its passphrase. check_readback's list is pinned the same way, over every position
        // and a range of typed input.
        #[test]
        fn the_two_calls_that_never_wipe_return_only_their_listed_errors() {
            let doc = read("backup.json");
            let zoo = named(&doc["plaintexts"], "zoo-24");
            let indices: Vec<usize> = text(&zoo["mnemonic"])
                .split(' ')
                .map(|w| usize::from(bip39::Language::English.find_word(w).expect("a word")))
                .collect();
            let generate = hex(&named(&doc["generate"], "stream")["os_hex"]);
            let mut ready = Session::<Ready>::ready_for_test(
                &indices,
                Source::Stub(stub(StubEntropy::Fixed(generate), &WipeProbe::new())),
            )
            .expect("Ready");
            let zoo_file = named(&doc["age_files"], "zoo-24");
            let file_bytes = |case: &Value| match case["file"].as_str() {
                Some(file) => file.as_bytes().to_vec(),
                None => hex(&case["file_hex"]),
            };
            assert_eq!(
                ready.verify_backup(&file_bytes(zoo_file)),
                Err(CoreError::NoBackupPassphrase)
            );
            ready.read_back_every_word_for_test();
            let (ready, new) = ready.generate_backup_passphrase().expect("generated");
            let passphrase = new.words().collect::<Vec<_>>().join(" ");
            assert_eq!(passphrase, text(&zoo_file["passphrase"]));

            let mut inputs: Vec<Vec<u8>> = Vec::new();
            for case in doc["age_files"].as_array().expect("files") {
                inputs.push(file_bytes(case));
            }
            for case in doc["age_refused"].as_array().expect("refused") {
                inputs.push(file_bytes(case));
            }
            let secrets = age::FileSecrets::new(&[1; 16], &[2; 16], &[3; 16]);
            for case in doc["plaintext_refused"].as_array().expect("refused") {
                let binary =
                    age::encrypt(passphrase.as_bytes(), &secrets, 10, &hex(&case["text_hex"]))
                        .expect("written");
                inputs.push(armor::encode(&binary).expect("armored"));
            }
            let abandon = named(&doc["plaintexts"], "abandon-12");
            let binary = age::encrypt(
                passphrase.as_bytes(),
                &secrets,
                10,
                text(&abandon["text"]).as_bytes(),
            )
            .expect("written");
            inputs.push(armor::encode(&binary).expect("armored"));
            let own = file_bytes(zoo_file);
            for end in 0..own.len() {
                inputs.push(own[..end].to_vec());
            }
            for at in 0..own.len() {
                let mut flipped = own.clone();
                flipped[at] ^= 1 << (at % 8);
                inputs.push(flipped);
            }
            let mut seen = std::collections::BTreeSet::new();
            for input in &inputs {
                let result = ready.verify_backup(input);
                assert!(listed_verify_result(result), "{result:?}");
                seen.insert(format!("{result:?}"));
            }
            assert!(seen.contains("Ok(())"), "{seen:?}");
            for want in [
                "Err(WrongPassphrase)",
                "Err(ReadbackMismatch)",
                "Err(Backup(Plaintext))",
                "Err(Backup(UnsupportedVersion))",
                "Err(Backup(Header))",
                "Err(Backup(Armor))",
            ] {
                assert!(seen.contains(want), "{want} in {seen:?}");
            }
            assert_eq!(
                ready.verify_backup(&file_bytes(named(&doc["age_files"], "abandon-12"))),
                Err(CoreError::WrongPassphrase)
            );

            let mut ready = ready;
            for position in 0..=u8::MAX {
                for typed in [
                    "",
                    "a",
                    "zo",
                    "zoo",
                    "ZOO",
                    "zoot",
                    "vote",
                    "zooo1",
                    "z o",
                    "zoos!",
                    "\u{e9}t\u{e9}",
                ] {
                    let result = ready.check_readback(position, typed);
                    assert!(
                        matches!(
                            result,
                            Ok(_)
                                | Err(CoreError::Braille(
                                    BrailleError::BadPosition | BrailleError::MalformedReadback
                                ))
                        ),
                        "{position} {typed:?}"
                    );
                }
            }
        }

        // Rejected and Wiped print only their variant names, never their contents.
        #[test]
        fn rejected_and_wiped_debug_print_names_only() {
            let checking = sealed_on(StubEntropy::Fixed(vec![0; 8]), &WipeProbe::new())
                .start_check()
                .expect("checking");
            let rejected = match checking.reveal(GoAhead::Code("x")) {
                Err(rejected) => rejected,
                Ok(_) => panic!("revealed"),
            };
            assert_eq!(format!("{rejected:?}"), "Rejected::Retry");
            let Rejected::Retry(checking, _) = rejected else {
                panic!("not a retry")
            };
            let wiped = checking.discard(Discard::Collision);
            assert_eq!(format!("{wiped:?}"), "Wiped");
            assert_eq!(
                format!("{:?}", Rejected::Collision(wiped)),
                "Rejected::Collision"
            );
        }
    }
}
