//! Every secret of one session, at fixed capacity, in one heap allocation (`Box<Inner>`), so
//! nothing reallocates and leaves a copy behind, and there is no `Option` to unwrap: each field
//! starts zeroed (or empty) and the transition that owns it fills it in place. `Drop` zeroizes all
//! of it, then tells the source (a stub counts the wipe).
//!
//! The typestate in `session.rs` decides which of these methods a state may call; this file does
//! the work. Every method here that can fail returns `Result`, and the session method above it
//! takes `self`, so an `Err` drops this `Inner` and wipes it. The exceptions are the user-input
//! calls that keep the session alive: `check_readback`, `verify_backup`, and a go-ahead whose
//! verdict is `Retry`.

use zeroize::Zeroize;

use super::{Config, GoAhead, Mode, Platform};
use crate::backup::{self, BackupFile, CreatedBy};
use crate::braille::{BrailleInserts, ReadbackResult};
use crate::descriptor::{self, WatchOnlyExport};
use crate::dice::{self, Dice};
use crate::error::{CheckError, CoreError, InternalFault};
use crate::health::HealthTester;
use crate::pool::Pool;
use crate::seal::{
    self, CheckNonce, CheckRequest, CollisionReport, SealCode, SealPublic, SealRegistration,
};
use crate::secret::{
    BackupPassphrase, Bip39Passphrase, MAX_WORDS, NewBackupPassphrase, SecretBytes32,
    SecretMnemonic, SecretSeed64,
};
use crate::seed::{self, EmptyPassphraseSeed};
use crate::source::{self, ExtraSource, OS_BYTES, Source, SourceId};

/// What a go-ahead says about this session's seal.
pub(super) enum Verdict {
    /// Verified clear: the words may be shown.
    Clear,
    /// Not verified (a typo, a bad scan, a proof for another bucket): try again, same nonce.
    Retry(CheckError),
    /// The registry holds this seal: the seed must be wiped unseen.
    Collision,
}

pub(super) struct Inner {
    pub(super) config: Config,
    source: Source,
    /// Set by `Wiped::restart` after a collision: the 99-roll minimum for either length.
    after_collision: bool,
    /// Collecting: the hwrng health tester. It remembers raw sample values.
    tester: HealthTester,
    /// Collecting: the SHA-512 pool behind D. Replaced by a fresh pool when D is taken from it.
    pool: Pool,
    /// The first pool failure in `add_extra`, which cannot fail the session itself (`&mut self`):
    /// `commit` returns it, so the session halts and wipes there (CLAUDE.md rule 3). The pool's
    /// only failure is a length that does not fit a u64.
    extra_fault: Option<CoreError>,
    /// D, the device leg (Mixed mode only).
    device_leg: SecretBytes32,
    /// C = SHA256("KCE/v1/commit" || D): public (Mixed mode only).
    commitment: [u8; 32],
    /// R, the dice rolls, zeroized as soon as E exists.
    dice: Dice,
    /// E, the seed entropy.
    seed_entropy: SecretBytes32,
    /// S, the BIP39 seed with the empty passphrase: the seal's and the fingerprint's only input.
    bip39_seed: EmptyPassphraseSeed,
    mnemonic: SecretMnemonic,
    /// The private seal code, for the registration and collision-report QRs.
    seal_code: SealCode,
    /// The public seal: empty until `finish`.
    seal: SealPublic,
    /// The master key fingerprint of S (public), which the backup plaintext names.
    fingerprint: [u8; 4],
    /// m/84'/0'/0'/0/0 of S (public).
    first_address: String,
    /// The nonce n of the running check (public).
    nonce: CheckNonce,
    /// Which positions (index = position - 1) last read back as a match.
    read_back: [bool; MAX_WORDS],
    /// The generated backup passphrase, kept for `encrypt_backup` and `verify_backup`.
    backup_passphrase: BackupPassphrase,
}

impl Inner {
    /// A session with every secret zeroed, on the heap from the start. `after_collision` comes from
    /// `Wiped::restart`.
    pub(super) fn new(config: Config, source: Source, after_collision: bool) -> Box<Self> {
        Box::new(Self {
            config,
            source,
            after_collision,
            tester: HealthTester::new(),
            pool: Pool::new(),
            extra_fault: None,
            device_leg: SecretBytes32::zeroed(),
            commitment: [0; 32],
            dice: Dice::new(),
            seed_entropy: SecretBytes32::zeroed(),
            bip39_seed: EmptyPassphraseSeed::zeroed(),
            mnemonic: SecretMnemonic::zeroed(),
            seal_code: SealCode::zeroed(),
            seal: SealPublic::empty(),
            fingerprint: [0; 4],
            first_address: String::new(),
            nonce: CheckNonce::from_bytes([0; 8]),
            read_back: [false; MAX_WORDS],
            backup_passphrase: BackupPassphrase::zeroed(),
        })
    }

    // --- Collecting ------------------------------------------------------------------------

    /// Health-tests a chunk of raw hwrng samples whole, then absorbs its post-startup samples as
    /// one hwrng record. Pi in Mixed mode only, else `NotInThisMode`.
    pub(super) fn add_hw_samples(&mut self, raw: &[u8]) -> Result<(), CoreError> {
        if (self.config.platform, self.config.mode) != (Platform::Pi, Mode::Mixed) {
            return Err(CoreError::NotInThisMode);
        }
        let from = self.tester.test(raw)?;
        let post_startup = raw
            .get(from..)
            .ok_or(CoreError::Internal(InternalFault::Length))?;
        self.pool.absorb(SourceId::Hwrng, post_startup)
    }

    /// Mixes an uncredited extra into the pool (Mixed mode; nothing in dice-only mode). A pool
    /// failure is kept for `commit`.
    pub(super) fn add_extra(&mut self, source: ExtraSource, bytes: &[u8]) {
        if self.config.mode == Mode::DiceOnly {
            return;
        }
        if let Err(fault) = self.pool.absorb(SourceId::Extra(source), bytes)
            && self.extra_fault.is_none()
        {
            self.extra_fault = Some(fault);
        }
    }

    /// The credited device-leg bits `commit` will count: the hwrng credit (whole windows only)
    /// plus the OS read's policy credit; 0 in dice-only mode, which uses no device leg. The same
    /// sum `source::quota_met` compares, in the same width (u64), so nothing is narrowed or
    /// defaulted on the way to the screen.
    pub(super) fn credited_bits(&self) -> u64 {
        match self.config.mode {
            Mode::DiceOnly => 0,
            Mode::Mixed => source::hwrng_credited_bits(self.tester.credited_samples())
                .saturating_add(u64::from(source::os_policy_bits(self.config.platform))),
        }
    }

    pub(super) fn required_bits(&self) -> u64 {
        u64::from(source::required_bits(
            self.config.platform,
            self.config.mode,
        ))
    }

    pub(super) fn hw_bytes_tested(&self) -> u64 {
        self.tester.tested()
    }

    /// Fixes D: checks the quota, reads 64 OS bytes and absorbs them last, then D and C. Dice-only
    /// mode reads nothing and has no D.
    pub(super) fn commit(&mut self) -> Result<(), CoreError> {
        if let Some(fault) = self.extra_fault {
            return Err(fault);
        }
        let (platform, mode) = (self.config.platform, self.config.mode);
        if !source::quota_met(platform, mode, self.tester.credited_samples()) {
            return Err(CoreError::QuotaUnmet);
        }
        if mode == Mode::DiceOnly {
            return Ok(());
        }
        let os = self.source.os_bytes::<OS_BYTES>()?;
        self.pool.absorb(SourceId::Os, os.as_slice())?;
        let pool = core::mem::replace(&mut self.pool, Pool::new());
        pool.finish_into(&mut self.device_leg);
        self.commitment = seed::commitment(&self.device_leg);
        Ok(())
    }

    // --- Committed and Rolling ---------------------------------------------------------------

    pub(super) fn commitment(&self) -> Option<[u8; 32]> {
        match self.config.mode {
            Mode::Mixed => Some(self.commitment),
            Mode::DiceOnly => None,
        }
    }

    pub(super) fn push_roll(&mut self, face: u8) -> Result<(), CoreError> {
        self.dice.push(face)
    }

    pub(super) fn undo_roll(&mut self) {
        self.dice.undo();
    }

    pub(super) fn rolls(&self) -> u16 {
        self.dice.count()
    }

    pub(super) fn millibits(&self) -> u32 {
        self.dice.millibits()
    }

    pub(super) fn minimum_rolls(&self) -> u16 {
        dice::minimum_rolls(self.config.len, self.after_collision)
    }

    /// Makes the seed, once: E (mixed or dice-only), then R is zeroized, then the words and S, the
    /// seal, the fingerprint and the first address. Below the minimum it is `TooFewRolls`.
    pub(super) fn finish(&mut self) -> Result<(), CoreError> {
        if self.dice.count() < self.minimum_rolls() {
            return Err(CoreError::TooFewRolls);
        }
        match self.config.mode {
            Mode::Mixed => seed::mixed_entropy_into(
                &self.device_leg,
                self.dice.ascii(),
                &mut self.seed_entropy,
            )?,
            Mode::DiceOnly => {
                seed::dice_only_entropy_into(self.dice.ascii(), &mut self.seed_entropy)
            }
        }
        self.dice.zeroize();
        seed::mnemonic_and_seed_into(
            &self.seed_entropy,
            self.config.len,
            &mut self.mnemonic,
            &mut self.bip39_seed,
        )?;
        self.derive_public()
    }

    /// From S: the seal (code and public half), the fingerprint and the first address.
    fn derive_public(&mut self) -> Result<(), CoreError> {
        self.seal = seal::derive_seal(&self.bip39_seed, &mut self.seal_code)?;
        let summary = seed::wallet_summary(&self.bip39_seed)?;
        self.fingerprint = summary.fingerprint;
        self.first_address = summary.first_address;
        Ok(())
    }

    // --- Sealed and Checking -------------------------------------------------------------------

    pub(super) fn seal(&self) -> &SealPublic {
        &self.seal
    }

    /// Draws this check's nonce n: 8 fresh OS bytes in a read of their own.
    pub(super) fn start_check(&mut self) -> Result<(), CoreError> {
        self.nonce = CheckNonce::draw(&mut self.source)?;
        Ok(())
    }

    pub(super) fn check_request(&self) -> CheckRequest {
        CheckRequest::new(self.seal.tag(), &self.nonce)
    }

    /// What a go-ahead says. A typed code must be this check's G (compared in constant time); a
    /// loaded snapshot or a verified proof must not hold T, and a proof must cover T's bucket.
    /// Freshness is the shell's warning, not a refusal: core has no clock.
    pub(super) fn judge(&self, go: GoAhead<'_>) -> Verdict {
        let tag = self.seal.tag();
        match go {
            GoAhead::Code(typed) => match seal::verify_go_ahead(tag, &self.nonce, typed) {
                Ok(()) => Verdict::Clear,
                Err(e) => Verdict::Retry(e),
            },
            GoAhead::Snapshot(snapshot) => match snapshot.lookup(tag) {
                Some(_) => Verdict::Collision,
                None => Verdict::Clear,
            },
            GoAhead::BucketProof(proof) => match proof.lookup(tag) {
                Ok(Some(_)) => Verdict::Collision,
                Ok(None) => Verdict::Clear,
                Err(e) => Verdict::Retry(e),
            },
        }
    }

    /// The "Report collision" QR for this seal.
    pub(super) fn collision_report(&self) -> CollisionReport {
        CollisionReport::new(&self.seal_code, &self.seal)
    }

    // --- Ready -----------------------------------------------------------------------------

    pub(super) fn mnemonic(&self) -> &SecretMnemonic {
        &self.mnemonic
    }

    pub(super) fn braille(&self) -> BrailleInserts<'_> {
        BrailleInserts::new(&self.mnemonic)
    }

    pub(super) fn fingerprint(&self) -> [u8; 4] {
        self.fingerprint
    }

    pub(super) fn first_address(&self) -> &str {
        &self.first_address
    }

    /// Compares the letters read back from the insert at `position` with its word, and records
    /// the result for that position: a match sets it, a mismatch clears it. Input errors
    /// (`BadPosition`, `MalformedReadback`) record nothing.
    pub(super) fn check_readback(
        &mut self,
        position: u8,
        typed: &str,
    ) -> Result<ReadbackResult, CoreError> {
        let result = BrailleInserts::new(&self.mnemonic).readback(position, typed)?;
        if let Some(slot) = usize::from(position)
            .checked_sub(1)
            .and_then(|i| self.read_back.get_mut(i))
        {
            *slot = matches!(result, ReadbackResult::Match);
        }
        Ok(result)
    }

    /// Whether every word of the seed has read back as a match.
    pub(super) fn readback_complete(&self) -> bool {
        let count = self.mnemonic.word_count();
        count > 0 && self.read_back.iter().take(count).all(|&matched| matched)
    }

    /// The read-back gate in front of the five exports: `ReadbackIncomplete` until every word has
    /// matched.
    pub(super) fn require_readback(&self) -> Result<(), CoreError> {
        if self.readback_complete() {
            Ok(())
        } else {
            Err(CoreError::ReadbackIncomplete)
        }
    }

    /// A new backup passphrase, stored here in place of any earlier one, and its display copy.
    pub(super) fn generate_backup_passphrase(&mut self) -> Result<NewBackupPassphrase, CoreError> {
        backup::new_passphrase(&mut self.source, &mut self.backup_passphrase)
    }

    /// The backup of these words under the stored passphrase.
    pub(super) fn encrypt_backup(&mut self, by: &CreatedBy) -> Result<BackupFile, CoreError> {
        backup::encrypt(
            &mut self.source,
            &self.backup_passphrase,
            &self.mnemonic,
            self.fingerprint,
            by,
        )
    }

    /// Reads a written backup back with the stored passphrase.
    pub(super) fn verify_backup(&self, file: &[u8]) -> Result<(), CoreError> {
        backup::verify(
            &self.backup_passphrase,
            file,
            &self.mnemonic,
            self.fingerprint,
        )
    }

    /// The watch-only export: of S, or, with a BIP39 passphrase, of the seed of these words under
    /// it (NFKD, never trimmed), in a zeroizing buffer of its own. The seal and the backup never
    /// see the passphrase.
    pub(super) fn watch_only(
        &self,
        passphrase: Option<&Bip39Passphrase>,
    ) -> Result<WatchOnlyExport, CoreError> {
        match passphrase {
            None => descriptor::watch_only_export(self.bip39_seed.as_seed(), false),
            Some(passphrase) => {
                let mut seed = SecretSeed64::zeroed();
                seed::passphrase_seed_into(
                    &self.seed_entropy,
                    self.config.len,
                    passphrase,
                    &mut seed,
                )?;
                descriptor::watch_only_export(&seed, true)
            }
        }
    }

    /// The "Register seal" QR.
    pub(super) fn registration(&self) -> SealRegistration {
        SealRegistration::new(&self.seal_code, &self.seal)
    }

    /// A copy of D for offline audit, in a wrapper of its own; None in dice-only mode.
    pub(super) fn reveal_device_leg(&self) -> Option<SecretBytes32> {
        match self.config.mode {
            Mode::Mixed => {
                let mut d = SecretBytes32::zeroed();
                d.expose_secret_mut()
                    .copy_from_slice(self.device_leg.expose_secret());
                Some(d)
            }
            Mode::DiceOnly => None,
        }
    }

    /// Fills the words, S and everything `finish` derives from S, from chosen word indices: tests
    /// only (the backup tests need given words, which no dice string gives).
    #[cfg(test)]
    pub(super) fn fill_words_for_test(&mut self, indices: &[usize]) -> Result<(), CoreError> {
        self.mnemonic.fill_from(indices.iter().copied())?;
        seed::seed_from_mnemonic_into(&self.mnemonic, &mut self.bip39_seed)?;
        self.derive_public()
    }

    /// White-box test support: plant a pool failure for `commit`, which no slice length can cause.
    #[cfg(test)]
    pub(super) fn plant_extra_fault_for_test(&mut self, fault: CoreError) {
        self.extra_fault = Some(fault);
    }
}

impl Zeroize for Inner {
    fn zeroize(&mut self) {
        self.tester.zeroize();
        // A fresh pool; the old SHA-512 state wipes itself when dropped (ZeroizeOnDrop).
        self.pool = Pool::new();
        self.device_leg.zeroize();
        self.commitment.zeroize();
        self.dice.zeroize();
        self.seed_entropy.zeroize();
        self.bip39_seed.zeroize();
        self.mnemonic.zeroize();
        self.seal_code.zeroize();
        self.seal = SealPublic::empty();
        self.fingerprint.zeroize();
        self.first_address.zeroize();
        self.nonce = CheckNonce::from_bytes([0; 8]);
        self.read_back.zeroize();
        self.backup_passphrase.zeroize();
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.zeroize();
        self.source.wiped();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::TestFill;
    use crate::session::SeedLength;

    const CONFIG: Config = Config {
        len: SeedLength::Words24,
        mode: Mode::Mixed,
        platform: Platform::Pi,
    };

    /// Whether each field `zeroize` must clear is clear.
    fn cleared(inner: &Inner) -> [bool; 14] {
        [
            inner.tester.tested() == 0,
            inner.device_leg.is_zero(),
            inner.commitment == [0; 32],
            inner.dice.count() == 0,
            inner.seed_entropy.is_zero(),
            inner.bip39_seed.is_zero(),
            inner.mnemonic.is_zero(),
            inner.seal_code.is_zero(),
            inner.seal == SealPublic::empty(),
            inner.fingerprint == [0; 4],
            inner.first_address.is_empty(),
            inner.nonce == CheckNonce::from_bytes([0; 8]),
            inner.read_back == [false; MAX_WORDS],
            inner.backup_passphrase.is_zero(),
        ]
    }

    // White box: fill every field, zeroize, and find zeros (tasks/todo.md, M1 group 2).
    #[test]
    fn zeroize_clears_every_field() {
        let mut inner = Inner::new(CONFIG, Source::Os, false);
        assert_eq!(inner.tester.test(&[1, 2, 3]), Ok(3));
        inner.device_leg.fill();
        inner.commitment = [0xc0; 32];
        for face in [1, 2, 3] {
            assert_eq!(inner.dice.push(face), Ok(()));
        }
        inner.seed_entropy.fill();
        inner.bip39_seed.fill();
        inner.mnemonic.fill();
        inner.seal_code.fill();
        inner.seal = SealPublic::from_code(&inner.seal_code).expect("a seal");
        inner.fingerprint = [0x73; 4];
        inner.first_address = "bc1q".to_owned();
        inner.nonce = CheckNonce::from_bytes([7; 8]);
        inner.read_back = [true; MAX_WORDS];
        inner.backup_passphrase.fill();
        assert_eq!(cleared(&inner), [false; 14]);
        inner.zeroize();
        assert_eq!(cleared(&inner), [true; 14]);
        assert_eq!(inner.config, CONFIG);
    }

    #[cfg(feature = "test-sources")]
    #[test]
    fn drop_counts_one_wipe_after_zeroizing() {
        use crate::source::{StubEntropy, StubSource, WipeProbe};
        let probe = WipeProbe::new();
        {
            let mut inner = Inner::new(
                CONFIG,
                Source::Stub(StubSource::new(StubEntropy::Fail, &probe)),
                false,
            );
            inner.device_leg.fill();
            assert_eq!(probe.wipes(), 0);
        }
        assert_eq!(probe.wipes(), 1);
    }
}
