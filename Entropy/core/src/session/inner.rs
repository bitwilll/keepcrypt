//! Every secret of one session, at fixed capacity, in one heap allocation (`Box<Inner>`), so
//! nothing reallocates and leaves a copy behind, and there is no `Option` to unwrap. `Drop`
//! zeroizes all of it, then tells the source (a stub counts the wipe). M1 groups 3 to 9 add the
//! pool, the health tester, the dice buffer and the seal as they land.

use zeroize::Zeroize;

use super::Config;
use crate::secret::{BackupPassphrase, SecretBytes32, SecretMnemonic, SecretSeed64};
use crate::source::Source;

pub(super) struct Inner {
    pub(super) config: Config,
    source: Source,
    /// D, the device leg.
    device_leg: SecretBytes32,
    /// E, the seed entropy.
    seed_entropy: SecretBytes32,
    /// S, the BIP39 seed with the empty passphrase.
    bip39_seed: SecretSeed64,
    mnemonic: SecretMnemonic,
    /// The generated backup passphrase, kept for `encrypt_backup` and `verify_backup`.
    backup_passphrase: BackupPassphrase,
}

impl Inner {
    /// A session with every secret zeroed, on the heap from the start.
    pub(super) fn new(config: Config, source: Source) -> Box<Self> {
        Box::new(Self {
            config,
            source,
            device_leg: SecretBytes32::zeroed(),
            seed_entropy: SecretBytes32::zeroed(),
            bip39_seed: SecretSeed64::zeroed(),
            mnemonic: SecretMnemonic::zeroed(),
            backup_passphrase: BackupPassphrase::zeroed(),
        })
    }
}

impl Zeroize for Inner {
    fn zeroize(&mut self) {
        self.device_leg.zeroize();
        self.seed_entropy.zeroize();
        self.bip39_seed.zeroize();
        self.mnemonic.zeroize();
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
    use crate::session::{Mode, Platform, SeedLength};

    const CONFIG: Config = Config {
        len: SeedLength::Words24,
        mode: Mode::Mixed,
        platform: Platform::Pi,
    };

    // White box: fill every secret field, zeroize, and find zeros (tasks/todo.md, M1 group 2).
    #[test]
    fn zeroize_clears_every_secret_field() {
        let mut inner = Inner::new(CONFIG, Source::Os);
        inner.device_leg.fill();
        inner.seed_entropy.fill();
        inner.bip39_seed.fill();
        inner.mnemonic.fill();
        inner.backup_passphrase.fill();
        let filled = [
            inner.device_leg.is_zero(),
            inner.seed_entropy.is_zero(),
            inner.bip39_seed.is_zero(),
            inner.mnemonic.is_zero(),
            inner.backup_passphrase.is_zero(),
        ];
        assert_eq!(filled, [false; 5]);
        inner.zeroize();
        let cleared = [
            inner.device_leg.is_zero(),
            inner.seed_entropy.is_zero(),
            inner.bip39_seed.is_zero(),
            inner.mnemonic.is_zero(),
            inner.backup_passphrase.is_zero(),
        ];
        assert_eq!(cleared, [true; 5]);
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
            );
            inner.device_leg.fill();
            assert_eq!(probe.wipes(), 0);
        }
        assert_eq!(probe.wipes(), 1);
    }
}
