//! From the two legs to the words (CLAUDE.md "Commitment", "Seed (mixed mode)", "Seed (dice
//! only)", "Seed length"; docs/design.md "From entropy to a BIP39 seed phrase"; docs/build-plan.md
//! "Invariants"; tasks/todo.md, M1 group 4).
//!
//! - C = SHA256("KCE/v1/commit" || D), shown before any roll.
//! - Mixed: E = SHA256("KCE/v1/seed" || D || len(R) as u64 big-endian || R).
//! - Dice only: E = SHA256(R), the same as Coldcard's rolls.py.
//! - 12 words from E[0..16], 24 from all of E, through the bip39 crate's English list, converted
//!   at once into a `SecretMnemonic`; S = the BIP39 seed with the empty passphrase, which is what
//!   the seal and the fingerprint use. S has its own type, `EmptyPassphraseSeed`, which only this
//!   module fills and only from the words; a seed under a BIP39 passphrase is a plain
//!   `SecretSeed64`, so it cannot reach the seal or the fingerprint (CLAUDE.md rule 7).
//! - The wallet summary is the master fingerprint and the m/84'/0'/0'/0/0 P2WPKH mainnet address.
//!   The extended private keys stay inside `wallet_summary`, held in a `SecretXpriv`, which derives
//!   in place one level at a time and erases the key when dropped; the secp256k1 context is not
//!   randomized (rust-bitcoin's `rand-std` is off).
//!
//! Every value core keeps is written in place into the session's zeroizing fields. Two library
//! calls hand secrets back by value, and the temporaries they leave are beyond core's reach:
//! bip39's `to_seed_normalized` returns S, which is wrapped in `Zeroizing` at once, and
//! rust-bitcoin's key derivation keeps copies in its own frames (see `wallet_summary`). That
//! residual is recorded in tasks/todo.md (M1 group 4) for the owner.
//! The session derives C at `commit` and E, the words, S and the wallet summary once, in `finish`.

use bitcoin::bip32::{ChildNumber, Fingerprint, Xpriv, Xpub};
use bitcoin::secp256k1::{Secp256k1, Signing};
use bitcoin::{Address, Network, NetworkKind};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{CoreError, InternalFault};
use crate::secret::{Bip39Passphrase, SecretBytes32, SecretMnemonic, SecretSeed64};
use crate::session::SeedLength;

/// The commitment's domain tag.
pub(crate) const COMMIT_TAG: &[u8] = b"KCE/v1/commit";
/// The mixed seed's domain tag.
pub(crate) const SEED_TAG: &[u8] = b"KCE/v1/seed";

/// The SHA-256 states below hold D (C, mixed E) and end as E itself (mixed and dice-only E): they
/// must wipe themselves when dropped. sha2's `zeroize` feature provides it; this pins it.
const fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
const _: () = assert_zeroize_on_drop::<Sha256>();

/// S, the BIP39 seed with the empty passphrase: the only seed the seal and the wallet summary (the
/// fingerprint the backup names) take (CLAUDE.md rule 7). Only this module fills one, from the words
/// alone (`mnemonic_and_seed_into`, `seed_from_mnemonic_into`); the seed of a BIP39 passphrase is a
/// plain `SecretSeed64` (`passphrase_seed_into`), so passing it to the seal fails to compile (review
/// fix after commit 18). `as_seed` lends S out as a `SecretSeed64` for what any seed may feed, such
/// as the watch-only export; nothing turns a `SecretSeed64` into one. No `Debug`, `Display` or
/// `Clone`; wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct EmptyPassphraseSeed(SecretSeed64);

impl EmptyPassphraseSeed {
    pub(crate) const fn zeroed() -> Self {
        Self(SecretSeed64::zeroed())
    }

    /// S, as a seed of either kind, for key derivation inside core only.
    pub(crate) fn as_seed(&self) -> &SecretSeed64 {
        &self.0
    }
}

/// C = SHA256("KCE/v1/commit" || D): public, safe to display.
pub(crate) fn commitment(d: &SecretBytes32) -> [u8; 32] {
    Sha256::new()
        .chain_update(COMMIT_TAG)
        .chain_update(d.expose_secret())
        .finalize()
        .into()
}

/// Mixed mode: E = SHA256("KCE/v1/seed" || D || len(R) as u64 big-endian || R), into `e`.
pub(crate) fn mixed_entropy_into(
    d: &SecretBytes32,
    rolls: &[u8],
    e: &mut SecretBytes32,
) -> Result<(), CoreError> {
    let len = u64::try_from(rolls.len()).map_err(|_| CoreError::Internal(InternalFault::Length))?;
    let hasher = Sha256::new()
        .chain_update(SEED_TAG)
        .chain_update(d.expose_secret());
    let hasher = hasher.chain_update(len.to_be_bytes()).chain_update(rolls);
    hasher.finalize_into(e.expose_secret_mut().into());
    Ok(())
}

/// Dice-only mode: E = SHA256(R), into `e`.
pub(crate) fn dice_only_entropy_into(rolls: &[u8], e: &mut SecretBytes32) {
    Sha256::new()
        .chain_update(rolls)
        .finalize_into(e.expose_secret_mut().into());
}

/// The bip39 mnemonic of E: 12 words from E[0..16], 24 from all 32 bytes. Wiped on drop (bip39's
/// `zeroize` feature).
fn bip39_mnemonic(e: &SecretBytes32, len: SeedLength) -> Result<bip39::Mnemonic, CoreError> {
    let entropy = match len {
        SeedLength::Words12 => &e.expose_secret()[..16],
        SeedLength::Words24 => &e.expose_secret()[..],
    };
    bip39::Mnemonic::from_entropy_in(bip39::Language::English, entropy)
        .map_err(|_| CoreError::Internal(InternalFault::Bip39))
}

/// From E: the words (12 from E[0..16], 24 from all 32 bytes) into `mnemonic`, and S, the BIP39
/// seed with the empty passphrase, into `seed`.
pub(crate) fn mnemonic_and_seed_into(
    e: &SecretBytes32,
    len: SeedLength,
    mnemonic: &mut SecretMnemonic,
    seed: &mut EmptyPassphraseSeed,
) -> Result<(), CoreError> {
    let words = bip39_mnemonic(e, len)?;
    mnemonic.fill_from(words.word_indices())?;
    // bip39 returns S by value; it is wrapped at once (the moved-from temporary is the residual
    // in the module comment).
    let s = Zeroizing::new(words.to_seed_normalized(""));
    seed.0.expose_secret_mut().copy_from_slice(s.as_slice());
    Ok(())
}

/// The bip39 mnemonic of these words, or `None` if their BIP39 checksum is wrong. The words'
/// entropy is unpacked from their indices into a zeroizing buffer (the bit accumulator is wiped
/// too), the bip39 crate re-encodes it, and its words must equal these. `Internal(Bip39)` for a
/// word count other than 12 or 24, or entropy bip39 refuses; bip39's own frames keep the residual
/// in the module comment.
fn checked_bip39(mnemonic: &SecretMnemonic) -> Result<Option<bip39::Mnemonic>, CoreError> {
    let indices = mnemonic.indices();
    let entropy_len = match indices.len() {
        12 => 16,
        24 => 32,
        _ => return Err(CoreError::Internal(InternalFault::Bip39)),
    };
    let mut entropy = Zeroizing::new([0u8; 32]);
    let mut pending = Zeroizing::new(0u32);
    let mut pending_bits = 0u32;
    let mut filled = 0usize;
    for &index in indices {
        *pending = (*pending << 11) | u32::from(index);
        pending_bits += 11;
        while pending_bits >= 8 && filled < entropy_len {
            pending_bits -= 8;
            entropy[filled] = (*pending >> pending_bits).to_be_bytes()[3];
            *pending &= (1 << pending_bits) - 1;
            filled += 1;
        }
    }
    let words = bip39::Mnemonic::from_entropy_in(bip39::Language::English, &entropy[..entropy_len])
        .map_err(|_| CoreError::Internal(InternalFault::Bip39))?;
    let same = words
        .word_indices()
        .eq(indices.iter().map(|&i| usize::from(i)));
    Ok(same.then_some(words))
}

/// Whether the words' BIP39 checksum is right. A backup's plaintext reader checks it as input (a
/// wrong one is the file's fault), apart from the faults `seed_from_mnemonic_into` reports.
pub(crate) fn checksum_is_valid(mnemonic: &SecretMnemonic) -> Result<bool, CoreError> {
    Ok(checked_bip39(mnemonic)?.is_some())
}

/// S, the BIP39 seed with the empty passphrase, of a mnemonic's words, into `seed`: what the seal
/// of an existing wallet needs (a decrypted backup; `seal_from_mnemonic`). The words must carry
/// their BIP39 checksum (`checked_bip39`), else `Internal(Bip39)`: core's own words always do, and
/// the backup reader checks a file's first (`checksum_is_valid`). Then S as in
/// `mnemonic_and_seed_into`.
pub(crate) fn seed_from_mnemonic_into(
    mnemonic: &SecretMnemonic,
    seed: &mut EmptyPassphraseSeed,
) -> Result<(), CoreError> {
    let words = checked_bip39(mnemonic)?.ok_or(CoreError::Internal(InternalFault::Bip39))?;
    let s = Zeroizing::new(words.to_seed_normalized(""));
    seed.0.expose_secret_mut().copy_from_slice(s.as_slice());
    Ok(())
}

/// The BIP39 seed of E's words under a BIP39 passphrase, for the watch-only export of a passphrase
/// wallet (docs/seal-watchonly-braille.md "Watch-only export" rules; tasks/todo.md, M1 Q5). The
/// passphrase is NFKD-normalized, never trimmed, into a zeroizing buffer sized exactly by a first
/// counting pass, so that buffer never reallocates; then bip39's `to_seed_normalized` takes it. The
/// seal and the backup never see a passphrase: they use S with the empty one (CLAUDE.md rule 7),
/// an `EmptyPassphraseSeed`, which this plain `SecretSeed64` is not.
///
/// Beyond core's reach (tasks/todo.md, M1 group 6, residual): during each pass,
/// unicode-normalization holds the characters it is decomposing in a `TinyVec<[(u8, char); 4]>`.
/// That buffer is inline on the stack, and on the heap once more than four characters are pending
/// (a starter with more than three combining marks, or a long compatibility decomposition). Both
/// are left unwiped, and the heap block is freed as it is. bip39 returns the seed by value (wrapped
/// in `Zeroizing` at once).
pub(crate) fn passphrase_seed_into(
    e: &SecretBytes32,
    len: SeedLength,
    passphrase: &Bip39Passphrase,
    seed: &mut SecretSeed64,
) -> Result<(), CoreError> {
    let words = bip39_mnemonic(e, len)?;
    let typed = passphrase.expose_secret();
    let size: usize = typed.nfkd().map(char::len_utf8).sum();
    let mut normalized = Zeroizing::new(String::with_capacity(size));
    normalized.extend(typed.nfkd());
    let s = Zeroizing::new(words.to_seed_normalized(&normalized));
    seed.expose_secret_mut().copy_from_slice(s.as_slice());
    Ok(())
}

/// What the wallet summary screen shows (pi-firmware.md step 10): public values only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WalletSummary {
    /// The BIP32 master key fingerprint.
    pub(crate) fingerprint: [u8; 4],
    /// The first receive address, m/84'/0'/0'/0/0, P2WPKH, mainnet.
    pub(crate) first_address: String,
}

/// The wallet summary from S. The extended private keys exist only in this function, in one
/// `SecretXpriv`: the master, overwritten in place by each level down to m/84'/0'/0'/0/0 (the
/// account key m/84'/0'/0' among them), and erased when it is dropped, on every path, error paths
/// included.
///
/// What it cannot reach: rust-bitcoin's `derive_priv` copies its parent into a local of its own,
/// and its private `ckd_priv` keeps key material in its HMAC state and output; secp256k1's tweak
/// has temporaries too, and each library call that returns a key by value leaves the moved-from
/// temporary. Those copies are left to the stack (tasks/todo.md, M1 group 4, residual).
pub(crate) fn wallet_summary(seed: &EmptyPassphraseSeed) -> Result<WalletSummary, CoreError> {
    let path = first_receive_path()?;
    let secp = Secp256k1::signing_only();
    let mut key = SecretXpriv::master(seed.as_seed())?;
    let fingerprint = key.fingerprint(&secp).to_bytes();
    key.derive_in_place(&secp, &path)?;
    let public = key.xpub(&secp).to_pub();
    Ok(WalletSummary {
        fingerprint,
        first_address: Address::p2wpkh(&public, Network::Bitcoin).to_string(),
    })
}

/// An extended private key core holds (CLAUDE.md rule 5). rust-bitcoin's `Xpriv` is `Copy`, so a
/// bare one passed by value leaves the caller's copy behind unerased; this wrapper implements
/// `Drop`, so it can be neither `Copy` nor `Clone` (E0184), derives in place, and overwrites the
/// key and chain code when dropped, on every path, unwinding included. Every extended private key
/// core derives lives in one (review fix after commit 15).
pub(crate) struct SecretXpriv(Xpriv);

/// `Drop` is what erases a `SecretXpriv`, and what rules out `Copy`; this pins it.
const _: () = assert!(core::mem::needs_drop::<SecretXpriv>());

impl SecretXpriv {
    /// The BIP32 mainnet master key of `seed`. A `match`, not `map` and `map_err`: each closure
    /// call moves the key once more, and an unoptimized build leaves a copy per move.
    pub(crate) fn master(seed: &SecretSeed64) -> Result<Self, CoreError> {
        match Xpriv::new_master(NetworkKind::Main, seed.expose_secret()) {
            Ok(master) => Ok(Self(master)),
            Err(e) => Err(derivation(e)),
        }
    }

    /// A second key equal to this one, erased on its own drop: to derive another branch while
    /// this one is kept.
    pub(crate) fn duplicate(&self) -> Self {
        Self(self.0)
    }

    /// Replaces this key by its descendant at `path`, one level at a time: each parent is erased
    /// as soon as its child exists, and on an error the key is erased.
    pub(crate) fn derive_in_place<C: Signing>(
        &mut self,
        secp: &Secp256k1<C>,
        path: &[ChildNumber],
    ) -> Result<(), CoreError> {
        for child in path {
            match self.0.derive_priv(secp, &[*child]) {
                Ok(mut next) => {
                    self.erase();
                    self.0 = next;
                    erase(&mut next);
                }
                Err(e) => {
                    self.erase();
                    return Err(derivation(e));
                }
            }
        }
        Ok(())
    }

    /// The key's BIP32 fingerprint (public).
    pub(crate) fn fingerprint<C: Signing>(&self, secp: &Secp256k1<C>) -> Fingerprint {
        self.0.fingerprint(secp)
    }

    /// The extended public key (public).
    pub(crate) fn xpub<C: Signing>(&self, secp: &Secp256k1<C>) -> Xpub {
        Xpub::from_priv(secp, &self.0)
    }

    /// Overwrites the key and chain code.
    fn erase(&mut self) {
        erase(&mut self.0);
    }
}

impl Drop for SecretXpriv {
    fn drop(&mut self) {
        self.erase();
    }
}

/// m/84'/0'/0'/0/0 (BIP84: purpose, coin, account hardened; receive chain, first index).
fn first_receive_path() -> Result<[ChildNumber; 5], CoreError> {
    Ok([
        ChildNumber::from_hardened_idx(84).map_err(derivation)?,
        ChildNumber::from_hardened_idx(0).map_err(derivation)?,
        ChildNumber::from_hardened_idx(0).map_err(derivation)?,
        ChildNumber::from_normal_idx(0).map_err(derivation)?,
        ChildNumber::from_normal_idx(0).map_err(derivation)?,
    ])
}

pub(crate) fn derivation<E>(_: E) -> CoreError {
    CoreError::Internal(InternalFault::KeyDerivation)
}

/// Overwrites an extended private key's secret parts, with volatile writes that the compiler
/// keeps even when the key is dead afterwards: the private key becomes secp256k1's dummy key
/// (`[1; 32]`, as zero is not a valid key) and the chain code zero.
fn erase(key: &mut Xpriv) {
    key.private_key.non_secure_erase();
    let chain_code: &mut [u8; 32] = key.chain_code.as_mut();
    chain_code.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::TestFill;
    use crate::test_vectors::{hex, keepcrypt_json, named, read, text};
    use serde_json::Value;
    use std::str::FromStr;

    // White box: S fills and wipes like the seed it wraps.
    impl TestFill for EmptyPassphraseSeed {
        fn fill(&mut self) {
            self.0.fill();
        }
        fn is_zero(&self) -> bool {
            self.0.is_zero()
        }
    }

    #[test]
    fn empty_passphrase_seed_zeroizes() {
        let mut seed = EmptyPassphraseSeed::zeroed();
        seed.fill();
        assert!(!seed.is_zero());
        seed.zeroize();
        assert!(seed.is_zero());
    }

    const _: () = assert_zeroize_on_drop::<EmptyPassphraseSeed>();

    fn d_from(v: &Value) -> SecretBytes32 {
        let mut d = SecretBytes32::zeroed();
        d.expose_secret_mut().copy_from_slice(&hex(v));
        d
    }

    // Owned copies: a word borrows its mnemonic, which is dropped here. Test vectors only.
    fn words(e: &SecretBytes32, len: SeedLength) -> Vec<String> {
        let mut mnemonic = SecretMnemonic::zeroed();
        let mut seed = EmptyPassphraseSeed::zeroed();
        assert_eq!(
            mnemonic_and_seed_into(e, len, &mut mnemonic, &mut seed),
            Ok(())
        );
        mnemonic.words().map(str::to_owned).collect()
    }

    fn listed(v: &Value) -> Vec<&str> {
        v.as_array()
            .expect("a word list")
            .iter()
            .map(text)
            .collect()
    }

    // S from the words equals S from E, for every mixed case at both lengths; a word changed so the
    // checksum breaks, or a word count other than 12 or 24, gives no S. checksum_is_valid tells the
    // two apart: false for the broken checksum, Internal(Bip39) for the count.
    #[test]
    fn s_from_the_words_equals_s_from_e() {
        for case in keepcrypt_json()["mixed"].as_array().expect("cases") {
            let e = d_from(&case["e_hex"]);
            for len in [SeedLength::Words12, SeedLength::Words24] {
                let mut mnemonic = SecretMnemonic::zeroed();
                let mut from_e = EmptyPassphraseSeed::zeroed();
                assert_eq!(
                    mnemonic_and_seed_into(&e, len, &mut mnemonic, &mut from_e),
                    Ok(())
                );
                let mut from_words = EmptyPassphraseSeed::zeroed();
                assert_eq!(seed_from_mnemonic_into(&mnemonic, &mut from_words), Ok(()));
                assert_eq!(
                    from_words.as_seed().expose_secret(),
                    from_e.as_seed().expose_secret()
                );
                let mut broken = SecretMnemonic::zeroed();
                let mut indices: Vec<usize> =
                    mnemonic.indices().iter().map(|&i| usize::from(i)).collect();
                // The last word's low bit is a checksum bit (4 of them for 12 words, 8 for 24).
                if let Some(last) = indices.last_mut() {
                    *last ^= 1;
                }
                assert_eq!(broken.fill_from(indices.into_iter()), Ok(()));
                let mut none = EmptyPassphraseSeed::zeroed();
                assert_eq!(
                    seed_from_mnemonic_into(&broken, &mut none),
                    Err(CoreError::Internal(InternalFault::Bip39))
                );
                assert_eq!(checksum_is_valid(&mnemonic), Ok(true));
                assert_eq!(checksum_is_valid(&broken), Ok(false));
            }
        }
        let mut empty = EmptyPassphraseSeed::zeroed();
        assert_eq!(
            seed_from_mnemonic_into(&SecretMnemonic::zeroed(), &mut empty),
            Err(CoreError::Internal(InternalFault::Bip39))
        );
        assert_eq!(
            checksum_is_valid(&SecretMnemonic::zeroed()),
            Err(CoreError::Internal(InternalFault::Bip39))
        );
    }

    #[test]
    fn tags_match_keepcrypt_json() {
        let constants = &keepcrypt_json()["constants"];
        assert_eq!(text(&constants["commit_tag_ascii"]).as_bytes(), COMMIT_TAG);
        assert_eq!(text(&constants["seed_tag_ascii"]).as_bytes(), SEED_TAG);
    }

    #[test]
    fn commitment_cases() {
        let doc = keepcrypt_json();
        for case in doc["commitment"].as_array().expect("cases") {
            assert_eq!(
                commitment(&d_from(&case["d_hex"])).to_vec(),
                hex(&case["c_hex"]),
                "{}",
                text(&case["name"])
            );
        }
        for case in doc["source_substitution"].as_array().expect("cases") {
            assert_eq!(
                commitment(&d_from(&case["d_hex"])).to_vec(),
                hex(&case["c_hex"]),
                "{}",
                text(&case["name"])
            );
        }
    }

    #[test]
    fn mixed_cases_and_their_words() {
        for case in keepcrypt_json()["mixed"].as_array().expect("cases") {
            let name = text(&case["name"]);
            let mut e = SecretBytes32::zeroed();
            assert_eq!(
                mixed_entropy_into(
                    &d_from(&case["d_hex"]),
                    text(&case["rolls"]).as_bytes(),
                    &mut e
                ),
                Ok(())
            );
            assert_eq!(e.expose_secret().to_vec(), hex(&case["e_hex"]), "{name}");
            assert_eq!(
                words(&e, SeedLength::Words12),
                listed(&case["words_12"]),
                "{name}"
            );
            assert_eq!(
                words(&e, SeedLength::Words24),
                listed(&case["words_24"]),
                "{name}"
            );
        }
    }

    #[test]
    fn the_length_of_r_is_hashed() {
        let doc = keepcrypt_json();
        let case = named(&doc["mixed"], "d-00-1f-coldcard-50");
        let d = d_from(&case["d_hex"]);
        let rolls = text(&case["rolls"]).as_bytes();
        let without_len: [u8; 32] = Sha256::new()
            .chain_update(SEED_TAG)
            .chain_update(d.expose_secret())
            .chain_update(rolls)
            .finalize()
            .into();
        let mut e = SecretBytes32::zeroed();
        assert_eq!(mixed_entropy_into(&d, rolls, &mut e), Ok(()));
        assert_ne!(e.expose_secret(), &without_len);
    }

    // keepcrypt.json's dice-only cases (Coldcard's rolls.py and rolls12.py re-run on each by
    // verify.py check 4), and vectors/coldcard/rolls.json itself.
    #[test]
    fn dice_only_matches_coldcard() {
        let doc = keepcrypt_json();
        let coldcard = read("coldcard/rolls.json");
        let mut cases: Vec<(String, &str, &Value, &Value, &Value)> = Vec::new();
        for case in doc["dice_only"].as_array().expect("cases") {
            cases.push((
                text(&case["name"]).to_owned(),
                text(&case["rolls"]),
                &case["e_hex"],
                &case["words_12"],
                &case["words_24"],
            ));
        }
        for case in coldcard["cases"].as_array().expect("cases") {
            cases.push((
                "rolls.json".to_owned(),
                text(&case["rolls"]),
                &case["sha256_hex"],
                &case["words_12"],
                &case["words_24"],
            ));
        }
        assert_eq!(cases.len(), 10);
        for (name, rolls, e_hex, words_12, words_24) in cases {
            let mut e = SecretBytes32::zeroed();
            dice_only_entropy_into(rolls.as_bytes(), &mut e);
            assert_eq!(e.expose_secret().to_vec(), hex(e_hex), "{name}");
            assert_eq!(words(&e, SeedLength::Words12), listed(words_12), "{name}");
            assert_eq!(words(&e, SeedLength::Words24), listed(words_24), "{name}");
        }
    }

    // BIP39 vectors.json (TREZOR): the 12- and 24-word entries encode as published, and the master
    // fingerprint from each published seed is that of the published xprv.
    #[test]
    fn bip39_vectors_json() {
        let english = read("bip39/vectors.json")["english"]
            .as_array()
            .expect("english")
            .clone();
        let mut checked = 0;
        for entry in &english {
            let entropy = hex(&entry[0]);
            let len = match entropy.len() {
                16 => SeedLength::Words12,
                32 => SeedLength::Words24,
                _ => continue,
            };
            let mut e = SecretBytes32::zeroed();
            e.expose_secret_mut()[..entropy.len()].copy_from_slice(&entropy);
            assert_eq!(words(&e, len).join(" "), text(&entry[1]));
            // A TREZOR-passphrase seed: a plain SecretSeed64, which wallet_summary does not take.
            let mut seed = SecretSeed64::zeroed();
            seed.expose_secret_mut().copy_from_slice(&hex(&entry[2]));
            let secp = Secp256k1::signing_only();
            let master = SecretXpriv::master(&seed).expect("a master");
            let xprv = Xpriv::from_str(text(&entry[3])).expect("an xprv");
            assert_eq!(
                master.fingerprint(&secp).to_bytes(),
                xprv.fingerprint(&secp).to_bytes()
            );
            checked += 1;
        }
        assert_eq!(checked, 16);
    }

    // BIP-84 test vector (abandon x 11 + about): fingerprint 73c5da0a, first receive address
    // bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu (tasks/todo.md, M1 group 4).
    #[test]
    fn bip84_fingerprint_and_first_address() {
        let e = SecretBytes32::zeroed();
        let mut mnemonic = SecretMnemonic::zeroed();
        let mut seed = EmptyPassphraseSeed::zeroed();
        assert_eq!(
            mnemonic_and_seed_into(&e, SeedLength::Words12, &mut mnemonic, &mut seed),
            Ok(())
        );
        assert_eq!(
            mnemonic.words().collect::<Vec<_>>().join(" "),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        assert_eq!(
            seed.as_seed().expose_secret()[..16],
            hex_16("5eb00bbddcf069084889a8ab91555681"),
            "S uses the empty passphrase"
        );
        let summary = wallet_summary(&seed).expect("a summary");
        assert_eq!(summary.fingerprint, [0x73, 0xc5, 0xda, 0x0a]);
        assert_eq!(
            summary.first_address,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
    }

    // White box (review fix after commit 15): the master binding is overwritten in place by its
    // descendant, which equals rust-bitcoin's one-shot derivation; erasing leaves the dummy key
    // and a zero chain code; a duplicate is erased on its own; a failed step erases the key.
    #[test]
    fn secret_xpriv_derives_in_place_and_erases() {
        let secp = Secp256k1::signing_only();
        let mut seed = SecretSeed64::zeroed();
        seed.expose_secret_mut().copy_from_slice(&[7u8; 64]);
        let path = first_receive_path().expect("a path");
        let mut key = SecretXpriv::master(&seed).expect("a master");
        let master = key.0; // a bare copy, test only
        assert_ne!(master.chain_code.to_bytes(), [0u8; 32]);
        key.derive_in_place(&secp, &path).expect("a leaf");
        assert_eq!(key.0, master.derive_priv(&secp, &path).expect("one shot"));
        assert_ne!(key.0.private_key, master.private_key);
        assert_ne!(key.0.chain_code, master.chain_code);
        let duplicate = key.duplicate();
        drop(duplicate);
        assert_eq!(key.0, master.derive_priv(&secp, &path).expect("one shot"));
        key.erase();
        assert_eq!(key.0.private_key.secret_bytes(), [1u8; 32]);
        assert_eq!(key.0.chain_code.to_bytes(), [0u8; 32]);
        // A child of depth 256 cannot exist: the step fails, and the key is erased.
        let mut deep = SecretXpriv(Xpriv {
            depth: 255,
            ..master
        });
        assert_eq!(
            deep.derive_in_place(&secp, &path),
            Err(CoreError::Internal(InternalFault::KeyDerivation))
        );
        assert_eq!(deep.0.private_key.secret_bytes(), [1u8; 32]);
        assert_eq!(deep.0.chain_code.to_bytes(), [0u8; 32]);
    }

    fn hex_16(s: &str) -> [u8; 16] {
        let bytes = crate::test_vectors::hex_str(s);
        let mut out = [0u8; 16];
        out.copy_from_slice(&bytes);
        out
    }

    // CLAUDE.md rule 2, D: each of the 256 single-bit flips of D changes both C and mixed E (R
    // fixed). Base D: keepcrypt.json commitment "d-stream", SHA-256 counter mode.
    #[test]
    fn every_bit_of_d_reaches_c_and_e() {
        let doc = keepcrypt_json();
        let base = hex(&named(&doc["commitment"], "d-stream")["d_hex"]);
        let rolls = text(&named(&doc["mixed"], "d-00-1f-coldcard-50")["rolls"])
            .as_bytes()
            .to_vec();
        let c_and_e = |d_bytes: &[u8]| {
            let mut d = SecretBytes32::zeroed();
            d.expose_secret_mut().copy_from_slice(d_bytes);
            let mut e = SecretBytes32::zeroed();
            assert_eq!(mixed_entropy_into(&d, &rolls, &mut e), Ok(()));
            (commitment(&d), *e.expose_secret())
        };
        let (c0, e0) = c_and_e(&base);
        for bit in 0..256 {
            let mut flipped = base.clone();
            flipped[bit / 8] ^= 0x80 >> (bit % 8);
            let (c, e) = c_and_e(&flipped);
            assert!(c != c0 && e != e0, "bit {bit} of D did not change C and E");
        }
    }

    // CLAUDE.md rule 2, E: for 24 words each of the 256 single-bit flips of E changes the words;
    // for 12 words each flip in E[0..16] does and each flip in E[16..32] does not, since 12 words
    // are the first 128 bits by design. Base E: keepcrypt.json mixed "d-stream-coldcard-99".
    #[test]
    fn every_bit_of_e_reaches_the_words() {
        let base = hex(&named(&keepcrypt_json()["mixed"], "d-stream-coldcard-99")["e_hex"]);
        let e_from = |bytes: &[u8]| {
            let mut e = SecretBytes32::zeroed();
            e.expose_secret_mut().copy_from_slice(bytes);
            e
        };
        let base_e = e_from(&base);
        let (w12, w24) = (
            words(&base_e, SeedLength::Words12),
            words(&base_e, SeedLength::Words24),
        );
        for bit in 0..256 {
            let mut flipped = base.clone();
            flipped[bit / 8] ^= 0x80 >> (bit % 8);
            let e = e_from(&flipped);
            assert_ne!(
                words(&e, SeedLength::Words24),
                w24,
                "bit {bit} did not change the 24 words"
            );
            if bit < 128 {
                assert_ne!(
                    words(&e, SeedLength::Words12),
                    w12,
                    "bit {bit} did not change the 12 words"
                );
            } else {
                assert_eq!(
                    words(&e, SeedLength::Words12),
                    w12,
                    "bit {bit} is past the 12-word entropy"
                );
            }
        }
    }
}
