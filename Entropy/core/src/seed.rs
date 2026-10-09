//! From the two legs to the words (CLAUDE.md "Commitment", "Seed (mixed mode)", "Seed (dice
//! only)", "Seed length"; docs/design.md "From entropy to a BIP39 seed phrase"; docs/build-plan.md
//! "Invariants"; tasks/todo.md, M1 group 4).
//!
//! - C = SHA256("KCE/v1/commit" || D), shown before any roll.
//! - Mixed: E = SHA256("KCE/v1/seed" || D || len(R) as u64 big-endian || R).
//! - Dice only: E = SHA256(R), the same as Coldcard's rolls.py.
//! - 12 words from E[0..16], 24 from all of E, through the bip39 crate's English list, converted
//!   at once into a `SecretMnemonic`; S = the BIP39 seed with the empty passphrase, which is what
//!   the seal and the fingerprint use.
//! - The wallet summary is the master fingerprint and the m/84'/0'/0'/0/0 P2WPKH mainnet address.
//!   The extended private keys stay inside `wallet_summary` and are erased there; the secp256k1
//!   context is not randomized (rust-bitcoin's `rand-std` is off).
//!
//! Every value is written in place into the session's zeroizing fields, so no secret is moved.
//! The words, S and the wallet summary are derived once, in `finish` (M1 group 9); until the
//! session calls them, only the commitment and E have a caller outside the tests (the Seed KAT).
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "Session::finish derives the words (M1 group 9)")
)]

use bitcoin::bip32::{ChainCode, ChildNumber, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network, NetworkKind};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{CoreError, InternalFault};
use crate::secret::{SecretBytes32, SecretMnemonic, SecretSeed64};
use crate::session::SeedLength;

/// The commitment's domain tag.
pub(crate) const COMMIT_TAG: &[u8] = b"KCE/v1/commit";
/// The mixed seed's domain tag.
pub(crate) const SEED_TAG: &[u8] = b"KCE/v1/seed";

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

/// From E: the words (12 from E[0..16], 24 from all 32 bytes) into `mnemonic`, and S, the BIP39
/// seed with the empty passphrase, into `seed`.
pub(crate) fn mnemonic_and_seed_into(
    e: &SecretBytes32,
    len: SeedLength,
    mnemonic: &mut SecretMnemonic,
    seed: &mut SecretSeed64,
) -> Result<(), CoreError> {
    let entropy = match len {
        SeedLength::Words12 => &e.expose_secret()[..16],
        SeedLength::Words24 => &e.expose_secret()[..],
    };
    let words = bip39::Mnemonic::from_entropy_in(bip39::Language::English, entropy)
        .map_err(|_| CoreError::Internal(InternalFault::Bip39))?;
    mnemonic.fill_from(words.word_indices())?;
    let s = Zeroizing::new(words.to_seed_normalized(""));
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

/// The wallet summary from S. The extended private keys exist only in this function, and their
/// keys and chain codes are overwritten before it returns, on every path.
pub(crate) fn wallet_summary(seed: &SecretSeed64) -> Result<WalletSummary, CoreError> {
    let secp = Secp256k1::signing_only();
    let mut master =
        Xpriv::new_master(NetworkKind::Main, seed.expose_secret()).map_err(derivation)?;
    let fingerprint = master.fingerprint(&secp).to_bytes();
    let first =
        first_receive_path().and_then(|path| master.derive_priv(&secp, &path).map_err(derivation));
    erase(&mut master);
    let mut first = first?;
    let public = Xpub::from_priv(&secp, &first).to_pub();
    erase(&mut first);
    Ok(WalletSummary {
        fingerprint,
        first_address: Address::p2wpkh(&public, Network::Bitcoin).to_string(),
    })
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

fn derivation<E>(_: E) -> CoreError {
    CoreError::Internal(InternalFault::KeyDerivation)
}

/// Overwrites an extended private key's secret parts.
fn erase(key: &mut Xpriv) {
    key.private_key.non_secure_erase();
    key.chain_code = ChainCode::from([0u8; 32]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::{hex, keepcrypt_json, named, read, text};
    use serde_json::Value;
    use std::str::FromStr;

    fn d_from(v: &Value) -> SecretBytes32 {
        let mut d = SecretBytes32::zeroed();
        d.expose_secret_mut().copy_from_slice(&hex(v));
        d
    }

    fn words(e: &SecretBytes32, len: SeedLength) -> Vec<&'static str> {
        let mut mnemonic = SecretMnemonic::zeroed();
        let mut seed = SecretSeed64::zeroed();
        assert_eq!(
            mnemonic_and_seed_into(e, len, &mut mnemonic, &mut seed),
            Ok(())
        );
        mnemonic.words().collect()
    }

    fn listed(v: &Value) -> Vec<&str> {
        v.as_array()
            .expect("a word list")
            .iter()
            .map(text)
            .collect()
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
            let mut seed = SecretSeed64::zeroed();
            seed.expose_secret_mut().copy_from_slice(&hex(&entry[2]));
            let summary = wallet_summary(&seed).expect("a summary");
            let xprv = Xpriv::from_str(text(&entry[3])).expect("an xprv");
            assert_eq!(
                summary.fingerprint,
                xprv.fingerprint(&Secp256k1::signing_only()).to_bytes()
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
        let mut seed = SecretSeed64::zeroed();
        assert_eq!(
            mnemonic_and_seed_into(&e, SeedLength::Words12, &mut mnemonic, &mut seed),
            Ok(())
        );
        assert_eq!(
            mnemonic.words().collect::<Vec<_>>().join(" "),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        assert_eq!(
            seed.expose_secret()[..16],
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
