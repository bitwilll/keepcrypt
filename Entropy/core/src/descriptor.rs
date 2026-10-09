//! The watch-only export (docs/build-plan.md "descriptor"; docs/seal-watchonly-braille.md
//! "Watch-only export"; tasks/todo.md, M1 group 6, Q2 and Q5).
//!
//! From a BIP39 seed: the master fingerprint, the BIP84 account key m/84'/0'/0' as an xpub, the
//! receive and change descriptors and the first receive address, and the BCR-2020-015 v1
//! `crypto-account` as a single-part UR for the account QR. Public keys only; nothing is written
//! as a file.
//!
//! - The descriptors are `wpkh([fingerprint/84h/0h/0h]xpub/0/*)` and `.../1/*`, written by core
//!   with `h` and checksummed with miniscript's BIP-380 checksum `Engine`. miniscript's `Display`
//!   is never used: it writes `'`, which changes the checksum.
//! - A runtime self-check fails closed (CLAUDE.md rule 3): each descriptor string must parse with
//!   `Descriptor::from_str` (which checks the checksum), equal the descriptor built from its parts,
//!   and give at index 0 the address derived privately from the seed. Otherwise the export is
//!   `ExportSelfCheck`, and nothing is shown.
//! - Extended private keys are derived one level at a time and erased as they are replaced
//!   (`seed::derive_erasing`); the residual copies inside rust-bitcoin are those recorded for the
//!   wallet summary (tasks/todo.md, M1 group 4).
//! - `WatchOnlyExport` is zeroized on drop and has no `Debug`, `Display`, `Clone` or `Serialize`:
//!   an xpub reveals every address and balance of the wallet.
//!
//! vectors/watchonly.json pins every field for six wallets, among them BIP-84's vector and
//! BCR-2020-015's shield seed.

use core::str::FromStr;

use bitcoin::Network;
use bitcoin::NetworkKind;
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::secp256k1::{Secp256k1, Signing, Verification};
use miniscript::Descriptor;
use miniscript::descriptor::checksum::Engine;
use miniscript::descriptor::{DescriptorPublicKey, DescriptorXKey, Wildcard};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CoreError;
use crate::secret::SecretSeed64;
use crate::seed::{derivation, derive_erasing, erase};
use crate::ur::{Item, cbor_encode, ur_single};

/// The UR type of the account QR (BCR-2020-015 v1; Q2).
pub(crate) const ACCOUNT_UR_TYPE: &str = "crypto-account";
/// CBOR tags of the v1 account output: crypto-output, witness-public-key-hash, crypto-hdkey,
/// crypto-keypath (BCR-2020-015 example; BCR-2020-007 version 1).
const TAG_OUTPUT: u64 = 308;
const TAG_WPKH: u64 = 404;
const TAG_HDKEY: u64 = 303;
const TAG_KEYPATH: u64 = 304;

/// What the account QR and the descriptor QR show: public keys only, but an xpub reveals every
/// address, so it is wiped on drop and cannot be printed or copied by accident.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WatchOnlyExport {
    fingerprint: [u8; 4],
    xpub: String,
    receive: String,
    change: String,
    ur: String,
    qr_text: String,
    first_address: String,
    passphrase_used: bool,
}

impl WatchOnlyExport {
    /// The exported wallet's master key fingerprint (that of the passphrase wallet, if one was
    /// given).
    pub fn fingerprint(&self) -> [u8; 4] {
        self.fingerprint
    }

    /// The account key m/84'/0'/0' as an xpub.
    pub fn xpub(&self) -> &str {
        &self.xpub
    }

    /// `wpkh([fingerprint/84h/0h/0h]xpub/0/*)#checksum`, for receiving.
    pub fn receive_descriptor(&self) -> &str {
        &self.receive
    }

    /// `wpkh([fingerprint/84h/0h/0h]xpub/1/*)#checksum`, for change.
    pub fn change_descriptor(&self) -> &str {
        &self.change
    }

    /// The `ur:crypto-account/...` text, lowercase.
    pub fn ur(&self) -> &str {
        &self.ur
    }

    /// The same UR in uppercase, for the QR code's alphanumeric mode.
    pub fn qr_text(&self) -> &str {
        &self.qr_text
    }

    /// The exported wallet's own first receive address, m/84'/0'/0'/0/0: with a BIP39 passphrase,
    /// the one Sparrow or Core must show, not the wallet summary's (Q10).
    pub fn first_address(&self) -> &str {
        &self.first_address
    }

    /// True if a BIP39 passphrase made this wallet.
    pub fn passphrase_used(&self) -> bool {
        self.passphrase_used
    }
}

/// The export of the wallet whose BIP39 seed is `seed` (S, or the passphrase wallet's seed).
pub(crate) fn watch_only_export(
    seed: &SecretSeed64,
    passphrase_used: bool,
) -> Result<WatchOnlyExport, CoreError> {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(NetworkKind::Main, seed.expose_secret()).map_err(derivation)?;
    let fingerprint = master.fingerprint(&secp);
    let mut account = derive_erasing(&secp, master, &account_path()?)?;
    let keys = account_keys(&secp, &account);
    erase(&mut account);
    let keys = keys?;
    let xpub = keys.xpub.to_string();
    let receive = descriptor_text(fingerprint, &xpub, 0)?;
    let change = descriptor_text(fingerprint, &xpub, 1)?;
    self_check(
        &secp,
        &receive,
        &build_descriptor(fingerprint, keys.xpub, 0)?,
        &keys.receive,
    )?;
    self_check(
        &secp,
        &change,
        &build_descriptor(fingerprint, keys.xpub, 1)?,
        &keys.change,
    )?;
    let master_fp = u32::from_be_bytes(fingerprint.to_bytes());
    let parent_fp = u32::from_be_bytes(keys.xpub.parent_fingerprint.to_bytes());
    let public_key = keys.xpub.public_key.serialize();
    let chain_code = keys.xpub.chain_code.to_bytes();
    let output = tagged(
        &[TAG_OUTPUT, TAG_WPKH],
        hdkey_item(
            &public_key,
            &chain_code,
            &[(84, true), (0, true), (0, true)],
            master_fp,
            parent_fp,
        ),
    );
    let cbor = cbor_encode(&account_item(master_fp, vec![output]))?;
    let ur = ur_single(ACCOUNT_UR_TYPE, &cbor);
    Ok(WatchOnlyExport {
        fingerprint: fingerprint.to_bytes(),
        xpub,
        receive,
        change,
        qr_text: ur.to_ascii_uppercase(),
        ur,
        first_address: keys.receive,
        passphrase_used,
    })
}

/// m/84'/0'/0': BIP84 purpose, Bitcoin, account 0, all hardened.
fn account_path() -> Result<[ChildNumber; 3], CoreError> {
    Ok([
        ChildNumber::from_hardened_idx(84).map_err(derivation)?,
        ChildNumber::from_hardened_idx(0).map_err(derivation)?,
        ChildNumber::from_hardened_idx(0).map_err(derivation)?,
    ])
}

/// The account's xpub and its first receive and change addresses, derived privately.
struct AccountKeys {
    xpub: Xpub,
    receive: String,
    change: String,
}

fn account_keys<C: Signing>(
    secp: &Secp256k1<C>,
    account: &Xpriv,
) -> Result<AccountKeys, CoreError> {
    Ok(AccountKeys {
        xpub: Xpub::from_priv(secp, account),
        receive: first_address(secp, account, 0)?,
        change: first_address(secp, account, 1)?,
    })
}

/// The address of `account`/`chain`/0, derived from the private key.
fn first_address<C: Signing>(
    secp: &Secp256k1<C>,
    account: &Xpriv,
    chain: u32,
) -> Result<String, CoreError> {
    let path = [
        ChildNumber::from_normal_idx(chain).map_err(derivation)?,
        ChildNumber::from_normal_idx(0).map_err(derivation)?,
    ];
    let mut leaf = derive_erasing(secp, *account, &path)?;
    let public = Xpub::from_priv(secp, &leaf).to_pub();
    erase(&mut leaf);
    Ok(bitcoin::Address::p2wpkh(&public, Network::Bitcoin).to_string())
}

/// `wpkh([fingerprint/84h/0h/0h]xpub/chain/*)#checksum`, written by core, never by miniscript.
fn descriptor_text(fingerprint: Fingerprint, xpub: &str, chain: u32) -> Result<String, CoreError> {
    let fp = fingerprint.to_bytes();
    let body = format!(
        "wpkh([{:02x}{:02x}{:02x}{:02x}/84h/0h/0h]{xpub}/{chain}/*)",
        fp[0], fp[1], fp[2], fp[3]
    );
    let checksum = checksum(&body)?;
    Ok(format!("{body}#{checksum}"))
}

/// The BIP-380 checksum of a descriptor, from miniscript's `Engine`.
pub(crate) fn checksum(descriptor: &str) -> Result<String, CoreError> {
    let mut engine = Engine::new();
    engine
        .input(descriptor)
        .map_err(|_| CoreError::ExportSelfCheck)?;
    Ok(engine.checksum_chars().iter().collect())
}

/// The descriptor the string must equal: wpkh of the account xpub, origin [fingerprint/84'/0'/0'],
/// then /chain/*.
fn build_descriptor(
    fingerprint: Fingerprint,
    xpub: Xpub,
    chain: u32,
) -> Result<Descriptor<DescriptorPublicKey>, CoreError> {
    let origin = DerivationPath::from(account_path()?.to_vec());
    let children = DerivationPath::from(vec![
        ChildNumber::from_normal_idx(chain).map_err(derivation)?,
    ]);
    let key = DescriptorPublicKey::XPub(DescriptorXKey {
        origin: Some((fingerprint, origin)),
        xkey: xpub,
        derivation_path: children,
        wildcard: Wildcard::Unhardened,
    });
    Descriptor::new_wpkh(key).map_err(|_| CoreError::ExportSelfCheck)
}

/// The runtime self-check: `text` parses (checksum included), equals `built`, and gives `address`
/// at index 0.
pub(crate) fn self_check<C: Verification>(
    secp: &Secp256k1<C>,
    text: &str,
    built: &Descriptor<DescriptorPublicKey>,
    address: &str,
) -> Result<(), CoreError> {
    let parsed = Descriptor::<DescriptorPublicKey>::from_str(text)
        .map_err(|_| CoreError::ExportSelfCheck)?;
    if &parsed != built {
        return Err(CoreError::ExportSelfCheck);
    }
    let derived = parsed
        .at_derivation_index(0)
        .map_err(|_| CoreError::ExportSelfCheck)?
        .derived_descriptor(secp)
        .address(Network::Bitcoin)
        .map_err(|_| CoreError::ExportSelfCheck)?;
    if derived.to_string() != address {
        return Err(CoreError::ExportSelfCheck);
    }
    Ok(())
}

/// A v1 crypto-hdkey (tag 303): key-data, chain-code, the crypto-keypath origin (tag 304) and the
/// parent fingerprint. A zero source or parent fingerprint is left out (BCR-2020-007: uint32
/// .ne 0).
pub(crate) fn hdkey_item<'a>(
    public_key: &'a [u8],
    chain_code: &'a [u8],
    components: &[(u32, bool)],
    source_fingerprint: u32,
    parent_fingerprint: u32,
) -> Item<'a> {
    let path = components
        .iter()
        .flat_map(|&(index, hardened)| [Item::Uint(u64::from(index)), Item::Bool(hardened)])
        .collect();
    let mut keypath = vec![(1, Item::Array(path))];
    if source_fingerprint != 0 {
        keypath.push((2, Item::Uint(u64::from(source_fingerprint))));
    }
    let mut fields = vec![
        (3, Item::Bytes(public_key)),
        (4, Item::Bytes(chain_code)),
        (6, Item::Tag(TAG_KEYPATH, Box::new(Item::Map(keypath)))),
    ];
    if parent_fingerprint != 0 {
        fields.push((8, Item::Uint(u64::from(parent_fingerprint))));
    }
    Item::Tag(TAG_HDKEY, Box::new(Item::Map(fields)))
}

/// `item` inside `tags`, the first tag outermost.
pub(crate) fn tagged<'a>(tags: &[u64], item: Item<'a>) -> Item<'a> {
    tags.iter()
        .rev()
        .fold(item, |inner, &tag| Item::Tag(tag, Box::new(inner)))
}

/// A v1 crypto-account, untagged at the top level: {1: master fingerprint, 2: [outputs]}.
pub(crate) fn account_item(master_fingerprint: u32, outputs: Vec<Item<'_>>) -> Item<'_> {
    Item::Map(vec![
        (1, Item::Uint(u64::from(master_fingerprint))),
        (2, Item::Array(outputs)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::{Bip39Passphrase, SecretBytes32, SecretMnemonic};
    use crate::seed::{mnemonic_and_seed_into, passphrase_seed_into};
    use crate::session::SeedLength;
    use crate::test_vectors::{hex, hex_str, named, read, text};
    use serde_json::Value;

    // The export of an exported wallet must wipe itself (CLAUDE.md rule 5).
    const fn zeroize_on_drop<T: ZeroizeOnDrop>() {}
    const _: () = zeroize_on_drop::<WatchOnlyExport>();

    fn watchonly() -> Value {
        read("watchonly.json")
    }

    fn array(v: &Value) -> &Vec<Value> {
        v.as_array().expect("a list")
    }

    /// E and the length for a public test mnemonic, as the session would hold them.
    fn entropy_of(mnemonic: &str) -> (SecretBytes32, SeedLength) {
        let parsed = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, mnemonic)
            .expect("a test mnemonic");
        let entropy = parsed.to_entropy();
        let mut e = SecretBytes32::zeroed();
        e.expose_secret_mut()[..entropy.len()].copy_from_slice(&entropy);
        let len = match entropy.len() {
            16 => SeedLength::Words12,
            _ => SeedLength::Words24,
        };
        (e, len)
    }

    /// The seed the session uses for an export: S, or the passphrase wallet's seed.
    fn seed_of(mnemonic: &str, passphrase: Option<&str>) -> SecretSeed64 {
        let (e, len) = entropy_of(mnemonic);
        let mut seed = SecretSeed64::zeroed();
        match passphrase {
            None => {
                let mut words = SecretMnemonic::zeroed();
                assert_eq!(
                    mnemonic_and_seed_into(&e, len, &mut words, &mut seed),
                    Ok(())
                );
            }
            Some(p) => {
                let p = Bip39Passphrase::new(p).expect("a non-empty passphrase");
                assert_eq!(passphrase_seed_into(&e, len, &p, &mut seed), Ok(()));
            }
        }
        seed
    }

    fn export_of(mnemonic: &str, passphrase: Option<&str>) -> WatchOnlyExport {
        watch_only_export(&seed_of(mnemonic, passphrase), passphrase.is_some()).expect("an export")
    }

    fn fingerprint_hex(export: &WatchOnlyExport) -> String {
        export
            .fingerprint()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    // All six watchonly.json wallets, every field; the descriptors use h, never an apostrophe, and
    // so never carry the apostrophe form's checksum.
    #[test]
    fn every_wallet_matches_watchonly_json() {
        let doc = watchonly();
        let wallets = array(&doc["wallets"]);
        assert_eq!(wallets.len(), 6);
        for w in wallets {
            let name = text(&w["name"]);
            let export = export_of(text(&w["mnemonic"]), w["passphrase"].as_str());
            assert_eq!(fingerprint_hex(&export), text(&w["fingerprint"]), "{name}");
            assert_eq!(export.xpub(), text(&w["account_xpub"]), "{name}");
            assert_eq!(
                export.receive_descriptor(),
                text(&w["receive_descriptor"]),
                "{name}"
            );
            assert_eq!(
                export.change_descriptor(),
                text(&w["change_descriptor"]),
                "{name}"
            );
            assert_eq!(
                export.first_address(),
                text(&w["first_receive_address"]),
                "{name}"
            );
            assert_eq!(export.ur(), text(&w["crypto_account_ur"]), "{name}");
            assert_eq!(export.qr_text(), text(&w["qr_text"]), "{name}");
            assert_eq!(
                export.passphrase_used(),
                !w["passphrase"].is_null(),
                "{name}"
            );
            assert_eq!(
                ur_single(ACCOUNT_UR_TYPE, &hex(&w["crypto_account_cbor_hex"])),
                export.ur(),
                "{name}: the CBOR"
            );
            let both = [export.receive_descriptor(), export.change_descriptor()].concat();
            assert!(!both.contains('\''), "{name}");
            let apostrophe = text(&w["receive_descriptor_apostrophe"]);
            assert_ne!(
                &apostrophe[apostrophe.len() - 8..],
                &export.receive_descriptor()[export.receive_descriptor().len() - 8..]
            );
        }
    }

    // BIP-84's vector and the plan's abandon pins: fingerprint 73c5da0a, receive #afwvtk2s, change
    // #vatdkr6g, a 116-byte crypto-account and a 258-character UR; the first change address too.
    #[test]
    fn bip84_vector() {
        let doc = watchonly();
        let export = export_of(text(&doc["bip84"]["mnemonic"]), None);
        assert_eq!(fingerprint_hex(&export), "73c5da0a");
        assert_eq!(export.xpub(), text(&doc["bip84"]["account_xpub"]));
        assert!(export.receive_descriptor().ends_with("#afwvtk2s"));
        assert!(export.change_descriptor().ends_with("#vatdkr6g"));
        assert_eq!(export.ur().len(), 258);
        assert!(export.ur().starts_with("ur:crypto-account/"));
        let abandon = named(&doc["wallets"], "abandon");
        assert_eq!(hex(&abandon["crypto_account_cbor_hex"]).len(), 116);
        let addresses = array(&doc["bip84"]["addresses"]);
        assert_eq!(export.first_address(), text(&addresses[0]["address"]));
        assert_eq!(
            export.first_address(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        let secp = Secp256k1::new();
        let seed = seed_of(text(&doc["bip84"]["mnemonic"]), None);
        let master = Xpriv::new_master(NetworkKind::Main, seed.expose_secret()).expect("a master");
        let mut account =
            derive_erasing(&secp, master, &account_path().expect("a path")).expect("an account");
        let keys = account_keys(&secp, &account).expect("keys");
        erase(&mut account);
        assert_eq!(keys.change, text(&addresses[2]["address"]));
        assert_eq!(keys.change, "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");
        assert_eq!(keys.change, text(&abandon["first_change_address"]));
    }

    // BIP39 passphrases: TREZOR b4e3f5ed and #l3mwu4e8; the bip32JP passphrase NFKD-normalized
    // gives 5d00908e and never the unnormalized 68896147; "TREZOR " is another wallet; the seed
    // equals bip39's own normalizing to_seed and the vectors.json TREZOR seed.
    #[test]
    fn bip39_passphrases() {
        let doc = watchonly();
        let mnemonic = text(&named(&doc["wallets"], "abandon")["mnemonic"]);
        let trezor = export_of(mnemonic, Some("TREZOR"));
        assert_eq!(fingerprint_hex(&trezor), "b4e3f5ed");
        assert!(trezor.receive_descriptor().ends_with("#l3mwu4e8"));
        assert!(trezor.passphrase_used());
        let spaced = export_of(mnemonic, Some("TREZOR "));
        assert_ne!(spaced.fingerprint(), trezor.fingerprint());
        assert_ne!(spaced.xpub(), trezor.xpub());
        let jp = named(&doc["wallets"], "abandon-bip32jp");
        let jp_export = export_of(mnemonic, jp["passphrase"].as_str());
        assert_eq!(fingerprint_hex(&jp_export), "5d00908e");
        assert_eq!(jp["unnormalized_fingerprint"], "68896147");
        assert_ne!(fingerprint_hex(&jp_export), "68896147");
        let plain = export_of(mnemonic, None);
        assert_ne!(plain.fingerprint(), trezor.fingerprint());
        assert!(!plain.passphrase_used());
        // The seed itself, two other ways.
        let parsed = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, mnemonic)
            .expect("parsed");
        let passphrase = text(&jp["passphrase"]);
        assert_eq!(
            seed_of(mnemonic, Some(passphrase)).expose_secret(),
            &parsed.to_seed(passphrase)
        );
        let english = read("bip39/vectors.json")["english"][0].clone();
        assert_eq!(english[1], mnemonic);
        assert_eq!(
            seed_of(mnemonic, Some("TREZOR")).expose_secret().to_vec(),
            hex(&english[2])
        );
    }

    // BCR-2020-015's shield seed: fingerprint 37b5eed4 and the example's wpkh xpub; and the whole
    // 7-output example, rebuilt by the same builders from watchonly.json's parts, gives its 773
    // bytes and its UR.
    #[test]
    fn bcr_2020_015_shield_and_the_full_example() {
        let doc = watchonly();
        let example = &doc["bcr_2020_015"];
        let shield = export_of(text(&example["mnemonic"]), None);
        assert_eq!(fingerprint_hex(&shield), "37b5eed4");
        let outputs = array(&example["outputs"]);
        assert_eq!(shield.xpub(), text(&outputs[2]["xpub"]));
        let keys: Vec<(Vec<u8>, Vec<u8>)> = outputs
            .iter()
            .map(|o| (hex(&o["key_hex"]), hex(&o["chain_code_hex"])))
            .collect();
        let items: Vec<Item<'_>> = outputs
            .iter()
            .zip(&keys)
            .map(|(o, (key, chain))| {
                let tags: Vec<u64> = array(&o["tags"])
                    .iter()
                    .map(|t| t.as_u64().expect("a tag"))
                    .collect();
                let components: Vec<(u32, bool)> = array(&o["components"])
                    .iter()
                    .map(|c| {
                        let index =
                            u32::try_from(c[0].as_u64().expect("an index")).expect("31 bits");
                        (index, c[1].as_bool().expect("hardened"))
                    })
                    .collect();
                let source =
                    u32::try_from(o["source_fingerprint"].as_u64().expect("fp")).expect("32 bits");
                let parent =
                    u32::try_from(o["parent_fingerprint"].as_u64().expect("fp")).expect("32 bits");
                tagged(&tags, hdkey_item(key, chain, &components, source, parent))
            })
            .collect();
        assert_eq!(items.len(), 7);
        let mfp =
            u32::try_from(example["master_fingerprint"].as_u64().expect("fp")).expect("32 bits");
        let cbor = cbor_encode(&account_item(mfp, items)).expect("an encoding");
        assert_eq!(cbor.len(), 773);
        assert_eq!(cbor, hex(&example["cbor_hex"]));
        assert_eq!(ur_single(ACCOUNT_UR_TYPE, &cbor), text(&example["ur"]));
    }

    // A zero fingerprint is left out of the key path and the hdkey, as the CDDL requires; the
    // account's own master fingerprint stays.
    #[test]
    fn zero_fingerprints_are_omitted() {
        let doc = watchonly();
        let zero = &doc["zero_fingerprints"];
        let (key, chain) = (hex(&zero["key_hex"]), hex(&zero["chain_code_hex"]));
        let output = tagged(
            &[TAG_OUTPUT, TAG_WPKH],
            hdkey_item(&key, &chain, &[(84, true), (0, true), (0, true)], 0, 0),
        );
        let cbor = cbor_encode(&account_item(0, vec![output])).expect("an encoding");
        assert_eq!(cbor, hex(&zero["cbor_hex"]));
        assert_eq!(&cbor[..3], &hex_str("a20100")[..]);
        assert_eq!(ur_single(ACCOUNT_UR_TYPE, &cbor), text(&zero["ur"]));
    }

    /// True for a descriptor that ends in '#' and its valid 8-character BIP-380 checksum.
    fn has_valid_checksum(text: &str) -> bool {
        match text.rsplit_once('#') {
            Some((body, sum)) => sum.len() == 8 && matches!(checksum(body), Ok(ref c) if c == sum),
            None => false,
        }
    }

    // BIP-380's checksum cases (watchonly.json "bip380"): "valid" means the string ends in a valid
    // checksum, as an export always does. miniscript's parser agrees on every string that carries a
    // checksum; it accepts the one without (a checksum is optional in BIP-380).
    #[test]
    fn bip380_checksum_cases() {
        let doc = watchonly();
        let cases = array(&doc["bip380"]);
        assert_eq!(cases.len(), 8);
        for c in cases {
            let descriptor = text(&c["descriptor"]);
            let valid = c["valid"].as_bool().expect("a flag");
            assert_eq!(
                has_valid_checksum(descriptor),
                valid,
                "{}",
                text(&c["name"])
            );
            if descriptor.contains('#') {
                let parsed = miniscript::descriptor::checksum::verify_checksum(descriptor);
                assert_eq!(parsed.is_ok(), valid, "{}", text(&c["name"]));
            }
        }
        assert_eq!(checksum("raw(deadbeef)"), Ok("89f8spxm".to_owned()));
        assert_eq!(checksum("raw(\u{dc})"), Err(CoreError::ExportSelfCheck));
    }

    // The runtime self-check refuses three tampered strings: a broken checksum, another fingerprint
    // with a correct checksum, and the right descriptor checked against another address.
    #[test]
    fn tampered_descriptors_fail_the_self_check() {
        let doc = watchonly();
        let abandon = named(&doc["wallets"], "abandon");
        let secp = Secp256k1::new();
        let xpub = Xpub::from_str(text(&abandon["account_xpub"])).expect("an xpub");
        let fingerprint =
            Fingerprint::from_str(text(&abandon["fingerprint"])).expect("a fingerprint");
        let built = build_descriptor(fingerprint, xpub, 0).expect("a descriptor");
        let receive = text(&abandon["receive_descriptor"]);
        let address = text(&abandon["first_receive_address"]);
        assert_eq!(self_check(&secp, receive, &built, address), Ok(()));
        let broken = format!(
            "{}{}",
            &receive[..receive.len() - 1],
            if receive.ends_with('s') { 'q' } else { 's' }
        );
        let body = receive[..receive.len() - 9].replace("73c5da0a", "73c5da0b");
        let refingered = format!("{body}#{}", checksum(&body).expect("a checksum"));
        let other_address = text(&abandon["first_change_address"]);
        for (text_in, address_in) in [
            (broken.as_str(), address),
            (refingered.as_str(), address),
            (receive, other_address),
        ] {
            assert_eq!(
                self_check(&secp, text_in, &built, address_in),
                Err(CoreError::ExportSelfCheck),
                "{text_in}"
            );
        }
    }

    // White box: every field of the export is wiped by zeroize.
    #[test]
    fn the_export_zeroizes_every_field() {
        let mut export = export_of(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Some("TREZOR"),
        );
        assert!(export.passphrase_used() && !export.xpub().is_empty());
        export.zeroize();
        assert_eq!(export.fingerprint(), [0; 4]);
        let fields = [
            export.xpub(),
            export.receive_descriptor(),
            export.change_descriptor(),
            export.ur(),
            export.qr_text(),
            export.first_address(),
        ];
        assert!(fields.iter().all(|f| f.is_empty()));
        assert!(!export.passphrase_used());
    }
}
