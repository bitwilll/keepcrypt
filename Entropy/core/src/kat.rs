//! Known-answer tests (docs/build-plan.md "kat" and test matrix row 1; docs/design.md "Test
//! continuously"; tasks/todo.md, M1 group 2).
//!
//! - `self_test` serves the Pi and phone boot screens (pi-firmware.md step 1, mobile-apps.md
//!   step 2); `Session::new` (and, from M1 group 9, `Wiped::restart`) runs the same suite.
//! - Each module adds its `KatId` group when it lands. The free functions that run KAT groups are
//!   thin wrappers over one crate-private body taking `Option<KatId>`; under `test-sources` each
//!   has a `*_with_kat_fault` twin that calls the same body, and `groups` is the one exhaustive
//!   match from entry point to groups.
//! - A faulted group flips one bit of a computed value before its comparison, so the comparison
//!   itself is what fails; nothing short-circuits it.
//! - Budget per full run: at most 3 PBKDF2-2048 (3 today: 2 BIP39 seeds, 1 BIP84; the Seal group
//!   starts from the S that the BIP84 group derives and checks, so it adds none), scrypt only at
//!   log2 N 10 (a later group), at most 2 Ed25519 verifies (2 today, in the Ed25519 group), one
//!   20-level Merkle path and never a full bucket root, and at most 1 s on a Pi Zero (an estimate;
//!   M4 measures). The Health group tests 2,064 samples.
//! - The known answers are copied from vectors/kat.json, vectors/bip39/vectors.json and the other
//!   vectors files each group names, and the unit tests below check every one of them against
//!   those files.

use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::{Hash, HashEngine, sha256, sha512};
use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{KeyInit, Mac};
use sha2::{Digest, Sha256, Sha512};

use crate::braille;
use crate::descriptor;
use crate::error::{CheckError, CoreError, HealthStage, HealthTest, KatId};
use crate::health::HealthTester;
use crate::pool::Pool;
use crate::seal::{self, CheckNonce, SealCode, SealPublic, SealTag};
use crate::secret::{SecretBytes32, SecretSeed64};
use crate::seed::{commitment, dice_only_entropy_into, mixed_entropy_into};
use crate::source::SourceId;

/// Where a known-answer suite runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Suite {
    /// Every group: `self_test`, `Session::new` and `Wiped::restart`.
    Full,
    /// `hwrng_boot_test`: the health tests.
    HwrngBoot,
    /// `seal_from_mnemonic`: the seal.
    Seal,
    /// `verify_snapshot`, `verify_bucket_proof` and `verify_bucket_proof_qr`: Ed25519, then the
    /// bucket tree.
    Registry,
}

/// The groups each entry point runs, in order: the one exhaustive match.
const fn groups(suite: Suite) -> &'static [KatId] {
    match suite {
        Suite::Full => &KatId::ALL,
        Suite::HwrngBoot => &[KatId::Health],
        Suite::Seal => &[KatId::Seal],
        Suite::Registry => &[KatId::Ed25519, KatId::Merkle],
    }
}

/// Runs `suite`, failing at the first group that does not pass. `fault` makes that one group
/// fail (tests only: the public functions pass `None`).
pub(crate) fn run(suite: Suite, fault: Option<KatId>) -> Result<(), CoreError> {
    for &id in groups(suite) {
        if !passes(id, fault == Some(id)) {
            return Err(CoreError::Kat(id));
        }
    }
    Ok(())
}

/// The boot-screen known-answer tests: every group. Any `Err` means no seed can be made.
pub fn self_test() -> Result<(), CoreError> {
    run(Suite::Full, None)
}

/// `self_test` with group `fault` made to fail, to prove the fail-closed path (tests only).
#[cfg(feature = "test-sources")]
pub fn self_test_with_kat_fault(fault: KatId) -> Result<(), CoreError> {
    run(Suite::Full, Some(fault))
}

/// One group's verdict. A new `KatId` must get its arm here.
fn passes(id: KatId, fault: bool) -> bool {
    match id {
        KatId::Sha256 => sha256_group(fault),
        KatId::Sha512 => sha512_group(fault),
        KatId::Hmac => hmac_group(fault),
        KatId::Bip39Wordlist => bip39_wordlist_group(fault),
        KatId::Bip39 => bip39_group(fault),
        KatId::Health => health_group(fault),
        KatId::Pool => pool_group(fault),
        KatId::Seed => seed_group(fault),
        KatId::Braille => braille_group(fault),
        KatId::Bip84 => bip84_group(fault),
        KatId::Seal => seal_group(fault),
        KatId::GoAhead => go_ahead_group(fault),
        KatId::Ed25519 => ed25519_group(fault),
        KatId::Merkle => merkle_group(fault),
    }
}

/// `computed == expected`, except that an injected fault flips the low bit of the first computed
/// byte first.
fn same(computed: &[u8], expected: &[u8], fault: bool) -> bool {
    computed.len() == expected.len()
        && computed
            .iter()
            .zip(expected)
            .enumerate()
            .all(|(i, (&c, &e))| {
                let flip = u8::from(fault && i == 0);
                (c ^ flip) == e
            })
}

/// `N` bytes from `2N` lowercase hex digits. Only ever evaluated in a const or static, so a
/// malformed literal fails the build instead of a check.
const fn unhex<const N: usize>(hex: &str) -> [u8; N] {
    let digits = hex.as_bytes();
    assert!(digits.len() == 2 * N, "wrong hex length");
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (nibble(digits[2 * i]) << 4) | nibble(digits[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        _ => panic!("not a lowercase hex digit"),
    }
}

// --- SHA-256 and SHA-512 (vectors/kat.json "sha256", "sha512": NIST FIPS 180-4 examples) ------

const SHA256_TWO_BLOCK: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
const SHA512_TWO_BLOCK: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

static SHA256_VECTORS: [(&[u8], [u8; 32]); 3] = [
    (
        b"",
        unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ),
    (
        b"abc",
        unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ),
    (
        SHA256_TWO_BLOCK,
        unhex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    ),
];

static SHA512_VECTORS: [(&[u8], [u8; 64]); 3] = [
    (
        b"",
        unhex(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ),
    ),
    (
        b"abc",
        unhex(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
    ),
    (
        SHA512_TWO_BLOCK,
        unhex(
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        ),
    ),
];

fn sha256_group(fault: bool) -> bool {
    let mut ok = true;
    for (i, (message, digest)) in SHA256_VECTORS.iter().enumerate() {
        ok &= same(Sha256::digest(message).as_slice(), digest, fault && i == 0);
    }
    ok
}

fn sha512_group(fault: bool) -> bool {
    let mut ok = true;
    for (i, (message, digest)) in SHA512_VECTORS.iter().enumerate() {
        ok &= same(Sha512::digest(message).as_slice(), digest, fault && i == 0);
    }
    ok
}

// --- HMAC (vectors/kat.json "hmac": RFC 4231 test case 2) -------------------------------------
// Both HMACs core runs: bitcoin_hashes' (inside BIP39's PBKDF2 and BIP32) and the hmac crate's
// HMAC-SHA256 (the seal code; later the age header MAC and HKDF).

const HMAC_KEY: &[u8] = b"Jefe";
const HMAC_DATA: &[u8] = b"what do ya want for nothing?";
const HMAC_SHA256: [u8; 32] =
    unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
const HMAC_SHA512: [u8; 64] = unhex(
    "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
);

fn hmac_group(fault: bool) -> bool {
    let mut engine256 = HmacEngine::<sha256::Hash>::new(HMAC_KEY);
    engine256.input(HMAC_DATA);
    let mac256 = Hmac::<sha256::Hash>::from_engine(engine256).to_byte_array();
    let mut engine512 = HmacEngine::<sha512::Hash>::new(HMAC_KEY);
    engine512.input(HMAC_DATA);
    let mac512 = Hmac::<sha512::Hash>::from_engine(engine512).to_byte_array();
    let crate_mac = match hmac::Hmac::<Sha256>::new_from_slice(HMAC_KEY) {
        Ok(mac) => mac.chain_update(HMAC_DATA).finalize(),
        Err(_) => return false,
    };
    same(&mac256, &HMAC_SHA256, fault)
        & same(&mac512, &HMAC_SHA512, false)
        & same(crate_mac.as_bytes().as_slice(), &HMAC_SHA256, false)
}

// --- BIP39 word list ----------------------------------------------------------------------------

/// SHA-256 of the official English list: the 2,048 words joined by LF, plus a final LF
/// (docs/seal-watchonly-braille.md "Sources").
const BIP39_WORDLIST_SHA256: [u8; 32] =
    unhex("2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda");

fn bip39_wordlist_group(fault: bool) -> bool {
    wordlist_passes(bip39::Language::English.word_list(), fault)
}

/// The list's digest against the pin; the unit tests feed it a damaged list. Braille takes its
/// words, and so its SeedBook numbers, from this list, so two swapped words fail this group.
fn wordlist_passes(words: &[&str], fault: bool) -> bool {
    let mut hasher = Sha256::new();
    for word in words {
        hasher.update(word.as_bytes());
        hasher.update(b"\n");
    }
    same(hasher.finalize().as_slice(), &BIP39_WORDLIST_SHA256, fault)
}

// --- BIP39 (vectors/bip39/vectors.json "english": entropy, mnemonic, seed with "TREZOR") -------

/// All 24 English entries: entropy and mnemonic.
static BIP39_PAIRS: [(&[u8], &str); 24] = [
    (
        &unhex::<16>("00000000000000000000000000000000"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    ),
    (
        &unhex::<16>("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"),
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    ),
    (
        &unhex::<16>("80808080808080808080808080808080"),
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    ),
    (
        &unhex::<16>("ffffffffffffffffffffffffffffffff"),
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    ),
    (
        &unhex::<24>("000000000000000000000000000000000000000000000000"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
    ),
    (
        &unhex::<24>("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"),
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
    ),
    (
        &unhex::<24>("808080808080808080808080808080808080808080808080"),
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
    ),
    (
        &unhex::<24>("ffffffffffffffffffffffffffffffffffffffffffffffff"),
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
    ),
    (
        &unhex::<32>("0000000000000000000000000000000000000000000000000000000000000000"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
    ),
    (
        &unhex::<32>("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"),
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
    ),
    (
        &unhex::<32>("8080808080808080808080808080808080808080808080808080808080808080"),
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
    ),
    (
        &unhex::<32>("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
    ),
    (
        &unhex::<16>("9e885d952ad362caeb4efe34a8e91bd2"),
        "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
    ),
    (
        &unhex::<24>("6610b25967cdcca9d59875f5cb50b0ea75433311869e930b"),
        "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
    ),
    (
        &unhex::<32>("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c"),
        "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
    ),
    (
        &unhex::<16>("c0ba5a8e914111210f2bd131f3d5e08d"),
        "scheme spot photo card baby mountain device kick cradle pact join borrow",
    ),
    (
        &unhex::<24>("6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3"),
        "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
    ),
    (
        &unhex::<32>("9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863"),
        "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
    ),
    (
        &unhex::<16>("23db8160a31d3e0dca3688ed941adbf3"),
        "cat swing flag economy stadium alone churn speed unique patch report train",
    ),
    (
        &unhex::<24>("8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0"),
        "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
    ),
    (
        &unhex::<32>("066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad"),
        "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
    ),
    (
        &unhex::<16>("f30f8c1da665478f49b001d94c5fc452"),
        "vessel ladder alter error federal sibling chat ability sun glass valve picture",
    ),
    (
        &unhex::<24>("c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05"),
        "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
    ),
    (
        &unhex::<32>("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f"),
        "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
    ),
];
/// The PBKDF2 seeds of entries 0 and 23 under the passphrase "TREZOR" (2 of the 3 PBKDF2-2048 the
/// budget allows).
static BIP39_SEEDS: [(usize, [u8; 64]); 2] = [
    (
        0,
        unhex::<64>(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        ),
    ),
    (
        23,
        unhex::<64>(
            "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
        ),
    ),
];
const BIP39_SEED_PASSPHRASE: &str = "TREZOR";

fn bip39_group(fault: bool) -> bool {
    let mut ok = true;
    for (i, (entropy, phrase)) in BIP39_PAIRS.iter().enumerate() {
        ok &= match bip39::Mnemonic::from_entropy_in(bip39::Language::English, entropy) {
            Ok(mnemonic) => {
                let words: Vec<&str> = mnemonic.words().collect();
                same(
                    words.join(" ").as_bytes(),
                    phrase.as_bytes(),
                    fault && i == 0,
                )
            }
            Err(_) => false,
        };
    }
    for (entry, seed) in &BIP39_SEEDS {
        ok &= match BIP39_PAIRS.get(*entry) {
            Some((entropy, _)) => {
                match bip39::Mnemonic::from_entropy_in(bip39::Language::English, entropy) {
                    Ok(mnemonic) => same(
                        &mnemonic.to_seed_normalized(BIP39_SEED_PASSPHRASE),
                        seed,
                        false,
                    ),
                    Err(_) => false,
                }
            }
            None => false,
        };
    }
    ok
}

// --- Health (vectors/keepcrypt.json "health": stuck, alternating, counting-1536) ---------------
// Fixed patterns, built here rather than stored, with their verdicts pinned below.

/// The three streams and their expected verdicts: stuck fails the Repetition Count at sample 5,
/// alternating fails the Adaptive Proportion test at sample 122 (both in the startup stage), and
/// counting passes and credits one window of 512 samples.
fn health_kat_cases() -> [(Vec<u8>, [u8; 10]); 3] {
    [
        (
            vec![0u8; 16],
            health_failure(HealthTest::RepetitionCount, HealthStage::Startup, 5),
        ),
        (
            [0u8, 1].into_iter().cycle().take(512).collect(),
            health_failure(HealthTest::AdaptiveProportion, HealthStage::Startup, 122),
        ),
        (
            (0..=u8::MAX).cycle().take(1_536).collect(),
            health_pass(512),
        ),
    ]
}

/// A failure verdict as bytes: test (1, 2), stage (1, 2), sample index (u64, big-endian).
fn health_failure(test: HealthTest, stage: HealthStage, sample: u64) -> [u8; 10] {
    let mut out = [0u8; 10];
    out[0] = match test {
        HealthTest::RepetitionCount => 1,
        HealthTest::AdaptiveProportion => 2,
    };
    out[1] = match stage {
        HealthStage::Startup => 1,
        HealthStage::Continuous => 2,
    };
    out[2..].copy_from_slice(&sample.to_be_bytes());
    out
}

/// A pass verdict as bytes: 0, 0, credited samples (u64, big-endian).
fn health_pass(credited_samples: u64) -> [u8; 10] {
    let mut out = [0u8; 10];
    out[2..].copy_from_slice(&credited_samples.to_be_bytes());
    out
}

/// `samples` through a fresh tester, as verdict bytes. Any other error matches no verdict.
fn health_verdict(samples: &[u8]) -> [u8; 10] {
    let mut tester = HealthTester::new();
    match tester.test(samples) {
        Ok(_) => health_pass(tester.credited_samples().get()),
        Err(CoreError::Health(f)) => health_failure(f.test, f.stage, f.sample),
        Err(_) => [0xff; 10],
    }
}

fn health_group(fault: bool) -> bool {
    let mut ok = true;
    for (i, (samples, expected)) in health_kat_cases().iter().enumerate() {
        ok &= same(&health_verdict(samples), expected, fault && i == 0);
    }
    ok
}

// --- Pool (vectors/keepcrypt.json "pool": one-os-record) ----------------------------------------

/// The OS record: counter_stream(b"KCE/test/pool/os", 64).
const POOL_OS_RECORD: [u8; 64] = unhex(
    "26ff8bd3a763d74e18922597b155a2e9c0a901d942d2a86ccf64990cb9b359ac20b32a8286b48300fc58f95fbed3005fd0d0f6299271e7c47758d5a85b8ddd0e",
);
/// D for the tag and that one record.
const POOL_D: [u8; 32] = unhex("2b74d8f916fca0ed465c6c7326a0fdfa1e34880f52199007b49c123a9154ed77");

fn pool_group(fault: bool) -> bool {
    let mut pool = Pool::new();
    match pool.absorb(SourceId::Os, &POOL_OS_RECORD) {
        Ok(()) => {
            let mut d = SecretBytes32::zeroed();
            pool.finish_into(&mut d);
            same(d.expose_secret(), &POOL_D, fault)
        }
        Err(_) => false,
    }
}

// --- Seed (vectors/keepcrypt.json: commitment "d-00-1f", mixed "d-00-1f-coldcard-50",
// dice_only "coldcard-123456") --------------------------------------------------------------------

/// D = 00 01 02 ... 1f.
const SEED_D: [u8; 32] = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
/// C for that D.
const SEED_C: [u8; 32] = unhex("21778a7463cef10741413d0b80909a1045ba902d6244f519d2520e247cbe2e8c");
/// R: the 50-roll string of vectors/coldcard/rolls.json.
const SEED_ROLLS: &[u8] = b"12345612345612345612345612345612345612345612345612";
/// Mixed E for that D and R.
const SEED_MIXED_E: [u8; 32] =
    unhex("b2e18e2cdeb6f07e9dd5d3df8e315fa609fd2ebfe543387a483828553da6eee2");
/// Coldcard's published dice-only example.
const SEED_DICE_ROLLS: &[u8] = b"123456";
/// E = SHA256("123456").
const SEED_DICE_E: [u8; 32] =
    unhex("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92");

fn seed_group(fault: bool) -> bool {
    let mut d = SecretBytes32::zeroed();
    d.expose_secret_mut().copy_from_slice(&SEED_D);
    let mut dice_only = SecretBytes32::zeroed();
    dice_only_entropy_into(SEED_DICE_ROLLS, &mut dice_only);
    let mut mixed = SecretBytes32::zeroed();
    match mixed_entropy_into(&d, SEED_ROLLS, &mut mixed) {
        Ok(()) => {
            same(&commitment(&d), &SEED_C, fault)
                & same(mixed.expose_secret(), &SEED_MIXED_E, false)
                & same(dice_only.expose_secret(), &SEED_DICE_E, false)
        }
        Err(_) => false,
    }
}

// --- Braille (vectors/braille.json "cells"."table_sha256" and "text" "2026") ---------------------

/// SHA-256 of the canonical cell table, the letters a-z and the signs with their glyphs and dots
/// (braille::table_text).
const BRAILLE_TABLE_SHA256: [u8; 32] =
    unhex("fd75c236d2ab92e0fe682d502a5b4bf2537f78d5ec5630b2bac20a963ece9c9d");
/// "2026" in cells, as printed in docs/seal-watchonly-braille.md "Cell alphabet": the number sign
/// once, then b j b f.
const BRAILLE_2026: &str = "⠼⠃⠚⠃⠋";

fn braille_group(fault: bool) -> bool {
    braille_table_passes(&braille::table_text(), fault) & braille_text_passes()
}

/// The table's digest against the pin; the unit tests feed it damaged tables.
fn braille_table_passes(table_text: &str, fault: bool) -> bool {
    same(
        Sha256::digest(table_text.as_bytes()).as_slice(),
        &BRAILLE_TABLE_SHA256,
        fault,
    )
}

fn braille_text_passes() -> bool {
    match braille::render_text("2026") {
        Ok(cells) => same(cells.as_bytes(), BRAILLE_2026.as_bytes(), false),
        Err(_) => false,
    }
}

// --- BIP84 (vectors/watchonly.json "wallets" "abandon"; BIP-84 "Test vectors") -----------------
// The whole watch-only export of the BIP-84 test mnemonic: PBKDF2, BIP32 down to the account and the
// first address (this catches a miscompiled secp256k1-sys on a target), the BIP-380 checksum and the
// crypto-account UR. Its PBKDF2 is the third and last of the budget.

/// abandon x 11 + about: entropy of 16 zero bytes.
const BIP84_ENTROPY: [u8; 16] = [0; 16];
/// Its S, the BIP39 seed with the empty passphrase (vectors/kcr.json "seeds" "vector-1"; its first 16
/// bytes are seal.json's and BIP39's published prefix). The BIP84 group checks its PBKDF2 against
/// it, and the Seal group starts from it.
const ABANDON_SEED: [u8; 64] = unhex(
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
);
const BIP84_FINGERPRINT: [u8; 4] = unhex("73c5da0a");
const BIP84_XPUB: &str = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V";
const BIP84_FIRST_ADDRESS: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
const BIP84_RECEIVE_CHECKSUM: &str = "afwvtk2s";
const BIP84_UR: &str = concat!(
    "ur:crypto-account/oeadcyjksktnbkaolytaadeetaadmwtaaddloxaxhdclaojoknidzcpssajtpt",
    "rpfrcecfkkamykjtvtcsbtbdtkcfiyvyoetneeykwfnbnyndaahdcxgegunbpyclrhuomdlnnsglmooy",
    "hscfglaxrtwsfhykadgeswmowkeosskoghmhztamtaaddyoeadlncsghykaeykaeykaocyjksktnbkay",
    "cykbwfdnuywftiglsn",
);

fn bip84_group(fault: bool) -> bool {
    let words = match bip39::Mnemonic::from_entropy_in(bip39::Language::English, &BIP84_ENTROPY) {
        Ok(words) => words,
        Err(_) => return false,
    };
    let mut seed = SecretSeed64::zeroed();
    seed.expose_secret_mut()
        .copy_from_slice(zeroize::Zeroizing::new(words.to_seed_normalized("")).as_slice());
    match descriptor::watch_only_export(&seed, false) {
        Ok(export) => {
            same(seed.expose_secret(), &ABANDON_SEED, false)
                & same(&export.fingerprint(), &BIP84_FINGERPRINT, fault)
                & same(export.xpub().as_bytes(), BIP84_XPUB.as_bytes(), false)
                & same(
                    export.first_address().as_bytes(),
                    BIP84_FIRST_ADDRESS.as_bytes(),
                    false,
                )
                & export
                    .receive_descriptor()
                    .ends_with(&["#", BIP84_RECEIVE_CHECKSUM].concat())
                & same(export.ur().as_bytes(), BIP84_UR.as_bytes(), false)
        }
        Err(_) => false,
    }
}

// --- Seal (vectors/seal.json vector 1; CLAUDE.md "Seal test vector") ---------------------------
// From the abandon S (ABANDON_SEED, which the BIP84 group checks against PBKDF2): the hmac crate's
// HMAC-SHA256, Crockford base32, the tag hash and the Seal ID.

const SEAL_CODE: &[u8; 26] = b"JXP3RDXYACJZ1NAX3RGQDJCJJN";
const SEAL_TAG: [u8; 32] =
    unhex("2b8103c8dd64611df5c8c28b8fbf864a1005372f5da06a5777f92708ce79cb5c");
const SEAL_ID: &str = "5E0G7J6X";

fn seal_group(fault: bool) -> bool {
    let mut seed = SecretSeed64::zeroed();
    seed.expose_secret_mut().copy_from_slice(&ABANDON_SEED);
    let mut code = SealCode::zeroed();
    code.fill_from_seed(&seed);
    match SealPublic::from_code(&code) {
        Ok(public) => {
            same(code.as_ascii(), SEAL_CODE, fault)
                & same(public.tag().as_bytes(), &SEAL_TAG, false)
                & same(public.seal_id().as_bytes(), SEAL_ID.as_bytes(), false)
        }
        Err(_) => false,
    }
}

// --- GoAhead (vectors/seal.json vector 1 "go_ahead"; CLAUDE.md "Go-ahead vector") ---------------

const GO_AHEAD_NONCE: [u8; 8] = unhex("0001020304050607");
const GO_AHEAD_CODE: &[u8; 8] = b"CF94BCAJ";
/// As typed, with the display dash.
const GO_AHEAD_TYPED: &str = "CF94-BCAJ";

fn go_ahead_group(fault: bool) -> bool {
    let tag = SealTag::from_bytes(SEAL_TAG);
    let nonce = CheckNonce::from_bytes(GO_AHEAD_NONCE);
    let mut wrong = GO_AHEAD_NONCE;
    wrong[7] ^= 1;
    same(&seal::go_ahead_code(&tag, &nonce), GO_AHEAD_CODE, fault)
        & (seal::verify_go_ahead(&tag, &nonce, GO_AHEAD_TYPED) == Ok(()))
        & (seal::verify_go_ahead(&tag, &CheckNonce::from_bytes(wrong), GO_AHEAD_TYPED)
            == Err(CheckError::WrongCode))
}

// --- Ed25519 (vectors/kat.json "ed25519": RFC 8032 section 7.1, TEST 1) -------------------------
// ed25519-dalek's verify_strict, the one check behind snapshots and proofs: two verifies, the
// budget's limit.

const ED25519_PUBLIC_KEY: [u8; 32] =
    unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
const ED25519_MESSAGE: &[u8] = b"";
const ED25519_SIGNATURE: [u8; 64] = unhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
);

fn ed25519_group(fault: bool) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(&ED25519_PUBLIC_KEY) else {
        return false;
    };
    let mut signature = ED25519_SIGNATURE;
    signature[0] ^= u8::from(fault);
    let accepted = key
        .verify_strict(ED25519_MESSAGE, &Signature::from_bytes(&signature))
        .is_ok();
    let mut flipped = ED25519_SIGNATURE;
    flipped[0] ^= 1;
    let refused = key
        .verify_strict(ED25519_MESSAGE, &Signature::from_bytes(&flipped))
        .is_err();
    accepted & refused
}

// --- Merkle (vectors/kcr.json "merkle": an empty leaf, the node, the vector-1 path) --------------
// A leaf, a node and one 20-level path, never a full root (2^20 leaves are the snapshot's job).

/// Seal vector 1's bucket, 0x2b810, and its empty leaf.
const MERKLE_BUCKET: u32 = 0x2b810;
const MERKLE_EMPTY_LEAF: [u8; 32] =
    unhex("9dbd45522ff2ad044ccaebaaf41ee955bc777df4e40b8d20cab11dea2898c393");
/// The node over the empty leaves of buckets 0 and 1.
const MERKLE_LEFT: [u8; 32] =
    unhex("dcaa835d1afed220c8fc58159c18cb98a3d723934bc58db3da26178c9999a667");
const MERKLE_RIGHT: [u8; 32] =
    unhex("d39fed3a350234a3fa2890a85f2659551f0fa132aed381ee2bc175380ed14e4f");
const MERKLE_NODE: [u8; 32] =
    unhex("c61b7e553b1962865ef3b510df90b11186d5cdf2349fbc3b4952ac544ccdd81b");
/// The vector-1 path: bucket 0x2b810 of kcr.json's "small" snapshot (its two entries), the 20
/// siblings leaf level first, and that snapshot's root.
const MERKLE_ENTRIES: [u8; 36] =
    unhex("2b8103c8dd64611df5c8c28b8fbf864bffff2b81090b7fd157945acf1ff22896eb670002");
const MERKLE_SIBLINGS: [u8; 640] = unhex(concat!(
    "a2b46473906b654a4073077ad45148c6e1b6dd01b3a9014a2a510960e026ef08f6e5c6671c43f12259d0aac53b89332d",
    "c32eba25a3a5471b7326abd9ed21687a5e84ec8b2bbb47f721a3ee363b760e789fe4cc6a03c946f76d547233f639f5e7",
    "dac7c64936487225df3c7b8d954f8b68575b55c297739751264a0aa64bdc245fa52a24d19079b4b5307d1238c72adccc",
    "0023bc03ac1d4fbff9b36ec8c7a2c39b08be87d16dbda790cb9ddf0c19e8021298b82347b0be14ed3a2db9f2348f87dc",
    "3f1e8d58f7f70e448a4b39ab59b2f1e26bb6b73e2f96c62203923cd0843f301a9121473b562b5a4c8f9396b06a6d18d1",
    "0a2f68c38747e5b22fef94370c970ed3940d280e774ec23bbedc394b4cead3ec335b794c0fb273f0d396cb0c87729c9e",
    "802ea7cab84cc3d24dda9f2cba9698ab4ce0b137c521dee80f7fec2d4afa3cd8ac698bfefb5515200600761ab664d00e",
    "87a0f90ee4c5492d37edf81e84a34b484d11c5b07ac9beda30a8b365d8f3b09f1de5e80bd250e1b5b473516f7fc98fd6",
    "a7d1ee55c1b9ee291159653f939d0779f29e6d83b5feda06b9e15c04f02d9a4b860f1795bbf15cb9f06fea0c3f38ba75",
    "8edd2d60da0c5dc34bd04e04e35cb677e9244d44f8c78a26fd89440647a30681c07f4a36125d888a76dd1bf6c170c05f",
    "8405343dcba08ec8fc4dc794c8331da80734c0fab6cacdce1d638a151afe2abd250e03944ee738e7f740123aff3c80a4",
    "dc258a2303d65c7e19cb32b9f02a7aabdba7cc2aba3bd8db656c173806a93f211068edb4e4b0438cf0688df40d3e3d61",
    "cd2b6333b0c154207d96d721016ba69c5f4df5f6deabe6b9e39e4f69dbafbb0b1a64e42c4c80f82084acc9c42622e99c",
    "1919f43168e926f549708a265806ffaf",
));
const MERKLE_ROOT: [u8; 32] =
    unhex("d0d2028a28b277c2e105a1a3275c92bae1762aa43117762cf164700a7802e0ed");

fn merkle_group(fault: bool) -> bool {
    let (rows, _) = MERKLE_SIBLINGS.as_chunks::<32>();
    let Ok(siblings) = <&[[u8; 32]; 20]>::try_from(rows) else {
        return false;
    };
    same(
        &seal::merkle_leaf(MERKLE_BUCKET, &[]),
        &MERKLE_EMPTY_LEAF,
        fault,
    ) & same(
        &seal::merkle_node(&MERKLE_LEFT, &MERKLE_RIGHT),
        &MERKLE_NODE,
        false,
    ) & same(
        &seal::merkle_root_of_path(MERKLE_BUCKET, &MERKLE_ENTRIES, siblings),
        &MERKLE_ROOT,
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::{hex_str as bytes, read as vectors};
    use serde_json::Value;

    fn text<'a>(v: &'a Value, key: &str) -> &'a str {
        v[key].as_str().expect("a string field")
    }

    #[test]
    fn sha_constants_match_kat_json() {
        let kat = vectors("kat.json");
        let sha256 = kat["sha256"].as_array().expect("sha256 list");
        assert_eq!(sha256.len(), SHA256_VECTORS.len());
        for (entry, (message, digest)) in sha256.iter().zip(&SHA256_VECTORS) {
            assert_eq!(bytes(text(entry, "message_hex")), *message);
            assert_eq!(bytes(text(entry, "digest_hex")), digest);
        }
        let sha512 = kat["sha512"].as_array().expect("sha512 list");
        assert_eq!(sha512.len(), SHA512_VECTORS.len());
        for (entry, (message, digest)) in sha512.iter().zip(&SHA512_VECTORS) {
            assert_eq!(bytes(text(entry, "message_hex")), *message);
            assert_eq!(bytes(text(entry, "digest_hex")), digest);
        }
    }

    #[test]
    fn hmac_constants_match_kat_json() {
        let kat = vectors("kat.json");
        let hmac = kat["hmac"].as_array().expect("hmac list");
        assert_eq!(hmac.len(), 1);
        assert_eq!(bytes(text(&hmac[0], "key_hex")), HMAC_KEY);
        assert_eq!(bytes(text(&hmac[0], "data_hex")), HMAC_DATA);
        assert_eq!(bytes(text(&hmac[0], "hmac_sha256_hex")), HMAC_SHA256);
        assert_eq!(bytes(text(&hmac[0], "hmac_sha512_hex")), HMAC_SHA512);
    }

    #[test]
    fn bip39_constants_match_vectors_json() {
        let english = vectors("bip39/vectors.json")["english"]
            .as_array()
            .expect("english list")
            .clone();
        assert_eq!(english.len(), BIP39_PAIRS.len());
        for (entry, (entropy, phrase)) in english.iter().zip(&BIP39_PAIRS) {
            assert_eq!(bytes(entry[0].as_str().expect("entropy")), *entropy);
            assert_eq!(entry[1].as_str().expect("mnemonic"), *phrase);
        }
        for (index, seed) in &BIP39_SEEDS {
            assert_eq!(bytes(english[*index][2].as_str().expect("seed")), seed);
        }
        assert!(
            BIP39_SEEDS.len() <= 3,
            "the KAT budget allows at most 3 PBKDF2-2048 per run"
        );
    }

    #[test]
    fn wordlist_constant_is_the_published_hash() {
        let published = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";
        assert_eq!(bytes(published), BIP39_WORDLIST_SHA256);
    }

    // Two swapped words, which would give braille's inserts the wrong SeedBook numbers, fail the
    // Bip39Wordlist group (tasks/todo.md, M1 group 5, the Braille KAT's proof; review fix after
    // commit 15). ACT and ACTION are SeedBook 0020 and 0021.
    #[test]
    fn two_swapped_words_fail_the_wordlist_group() {
        let list = bip39::Language::English.word_list();
        assert!(wordlist_passes(list, false));
        let mut swapped = *list;
        assert_eq!((swapped[19], swapped[20]), ("act", "action"));
        swapped.swap(19, 20);
        assert!(!wordlist_passes(&swapped, false));
    }

    #[test]
    fn every_group_passes_and_fails_under_its_fault() {
        for id in KatId::ALL {
            assert!(passes(id, false), "{id:?} must pass");
            assert!(
                !passes(id, true),
                "{id:?} must fail under an injected fault"
            );
        }
    }

    #[test]
    fn a_faulted_group_fails_the_suite_with_its_own_id() {
        assert_eq!(run(Suite::Full, None), Ok(()));
        assert_eq!(self_test(), Ok(()));
        for id in KatId::ALL {
            assert_eq!(run(Suite::Full, Some(id)), Err(CoreError::Kat(id)));
        }
        assert_eq!(groups(Suite::Full), &KatId::ALL);
        for (suite, only) in [
            (Suite::HwrngBoot, &[KatId::Health][..]),
            (Suite::Seal, &[KatId::Seal][..]),
            (Suite::Registry, &[KatId::Ed25519, KatId::Merkle][..]),
        ] {
            assert_eq!(groups(suite), only);
            assert_eq!(run(suite, None), Ok(()));
            for id in KatId::ALL {
                let want = if only.contains(&id) {
                    Err(CoreError::Kat(id))
                } else {
                    Ok(())
                };
                assert_eq!(run(suite, Some(id)), want, "{suite:?} {id:?}");
            }
        }
    }

    #[test]
    fn pool_constants_match_keepcrypt_json() {
        let doc = crate::test_vectors::keepcrypt_json();
        let case = crate::test_vectors::named(&doc["pool"], "one-os-record");
        assert_eq!(case["records"].as_array().map(Vec::len), Some(1));
        assert_eq!(case["records"][0]["id"], 1);
        assert_eq!(
            crate::test_vectors::hex(&case["records"][0]["data_hex"]),
            POOL_OS_RECORD
        );
        assert_eq!(crate::test_vectors::hex(&case["d_hex"]), POOL_D);
    }

    #[test]
    fn seed_constants_match_keepcrypt_json() {
        use crate::test_vectors::{hex, keepcrypt_json, named, text};
        let doc = keepcrypt_json();
        let c = named(&doc["commitment"], "d-00-1f");
        assert_eq!(
            (hex(&c["d_hex"]), hex(&c["c_hex"])),
            (SEED_D.to_vec(), SEED_C.to_vec())
        );
        let mixed = named(&doc["mixed"], "d-00-1f-coldcard-50");
        assert_eq!(hex(&mixed["d_hex"]), SEED_D);
        assert_eq!(text(&mixed["rolls"]).as_bytes(), SEED_ROLLS);
        assert_eq!(hex(&mixed["e_hex"]), SEED_MIXED_E);
        let dice = named(&doc["dice_only"], "coldcard-123456");
        assert_eq!(text(&dice["rolls"]).as_bytes(), SEED_DICE_ROLLS);
        assert_eq!(hex(&dice["e_hex"]), SEED_DICE_E);
    }

    #[test]
    fn health_cases_match_keepcrypt_json() {
        let doc = crate::test_vectors::keepcrypt_json();
        let names = ["stuck", "alternating", "counting-1536"];
        for (name, (samples, expected)) in names.iter().zip(health_kat_cases()) {
            let case = crate::test_vectors::named(&doc["health"], name);
            assert_eq!(
                crate::test_vectors::hex(&case["samples_hex"]),
                samples,
                "{name}"
            );
            let expect = &case["expect"];
            let from_json = if expect["result"] == "pass" {
                health_pass(expect["credited_samples"].as_u64().expect("credited"))
            } else {
                let test = if expect["test"] == "repetition_count" {
                    HealthTest::RepetitionCount
                } else {
                    HealthTest::AdaptiveProportion
                };
                let stage = if expect["stage"] == "startup" {
                    HealthStage::Startup
                } else {
                    HealthStage::Continuous
                };
                health_failure(test, stage, expect["sample"].as_u64().expect("sample"))
            };
            assert_eq!(from_json, expected, "{name}");
        }
    }

    #[test]
    fn braille_constants_match_braille_json() {
        let doc = vectors("braille.json");
        assert_eq!(
            bytes(doc["cells"]["table_sha256"].as_str().expect("digest")),
            BRAILLE_TABLE_SHA256
        );
        let text = crate::test_vectors::named_by(&doc["text"], "text", "2026");
        assert_eq!(text["cells"].as_str(), Some(BRAILLE_2026));
    }

    // One flipped dot, or two letters' cells swapped, changes the table's digest, so the group
    // fails (tasks/todo.md, M1 group 5). The table holds cells, not words: two swapped words fail
    // the Bip39Wordlist group (two_swapped_words_fail_the_wordlist_group).
    #[test]
    fn a_damaged_braille_table_fails_the_group() {
        assert!(braille_table_passes(&braille::table_text(), false));
        let mut flipped = braille::LETTERS;
        flipped[4].1 ^= 0x20;
        assert!(!braille_table_passes(
            &braille::table_text_from(&flipped),
            false
        ));
        let mut swapped = braille::LETTERS;
        swapped.swap(4, 8);
        assert!(!braille_table_passes(
            &braille::table_text_from(&swapped),
            false
        ));
    }

    #[test]
    fn bip84_constants_match_watchonly_json() {
        let doc = vectors("watchonly.json");
        let abandon = crate::test_vectors::named(&doc["wallets"], "abandon");
        assert_eq!(
            abandon["mnemonic"],
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        assert_eq!(
            bytes(abandon["fingerprint"].as_str().expect("fp")),
            BIP84_FINGERPRINT
        );
        assert_eq!(abandon["account_xpub"], BIP84_XPUB);
        assert_eq!(abandon["first_receive_address"], BIP84_FIRST_ADDRESS);
        let receive = abandon["receive_descriptor"].as_str().expect("descriptor");
        assert!(receive.ends_with(&format!("#{BIP84_RECEIVE_CHECKSUM}")));
        assert_eq!(abandon["crypto_account_ur"], BIP84_UR);
        // BIP-84's own published address for m/84'/0'/0'/0/0.
        assert_eq!(
            BIP84_FIRST_ADDRESS,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
    }

    #[test]
    fn seal_and_go_ahead_constants_match_seal_json_and_kcr_json() {
        let seal = vectors("seal.json");
        let v1 = &seal["vectors"][0];
        assert_eq!(
            v1["seal_code_hashed"].as_str().map(str::as_bytes),
            Some(&SEAL_CODE[..])
        );
        assert_eq!(bytes(v1["seal_tag_hex"].as_str().expect("T")), SEAL_TAG);
        assert_eq!(v1["seal_id"], SEAL_ID);
        assert_eq!(
            bytes(v1["go_ahead"]["nonce_hex"].as_str().expect("n")),
            GO_AHEAD_NONCE
        );
        assert_eq!(
            v1["go_ahead"]["code_compact"].as_str().map(str::as_bytes),
            Some(&GO_AHEAD_CODE[..])
        );
        assert_eq!(v1["go_ahead"]["code"], GO_AHEAD_TYPED);
        assert_eq!(
            bytes(v1["seed_prefix_hex"].as_str().expect("S prefix")),
            ABANDON_SEED[..16]
        );
        let kcr = vectors("kcr.json");
        let seed = crate::test_vectors::named(&kcr["seeds"], "vector-1");
        assert_eq!(bytes(seed["seed_hex"].as_str().expect("S")), ABANDON_SEED);
        assert_eq!(seed["mnemonic"], v1["mnemonic"]);
        // The BIP84 group's PBKDF2 of the same words gives this S.
        let words = bip39::Mnemonic::from_entropy_in(bip39::Language::English, &BIP84_ENTROPY)
            .expect("16 bytes");
        assert_eq!(words.to_seed_normalized(""), ABANDON_SEED);
    }

    #[test]
    fn ed25519_constants_match_kat_json() {
        let kat = vectors("kat.json");
        let ed = kat["ed25519"].as_array().expect("ed25519 list");
        assert_eq!(ed.len(), 1);
        assert_eq!(bytes(text(&ed[0], "public_key_hex")), ED25519_PUBLIC_KEY);
        assert_eq!(bytes(text(&ed[0], "message_hex")), ED25519_MESSAGE);
        assert_eq!(bytes(text(&ed[0], "signature_hex")), ED25519_SIGNATURE);
        let kcr = vectors("kcr.json");
        let rfc = crate::test_vectors::named(&kcr["rfc8032"], "rfc8032-test-1");
        assert_eq!(bytes(text(rfc, "signature_hex")), ED25519_SIGNATURE);
    }

    #[test]
    fn merkle_constants_match_kcr_json() {
        let kcr = vectors("kcr.json");
        let merkle = &kcr["merkle"];
        let leaf = crate::test_vectors::named_by_u64(
            &merkle["empty_leaves"],
            "bucket",
            u64::from(MERKLE_BUCKET),
        );
        assert_eq!(bytes(text(leaf, "leaf_hex")), MERKLE_EMPTY_LEAF);
        assert_eq!(bytes(text(&merkle["node"], "left_hex")), MERKLE_LEFT);
        assert_eq!(bytes(text(&merkle["node"], "right_hex")), MERKLE_RIGHT);
        assert_eq!(bytes(text(&merkle["node"], "node_hex")), MERKLE_NODE);
        let path = &merkle["vector_1_path"];
        assert_eq!(path["bucket"], MERKLE_BUCKET);
        assert_eq!(bytes(text(path, "entries_hex")), MERKLE_ENTRIES);
        let siblings: String = path["siblings_hex"]
            .as_array()
            .expect("siblings")
            .iter()
            .map(|s| s.as_str().expect("hex"))
            .collect();
        assert_eq!(bytes(&siblings), MERKLE_SIBLINGS);
        assert_eq!(bytes(text(path, "root_hex")), MERKLE_ROOT);
        let seal = vectors("seal.json");
        assert_eq!(seal["vectors"][0]["lookup_prefix"], "2b810");
    }

    #[test]
    fn comparison_and_hex_helpers() {
        assert!(same(b"ab", b"ab", false));
        assert!(!same(b"ab", b"ab", true));
        assert!(!same(b"ab", b"abc", false));
        assert!(
            same(b"`b", b"ab", true),
            "a fault flips the low bit of the first byte only"
        );
        assert_eq!(unhex::<3>("0a9fff"), [0x0a, 0x9f, 0xff]);
    }
}
