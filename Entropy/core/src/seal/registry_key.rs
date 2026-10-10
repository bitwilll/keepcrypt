//! The registry key a build pins (CLAUDE.md rule 10; docs/seal-watchonly-braille.md "Registry
//! service spec"; tasks/todo.md, M1 Q3 and group 7).
//!
//! - Release builds pin no key until M9, so every snapshot and proof fails closed with
//!   `NoRegistryKey` and only the typed go-ahead code works.
//! - Under the `test-registry` feature (which `test-sources` turns on, never the reverse), the key
//!   is the public half of the Ed25519 key whose 32-byte seed is SHA-256("KCE/test/registry-key/v1"),
//!   the key tools/verify/verify.py signs vectors/kcr.json with. The key bytes and the marker
//!   `KC_TEST_REGISTRY_DO_NOT_SHIP` exist only under that feature. Both are `#[used]` statics that
//!   pass through `core::hint::black_box` on the key-selection path, and the key is read back
//!   through it, so any linked artifact that can select the key holds the marker and the key's 32
//!   bytes in one piece (a constant could be split into immediates or constant-pool chunks), and
//!   the release scan (`scripts/banned-api-check.sh --artifact`) fails that artifact.
//! - The choice between no key and the test key is the pure function `choose`, unit-tested both
//!   ways. One key per release; rotation statements wait for M9.
//! - `registry_key_is_test` answers from the feature, not from whether a key is pinned: once M9
//!   pins the production key in release builds, they must still say false (review fix after
//!   commit 18).

use ed25519_dalek::VerifyingKey;

use crate::error::CoreError;

/// The test-registry marker. `#[used]` keeps it in every object that links this module.
#[cfg(feature = "test-registry")]
#[used]
static MARKER: [u8; 28] = *b"KC_TEST_REGISTRY_DO_NOT_SHIP";

/// The test registry public key: the public half of seed SHA-256("KCE/test/registry-key/v1")
/// (vectors/kcr.json "keys" "test_registry"; computed apart from verify.py and by OpenSSL too). A
/// `#[used]` static, so a linked artifact holds its 32 bytes in one piece for the release scan.
#[cfg(feature = "test-registry")]
#[used]
static TEST_REGISTRY_KEY: [u8; 32] = [
    0x42, 0xe9, 0xfa, 0x0e, 0x20, 0x6d, 0x4b, 0xdf, 0x41, 0x0f, 0x98, 0x7a, 0xc7, 0xde, 0xd5, 0x4f,
    0xb0, 0x2f, 0xb4, 0x9e, 0xf2, 0x77, 0xcc, 0x42, 0x5d, 0x5f, 0xdf, 0xdb, 0x72, 0xc3, 0xb9, 0x4b,
];

/// The key bytes this build pins: the test key under `test-registry`, none otherwise. The bytes
/// are read from the static through `black_box`, so the compiler cannot fold them into code and
/// drop the static.
#[cfg(feature = "test-registry")]
fn pinned_bytes() -> Option<[u8; 32]> {
    core::hint::black_box(&MARKER);
    Some(*core::hint::black_box(&TEST_REGISTRY_KEY))
}

/// The key bytes this build pins: none until M9.
#[cfg(not(feature = "test-registry"))]
fn pinned_bytes() -> Option<[u8; 32]> {
    None
}

/// No key is `NoRegistryKey`; so is a key that does not decode or is weak (small order), so a
/// wrong pin fails closed too.
pub(crate) fn choose(pinned: Option<[u8; 32]>) -> Result<VerifyingKey, CoreError> {
    let Some(bytes) = pinned else {
        return Err(CoreError::NoRegistryKey);
    };
    match VerifyingKey::from_bytes(&bytes) {
        Ok(key) if !key.is_weak() => Ok(key),
        _ => Err(CoreError::NoRegistryKey),
    }
}

/// The key snapshots and proofs are verified against.
pub(crate) fn pinned_key() -> Result<VerifyingKey, CoreError> {
    choose(pinned_bytes())
}

/// True when this build trusts the local test registry (`test-registry`), so a shell can show a
/// test banner. Release builds return false, now and after M9 pins the production key: the answer
/// is the feature, never the presence of a pinned key.
pub fn registry_key_is_test() -> bool {
    cfg!(feature = "test-registry")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::{hex, read};

    fn key_bytes(name: &str) -> [u8; 32] {
        hex(&read("kcr.json")["keys"][name]["public_key_hex"])
            .try_into()
            .expect("32 bytes")
    }

    // Both ways: no key is NoRegistryKey; the test key and the other test key decode and are not
    // weak; a small-order key and bytes that decode to no point are refused.
    #[test]
    fn choose_both_ways() {
        assert!(matches!(choose(None), Err(CoreError::NoRegistryKey)));
        for name in ["test_registry", "other"] {
            match choose(Some(key_bytes(name))) {
                Ok(key) => assert_eq!(key.as_bytes(), &key_bytes(name)),
                Err(e) => panic!("{name}: {e}"),
            }
        }
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(matches!(
            choose(Some(identity)),
            Err(CoreError::NoRegistryKey)
        ));
        // y = 2 is not on the curve: x^2 has no square root.
        let mut off_curve = [0u8; 32];
        off_curve[0] = 2;
        assert!(VerifyingKey::from_bytes(&off_curve).is_err());
        assert!(matches!(
            choose(Some(off_curve)),
            Err(CoreError::NoRegistryKey)
        ));
    }

    // The label keys are the public halves of their seeds, as verify.py says.
    #[test]
    fn the_keys_are_the_labels_public_halves() {
        use sha2::{Digest, Sha256};
        for (name, label) in [
            ("test_registry", "KCE/test/registry-key/v1"),
            ("other", "KCE/test/other-key/v1"),
        ] {
            let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
            let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
            assert_eq!(public.as_bytes(), &key_bytes(name), "{name}");
        }
    }

    // Two separate facts: the pin is the test key, and the build reports itself as a test build.
    #[cfg(feature = "test-registry")]
    #[test]
    fn a_test_registry_build_pins_the_test_key() {
        assert_eq!(TEST_REGISTRY_KEY, key_bytes("test_registry"));
        assert_eq!(pinned_bytes(), Some(TEST_REGISTRY_KEY));
        assert!(registry_key_is_test());
        match pinned_key() {
            Ok(key) => assert_eq!(key.as_bytes(), &TEST_REGISTRY_KEY),
            Err(e) => panic!("{e}"),
        }
        assert_eq!(&MARKER, b"KC_TEST_REGISTRY_DO_NOT_SHIP");
    }

    // Two separate facts: no key is pinned (until M9), and the build is not a test build (always).
    #[cfg(not(feature = "test-registry"))]
    #[test]
    fn a_release_build_pins_no_key() {
        assert_eq!(pinned_bytes(), None);
        assert!(matches!(pinned_key(), Err(CoreError::NoRegistryKey)));
        assert!(!registry_key_is_test());
    }
}
