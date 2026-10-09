//! The release-mode sweep (tasks/todo.md, M1 group 7; CLAUDE.md rule 10): a build without the
//! `test-registry` feature pins no registry key until M9, so every vectors/kcr.json case, valid,
//! tampered or malformed, snapshot, proof bytes or go-ahead QR text, gives `NoRegistryKey` before
//! a byte is read, and only the typed go-ahead code works. Its own test target with no required
//! features; in a build with `test-registry` it compiles to nothing (tests/kcr.rs runs instead).
#![cfg(not(feature = "test-registry"))]

mod common;

use common::{hex, named, read, text};
use keepcrypt_core::{
    CoreError, registry_key_is_test, verify_bucket_proof, verify_bucket_proof_qr, verify_snapshot,
};

#[test]
fn no_registry_key_is_pinned() {
    assert!(!registry_key_is_test());
}

#[test]
fn every_kcr_json_case_gives_no_registry_key() {
    let doc = read("kcr.json");
    let snapshots = doc["snapshots"].as_array().expect("snapshots");
    for case in snapshots {
        assert!(
            matches!(
                verify_snapshot(&hex(&case["kcr_hex"])),
                Err(CoreError::NoRegistryKey)
            ),
            "{}",
            text(&case["name"])
        );
    }
    let proofs = doc["proofs"].as_array().expect("proofs");
    for case in proofs {
        let result = match case["ur"].as_str() {
            Some(qr) => verify_bucket_proof_qr(qr),
            None => verify_bucket_proof(&hex(&case["kcp1_hex"])),
        };
        assert!(
            matches!(result, Err(CoreError::NoRegistryKey)),
            "{}",
            text(&case["name"])
        );
    }
    // The valid ones too: a snapshot that would verify under the test key, and an empty input.
    assert!(matches!(
        verify_snapshot(&hex(&named(&doc["snapshots"], "small")["kcr_hex"])),
        Err(CoreError::NoRegistryKey)
    ));
    assert!(matches!(
        verify_snapshot(&[]),
        Err(CoreError::NoRegistryKey)
    ));
    assert!(matches!(
        verify_bucket_proof_qr(""),
        Err(CoreError::NoRegistryKey)
    ));
    assert_eq!(snapshots.len() + proofs.len(), 107);
}
