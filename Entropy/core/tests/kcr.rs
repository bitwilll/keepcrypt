//! vectors/kcr.json through the public API, in a build that pins the test registry key
//! (`required-features = ["test-registry"]` in core/Cargo.toml; tasks/todo.md, M1 group 7): every
//! snapshot and proof case gives exactly its result, a verified snapshot or proof gives its date,
//! freshness and lookups, and the build says it trusts the test registry. The release-mode sweep is
//! tests/kcr_release.rs.

mod common;

use common::{hex, named, read, text};
use core::num::NonZeroU16;
use keepcrypt_core::{
    CheckError, CoreError, RegistryDate, SealTag, registry_key_is_test, verify_bucket_proof,
    verify_bucket_proof_qr, verify_snapshot,
};
use serde_json::Value;

fn today(doc: &Value) -> RegistryDate {
    let value = u32::try_from(doc["today"].as_u64().expect("today")).expect("u32");
    RegistryDate::from_yyyymmdd(value).expect("a date")
}

fn tag_of(doc: &Value, seed: &str) -> SealTag {
    SealTag::from_bytes(
        hex(&named(&doc["seeds"], seed)["seal_tag_hex"])
            .try_into()
            .expect("32 bytes"),
    )
}

/// A rejected case's error as kcr.json names it: the SnapshotError inside CoreError::Snapshot.
fn snapshot_error(name: &str, e: CoreError) -> String {
    match e {
        CoreError::Snapshot(inner) => format!("{inner:?}"),
        other => panic!("{name}: {other:?} is not a snapshot error"),
    }
}

#[test]
fn the_test_registry_key_is_pinned() {
    assert!(registry_key_is_test());
}

#[test]
fn every_snapshot_case() {
    let doc = read("kcr.json");
    for case in doc["snapshots"].as_array().expect("snapshots") {
        let name = text(&case["name"]);
        let expect = &case["expect"];
        match verify_snapshot(&hex(&case["kcr_hex"])) {
            Ok(snapshot) => {
                assert_eq!(expect["ok"], true, "{name}");
                assert_eq!(Some(snapshot.number()), expect["number"].as_u64(), "{name}");
                assert_eq!(
                    Some(u64::from(snapshot.date().yyyymmdd())),
                    expect["date"].as_u64(),
                    "{name}"
                );
                assert_eq!(
                    Some(u64::try_from(snapshot.entry_count()).expect("a count")),
                    expect["count"].as_u64(),
                    "{name}"
                );
                assert_eq!(
                    format!("{:?}", snapshot.freshness(today(&doc))),
                    text(&expect["freshness"]),
                    "{name}"
                );
                for lookup in expect["lookups"].as_array().expect("lookups") {
                    let got = snapshot
                        .lookup(&tag_of(&doc, text(&lookup["seed"])))
                        .map(|count| u64::from(count.get()));
                    assert_eq!(got, lookup["count"].as_u64(), "{name}");
                }
            }
            Err(e) => {
                assert_eq!(expect["ok"], false, "{name}");
                assert_eq!(snapshot_error(name, e), text(&expect["error"]), "{name}");
            }
        }
    }
}

#[test]
fn every_proof_case() {
    let doc = read("kcr.json");
    for case in doc["proofs"].as_array().expect("proofs") {
        let name = text(&case["name"]);
        let expect = &case["expect"];
        let result = match case["ur"].as_str() {
            Some(qr) => verify_bucket_proof_qr(qr),
            None => verify_bucket_proof(&hex(&case["kcp1_hex"])),
        };
        match result {
            Ok(proof) => {
                assert_eq!(expect["ok"], true, "{name}");
                assert_eq!(
                    Some(u64::from(proof.bucket())),
                    expect["bucket"].as_u64(),
                    "{name}"
                );
                assert_eq!(Some(proof.number()), expect["number"].as_u64(), "{name}");
                assert_eq!(
                    Some(u64::from(proof.date().yyyymmdd())),
                    expect["date"].as_u64(),
                    "{name}"
                );
                assert_eq!(
                    Some(u64::try_from(proof.entry_count()).expect("k")),
                    expect["k"].as_u64(),
                    "{name}"
                );
                assert_eq!(
                    format!("{:?}", proof.freshness(today(&doc))),
                    text(&expect["freshness"]),
                    "{name}"
                );
                for lookup in expect["lookups"].as_array().expect("lookups") {
                    let want = match text(&lookup["result"]) {
                        "wrong_bucket" => Err(CheckError::WrongBucket),
                        "clear" => Ok(None),
                        _ => Ok(NonZeroU16::new(
                            u16::try_from(lookup["count"].as_u64().expect("count")).expect("u16"),
                        )),
                    };
                    assert_eq!(
                        proof.lookup(&tag_of(&doc, text(&lookup["seed"]))),
                        want,
                        "{name}"
                    );
                }
            }
            Err(e) => {
                assert_eq!(expect["ok"], false, "{name}");
                assert_eq!(snapshot_error(name, e), text(&expect["error"]), "{name}");
            }
        }
    }
}
