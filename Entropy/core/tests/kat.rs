//! The known-answer subsets, cross-checked (docs/build-plan.md "kat" and test matrix row 1;
//! tasks/todo.md, M1 group 2 and group 10). Each known-answer group copies its answers from one
//! vectors file, and kat.rs's unit tests compare every constant with that file. This test checks
//! from the outside that the files agree with each other on the answers the groups share, and that
//! the public entry points give them:
//!
//! - `self_test` passes, and `hwrng_boot_test` passes 1,024 clean samples and refuses any other
//!   count and a stuck stream (the Health group's streams are keepcrypt.json's);
//! - Seal and GoAhead: seal.json's vector 1 is kcr.json's vector-1 seed and CLAUDE.md's seal vector,
//!   and a checked backup of those words gives it;
//! - Bip84: the fingerprint `73c5da0a` is watchonly.json's abandon wallet and backup.json's
//!   abandon plaintext, and `decrypt_backup` gives it;
//! - Seed: the dice-only E of `123456` is keepcrypt.json's and Coldcard's;
//! - Ed25519: kat.json's RFC 8032 TEST 1 is kcr.json's;
//! - Hmac, Sha256, Sha512: kat.json's entries are the published RFC 4231 and FIPS 180-4 values;
//! - Age: CCTV's `scrypt` and `armor_scrypt` are backup.json's `cctv-scrypt` and
//!   `cctv-armor-scrypt`;
//! - Braille: braille.json's `2026` and Seal ID text vectors match seal.json's caption.

mod common;

use common::{hex, named, read, text};
use keepcrypt_core::{
    CoreError, SourceFault, TypedBackupPassphrase, decrypt_backup, hwrng_boot_test, self_test,
};
use std::path::Path;

#[test]
fn the_boot_screens_pass() {
    assert_eq!(self_test(), Ok(()));
    let clean = hex(&named(&read("keepcrypt.json")["health"], "clean-4096")["samples_hex"]);
    assert_eq!(hwrng_boot_test(&clean[..1_024]), Ok(()));
    for count in [0, 1_023, 1_025] {
        assert_eq!(
            hwrng_boot_test(&clean[..count]),
            Err(CoreError::Source(SourceFault::HwrngSampleCount))
        );
    }
    assert!(matches!(
        hwrng_boot_test(&[0; 1_024]),
        Err(CoreError::Health(_))
    ));
}

#[test]
fn seal_and_go_ahead_answers_agree() {
    let seal = &read("seal.json")["vectors"][0];
    let kcr = named(&read("kcr.json")["seeds"], "vector-1").clone();
    for key in ["mnemonic", "seal_code", "seal_tag_hex", "seal_id"] {
        assert_eq!(seal[key], kcr[key], "{key}");
    }
    assert_eq!(seal["go_ahead"]["code"], kcr["go_ahead"]);
    assert_eq!(seal["go_ahead"]["nonce_hex"], kcr["nonce_hex"]);
    // CLAUDE.md's seal vector and go-ahead vector.
    assert_eq!(seal["seal_code"], "JXP3R-DXYAC-JZ1NA-X3RGQ-DJCJJN");
    assert_eq!(
        seal["seal_tag_hex"],
        "2b8103c8dd64611df5c8c28b8fbf864a1005372f5da06a5777f92708ce79cb5c"
    );
    assert_eq!(seal["seal_id"], "5E0G7J6X");
    assert_eq!(seal["go_ahead"]["nonce_hex"], "0001020304050607");
    assert_eq!(seal["go_ahead"]["code"], "CF94-BCAJ");
}

#[test]
fn bip84_and_backup_answers_agree() {
    let watchonly = read("watchonly.json");
    let wallet = named(&watchonly["wallets"], "abandon");
    let backup = read("backup.json");
    let plaintext = named(&backup["plaintexts"], "abandon-12");
    assert_eq!(wallet["mnemonic"], plaintext["mnemonic"]);
    assert_eq!(wallet["fingerprint"], "73c5da0a");
    assert_eq!(plaintext["fingerprint"], "73c5da0a");
    let file = named(&backup["age_files"], "abandon-12");
    let words: Vec<&str> = text(&file["passphrase"]).split(' ').collect();
    let typed = TypedBackupPassphrase::from_words(&words).expect("eight words");
    let checked = decrypt_backup(text(&file["file"]).as_bytes(), &typed).expect("checked");
    assert_eq!(checked.fingerprint(), [0x73, 0xc5, 0xda, 0x0a]);
    let seal = checked.seal().expect("a seal");
    assert_eq!(
        seal.seal_id(),
        text(&read("seal.json")["vectors"][0]["seal_id"])
    );
}

#[test]
fn seed_answers_agree() {
    let keepcrypt = read("keepcrypt.json");
    let case = named(&keepcrypt["dice_only"], "coldcard-123456");
    let coldcard = read("coldcard/rolls.json");
    let published = coldcard["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["rolls"] == "123456")
        .expect("the published 123456 example");
    assert_eq!(case["e_hex"], published["sha256_hex"]);
    assert_eq!(
        case["e_hex"],
        "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
    );
}

#[test]
fn ed25519_and_hash_answers_agree() {
    let kat = read("kat.json");
    let kcr = read("kcr.json");
    let ours = named(&kat["ed25519"], "rfc8032-test-1");
    let theirs = named(&kcr["rfc8032"], "rfc8032-test-1");
    for key in ["public_key_hex", "message_hex", "signature_hex"] {
        assert_eq!(ours[key], theirs[key], "{key}");
    }
    let hmac = named(&kat["hmac"], "rfc4231-case-2");
    assert_eq!(
        hmac["hmac_sha256_hex"],
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    let abc = kat["sha256"]
        .as_array()
        .expect("sha256")
        .iter()
        .find(|e| e["message_ascii"] == "abc")
        .expect("the abc example");
    assert_eq!(
        abc["digest_hex"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn age_answers_agree() {
    let backup = read("backup.json");
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors/age/scrypt");
    for (cctv, name) in [
        ("scrypt", "cctv-scrypt"),
        ("armor_scrypt", "cctv-armor-scrypt"),
    ] {
        let test_file = std::fs::read(dir.join(cctv)).expect("a CCTV file");
        let body_at = test_file
            .windows(2)
            .position(|w| w == b"\n\n")
            .expect("the CCTV header ends with an empty line")
            + 2;
        let case = named(&backup["age_files"], name);
        let ours = match case["file"].as_str() {
            Some(file) => file.as_bytes().to_vec(),
            None => hex(&case["file_hex"]),
        };
        assert_eq!(&test_file[body_at..], ours.as_slice(), "{cctv}");
    }
}

#[test]
fn braille_answers_agree() {
    let braille = read("braille.json");
    let seal = &read("seal.json")["vectors"][0];
    let texts = braille["text"].as_array().expect("text vectors");
    let cells = |t: &str| {
        texts
            .iter()
            .find(|v| v["text"] == t)
            .map(|v| text(&v["cells"]).to_owned())
            .expect("a text vector")
    };
    assert_eq!(cells("2026"), "\u{283c}\u{2803}\u{281a}\u{2803}\u{280b}");
    assert_eq!(cells("5e0g7j6x"), text(&seal["seal_id_braille"]));
}
