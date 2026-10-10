//! The vector sets through the public API (docs/build-plan.md test matrix "Known answers", "Seal,
//! braille and descriptor vectors"; tasks/todo.md, M1 group 10 and Verification "All vectors pass").
//! Default features: a release-configuration build, real OS source.
//!
//! - rolls.json (Coldcard's own outputs) and every keepcrypt.json dice-only case, through
//!   dice-only sessions at 12 and 24 words: the words, or `TooFewRolls` below the minimum.
//! - backup.json and the age CLI's files, through `decrypt_backup`: every file with typed
//!   passphrase words opens to its plaintext's words and fingerprint, or gives its exact error.
//! - seal.json's vector 1 (the CLAUDE.md seal vector), through a checked backup's `seal()`.
//! - braille.json's entry for every word those seeds and backups hold, through the braille views.
//! - kcr.json runs in tests/kcr.rs (test registry key) and tests/kcr_release.rs (no key).
//!
//! Secrets have no public constructor, so the rest of each full set runs in the unit tests of its
//! module, which read the same files: BIP39 vectors.json (seed.rs), the 26 CCTV files, whose
//! passphrase "password" is not eight list words (backup/age.rs), seal.json's vectors 2 and 3
//! (seal.rs), all 2,048 braille.json entries (braille.rs) and watchonly.json (descriptor.rs,
//! ur.rs).

mod common;

use common::{hex, named, read, text};
use keepcrypt_core::{
    BackupError, BrailleInserts, CoreError, Mode, Platform, SeedLength, Session,
    TypedBackupPassphrase, decrypt_backup,
};
use serde_json::Value;
use std::collections::BTreeSet;

fn listed(v: &Value) -> Vec<String> {
    v.as_array()
        .expect("a word list")
        .iter()
        .map(|w| text(w).to_owned())
        .collect()
}

/// The words of a dice-only session from `rolls`, or its error (`TooFewRolls` below the minimum).
fn dice_only_words(len: SeedLength, rolls: &str) -> Result<Vec<String>, CoreError> {
    let mut rolling = Session::new(len, Mode::DiceOnly, Platform::Phone)?
        .commit()?
        .start_dice();
    for b in rolls.bytes() {
        rolling = rolling.push_roll(b - b'0')?;
    }
    let ready = rolling.finish()?.skip_check();
    let words = ready.mnemonic().words().map(str::to_owned).collect();
    check_braille(&ready.braille());
    Ok(words)
}

/// Every insert's SeedBook number, faces (blanks included), lighter face, mirror partners and cells
/// equal braille.json's entry for its word.
fn check_braille(inserts: &BrailleInserts<'_>) {
    let doc = read("braille.json");
    let entries = doc["words"].as_array().expect("words");
    for insert in inserts.iter() {
        let entry = &entries[usize::from(insert.seedbook_number()) - 1];
        let word = insert.word();
        assert_eq!(entry["word"], word);
        assert_eq!(entry["number"], insert.seedbook_number(), "{word}");
        let faces = insert.faces();
        for (i, face) in faces.iter().enumerate() {
            let letter = face.letter().map(String::from);
            assert_eq!(
                entry["faces"][i].as_str().map(str::to_owned),
                letter,
                "{word}"
            );
            let partner = face.mirror_partner().map(String::from);
            assert_eq!(
                entry["mirror_partners"][i].as_str().map(str::to_owned),
                partner,
                "{word}"
            );
            assert_eq!(face.is_lighter(), entry["lighter_face"] == i + 1, "{word}");
        }
        assert_eq!(
            entry["cells"],
            insert.word_cells().collect::<String>(),
            "{word}"
        );
    }
}

#[test]
fn rolls_json_through_dice_only_sessions() {
    let doc = read("coldcard/rolls.json");
    for case in doc["cases"].as_array().expect("cases") {
        let rolls = text(&case["rolls"]);
        for (len, key, minimum) in [
            (SeedLength::Words12, "words_12", 50),
            (SeedLength::Words24, "words_24", 99),
        ] {
            let got = dice_only_words(len, rolls);
            if rolls.len() < minimum {
                assert_eq!(got, Err(CoreError::TooFewRolls), "{rolls} {len:?}");
            } else {
                assert_eq!(got, Ok(listed(&case[key])), "{rolls} {len:?}");
            }
        }
    }
}

#[test]
fn keepcrypt_json_dice_only_cases() {
    let doc = read("keepcrypt.json");
    let cases = doc["dice_only"].as_array().expect("cases");
    assert_eq!(cases.len(), 6);
    for case in cases {
        let name = text(&case["name"]);
        let rolls = text(&case["rolls"]);
        for (len, key, minimum) in [
            (SeedLength::Words12, "words_12", 50),
            (SeedLength::Words24, "words_24", 99),
        ] {
            let got = dice_only_words(len, rolls);
            if rolls.len() < minimum {
                assert_eq!(got, Err(CoreError::TooFewRolls), "{name} {len:?}");
            } else {
                assert_eq!(got, Ok(listed(&case[key])), "{name} {len:?}");
            }
        }
    }
}

/// A backup.json file entry's bytes.
fn file_of(case: &Value) -> Vec<u8> {
    match case["file"].as_str() {
        Some(file) => file.as_bytes().to_vec(),
        None => hex(&case["file_hex"]),
    }
}

/// Typed words for a passphrase; refused unless it is eight list words (CCTV's "password" is not).
fn typed(passphrase: &str) -> Result<TypedBackupPassphrase, CoreError> {
    let words: Vec<&str> = passphrase.split(' ').collect();
    TypedBackupPassphrase::from_words(&words)
}

#[test]
fn backup_json_and_the_age_cli_files_through_decrypt_backup() {
    let doc = read("backup.json");
    let cli = read("age/age_cli_written.json");
    let files: Vec<&Value> = doc["age_files"]
        .as_array()
        .expect("files")
        .iter()
        .chain(cli["files"].as_array().expect("files"))
        .collect();
    let mut untyped = BTreeSet::new();
    let mut opened = 0;
    for case in files {
        let name = text(&case["name"]);
        let Ok(passphrase) = typed(text(&case["passphrase"])) else {
            untyped.insert(text(&case["passphrase"]).to_owned());
            continue;
        };
        let result = decrypt_backup(&file_of(case), &passphrase);
        match case["plaintext"].as_str() {
            Some(plaintext) => {
                let want = named(&doc["plaintexts"], plaintext);
                let checked = match result {
                    Ok(checked) => checked,
                    Err(e) => panic!("{name}: {e:?}"),
                };
                assert_eq!(
                    hex(&want["fingerprint"]),
                    checked.fingerprint().to_vec(),
                    "{name}"
                );
                let words: Vec<&str> = checked.reveal_words().collect();
                assert_eq!(words.join(" "), text(&want["mnemonic"]), "{name}");
                check_braille(&checked.reveal_braille());
                opened += 1;
            }
            None => assert!(
                matches!(result, Err(CoreError::Backup(BackupError::Plaintext))),
                "{name}: not a KeepCrypt plaintext"
            ),
        }
    }
    assert_eq!(opened, 13, "9 backup.json backups and the age CLI's 4");
    for case in doc["age_refused"].as_array().expect("refused") {
        let name = text(&case["name"]);
        let Ok(passphrase) = typed(text(&case["passphrase"])) else {
            untyped.insert(text(&case["passphrase"]).to_owned());
            continue;
        };
        let result = decrypt_backup(&file_of(case), &passphrase).map(|c| c.fingerprint());
        match result {
            Ok(_) => panic!("{name}: opened"),
            Err(e) => assert_eq!(format!("{e:?}"), text(&case["error"]), "{name}"),
        }
    }
    assert_eq!(
        untyped.into_iter().collect::<Vec<_>>(),
        ["password"],
        "only CCTV's files are out of reach of typed words"
    );
}

#[test]
fn seal_json_vector_1_through_a_checked_backup() {
    let doc = read("backup.json");
    let file = named(&doc["age_files"], "abandon-12");
    let passphrase = typed(text(&file["passphrase"])).expect("eight words");
    let checked = decrypt_backup(&file_of(file), &passphrase).expect("checked");
    let seal = checked.seal().expect("a seal");
    let vector = &read("seal.json")["vectors"][0];
    assert_eq!(
        checked.reveal_words().collect::<Vec<_>>().join(" "),
        text(&vector["mnemonic"])
    );
    assert_eq!(seal.tag().to_hex(), text(&vector["seal_tag_hex"]));
    assert_eq!(seal.seal_id(), text(&vector["seal_id"]));
    assert_eq!(seal.seal_id_braille(), text(&vector["seal_id_braille"]));
    assert_eq!(seal.lookup_prefix(), text(&vector["lookup_prefix"]));
    assert_eq!(seal.colour_index(), vector["colour_index"]);
    assert_eq!(seal.colour_hex(), text(&vector["colour_hex"]));
    let grid: Vec<String> = seal
        .grid()
        .iter()
        .map(|row| row.iter().map(|&on| if on { '#' } else { '.' }).collect())
        .collect();
    assert_eq!(grid, listed(&vector["grid"]));
    assert_eq!(
        seal.recheck_url(),
        format!(
            "https://registry.invalid/check#t={}",
            text(&vector["seal_tag_hex"])
        )
    );
}
