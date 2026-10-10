//! Full ceremonies on the real OS source (docs/build-plan.md "Public API", test matrix "Full ceremony
//! with offline verification"; docs/pi-firmware.md and docs/mobile-apps.md ceremony steps;
//! tasks/todo.md, M1 group 10): Mixed and dice-only mode, on the Pi and on a phone, at 12 and 24
//! words. Default features, no stub: the Pi's hwrng input is keepcrypt.json's clean counter-mode
//! stream, and the dice are its public roll strings.
//!
//! Each ceremony reaches `Ready` through Skip (tests/check_flow.rs covers the check), reads every
//! insert back from its own faces, and only then exports: D (Mixed only, and C commits to it), the
//! backup, which `decrypt_backup` opens to the session's fingerprint, words, braille and seal, the
//! registration and the watch-only export. After `watch_only(Some(TREZOR))` the backup and the
//! registration are unchanged and hold no passphrase. Before read-back, every export fails.

mod common;

use common::{hex, named, read, text};
use keepcrypt_core::{
    BackupApp, Bip39Passphrase, CoreError, CreatedBy, ExtraSource, HW_BYTES_NEEDED, Mode, Platform,
    ReadbackResult, Ready, SeedLength, Session, TypedBackupPassphrase, decrypt_backup,
};
use sha2::{Digest, Sha256};

const BY: CreatedBy = CreatedBy::new(BackupApp::Android, 1, 2, 3);

/// keepcrypt.json's roll string for a seed length, as faces: 50 rolls for 12 words, 99 for 24.
fn faces(len: SeedLength) -> Vec<u8> {
    let name = match len {
        SeedLength::Words12 => "coldcard-50",
        SeedLength::Words24 => "coldcard-99",
    };
    let doc = read("keepcrypt.json");
    text(&named(&doc["dice_only"], name)["rolls"])
        .bytes()
        .map(|b| b - b'0')
        .collect()
}

/// The letters a reader takes from an insert's faces 1-4, up to the first blank face.
fn letters_on_the_metal(ready: &Session<Ready>, position: u8) -> String {
    let insert = ready.braille().insert(position).expect("an insert");
    insert.faces()[..4]
        .iter()
        .map_while(|face| face.letter())
        .collect()
}

/// One ceremony from `new` to the exports. With `with_passphrase`, it also exports a TREZOR
/// passphrase wallet and checks that the backup and the registration do not change.
fn ceremony(len: SeedLength, mode: Mode, platform: Platform, with_passphrase: bool) {
    let what = format!("{len:?} {mode:?} {platform:?}");
    let mut session = Session::new(len, mode, platform).expect("a session");
    if (platform, mode) == (Platform::Pi, Mode::Mixed) {
        let doc = read("keepcrypt.json");
        let stream = hex(&named(&doc["health"], "clean-4096")["samples_hex"]);
        let mut chunks = stream.chunks(64);
        while session.credited_bits() < session.required_bits() {
            let chunk = chunks.next().expect("enough hwrng");
            session = session.add_hw_samples(chunk).expect("healthy");
        }
        assert_eq!(session.hw_bytes_tested(), HW_BYTES_NEEDED, "{what}");
        assert_eq!(session.credited_bits(), 2_048, "{what}");
    }
    session.add_extra(ExtraSource::InputTiming, &[0x12, 0x34, 0x56, 0x78]);
    assert!(session.credited_bits() >= session.required_bits(), "{what}");
    let committed = session.commit().expect("committed");
    let commitment = committed.commitment();
    assert_eq!(commitment.is_some(), mode == Mode::Mixed, "{what}");

    let mut rolling = committed.start_dice();
    for face in faces(len) {
        rolling = rolling.push_roll(face).expect("a face");
    }
    assert_eq!(rolling.rolls(), rolling.minimum_rolls(), "{what}");
    assert_eq!(
        rolling.millibits(),
        u32::from(rolling.rolls()) * 2_585,
        "{what}"
    );
    let sealed = rolling.finish().expect("sealed");
    let seal = sealed.seal().clone();
    let mut ready = sealed.skip_check();

    let count = match len {
        SeedLength::Words12 => 12u8,
        SeedLength::Words24 => 24u8,
    };
    let words: Vec<String> = ready.mnemonic().words().map(str::to_owned).collect();
    assert_eq!(words.len(), usize::from(count), "{what}");
    assert_eq!(ready.braille().count(), usize::from(count), "{what}");
    assert_eq!(ready.braille().device_count(), count / 12, "{what}");
    for position in 1..=count {
        assert!(!ready.readback_complete(), "{what}: before word {position}");
        let letters = letters_on_the_metal(&ready, position);
        assert!(matches!(
            ready.check_readback(position, &letters),
            Ok(ReadbackResult::Match)
        ));
    }
    assert!(ready.readback_complete(), "{what}");

    let (ready, d) = ready.reveal_device_leg().expect("revealed");
    match (mode, d, commitment) {
        (Mode::Mixed, Some(d), Some(c)) => {
            let recomputed: [u8; 32] = Sha256::new()
                .chain_update(b"KCE/v1/commit")
                .chain_update(d.expose_secret())
                .finalize()
                .into();
            assert_eq!(recomputed, c, "{what}: C commits to D");
        }
        (Mode::DiceOnly, None, None) => {}
        _ => panic!("{what}: D and C disagree with the mode"),
    }

    let (ready, new) = ready.generate_backup_passphrase().expect("generated");
    let passphrase: Vec<String> = new.words().map(str::to_owned).collect();
    let typed = TypedBackupPassphrase::from_words(
        &passphrase.iter().map(String::as_str).collect::<Vec<_>>(),
    )
    .expect("8 list words");
    let (ready, file) = ready.encrypt_backup(&BY).expect("written");
    assert_eq!(ready.verify_backup(file.bytes()), Ok(()), "{what}");
    let checked = decrypt_backup(file.bytes(), &typed).expect("checked");
    assert_eq!(checked.fingerprint(), ready.fingerprint(), "{what}");
    let revealed: Vec<&str> = checked.reveal_words().collect();
    assert_eq!(revealed, words, "{what}");
    let session_braille: Vec<(u8, u8, u8, u16, String)> = ready
        .braille()
        .iter()
        .map(|i| {
            (
                i.position(),
                i.device(),
                i.sequence(),
                i.seedbook_number(),
                i.word_cells().collect(),
            )
        })
        .collect();
    let backup_braille: Vec<(u8, u8, u8, u16, String)> = checked
        .reveal_braille()
        .iter()
        .map(|i| {
            (
                i.position(),
                i.device(),
                i.sequence(),
                i.seedbook_number(),
                i.word_cells().collect(),
            )
        })
        .collect();
    assert_eq!(backup_braille, session_braille, "{what}");
    assert_eq!(checked.seal().expect("a seal"), seal, "{what}");

    let (ready, registration) = ready.registration().expect("registration");
    assert_eq!(registration.seal_id(), seal.seal_id(), "{what}");
    let registration_url = registration.url().to_owned();
    let (ready, plain) = ready.watch_only(None).expect("an export");
    assert!(!plain.passphrase_used(), "{what}");
    assert_eq!(plain.fingerprint(), ready.fingerprint(), "{what}");
    assert_eq!(plain.first_address(), ready.first_address(), "{what}");
    if !with_passphrase {
        return;
    }

    let trezor = Bip39Passphrase::new("TREZOR").expect("a passphrase");
    let (ready, export) = ready.watch_only(Some(&trezor)).expect("an export");
    assert!(export.passphrase_used(), "{what}");
    assert_ne!(export.fingerprint(), ready.fingerprint(), "{what}");
    assert_ne!(export.first_address(), ready.first_address(), "{what}");
    let (ready, again) = ready.registration().expect("registration");
    assert_eq!(
        again.url(),
        registration_url,
        "{what}: the seal ignores the passphrase"
    );
    let (ready, second) = ready.encrypt_backup(&BY).expect("written");
    assert_eq!(ready.verify_backup(second.bytes()), Ok(()), "{what}");
    let checked = decrypt_backup(second.bytes(), &typed).expect("checked");
    assert_eq!(
        checked.fingerprint(),
        ready.fingerprint(),
        "{what}: no passphrase in the backup"
    );
    let revealed: Vec<&str> = checked.reveal_words().collect();
    assert_eq!(revealed, words, "{what}");
}

#[test]
fn mixed_mode_on_the_pi() {
    ceremony(SeedLength::Words12, Mode::Mixed, Platform::Pi, true);
    ceremony(SeedLength::Words24, Mode::Mixed, Platform::Pi, false);
}

#[test]
fn mixed_mode_on_a_phone() {
    ceremony(SeedLength::Words12, Mode::Mixed, Platform::Phone, false);
    ceremony(SeedLength::Words24, Mode::Mixed, Platform::Phone, false);
}

#[test]
fn dice_only_on_the_pi() {
    ceremony(SeedLength::Words12, Mode::DiceOnly, Platform::Pi, false);
    ceremony(SeedLength::Words24, Mode::DiceOnly, Platform::Pi, true);
}

#[test]
fn dice_only_on_a_phone() {
    ceremony(SeedLength::Words12, Mode::DiceOnly, Platform::Phone, false);
    ceremony(SeedLength::Words24, Mode::DiceOnly, Platform::Phone, false);
}

/// Before every word has read back, each export fails with `ReadbackIncomplete` (and wipes; see
/// tests/error_injection.rs for the probe).
#[test]
fn every_export_fails_before_read_back() {
    type Export = fn(Session<Ready>) -> Result<(), CoreError>;
    let exports: [(&str, Export); 5] = [
        ("generate_backup_passphrase", |s| {
            s.generate_backup_passphrase().map(|_| ())
        }),
        ("encrypt_backup", |s| s.encrypt_backup(&BY).map(|_| ())),
        ("watch_only", |s| s.watch_only(None).map(|_| ())),
        ("registration", |s| s.registration().map(|_| ())),
        ("reveal_device_leg", |s| s.reveal_device_leg().map(|_| ())),
    ];
    for (name, export) in exports {
        let mut rolling = Session::new(SeedLength::Words12, Mode::Mixed, Platform::Phone)
            .and_then(Session::commit)
            .expect("committed")
            .start_dice();
        for face in faces(SeedLength::Words12) {
            rolling = rolling.push_roll(face).expect("a face");
        }
        let mut ready = rolling.finish().expect("sealed").skip_check();
        for position in 1..12 {
            let letters = letters_on_the_metal(&ready, position);
            assert!(ready.check_readback(position, &letters).is_ok());
        }
        assert_eq!(export(ready), Err(CoreError::ReadbackIncomplete), "{name}");
    }
}
