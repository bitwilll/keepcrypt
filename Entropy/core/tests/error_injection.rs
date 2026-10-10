//! Error injection (docs/build-plan.md CI rule "Fail closed", test matrix "Error injection on every
//! source" and "Repetition Count and Adaptive Proportion"; CLAUDE.md rule 3; tasks/todo.md, M1
//! group 10 and "Inputs from M0"). Every failure halts the session and wipes it: each session case
//! below asserts the exact `Err` and exactly one wipe on the stub's probe, which zeroizing `Inner`
//! bumps last, once every field is clear (`Inner`'s `Drop` runs that zeroize). No lint sees an OS
//! read whose error is matched and dropped (`if let Err(_) = read(..) {}`), so these tests are what
//! proves that no source failure is swallowed: `every_os_read_of_a_ceremony_halts_and_wipes` fails
//! each OS read of a whole ceremony in turn, from a pinned list that a new draw site cannot stay
//! out of.
//!
//! The free functions that run known-answer groups hold no session, so they have no probe: each
//! `*_with_kat_fault` twin gives exactly `Kat(id)` for every group its function runs and the
//! unfaulted result for every other group, both read from one exhaustive match.

mod common;

use common::{hex, named, read, text};
use keepcrypt_core::{
    BackupApp, Collecting, CoreError, CreatedBy, Discard, ExtraSource, GoAhead, HealthFailure,
    HealthStage, HealthTest, KatId, Mode, Platform, ReadbackResult, Ready, Rolling, Sealed,
    SeedLength, Session, SnapshotError, SourceFault, StubEntropy, StubSource,
    TypedBackupPassphrase, VerifiedSnapshot, WipeProbe, Wiped, decrypt_backup_with_kat_fault,
    hwrng_boot_test_with_kat_fault, seal_from_mnemonic_with_kat_fault, self_test_with_kat_fault,
    verify_bucket_proof_qr_with_kat_fault, verify_bucket_proof_with_kat_fault, verify_snapshot,
    verify_snapshot_with_kat_fault,
};

/// Asserts that `result` is exactly `want` and that the session was wiped exactly once.
fn assert_halted<T>(result: Result<T, CoreError>, want: CoreError, probe: &WipeProbe, what: &str) {
    match result {
        Ok(_) => panic!("{what}: no error"),
        Err(e) => assert_eq!(e, want, "{what}"),
    }
    assert_eq!(probe.wipes(), 1, "{what}: wipes");
}

fn stub(entropy: StubEntropy, probe: &WipeProbe) -> StubSource {
    StubSource::new(entropy, probe)
}

fn new(
    len: SeedLength,
    mode: Mode,
    platform: Platform,
    entropy: StubEntropy,
    probe: &WipeProbe,
) -> Session<Collecting> {
    Session::new_with_stub(len, mode, platform, stub(entropy, probe), None).expect("a session")
}

/// keepcrypt.json's clean hwrng stream (4,096 samples).
fn clean_hwrng() -> Vec<u8> {
    hex(&named(&read("keepcrypt.json")["health"], "clean-4096")["samples_hex"])
}

/// `bytes` of the clean stream through `add_hw_samples`, in 64-byte chunks.
fn fed(mut session: Session<Collecting>, bytes: usize) -> Session<Collecting> {
    for chunk in clean_hwrng()[..bytes].chunks(64) {
        session = session.add_hw_samples(chunk).expect("healthy");
    }
    session
}

/// keepcrypt.json's dice-only roll string `name`, as faces.
fn faces(name: &str) -> Vec<u8> {
    let doc = read("keepcrypt.json");
    text(&named(&doc["dice_only"], name)["rolls"])
        .bytes()
        .map(|b| b - b'0')
        .collect()
}

fn roll_all(mut rolling: Session<Rolling>, faces: &[u8]) -> Session<Rolling> {
    for &face in faces {
        rolling = rolling.push_roll(face).expect("a face");
    }
    rolling
}

/// A 12-word dice-only session on `entropy`, through `finish`: dice-only mode reads nothing before
/// a check, so every OS byte the stub serves goes to what follows.
fn sealed(entropy: StubEntropy, probe: &WipeProbe) -> Session<Sealed> {
    let committed = new(
        SeedLength::Words12,
        Mode::DiceOnly,
        Platform::Phone,
        entropy,
        probe,
    )
    .commit()
    .expect("committed");
    roll_all(committed.start_dice(), &faces("coldcard-50"))
        .finish()
        .expect("sealed")
}

fn read_back_every_word(ready: &mut Session<Ready>) {
    let typed: Vec<(u8, String)> = ready
        .braille()
        .iter()
        .map(|insert| (insert.position(), insert.word().chars().take(4).collect()))
        .collect();
    for (position, letters) in typed {
        assert!(matches!(
            ready.check_readback(position, &letters),
            Ok(ReadbackResult::Match)
        ));
    }
}

/// A `Ready` session on `entropy` with every word read back, so the exports are open.
fn ready(entropy: StubEntropy, probe: &WipeProbe) -> Session<Ready> {
    let mut ready = sealed(entropy, probe).skip_check();
    read_back_every_word(&mut ready);
    ready
}

/// The OS bytes backup.json's "stream" case gives `generate_backup_passphrase` (one attempt).
fn generate_bytes() -> Vec<u8> {
    hex(&named(&read("backup.json")["generate"], "stream")["os_hex"])
}

const BY: CreatedBy = CreatedBy::new(BackupApp::Pi, 1, 0, 0);

#[test]
fn the_os_source_failing_halts_and_wipes() {
    for platform in [Platform::Pi, Platform::Phone] {
        let probe = WipeProbe::new();
        let session = new(
            SeedLength::Words12,
            Mode::Mixed,
            platform,
            StubEntropy::Fail,
            &probe,
        );
        let session = match platform {
            Platform::Pi => fed(session, 1_536),
            Platform::Phone => session,
        };
        let what = format!("commit on {platform:?}");
        assert_halted(
            session.commit(),
            CoreError::Source(SourceFault::Os),
            &probe,
            &what,
        );
    }

    let probe = WipeProbe::new();
    let checking = sealed(StubEntropy::Fail, &probe).start_check();
    assert_halted(
        checking,
        CoreError::Source(SourceFault::Os),
        &probe,
        "start_check",
    );

    let probe = WipeProbe::new();
    let result = ready(StubEntropy::Fail, &probe).generate_backup_passphrase();
    assert_halted(
        result,
        CoreError::Source(SourceFault::Os),
        &probe,
        "generate",
    );

    // encrypt_backup with nothing left after the passphrase, and with only the file key left.
    for extra in [0, 16] {
        let mut bytes = generate_bytes();
        bytes.extend(std::iter::repeat_n(7, extra));
        let probe = WipeProbe::new();
        let (session, _) = ready(StubEntropy::Fixed(bytes), &probe)
            .generate_backup_passphrase()
            .expect("generated");
        let what = format!("encrypt with {extra} bytes left");
        assert_halted(
            session.encrypt_backup(&BY),
            CoreError::Source(SourceFault::Os),
            &probe,
            &what,
        );
    }
}

#[test]
fn short_reads_halt_and_wipe() {
    let probe = WipeProbe::new();
    let session = new(
        SeedLength::Words12,
        Mode::Mixed,
        Platform::Phone,
        StubEntropy::ShortAfter(10),
        &probe,
    );
    assert_halted(
        session.commit(),
        CoreError::Source(SourceFault::ShortRead),
        &probe,
        "commit",
    );

    let probe = WipeProbe::new();
    let checking = sealed(StubEntropy::ShortAfter(4), &probe).start_check();
    assert_halted(
        checking,
        CoreError::Source(SourceFault::ShortRead),
        &probe,
        "start_check",
    );

    let probe = WipeProbe::new();
    let result = ready(StubEntropy::ShortAfter(5), &probe).generate_backup_passphrase();
    assert_halted(
        result,
        CoreError::Source(SourceFault::ShortRead),
        &probe,
        "generate",
    );

    // The passphrase and its challenge take 27 bytes; the file key's 16 leave 4 for the salt.
    let probe = WipeProbe::new();
    let (session, _) = ready(StubEntropy::ShortAfter(27 + 20), &probe)
        .generate_backup_passphrase()
        .expect("generated");
    assert_halted(
        session.encrypt_backup(&BY),
        CoreError::Source(SourceFault::ShortRead),
        &probe,
        "encrypt",
    );
}

/// The steps of a whole ceremony that read the OS source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Commit,
    StartCheck,
    Generate,
    Encrypt,
}

/// Every OS read of a 12-word Mixed phone ceremony, in order: the step that makes it and its size.
const CEREMONY_READS: [(Step, usize); 8] = [
    (Step::Commit, 64),    // the OS record, absorbed last
    (Step::StartCheck, 8), // the check nonce n
    (Step::Generate, 11),  // the backup passphrase
    (Step::Generate, 16),  // one confirm-challenge attempt (the stub's first is usable)
    (Step::Encrypt, 16),   // the age file key
    (Step::Encrypt, 16),   // the scrypt salt
    (Step::Encrypt, 16),   // the payload nonce
    (Step::Encrypt, 4),    // the file name
];

/// A whole 12-word Mixed phone ceremony on `entropy`, from `new` through a cleared check to
/// `encrypt_backup`: `Ok` if every step passed, else the step that failed and its error. Either
/// way the session has been dropped by the time it returns.
fn ceremony_on(
    entropy: StubEntropy,
    clear: &VerifiedSnapshot,
    probe: &WipeProbe,
) -> Result<(), (Step, CoreError)> {
    let session = new(
        SeedLength::Words12,
        Mode::Mixed,
        Platform::Phone,
        entropy,
        probe,
    );
    let committed = session.commit().map_err(|e| (Step::Commit, e))?;
    let sealed = roll_all(committed.start_dice(), &faces("coldcard-50"))
        .finish()
        .expect("sealed");
    let checking = sealed.start_check().map_err(|e| (Step::StartCheck, e))?;
    let mut ready = match checking.reveal(GoAhead::Snapshot(clear)) {
        Ok(ready) => ready,
        Err(rejected) => panic!("the snapshot does not clear this seal: {rejected:?}"),
    };
    read_back_every_word(&mut ready);
    let (ready, _) = ready
        .generate_backup_passphrase()
        .map_err(|e| (Step::Generate, e))?;
    ready.encrypt_backup(&BY).map_err(|e| (Step::Encrypt, e))?;
    Ok(())
}

/// Each OS read of a whole ceremony fails in turn (`FailAt`), then comes up one byte short in turn
/// (`ShortAfter`): every time, the step that makes that read halts with exactly `Source(Os)` or
/// `Source(ShortRead)` and the session is wiped once. With every listed read served, the ceremony
/// completes, so there is no read the list leaves out: a new draw site fails this test until it is
/// listed, and then its failure is injected too (review fix after commit 25: no test failed the
/// backup's nonce or file-name read).
#[test]
fn every_os_read_of_a_ceremony_halts_and_wipes() {
    let clear = verify_snapshot(&hex(
        &named(&read("kcr.json")["snapshots"], "small")["kcr_hex"],
    ))
    .expect("valid");
    let mut offset = 0;
    for (n, &(step, size)) in CEREMONY_READS.iter().enumerate() {
        let probe = WipeProbe::new();
        assert_eq!(
            ceremony_on(StubEntropy::FailAt(n), &clear, &probe),
            Err((step, CoreError::Source(SourceFault::Os))),
            "read {n} fails"
        );
        assert_eq!(probe.wipes(), 1, "read {n} fails: wipes");
        let probe = WipeProbe::new();
        assert_eq!(
            ceremony_on(StubEntropy::ShortAfter(offset + size - 1), &clear, &probe),
            Err((step, CoreError::Source(SourceFault::ShortRead))),
            "read {n} short"
        );
        assert_eq!(probe.wipes(), 1, "read {n} short: wipes");
        offset += size;
    }
    for entropy in [
        StubEntropy::FailAt(CEREMONY_READS.len()),
        StubEntropy::ShortAfter(offset),
    ] {
        let probe = WipeProbe::new();
        assert_eq!(ceremony_on(entropy, &clear, &probe), Ok(()));
        assert_eq!(probe.wipes(), 1, "dropped at the end");
    }
}

fn health_test(name: &str) -> HealthTest {
    match name {
        "repetition_count" => HealthTest::RepetitionCount,
        "adaptive_proportion" => HealthTest::AdaptiveProportion,
        other => panic!("no health test {other}"),
    }
}

fn health_stage(name: &str) -> HealthStage {
    match name {
        "startup" => HealthStage::Startup,
        "continuous" => HealthStage::Continuous,
        other => panic!("no health stage {other}"),
    }
}

/// Every keepcrypt.json health case through a Pi session, in 64-byte chunks: a failing stream halts
/// the session at its pinned test, stage and sample, in the startup and the continuous stage; a
/// passing one is tested and credited as pinned, and commits once credited.
#[test]
fn every_health_case_through_the_session() {
    let doc = read("keepcrypt.json");
    for case in doc["health"].as_array().expect("cases") {
        let name = text(&case["name"]);
        let expect = &case["expect"];
        let probe = WipeProbe::new();
        let mut session = Some(new(
            SeedLength::Words12,
            Mode::Mixed,
            Platform::Pi,
            StubEntropy::Fixed(vec![0x5a; 64]),
            &probe,
        ));
        let mut failure = None;
        for chunk in hex(&case["samples_hex"]).chunks(64) {
            let Some(current) = session.take() else {
                break;
            };
            match current.add_hw_samples(chunk) {
                Ok(next) => session = Some(next),
                Err(e) => failure = Some(e),
            }
        }
        if text(&expect["result"]) == "fail" {
            let want = CoreError::Health(HealthFailure {
                test: health_test(text(&expect["test"])),
                stage: health_stage(text(&expect["stage"])),
                sample: expect["sample"].as_u64().expect("a sample"),
            });
            assert_eq!(failure, Some(want), "{name}");
            assert!(session.is_none(), "{name}: halted");
            assert_eq!(probe.wipes(), 1, "{name}: wipes");
            continue;
        }
        let session = session.expect("healthy");
        assert_eq!(session.hw_bytes_tested(), expect["tested"], "{name}");
        let credited = expect["credited_samples"].as_u64().expect("credited");
        assert_eq!(session.credited_bits(), credited * 4, "{name}");
        assert!(
            session.commit().is_ok(),
            "{name}: 512 credited samples meet the quota"
        );
    }
}

/// 1,535 hwrng bytes complete no post-startup window, so nothing is credited; extras are never
/// credited, even a MiB from each.
#[test]
fn the_pi_quota_needs_a_whole_window_of_hwrng() {
    let probe = WipeProbe::new();
    let session = fed(
        new(
            SeedLength::Words12,
            Mode::Mixed,
            Platform::Pi,
            StubEntropy::Stream(b"os".to_vec()),
            &probe,
        ),
        1_535,
    );
    assert_eq!(
        (session.hw_bytes_tested(), session.credited_bits()),
        (1_535, 0)
    );
    assert_halted(
        session.commit(),
        CoreError::QuotaUnmet,
        &probe,
        "1,535 bytes",
    );

    let probe = WipeProbe::new();
    let mut session = new(
        SeedLength::Words24,
        Mode::Mixed,
        Platform::Pi,
        StubEntropy::Stream(b"os".to_vec()),
        &probe,
    );
    let mebibyte = vec![0xa5; 1 << 20];
    for source in [
        ExtraSource::InputTiming,
        ExtraSource::Motion,
        ExtraSource::Camera,
        ExtraSource::Microphone,
    ] {
        session.add_extra(source, &mebibyte);
    }
    assert_eq!(session.credited_bits(), 0);
    assert_halted(
        session.commit(),
        CoreError::QuotaUnmet,
        &probe,
        "extras only",
    );
}

/// hwrng samples where no hwrng is credited: a phone, or dice-only mode.
#[test]
fn hwrng_input_on_a_phone_or_in_dice_only_mode() {
    for (mode, platform) in [
        (Mode::Mixed, Platform::Phone),
        (Mode::DiceOnly, Platform::Pi),
        (Mode::DiceOnly, Platform::Phone),
    ] {
        let probe = WipeProbe::new();
        let session = new(
            SeedLength::Words12,
            mode,
            platform,
            StubEntropy::Fail,
            &probe,
        );
        let what = format!("{mode:?} on {platform:?}");
        assert_halted(
            session.add_hw_samples(&clean_hwrng()[..64]),
            CoreError::NotInThisMode,
            &probe,
            &what,
        );
    }
}

#[test]
fn bad_faces_and_a_257th_roll() {
    for face in [0, 7, 255] {
        let probe = WipeProbe::new();
        let rolling = new(
            SeedLength::Words12,
            Mode::DiceOnly,
            Platform::Phone,
            StubEntropy::Fail,
            &probe,
        )
        .commit()
        .expect("committed")
        .start_dice();
        let what = format!("face {face}");
        assert_halted(
            rolling.push_roll(face),
            CoreError::InvalidRoll,
            &probe,
            &what,
        );
    }
    let probe = WipeProbe::new();
    let rolling = new(
        SeedLength::Words24,
        Mode::DiceOnly,
        Platform::Phone,
        StubEntropy::Fail,
        &probe,
    )
    .commit()
    .expect("committed")
    .start_dice();
    let rolling = roll_all(rolling, &[3; 256]);
    assert_halted(
        rolling.push_roll(3),
        CoreError::TooManyRolls,
        &probe,
        "roll 257",
    );
}

/// A `Wiped` after a collision, from a real check on its own stub.
fn wiped_after_collision() -> Wiped {
    sealed(StubEntropy::Fixed(vec![0; 8]), &WipeProbe::new())
        .start_check()
        .expect("checking")
        .discard(Discard::Collision)
}

/// `finish` below the minimum: 49 for 12 words, 98 for 24, and 98 for either after a collision.
#[test]
fn finish_below_the_minimum() {
    let rolls99 = faces("coldcard-99");
    for (len, rolls) in [(SeedLength::Words12, 49), (SeedLength::Words24, 98)] {
        let probe = WipeProbe::new();
        let rolling = new(
            len,
            Mode::DiceOnly,
            Platform::Phone,
            StubEntropy::Fail,
            &probe,
        )
        .commit()
        .expect("committed")
        .start_dice();
        let rolling = roll_all(rolling, &rolls99[..rolls]);
        let what = format!("{len:?} at {rolls}");
        assert_halted(rolling.finish(), CoreError::TooFewRolls, &probe, &what);
    }
    for len in [SeedLength::Words12, SeedLength::Words24] {
        let probe = WipeProbe::new();
        let rolling = wiped_after_collision()
            .restart_with_stub(len, Mode::DiceOnly, stub(StubEntropy::Fail, &probe), None)
            .and_then(Session::commit)
            .expect("committed")
            .start_dice();
        assert_eq!(rolling.minimum_rolls(), 99);
        let rolling = roll_all(rolling, &rolls99[..98]);
        let what = format!("{len:?} at 98 after a collision");
        assert_halted(rolling.finish(), CoreError::TooFewRolls, &probe, &what);
    }
}

/// Shell-order bugs wipe: each of the five exports before every word has read back, and
/// `encrypt_backup` before `generate_backup_passphrase`.
#[test]
fn shell_order_bugs_halt_and_wipe() {
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
        let probe = WipeProbe::new();
        let ready = sealed(StubEntropy::Stream(b"os".to_vec()), &probe).skip_check();
        assert_halted(export(ready), CoreError::ReadbackIncomplete, &probe, name);
    }
    let probe = WipeProbe::new();
    let result = ready(StubEntropy::Stream(b"os".to_vec()), &probe).encrypt_backup(&BY);
    assert_halted(
        result,
        CoreError::NoBackupPassphrase,
        &probe,
        "encrypt first",
    );
}

/// Every known-answer group made to fail at `new` and at `restart`: exactly `Kat(id)`, and the new
/// session wiped once.
#[test]
fn every_kat_at_new_and_at_restart() {
    for id in KatId::ALL {
        let probe = WipeProbe::new();
        let result = Session::new_with_stub(
            SeedLength::Words24,
            Mode::Mixed,
            Platform::Pi,
            stub(StubEntropy::Fail, &probe),
            Some(id),
        );
        assert_halted(result, CoreError::Kat(id), &probe, &format!("new, {id:?}"));

        let probe = WipeProbe::new();
        let result = wiped_after_collision().restart_with_stub(
            SeedLength::Words12,
            Mode::DiceOnly,
            stub(StubEntropy::Fail, &probe),
            Some(id),
        );
        assert_halted(
            result,
            CoreError::Kat(id),
            &probe,
            &format!("restart, {id:?}"),
        );
    }
}

/// The free functions that run known-answer groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Entry {
    SelfTest,
    HwrngBootTest,
    SealFromMnemonic,
    VerifySnapshot,
    VerifyBucketProof,
    VerifyBucketProofQr,
    DecryptBackup,
}

const ENTRIES: [Entry; 7] = [
    Entry::SelfTest,
    Entry::HwrngBootTest,
    Entry::SealFromMnemonic,
    Entry::VerifySnapshot,
    Entry::VerifyBucketProof,
    Entry::VerifyBucketProofQr,
    Entry::DecryptBackup,
];

/// The one exhaustive match: which entry points run group `id` (kat.rs `groups`, read the other
/// way). A new `KatId` does not compile here until it is placed.
fn runs(id: KatId) -> &'static [Entry] {
    const REGISTRY: &[Entry] = &[
        Entry::SelfTest,
        Entry::VerifySnapshot,
        Entry::VerifyBucketProof,
        Entry::VerifyBucketProofQr,
    ];
    match id {
        KatId::Sha256
        | KatId::Sha512
        | KatId::Hmac
        | KatId::Bip39Wordlist
        | KatId::Bip39
        | KatId::Pool
        | KatId::Seed
        | KatId::Braille
        | KatId::Bip84
        | KatId::GoAhead => &[Entry::SelfTest],
        KatId::Health => &[Entry::SelfTest, Entry::HwrngBootTest],
        KatId::Seal => &[Entry::SelfTest, Entry::SealFromMnemonic],
        KatId::Ed25519 | KatId::Merkle => REGISTRY,
        KatId::Age => &[Entry::SelfTest, Entry::DecryptBackup],
    }
}

/// Every group through every fault twin: `Kat(id)` where the function runs that group, and the
/// unfaulted result (each function's own known answer) everywhere else. Every valid snapshot costs
/// a full 2^20-leaf root pass, so the snapshot twin reads kcr.json's `truncated-body`, which passes
/// the signature check and is then refused for its length (tests/kcr.rs verifies the valid ones).
#[test]
fn every_kat_through_each_free_function() {
    let kcr = read("kcr.json");
    let snapshot = hex(&named(&kcr["snapshots"], "truncated-body")["kcr_hex"]);
    let proof = hex(&named(&kcr["proofs"], "clear-shared-prefix")["kcp1_hex"]);
    let proof_qr = text(&named(&kcr["proofs"], "ur-lowercase")["ur"]).to_owned();
    let dice_50 = named(&kcr["seeds"], "dice-50-words12");
    let backup = read("backup.json");
    let file = named(&backup["age_files"], "abandon-12");
    let words: Vec<&str> = text(&file["passphrase"]).split(' ').collect();
    let typed = TypedBackupPassphrase::from_words(&words).expect("8 list words");
    let boot = clean_hwrng()[..1_024].to_vec();
    let ready = sealed(StubEntropy::Fail, &WipeProbe::new()).skip_check();

    for id in KatId::ALL {
        for entry in ENTRIES {
            let what = format!("{entry:?}, {id:?}");
            let result: Result<String, CoreError> = match entry {
                Entry::SelfTest => self_test_with_kat_fault(id).map(|()| "ok".into()),
                Entry::HwrngBootTest => {
                    hwrng_boot_test_with_kat_fault(&boot, id).map(|()| "ok".into())
                }
                Entry::SealFromMnemonic => seal_from_mnemonic_with_kat_fault(ready.mnemonic(), id)
                    .map(|seal| seal.tag().to_hex()),
                Entry::VerifySnapshot => verify_snapshot_with_kat_fault(&snapshot, id)
                    .map(|s| format!("snapshot {}", s.number())),
                Entry::VerifyBucketProof => verify_bucket_proof_with_kat_fault(&proof, id)
                    .map(|p| format!("proof {}", p.bucket())),
                Entry::VerifyBucketProofQr => verify_bucket_proof_qr_with_kat_fault(&proof_qr, id)
                    .map(|p| format!("proof {}", p.bucket())),
                Entry::DecryptBackup => {
                    decrypt_backup_with_kat_fault(text(&file["file"]).as_bytes(), &typed, id)
                        .map(|c| format!("{:02x?}", c.fingerprint()))
                }
            };
            if runs(id).contains(&entry) {
                assert_eq!(result, Err(CoreError::Kat(id)), "{what}");
                continue;
            }
            let unfaulted = match entry {
                Entry::SelfTest | Entry::HwrngBootTest => Ok("ok".to_owned()),
                Entry::SealFromMnemonic => Ok(text(&dice_50["seal_tag_hex"]).to_owned()),
                Entry::VerifySnapshot => Err(CoreError::Snapshot(SnapshotError::BadLength)),
                Entry::VerifyBucketProof | Entry::VerifyBucketProofQr => {
                    Ok("proof 178192".to_owned())
                }
                Entry::DecryptBackup => Ok("[73, c5, da, 0a]".to_owned()),
            };
            assert_eq!(result, unfaulted, "{what}");
        }
    }
    // The boot suite runs every group, and every other entry point runs at least one.
    for entry in ENTRIES {
        assert!(
            KatId::ALL.iter().any(|&id| runs(id).contains(&entry)),
            "{entry:?}"
        );
    }
    assert!(
        KatId::ALL
            .iter()
            .all(|&id| runs(id).contains(&Entry::SelfTest))
    );
}
