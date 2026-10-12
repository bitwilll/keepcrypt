//! `SimHal` against core (tasks/todo.md, M3 group 7): the hwrng streams the scenarios use get
//! core's recorded verdicts, the stick takes a real core backup and refuses what pi/app's `hal`
//! says it must, and capture mode writes one PNG file per present.
//!
//! The vectors come in through `include_str!` (the simulator reads no file). The backup is made
//! from a vector run (keepcrypt.json's `coldcard-50` rolls, dice only), so its words are public.

use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

use keepcrypt_core::{
    BackupApp, BackupFile, CoreError, CreatedBy, HW_BYTES_NEEDED, HealthFailure, HealthStage,
    HealthTest, Mode, Platform, Ready, SeedLength, Session, hwrng_boot_test,
};
use keepcrypt_pi::hal::{FileName, HalError, HwRng, Usb, Written};
use keepcrypt_pi::screen::{Banners, Element, Item, Screen, ScreenId};
use keepcrypt_pi::ui::Painter;
use keepcrypt_pi_sim::{
    Access, Fault, HwRngStream, Mount, Op, ProtectedFrames, SimHal, placeholder,
};
use serde_json::Value;

/// The boot test's samples: 16 blocks.
const BOOT_BYTES: usize = 1_024;

fn keepcrypt_json() -> Value {
    serde_json::from_str(include_str!("../../../vectors/keepcrypt.json")).expect("keepcrypt.json")
}

/// The entry named `name` in the list `section`.
fn named<'a>(section: &'a Value, name: &str) -> &'a Value {
    let found: Vec<&Value> = section
        .as_array()
        .expect("a list")
        .iter()
        .filter(|entry| entry["name"] == name)
        .collect();
    assert_eq!(found.len(), 1, "exactly one entry named {name}");
    found[0]
}

fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().expect("a hex string");
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// keepcrypt.json's health stream `name`: its samples and, for a failing one, core's verdict.
fn health(name: &str) -> (Vec<u8>, Option<HealthFailure>) {
    let doc = keepcrypt_json();
    let case = named(&doc["health"], name);
    let expect = &case["expect"];
    let verdict = match expect["result"].as_str() {
        Some("pass") => None,
        Some("fail") => Some(HealthFailure {
            test: match expect["test"].as_str() {
                Some("repetition_count") => HealthTest::RepetitionCount,
                Some("adaptive_proportion") => HealthTest::AdaptiveProportion,
                other => panic!("{name}: test {other:?}"),
            },
            stage: match expect["stage"].as_str() {
                Some("startup") => HealthStage::Startup,
                Some("continuous") => HealthStage::Continuous,
                other => panic!("{name}: stage {other:?}"),
            },
            sample: expect["sample"].as_u64().expect("a sample index"),
        }),
        other => panic!("{name}: result {other:?}"),
    };
    (hex(&case["samples_hex"]), verdict)
}

/// `blocks` reads of the simulated hwrng, concatenated.
fn read_blocks(hal: &mut SimHal, blocks: usize) -> Vec<u8> {
    let mut served = Vec::with_capacity(64 * blocks);
    for _ in 0..blocks {
        let mut block = [0u8; 64];
        hal.read_block(&mut block)
            .expect("the stream holds the block");
        served.extend_from_slice(&block);
    }
    served
}

fn ran_out(hal: &mut SimHal) -> bool {
    hal.read_block(&mut [0u8; 64]) == Err(HalError::HwRng)
}

#[test]
fn the_counting_stream_is_counting_1536_and_passes_boot_and_a_session() {
    let (counting, verdict) = health("counting-1536");
    assert_eq!(verdict, None);
    assert_eq!(counting.len(), 1_536);
    let mut hal = SimHal::new(HwRngStream::Counting);
    let boot = read_blocks(&mut hal, BOOT_BYTES / 64);
    assert_eq!(boot, counting[..BOOT_BYTES]);
    assert_eq!(hwrng_boot_test(&boot), Ok(()));
    // 1,024 is a multiple of 256, so the session's 1,536 bytes are counting-1536 again.
    let mut session =
        Session::new(SeedLength::Words12, Mode::Mixed, Platform::Pi).expect("a session");
    let served = read_blocks(&mut hal, 24);
    assert_eq!(served, counting);
    for block in served.chunks(64) {
        session = session.add_hw_samples(block).expect("healthy");
    }
    assert_eq!(session.hw_bytes_tested(), HW_BYTES_NEEDED);
    assert!(session.credited_bits() >= session.required_bits());
    assert!(!ran_out(&mut hal), "the counting stream has no end");
}

#[test]
fn the_boot_stop_streams_are_their_vectors_and_get_cores_startup_verdicts() {
    for name in ["run-of-6-startup", "apt-62-startup"] {
        let (samples, verdict) = health(name);
        assert_eq!(samples.len(), 2_048, "{name}");
        let mut hal = SimHal::new(HwRngStream::Bytes(samples.clone()));
        let served = read_blocks(&mut hal, 32);
        assert_eq!(served, samples, "{name}: every byte, in order");
        assert!(ran_out(&mut hal), "{name}: past the end is a read fault");
        let expected = verdict.expect("a failing stream");
        assert_eq!(expected.stage, HealthStage::Startup);
        assert_eq!(
            hwrng_boot_test(&served[..BOOT_BYTES]),
            Err(CoreError::Health(expected)),
            "{name}"
        );
    }
}

#[test]
fn the_runtime_stop_stream_gets_cores_continuous_verdict_in_a_session() {
    // Concatenated by read phase: a passing boot (the counting stream's first 1,024 bytes), then
    // the session's 1,536 bytes of run-of-6-continuous.
    let (counting, _) = health("counting-1536");
    let (continuous, verdict) = health("run-of-6-continuous");
    let mut stream = counting[..BOOT_BYTES].to_vec();
    stream.extend_from_slice(&continuous[..1_536]);
    let mut hal = SimHal::new(HwRngStream::Bytes(stream));
    assert_eq!(
        hwrng_boot_test(&read_blocks(&mut hal, BOOT_BYTES / 64)),
        Ok(())
    );
    let mut session =
        Session::new(SeedLength::Words12, Mode::Mixed, Platform::Pi).expect("a session");
    let mut served = Vec::new();
    let error = loop {
        let mut block = [0u8; 64];
        hal.read_block(&mut block)
            .expect("the stream holds the block");
        served.extend_from_slice(&block);
        match session.add_hw_samples(&block) {
            Ok(next) => session = next,
            Err(error) => break error,
        }
    };
    let expected = verdict.expect("a failing stream");
    assert_eq!(expected.stage, HealthStage::Continuous);
    assert_eq!(error, CoreError::Health(expected));
    // Sample 1505 is in the 24th block, the session's last: every byte was the vector's.
    assert_eq!(served, continuous[..1_536]);
    assert!(ran_out(&mut hal));
}

/// A `Ready` session of a vector run (dice only, 12 words, `coldcard-50`) with every insert read
/// back, and its backup.
fn backup() -> (Session<Ready>, BackupFile) {
    let doc = keepcrypt_json();
    let rolls = named(&doc["dice_only"], "coldcard-50")["rolls"]
        .as_str()
        .expect("a roll string");
    let session =
        Session::new(SeedLength::Words12, Mode::DiceOnly, Platform::Pi).expect("a session");
    let mut rolling = session.commit().expect("committed").start_dice();
    for face in rolls.bytes() {
        rolling = rolling.push_roll(face - b'0').expect("a face");
    }
    let mut ready = rolling.finish().expect("sealed").skip_check();
    let first_fours: Vec<String> = ready
        .mnemonic()
        .words()
        .map(|word| word.chars().take(4).collect())
        .collect();
    for (position, letters) in (1u8..).zip(&first_fours) {
        assert!(ready.check_readback(position, letters).is_ok());
    }
    assert!(ready.readback_complete());
    let ready = ready.generate_backup_passphrase().expect("generated").0;
    ready
        .encrypt_backup(&CreatedBy::new(BackupApp::Pi, 0, 0, 0))
        .expect("encrypted")
}

#[test]
fn the_stick_takes_a_new_backup_and_refuses_what_hal_usb_refuses() {
    let (ready, backup) = backup();
    let name = backup.name().to_owned();
    let mut hal = SimHal::new(HwRngStream::Counting);
    assert_eq!(hal.stick(), Ok(false));
    assert_eq!(hal.write_backup(&backup), Err(HalError::NoStick));
    hal.insert_stick();
    assert_eq!(hal.stick(), Ok(true));

    // A write fault, a sync fault and a read-only stick leave no file.
    for (fault, error) in [
        (Fault::Write, HalError::Write),
        (Fault::Sync, HalError::Sync),
    ] {
        hal.fault(fault);
        assert_eq!(hal.write_backup(&backup), Err(error));
        assert!(hal.stick_files().is_empty(), "{fault:?}");
    }
    hal.set_mount(Mount::ReadOnly);
    assert_eq!(hal.write_backup(&backup), Err(HalError::ReadOnly));
    assert!(hal.stick_files().is_empty());
    hal.set_mount(Mount::ReadWrite);

    // Written as a new file, read back under a read-only remount, and core verifies it.
    let written = hal.write_backup(&backup).expect("written");
    assert_eq!(hal.stick_files(), [name.as_str()]);
    let back = hal.read_written(&written, 8 * 1024).expect("read back");
    assert_eq!(ready.verify_backup(&back), Ok(()));
    // A corrupt read-back fails core's verification; the file itself is unchanged.
    hal.fault(Fault::ReadBackCorrupt);
    let corrupt = hal.read_written(&written, 8 * 1024).expect("read back");
    assert!(ready.verify_backup(&corrupt).is_err());
    assert_eq!(hal.stick_file(&name), Some(backup.bytes()));

    // Only the file just written can be read back or removed.
    hal.put_file("other.age", b"not ours".to_vec());
    let other = || Written::new(FileName::new("other.age").expect("a name"));
    assert_eq!(hal.read_written(&other(), 64), Err(HalError::NotWritten));
    assert_eq!(hal.remove_written(other()), Err(HalError::NotWritten));
    assert_eq!(hal.remove_written(written), Ok(()));
    assert_eq!(hal.stick_files(), ["other.age"]);

    // Never over an existing name, and after that refused attempt the earlier file is no longer
    // the file just written (hal::Usb).
    let again = hal.write_backup(&backup).expect("written again");
    assert_eq!(hal.write_backup(&backup), Err(HalError::Exists));
    assert_eq!(
        hal.read_written(&again, 8 * 1024),
        Err(HalError::NotWritten)
    );
    assert_eq!(hal.remove_written(again), Err(HalError::NotWritten));
    assert_eq!(hal.stick_file(&name), Some(backup.bytes()));

    // The log (rule 8): the writes and the removal under read-write mounts, and the refused write
    // on the read-only stick. Reads are logged read-only by the simulator's construction (the app
    // cannot choose a mount), so that part pins the simulator, not the device's mounts (M4).
    let log = hal.stick_log();
    assert!(log.iter().all(|access| match &access.op {
        Op::List(_) | Op::Read(_) | Op::ReadWritten(_) => access.mount == Mount::ReadOnly,
        Op::Write(_) | Op::RemoveWritten(_) => true,
    }));
    assert_eq!(
        log[..3],
        [
            Access {
                mount: Mount::ReadWrite,
                op: Op::Write(name.clone())
            },
            Access {
                mount: Mount::ReadWrite,
                op: Op::Write(name.clone())
            },
            Access {
                mount: Mount::ReadOnly,
                op: Op::Write(name.clone())
            },
        ]
    );

    // A stick pulled out mid-call stays out.
    hal.fault(Fault::Removed);
    assert_eq!(hal.write_backup(&backup), Err(HalError::Removed));
    assert_eq!(hal.stick(), Ok(false));
    assert_eq!(hal.stick_files(), [name.as_str(), "other.age"]);
}

#[test]
fn capture_mode_writes_one_png_per_present_and_protected_frames_as_placeholders() {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("pi-sim-hal-capture");
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => panic!("cannot clear {}: {error}", root.display()),
    }
    let banners = Banners {
        test_registry: false,
        simulator: true,
    };
    for (protected, folder) in [
        (ProtectedFrames::Placeholder, "throwaway"),
        (ProtectedFrames::AsDrawn, "vector"),
    ] {
        let dir = root.join(folder);
        let mut hal = SimHal::new(HwRngStream::Counting);
        hal.capture(dir.clone(), protected);
        let about = Screen::new(ScreenId::About, "About", banners).with(Element::public(
            (0, 0).into(),
            Item::Text("KeepCrypt".into()),
        ));
        let insert =
            Screen::new(ScreenId::WordsInsert, "Insert 01", banners).with(Element::protected(
                (40, 0).into(),
                Item::Large {
                    text: "abandon".into(),
                    lighter_from: Some(4),
                },
            ));
        let mut painter = Painter::new();
        painter.present(&mut hal, &about).expect("draws");
        painter.present(&mut hal, &insert).expect("draws");
        let presents = hal.take_presents();
        let [about_shown, insert_shown] = &presents[..] else {
            panic!("{folder}: two presents");
        };
        let (Some(about_file), Some(insert_file)) = (&about_shown.capture, &insert_shown.capture)
        else {
            panic!("{folder}: both presents captured");
        };
        assert_eq!(about_file.file, "001-about.png");
        assert_eq!(insert_file.file, "002-words-insert.png");
        // The bytes each file got (the simulator reads no file back, so `Captured` keeps what it
        // handed to the write). A Public frame is written as drawn; the Protected one is the
        // placeholder in a throwaway run and as drawn in a vector run, never the other.
        assert!(!about_file.placeholder);
        assert!(
            about_file.png[..] == about_shown.frame.png()[..],
            "{folder}: about as drawn"
        );
        let drawn = insert_shown.frame.png();
        let grey = placeholder(ScreenId::WordsInsert).png();
        assert!(
            drawn[..] != grey[..],
            "the drawn insert is not the placeholder"
        );
        match protected {
            ProtectedFrames::Placeholder => {
                assert!(insert_file.placeholder);
                assert!(
                    insert_file.png[..] == grey[..],
                    "throwaway: the placeholder"
                );
            }
            ProtectedFrames::AsDrawn => {
                assert!(!insert_file.placeholder);
                assert!(
                    insert_file.png[..] == drawn[..],
                    "vector: the insert as drawn"
                );
            }
        }
        // Every frame and placeholder is a 240 × 240 stored PNG of the same length, and each file
        // holds that many bytes.
        for captured in [about_file, insert_file] {
            assert_eq!(captured.png.len(), 173_118, "{folder}/{}", captured.file);
            let len = fs::metadata(dir.join(&captured.file))
                .expect("written")
                .len();
            assert_eq!(len, 173_118, "{folder}/{}", captured.file);
        }
    }
}
