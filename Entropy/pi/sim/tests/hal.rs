//! `SimHal` against core (tasks/todo.md, M3 group 7): the hwrng streams the scenarios use get
//! core's recorded verdicts, the stick takes a real core backup and refuses what pi/app's `hal`
//! says it must, capture mode writes one PNG file per present, and live mode (group 12) rewrites
//! one, with the build's strip on the bin's screens (group 16).
//!
//! The vectors come in through `include_str!` (the simulator reads no file). The backup is made
//! from a vector run (keepcrypt.json's `coldcard-50` rolls, dice only), so its words are public.

use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

use keepcrypt_core::{
    BackupApp, BackupFile, CoreError, CreatedBy, HW_BYTES_NEEDED, HealthFailure, HealthStage,
    HealthTest, Mode, Platform, Ready, SeedLength, Session, hwrng_boot_test, registry_key_is_test,
};
use keepcrypt_pi::App;
use keepcrypt_pi::hal::{FileName, HalError, HwRng, Usb, Written};
use keepcrypt_pi::input::Key;
use keepcrypt_pi::screen::{Banners, Element, Item, Screen, ScreenId};
use keepcrypt_pi::ui::Painter;
use keepcrypt_pi_sim::{
    Access, Fault, HwRngStream, Mount, Op, Pixels, ProtectedFrames, SimHal, placeholder,
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

/// The folder `name` under cargo's test tmpdir, removed with what it held.
fn cleared(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    match fs::remove_dir_all(&dir) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => panic!("cannot clear {}: {error}", dir.display()),
    }
    dir
}

#[test]
fn capture_mode_writes_one_png_per_present_and_protected_frames_as_placeholders() {
    let root = cleared("pi-sim-hal-capture");
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
        hal.capture(dir.clone(), protected, 0);
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

#[test]
fn live_mode_rewrites_one_png_per_present_and_every_protected_frame_as_the_placeholder() {
    let dir = cleared("pi-sim-hal-live");
    let banners = Banners {
        test_registry: false,
        simulator: true,
    };
    // Live mode takes no `ProtectedFrames`: its Protected frames are placeholders in every run,
    // so an insert showing a public vector word is one too.
    let mut hal = SimHal::new(HwRngStream::Counting);
    hal.live(dir.clone());
    let about = Screen::new(ScreenId::About, "About", banners).with(Element::public(
        (0, 0).into(),
        Item::Text("KeepCrypt".into()),
    ));
    let insert = Screen::new(ScreenId::WordsInsert, "Insert 01", banners).with(Element::protected(
        (40, 0).into(),
        Item::Large {
            text: "abandon".into(),
            lighter_from: Some(4),
        },
    ));
    let mut painter = Painter::new();
    for screen in [&about, &insert, &about] {
        painter.present(&mut hal, screen).expect("draws");
    }
    let presents = hal.take_presents();
    let [about_shown, insert_shown, again_shown] = &presents[..] else {
        panic!("three presents");
    };
    let (Some(about_file), Some(insert_file), Some(again_file)) = (
        &about_shown.capture,
        &insert_shown.capture,
        &again_shown.capture,
    ) else {
        panic!("every present captured");
    };
    for captured in [about_file, insert_file, again_file] {
        assert_eq!(captured.file, "live.png");
        assert_eq!(captured.png.len(), 173_118);
    }
    // The bytes each write got (the simulator reads no file back): Public frames as drawn, the
    // Protected one the placeholder and not the frame.
    for (file, shown) in [(about_file, about_shown), (again_file, again_shown)] {
        assert!(!file.placeholder);
        assert!(file.png[..] == shown.frame.png()[..], "about as drawn");
    }
    let grey = placeholder(ScreenId::WordsInsert).png();
    assert!(insert_file.placeholder);
    assert!(
        insert_file.png[..] == grey[..],
        "the insert is the placeholder"
    );
    assert!(
        insert_shown.frame.png()[..] != grey[..],
        "the drawn insert is not the placeholder"
    );
    // One file, rewritten: the folder holds `live.png` alone.
    let names: Vec<String> = fs::read_dir(&dir)
        .expect("the live folder")
        .map(|entry| {
            let entry = entry.expect("an entry");
            entry.file_name().into_string().expect("a UTF-8 name")
        })
        .collect();
    assert_eq!(names, ["live.png"]);
    let len = fs::metadata(dir.join("live.png")).expect("written").len();
    assert_eq!(len, 173_118);
}

/// The strip's labels with the test key ("SIMULATOR" beside "TEST REGISTRY", Q33 (j)), without it
/// ("SIMULATOR · NOT FOR REAL FUNDS" alone, Q30 (h)), and the short label alone, which no build
/// shows.
const PAIR: &[&str] = &["TEST REGISTRY", "SIMULATOR"];
const ALONE: &[&str] = &["SIMULATOR · NOT FOR REAL FUNDS"];
const SHORT: &[&str] = &["SIMULATOR"];

/// `label` drawn as a screen's only content: the step title, in pi/app's accent colour on black,
/// from the strip's left edge.
fn title(label: &str) -> Pixels {
    let none = Banners {
        test_registry: false,
        simulator: false,
    };
    let model = Key::ALL
        .into_iter()
        .fold(Screen::new(ScreenId::About, label, none), Screen::without);
    let mut hal = SimHal::new(HwRngStream::Counting);
    Painter::new().present(&mut hal, &model).expect("draws");
    hal.take_presents().remove(0).frame
}

/// True when the top strip of `frame` shows `labels` and nothing else: each centred in an equal
/// share of the 240 × 12 strip, in black on a bar of one other colour, glyph for glyph as pi/app
/// draws the label as a title (another path through its renderer, so this reads the strip
/// without the banner code). The font is 6 px a character; row 0 is above the text.
fn strip_shows(frame: &Pixels, labels: &[&str]) -> bool {
    let share = 240 / labels.len();
    labels.iter().enumerate().all(|(i, label)| {
        let glyphs = title(label);
        let width = 6 * label.chars().count();
        let left = i * share;
        let start = left + share.checked_sub(width).expect("the label fits its share") / 2;
        let bar = frame.at(left, 0).expect("on the panel");
        bar != 0
            && (0..12).all(|y| {
                (left..left + share).all(|x| {
                    let ink =
                        (start..start + width).contains(&x) && glyphs.at(x - start, y) != Some(0);
                    frame.at(x, y) == Some(if ink { 0 } else { bar })
                })
            })
    })
}

#[test]
fn live_mode_shows_the_builds_strip_and_writes_it_to_live_png() {
    // The bin's hardware (src/main.rs, `hardware`) under the bin's `App`: the counting hwrng,
    // live mode, an empty stick in the slot. Its start presents boot and Home, both Public, both
    // written to `live.png` as drawn.
    let dir = cleared("pi-sim-hal-live-strip");
    let mut hal = SimHal::new(HwRngStream::Counting);
    hal.live(dir);
    hal.insert_stick();
    let mut app = App::new(hal);
    app.start();
    let presents = app.hal_mut().take_presents();
    let shown: Vec<&str> = presents.iter().map(|p| p.id.name()).collect();
    assert_eq!(shown, ["boot", "home"]);
    // The release configuration, which live mode runs as CLAUDE.md's Commands give it, shows the
    // long label; the test registry key, the pair.
    let (labels, others) = if registry_key_is_test() {
        (PAIR, [ALONE, SHORT])
    } else {
        (ALONE, [PAIR, SHORT])
    };
    for present in &presents {
        let id = present.id.name();
        assert!(strip_shows(&present.frame, labels), "{id}: {labels:?}");
        for other in others {
            assert!(!strip_shows(&present.frame, other), "{id}: not {other:?}");
        }
        let captured = present.capture.as_ref().expect("written");
        assert_eq!(captured.file, "live.png");
        assert!(!captured.placeholder);
        assert!(captured.png[..] == present.frame.png()[..], "{id} as drawn");
    }
}
