//! Source substitution (docs/design.md "Prove the path" 1; docs/build-plan.md test matrix
//! "Source-substitution"; tasks/todo.md, M1 group 10 and Verification): every source reaches the
//! pool, the failure the Coldcard bug was. A fixed stub OS read, keepcrypt.json's counter-mode hwrng
//! stream in 64-byte chunks and its extras give keepcrypt.json's D and C, on the Pi and on a phone.
//! One changed byte of any source, a changed source id or a dropped extra changes D; a changed but
//! still healthy startup byte does not, since startup samples are tested and then discarded.
//! Exactly 64 OS bytes are read. In dice-only mode E = SHA-256(R) whatever the stubs, and a stub
//! with no bytes still reaches `Ready` through Skip.
//!
//! D is read through `reveal_device_leg`, after a ceremony reads every word back; C stands in for
//! D where only a difference matters, since C = SHA-256("KCE/v1/commit" || D).

mod common;

use common::{hex, named, read, text};
use keepcrypt_core::{
    Committed, CoreError, ExtraSource, Mode, Platform, ReadbackResult, Ready, Rolling, SeedLength,
    Session, SourceFault, StubEntropy, StubSource, WipeProbe,
};
use serde_json::Value;

/// One call a shell makes before `commit`.
#[derive(Clone)]
enum Event {
    Hwrng(Vec<u8>),
    Extra(ExtraSource, Vec<u8>),
}

/// A keepcrypt.json source-substitution case.
#[derive(Clone)]
struct Case {
    platform: Platform,
    os: Vec<u8>,
    events: Vec<Event>,
}

const EXTRAS: [ExtraSource; 4] = [
    ExtraSource::InputTiming,
    ExtraSource::Motion,
    ExtraSource::Camera,
    ExtraSource::Microphone,
];

fn extra_source(name: &Value) -> ExtraSource {
    match text(name) {
        "input_timing" => ExtraSource::InputTiming,
        "motion" => ExtraSource::Motion,
        "camera" => ExtraSource::Camera,
        "microphone" => ExtraSource::Microphone,
        other => panic!("no extra source {other}"),
    }
}

fn case(name: &str) -> (Case, Value) {
    let doc = read("keepcrypt.json");
    let v = named(&doc["source_substitution"], name).clone();
    let platform = match text(&v["platform"]) {
        "pi" => Platform::Pi,
        _ => Platform::Phone,
    };
    let events = v["events"]
        .as_array()
        .expect("events")
        .iter()
        .map(|e| match text(&e["kind"]) {
            "hwrng" => Event::Hwrng(hex(&e["data_hex"])),
            _ => Event::Extra(extra_source(&e["source"]), hex(&e["data_hex"])),
        })
        .collect();
    (
        Case {
            platform,
            os: hex(&v["os_hex"]),
            events,
        },
        v,
    )
}

/// The case's calls on a 12-word Mixed session whose stub serves exactly the case's OS bytes, up to
/// `commit`.
fn committed(case: &Case, probe: &WipeProbe) -> Session<Committed> {
    let stub = StubSource::new(StubEntropy::Fixed(case.os.clone()), probe);
    let mut session =
        Session::new_with_stub(SeedLength::Words12, Mode::Mixed, case.platform, stub, None)
            .expect("a session");
    for event in &case.events {
        session = match event {
            Event::Hwrng(data) => session.add_hw_samples(data).expect("healthy"),
            Event::Extra(source, data) => {
                session.add_extra(*source, data);
                session
            }
        };
    }
    session.commit().expect("committed")
}

fn commitment(case: &Case) -> [u8; 32] {
    committed(case, &WipeProbe::new())
        .commitment()
        .expect("C in Mixed mode")
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

/// Reads every insert back from its own faces: its first four letters (three for a three-letter
/// word, whose fourth face is blank).
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
    assert!(ready.readback_complete());
}

/// D, revealed after a full ceremony: 50 rolls, Skip, every word read back.
fn device_leg(committed: Session<Committed>) -> [u8; 32] {
    let mut ready = roll_all(committed.start_dice(), &faces("coldcard-50"))
        .finish()
        .expect("sealed")
        .skip_check();
    read_back_every_word(&mut ready);
    let (_, d) = ready.reveal_device_leg().expect("revealed");
    *d.expect("D in Mixed mode").expose_secret()
}

/// The vectors' D and C on both platforms, with the Pi's tested and credited counts.
#[test]
fn a_fixed_stub_gives_the_vectors_d_and_c() {
    for name in ["pi", "phone"] {
        let (case, v) = case(name);
        let probe = WipeProbe::new();
        let committed = committed(&case, &probe);
        assert_eq!(
            committed.commitment().map(|c| c.to_vec()),
            Some(hex(&v["c_hex"])),
            "{name}"
        );
        assert_eq!(device_leg(committed).to_vec(), hex(&v["d_hex"]), "{name}");
        assert_eq!(probe.wipes(), 1, "{name}");
    }
    let (case, v) = case("pi");
    let stub = StubSource::new(StubEntropy::Fixed(case.os.clone()), &WipeProbe::new());
    let mut session =
        Session::new_with_stub(SeedLength::Words12, Mode::Mixed, Platform::Pi, stub, None)
            .expect("a session");
    for event in &case.events {
        session = match event {
            Event::Hwrng(data) => session.add_hw_samples(data).expect("healthy"),
            Event::Extra(source, data) => {
                session.add_extra(*source, data);
                session
            }
        };
    }
    assert_eq!(session.hw_bytes_tested(), v["hw_bytes_tested"]);
    let credited = v["credited_samples"].as_u64().expect("credited") * 4;
    assert_eq!(session.credited_bits(), credited);
}

/// Commit reads exactly 64 OS bytes: 63 are not enough, and after 64 the stub is used up, so the
/// next draw (the check nonce) fails.
#[test]
fn exactly_64_os_bytes_are_read() {
    let (case, v) = case("phone");
    let mut short = case.clone();
    short.os.truncate(63);
    let probe = WipeProbe::new();
    let stub = StubSource::new(StubEntropy::Fixed(short.os.clone()), &probe);
    let result = Session::new_with_stub(
        SeedLength::Words12,
        Mode::Mixed,
        Platform::Phone,
        stub,
        None,
    )
    .and_then(Session::commit)
    .map(|_| ());
    assert_eq!(result, Err(CoreError::Source(SourceFault::Os)));
    assert_eq!(probe.wipes(), 1);

    let probe = WipeProbe::new();
    let committed = committed(&case, &probe);
    assert_eq!(
        committed.commitment().map(|c| c.to_vec()),
        Some(hex(&v["c_hex"]))
    );
    let sealed = roll_all(committed.start_dice(), &faces("coldcard-50"))
        .finish()
        .expect("sealed");
    assert_eq!(
        sealed.start_check().map(|_| ()),
        Err(CoreError::Source(SourceFault::Os)),
        "nothing beyond the 64 bytes was there to read"
    );
    assert_eq!(probe.wipes(), 1);
}

/// One byte of the case changed, at `at` in event `index` (the OS read for `None`).
fn with_byte_changed(case: &Case, index: Option<usize>, at: usize) -> Case {
    let mut changed = case.clone();
    let data = match index {
        None => &mut changed.os,
        Some(i) => match &mut changed.events[i] {
            Event::Hwrng(data) | Event::Extra(_, data) => data,
        },
    };
    data[at] ^= 0x01;
    changed
}

/// A changed byte in any post-startup hwrng chunk, any extra or the OS read changes D; a changed
/// byte among the 1,024 startup samples, still healthy, does not.
#[test]
fn one_changed_byte_of_any_source_changes_d() {
    for name in ["pi", "phone"] {
        let (case, _) = case(name);
        let base = commitment(&case);
        assert_ne!(
            commitment(&with_byte_changed(&case, None, 63)),
            base,
            "{name}: OS"
        );
        let mut hwrng_bytes = 0usize;
        for (index, event) in case.events.iter().enumerate() {
            match event {
                Event::Extra(..) => {
                    let changed = with_byte_changed(&case, Some(index), 0);
                    assert_ne!(commitment(&changed), base, "{name}: extra {index}");
                }
                Event::Hwrng(data) => {
                    let startup = hwrng_bytes + data.len() <= 1_024;
                    hwrng_bytes += data.len();
                    for at in [0, data.len() - 1] {
                        let changed = commitment(&with_byte_changed(&case, Some(index), at));
                        if startup {
                            assert_eq!(changed, base, "{name}: startup chunk {index}, byte {at}");
                        } else {
                            assert_ne!(changed, base, "{name}: chunk {index}, byte {at}");
                        }
                    }
                }
            }
        }
        if case.platform == Platform::Pi {
            assert_eq!(hwrng_bytes, 1_600, "16 startup chunks, 9 credited");
        }
    }
}

/// An extra under another source id, or left out, changes D.
#[test]
fn a_changed_source_id_or_a_dropped_extra_changes_d() {
    for name in ["pi", "phone"] {
        let (case, _) = case(name);
        let base = commitment(&case);
        for (index, event) in case.events.iter().enumerate() {
            let Event::Extra(source, data) = event else {
                continue;
            };
            for other in EXTRAS.into_iter().filter(|other| other != source) {
                let mut renamed = case.clone();
                renamed.events[index] = Event::Extra(other, data.clone());
                assert_ne!(
                    commitment(&renamed),
                    base,
                    "{name}: extra {index} as {other:?}"
                );
            }
            let mut dropped = case.clone();
            dropped.events.remove(index);
            assert_ne!(commitment(&dropped), base, "{name}: extra {index} dropped");
        }
    }
}

/// Dice only: E = SHA-256(R) whatever the stub holds, even one that has no bytes or always fails,
/// since dice-only mode reads nothing before a check; Skip reaches the words.
#[test]
fn dice_only_e_is_sha256_of_r_whatever_the_stubs() {
    let doc = read("keepcrypt.json");
    for (len, rolls, key) in [
        (SeedLength::Words12, "coldcard-50", "words_12"),
        (SeedLength::Words24, "coldcard-99", "words_24"),
    ] {
        let want: Vec<&str> = named(&doc["dice_only"], rolls)[key]
            .as_array()
            .expect("words")
            .iter()
            .map(text)
            .collect();
        for entropy in [
            StubEntropy::Fixed(Vec::new()),
            StubEntropy::Stream(b"other".to_vec()),
            StubEntropy::Fail,
        ] {
            let probe = WipeProbe::new();
            let stub = StubSource::new(entropy, &probe);
            let mut session = Session::new_with_stub(len, Mode::DiceOnly, Platform::Pi, stub, None)
                .expect("a session");
            session.add_extra(ExtraSource::Camera, b"not mixed in dice-only mode");
            let committed = session.commit().expect("committed");
            assert_eq!(committed.commitment(), None);
            let mut ready = roll_all(committed.start_dice(), &faces(rolls))
                .finish()
                .expect("sealed")
                .skip_check();
            let words: Vec<&str> = ready.mnemonic().words().collect();
            assert_eq!(words, want, "{len:?}");
            read_back_every_word(&mut ready);
            let (_, d) = ready.reveal_device_leg().expect("revealed");
            assert!(d.is_none(), "no D in dice-only mode");
            assert_eq!(probe.wipes(), 1);
        }
    }
}
