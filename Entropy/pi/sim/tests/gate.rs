//! The gate scenarios (tasks/todo.md, M3 group 11; build-plan.md M3 gate): scripted runs of the
//! real app on `SimHal`, in the release configuration (`cargo test --workspace`) and the registry
//! configuration (`cargo test -p keepcrypt-pi-sim --features keepcrypt-core/test-registry`).
//!
//! Steps 1-15 and Home's side flows: boot and its stops, Home and About, length and mode, step 4's
//! hwrng intake, Snake and the stop, the commitment, the dice, the collision check (snapshot, seal
//! card, go-ahead code, Match found, Cannot check, Skip), the words in insert view and overview,
//! the read-back drill, the wallet summary, the backup to a stick, the watch-only export, the
//! registration, D and the verify.py tie, the checklist and power-off; "Load registry snapshot"
//! and "Check a backup"; and the halts, restarts and idle steps on the way.
//!
//! Beside the scenarios: `every_screen_is_expected` (the scenarios expect every screen),
//! `drill_12_repeats` (a vector run draws the same frames twice, but for the nonce), the ignored
//! `capture_set` (every scenario's presents as PNG files, with an index, Q30 (g), and the owner's
//! review page of some of them, each QR code beside core's string), and the review page's tests:
//! its rule on made-up rows, and two short runs, a throwaway one and a vector one, each captured
//! as `capture_set` does into a folder under target/tmp that it clears again when the run ends.
//!
//! Test data is public and repeatable (Q30 (a), (c)): the counting hwrng stream, keepcrypt.json's
//! health streams for the stops, and its public dice strings for the vector runs. The vectors come
//! in through `include_str!`; the simulator reads no file, and the tests read back only the PNG
//! files `capture_set` wrote, to copy them into review/. The verify.py tie runs the shipped
//! verifier on a throwaway run's values, in memory.

mod report;
mod scenario;

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::rc::Rc;

use keepcrypt_core::{
    BackupError, Bip39Passphrase, CoreError, HealthFailure, HealthStage, HealthTest, Mode,
    Platform, ReadbackResult, SeedLength, Session, TypedBackupPassphrase, decrypt_backup,
    registry_key_is_test,
};
use keepcrypt_pi::hal::{HalError, Zeroizing};
use keepcrypt_pi::input::Key;
use keepcrypt_pi::screen::{Banners, Class, Element, Item, Screen, ScreenId};
use keepcrypt_pi::ui::{Painter, hex_groups};
use keepcrypt_pi_sim::{Fault, HwRngStream, Op, Present, ProtectedFrames, Shown, SimHal};
use report::report;
use scenario::{
    Answer, Code, Config, Keep, Readback, Scenario, Shot, Step, Stick, qr_payload, run, run_keeping,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use Step::{Assert, Dice, Expect, PowerCycle, Type, Wait};

/// The boot test's samples.
const BOOT_BYTES: usize = 1_024;
/// One Mixed session's step 4 (core's `HW_BYTES_NEEDED`).
const SESSION_BYTES: usize = 1_536;
/// Long enough for step 4's 24 blocks, one per 100 ms tick.
const QUOTA_SECONDS: u64 = 3;
/// Long enough for usb-insert to look for the stick once more (every 100 ms).
const STICK_SECONDS: u64 = 1;
/// The registry origin of the QR URLs until M9.
const ORIGIN: &str = "https://registry.invalid";
/// The BIP39 passphrase `dice_24_code` types: letters of both cases, a digit and a sign, on all
/// three pages of the ASCII grid.
const BIP39_PASSPHRASE: &str = "Tr3zor!";

fn keepcrypt_json() -> Value {
    serde_json::from_str(include_str!("../../../vectors/keepcrypt.json")).expect("keepcrypt.json")
}

fn kcr_json() -> Value {
    serde_json::from_str(include_str!("../../../vectors/kcr.json")).expect("kcr.json")
}

fn backup_json() -> Value {
    serde_json::from_str(include_str!("../../../vectors/backup.json")).expect("backup.json")
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

/// keepcrypt.json's failing health stream `name`: its samples and core's recorded verdict.
fn health(name: &str) -> (Vec<u8>, HealthFailure) {
    let doc = keepcrypt_json();
    let case = named(&doc["health"], name);
    let expect = &case["expect"];
    assert_eq!(expect["result"], "fail", "{name}");
    let verdict = HealthFailure {
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
    };
    (hex(&case["samples_hex"]), verdict)
}

/// keepcrypt.json's public dice-only roll string `name`.
fn rolls(name: &str) -> String {
    let doc = keepcrypt_json();
    named(&doc["dice_only"], name)["rolls"]
        .as_str()
        .expect("a roll string")
        .to_owned()
}

/// kcr.json's field `field` of the vector seed `name`.
fn seed(name: &str, field: &str) -> String {
    let doc = kcr_json();
    named(&doc["seeds"], name)[field]
        .as_str()
        .expect("a text field")
        .to_owned()
}

/// kcr.json's Seal ID of the vector seed `name`.
fn seal_id(name: &str) -> String {
    seed(name, "seal_id")
}

/// kcr.json's snapshot `name`, as bytes.
fn snapshot(name: &str) -> Vec<u8> {
    hex(&named(&kcr_json()["snapshots"], name)["kcr_hex"])
}

/// backup.json's age file `name` and the passphrase that opens it.
fn age_file(name: &str) -> (Vec<u8>, String) {
    let doc = backup_json();
    let file = named(&doc["age_files"], name);
    let text = file["file"].as_str().expect("an armored file");
    let passphrase = file["passphrase"].as_str().expect("a passphrase");
    (text.as_bytes().to_vec(), passphrase.to_owned())
}

/// backup.json's fingerprint of the plaintext `name`.
fn plaintext_fingerprint(name: &str) -> String {
    let doc = backup_json();
    named(&doc["plaintexts"], name)["fingerprint"]
        .as_str()
        .expect("a fingerprint")
        .to_owned()
}

/// How a passphrase is typed on the Pi (Q32 (b)): each word's first four letters, or the whole
/// word when it has three.
fn first_fours(passphrase: &str) -> Vec<String> {
    passphrase
        .split(' ')
        .map(|word| word.chars().take(4).collect())
        .collect()
}

/// The fingerprint a summary shows: its one text of 8 lowercase hex digits.
fn fingerprint_shown(texts: &[Zeroizing<String>]) -> &str {
    texts
        .iter()
        .map(|text| text.as_str())
        .find(|text| {
            text.len() == 8
                && text
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .expect("a fingerprint")
}

/// 4 bytes as 8 lowercase hex digits.
fn hex4(bytes: [u8; 4]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Every text element of `present`.
fn texts(present: &Present) -> Vec<&str> {
    present
        .elements
        .iter()
        .filter_map(|element| element.item.text())
        .collect()
}

/// True when `present` shows exactly `text` as one element.
fn shows(present: &Present, text: &str) -> bool {
    texts(present).contains(&text)
}

fn black(present: &Present) -> bool {
    present.frame.raw().iter().all(|&pixel| pixel == 0)
}

fn key(key: Key) -> Step {
    Step::Key(key)
}

/// An assertion on the latest present: it shows exactly `text`.
fn latest_shows(what: &'static str, text: String) -> Step {
    Assert(what, Box::new(move |seen| shows(seen.latest, &text)))
}

/// An assertion that the latest present offers KEY2 "back" (the owner's decision of 2026-10-13).
fn offers_back(what: &'static str) -> Step {
    Assert(
        what,
        Box::new(|seen| seen.latest.keys.label(Key::Key2) == Some("back")),
    )
}

/// The halt after a black frame, naming `stop` exactly, with nothing held. (No element of the halt
/// is Protected: the panel fails a Protected element on any Public screen.)
fn halted(stop: String) -> Vec<Step> {
    vec![
        Expect(ScreenId::Blank),
        Assert("a black frame first", Box::new(|seen| black(seen.matched))),
        Expect(ScreenId::Halt),
        Assert(
            "the halt names the failure in core's or the HAL's fixed text",
            Box::new(move |seen| shows(seen.matched, &stop)),
        ),
        Assert(
            "nothing held after a halt",
            Box::new(|seen| !seen.app.holds_secrets() && !seen.app.keeps_wiped()),
        ),
    ]
}

/// The halt for core's health-test verdict, naming no HAL fault.
fn halted_by_health(verdict: HealthFailure) -> Vec<Step> {
    let mut steps = halted(CoreError::Health(verdict).to_string());
    steps.push(Assert(
        "the halt names no HAL fault",
        Box::new(|seen| {
            HalError::ALL.into_iter().all(|fault| {
                texts(seen.matched)
                    .iter()
                    .all(|t| !t.contains(fault.text()))
            })
        }),
    ));
    steps
}

fn boot() -> Vec<Step> {
    vec![Expect(ScreenId::Boot), Expect(ScreenId::Home)]
}

/// Home's entries by place (pi-firmware.md step 2): New seed, Dice-only seed, Check a backup,
/// Load registry snapshot, About.
const CHECK_A_BACKUP: usize = 2;
const LOAD_SNAPSHOT: usize = 3;
const ABOUT: usize = 4;

/// From Home, the entry at `place`.
fn home(place: usize) -> Vec<Step> {
    let mut steps: Vec<Step> = (0..place).map(|_| key(Key::Down)).collect();
    steps.push(key(Key::Press));
    steps
}

/// usb-insert, then a stick holding `files`, which the device notices by itself.
fn insert_stick(files: Vec<(&str, Vec<u8>)>) -> Vec<Step> {
    let files = files
        .into_iter()
        .map(|(name, bytes)| (name.to_owned(), bytes))
        .collect();
    vec![
        Expect(ScreenId::UsbInsert),
        Step::Stick(Stick::Insert(files)),
        Wait(STICK_SECONDS),
    ]
}

/// usb-insert with the stick still in: the device goes on by itself.
fn stick_still_in() -> Vec<Step> {
    vec![Expect(ScreenId::UsbInsert), Wait(STICK_SECONDS)]
}

/// From Home: a new seed of `mode` and `len`, to the wait screen of its first session.
fn new_seed(mode: Mode, len: SeedLength) -> Vec<Step> {
    let mut steps = Vec::new();
    if mode == Mode::DiceOnly {
        steps.push(key(Key::Down));
    }
    steps.extend([key(Key::Press), Expect(ScreenId::Length)]);
    if len == SeedLength::Words24 {
        steps.push(key(Key::Down));
    }
    steps.extend([key(Key::Press), Expect(ScreenId::Wait)]);
    steps
}

/// Step 4 to the dice: Mixed fills the quota, then Continue and the commitment; dice only passes
/// its notice. The dice screen then shows 0 rolls of `minimum`.
fn to_dice(mode: Mode, minimum: u16) -> Vec<Step> {
    let mut steps = match mode {
        Mode::Mixed => vec![
            Expect(ScreenId::Hwrng),
            Wait(QUOTA_SECONDS),
            key(Key::Press),
            Expect(ScreenId::Commitment),
            key(Key::Press),
        ],
        Mode::DiceOnly => vec![Expect(ScreenId::DiceOnlyNotice), key(Key::Press)],
    };
    steps.extend([
        Expect(ScreenId::Dice),
        latest_shows(
            "the dice start at 0 rolls of the session's minimum",
            format!("0 / {minimum} rolls, 0.0 bits"),
        ),
    ]);
    steps
}

/// The rolls, Done, the check prompt.
fn roll(rolls: String) -> Vec<Step> {
    vec![Dice(rolls), key(Key::Key3), Expect(ScreenId::CheckPrompt)]
}

/// Skip, confirmed: the privacy gate in front of the words.
fn skip() -> Vec<Step> {
    vec![
        key(Key::Down),
        key(Key::Press),
        Expect(ScreenId::SkipConfirm),
        key(Key::Press),
        Expect(ScreenId::PrivacyGate),
    ]
}

/// From the privacy gate in front of the words: every insert of a seed of `count` words, to the
/// last (`pages`).
fn page_through(count: u8) -> Vec<Step> {
    let mut steps = vec![key(Key::Press), Expect(ScreenId::WordsInsert)];
    steps.extend(pages(count));
    steps
}

/// From insert 1: every insert of a seed of `count` words, paged with KEY3 to the last,
/// device-swap (and its gate) before word 13.
fn pages(count: u8) -> Vec<Step> {
    let mut steps = Vec::new();
    for position in 2..=count {
        if position == 13 {
            steps.extend([
                key(Key::Key3),
                Expect(ScreenId::DeviceSwap),
                key(Key::Press),
                Expect(ScreenId::PrivacyGate),
                key(Key::Press),
            ]);
        } else {
            steps.push(key(Key::Key3));
        }
        steps.push(Expect(ScreenId::WordsInsert));
    }
    steps
}

/// From the last insert: the read-back of every insert, each as its insert view showed it, then
/// readback-done.
fn read_back(count: u8) -> Vec<Step> {
    let mut steps = vec![key(Key::Press), Expect(ScreenId::ReadbackEntry)];
    for _ in 0..count {
        steps.extend(read_back_one());
    }
    steps.push(Expect(ScreenId::ReadbackDone));
    steps
}

/// One insert read back from the screen: a match shows the whole word, and done goes on.
fn read_back_one() -> Vec<Step> {
    vec![
        Step::Readback(Readback::FromScreen),
        Expect(ScreenId::ReadbackEntry),
        Assert(
            "a match shows the whole word, offering only done",
            Box::new(|seen| {
                seen.matched
                    .elements
                    .iter()
                    .any(|e| e.class == Class::Protected && e.item.text().is_some())
                    && Key::ALL
                        .into_iter()
                        .all(|k| seen.matched.keys.label(k).is_some() == (k == Key::Key3))
            }),
        ),
        key(Key::Key3),
    ]
}

/// From readback-done: the wallet summary, then steps 11-13 skipped, to step 14's offer (Mixed)
/// or the checklist (dice only).
fn skip_steps_11_to_13() -> Vec<Step> {
    vec![
        key(Key::Press),
        Expect(ScreenId::Wallet),
        key(Key::Press),
        Expect(ScreenId::BackupOffer),
        key(Key::Down),
        key(Key::Press),
        Expect(ScreenId::WatchOffer),
        key(Key::Down),
        key(Key::Press),
        Expect(ScreenId::RegisterOffer),
        key(Key::Down),
        key(Key::Press),
    ]
}

/// The checklist's two pages, then Finish: a black frame, power-off and the session wiped.
fn finish() -> Vec<Step> {
    vec![
        Expect(ScreenId::Checklist),
        key(Key::Key3),
        Expect(ScreenId::Checklist),
        key(Key::Press),
        Expect(ScreenId::Blank),
        Assert("a black frame first", Box::new(|seen| black(seen.matched))),
        Expect(ScreenId::PowerOff),
        Assert(
            "Finish wipes the session",
            Box::new(|seen| !seen.app.holds_secrets()),
        ),
    ]
}

/// From readback-done: the wallet summary, steps 11-13 skipped, then (dice only, no step 14)
/// the checklist's two pages and power-off.
fn skip_exports() -> Vec<Step> {
    chain(vec![skip_steps_11_to_13(), finish()])
}

/// On backup-check-entry: each entry typed, then done.
fn entries(entries: &[String]) -> Vec<Step> {
    entries
        .iter()
        .flat_map(|entry| [Type(entry.clone()), key(Key::Key3)])
        .collect()
}

/// Check now with no snapshot: the seal card's three pages, then its actions.
fn seal_card() -> Vec<Step> {
    vec![
        key(Key::Press),
        Expect(ScreenId::SealImage),
        key(Key::Key3),
        Expect(ScreenId::SealId),
        key(Key::Key3),
        Expect(ScreenId::SealQr),
        key(Key::Press),
        Expect(ScreenId::CheckActions),
    ]
}

/// Match found, confirmed: the collision, the privacy gate and the collision report QR.
fn match_found() -> Vec<Step> {
    vec![
        key(Key::Down),
        key(Key::Press),
        Expect(ScreenId::StopConfirm),
        key(Key::Press),
        Expect(ScreenId::Collision),
        key(Key::Press),
        Expect(ScreenId::PrivacyGate),
        key(Key::Press),
        Expect(ScreenId::CollisionQr),
    ]
}

/// "Add fresh entropy" on the collision report: a new session behind the wait screen.
fn add_fresh_entropy() -> Vec<Step> {
    vec![key(Key::Press), Expect(ScreenId::Wait)]
}

/// Cannot check, confirmed: a new session behind the wait screen.
fn cannot_check() -> Vec<Step> {
    vec![
        key(Key::Down),
        key(Key::Down),
        key(Key::Press),
        Expect(ScreenId::CannotCheckConfirm),
        key(Key::Press),
        Expect(ScreenId::Wait),
    ]
}

/// On the code grid: the mock checker's G for the check QR shown, then check-clear with the
/// code-path text (Q33 (l)), naming `seal` (a vector run's Seal ID) or, for a throwaway run, a
/// seal whose ID is known only once drawn.
fn type_go_ahead(seal: Option<String>) -> Vec<Step> {
    vec![
        Expect(ScreenId::CodeEntry),
        Step::Code(Code::FromCheck),
        Expect(ScreenId::CheckClear),
        Assert(
            "check-clear says the device cannot know the checker's date",
            Box::new(move |seen| {
                texts(seen.matched).iter().any(|text| match &seal {
                    Some(seal) => {
                        *text
                            == format!(
                                "No collision for seal {seal}, as of the date your checker showed."
                            )
                    }
                    None => {
                        text.starts_with("No collision for seal ")
                            && text.ends_with(", as of the date your checker showed.")
                    }
                })
            }),
        ),
    ]
}

/// An assertion that the last `count` check QRs presented carry one payload: the same check, so
/// the same nonce.
fn same_check_qr(what: &'static str, count: usize) -> Step {
    Assert(
        what,
        Box::new(move |seen| {
            let urls = &seen.record.check_urls;
            urls.len() >= count
                && urls[urls.len() - count..]
                    .windows(2)
                    .all(|pair| pair[0] == pair[1])
        }),
    )
}

fn chain(parts: Vec<Vec<Step>>) -> Vec<Step> {
    parts.into_iter().flatten().collect()
}

/// The two boot stops (Q25; Q30 (a)): each startup health failure halts, with core's verdict.
fn boot_stops() -> Scenario {
    let (run_of_6, rct) = health("run-of-6-startup");
    let (apt_62, apt) = health("apt-62-startup");
    assert_eq!((rct.stage, rct.sample), (HealthStage::Startup, 505));
    assert_eq!((apt.stage, apt.sample), (HealthStage::Startup, 500));
    Scenario {
        name: "boot_stops",
        hwrng: HwRngStream::Bytes(run_of_6),
        protected: ProtectedFrames::Placeholder,
        steps: chain(vec![
            vec![Expect(ScreenId::Boot)],
            halted_by_health(rct),
            vec![
                PowerCycle(HwRngStream::Bytes(apt_62)),
                Expect(ScreenId::Boot),
            ],
            halted_by_health(apt),
        ]),
    }
}

/// A throwaway run (Q25, Q26): a collision, then a continuous health failure in the restart's
/// step 4 halts with nothing held, and a power cycle forgets the 99-roll minimum, as documented.
/// After another power cycle, an hwrng read fault in step 4 halts too, with the HAL's text.
fn runtime_stop() -> Scenario {
    let (continuous, rct) = health("run-of-6-continuous");
    assert_eq!((rct.stage, rct.sample), (HealthStage::Continuous, 1505));
    // Concatenated by read phase: a passing boot and first session from the counting stream, then
    // the restart's step 4 from run-of-6-continuous.
    let mut stream: Vec<u8> = (0..BOOT_BYTES + SESSION_BYTES)
        .map(|i| i.to_le_bytes()[0])
        .collect();
    stream.extend_from_slice(&continuous[..SESSION_BYTES]);
    Scenario {
        name: "runtime_stop",
        hwrng: HwRngStream::Bytes(stream),
        protected: ProtectedFrames::Placeholder,
        steps: chain(vec![
            boot(),
            new_seed(Mode::Mixed, SeedLength::Words12),
            to_dice(Mode::Mixed, 50),
            roll(rolls("coldcard-50")),
            seal_card(),
            match_found(),
            add_fresh_entropy(),
            vec![Expect(ScreenId::Hwrng), Wait(QUOTA_SECONDS)],
            halted_by_health(rct),
            vec![PowerCycle(HwRngStream::Counting)],
            boot(),
            new_seed(Mode::DiceOnly, SeedLength::Words12),
            to_dice(Mode::DiceOnly, 50),
            vec![PowerCycle(HwRngStream::Counting)],
            boot(),
            new_seed(Mode::Mixed, SeedLength::Words12),
            vec![
                Expect(ScreenId::Hwrng),
                Step::Fault(Fault::HwRng),
                Wait(QUOTA_SECONDS),
            ],
            halted(HalError::HwRng.text().to_owned()),
        ]),
    }
}

/// The shipped verifier (tasks/todo.md, M2).
const VERIFY_PY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tools/verify/verify.py");

/// The 16 groups of 4 hex digits among a screen's texts (C or D), on one line, as they are typed
/// into verify.py.
fn hex_line(texts: &[Zeroizing<String>]) -> Zeroizing<String> {
    let hex = texts
        .iter()
        .find(|text| {
            text.contains('\n') && text.chars().filter(|c| c.is_ascii_hexdigit()).count() == 64
        })
        .expect("16 groups of 4 hex digits");
    Zeroizing::new(hex.replace('\n', " "))
}

/// The Seal ID among the seal-id page's texts: its one text of 8 Crockford symbols.
fn seal_id_shown(texts: &[Zeroizing<String>]) -> &str {
    texts
        .iter()
        .map(|text| text.as_str())
        .find(|text| {
            text.len() == 8
                && text
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        })
        .expect("a Seal ID")
}

/// The verify.py tie (Q30 (e); tasks/todo.md, M3 group 11): C from the last commitment screen and
/// D from reveal-d, each typed on one line, and `rolls`, piped into
/// `python3 -I verify.py mixed --words 12`. It must exit 0, its insert lines must name the words
/// the inserts showed, in order, and its Seal ID must be the seal-id page's. All of it stays in
/// memory, and the assertion's message is fixed: nothing is printed.
fn verify_py_tie(rolls: String) -> Step {
    Assert(
        "verify.py mixed recomputes the words and the Seal ID shown from C, D and the rolls",
        Box::new(move |seen| {
            let record = seen.record;
            let c = hex_line(record.texts_of(ScreenId::Commitment));
            let d = hex_line(record.texts_of(ScreenId::RevealD));
            let input = Zeroizing::new(format!("{}\n{}\n{rolls}\n\n", c.as_str(), d.as_str()));
            let mut verify = Command::new("python3")
                .args(["-I", VERIFY_PY, "mixed", "--words", "12"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("python3 starts");
            verify
                .stdin
                .take()
                .expect("its stdin")
                .write_all(input.as_bytes())
                .expect("the input is written");
            let output = verify.wait_with_output().expect("verify.py ends");
            // Output that is not UTF-8 fails the fixed message: a panic with the error would print
            // the words.
            let stdout = Zeroizing::new(output.stdout);
            let Ok(stdout) = std::str::from_utf8(&stdout) else {
                return false;
            };
            let inserts: Vec<&str> = stdout
                .lines()
                .filter_map(|line| line.strip_prefix("insert: ")?.split_whitespace().nth(7))
                .collect();
            let seal = stdout
                .lines()
                .find_map(|line| line.strip_prefix("seal-id: ")?.split_whitespace().next());
            output.status.success()
                && inserts == record.words()
                && seal == Some(seal_id_shown(record.texts_of(ScreenId::SealId)))
        }),
    )
}

/// reveal-d as the app lays it out, showing `d`: the capture set draws it with keepcrypt.json's
/// public D, the specimen of a screen whose captures are placeholders (Q30 (g)).
/// `mixed_12_restarts` holds this layout to the app's own reveal-d.
fn reveal_d_specimen(d: &str, banners: Banners) -> Screen<'_> {
    Screen::new(ScreenId::RevealD, "Device leg D", banners)
        .with(Element::public(
            (0, 0).into(),
            Item::Text("Device leg D".into()),
        ))
        .with(Element::protected((25, 24).into(), Item::Hex(d.into())))
        .with(Element::public(
            (0, 108).into(),
            Item::Small("Only for verify.py on an offline computer.".into()),
        ))
}

/// True when `present` has `model`'s title, banners, keys and elements: each at its place, of its
/// class and kind, and a Public one with its text (a Protected element's text is not compared).
fn same_layout(present: &Present, model: &Screen<'_>) -> bool {
    present.title.as_str() == model.title()
        && present.banners == model.banners()
        && present.keys == model.keys()
        && present.elements.len() == model.elements().len()
        && present
            .elements
            .iter()
            .zip(model.elements())
            .all(|(shown, element)| {
                let text = match element.item() {
                    Item::Text(text) | Item::Small(text) | Item::Hex(text) => Some(text.as_str()),
                    _ => None,
                };
                let kind = matches!(
                    (&shown.item, element.item()),
                    (Shown::Text(_), Item::Text(_))
                        | (Shown::Small(_), Item::Small(_))
                        | (Shown::Hex(_), Item::Hex(_))
                );
                shown.at == (element.at().x, element.at().y)
                    && shown.class == element.class()
                    && kind
                    && (shown.class == Class::Protected || shown.item.text() == text)
            })
}

/// A throwaway run on the counting stream (Q26, Q27, Q29; matrix "Full ceremony with offline
/// verification", simulator half): Snake while step 4 fills, closed by the quota; the restarts and
/// idle steps of steps 1-7; then a check passed on the mock checker's code, the words read back,
/// the exports skipped but D, the verify.py tie on the last session's C, D and rolls, and Finish.
fn mixed_12_restarts() -> Scenario {
    let last_rolls = rolls("coldcard-99");
    Scenario {
        name: "mixed_12_restarts",
        hwrng: HwRngStream::Counting,
        protected: ProtectedFrames::Placeholder,
        steps: chain(vec![
            boot(),
            new_seed(Mode::Mixed, SeedLength::Words12),
            // 1. Continue is refused before the bar is full: step 4 offers Snake instead (and the
            // probe presses every other key). The bar counts health-tested bytes, not credited
            // bits.
            vec![
                Expect(ScreenId::Hwrng),
                Assert(
                    "before the bar is full, step 4 offers Snake and no Continue",
                    Box::new(|seen| {
                        shows(seen.matched, ">Play while you wait")
                            && texts(seen.matched).iter().all(|t| !t.contains("Continue"))
                    }),
                ),
                Assert(
                    "the bar starts empty, with no byte tested and no bit credited",
                    Box::new(|seen| {
                        shows(seen.matched, "[--------------------]")
                            && shows(seen.matched, "0 / 1536 bytes health-tested")
                            && shows(seen.matched, "0 / 512 bits credited")
                    }),
                ),
            ],
            // 2. Snake is open when the quota fills, and the quota closes it: the first step 4
            // screen after it shows the full bar, and Continue.
            vec![
                key(Key::Press),
                Expect(ScreenId::GameSnake),
                Assert(
                    "Snake shows its board, steered with the joystick",
                    Box::new(|seen| {
                        seen.matched
                            .elements
                            .iter()
                            .any(|e| matches!(e.item, Shown::Board(_)))
                            && seen.matched.keys.label(Key::Up) == Some("steer")
                    }),
                ),
                key(Key::Up),
                Wait(QUOTA_SECONDS),
                Expect(ScreenId::Hwrng),
                Assert(
                    "at the quota the bar is full, the first window credited 2,048 bits, and \
                     Continue is offered",
                    Box::new(|seen| {
                        shows(seen.matched, "[####################]")
                            && shows(seen.matched, "1536 / 1536 bytes health-tested")
                            && shows(seen.matched, "2048 / 512 bits credited")
                            && shows(seen.matched, ">Continue")
                    }),
                ),
            ],
            // 3. The commitment; coldcard-50 as the rolls.
            vec![
                key(Key::Press),
                Expect(ScreenId::Commitment),
                key(Key::Press),
                Expect(ScreenId::Dice),
            ],
            roll(rolls("coldcard-50")),
            // 4. Match found: the restart needs 99 rolls.
            seal_card(),
            match_found(),
            add_fresh_entropy(),
            to_dice(Mode::Mixed, 99),
            // 5. Cannot check in that restart: still 99.
            roll(rolls("coldcard-99")),
            seal_card(),
            cannot_check(),
            // 6. Nine minutes on step 4: the warning, and a key keeps the session.
            vec![
                Expect(ScreenId::Hwrng),
                Wait(540),
                Expect(ScreenId::IdleWarning),
                key(Key::Down),
                Expect(ScreenId::Hwrng),
                Assert(
                    "a key keeps the session",
                    Box::new(|seen| seen.app.holds_secrets()),
                ),
                key(Key::Press),
                Expect(ScreenId::Commitment),
                key(Key::Press),
                Expect(ScreenId::Dice),
                latest_shows(
                    "Cannot check in the restart keeps 99 rolls",
                    String::from("0 / 99 rolls, 0.0 bits"),
                ),
            ],
            // 7. Ten minutes in Rolling: the idle wipe; New seed still needs 99.
            vec![
                Wait(600),
                Expect(ScreenId::IdleWarning),
                Expect(ScreenId::Blank),
                Expect(ScreenId::IdleWiped),
                Assert(
                    "the idle wipe keeps the kept Wiped and nothing else",
                    Box::new(|seen| !seen.app.holds_secrets() && seen.app.keeps_wiped()),
                ),
                key(Key::Press),
                Expect(ScreenId::Home),
            ],
            new_seed(Mode::Mixed, SeedLength::Words12),
            to_dice(Mode::Mixed, 99),
            // 8. A check that passes on the mock checker's code, the privacy gate, then the words,
            // read back from the screen.
            roll(last_rolls.clone()),
            seal_card(),
            vec![key(Key::Press)],
            type_go_ahead(None),
            vec![
                key(Key::Press),
                Expect(ScreenId::PrivacyGate),
                Assert(
                    "a passed check ends the kept Wiped",
                    Box::new(|seen| seen.app.holds_secrets() && !seen.app.keeps_wiped()),
                ),
            ],
            page_through(12),
            read_back(12),
            // 9. The exports skipped but Reveal D, then the verify.py tie and Finish.
            skip_steps_11_to_13(),
            vec![
                Expect(ScreenId::RevealDOffer),
                latest_shows(
                    "reveal-d-offer says to type each value only after its prompt",
                    String::from(
                        "On the offline computer, type each value into verify.py only after its \
                         prompt appears.",
                    ),
                ),
                key(Key::Press),
                Expect(ScreenId::PrivacyGate),
                key(Key::Press),
                Expect(ScreenId::RevealD),
                Assert(
                    "reveal-d is laid out as the capture set's specimen, D aside",
                    Box::new(|seen| {
                        same_layout(seen.matched, &reveal_d_specimen("", seen.matched.banners))
                    }),
                ),
                verify_py_tie(last_rolls),
                key(Key::Press),
            ],
            finish(),
        ]),
    }
}

/// The duplicate-seed drill, a vector run (Q26, Q33 (a); matrix "Duplicate-seed drill"). In the
/// release configuration the build pins no registry key, so the snapshot is refused with
/// `NoRegistryKey`'s text, and the drill ends there. With the test key: a tampered snapshot is
/// refused and `with-dice-50` loads; it catches `coldcard-50` before any word is shown; the
/// restart needs 99 rolls, through a Cannot check after No on the date; then `coldcard-99` passes
/// as of the snapshot's date, its words equal kcr.json's and read back, the exports are skipped
/// and Finish powers off.
fn drill_12(config: Config) -> Scenario {
    let dice_50 = snapshot("with-dice-50");
    if config == Config::Release {
        return Scenario {
            name: "drill_12",
            hwrng: HwRngStream::Counting,
            protected: ProtectedFrames::AsDrawn,
            steps: chain(vec![
                boot(),
                home(LOAD_SNAPSHOT),
                insert_stick(vec![("keepcrypt-registry-2026-03-01.kcr", dice_50)]),
                vec![
                    Expect(ScreenId::Wait),
                    Expect(ScreenId::SnapshotFailed),
                    latest_shows(
                        "a release build refuses every snapshot: no registry key",
                        CoreError::NoRegistryKey.to_string(),
                    ),
                    key(Key::Press),
                    Expect(ScreenId::Home),
                ],
            ]),
        };
    }
    let mut first_ten = rolls("coldcard-50");
    let rest = first_ten.split_off(10);
    let collision_report = format!(
        "{ORIGIN}/register#c={}",
        seed("dice-50-words12", "seal_code_hashed")
    );
    let words: Vec<String> = seed("dice-99-words12", "mnemonic")
        .split(' ')
        .map(str::to_owned)
        .collect();
    let check_prefix = format!(
        "{ORIGIN}/check#t={}&n=",
        seed("dice-99-words12", "seal_tag_hex")
    );
    let load = |cursor_down: bool| {
        let mut steps = vec![Expect(ScreenId::UsbPick)];
        if cursor_down {
            steps.push(key(Key::Down));
        }
        steps.extend([key(Key::Press), Expect(ScreenId::Wait)]);
        steps
    };
    Scenario {
        name: "drill_12",
        hwrng: HwRngStream::Counting,
        protected: ProtectedFrames::AsDrawn,
        steps: chain(vec![
            boot(),
            // 1. A tampered snapshot is refused; with-dice-50 loads.
            home(LOAD_SNAPSHOT),
            insert_stick(vec![
                ("flipped-signature-r.kcr", snapshot("flipped-signature-r")),
                ("keepcrypt-registry-2026-03-01.kcr", dice_50),
            ]),
            load(false),
            vec![
                Expect(ScreenId::SnapshotFailed),
                latest_shows(
                    "a tampered snapshot is refused with core's text",
                    String::from("registry snapshot or proof rejected: bad signature"),
                ),
                key(Key::Press),
                Expect(ScreenId::Home),
            ],
            home(LOAD_SNAPSHOT),
            stick_still_in(),
            load(true),
            vec![
                Expect(ScreenId::SnapshotLoaded),
                latest_shows(
                    "the snapshot loaded is No. 4",
                    String::from("Snapshot No. 4, dated 2026-03-01, 7 entries."),
                ),
                key(Key::Press),
                Expect(ScreenId::Home),
                latest_shows(
                    "Home names the loaded snapshot",
                    String::from("Snapshot No. 4, dated 2026-03-01"),
                ),
            ],
            // 2. Dice-only, 12 words, coldcard-50 with one undo.
            new_seed(Mode::DiceOnly, SeedLength::Words12),
            to_dice(Mode::DiceOnly, 50),
            vec![
                Dice(first_ten),
                Dice(String::from("4")),
                key(Key::Key1),
                latest_shows(
                    "KEY1 undoes the extra roll",
                    String::from("10 / 50 rolls, 25.8 bits"),
                ),
            ],
            roll(rest),
            // 3. Check now, the date confirmed: the collision, before any words screen.
            vec![
                key(Key::Press),
                Expect(ScreenId::SnapshotDate),
                latest_shows(
                    "the date is confirmed before the snapshot reveal",
                    String::from(
                        "Snapshot No. 4, dated 2026-03-01, 7 entries. Use it for this check?",
                    ),
                ),
                key(Key::Press),
                Expect(ScreenId::Collision),
                Assert(
                    "no words screen before the collision",
                    Box::new(|seen| !seen.record.screens.contains(&ScreenId::WordsInsert)),
                ),
                key(Key::Press),
                Expect(ScreenId::PrivacyGate),
                key(Key::Press),
                Expect(ScreenId::CollisionQr),
                latest_shows(
                    "the collision report carries the destroyed seed's seal code",
                    collision_report,
                ),
            ],
            // 4. Add fresh entropy: 99 rolls.
            add_fresh_entropy(),
            to_dice(Mode::DiceOnly, 99),
            // 5. No on the date keeps the check open: the seal card, whose check QR carries this
            // seal's T and a nonce; then Cannot check: 99.
            roll(rolls("coldcard-99")),
            vec![
                key(Key::Press),
                Expect(ScreenId::SnapshotDate),
                key(Key::Down),
                key(Key::Press),
                Expect(ScreenId::SealImage),
                key(Key::Key3),
                Expect(ScreenId::SealId),
                key(Key::Key3),
                Expect(ScreenId::SealQr),
                Assert(
                    "after No, the check QR is this seal's check, with a nonce",
                    Box::new(move |seen| {
                        texts(seen.matched).iter().any(|t| {
                            t.strip_prefix(check_prefix.as_str())
                                .is_some_and(|n| n.len() == 16)
                        })
                    }),
                ),
                key(Key::Press),
                Expect(ScreenId::CheckActions),
            ],
            cannot_check(),
            to_dice(Mode::DiceOnly, 99),
            // 6. The date confirmed: no collision, as of the snapshot's date.
            roll(rolls("coldcard-99")),
            vec![
                key(Key::Press),
                Expect(ScreenId::SnapshotDate),
                key(Key::Press),
                Expect(ScreenId::CheckClear),
                latest_shows(
                    "check-clear names the seal and the snapshot's date",
                    String::from("No collision for seal 9FHYMCQA as of 2026-03-01."),
                ),
                Assert(
                    "a passed check ends the kept Wiped",
                    Box::new(|seen| !seen.app.keeps_wiped()),
                ),
                key(Key::Press),
                Expect(ScreenId::PrivacyGate),
            ],
            // 7. The words are dice-99-words12's, and read back from the screen.
            page_through(12),
            vec![Assert(
                "the words are kcr.json's dice-99-words12",
                Box::new(move |seen| seen.record.words() == words),
            )],
            read_back(12),
            // 8. Steps 11-13 skipped; the checklist; power-off.
            skip_exports(),
        ]),
    }
}

/// A vector run (Q26, Q29): a collision restarts at 99, and Skip reaches the words through the
/// privacy gate with its note, dropping the kept `Wiped`; ten idle minutes on the words cover,
/// warn and wipe them; the next seed needs 50 rolls again.
fn skip_and_idle() -> Scenario {
    Scenario {
        name: "skip_and_idle",
        hwrng: HwRngStream::Counting,
        protected: ProtectedFrames::AsDrawn,
        steps: chain(vec![
            boot(),
            new_seed(Mode::DiceOnly, SeedLength::Words12),
            to_dice(Mode::DiceOnly, 50),
            roll(rolls("coldcard-50")),
            seal_card(),
            match_found(),
            add_fresh_entropy(),
            to_dice(Mode::DiceOnly, 99),
            roll(rolls("coldcard-99")),
            skip(),
            vec![
                latest_shows(
                    "the privacy gate after Skip carries the note",
                    String::from(
                        "You skipped the check: the seal can be checked later from the words.",
                    ),
                ),
                Assert(
                    "Skip drops the kept Wiped",
                    Box::new(|seen| seen.app.holds_secrets() && !seen.app.keeps_wiped()),
                ),
                key(Key::Press),
                Expect(ScreenId::WordsInsert),
                Wait(600),
                Expect(ScreenId::Cover),
                Expect(ScreenId::IdleWarning),
                Expect(ScreenId::Blank),
                Expect(ScreenId::IdleWiped),
                Assert(
                    "the idle wipe holds nothing",
                    Box::new(|seen| !seen.app.holds_secrets() && !seen.app.keeps_wiped()),
                ),
                key(Key::Press),
                Expect(ScreenId::Home),
            ],
            new_seed(Mode::DiceOnly, SeedLength::Words12),
            to_dice(Mode::DiceOnly, 50),
        ]),
    }
}

/// Core's watch-only export of the dice-only seed of `rolls` with the BIP39 passphrase
/// `passphrase`, from a session of its own (a dice-only seed is its rolls' alone), read back
/// from its own faces: the account QR's text, and both descriptors on two lines.
fn core_export(
    len: SeedLength,
    rolls: &str,
    passphrase: &str,
) -> (Zeroizing<String>, Zeroizing<String>) {
    let session = Session::new(len, Mode::DiceOnly, Platform::Pi).expect("a session");
    let mut rolling = session.commit().expect("committed").start_dice();
    for face in rolls.bytes() {
        rolling = rolling.push_roll(face - b'0').expect("a face");
    }
    let mut ready = rolling.finish().expect("sealed").skip_check();
    let faces: Vec<(u8, String)> = ready
        .braille()
        .iter()
        .map(|insert| (insert.position(), insert.word().chars().take(4).collect()))
        .collect();
    for (position, letters) in faces {
        assert!(matches!(
            ready.check_readback(position, &letters),
            Ok(ReadbackResult::Match)
        ));
    }
    let passphrase = Bip39Passphrase::new(passphrase).expect("a passphrase");
    let (_, export) = ready.watch_only(Some(&passphrase)).expect("an export");
    let descriptors = format!(
        "{}\n{}",
        export.receive_descriptor(),
        export.change_descriptor()
    );
    (
        Zeroizing::new(export.qr_text().to_owned()),
        Zeroizing::new(descriptors),
    )
}

/// A vector run on the code path, the read-back drill and the exports (Q30 (c), (d); matrices
/// "Metal read-back drill" and "Watch-only import", Pi parts): Done refused at 98 of 99 rolls; a
/// wrong code refused with core's text and the same nonce, then the mock checker's code; 24
/// inserts with the device swap, equal to kcr.json's; the cover and one press; each kind of
/// read-back mistake, then corrected; a wrong confirm pick, a write fault and Retry, a read-back
/// that does not verify (the file removed), another whose removal fails (the file stays, and
/// backup-failed says so), then a verified backup the shown passphrase opens; the watch-only QRs
/// of a typed BIP39 passphrase's wallet, equal to core's; the registration QR; the checklist and
/// power-off.
fn dice_24_code() -> Scenario {
    let all_99 = rolls("coldcard-99");
    let mut first_98 = all_99.clone();
    let last = first_98.split_off(98);
    let seal = seal_id("dice-99-words24");
    let shown = seal.clone();
    let words24: Vec<String> = seed("dice-99-words24", "mnemonic")
        .split(' ')
        .map(str::to_owned)
        .collect();
    let words12: Vec<String> = seed("dice-99-words12", "mnemonic")
        .split(' ')
        .map(str::to_owned)
        .collect();
    let (account, descriptors) = core_export(SeedLength::Words24, &all_99, BIP39_PASSPHRASE);
    let registration = format!(
        "{ORIGIN}/register#c={}",
        seed("dice-99-words24", "seal_code_hashed")
    );
    let verdict = |what: &'static str, text: &'static str| {
        Assert(
            what,
            Box::new(move |seen| {
                seen.matched.elements.iter().any(|e| {
                    e.class == Class::Protected && e.item.text().is_some_and(|t| t.ends_with(text))
                })
            }),
        )
    };
    let mistake = |faces: &'static str, what: &'static str, text: &'static str| {
        vec![
            Step::Readback(Readback::Faces(faces)),
            Expect(ScreenId::ReadbackMismatch),
            verdict(what, text),
        ]
    };
    Scenario {
        name: "dice_24_code",
        hwrng: HwRngStream::Counting,
        protected: ProtectedFrames::AsDrawn,
        steps: chain(vec![
            // 1-3. The dice, the seal card, a wrong code and the checker's.
            boot(),
            new_seed(Mode::DiceOnly, SeedLength::Words24),
            to_dice(Mode::DiceOnly, 99),
            vec![
                Dice(first_98),
                Assert(
                    "Done is not offered at 98 rolls",
                    Box::new(|seen| seen.latest.keys.label(Key::Key3).is_none()),
                ),
                Step::Dead(Key::Key3),
            ],
            roll(last),
            vec![
                key(Key::Press),
                Expect(ScreenId::SealImage),
                key(Key::Key3),
                Expect(ScreenId::SealId),
                Assert(
                    "the seal-id page shows the vector's Seal ID",
                    Box::new(move |seen| shows(seen.matched, &shown)),
                ),
                key(Key::Key3),
                Expect(ScreenId::SealQr),
                key(Key::Press),
                Expect(ScreenId::CheckActions),
                key(Key::Press),
                Expect(ScreenId::CodeEntry),
                Step::Code(Code::Wrong),
                Expect(ScreenId::CodeWrong),
                Assert(
                    "a wrong code is refused with core's text",
                    Box::new(|seen| shows(seen.matched, "the go-ahead code does not match")),
                ),
                key(Key::Press),
            ],
            // The code for the check QR shown before the wrong one: the nonce is unchanged.
            type_go_ahead(Some(seal)),
            vec![key(Key::Press), Expect(ScreenId::PrivacyGate)],
            // 4. 24 inserts: the overview on and off, the device swap in both views, the device
            // labels.
            vec![
                key(Key::Press),
                Expect(ScreenId::WordsInsert),
                key(Key::Key1),
                Expect(ScreenId::WordsOverview),
                Assert(
                    "the overview names its words and device",
                    Box::new(|seen| shows(seen.matched, "Words 01-04 · device 1 of 2")),
                ),
                key(Key::Key3),
                Expect(ScreenId::WordsOverview),
                key(Key::Key3),
                Expect(ScreenId::WordsOverview),
                // The overview pages on past word 12 only through device-swap.
                key(Key::Key3),
                Expect(ScreenId::DeviceSwap),
                key(Key::Press),
                Expect(ScreenId::PrivacyGate),
                key(Key::Press),
                Expect(ScreenId::WordsOverview),
                latest_shows(
                    "device-swap leads on to the overview of words 13-16",
                    String::from("Words 13-16 · device 2 of 2"),
                ),
                key(Key::Key2),
                Expect(ScreenId::WordsOverview),
                latest_shows(
                    "paging back names device 1 again",
                    String::from("Words 09-12 · device 1 of 2"),
                ),
                key(Key::Key2),
                Expect(ScreenId::WordsOverview),
                key(Key::Key2),
                Expect(ScreenId::WordsOverview),
                key(Key::Key1),
                Expect(ScreenId::WordsInsert),
            ],
            // Back on insert 1: page through all 24.
            pages(24),
            vec![
                latest_shows(
                    "insert 24 names device 2 of 2",
                    String::from("Insert 24 · device 2 of 2"),
                ),
                Assert(
                    "the 24 words are kcr.json's dice-99-words24",
                    Box::new(move |seen| seen.record.words() == words24),
                ),
                // 5. 31 s on an insert: the cover; one press shows the same page again.
                Wait(31),
                Expect(ScreenId::Cover),
                key(Key::Press),
                Expect(ScreenId::WordsInsert),
                latest_shows(
                    "the press only uncovers the same insert",
                    String::from("Insert 24 · device 2 of 2"),
                ),
                Assert(
                    "on the ceremony's last insert, Press starts the read-back",
                    Box::new(|seen| seen.latest.keys.label(Key::Press) == Some("read-back")),
                ),
                key(Key::Press),
                Expect(ScreenId::ReadbackEntry),
                // KEY2 "back" is the go-ahead code's and the backup check's alone.
                Step::Dead(Key::Key2),
            ],
            // 6. The read-back: each kind of mistake, then corrected.
            vec![
                Step::Readback(Readback::Faces("vari")),
                Expect(ScreenId::ReadbackEntry),
                latest_shows("vari completes to various", String::from("various")),
                key(Key::Key3),
            ],
            mistake("tap", "tap for tape", "should have a letter"),
            vec![key(Key::Press), Expect(ScreenId::ReadbackEntry)],
            read_back_one(),
            mistake("mirc", "mirc for mercy", "mirror misread"),
            // KEY1 shows the insert, where Press returns to its entry.
            vec![
                key(Key::Key1),
                Expect(ScreenId::WordsInsert),
                latest_shows(
                    "KEY1 shows the insert that did not match",
                    String::from("Insert 03 · device 1 of 2"),
                ),
                key(Key::Press),
                Expect(ScreenId::ReadbackEntry),
            ],
            read_back_one(),
            mistake(
                "eask",
                "eask for east",
                "wrong letter: missing 2 4 5, extra 1",
            ),
            vec![key(Key::Press), Expect(ScreenId::ReadbackEntry)],
            read_back_one(),
            read_back_one(),
            read_back_one(),
            read_back_one(),
            read_back_one(),
            read_back_one(),
            mistake("taga", "taga for tag", "should be blank"),
            vec![
                key(Key::Press),
                Expect(ScreenId::ReadbackEntry),
                Step::Readback(Readback::Faces("tag_")),
                Expect(ScreenId::ReadbackEntry),
                latest_shows(
                    "tag and a blank face 4 complete to tag",
                    String::from("tag"),
                ),
                key(Key::Key3),
            ],
            (11..=24).flat_map(|_| read_back_one()).collect(),
            vec![
                Expect(ScreenId::ReadbackDone),
                Assert(
                    "the first 11 words are dice-99-words12's",
                    Box::new(move |seen| seen.record.words()[..11] == words12[..11]),
                ),
                // 7. The wallet summary.
                key(Key::Press),
                Expect(ScreenId::Wallet),
                // 8. The backup: a wrong confirm pick shows the same questions again.
                key(Key::Press),
                Expect(ScreenId::BackupOffer),
                key(Key::Press),
                Expect(ScreenId::PrivacyGate),
                key(Key::Press),
                Expect(ScreenId::BackupPassphrase),
                key(Key::Key3),
                Expect(ScreenId::BackupPassphrase),
                key(Key::Press),
                Expect(ScreenId::BackupConfirm),
                Step::Pick(Answer::Wrong),
                Expect(ScreenId::BackupConfirmWrong),
                key(Key::Press),
                Expect(ScreenId::BackupPassphrase),
                key(Key::Press),
                Expect(ScreenId::BackupPassphrase),
                key(Key::Press),
                Expect(ScreenId::BackupConfirm),
                Step::Pick(Answer::Right),
                Expect(ScreenId::BackupConfirm),
                Step::Pick(Answer::Right),
                // The passphrase is generated once: back on the offer, Back up goes straight to the
                // stick, under the same passphrase.
                Expect(ScreenId::UsbInsert),
                key(Key::Key1),
                Expect(ScreenId::BackupOffer),
                key(Key::Press),
                // A write fault: nothing is left on the stick, and Retry writes a new file.
                Step::Fault(Fault::Write),
            ],
            insert_stick(Vec::new()),
            vec![
                Expect(ScreenId::Wait),
                Expect(ScreenId::BackupFailed),
                latest_shows(
                    "a write fault is the HAL's text",
                    HalError::Write.text().to_owned(),
                ),
                Assert(
                    "a failed write leaves nothing on the stick",
                    Box::new(|seen| seen.app.hal().stick_files().is_empty()),
                ),
                key(Key::Press),
                // A read-back that does not verify: core's text, and the file just written is read
                // back and removed, and nothing else.
                Expect(ScreenId::UsbInsert),
                Step::Fault(Fault::ReadBackCorrupt),
                Wait(STICK_SECONDS),
                Expect(ScreenId::Wait),
                Expect(ScreenId::BackupFailed),
                latest_shows(
                    "a read-back that does not verify is core's text",
                    CoreError::Backup(BackupError::Armor).to_string(),
                ),
                Assert(
                    "the file just written was read back and removed, and nothing else",
                    Box::new(|seen| {
                        let hal = seen.app.hal();
                        let [.., written, read, removed] = hal.stick_log() else {
                            return false;
                        };
                        let (Op::Write(name), Op::ReadWritten(back), Op::RemoveWritten(gone)) =
                            (&written.op, &read.op, &removed.op)
                        else {
                            return false;
                        };
                        name.ends_with(".age")
                            && back == name
                            && gone == name
                            && hal.stick_files().is_empty()
                    }),
                ),
                key(Key::Press),
                // A read-back that does not verify again, and a removal that fails: the file just
                // written stays on the stick, and backup-failed says so.
                Expect(ScreenId::UsbInsert),
                Step::Fault(Fault::ReadBackCorrupt),
                Step::Fault(Fault::Remove),
                Wait(STICK_SECONDS),
                Expect(ScreenId::Wait),
                Expect(ScreenId::BackupFailed),
                latest_shows(
                    "a removal that fails leaves the file, and the HAL's text says so",
                    format!("The file stays on the stick: {}", HalError::Remove.text()),
                ),
                Assert(
                    "the file just written was read back, its removal failed, and it stays",
                    Box::new(|seen| {
                        let hal = seen.app.hal();
                        let [.., written, read, removed] = hal.stick_log() else {
                            return false;
                        };
                        let (Op::Write(name), Op::ReadWritten(back), Op::RemoveWritten(gone)) =
                            (&written.op, &read.op, &removed.op)
                        else {
                            return false;
                        };
                        back == name && gone == name && hal.stick_files() == [name.as_str()]
                    }),
                ),
                key(Key::Press),
            ],
            stick_still_in(),
            vec![
                Expect(ScreenId::Wait),
                Expect(ScreenId::BackupVerified),
                Assert(
                    "the stick holds the file left behind and the verified backup, which the \
                     shown passphrase opens to this wallet",
                    Box::new(|seen| {
                        let hal = seen.app.hal();
                        // The last write is the verified backup; the last removal, the one that
                        // failed.
                        let log = hal.stick_log();
                        let written = log.iter().rev().find_map(|access| match &access.op {
                            Op::Write(name) => Some(name),
                            _ => None,
                        });
                        let left = log.iter().rev().find_map(|access| match &access.op {
                            Op::RemoveWritten(name) => Some(name),
                            _ => None,
                        });
                        let (Some(name), Some(left)) = (written, left) else {
                            return false;
                        };
                        let mut both = [name.as_str(), left.as_str()];
                        both.sort_unstable();
                        if hal.stick_files() != both {
                            return false;
                        }
                        let Some(file) = hal.stick_file(name) else {
                            return false;
                        };
                        let words = seen.record.passphrase();
                        let typed = TypedBackupPassphrase::from_words(&words).expect("8 words");
                        let checked = decrypt_backup(file, &typed).expect("the backup opens");
                        name.ends_with(".age")
                            && hex4(checked.fingerprint())
                                == fingerprint_shown(seen.record.texts_of(ScreenId::Wallet))
                    }),
                ),
                // 9. Watch-only, with a typed BIP39 passphrase.
                key(Key::Press),
                Expect(ScreenId::WatchOffer),
                key(Key::Press),
                Expect(ScreenId::Bip39Ask),
                key(Key::Down),
                key(Key::Press),
                Expect(ScreenId::PrivacyGate),
                key(Key::Press),
                Expect(ScreenId::Bip39Entry),
                Step::Dead(Key::Key2),
                Type(BIP39_PASSPHRASE.to_owned()),
                key(Key::Key3),
                Expect(ScreenId::WatchSummary),
                Assert(
                    "the passphrase's wallet has another fingerprint",
                    Box::new(|seen| {
                        fingerprint_shown(seen.record.texts_of(ScreenId::WatchSummary))
                            != fingerprint_shown(seen.record.texts_of(ScreenId::Wallet))
                    }),
                ),
                key(Key::Press),
                Expect(ScreenId::PrivacyGate),
                key(Key::Press),
                Expect(ScreenId::WatchAccountQr),
                Assert(
                    "the account QR is core's qr_text",
                    Box::new(move |seen| shows(seen.matched, &account)),
                ),
                key(Key::Key3),
                Expect(ScreenId::WatchDescriptorQr),
                Assert(
                    "the descriptor QR is both descriptors on two lines",
                    Box::new(move |seen| shows(seen.matched, &descriptors)),
                ),
                key(Key::Press),
                // 10. The registration QR, the checklist and power-off.
                Expect(ScreenId::RegisterOffer),
                key(Key::Press),
                Expect(ScreenId::PrivacyGate),
                key(Key::Press),
                Expect(ScreenId::RegisterQr),
                latest_shows("the registration QR carries the seal code", registration),
                key(Key::Press),
                Expect(ScreenId::Checklist),
                latest_shows(
                    "the checklist names both devices",
                    String::from(
                        "Device 1 of 2 holds words 1-12; device 2 of 2 holds words 13-24.",
                    ),
                ),
                key(Key::Key3),
                Expect(ScreenId::Checklist),
                key(Key::Press),
                Expect(ScreenId::Blank),
                Expect(ScreenId::PowerOff),
            ],
        ]),
    }
}

/// After a wipe: a black frame, then `next` (a Public screen, so the panel fails any Protected
/// element on it), and nothing held.
fn wiped_to(next: ScreenId) -> Vec<Step> {
    vec![
        Expect(ScreenId::Blank),
        Assert("a black frame first", Box::new(|seen| black(seen.matched))),
        Expect(next),
        Assert(
            "nothing held after the wipe",
            Box::new(|seen| !seen.app.holds_secrets()),
        ),
    ]
}

/// Ten idle minutes on a Protected screen that holds a secret: the cover, the warning, the wipe,
/// then Home.
fn idle_wipe() -> Vec<Step> {
    let mut steps = vec![
        Wait(600),
        Expect(ScreenId::Cover),
        Expect(ScreenId::IdleWarning),
    ];
    steps.extend(wiped_to(ScreenId::IdleWiped));
    steps.extend([key(Key::Press), Expect(ScreenId::Home)]);
    steps
}

/// A button fault: the halt, then a power cycle.
fn fault_halt() -> Vec<Step> {
    let mut steps = vec![Step::Fault(Fault::Buttons), key(Key::Press)];
    steps.extend(halted(HalError::Buttons.text().to_owned()));
    steps.push(PowerCycle(HwRngStream::Counting));
    steps.extend(boot());
    steps
}

/// The idle wipe and a fault (Q25, Q29) on one Protected screen of each stage that holds a
/// secret: both clear the stage and present a black frame, then a Public screen. On
/// collision-qr, whose seal code is the kept `Wiped`'s, the idle wipe keeps the kept `Wiped`
/// and the fault's halt drops it.
fn wipes_clear_the_stage() -> Scenario {
    let to_collision_qr = || {
        chain(vec![
            new_seed(Mode::DiceOnly, SeedLength::Words12),
            to_dice(Mode::DiceOnly, 50),
            roll(rolls("coldcard-50")),
            seal_card(),
            match_found(),
        ])
    };
    // A dice-only vector run, skipped to the words, to its last insert.
    let to_last_insert = || {
        chain(vec![
            new_seed(Mode::DiceOnly, SeedLength::Words12),
            to_dice(Mode::DiceOnly, 50),
            roll(rolls("coldcard-50")),
            skip(),
            page_through(12),
        ])
    };
    let to_readback_entry = || {
        chain(vec![
            to_last_insert(),
            vec![
                key(Key::Press),
                Expect(ScreenId::ReadbackEntry),
                Type(String::from("u")),
            ],
        ])
    };
    let to_backup_passphrase = || {
        chain(vec![
            to_last_insert(),
            read_back(12),
            vec![
                key(Key::Press),
                Expect(ScreenId::Wallet),
                key(Key::Press),
                Expect(ScreenId::BackupOffer),
                key(Key::Press),
                Expect(ScreenId::PrivacyGate),
                key(Key::Press),
                Expect(ScreenId::BackupPassphrase),
            ],
        ])
    };
    let to_bip39_entry = || {
        chain(vec![
            to_last_insert(),
            read_back(12),
            vec![
                key(Key::Press),
                Expect(ScreenId::Wallet),
                key(Key::Press),
                Expect(ScreenId::BackupOffer),
                key(Key::Down),
                key(Key::Press),
                Expect(ScreenId::WatchOffer),
                key(Key::Press),
                Expect(ScreenId::Bip39Ask),
                key(Key::Down),
                key(Key::Press),
                Expect(ScreenId::PrivacyGate),
                key(Key::Press),
                Expect(ScreenId::Bip39Entry),
                Type(String::from("T")),
            ],
        ])
    };
    let (abandon, passphrase) = age_file("abandon-12");
    let late_stick = vec![(String::from("abandon-12.age"), abandon.clone())];
    let to_backup_check_entry = move |stick_in: bool| {
        let stick = if stick_in {
            stick_still_in()
        } else {
            insert_stick(vec![("abandon-12.age", abandon.clone())])
        };
        chain(vec![
            home(CHECK_A_BACKUP),
            stick,
            vec![Expect(ScreenId::PrivacyGate), key(Key::Press)],
            vec![Expect(ScreenId::BackupCheckEntry)],
        ])
    };
    let typed = first_fours(&passphrase);
    let to_checked_words = |entry: Vec<Step>| {
        chain(vec![
            entry,
            entries(&typed),
            vec![
                Expect(ScreenId::Wait),
                Expect(ScreenId::BackupCheckResult),
                key(Key::Down),
                key(Key::Press),
                Expect(ScreenId::PrivacyGate),
                key(Key::Press),
                Expect(ScreenId::WordsInsert),
            ],
        ])
    };
    Scenario {
        name: "wipes_clear_the_stage",
        hwrng: HwRngStream::Counting,
        protected: ProtectedFrames::AsDrawn,
        steps: chain(vec![
            boot(),
            // collision-qr: the idle wipe keeps the kept Wiped, the fault drops it.
            to_collision_qr(),
            vec![
                Wait(600),
                Expect(ScreenId::Cover),
                Expect(ScreenId::Blank),
                Assert("a black frame first", Box::new(|seen| black(seen.matched))),
                Expect(ScreenId::IdleWiped),
                Assert(
                    "the idle wipe keeps the kept Wiped and nothing else",
                    Box::new(|seen| !seen.app.holds_secrets() && seen.app.keeps_wiped()),
                ),
                PowerCycle(HwRngStream::Counting),
            ],
            boot(),
            to_collision_qr(),
            fault_halt(),
            // readback-entry, with a face typed (the ceremony's Ready stage).
            to_readback_entry(),
            idle_wipe(),
            to_readback_entry(),
            fault_halt(),
            // backup-passphrase (Ready, holding the passphrase's display copy).
            to_backup_passphrase(),
            idle_wipe(),
            to_backup_passphrase(),
            fault_halt(),
            // bip39-entry, with a character typed (Ready, holding the typed passphrase).
            to_bip39_entry(),
            idle_wipe(),
            to_bip39_entry(),
            fault_halt(),
            // The words of a checked backup (Checked).
            to_checked_words(to_backup_check_entry(false)),
            idle_wipe(),
            to_checked_words(to_backup_check_entry(true)),
            fault_halt(),
            // backup-check-entry, with a face typed (BackupCheck, holding the file). The stick goes
            // in after ten idle minutes on usb-insert: the device noticing it is input, so the
            // backup it opens is not wiped in the same tick.
            home(CHECK_A_BACKUP),
            vec![
                Expect(ScreenId::UsbInsert),
                Wait(601),
                Step::Stick(Stick::Insert(late_stick)),
                Wait(STICK_SECONDS),
                Expect(ScreenId::PrivacyGate),
                Assert(
                    "a stick put in restarts the idle timer: the backup it opens stays",
                    Box::new(|seen| {
                        seen.app.holds_secrets() && seen.latest.id == ScreenId::PrivacyGate
                    }),
                ),
                key(Key::Press),
                Expect(ScreenId::BackupCheckEntry),
                Type(String::from("f")),
            ],
            idle_wipe(),
            to_backup_check_entry(true),
            vec![Type(String::from("f"))],
            vec![Step::Fault(Fault::Buttons), key(Key::Press)],
            halted(HalError::Buttons.text().to_owned()),
        ]),
    }
}

/// Home's About (Q33 (i)) and "Check a backup" (Q32 (b), Q33 (l)): KEY2 on the entry returns Home,
/// the backup read dropped and the stick as it was; an unrecognised entry is refused with core's
/// text and the screen's own instruction under it, and a wrong passphrase with core's text, the
/// entry emptied, the backup kept and KEY2 still offered; abandon-12's passphrase, typed by first
/// fours, opens it to backup.json's fingerprint; with a snapshot loaded (registry configuration),
/// its seal's registration count as of the snapshot's date; the re-check QR and the words on
/// request; a USB fault, and a backup over 8 KiB, named on usb-pick; zoo-24's words, its seal never
/// registered.
fn check_backup(config: Config) -> Scenario {
    let key_state = match config {
        Config::Release => "Registry key: none pinned in this build",
        Config::Registry => "Registry key: the TEST key",
    };
    let (abandon, abandon_passphrase) = age_file("abandon-12");
    let (zoo, zoo_passphrase) = age_file("zoo-24");
    let mut wrong = first_fours(&abandon_passphrase);
    wrong[0] = String::from("zzzz");
    let zoo_typed = first_fours(&zoo_passphrase);
    let abandon_fingerprint = plaintext_fingerprint("abandon-12");
    let zoo_fingerprint = plaintext_fingerprint("zoo-24");
    let recheck = format!("{ORIGIN}/check#t={}", seed("vector-1", "seal_tag_hex"));
    let stick = vec![("abandon-12.age", abandon), ("zoo-24.age", zoo)];
    let first_entry = match config {
        // Load with-vector-1 first: one .kcr on the stick, so no picker.
        Config::Registry => {
            let mut files = stick;
            files.push(("with-vector-1.kcr", snapshot("with-vector-1")));
            chain(vec![
                home(LOAD_SNAPSHOT),
                insert_stick(files),
                vec![
                    Expect(ScreenId::Wait),
                    Expect(ScreenId::SnapshotLoaded),
                    key(Key::Press),
                    Expect(ScreenId::Home),
                ],
                home(CHECK_A_BACKUP),
                stick_still_in(),
            ])
        }
        Config::Release => chain(vec![home(CHECK_A_BACKUP), insert_stick(stick)]),
    };
    let registrations = move |count: u32| {
        Assert(
            "with a snapshot loaded, the count as of its date; with none, no count",
            Box::new(move |seen| {
                let shown = format!("Registrations: {count}, as of 2026-03-01");
                let any = texts(seen.matched)
                    .iter()
                    .any(|t| t.starts_with("Registrations"));
                match config {
                    Config::Registry => shows(seen.matched, &shown),
                    Config::Release => !any,
                }
            }),
        )
    };
    Scenario {
        name: "check_backup",
        hwrng: HwRngStream::Counting,
        protected: ProtectedFrames::AsDrawn,
        steps: chain(vec![
            boot(),
            // 1. About.
            home(ABOUT),
            vec![
                Expect(ScreenId::About),
                Assert(
                    "About shows the build's registry key state and banners",
                    Box::new(move |seen| {
                        shows(seen.matched, key_state)
                            && shows(seen.matched, "Root filesystem sim")
                            && seen.matched.banners.simulator
                            && seen.matched.banners.test_registry == (config == Config::Registry)
                    }),
                ),
                key(Key::Key1),
                Expect(ScreenId::Home),
            ],
            // 2. abandon-12: KEY2 back Home with a face typed, then an unrecognised entry, then its
            // passphrase by first fours.
            first_entry,
            vec![
                Expect(ScreenId::UsbPick),
                key(Key::Press),
                Expect(ScreenId::PrivacyGate),
                key(Key::Press),
                Expect(ScreenId::BackupCheckEntry),
                offers_back("KEY2 back on an empty entry"),
                Type(String::from("a")),
                key(Key::Key2),
                Expect(ScreenId::Home),
                Assert(
                    "KEY2 drops the backup read, and no write or removal reached the stick",
                    Box::new(|seen| {
                        let hal = seen.app.hal();
                        !seen.app.holds_secrets()
                            && hal.stick_files().contains(&"abandon-12.age")
                            && hal
                                .stick_log()
                                .iter()
                                .all(|access| matches!(access.op, Op::List(_) | Op::Read(_)))
                    }),
                ),
            ],
            home(CHECK_A_BACKUP),
            stick_still_in(),
            vec![
                Expect(ScreenId::UsbPick),
                key(Key::Press),
                Expect(ScreenId::PrivacyGate),
                key(Key::Press),
                Expect(ScreenId::BackupCheckEntry),
            ],
            entries(&wrong),
            vec![
                Expect(ScreenId::BackupCheckEntry),
                Assert(
                    "core's text verbatim, and the first-fours instruction right under it",
                    Box::new(|seen| {
                        let shown = texts(seen.matched);
                        let core = CoreError::Backup(keepcrypt_core::BackupError::PassphraseWords)
                            .to_string();
                        shown.iter().position(|t| *t == core).is_some_and(|at| {
                            shown.get(at + 1)
                                == Some(
                                    &"Type the first four letters of each word, or a whole \
                                      three-letter word.",
                                )
                        })
                    }),
                ),
            ],
            // A passphrase of valid first fours that does not open it: another file's.
            entries(&zoo_typed),
            vec![
                Expect(ScreenId::Wait),
                Expect(ScreenId::BackupCheckEntry),
                Assert(
                    "a wrong passphrase returns to entry, emptied, with core's text; the backup stays",
                    Box::new(|seen| {
                        shows(seen.matched, &CoreError::WrongPassphrase.to_string())
                            && shows(seen.matched, "Backup passphrase, word 1 of 8")
                            && seen.app.holds_secrets()
                    }),
                ),
                offers_back("KEY2 back after a wrong passphrase"),
            ],
            entries(&first_fours(&abandon_passphrase)),
            vec![
                Expect(ScreenId::Wait),
                Expect(ScreenId::BackupCheckResult),
                latest_shows(
                    "the fingerprint is backup.json's",
                    format!("Fingerprint {abandon_fingerprint}"),
                ),
                latest_shows(
                    "the Seal ID is vector-1's",
                    format!("Seal ID {}", seal_id("vector-1")),
                ),
                registrations(1),
                // 3. The re-check QR on request: T only.
                key(Key::Press),
                Expect(ScreenId::BackupCheckRecheckQr),
                latest_shows("the re-check QR carries T and no nonce", recheck),
                key(Key::Key1),
                Expect(ScreenId::BackupCheckResult),
                // 4. The words on request, behind the privacy gate: ABANDON 0001.
                key(Key::Down),
                key(Key::Press),
                Expect(ScreenId::PrivacyGate),
                key(Key::Press),
                Expect(ScreenId::WordsInsert),
                latest_shows("insert 1 is abandon", String::from("abandon")),
                latest_shows("abandon is SeedBook 0001", String::from("SeedBook 0001")),
            ],
            // Back to the result from the last insert, and Done drops the backup.
            (2..=12)
                .flat_map(|_| [key(Key::Key3), Expect(ScreenId::WordsInsert)])
                .collect(),
            vec![
                Assert(
                    "a checked backup has no read-back: Press on its last insert is done",
                    Box::new(|seen| seen.latest.keys.label(Key::Press) == Some("done")),
                ),
                key(Key::Press),
                Expect(ScreenId::BackupCheckResult),
                key(Key::Down),
                key(Key::Down),
                key(Key::Press),
                Expect(ScreenId::Home),
                Assert(
                    "Done drops the checked backup",
                    Box::new(|seen| !seen.app.holds_secrets()),
                ),
            ],
            // A USB fault is named on usb-pick, and so is a backup over 8 KiB, which its read
            // refuses (rule 8); Back returns Home from both.
            home(CHECK_A_BACKUP),
            vec![
                Expect(ScreenId::UsbInsert),
                Step::Fault(Fault::Removed),
                Wait(STICK_SECONDS),
                Expect(ScreenId::UsbPick),
                latest_shows(
                    "a USB fault is the HAL's text",
                    HalError::Removed.text().to_owned(),
                ),
                key(Key::Key1),
                Expect(ScreenId::Home),
            ],
            home(CHECK_A_BACKUP),
            insert_stick(vec![("zz-oversized.age", vec![b'-'; 8 * 1024 + 1])]),
            vec![
                Expect(ScreenId::UsbPick),
                key(Key::Down),
                key(Key::Down),
                key(Key::Press),
                Expect(ScreenId::UsbPick),
                latest_shows(
                    "a backup over 8 KiB is refused by its read",
                    HalError::TooLarge.text().to_owned(),
                ),
                key(Key::Key1),
                Expect(ScreenId::Home),
            ],
            // 5. zoo-24: ZOO 2048, a seal with no registration.
            home(CHECK_A_BACKUP),
            stick_still_in(),
            vec![
                Expect(ScreenId::UsbPick),
                key(Key::Down),
                key(Key::Press),
                Expect(ScreenId::PrivacyGate),
                key(Key::Press),
                Expect(ScreenId::BackupCheckEntry),
            ],
            entries(&zoo_typed),
            vec![
                Expect(ScreenId::Wait),
                Expect(ScreenId::BackupCheckResult),
                latest_shows(
                    "the fingerprint is backup.json's",
                    format!("Fingerprint {zoo_fingerprint}"),
                ),
                registrations(0),
                key(Key::Down),
                key(Key::Press),
                Expect(ScreenId::PrivacyGate),
                key(Key::Press),
                Expect(ScreenId::WordsInsert),
                latest_shows("insert 1 is zoo", String::from("zoo")),
                latest_shows("zoo is SeedBook 2048", String::from("SeedBook 2048")),
            ],
        ]),
    }
}

/// Step 7's restarts (tasks/todo.md, M3 group 8, Step 7; entry 11f), on vector runs. A Cannot check
/// in a first session restarts at the normal minimum, 50 rolls for 12 words; a later collision's
/// report is the newer seal's, since its `Wiped` replaces the kept one; and both restarts keep the
/// seed length: a 24-word Cannot check in a first session restarts at 99 rolls, not 12 words' 50,
/// and the 24-word restart after a collision makes dice-99-words24's seal, not dice-99-words12's.
/// KEY2 on the code grid (the owner's decision of 2026-10-13) closes a trap: with the entry opened
/// before any scan, or after a checker's Stop, nothing else left it but the idle wipe, which gives
/// no collision report and no 99-roll restart. Back on the actions, with the same check, Match
/// found still reports the seal and the restart needs 99 rolls; and after KEY2 and the seal card
/// paged, the mock checker's code for the check QR verifies.
/// With the test key, No on a snapshot's date keeps the check started at Check now: the mock
/// checker's code for the check QR drawn after No verifies.
fn check_restarts(config: Config) -> Scenario {
    let report = |name: &str| format!("{ORIGIN}/register#c={}", seed(name, "seal_code_hashed"));
    let mut steps = chain(vec![
        boot(),
        // A Cannot check in a first 12-word session: 50 rolls again.
        new_seed(Mode::DiceOnly, SeedLength::Words12),
        to_dice(Mode::DiceOnly, 50),
        roll(rolls("coldcard-50")),
        seal_card(),
        cannot_check(),
        to_dice(Mode::DiceOnly, 50),
        // Two collisions in a row: the second report is the newer seal's. Before the first, the
        // trap: Enter go-ahead code before any scan, three symbols typed, KEY2; then a wrong code,
        // code-wrong and KEY2 again, as when the checker said Stop and gave no code.
        roll(rolls("coldcard-50")),
        seal_card(),
        vec![
            key(Key::Press),
            Expect(ScreenId::CodeEntry),
            Type(String::from("7QX")),
            key(Key::Key2),
            Expect(ScreenId::CheckActions),
            key(Key::Key1),
            Expect(ScreenId::SealQr),
            same_check_qr(
                "KEY2 keeps the check: its QR is the one Check now showed",
                2,
            ),
            key(Key::Press),
            Expect(ScreenId::CheckActions),
            key(Key::Press),
            Expect(ScreenId::CodeEntry),
            latest_shows("KEY2 cleared the code typed", String::from("____-____")),
            Step::Code(Code::Wrong),
            Expect(ScreenId::CodeWrong),
            key(Key::Press),
            Expect(ScreenId::CodeEntry),
            key(Key::Key2),
            Expect(ScreenId::CheckActions),
        ],
        match_found(),
        vec![latest_shows(
            "the first collision reports dice-50's seal",
            report("dice-50-words12"),
        )],
        add_fresh_entropy(),
        to_dice(Mode::DiceOnly, 99),
        roll(rolls("coldcard-99")),
        seal_card(),
        match_found(),
        vec![latest_shows(
            "a later collision reports the newer seal, not the kept one",
            report("dice-99-words12"),
        )],
        // 24 words: a Cannot check in a first session, then a collision; each restart keeps the
        // length.
        vec![PowerCycle(HwRngStream::Counting)],
        boot(),
        new_seed(Mode::DiceOnly, SeedLength::Words24),
        to_dice(Mode::DiceOnly, 99),
        roll(rolls("coldcard-99")),
        seal_card(),
        cannot_check(),
        to_dice(Mode::DiceOnly, 99),
        roll(rolls("coldcard-99")),
        seal_card(),
        match_found(),
        add_fresh_entropy(),
        to_dice(Mode::DiceOnly, 99),
        roll(rolls("coldcard-99")),
        vec![
            key(Key::Press),
            Expect(ScreenId::SealImage),
            key(Key::Key3),
            Expect(ScreenId::SealId),
            latest_shows(
                "the restart after a collision keeps 24 words",
                seal_id("dice-99-words24"),
            ),
            // Enter go-ahead code, KEY2, then the seal card paged: the check QR is the one shown
            // before, and the mock checker's code for it verifies.
            key(Key::Key3),
            Expect(ScreenId::SealQr),
            key(Key::Press),
            Expect(ScreenId::CheckActions),
            key(Key::Press),
            Expect(ScreenId::CodeEntry),
            key(Key::Key2),
            Expect(ScreenId::CheckActions),
            key(Key::Key1),
            Expect(ScreenId::SealQr),
            key(Key::Key2),
            Expect(ScreenId::SealId),
            key(Key::Key3),
            Expect(ScreenId::SealQr),
            same_check_qr(
                "after KEY2 and the seal card paged, the check QR is the one shown before",
                3,
            ),
            key(Key::Press),
            Expect(ScreenId::CheckActions),
            key(Key::Press),
        ],
        type_go_ahead(Some(seal_id("dice-99-words24"))),
    ]);
    if config == Config::Registry {
        // No on the date, then the seal card: the code for the check QR drawn after No verifies.
        steps.extend(chain(vec![
            vec![PowerCycle(HwRngStream::Counting)],
            boot(),
            home(LOAD_SNAPSHOT),
            insert_stick(vec![(
                "keepcrypt-registry-2026-03-01.kcr",
                snapshot("with-dice-50"),
            )]),
            vec![
                Expect(ScreenId::Wait),
                Expect(ScreenId::SnapshotLoaded),
                key(Key::Press),
                Expect(ScreenId::Home),
            ],
            new_seed(Mode::DiceOnly, SeedLength::Words12),
            to_dice(Mode::DiceOnly, 50),
            roll(rolls("coldcard-99")),
            vec![
                key(Key::Press),
                Expect(ScreenId::SnapshotDate),
                key(Key::Down),
                key(Key::Press),
                Expect(ScreenId::SealImage),
                key(Key::Key3),
                Expect(ScreenId::SealId),
                key(Key::Key3),
                Expect(ScreenId::SealQr),
                key(Key::Press),
                Expect(ScreenId::CheckActions),
                key(Key::Press),
            ],
            type_go_ahead(Some(seal_id("dice-99-words12"))),
        ]));
    }
    Scenario {
        name: "check_restarts",
        hwrng: HwRngStream::Counting,
        protected: ProtectedFrames::AsDrawn,
        steps,
    }
}

/// Every scenario of `config`, in the order `capture_set` writes them; each one also runs as a
/// test of its own.
fn scenarios(config: Config) -> Vec<Scenario> {
    vec![
        boot_stops(),
        runtime_stop(),
        mixed_12_restarts(),
        drill_12(config),
        skip_and_idle(),
        dice_24_code(),
        wipes_clear_the_stage(),
        check_backup(config),
        check_restarts(config),
    ]
}

/// The capture set's folder of the specimen, in place of a scenario's.
const SPECIMEN: &str = "specimen";

/// The PNG files `capture_set` wrote, each with its scenario.
struct Captures {
    rows: Vec<(&'static str, Shot)>,
}

impl Captures {
    /// The cells that say which capture a row is: its number, scenario, step, screen, class and
    /// what its file holds. No screen text.
    fn cells(number: usize, scenario: &str, shot: &Shot) -> String {
        let (_, placeholder) = shot.file.as_ref().expect("a captured present");
        let holds = match (scenario, placeholder) {
            (SPECIMEN, _) => "specimen: D is keepcrypt.json's public d-00-1f",
            (_, true) => "placeholder",
            (_, false) => "as drawn",
        };
        let class = match shot.id.class() {
            Class::Public => "Public",
            Class::Protected => "Protected",
        };
        let step = match scenario {
            SPECIMEN => String::from("-"),
            _ => shot.step.to_string(),
        };
        format!(
            "<td>{number}</td><td>{scenario}</td><td>{step}</td><td>{}</td><td>{class}</td>\
             <td>{holds}</td>",
            shot.id.name()
        )
    }

    /// One row of the index: the capture's cells, its SHA-256, and a link to its file (with the
    /// image too, when `image`). No screen text.
    fn row(number: usize, scenario: &str, shot: &Shot, image: bool) -> String {
        let (file, _) = shot.file.as_ref().expect("a captured present");
        let path = format!("{scenario}/{file}");
        let link = if image {
            format!(
                "<a href=\"{path}\"><img src=\"{path}\" alt=\"{}\"></a>",
                shot.id.name()
            )
        } else {
            format!("<a href=\"{path}\">{file}</a>")
        };
        let sha256: String = shot.sha256.iter().map(|b| format!("{b:02x}")).collect();
        format!(
            "<tr>{}<td><code>{sha256}</code></td><td>{link}</td></tr>\n",
            Captures::cells(number, scenario, shot)
        )
    }

    /// The static index (Q30 (g)): the configuration and crate version, then the first capture of
    /// every screen (and the specimen), then every capture in order.
    fn index(&self, config: Config) -> String {
        let header = "<tr><th>No.</th><th>Scenario</th><th>Step</th><th>Screen</th>\
                      <th>Class</th><th>File holds</th><th>SHA-256</th><th>File</th></tr>\n";
        let mut first = String::new();
        for id in ScreenId::ALL {
            let mut of_id = self
                .rows
                .iter()
                .enumerate()
                .filter(|(_, (_, shot))| shot.id == id);
            if let Some((at, (scenario, shot))) = of_id.next() {
                first.push_str(&Captures::row(at + 1, scenario, shot, true));
            }
            for (at, (scenario, shot)) in of_id.filter(|(_, (scenario, _))| *scenario == SPECIMEN) {
                first.push_str(&Captures::row(at + 1, scenario, shot, true));
            }
        }
        let every: String = self
            .rows
            .iter()
            .enumerate()
            .map(|(at, (scenario, shot))| Captures::row(at + 1, scenario, shot, false))
            .collect();
        format!(
            "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
             <title>KeepCrypt Pi simulator captures</title>\n<style>body{{font-family:sans-serif}}\
             td,th{{padding:2px 8px;text-align:left}}img{{width:240px;height:240px}}</style>\
             </head><body>\n<h1>KeepCrypt Pi simulator captures</h1>\n<p>Configuration: {}. \
             keepcrypt-pi-sim {}. {} PNG files, each 240 × 240.</p>\n\
             <h2>The first capture of every screen, and the specimen</h2>\n<table>\n{header}{first}\
             </table>\n<h2>Every capture, in order</h2>\n<table>\n{header}{every}</table>\n\
             </body></html>\n",
            config.name(),
            env!("CARGO_PKG_VERSION"),
            self.rows.len()
        )
    }

    /// The rows of the review page, in capture order (a lead decision, M3 commit 21): each
    /// screen's first capture drawn as is (its first capture when all are placeholders, as
    /// reveal-d's are), the specimen, and each scenario's first capture of every QR code it
    /// shows with its string.
    fn reviewed(&self) -> Vec<usize> {
        let placeholder = |shot: &Shot| matches!(shot.file, Some((_, true)));
        let mut rows = BTreeSet::new();
        for id in ScreenId::ALL {
            let mut of_id = self
                .rows
                .iter()
                .enumerate()
                .filter(|(_, (scenario, shot))| *scenario != SPECIMEN && shot.id == id);
            let first = of_id.clone().next();
            let drawn = of_id.find(|(_, (_, shot))| !placeholder(shot));
            rows.extend(drawn.or(first).map(|(at, _)| at));
        }
        rows.extend(
            self.rows
                .iter()
                .position(|(scenario, _)| *scenario == SPECIMEN),
        );
        let mut kinds = BTreeSet::new();
        for (at, (scenario, shot)) in self.rows.iter().enumerate() {
            if shot.qr.is_some() && kinds.insert((*scenario, shot.id.name())) {
                rows.insert(at);
            }
        }
        rows.into_iter().collect()
    }

    /// `scenario` captured as `capture_set` captures it, for the review page's tests: into a
    /// folder of its own under target/tmp, cleared before the run and again after it, so no
    /// capture outlasts the run (Q30 (g): the capture set comes only from `capture_set`). The rows
    /// hold all the page needs; no file is read.
    fn of_run(scenario: Scenario) -> Captures {
        let name = scenario.name;
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join("pi-sim-review-rule")
            .join(name);
        cleared(&dir);
        let counts = run_keeping(scenario, Keep::Captures(dir.clone()));
        cleared(&dir);
        Captures {
            rows: counts.shots.into_iter().map(|shot| (name, shot)).collect(),
        }
    }

    /// The one capture of `id`, or fails the test.
    fn only(&self, id: ScreenId) -> &Shot {
        let mut of_id = self.rows.iter().filter(|(_, shot)| shot.id == id);
        match (of_id.next(), of_id.next()) {
            (Some((_, shot)), None) => shot,
            _ => panic!("one capture of {}", id.name()),
        }
    }

    /// The name of a reviewed capture's copy in review/.
    fn review_file(scenario: &str, shot: &Shot) -> String {
        let (file, _) = shot.file.as_ref().expect("a captured present");
        format!("{scenario}-{file}")
    }

    /// The review page (a lead decision, M3 commit 21), the owner's working view of `rows`: each
    /// capture's cells and its copy in review/, and beside each QR code core's string, the payload
    /// the app drew, to compare with a phone's scan of the image. A string is listed only for a
    /// file that shows its QR code as drawn: a Public one, or a vector run's Protected one, never
    /// a placeholder's. No other screen text.
    fn review(&self, config: Config, rows: &[usize]) -> String {
        let body: String = rows
            .iter()
            .map(|&at| {
                let (scenario, shot) = &self.rows[at];
                let string = match (&shot.file, &shot.qr) {
                    (Some((_, false)), Some(qr)) => format!("<pre>{}</pre>", escaped(qr)),
                    _ => String::new(),
                };
                format!(
                    "<tr>{}<td>{string}</td><td><img src=\"review/{}\" alt=\"{}\"></td></tr>\n",
                    Captures::cells(at + 1, scenario, shot),
                    Captures::review_file(scenario, shot),
                    shot.id.name()
                )
            })
            .collect();
        format!(
            "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
             <title>KeepCrypt Pi simulator review</title>\n<style>body{{font-family:sans-serif}}\
             td,th{{padding:2px 8px;text-align:left;vertical-align:top}}\
             img{{width:240px;height:240px}}\
             pre{{margin:0;max-width:480px;white-space:pre-wrap;word-break:break-all}}</style>\
             </head><body>\n<h1>KeepCrypt Pi simulator review</h1>\n<p>Configuration: {}. \
             keepcrypt-pi-sim {}. {} PNG files in review/, each 240 × 240: each screen's first \
             capture drawn as is (reveal-d's are all placeholders), reveal-d's specimen, and each \
             scenario's first capture of every QR code it draws as is. This page is the owner's \
             working view; the full capture set and index.html are the record. No. is a \
             capture's number there.</p>\n<p>Scan each QR code on the screen with a phone: the \
             decoded text must equal core's string beside it, the payload the app drew. A string \
             is listed only for a Public QR code (check, re-check) or a vector run's Protected one \
             (register, collision report, account, descriptors); a placeholder has none.</p>\n\
             <table>\n<tr><th>No.</th><th>Scenario</th><th>Step</th><th>Screen</th>\
             <th>Class</th><th>File holds</th><th>Core's string</th><th>Capture</th></tr>\n\
             {body}</table>\n</body></html>\n",
            config.name(),
            env!("CARGO_PKG_VERSION"),
            rows.len()
        )
    }
}

/// `text` with HTML's special characters escaped.
fn escaped(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            other => out.push(other),
        }
    }
    out
}

/// Clears `dir`, if it is there.
fn cleared(dir: &Path) {
    match fs::remove_dir_all(dir) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => panic!("cannot clear {}: {error}", dir.display()),
    }
}

#[test]
fn boot_stops_halt_with_cores_startup_verdicts() {
    run(boot_stops());
}

#[test]
fn runtime_stop_halts_and_a_power_cycle_forgets_the_99_roll_minimum() {
    run(runtime_stop());
}

#[test]
fn mixed_12_restarts_keep_99_rolls_through_cannot_check_and_the_idle_wipe() {
    run(mixed_12_restarts());
}

#[test]
fn drill_12_catches_dice_50_before_any_word_and_restarts_at_99() {
    run(drill_12(Config::of_this_build()));
}

#[test]
fn skip_and_idle_skip_drops_the_kept_wiped_and_the_idle_wipe_the_words() {
    run(skip_and_idle());
}

#[test]
fn dice_24_code_reads_back_every_mistake_and_exports() {
    run(dice_24_code());
}

#[test]
fn wipes_clear_the_stage_of_every_secret() {
    run(wipes_clear_the_stage());
}

#[test]
fn check_backup_opens_by_first_fours_and_shows_its_words_on_request() {
    run(check_backup(Config::of_this_build()));
}

#[test]
fn check_restarts_keep_the_length_and_report_the_newest_collision() {
    run(check_restarts(Config::of_this_build()));
}

#[test]
fn every_screen_is_expected() {
    // The union of every scenario's `Expect` steps against the inventory (group 8): all of it with
    // the test key; without it, all but the two screens of a loaded snapshot. Each scenario's test
    // fails on an unmet `Expect`, so every screen counted here is reached.
    let config = Config::of_this_build();
    let mut expected = BTreeSet::new();
    for scenario in scenarios(config) {
        for step in &scenario.steps {
            if let Expect(id) = step {
                expected.insert(id.name());
            }
        }
    }
    let mut inventory: BTreeSet<&str> = ScreenId::ALL.into_iter().map(ScreenId::name).collect();
    if config == Config::Release {
        for unloaded in ["snapshot-loaded", "snapshot-date"] {
            assert!(inventory.remove(unloaded), "{unloaded} is in the inventory");
        }
    }
    assert_eq!(expected, inventory);
}

#[test]
fn drill_12_repeats() {
    // A vector run is reproducible: run twice, it presents the same screens at the same steps, in
    // the same frames, but for the check QR, whose nonce is fresh (with the test key; without it
    // the drill ends before any check).
    let config = Config::of_this_build();
    let first = run_keeping(drill_12(config), Keep::Digests).shots;
    let second = run_keeping(drill_12(config), Keep::Digests).shots;
    assert_eq!(first.len(), second.len());
    let mut check_qrs = 0;
    for (one, two) in first.iter().zip(&second) {
        assert_eq!((one.step, one.id), (two.step, two.id));
        if one.id == ScreenId::SealQr {
            check_qrs += 1;
            assert_ne!(one.sha256, two.sha256, "step {}: a fresh nonce", one.step);
        } else {
            assert_eq!(
                one.sha256,
                two.sha256,
                "step {}: {} drawn alike",
                one.step,
                one.id.name()
            );
        }
    }
    let expected = match config {
        Config::Release => 0,
        Config::Registry => 1,
    };
    assert_eq!(check_qrs, expected);
}

#[test]
#[ignore = "writes the capture set, on request (tasks/todo.md, M3 Q30 (g))"]
fn capture_set() {
    // Every scenario of this configuration, in order, one PNG file per present, under
    // target/tmp/pi-sim-captures/<configuration>/<scenario>/, cleared first; then reveal-d's
    // specimen, the index, and the review page with its copies in review/.
    let config = Config::of_this_build();
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("pi-sim-captures")
        .join(config.name());
    cleared(&root);
    let mut captures = Captures { rows: Vec::new() };
    for scenario in scenarios(config) {
        let name = scenario.name;
        let counts = run_keeping(scenario, Keep::Captures(root.join(name)));
        assert_eq!(
            counts.shots.len(),
            counts.presents,
            "{name}: one file a present"
        );
        // Numbered on across power cycles: every present has a file of its own, and the folder
        // holds those files and nothing else, so no index row names a file another present
        // overwrote.
        let files: BTreeSet<String> = counts
            .shots
            .iter()
            .filter_map(|shot| shot.file.as_ref().map(|(file, _)| file.clone()))
            .collect();
        assert_eq!(
            files.len(),
            counts.presents,
            "{name}: a file name a present"
        );
        let on_disk: BTreeSet<String> = fs::read_dir(root.join(name))
            .expect("the scenario's folder")
            .map(|entry| {
                let entry = entry.expect("an entry");
                entry.file_name().into_string().expect("a UTF-8 name")
            })
            .collect();
        assert_eq!(
            on_disk, files,
            "{name}: the folder holds the presents' files alone"
        );
        captures
            .rows
            .extend(counts.shots.into_iter().map(|shot| (name, shot)));
    }
    // reveal-d, drawn with keepcrypt.json's public D.
    let doc = keepcrypt_json();
    let d = <[u8; 32]>::try_from(hex(&named(&doc["commitment"], "d-00-1f")["d_hex"]))
        .expect("32 bytes");
    let d = hex_groups(&d);
    let banners = Banners {
        test_registry: registry_key_is_test(),
        simulator: true,
    };
    let mut hal = SimHal::new(HwRngStream::Counting);
    hal.capture(root.join(SPECIMEN), ProtectedFrames::AsDrawn, 0);
    Painter::new()
        .present(&mut hal, &reveal_d_specimen(&d, banners))
        .expect("the specimen draws");
    let presents = hal.take_presents();
    let [present] = &presents[..] else {
        panic!("one present of the specimen");
    };
    let captured = present.capture.as_ref().expect("the specimen is captured");
    captures.rows.push((
        SPECIMEN,
        Shot {
            step: 0,
            id: ScreenId::RevealD,
            sha256: Sha256::digest(&captured.png[..]).into(),
            file: Some((captured.file.clone(), captured.placeholder)),
            qr: None,
        },
    ));
    fs::write(root.join("index.html"), captures.index(config)).expect("the index is written");
    // The owner's working view (a lead decision, M3 commit 21): a copy of each reviewed capture
    // in review/, and review.html.
    let reviewed = captures.reviewed();
    let review = root.join("review");
    fs::create_dir(&review).expect("the review folder is made");
    for &at in &reviewed {
        let (scenario, shot) = &captures.rows[at];
        let (file, _) = shot.file.as_ref().expect("a captured present");
        fs::copy(
            root.join(scenario).join(file),
            review.join(Captures::review_file(scenario, shot)),
        )
        .expect("a reviewed capture is copied");
    }
    assert_eq!(
        fs::read_dir(&review).expect("the review folder").count(),
        reviewed.len(),
        "a copy in review/ a reviewed capture"
    );
    fs::write(root.join("review.html"), captures.review(config, &reviewed))
        .expect("the review page is written");
    let screens: BTreeSet<&str> = captures
        .rows
        .iter()
        .map(|(_, shot)| shot.id.name())
        .collect();
    report(format_args!(
        "capture_set: {} configuration, {} PNG files of {} screens, and index.html; review.html \
         shows {} of them, copied into review/",
        config.name(),
        captures.rows.len(),
        screens.len(),
        reviewed.len()
    ));
}

#[test]
fn the_review_page_lists_a_public_qr_string_but_no_throwaway_protected_payload() {
    // A throwaway run to its collision report, captured as capture_set does: the check QR is
    // Public, so the review page lists its string; the collision report QR is Protected and its
    // file the placeholder, so its payload (the destroyed seed's seal code) is neither kept nor
    // on the page, though the placeholder is.
    let name = "throwaway_collision_qr";
    let drawn: Rc<RefCell<Vec<Zeroizing<String>>>> = Rc::default();
    let note = Rc::clone(&drawn);
    let mut steps = chain(vec![
        boot(),
        new_seed(Mode::Mixed, SeedLength::Words12),
        to_dice(Mode::Mixed, 50),
        roll(rolls("coldcard-50")),
        seal_card(),
        match_found(),
    ]);
    steps.push(Assert(
        "the check QR and the collision report QR were drawn",
        Box::new(move |seen| {
            let (Some(check), Some(report)) =
                (seen.record.check_urls.last(), qr_payload(seen.matched))
            else {
                return false;
            };
            let mut note = note.borrow_mut();
            note.push(check.clone());
            note.push(Zeroizing::new(report.to_owned()));
            true
        }),
    ));
    let captures = Captures::of_run(Scenario {
        name,
        hwrng: HwRngStream::Counting,
        protected: ProtectedFrames::Placeholder,
        steps,
    });
    let drawn = drawn.borrow();
    let [check, report] = &drawn[..] else {
        panic!("one check QR and one collision report QR noted");
    };
    let (_, seal_code) = report.split_once("#c=").expect("a collision report URL");
    let seal_qr = captures.only(ScreenId::SealQr);
    assert!(
        seal_qr
            .file
            .as_ref()
            .is_some_and(|(_, placeholder)| !placeholder)
            && seal_qr.qr.as_ref() == Some(check),
        "the Public check QR is captured as drawn, with its payload kept"
    );
    let collision_qr = captures.only(ScreenId::CollisionQr);
    assert!(
        collision_qr
            .file
            .as_ref()
            .is_some_and(|(_, placeholder)| *placeholder)
            && collision_qr.qr.is_none(),
        "the throwaway collision report QR is captured as the placeholder, its payload not kept"
    );
    let reviewed = captures.reviewed();
    let on_page: Vec<ScreenId> = reviewed.iter().map(|&at| captures.rows[at].1.id).collect();
    assert!(
        on_page.contains(&ScreenId::SealQr) && on_page.contains(&ScreenId::CollisionQr),
        "the review page shows both QR screens"
    );
    let page = captures.review(Config::of_this_build(), &reviewed);
    // The check URL's `&` before n, escaped as HTML wants it.
    assert!(
        check.contains("&n=")
            && page.contains(&format!("<pre>{}</pre>", check.replace('&', "&amp;")))
            && !page.contains("&n="),
        "the review page lists the check QR's string, its & escaped"
    );
    assert!(
        !page.contains(report.as_str())
            && !page.contains(&escaped(report))
            && !page.contains(seal_code),
        "the review page holds no part of the throwaway collision report's payload"
    );
}

#[test]
fn the_review_page_lists_a_vector_runs_protected_qr_string() {
    // A dice-only vector run to its collision report, captured as capture_set does: its Protected
    // frames are drawn as is, so the collision report QR's payload, kcr.json's dice-50-words12
    // report, is kept and listed beside its capture, as is the check QR's string, its & escaped.
    let captures = Captures::of_run(Scenario {
        name: "vector_collision_qr",
        hwrng: HwRngStream::Counting,
        protected: ProtectedFrames::AsDrawn,
        steps: chain(vec![
            boot(),
            new_seed(Mode::DiceOnly, SeedLength::Words12),
            to_dice(Mode::DiceOnly, 50),
            roll(rolls("coldcard-50")),
            seal_card(),
            match_found(),
        ]),
    });
    let report = format!(
        "{ORIGIN}/register#c={}",
        seed("dice-50-words12", "seal_code_hashed")
    );
    let collision_qr = captures.only(ScreenId::CollisionQr);
    assert!(
        matches!(collision_qr.file, Some((_, false)))
            && collision_qr
                .qr
                .as_ref()
                .is_some_and(|qr| qr.as_str() == report),
        "the vector run's collision report QR is captured as drawn, with its payload kept"
    );
    let reviewed = captures.reviewed();
    let page = captures.review(Config::of_this_build(), &reviewed);
    let check = format!(
        "<pre>{ORIGIN}/check#t={}&amp;n=",
        seed("dice-50-words12", "seal_tag_hex")
    );
    assert!(
        page.contains(&format!("<pre>{report}</pre>"))
            && page.contains(&check)
            && page.matches("<pre>").count() == 2,
        "the review page lists the vector run's collision report and its check QR's string"
    );
}

#[test]
fn the_review_page_shows_each_screens_first_drawn_capture_the_specimen_and_each_qr_kind() {
    // The review page's rule (a lead decision, M3 commit 21) on rows made up here, with no run and
    // no file: each screen's first capture drawn as is, or its first when all are placeholders
    // (reveal-d); the specimen; each scenario's first capture of every QR code it keeps a string
    // for; each row numbered as in the index, its copy named after its scenario; and a string
    // beside each QR code drawn as is, escaped, never beside a placeholder.
    let check_one = "https://registry.invalid/check#t=0a&n=0b";
    let check_two = "https://registry.invalid/check#t=1a&n=1b";
    let report = "https://registry.invalid/register#c=MADEUPSEALCODE";
    let row = |scenario: &'static str, number: usize, id: ScreenId, placeholder: bool, qr| {
        let qr: Option<&str> = qr;
        (
            scenario,
            Shot {
                step: number,
                id,
                sha256: [0; 32],
                file: Some((format!("{number:03}-{}.png", id.name()), placeholder)),
                qr: qr.map(|qr| Zeroizing::new(qr.to_owned())),
            },
        )
    };
    let captures = Captures {
        rows: vec![
            row("one", 1, ScreenId::Boot, false, None),
            row("one", 2, ScreenId::Boot, false, None),
            row("one", 3, ScreenId::WordsInsert, true, None),
            row("one", 4, ScreenId::SealQr, false, Some(check_one)),
            row("one", 5, ScreenId::SealQr, false, Some(check_one)),
            row("one", 6, ScreenId::CollisionQr, true, None),
            row("two", 1, ScreenId::WordsInsert, false, None),
            row("two", 4, ScreenId::SealQr, false, Some(check_two)),
            row("two", 5, ScreenId::RevealD, true, None),
            row("two", 6, ScreenId::CollisionQr, false, Some(report)),
            row("two", 7, ScreenId::RevealD, true, None),
            row(SPECIMEN, 1, ScreenId::RevealD, false, None),
        ],
    };
    let reviewed = captures.reviewed();
    assert_eq!(reviewed, [0, 3, 6, 7, 8, 9, 11]);
    // Each row: its cells (No. is its place in the index, counting from 1), its string, and its
    // copy, named after its scenario, so one-004 and two-004 stay apart.
    let expected = [
        (
            "<tr><td>1</td><td>one</td><td>1</td><td>boot</td>",
            None,
            "one-001-boot.png",
        ),
        (
            "<tr><td>4</td><td>one</td><td>4</td><td>seal-qr</td>",
            Some("https://registry.invalid/check#t=0a&amp;n=0b"),
            "one-004-seal-qr.png",
        ),
        (
            "<tr><td>7</td><td>two</td><td>1</td><td>words-insert</td>",
            None,
            "two-001-words-insert.png",
        ),
        (
            "<tr><td>8</td><td>two</td><td>4</td><td>seal-qr</td>",
            Some("https://registry.invalid/check#t=1a&amp;n=1b"),
            "two-004-seal-qr.png",
        ),
        (
            "<tr><td>9</td><td>two</td><td>5</td><td>reveal-d</td>",
            None,
            "two-005-reveal-d.png",
        ),
        (
            "<tr><td>10</td><td>two</td><td>6</td><td>collision-qr</td>",
            Some(report),
            "two-006-collision-qr.png",
        ),
        (
            "<tr><td>12</td><td>specimen</td><td>-</td><td>reveal-d</td>",
            None,
            "specimen-001-reveal-d.png",
        ),
    ];
    let page = captures.review(Config::of_this_build(), &reviewed);
    let rows: Vec<&str> = page
        .lines()
        .filter(|line| line.starts_with("<tr><td>"))
        .collect();
    assert_eq!(rows.len(), expected.len(), "one row a reviewed capture");
    for (at, (line, (cells, string, copy))) in rows.iter().zip(expected).enumerate() {
        let string = match string {
            Some(text) => format!("<pre>{text}</pre>"),
            None => String::new(),
        };
        assert!(
            line.starts_with(cells)
                && line.contains(&format!("<td>{string}</td><td><img src=\"review/{copy}\"")),
            "row {at} of the review page"
        );
    }
    assert_eq!(page.matches("<pre>").count(), 3);
    assert!(!page.contains("&n="), "every & on the page is escaped");
    assert_eq!(escaped("<a&\"b>"), "&lt;a&amp;&quot;b&gt;");
    // The page checks the flag again: a placeholder's payload, which the driver never keeps,
    // would still not be listed.
    let hidden = Captures {
        rows: vec![row("three", 1, ScreenId::CollisionQr, true, Some(report))],
    };
    let page = hidden.review(Config::of_this_build(), &[0]);
    assert!(
        !page.contains("<pre>") && !page.contains("MADEUPSEALCODE"),
        "no string beside a placeholder"
    );
}
