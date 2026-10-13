//! The gate scenarios (tasks/todo.md, M3 group 11; build-plan.md M3 gate): scripted runs of the
//! real app on `SimHal`, in the release configuration (`cargo test --workspace`) and the registry
//! configuration (`cargo test -p keepcrypt-pi-sim --features keepcrypt-core/test-registry`).
//!
//! Steps 1-15 and Home's side flows: boot and its stops, Home and About, length and mode, step 4's
//! hwrng intake and its stop, the commitment, the dice, the collision check (snapshot, seal card,
//! go-ahead code, Match found, Cannot check, Skip), the words in insert view and overview, the
//! read-back drill, the wallet summary, the backup to a stick, the watch-only export, the
//! registration, the checklist and power-off; "Load registry snapshot" and "Check a backup";
//! and the halts, restarts and idle steps on the way. Snake, and `mixed_12_restarts` past the
//! words' privacy gate, come with group 10.
//!
//! Test data is public and repeatable (Q30 (a), (c)): the counting hwrng stream, keepcrypt.json's
//! health streams for the stops, and its public dice strings for the vector runs. The vectors come
//! in through `include_str!`; the simulator reads no file.

mod report;
mod scenario;

use keepcrypt_core::{
    Bip39Passphrase, CoreError, HealthFailure, HealthStage, HealthTest, Mode, Platform,
    ReadbackResult, SeedLength, Session, TypedBackupPassphrase, decrypt_backup,
};
use keepcrypt_pi::hal::{HalError, Zeroizing};
use keepcrypt_pi::input::Key;
use keepcrypt_pi::screen::{Class, ScreenId};
use keepcrypt_pi_sim::{Fault, HwRngStream, Present};
use scenario::{Answer, Code, Config, Readback, Scenario, Step, Stick, run};
use serde_json::Value;

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

/// The halt after a black frame, naming `stop` exactly, with nothing held and no Protected
/// element.
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
        Assert(
            "no Protected element after a halt",
            Box::new(|seen| {
                seen.matched
                    .elements
                    .iter()
                    .all(|e| e.class == Class::Public)
            }),
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

/// From readback-done: the wallet summary, steps 11-13 skipped, then (dice only, no step 14)
/// the checklist's two pages and power-off.
fn skip_exports() -> Vec<Step> {
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

/// A throwaway run on the counting stream: the restarts and idle steps of steps 1-7 (Q26, Q29).
fn mixed_12_restarts() -> Scenario {
    Scenario {
        name: "mixed_12_restarts",
        hwrng: HwRngStream::Counting,
        steps: chain(vec![
            boot(),
            new_seed(Mode::Mixed, SeedLength::Words12),
            // 1. Continue is refused before the bar is full (and the probe presses every key). The
            // bar counts health-tested bytes, not credited bits.
            vec![
                Expect(ScreenId::Hwrng),
                Assert(
                    "no Continue before the bar is full",
                    Box::new(|seen| seen.matched.keys.label(Key::Press).is_none()),
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
            // 3. The commitment; coldcard-50 as the rolls.
            vec![
                Wait(QUOTA_SECONDS),
                Assert(
                    "at the quota the bar is full, and the first window credited 2,048 bits",
                    Box::new(|seen| {
                        shows(seen.latest, "[####################]")
                            && shows(seen.latest, "1536 / 1536 bytes health-tested")
                            && shows(seen.latest, "2048 / 512 bits credited")
                    }),
                ),
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
            // 8. A check that passes on the mock checker's code, then the privacy gate before
            // the words.
            roll(rolls("coldcard-99")),
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
/// read-back mistake, then corrected; a wrong confirm pick, a write fault and Retry, then a
/// verified backup the shown passphrase opens; the watch-only QRs of a typed BIP39 passphrase's
/// wallet, equal to core's; the registration QR; the checklist and power-off.
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
            // 4. 24 inserts: the overview on and off, the device swap, the device labels.
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
                key(Key::Press),
                Expect(ScreenId::ReadbackEntry),
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
            ],
            stick_still_in(),
            vec![
                Expect(ScreenId::Wait),
                Expect(ScreenId::BackupVerified),
                Assert(
                    "the stick holds one .age, which the shown passphrase opens to this wallet",
                    Box::new(|seen| {
                        let hal = seen.app.hal();
                        let [name] = hal.stick_files()[..] else {
                            return false;
                        };
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

/// After a wipe: a black frame, then `next` with no Protected element, and nothing held.
fn wiped_to(next: ScreenId) -> Vec<Step> {
    vec![
        Expect(ScreenId::Blank),
        Assert("a black frame first", Box::new(|seen| black(seen.matched))),
        Expect(next),
        Assert(
            "nothing held, and no Protected element, after the wipe",
            Box::new(|seen| {
                !seen.app.holds_secrets()
                    && seen
                        .matched
                        .elements
                        .iter()
                        .all(|e| e.class == Class::Public)
            }),
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
/// secret: both clear the stage, present a black frame and leave no Protected element. On
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
                    "the idle wipe keeps the kept Wiped and clears the screen",
                    Box::new(|seen| {
                        !seen.app.holds_secrets()
                            && seen.app.keeps_wiped()
                            && seen
                                .matched
                                .elements
                                .iter()
                                .all(|e| e.class == Class::Public)
                    }),
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
            // backup-check-entry, with a face typed (BackupCheck, holding the file).
            to_backup_check_entry(false),
            vec![Type(String::from("f"))],
            idle_wipe(),
            to_backup_check_entry(true),
            vec![Type(String::from("f"))],
            vec![Step::Fault(Fault::Buttons), key(Key::Press)],
            halted(HalError::Buttons.text().to_owned()),
        ]),
    }
}

/// Home's About (Q33 (i)) and "Check a backup" (Q32 (b), Q33 (l)): an unrecognised entry is
/// refused with core's text and the screen's own instruction under it; abandon-12's passphrase,
/// typed by first fours, opens it to backup.json's fingerprint; with a snapshot loaded (registry
/// configuration), its seal's registration count as of the snapshot's date; the re-check QR and
/// the words on request; zoo-24's words.
fn check_backup(config: Config) -> Scenario {
    let key_state = match config {
        Config::Release => "Registry key: none pinned in this build",
        Config::Registry => "Registry key: the TEST key",
    };
    let (abandon, abandon_passphrase) = age_file("abandon-12");
    let (zoo, zoo_passphrase) = age_file("zoo-24");
    let mut wrong = first_fours(&abandon_passphrase);
    wrong[0] = String::from("zzzz");
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
    let registrations = Assert(
        "with a snapshot loaded, the count as of its date; with none, no count",
        Box::new(move |seen| {
            let count = shows(seen.matched, "Registrations: 1, as of 2026-03-01");
            let any = texts(seen.matched)
                .iter()
                .any(|t| t.starts_with("Registrations"));
            match config {
                Config::Registry => count,
                Config::Release => !any,
            }
        }),
    );
    Scenario {
        name: "check_backup",
        hwrng: HwRngStream::Counting,
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
            // 2. abandon-12: an unrecognised entry, then its passphrase by first fours.
            first_entry,
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
                registrations,
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
            // 5. zoo-24: ZOO 2048.
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
            entries(&first_fours(&zoo_passphrase)),
            vec![
                Expect(ScreenId::Wait),
                Expect(ScreenId::BackupCheckResult),
                latest_shows(
                    "the fingerprint is backup.json's",
                    format!("Fingerprint {zoo_fingerprint}"),
                ),
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
