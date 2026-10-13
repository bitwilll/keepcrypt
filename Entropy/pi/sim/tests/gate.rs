//! The gate scenarios (tasks/todo.md, M3 group 11; build-plan.md M3 gate): scripted runs of the
//! real app on `SimHal`, in the release configuration (`cargo test --workspace`) and the registry
//! configuration (`cargo test -p keepcrypt-pi-sim --features keepcrypt-core/test-registry`).
//!
//! Steps 1-7 so far: boot and its stops, Home and About, length and mode, step 4's hwrng intake
//! and its stop, the commitment, the dice, and the collision check with its seal card, go-ahead
//! code, Match found, Cannot check and Skip, plus the halts, restarts and idle steps on the way.
//! The words and everything after them (steps 8-15, Home's side flows) come with group 9, Snake
//! with group 10.
//!
//! Test data is public and repeatable (Q30 (a), (c)): the counting hwrng stream, keepcrypt.json's
//! health streams for the stops, and its public dice strings for the vector runs. The vectors come
//! in through `include_str!`; the simulator reads no file.

mod report;
mod scenario;

use keepcrypt_core::{CoreError, HealthFailure, HealthStage, HealthTest, Mode, SeedLength};
use keepcrypt_pi::hal::HalError;
use keepcrypt_pi::input::Key;
use keepcrypt_pi::screen::{Class, ScreenId};
use keepcrypt_pi_sim::{Fault, HwRngStream, Present};
use scenario::{Code, Config, Scenario, Step, run};
use serde_json::Value;

use Step::{Assert, Dice, Expect, PowerCycle, Wait};

/// The boot test's samples.
const BOOT_BYTES: usize = 1_024;
/// One Mixed session's step 4 (core's `HW_BYTES_NEEDED`).
const SESSION_BYTES: usize = 1_536;
/// Long enough for step 4's 24 blocks, one per 100 ms tick.
const QUOTA_SECONDS: u64 = 3;

fn keepcrypt_json() -> Value {
    serde_json::from_str(include_str!("../../../vectors/keepcrypt.json")).expect("keepcrypt.json")
}

fn kcr_json() -> Value {
    serde_json::from_str(include_str!("../../../vectors/kcr.json")).expect("kcr.json")
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

/// kcr.json's Seal ID of the vector seed `name`.
fn seal_id(name: &str) -> String {
    let doc = kcr_json();
    named(&doc["seeds"], name)["seal_id"]
        .as_str()
        .expect("a Seal ID")
        .to_owned()
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
            // 1. Continue is refused before the bar is full (and the probe presses every key).
            vec![
                Expect(ScreenId::Hwrng),
                Assert(
                    "no Continue before the bar is full",
                    Box::new(|seen| seen.matched.keys.label(Key::Press).is_none()),
                ),
            ],
            // 3. The commitment; coldcard-50 as the rolls.
            vec![
                Wait(QUOTA_SECONDS),
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

/// A vector run (Q26): a collision restarts at 99, and Skip reaches the words' privacy gate with
/// its note, dropping the kept `Wiped`.
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
            vec![
                key(Key::Down),
                key(Key::Press),
                Expect(ScreenId::SkipConfirm),
                key(Key::Press),
                Expect(ScreenId::PrivacyGate),
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
            ],
        ]),
    }
}

/// A vector run on the code path (Q30 (c), (d)): Done refused at 98 of 99 rolls, the seal card,
/// a wrong code refused with core's text and the same nonce, then the mock checker's code.
fn dice_24_code() -> Scenario {
    let mut first_98 = rolls("coldcard-99");
    let last = first_98.split_off(98);
    let seal = seal_id("dice-99-words24");
    let shown = seal.clone();
    Scenario {
        name: "dice_24_code",
        hwrng: HwRngStream::Counting,
        steps: chain(vec![
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
        ]),
    }
}

/// The idle wipe and a fault on collision-qr (Q25, Q29): both clear the screen; the idle wipe
/// keeps the kept `Wiped`, the fault's halt drops it.
fn wipes_clear_the_stage() -> Scenario {
    let to_collision_qr = || {
        chain(vec![
            boot(),
            new_seed(Mode::DiceOnly, SeedLength::Words12),
            to_dice(Mode::DiceOnly, 50),
            roll(rolls("coldcard-50")),
            seal_card(),
            match_found(),
        ])
    };
    Scenario {
        name: "wipes_clear_the_stage",
        hwrng: HwRngStream::Counting,
        steps: chain(vec![
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
            to_collision_qr(),
            vec![Step::Fault(Fault::Buttons), key(Key::Press)],
            halted(HalError::Buttons.text().to_owned()),
        ]),
    }
}

/// Home's About (Q33 (i)); Check a backup comes with group 9.
fn check_backup(config: Config) -> Scenario {
    let key_state = match config {
        Config::Release => "Registry key: none pinned in this build",
        Config::Registry => "Registry key: the TEST key",
    };
    Scenario {
        name: "check_backup",
        hwrng: HwRngStream::Counting,
        steps: chain(vec![
            boot(),
            vec![
                key(Key::Down),
                key(Key::Down),
                key(Key::Press),
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
fn skip_and_idle_skip_drops_the_kept_wiped() {
    run(skip_and_idle());
}

#[test]
fn dice_24_code_refuses_a_wrong_code_and_takes_the_checkers() {
    run(dice_24_code());
}

#[test]
fn wipes_clear_the_stage_on_collision_qr() {
    run(wipes_clear_the_stage());
}

#[test]
fn check_backup_about() {
    run(check_backup(Config::of_this_build()));
}
