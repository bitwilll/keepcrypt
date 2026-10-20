//! The safe layer's ceremony through its public calls and through the wire's bytes (tasks/todo.md,
//! M5 groups 8, 9 and 11), in the release configuration (`cargo test -p keepcrypt-ffi`) and the
//! registry configuration (`cargo test -p keepcrypt-ffi --features keepcrypt-core/test-registry`);
//! the tests that need the test key branch on `registry_key_is_test()`, as pi/sim's do.
//!
//! Each test builds its own `Slot`, never the phone's `FFI`. Test data comes from vectors/ only
//! (rule 12): kcr.json's public dice-only gate seeds, snapshots and proofs, braille.json, seal.json,
//! watchonly.json and backup.json's public test files. The ceremonies on the OS source (the verify.py
//! tie, C and D, the backup passphrases) are throwaway seeds, held in memory and never printed.
//! Assertion messages are fixed or name public values only: `Reply`'s `Debug` names its variant
//! alone.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Barrier;
use std::sync::atomic::{AtomicBool, Ordering};

use common::{Json, braille, cbor_bytes, crc32, go_ahead, kcr, proof_ur, ur, watchonly};
use keepcrypt_core::{
    BackupError, CheckError, CoreError, ExtraSource, FaceVerdict, Freshness, Mode, RegistryDate,
    SeedLength, SnapshotError, UrError, WatchOnlyExport, registry_key_is_test,
};
use keepcrypt_ffi::ceremony::{
    Holds, Readback, Refusal, Registry, Reply, Revealed, Slot, StageKind,
};
use keepcrypt_ffi::wire;
use qrcodegen_no_heap::{QrCode, QrCodeEcc, Version};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// kcr.json's `today`: its snapshots and proofs are dated 2026-03-01.
const VECTOR_DAY: u32 = 20260301;
/// A day in M5, when those fixtures read Stale (todo.md, M5 group 11).
const M5_DAY: u32 = 20261017;
/// The shipped verifier (tasks/todo.md, M2).
const VERIFY_PY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tools/verify/verify.py");

/// A slot at home holding nothing.
const HOME: Holds = Holds {
    stage: StageKind::Idle,
    kept: false,
    report: false,
    snapshot: false,
    backup: false,
};
/// A halted slot: nothing held.
const HALTED: Holds = Holds {
    stage: StageKind::Halted,
    kept: false,
    report: false,
    snapshot: false,
    backup: false,
};

/// A call's result, or the test fails naming the reply's variant (never a secret).
fn done<T>(reply: Reply<T>) -> T {
    match reply {
        Reply::Done(made) => made,
        other => panic!("{other:?}"),
    }
}

/// The reply's variant alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Got {
    Done,
    Refused(Refusal),
    Discarded,
    Halted,
}

fn got<T>(reply: Reply<T>) -> Got {
    match reply {
        Reply::Done(_) => Got::Done,
        Reply::Refused(refusal) => Got::Refused(refusal),
        Reply::Discarded => Got::Discarded,
        Reply::Halted => Got::Halted,
    }
}

/// kcr.json's field `field` of gate seed `name`.
fn seed(name: &str, field: &str) -> String {
    kcr().get("seeds").named(name).get(field).text().to_owned()
}

/// kcr.json's rolls of gate seed `name`, as faces.
fn rolls(name: &str) -> Vec<u8> {
    seed(name, "rolls")
        .bytes()
        .map(|digit| digit - b'0')
        .collect()
}

/// kcr.json's snapshot `name`, as bytes.
fn snapshot(name: &str) -> Vec<u8> {
    kcr().get("snapshots").named(name).get("kcr_hex").hex()
}

fn date(yyyymmdd: u32) -> RegistryDate {
    RegistryDate::from_yyyymmdd(yyyymmdd).expect("a date")
}

/// Freshness as kcr.json names it.
fn freshness(name: &str) -> Freshness {
    match name {
        "Current" => Freshness::Current,
        "Stale" => Freshness::Stale,
        "Future" => Freshness::Future,
        other => panic!("no freshness {other}"),
    }
}

/// kcr.json's header of snapshot or proof `name` (its `expect`), at `freshness`: a snapshot's
/// count is its seals, a proof's the entries in its bucket (k).
fn header(section: &str, name: &str, freshness: Freshness) -> Registry {
    let expect = kcr().get(section).named(name).get("expect");
    let count = expect.get(if section == "proofs" { "k" } else { "count" });
    Registry {
        number: expect.get("number").number(),
        date: date(u32::try_from(expect.get("date").number()).expect("YYYYMMDD")),
        count: usize::try_from(count.number()).expect("a count"),
        freshness,
    }
}

/// The seed length a gate seed's words give.
fn length(name: &str) -> SeedLength {
    match seed(name, "mnemonic").split(' ').count() {
        24 => SeedLength::Words24,
        _ => SeedLength::Words12,
    }
}

/// A dice-only ceremony through `finish` on gate seed `name`'s rolls, from `start` on (the kept
/// `Wiped`, if any, sets the minimum).
fn sealed(slot: &Slot, name: &str) {
    done(slot.start(length(name), Mode::DiceOnly));
    done(slot.commit());
    assert_eq!(done(slot.commitment()), None, "no C in dice-only mode");
    done(slot.start_dice());
    for face in rolls(name) {
        done(slot.push_roll(face));
    }
    done(slot.finish());
}

/// Every word on show, page by page.
fn words(slot: &Slot) -> Zeroizing<Vec<String>> {
    let count = done(slot.word_page(1)).count();
    Zeroizing::new(
        (1..=count)
            .map(|position| done(slot.word_page(position)).word().to_owned())
            .collect(),
    )
}

/// Reads every insert back from its own first four letters, as a user at the metal would.
fn read_back_all(slot: &Slot) {
    let count = done(slot.word_page(1)).count();
    for position in 1..=count {
        let letters: Zeroizing<String> = Zeroizing::new(
            done(slot.word_page(position))
                .word()
                .chars()
                .take(4)
                .collect(),
        );
        let readback = done(slot.check_readback(position, &letters));
        assert!(
            matches!(readback, Readback::Match { complete } if complete == (position == count)),
            "insert {position} reads back"
        );
    }
}

/// Up to `to`, on gate seed dice-50-words12 (12 words, dice only): from `start` on. `Restart` is
/// after Match found.
fn drive(slot: &Slot, to: StageKind) {
    if to == StageKind::Idle {
        return;
    }
    done(slot.start(SeedLength::Words12, Mode::DiceOnly));
    if to == StageKind::Collecting {
        return;
    }
    done(slot.commit());
    if to == StageKind::Committed {
        return;
    }
    done(slot.start_dice());
    if to == StageKind::Rolling {
        return;
    }
    for face in rolls("dice-50-words12") {
        done(slot.push_roll(face));
    }
    done(slot.finish());
    match to {
        StageKind::Sealed => {}
        StageKind::Checking => done(slot.start_check()),
        StageKind::Restart => {
            done(slot.start_check());
            done(slot.match_found());
        }
        StageKind::Ready => done(slot.skip_check()),
        other => panic!("no drive to {other:?}"),
    }
}

/// The next ceremony's dice minimum: a start from what the slot keeps, through to the dice.
fn next_minimum(slot: &Slot) -> u16 {
    done(slot.start(SeedLength::Words12, Mode::DiceOnly));
    done(slot.commit());
    done(slot.start_dice());
    done(slot.dice_progress()).minimum
}

/// A check on gate seed `name`, open: `start` from what the slot keeps, the dice, `start_check`.
fn checking(slot: &Slot, name: &str) {
    sealed(slot, name);
    done(slot.start_check());
}

/// One call of the table, by name, and the stages that offer it.
type Call = (&'static str, fn(&Slot) -> Got, &'static [StageKind]);
/// A named case: a call on a slot, or a run up to one.
type Case = (&'static str, fn(&Slot) -> Got);
/// A named way out of a slot, and what the slot holds after it.
type Exit = (&'static str, fn(&Slot) -> Got, Holds);
/// What a read-back should say of faces 1-4.
type Verdicts = [fn(&FaceVerdict) -> bool; 4];

/// Every call but `discard`, `wipe_all` and `holds`, which every stage offers. A stage offers a
/// call even where a precondition of the call's own (enough rolls, the read-back, the passphrase)
/// makes it halt; `reveal_snapshot` needs a loaded snapshot, which no driven stage holds.
fn calls() -> [Call; 37] {
    use StageKind::{Checking, Collecting, Committed, Idle, Ready, Restart, Rolling, Sealed};
    [
        ("self_test", |s| got(s.self_test()), &[Idle]),
        (
            "start",
            |s| got(s.start(SeedLength::Words12, Mode::DiceOnly)),
            &[Idle, Restart],
        ),
        ("hold", |s| got(s.hold(|| ())), &[Idle]),
        (
            "load_snapshot",
            |s| got(s.load_snapshot(&[], VECTOR_DAY)),
            &[Idle],
        ),
        ("open_backup", |s| got(s.open_backup(&[], &[])), &[Idle]),
        (
            "add_extra",
            |s| got(s.add_extra(ExtraSource::InputTiming, &[1])),
            &[Collecting],
        ),
        (
            "device_progress",
            |s| got(s.device_progress()),
            &[Collecting],
        ),
        ("commit", |s| got(s.commit()), &[Collecting]),
        ("commitment", |s| got(s.commitment()), &[Committed]),
        ("start_dice", |s| got(s.start_dice()), &[Committed]),
        ("push_roll", |s| got(s.push_roll(1)), &[Rolling]),
        ("undo_roll", |s| got(s.undo_roll()), &[Rolling]),
        ("dice_progress", |s| got(s.dice_progress()), &[Rolling]),
        ("finish", |s| got(s.finish()), &[Rolling]),
        ("seal", |s| got(s.seal()), &[Sealed, Checking]),
        ("skip_check", |s| got(s.skip_check()), &[Sealed]),
        ("start_check", |s| got(s.start_check()), &[Sealed]),
        ("check_request", |s| got(s.check_request()), &[Checking]),
        (
            "reveal_code",
            |s| got(s.reveal_code("0000-0000")),
            &[Checking],
        ),
        (
            "reveal_snapshot",
            |s| got(s.reveal_snapshot(VECTOR_DAY)),
            &[],
        ),
        (
            "reveal_proof",
            |s| got(s.reveal_proof("ur:x/", VECTOR_DAY)),
            &[Checking],
        ),
        ("match_found", |s| got(s.match_found()), &[Checking]),
        ("cannot_check", |s| got(s.cannot_check()), &[Checking]),
        (
            "collision_report",
            |s| got(s.collision_report()),
            &[Restart],
        ),
        ("word_page", |s| got(s.word_page(1)), &[Ready]),
        (
            "check_readback",
            |s| got(s.check_readback(1, "abc")),
            &[Ready],
        ),
        ("summary", |s| got(s.summary()), &[Ready]),
        (
            "generate_backup_passphrase",
            |s| got(s.generate_backup_passphrase()),
            &[Ready],
        ),
        (
            "backup_passphrase_page",
            |s| got(s.backup_passphrase_page(0)),
            &[Ready],
        ),
        ("backup_challenge", |s| got(s.backup_challenge()), &[Ready]),
        (
            "confirm_backup",
            |s| got(s.confirm_backup([0, 0])),
            &[Ready],
        ),
        ("encrypt_backup", |s| got(s.encrypt_backup()), &[Ready]),
        ("verify_backup", |s| got(s.verify_backup(&[])), &[Ready]),
        ("watch_only", |s| got(s.watch_only(None)), &[Ready]),
        ("registration", |s| got(s.registration()), &[Ready]),
        (
            "reveal_device_leg",
            |s| got(s.reveal_device_leg()),
            &[Ready],
        ),
        ("end", |s| got(s.end()), &[Ready]),
    ]
}

// Each stage's refused calls (todo.md, M5 group 8): a call in a stage that does not offer it is
// the shell's bug and halts, and the halt empties the slot. Each case gets a fresh slot. After
// Match found only the restart and the collision's report are offered: home's other calls halt.
#[test]
fn ffi_a_call_in_a_stage_that_does_not_offer_it_halts() {
    let stages = [
        StageKind::Idle,
        StageKind::Collecting,
        StageKind::Committed,
        StageKind::Rolling,
        StageKind::Sealed,
        StageKind::Checking,
        StageKind::Ready,
        StageKind::Restart,
    ];
    let mut refused = 0;
    for stage in stages {
        for (name, call, offered) in calls() {
            if offered.contains(&stage) {
                continue;
            }
            let slot = Slot::new();
            drive(&slot, stage);
            assert_eq!(slot.holds().stage, stage, "{stage:?}");
            assert_eq!(call(&slot), Got::Halted, "{name} in {stage:?}");
            assert_eq!(slot.holds(), HALTED, "{name} in {stage:?}");
            refused += 1;
        }
    }
    // 37 calls in 8 stages, less the 38 pairs where a stage offers its call.
    assert_eq!(refused, 258);
}

// And the calls each stage offers that change nothing keep it (the rest are the flows below).
#[test]
fn ffi_queries_keep_their_stage() {
    let slot = Slot::new();
    drive(&slot, StageKind::Collecting);
    done(slot.add_extra(ExtraSource::Motion, &[1, 2, 3]));
    assert_eq!(done(slot.device_progress()).required_bits, 0, "dice only");
    assert_eq!(slot.holds().stage, StageKind::Collecting);
    done(slot.commit());
    assert_eq!(done(slot.commitment()), None);
    done(slot.start_dice());
    done(slot.push_roll(6));
    done(slot.undo_roll());
    done(slot.undo_roll());
    let progress = done(slot.dice_progress());
    assert_eq!(
        (progress.rolls, progress.minimum, progress.millibits),
        (0, 50, 0)
    );
    for face in rolls("dice-50-words12") {
        done(slot.push_roll(face));
    }
    assert_eq!(done(slot.dice_progress()).millibits, 50 * 2_585);
    done(slot.finish());
    let seal = done(slot.seal());
    assert_eq!(seal.seal_id(), seed("dice-50-words12", "seal_id"));
    done(slot.start_check());
    assert_eq!(done(slot.seal()), seal, "the same seal while checking");
    let url = done(slot.check_request());
    assert_eq!(
        got(slot.reveal_code("0000-0000")),
        Got::Refused(Refusal::Code(CheckError::WrongCode))
    );
    assert_eq!(
        got(slot.reveal_code("0000")),
        Got::Refused(Refusal::Code(CheckError::MalformedCode))
    );
    assert_eq!(
        done(slot.check_request()),
        url,
        "the same nonce after a refusal"
    );
    assert_eq!(slot.holds().stage, StageKind::Checking);
}

/// "Check a backup" opened at home: backup.json's abandon-12-binary file (work factor 10), with its
/// passphrase's first four letters.
fn open_abandon_12(slot: &Slot) {
    let age = common::backup().get("age_files").named("abandon-12-binary");
    let first_four: Vec<String> = age
        .get("passphrase")
        .text()
        .split(' ')
        .map(|word| word.chars().take(4).collect())
        .collect();
    let entries: Vec<&str> = first_four.iter().map(String::as_str).collect();
    done(slot.open_backup(&age.get("file_hex").hex(), &entries));
}

// Every exit path empties the slot (todo.md, M5 group 11; MA:127): Finish, a discard in every
// stage, Match found and Cannot check (a `Wiped` stays, which holds no seed), and a halt by error,
// which drops the kept `Wiped` too. A halt by panic is keepcrypt-guard's test (M5 commit 12); a
// poisoned lock is ffi_a_poisoned_lock_halts, and a discard during a long call
// ffi_discard_during_call. With "Check a backup" open and, in the test-registry build, a snapshot
// loaded, a halt (an op the table does not hold, an insert past the backup's words) and a wipe
// drop both (todo.md, M5 group 8).
#[test]
fn ffi_every_exit_path_empties_the_slot() {
    let slot = Slot::new();
    drive(&slot, StageKind::Ready);
    done(slot.end());
    assert_eq!(slot.holds(), HOME, "Finish");

    for stage in [
        StageKind::Collecting,
        StageKind::Committed,
        StageKind::Rolling,
        StageKind::Sealed,
        StageKind::Checking,
        StageKind::Ready,
    ] {
        let slot = Slot::new();
        drive(&slot, stage);
        done(slot.discard());
        assert_eq!(slot.holds(), HOME, "a discard in {stage:?}");
    }

    let slot = Slot::new();
    drive(&slot, StageKind::Checking);
    done(slot.match_found());
    let kept = Holds {
        stage: StageKind::Restart,
        kept: true,
        report: true,
        ..HOME
    };
    assert_eq!(slot.holds(), kept, "Match found");
    let report = done(slot.collision_report());
    assert_eq!(report.grouped_code(), seed("dice-50-words12", "seal_code"));
    assert_eq!(report.seal_id(), seed("dice-50-words12", "seal_id"));
    assert!(
        report
            .url()
            .ends_with(&report.grouped_code().replace('-', ""))
    );
    // The idle wipe after it leaves home, the `Wiped` kept: home's calls again, and no report.
    done(slot.discard());
    assert_eq!(
        slot.holds(),
        Holds {
            stage: StageKind::Idle,
            ..kept
        },
        "a discard after Match found"
    );
    done(slot.hold(|| ()));
    assert_eq!(
        got(slot.collision_report()),
        Got::Halted,
        "no report at home"
    );

    let slot = Slot::new();
    drive(&slot, StageKind::Checking);
    done(slot.cannot_check());
    assert_eq!(
        slot.holds(),
        Holds {
            stage: StageKind::Restart,
            kept: true,
            ..HOME
        },
        "Cannot check"
    );

    // Halts by error: a face core refuses, too few rolls, a position outside the seed, an export
    // before the read-back. The first comes after a Stop, so a kept `Wiped` goes with it.
    let halts: [Case; 4] = [
        ("a face of 7", |slot| {
            drive(slot, StageKind::Checking);
            done(slot.match_found());
            drive(slot, StageKind::Rolling);
            got(slot.push_roll(7))
        }),
        ("finish below the minimum", |slot| {
            drive(slot, StageKind::Rolling);
            done(slot.push_roll(1));
            got(slot.finish())
        }),
        ("insert 13 of 12", |slot| {
            drive(slot, StageKind::Ready);
            got(slot.word_page(13))
        }),
        ("an export before the read-back", |slot| {
            drive(slot, StageKind::Ready);
            got(slot.registration())
        }),
    ];
    for (what, halt) in halts {
        let slot = Slot::new();
        assert_eq!(halt(&slot), Got::Halted, "{what}");
        assert_eq!(slot.holds(), HALTED, "{what}");
        assert_eq!(got(slot.discard()), Got::Halted, "{what}: the halt latches");
        assert_eq!(
            got(slot.start(SeedLength::Words12, Mode::DiceOnly)),
            Got::Halted,
            "{what}"
        );
    }

    let exits: [Exit; 3] = [
        (
            "an op the table does not hold",
            |slot| match slot.dispatch(999, &[])[..] {
                [wire::HALTED] => Got::Halted,
                _ => Got::Done,
            },
            HALTED,
        ),
        ("insert 13 of 12", |slot| got(slot.word_page(13)), HALTED),
        ("a wipe", |slot| got(slot.wipe_all()), HOME),
    ];
    let loaded = registry_key_is_test();
    for (what, exit, after) in exits {
        let slot = Slot::new();
        if loaded {
            done(slot.load_snapshot(&snapshot("with-dice-50"), M5_DAY));
        }
        open_abandon_12(&slot);
        assert_eq!(
            slot.holds(),
            Holds {
                snapshot: loaded,
                backup: true,
                ..HOME
            },
            "{what}"
        );
        let want = if after == HOME {
            Got::Done
        } else {
            Got::Halted
        };
        assert_eq!(exit(&slot), want, "{what}");
        assert_eq!(
            slot.holds(),
            after,
            "{what}: the backup and the snapshot go"
        );
    }
}

// "99 after Stop" (todo.md:1404-1406, :3064-3067): Match found keeps the `Wiped`, and the restart
// asks for 99 rolls at 12 words.
#[test]
fn ffi_99_after_stop() {
    let slot = Slot::new();
    checking(&slot, "dice-50-words12");
    done(slot.match_found());
    assert_eq!(next_minimum(&slot), 99);
}

// "99 after Cannot check in the restart after a collision": Cannot check keeps that session's own
// 99-roll minimum, and the report goes.
#[test]
fn ffi_99_after_cannot_check_in_the_restart_after_a_collision() {
    let slot = Slot::new();
    checking(&slot, "dice-50-words12");
    done(slot.match_found());
    checking(&slot, "dice-99-words12");
    done(slot.cannot_check());
    assert_eq!(
        slot.holds(),
        Holds {
            stage: StageKind::Restart,
            kept: true,
            ..HOME
        }
    );
    assert_eq!(next_minimum(&slot), 99);
}

// "99 after an idle wipe following a Stop": the idle wipe is a discard, which keeps the `Wiped`.
#[test]
fn ffi_99_after_an_idle_wipe_following_a_stop() {
    let slot = Slot::new();
    checking(&slot, "dice-50-words12");
    done(slot.match_found());
    assert_eq!(next_minimum(&slot), 99);
    done(slot.discard());
    assert_eq!(next_minimum(&slot), 99);
}

// "50 after Skip": Skip ends the kept `Wiped`, so the next ceremony starts fresh.
#[test]
fn ffi_50_after_skip() {
    let slot = Slot::new();
    checking(&slot, "dice-50-words12");
    done(slot.match_found());
    sealed(&slot, "dice-99-words12");
    done(slot.skip_check());
    assert!(!slot.holds().kept);
    done(slot.end());
    assert_eq!(next_minimum(&slot), 50);
}

// "Every session is Platform::Phone": a phone's quota, 256 credited bits from the OS read in Mixed
// mode (a Pi's is 512, from 0), fresh and in a restart after a Stop.
#[test]
fn ffi_every_session_is_platform_phone() {
    let quota = |slot: &Slot| {
        done(slot.start(SeedLength::Words12, Mode::Mixed));
        let progress = done(slot.device_progress());
        done(slot.discard());
        (progress.credited_bits, progress.required_bits)
    };
    let slot = Slot::new();
    assert_eq!(quota(&slot), (256, 256), "a fresh session");
    checking(&slot, "dice-50-words12");
    done(slot.match_found());
    assert_eq!(quota(&slot), (256, 256), "a restart");
    assert!(slot.holds().kept, "from the kept Wiped");
}

// The slot's own rules (todo.md, M5 group 8; app.rs's home): home is no session and no checked
// backup, so with "Check a backup" open each call that starts something halts and drops it; the
// collision's report is offered at `Restart` alone, not in the restart's own stages; a collision
// replaces a kept `Wiped` (a Cannot check's, with no report, in the test-registry build); a `today`
// no calendar has is the shell's bug and halts; and D, which a dice-only seed does not have, halts
// after the read-back.
#[test]
fn ffi_home_restart_and_input_rules() {
    let starts: [Case; 5] = [
        ("self_test", |slot| got(slot.self_test())),
        ("start", |slot| {
            got(slot.start(SeedLength::Words12, Mode::DiceOnly))
        }),
        ("hold", |slot| got(slot.hold(|| ()))),
        ("load_snapshot", |slot| {
            got(slot.load_snapshot(&[], VECTOR_DAY))
        }),
        ("open_backup", |slot| got(slot.open_backup(&[], &[]))),
    ];
    for (what, call) in starts {
        let slot = Slot::new();
        open_abandon_12(&slot);
        assert_eq!(call(&slot), Got::Halted, "{what} with a backup open");
        assert_eq!(slot.holds(), HALTED, "{what}");
    }

    let slot = Slot::new();
    checking(&slot, "dice-50-words12");
    done(slot.match_found());
    done(slot.start(SeedLength::Words12, Mode::DiceOnly));
    assert_eq!(
        got(slot.collision_report()),
        Got::Halted,
        "no report once the restart has begun"
    );
    assert_eq!(slot.holds(), HALTED);

    if registry_key_is_test() {
        let slot = Slot::new();
        checking(&slot, "dice-99-words12");
        done(slot.cannot_check());
        // A fresh session's Cannot check keeps its own 50-roll minimum, so the restart can be
        // dice-50-words12, which collision-dice-50 holds.
        checking(&slot, "dice-50-words12");
        assert_eq!(
            done(slot.reveal_proof(&proof_ur("collision-dice-50"), VECTOR_DAY)),
            Revealed::Collision(Some(header(
                "proofs",
                "collision-dice-50",
                Freshness::Current
            )))
        );
        assert_eq!(
            slot.holds(),
            Holds {
                stage: StageKind::Restart,
                kept: true,
                report: true,
                ..HOME
            },
            "the collision's Wiped replaced the kept one"
        );
        assert_eq!(
            done(slot.collision_report()).grouped_code(),
            seed("dice-50-words12", "seal_code")
        );
        assert_eq!(next_minimum(&slot), 99);
    }

    let slot = Slot::new();
    assert_eq!(
        got(slot.load_snapshot(&snapshot("with-dice-50"), 20261332)),
        Got::Halted,
        "month 13"
    );
    let slot = Slot::new();
    checking(&slot, "dice-99-words12");
    assert_eq!(
        got(slot.reveal_proof(&proof_ur("clear-empty-bucket"), 20260230)),
        Got::Halted,
        "February 30"
    );
    assert_eq!(slot.holds(), HALTED);

    let slot = Slot::new();
    drive(&slot, StageKind::Ready);
    read_back_all(&slot);
    assert_eq!(
        got(slot.reveal_device_leg()),
        Got::Halted,
        "no D in dice-only mode"
    );
    assert_eq!(slot.holds(), HALTED);
}

/// A value whose drop is observed: the result of a long call that a discard overtook.
struct Observed<'a>(&'a AtomicBool);

impl Drop for Observed<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// What a held call saw: the stage while it ran, what `meanwhile` gave and the stage after it,
/// the call's reply, and whether its result was dropped.
struct Held<M> {
    busy: StageKind,
    meanwhile: (M, StageKind),
    reply: Got,
    dropped: bool,
}

/// Holds a long call at a barrier on a second caller, runs `meanwhile` on this one while the slot
/// is `Busy`, then releases the call. Nothing here can fail before the release, so a failing
/// assertion never leaves the call waiting: the tests assert on what comes back.
fn held_call<M>(slot: &Slot, meanwhile: impl FnOnce(&Slot) -> M) -> Held<M> {
    let entered = Barrier::new(2);
    let release = Barrier::new(2);
    let dropped = AtomicBool::new(false);
    let (busy, meanwhile, reply) = std::thread::scope(|scope| {
        let call = scope.spawn(|| {
            got(slot.hold(|| {
                entered.wait();
                release.wait();
                Observed(&dropped)
            }))
        });
        entered.wait();
        let busy = slot.holds().stage;
        let meanwhile = meanwhile(slot);
        let after = slot.holds().stage;
        release.wait();
        let reply = call.join().expect("the held call returns");
        (busy, (meanwhile, after), reply)
    });
    Held {
        busy,
        meanwhile,
        reply,
        dropped: dropped.load(Ordering::SeqCst),
    }
}

/// A long call's result whose drop panics. A discard that overtook the call leaves its result to be
/// dropped under the slot's lock, so the panic poisons the lock.
struct PanicsOnDrop;

impl Drop for PanicsOnDrop {
    fn drop(&mut self) {
        panic!("a result dropped under the lock panics");
    }
}

// A poisoned lock halts (todo.md, M5 group 8): a long call that a discard overtook drops its result
// under the lock, and a panic in that drop poisons it, so the next call's lock finds the
// PoisonError. It halts there: the kept `Wiped` goes and `Halted` latches, a discard and a start
// included. The panic ends the call's own thread, as it would end the boundary's call.
#[test]
fn ffi_a_poisoned_lock_halts() {
    let slot = Slot::new();
    checking(&slot, "dice-50-words12");
    done(slot.match_found());
    done(slot.discard());
    assert!(slot.holds().kept, "a kept Wiped to drop");
    let (entered, release) = (Barrier::new(2), Barrier::new(2));
    let (discarded, panicked) = std::thread::scope(|scope| {
        let call = scope.spawn(|| {
            got(slot.hold(|| {
                entered.wait();
                release.wait();
                PanicsOnDrop
            }))
        });
        entered.wait();
        let discarded = got(slot.discard());
        release.wait();
        (discarded, call.join().is_err())
    });
    assert_eq!(discarded, Got::Done, "the discard overtook the call");
    assert!(panicked, "the result's drop panicked under the lock");
    assert_eq!(slot.holds(), HALTED, "the poisoned lock halted the slot");
    assert_eq!(got(slot.discard()), Got::Halted, "the halt latches");
    assert_eq!(
        got(slot.start(SeedLength::Words12, Mode::DiceOnly)),
        Got::Halted
    );
}

/// What two long calls gave when a discard or a wipe overtook the first and the second started
/// before the first ended: what `between` gave, each call's reply, and whether the first call's
/// result was dropped.
struct Overtaken {
    between: Got,
    first: Got,
    second: Option<Got>,
    dropped: bool,
}

/// Holds a long call at a barrier, runs `between` on this caller while the slot is `Busy`, then
/// holds a second long call at its own barrier and releases the first while the second still runs,
/// and the second after it. The second starts only from `Idle` (a `hold` anywhere else returns at
/// once and would never reach its barrier), so nothing waits for a call that did not run.
fn overtaken_call(slot: &Slot, between: fn(&Slot) -> Got) -> Overtaken {
    let (entered, release) = (Barrier::new(2), Barrier::new(2));
    let (entered_second, release_second) = (Barrier::new(2), Barrier::new(2));
    let dropped = AtomicBool::new(false);
    let (between, first, second) = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            got(slot.hold(|| {
                entered.wait();
                release.wait();
                Observed(&dropped)
            }))
        });
        entered.wait();
        let between = between(slot);
        let second = (slot.holds().stage == StageKind::Idle).then(|| {
            let second = scope.spawn(|| {
                got(slot.hold(|| {
                    entered_second.wait();
                    release_second.wait();
                }))
            });
            entered_second.wait();
            second
        });
        release.wait();
        let first = first.join().expect("the first call returns");
        let second = second.map(|second| {
            release_second.wait();
            second.join().expect("the second call returns")
        });
        (between, first, second)
    });
    Overtaken {
        between,
        first,
        second,
        dropped: dropped.load(Ordering::SeqCst),
    }
}

// A discard never waits for a long call (todo.md, M5 group 8): with the call held at a barrier, a
// discard takes the lock at once; the call's result is dropped and it returns Discarded; the slot
// is Idle, keeps its `Wiped`, and the next start works. The same with a wipe, which drops the
// `Wiped` too. Any other call while Busy halts. A call nothing interrupts gives its result. And a
// discard or a wipe starts a new generation: the call it overtook drops its result even when a
// second long call has started since and holds the slot `Busy` again, and the second gives its own.
#[test]
fn ffi_discard_during_call() {
    // At home with a kept `Wiped`: Match found, then the idle wipe.
    let stopped = || {
        let slot = Slot::new();
        checking(&slot, "dice-50-words12");
        done(slot.match_found());
        done(slot.discard());
        slot
    };

    let slot = stopped();
    let held = held_call(&slot, |slot| got(slot.discard()));
    assert_eq!(held.busy, StageKind::Busy);
    assert_eq!(
        held.meanwhile,
        (Got::Done, StageKind::Idle),
        "a discard at once"
    );
    assert_eq!(
        (held.reply, held.dropped),
        (Got::Discarded, true),
        "a discard"
    );
    assert_eq!(
        slot.holds(),
        Holds {
            kept: true,
            report: true,
            ..HOME
        }
    );
    assert_eq!(
        next_minimum(&slot),
        99,
        "the kept Wiped survives the discard"
    );

    let slot = stopped();
    let held = held_call(&slot, |slot| got(slot.wipe_all()));
    assert_eq!(held.busy, StageKind::Busy);
    assert_eq!(
        held.meanwhile,
        (Got::Done, StageKind::Idle),
        "a wipe at once"
    );
    assert_eq!((held.reply, held.dropped), (Got::Discarded, true), "a wipe");
    assert_eq!(slot.holds(), HOME);
    assert_eq!(next_minimum(&slot), 50, "the wipe took the kept Wiped");

    let slot = stopped();
    let held = held_call(&slot, |slot| got(slot.device_progress()));
    assert_eq!(held.busy, StageKind::Busy);
    assert_eq!(
        held.meanwhile,
        (Got::Halted, StageKind::Halted),
        "a call while Busy"
    );
    assert_eq!((held.reply, held.dropped), (Got::Halted, true), "a halt");
    assert_eq!(slot.holds(), HALTED);

    let slot = Slot::new();
    let held = held_call(&slot, |_| ());
    assert_eq!(held.busy, StageKind::Busy);
    assert_eq!(
        (held.reply, held.dropped),
        (Got::Done, true),
        "dropped with its reply"
    );
    assert_eq!(slot.holds(), HOME);

    let overtaking: [Case; 2] = [
        ("a discard", |slot| got(slot.discard())),
        ("a wipe", |slot| got(slot.wipe_all())),
    ];
    for (what, between) in overtaking {
        let slot = stopped();
        let overtaken = overtaken_call(&slot, between);
        assert_eq!(overtaken.between, Got::Done, "{what}");
        assert_eq!(
            (overtaken.first, overtaken.dropped),
            (Got::Discarded, true),
            "{what}: the overtaken call drops its result"
        );
        assert_eq!(
            overtaken.second,
            Some(Got::Done),
            "{what}: the call started since gives its own"
        );
        assert_eq!(slot.holds().stage, StageKind::Idle, "{what}");
    }
}

// The test's own helpers first, each against vectors/: the JSON reader, CRC-32, the CBOR byte
// string head and the UR encoder (watchonly.json), and the mock checker's go-ahead code (kcr.json's
// seeds, each with seal vector 1's nonce).
#[test]
fn ffi_test_helpers_match_their_vectors() {
    let doc = watchonly();
    for case in doc.get("crc32").list() {
        let want = u32::from_str_radix(case.get("crc32").text(), 16).expect("hex");
        assert_eq!(crc32(&case.get("data_hex").hex()), want);
    }
    let mut strings = 0;
    for case in doc.get("cbor").list() {
        let item = case.get("item");
        if item.has("bytes") {
            assert_eq!(cbor_bytes(&item.get("bytes").hex()), case.get("hex").hex());
            strings += 1;
        }
    }
    assert!(strings > 0, "CBOR byte strings checked");
    for case in doc.get("ur").list() {
        let text = ur(case.get("type").text(), &case.get("cbor_hex").hex());
        assert_eq!(text, case.get("ur").text());
    }
    assert_eq!(kcr().get("today").number(), u64::from(VECTOR_DAY));
    for case in kcr().get("seeds").list() {
        let url = format!(
            "https://registry.invalid/check#t={}&n={}",
            case.get("seal_tag_hex").text(),
            case.get("nonce_hex").text()
        );
        assert_eq!(go_ahead(&url), case.get("go_ahead_compact").text());
    }
    let parsed =
        Json::parse("{\"a\": [null, true, false, 7, \"\\u00e9\\ud83d\\ude00\\n\"], \"b\": {}}");
    let items = parsed.get("a").list();
    assert!(items[0].is_null() && items[1].flag() && !items[2].flag());
    assert_eq!(items[3].number(), 7);
    assert_eq!(items[4].text(), "\u{e9}\u{1f600}\n");
    assert!(!parsed.get("b").has("a"));
}

/// braille.json's dots of `letter`, dot d at bit d - 1.
fn dots_of(letter: char) -> u8 {
    let cells = braille().get("cells").get("letters").list();
    let cell = cells
        .iter()
        .find(|cell| cell.get("letter").text().starts_with(letter))
        .expect("a letter's cell");
    cell.get("dots")
        .text()
        .bytes()
        .map(|digit| 1u8 << (digit - b'1'))
        .sum()
}

// The vectors (todo.md, M5 group 11): each gate seed through `start`, its rolls and `finish` gives
// kcr.json's Seal ID and T; after the go-ahead code a checker computes from the drawn check request
// (lessons 2), the words are its mnemonic and every page is braille.json's insert: the SeedBook
// number, faces 1-5 with their dots, blanks, the lighter face and mirror partners, the device and
// sequence. After the read-back, the registration QR carries its seal code.
#[test]
fn ffi_dice_vectors() {
    for name in ["dice-50-words12", "dice-99-words12", "dice-99-words24"] {
        let slot = Slot::new();
        sealed(&slot, name);
        let seal = done(slot.seal());
        assert_eq!(seal.seal_id(), seed(name, "seal_id"), "{name}");
        assert_eq!(seal.tag().to_hex(), seed(name, "seal_tag_hex"), "{name}");
        done(slot.start_check());
        let code = go_ahead(&done(slot.check_request()));
        assert_eq!(
            done(slot.reveal_code(&code)),
            Revealed::Clear(None),
            "{name}"
        );
        assert!(!slot.holds().kept);
        let mnemonic = seed(name, "mnemonic");
        assert_eq!(words(&slot).join(" "), mnemonic, "{name}");
        let positions = braille().get("positions").get(match length(name) {
            SeedLength::Words24 => "words_24",
            SeedLength::Words12 => "words_12",
        });
        for (slot_of, word) in positions.list().iter().zip(mnemonic.split(' ')) {
            let position = u8::try_from(slot_of.get("position").number()).expect("1-24");
            let page = done(slot.word_page(position));
            let entry = braille()
                .get("words")
                .list()
                .iter()
                .find(|entry| entry.get("word").text() == word)
                .expect("a BIP39 word");
            assert_eq!(
                u64::from(page.seedbook()),
                entry.get("number").number(),
                "{word}"
            );
            assert_eq!(u64::from(page.device()), slot_of.get("device").number());
            assert_eq!(u64::from(page.devices()), slot_of.get("devices").number());
            assert_eq!(u64::from(page.sequence()), slot_of.get("sequence").number());
            let lighter = entry.get("lighter_face");
            for (i, face) in page.faces().iter().enumerate() {
                let letter = entry.get("faces").list()[i].text_or_null();
                let want = letter.map(|text| text.chars().next().expect("a letter"));
                assert_eq!(face.letter(), want, "{word} face {}", i + 1);
                assert_eq!(face.is_blank(), want.is_none());
                let dots = match want {
                    Some(letter) => dots_of(letter),
                    None => 0,
                };
                assert_eq!(face.dots(), dots, "{word} face {}", i + 1);
                let lighter_here =
                    !lighter.is_null() && lighter.number() == u64::try_from(i + 1).expect("1-5");
                assert_eq!(face.is_lighter(), lighter_here, "{word} face {}", i + 1);
                let mirror = entry.get("mirror_partners").list()[i]
                    .text_or_null()
                    .map(|text| text.chars().next().expect("a letter"));
                assert_eq!(face.mirror_partner(), mirror, "{word} face {}", i + 1);
            }
        }
        read_back_all(&slot);
        let registration = done(slot.registration());
        assert_eq!(
            registration.grouped_code(),
            seed(name, "seal_code"),
            "{name}"
        );
        assert_eq!(registration.seal_id(), seed(name, "seal_id"));
        done(slot.end());
        assert_eq!(slot.holds(), HOME);
    }
}

/// C or D as verify.py reads it: 16 groups of 4 hex digits on one line (todo.md:4262-4267), sized
/// once, with no formatted copy left behind.
fn hex_groups(bytes: &[u8]) -> Zeroizing<String> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = Zeroizing::new(String::with_capacity(80));
    for (i, pair) in bytes.chunks(2).enumerate() {
        if i > 0 {
            text.push(' ');
        }
        for byte in pair {
            text.push(char::from(DIGITS[usize::from(byte >> 4)]));
            text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
    }
    text
}

// Mixed mode on the OS source (todo.md, M5 group 11; pi/sim's verify_py_tie): C, D and the rolls
// typed into `python3 -I verify.py mixed --words 12` give the words and the Seal ID the FFI showed.
// The run is a throwaway seed: everything stays in memory, and the message is fixed.
#[test]
fn ffi_verify_py_tie() {
    let slot = Slot::new();
    done(slot.start(SeedLength::Words12, Mode::Mixed));
    done(slot.add_extra(ExtraSource::InputTiming, &[0, 1, 2, 3]));
    done(slot.commit());
    let c = done(slot.commitment()).expect("C in Mixed mode");
    done(slot.start_dice());
    let typed = seed("dice-50-words12", "rolls");
    for face in rolls("dice-50-words12") {
        done(slot.push_roll(face));
    }
    done(slot.finish());
    let seal_id = done(slot.seal()).seal_id().to_owned();
    done(slot.skip_check());
    let shown = words(&slot);
    read_back_all(&slot);
    let d = done(slot.reveal_device_leg());
    let input = Zeroizing::new(format!(
        "{}\n{}\n{typed}\n\n",
        hex_groups(&c).as_str(),
        hex_groups(&d[..]).as_str()
    ));
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
    let stdout = Zeroizing::new(output.stdout);
    let text = std::str::from_utf8(&stdout);
    let tied = match text {
        Ok(text) => {
            let inserts: Vec<&str> = text
                .lines()
                .filter_map(|line| line.strip_prefix("insert: ")?.split_whitespace().nth(7))
                .collect();
            let seal = text
                .lines()
                .find_map(|line| line.strip_prefix("seal-id: ")?.split_whitespace().next());
            output.status.success() && inserts == *shown && seal == Some(seal_id.as_str())
        }
        Err(_) => false,
    };
    assert!(
        tied,
        "verify.py mixed recomputes the words and the Seal ID shown from C, D and the rolls"
    );
}

// The test registry's drill (todo.md, M5 group 11; the gate's "a Stop wipes them"): with-dice-50
// loaded, its Stale warning at an M5 date, catches dice-50-words12's rolls before any word page:
// Match found by itself, the report of the destroyed seed, and a restart that needs 99 rolls,
// whose seed the same snapshot clears. A release build pins no key: the snapshot is refused.
#[test]
fn ffi_drill_12() {
    let slot = Slot::new();
    let loaded = slot.load_snapshot(&snapshot("with-dice-50"), M5_DAY);
    if !registry_key_is_test() {
        assert_eq!(
            got(loaded),
            Got::Refused(Refusal::Core(CoreError::NoRegistryKey))
        );
        assert_eq!(slot.holds(), HOME, "nothing loaded");
        return;
    }
    let registry = done(loaded);
    let with_dice_50 = header("snapshots", "with-dice-50", Freshness::Stale);
    assert_eq!(registry, with_dice_50);
    checking(&slot, "dice-50-words12");
    assert_eq!(
        done(slot.reveal_snapshot(M5_DAY)),
        Revealed::Collision(Some(with_dice_50))
    );
    assert_eq!(
        slot.holds(),
        Holds {
            stage: StageKind::Restart,
            kept: true,
            report: true,
            snapshot: true,
            ..HOME
        },
        "no words: the seed is gone"
    );
    assert_eq!(
        done(slot.collision_report()).grouped_code(),
        seed("dice-50-words12", "seal_code")
    );
    assert_eq!(next_minimum(&slot), 99, "Add fresh entropy: 0 / 99");
    done(slot.discard());
    checking(&slot, "dice-99-words12");
    assert_eq!(
        done(slot.reveal_snapshot(M5_DAY)),
        Revealed::Clear(Some(with_dice_50))
    );
    assert_eq!(words(&slot).join(" "), seed("dice-99-words12", "mnemonic"));
    assert!(
        !slot.holds().kept,
        "a passed check ends the 99-roll minimum"
    );
}

// The go-ahead QR paths (todo.md, M5 group 11): clear-empty-bucket's UR reveals dice-99-words12's
// words, Stale at an M5 date and Current at its own; a proof for another bucket is refused and the
// check stays; collision-dice-50 gives a collision; QR text that is no UR is refused. A wrong typed
// code is refused, then the right one reveals, in either build. A release build refuses every
// proof for want of a key, and the check stays.
#[test]
fn ffi_proof_paths() {
    let clear = proof_ur("clear-empty-bucket");
    let clear_at = |freshness| header("proofs", "clear-empty-bucket", freshness);
    let slot = Slot::new();
    checking(&slot, "dice-99-words12");
    let url = done(slot.check_request());
    assert_eq!(
        got(slot.reveal_code("ZZZZ-ZZZZ")),
        Got::Refused(Refusal::Code(CheckError::WrongCode))
    );
    if !registry_key_is_test() {
        for text in [clear.as_str(), "not a ur"] {
            assert_eq!(
                got(slot.reveal_proof(text, M5_DAY)),
                Got::Refused(Refusal::Core(CoreError::NoRegistryKey))
            );
        }
        assert_eq!(
            done(slot.check_request()),
            url,
            "the check stays, with its nonce"
        );
        assert_eq!(
            done(slot.reveal_code(&go_ahead(&url))),
            Revealed::Clear(None)
        );
        return;
    }
    assert_eq!(
        got(slot.reveal_proof("not a ur", M5_DAY)),
        Got::Refused(Refusal::Core(CoreError::Snapshot(SnapshotError::Ur(
            UrError::NotUr
        ))))
    );
    assert_eq!(
        done(slot.reveal_proof(&clear, M5_DAY)),
        Revealed::Clear(Some(clear_at(Freshness::Stale)))
    );
    assert_eq!(words(&slot).join(" "), seed("dice-99-words12", "mnemonic"));

    let slot = Slot::new();
    checking(&slot, "dice-99-words12");
    assert_eq!(
        done(slot.reveal_proof(&clear, VECTOR_DAY)),
        Revealed::Clear(Some(clear_at(Freshness::Current)))
    );

    let slot = Slot::new();
    checking(&slot, "dice-50-words12");
    let url = done(slot.check_request());
    assert_eq!(
        got(slot.reveal_proof(&clear, VECTOR_DAY)),
        Got::Refused(Refusal::Code(CheckError::WrongBucket))
    );
    assert_eq!(
        done(slot.check_request()),
        url,
        "the check stays, with its nonce"
    );
    assert_eq!(
        done(slot.reveal_proof(&proof_ur("collision-dice-50"), VECTOR_DAY)),
        Revealed::Collision(Some(header(
            "proofs",
            "collision-dice-50",
            Freshness::Current
        )))
    );
    assert_eq!(
        slot.holds(),
        Holds {
            stage: StageKind::Restart,
            kept: true,
            report: true,
            ..HOME
        }
    );

    let slot = Slot::new();
    checking(&slot, "dice-50-words12");
    let url = done(slot.check_request());
    assert_eq!(
        got(slot.reveal_code("ZZZZ-ZZZZ")),
        Got::Refused(Refusal::Code(CheckError::WrongCode))
    );
    assert_eq!(
        done(slot.reveal_code(&go_ahead(&url))),
        Revealed::Clear(None)
    );
}

// Freshness against the shell's date (todo.md, M5 group 8; lessons 3): Current, Stale (day 31) and
// Future (day 1 ahead) for a loaded snapshot and a verified proof, at kcr.json's own date. Test
// registry only; a release build refuses them all (ffi_no_registry_key).
#[test]
fn ffi_freshness() {
    if !registry_key_is_test() {
        return;
    }
    for (name, want) in [
        ("current-day-30", Freshness::Current),
        ("stale-day-31", Freshness::Stale),
        ("future-day-1", Freshness::Future),
    ] {
        for section in ["snapshots", "proofs"] {
            let expect = kcr().get(section).named(name).get("expect");
            assert_eq!(
                freshness(expect.get("freshness").text()),
                want,
                "{section} {name}"
            );
        }
        let slot = Slot::new();
        assert_eq!(
            done(slot.load_snapshot(&snapshot(name), VECTOR_DAY)),
            header("snapshots", name, want),
            "snapshot {name}"
        );
        let slot = Slot::new();
        checking(&slot, "dice-50-words12");
        assert_eq!(
            done(slot.reveal_proof(&proof_ur(name), VECTOR_DAY)),
            Revealed::Clear(Some(header("proofs", name, want))),
            "proof {name}"
        );
    }
}

// No registry key in a release build (todo.md:3069-3070; M5 group 11): every snapshot and every
// proof in kcr.json, the UR cases' text included, is refused with NoRegistryKey before any byte is
// read, and nothing is loaded. The test-registry build pins the test key.
#[test]
fn ffi_no_registry_key() {
    if registry_key_is_test() {
        let slot = Slot::new();
        done(slot.load_snapshot(&snapshot("small"), VECTOR_DAY));
        assert!(slot.holds().snapshot);
        return;
    }
    let no_key = Got::Refused(Refusal::Core(CoreError::NoRegistryKey));
    let slot = Slot::new();
    for case in kcr().get("snapshots").list() {
        assert_eq!(
            got(slot.load_snapshot(&case.get("kcr_hex").hex(), VECTOR_DAY)),
            no_key
        );
    }
    assert_eq!(slot.holds(), HOME);
    checking(&slot, "dice-50-words12");
    for case in kcr().get("proofs").list() {
        let text = if case.has("ur") {
            case.get("ur").text().to_owned()
        } else {
            ur("keepcrypt-proof", &cbor_bytes(&case.get("kcp1_hex").hex()))
        };
        assert_eq!(got(slot.reveal_proof(&text, VECTOR_DAY)), no_key);
    }
    assert_eq!(slot.holds().stage, StageKind::Checking);
}

/// Opens `file` with verify.py's own age reader (tools/verify, loaded by path as vectorgen.py
/// does) under `passphrase`, and returns its plaintext's `created-by:` app and version and its
/// fingerprint: public values. The passphrase goes in on stdin, never on a command line.
fn verify_py_opens(file: &[u8], passphrase: &str) -> String {
    const OPEN: &str = "import importlib.util, sys\n\
        spec = importlib.util.spec_from_file_location('verify', sys.argv[1])\n\
        verify = importlib.util.module_from_spec(spec)\n\
        spec.loader.exec_module(verify)\n\
        passphrase, _, data = sys.stdin.buffer.read().partition(b'\\n')\n\
        words, fingerprint, app, version = verify.backup_plaintext_parse(verify.age_decrypt(data, passphrase))\n\
        sys.stdout.write('%s %d.%d.%d %s' % ((app,) + tuple(version) + (fingerprint.hex(),)))\n";
    let mut open = Command::new("python3")
        .args(["-I", "-c", OPEN, VERIFY_PY])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("python3 starts");
    let mut input = Zeroizing::new(Vec::with_capacity(passphrase.len() + 1 + file.len()));
    input.extend_from_slice(passphrase.as_bytes());
    input.push(b'\n');
    input.extend_from_slice(file);
    open.stdin
        .take()
        .expect("its stdin")
        .write_all(&input)
        .expect("the input is written");
    let output = open.wait_with_output().expect("python3 ends");
    assert!(
        output.status.success(),
        "verify.py's reader opens the backup"
    );
    String::from_utf8(output.stdout).expect("ASCII")
}

/// The passphrase's display copy, both pages.
fn passphrase(slot: &Slot) -> Zeroizing<Vec<String>> {
    let mut words = Zeroizing::new(Vec::with_capacity(8));
    for page in 0..2 {
        let text = done(slot.backup_passphrase_page(page));
        words.extend(text.split(' ').map(str::to_owned));
    }
    assert_eq!(words.len(), 8);
    words
}

/// The confirm's right picks: in each question, the choice that is the passphrase's word there.
fn right_picks(slot: &Slot, passphrase: &[String]) -> [u8; 2] {
    let challenge = done(slot.backup_challenge());
    challenge.questions().each_ref().map(|question| {
        let word = &passphrase[usize::from(question.position() - 1)];
        let at = question
            .choices()
            .iter()
            .position(|choice| choice == word)
            .expect("one choice is the word");
        u8::try_from(at).expect("0-3")
    })
}

// The backup round trip (todo.md, M5 group 11; the gate's "backup round trip passes"): the
// generated passphrase, page by page, and its 2-of-4 confirm (a wrong pick keeps the display copy;
// a second passphrase halts before the confirm and after it, which would void the paper copy);
// `encrypt_backup`, then `verify_backup` of the saved bytes (a changed byte is refused and the words
// stay); verify.py's own reader opens it, `keepcrypt-android 0.0.0` with the summary's fingerprint;
// and "Check a backup" with first-four entries: an entry that names no word is refused before
// scrypt, a wrong passphrase after it, and the right one gives the same fingerprint, Seal ID and
// words, until Done or a discard drops them.
#[test]
fn ffi_backup_round_trip() {
    let name = "dice-99-words12";
    let slot = Slot::new();
    sealed(&slot, name);
    let seal_id = done(slot.seal()).seal_id().to_owned();
    done(slot.skip_check());
    read_back_all(&slot);
    let fingerprint = done(slot.summary()).fingerprint();
    done(slot.generate_backup_passphrase());
    assert_eq!(
        got(slot.generate_backup_passphrase()),
        Got::Halted,
        "a second one halts"
    );

    let slot = Slot::new();
    sealed(&slot, name);
    done(slot.skip_check());
    read_back_all(&slot);
    done(slot.generate_backup_passphrase());
    let right = right_picks(&slot, &passphrase(&slot));
    let wrong = [(right[0] + 1) % 4, right[1]];
    assert!(!done(slot.confirm_backup(wrong)), "a wrong pick");
    assert_eq!(
        done(slot.backup_passphrase_page(0)).split(' ').count(),
        4,
        "the copy stays"
    );
    assert!(done(slot.confirm_backup(right)));
    assert_eq!(slot.holds().stage, StageKind::Ready);
    assert_eq!(
        got(slot.generate_backup_passphrase()),
        Got::Halted,
        "a second one after the confirm halts"
    );

    let slot = Slot::new();
    sealed(&slot, name);
    done(slot.skip_check());
    read_back_all(&slot);
    done(slot.generate_backup_passphrase());
    let right = right_picks(&slot, &passphrase(&slot));
    assert!(done(slot.confirm_backup(right)));
    assert_eq!(
        got(slot.backup_passphrase_page(0)),
        Got::Halted,
        "the copy is gone"
    );

    let slot = Slot::new();
    sealed(&slot, name);
    done(slot.skip_check());
    read_back_all(&slot);
    done(slot.generate_backup_passphrase());
    assert_eq!(
        got(slot.encrypt_backup()),
        Got::Halted,
        "before the confirm"
    );

    let slot = Slot::new();
    sealed(&slot, name);
    done(slot.skip_check());
    read_back_all(&slot);
    assert_eq!(
        done(slot.summary()).fingerprint(),
        fingerprint,
        "the same seed"
    );
    done(slot.generate_backup_passphrase());
    let passphrase = passphrase(&slot);
    let right = right_picks(&slot, &passphrase);
    assert!(done(slot.confirm_backup(right)));
    let file = done(slot.encrypt_backup());
    let saved = file.bytes().to_vec();
    assert!(file.name().starts_with("keepcrypt-backup-") && file.name().ends_with(".age"));
    done(slot.verify_backup(&saved));
    let mut changed = saved.clone();
    let middle = changed.len() / 2;
    changed[middle] ^= 0x01;
    assert!(matches!(
        got(slot.verify_backup(&changed)),
        Got::Refused(Refusal::Core(
            CoreError::Backup(_) | CoreError::WrongPassphrase
        ))
    ));
    assert_eq!(slot.holds().stage, StageKind::Ready, "the words stay");
    let opened = verify_py_opens(&saved, &passphrase.join(" "));
    let hex4: String = fingerprint
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(opened, format!("android 0.0.0 {hex4}"));
    done(slot.end());

    let entries: Zeroizing<Vec<String>> = Zeroizing::new(
        passphrase
            .iter()
            .map(|word| word.chars().take(4).collect())
            .collect(),
    );
    let typed: Vec<&str> = entries.iter().map(String::as_str).collect();
    let mut unknown = typed.clone();
    unknown[3] = "zzzz";
    assert_eq!(
        got(slot.open_backup(&saved, &unknown)),
        Got::Refused(Refusal::Core(CoreError::Backup(
            BackupError::PassphraseWords
        ))),
        "refused before scrypt"
    );
    let mut swapped = typed.clone();
    swapped.swap(0, 1);
    if swapped != typed {
        assert_eq!(
            got(slot.open_backup(&saved, &swapped)),
            Got::Refused(Refusal::Core(CoreError::WrongPassphrase))
        );
    }
    assert_eq!(slot.holds(), HOME);
    let opened = done(slot.open_backup(&saved, &typed));
    assert_eq!(opened.fingerprint, fingerprint);
    assert_eq!(opened.seal.seal_id(), seal_id);
    assert_eq!(
        slot.holds(),
        Holds {
            backup: true,
            ..HOME
        }
    );
    assert_eq!(words(&slot).join(" "), seed(name, "mnemonic"));
    done(slot.end());
    assert_eq!(slot.holds(), HOME, "Done");
    done(slot.open_backup(&saved, &typed));
    done(slot.discard());
    assert_eq!(slot.holds(), HOME, "a discard");
}

// The metal read-back drill (BP:327; todo.md, M5 group 11): a mirror-pair misread, a letter read on
// a blank face and a missed letter are each named face by face; a mismatch clears its insert; and
// no export opens before every insert has read back.
#[test]
fn ffi_readback_drill() {
    let name = "dice-99-words12";
    let mnemonic = seed(name, "mnemonic");
    let words: Vec<&str> = mnemonic.split(' ').collect();
    let at = |word: &str| {
        let index = words
            .iter()
            .position(|w| *w == word)
            .expect("a word of the seed");
        u8::try_from(index + 1).expect("1-12")
    };
    let slot = Slot::new();
    sealed(&slot, name);
    done(slot.skip_check());
    let misreads: [(&str, &str, Verdicts); 3] = [
        // various: r read as its mirror image w.
        (
            "various",
            "vawi",
            [
                is_ok,
                is_ok,
                |v| matches!(v, FaceVerdict::MirrorMisread),
                is_ok,
            ],
        ),
        // day: a letter read on its blank fourth face.
        (
            "day",
            "days",
            [is_ok, is_ok, is_ok, |v| {
                matches!(v, FaceVerdict::ShouldBeBlank)
            }],
        ),
        // various: its fourth face read as blank.
        (
            "various",
            "var",
            [is_ok, is_ok, is_ok, |v| {
                matches!(v, FaceVerdict::ShouldHaveLetter)
            }],
        ),
    ];
    for (word, typed, verdicts) in misreads {
        let Readback::Mismatch(mismatch) = done(slot.check_readback(at(word), typed)) else {
            panic!("{typed} for {word} is a mismatch");
        };
        for (face, (verdict, want)) in mismatch.faces().iter().zip(verdicts).enumerate() {
            assert!(want(verdict), "{typed} for {word}, face {}", face + 1);
        }
    }
    read_back_all(&slot);
    assert!(matches!(
        done(slot.check_readback(at("various"), "vawi")),
        Readback::Mismatch(_)
    ));
    assert!(
        matches!(
            done(slot.check_readback(1, "vari")),
            Readback::Match { complete: true }
        ),
        "the cleared insert reads back again"
    );

    let exports: [Case; 4] = [
        ("generate_backup_passphrase", |s| {
            got(s.generate_backup_passphrase())
        }),
        ("watch_only", |s| got(s.watch_only(None))),
        ("registration", |s| got(s.registration())),
        ("reveal_device_leg", |s| got(s.reveal_device_leg())),
    ];
    for (export, call) in exports {
        let slot = Slot::new();
        done(slot.start(SeedLength::Words12, Mode::Mixed));
        done(slot.commit());
        done(slot.start_dice());
        for face in rolls(name) {
            done(slot.push_roll(face));
        }
        done(slot.finish());
        done(slot.skip_check());
        for position in 1..12 {
            let letters: Zeroizing<String> = Zeroizing::new(
                done(slot.word_page(position))
                    .word()
                    .chars()
                    .take(4)
                    .collect(),
            );
            done(slot.check_readback(position, &letters));
        }
        assert_eq!(
            call(&slot),
            Got::Halted,
            "{export} before the last insert reads back"
        );
        assert_eq!(slot.holds(), HALTED);
    }
    let slot = Slot::new();
    done(slot.start(SeedLength::Words12, Mode::Mixed));
    done(slot.commit());
    done(slot.start_dice());
    for face in rolls(name) {
        done(slot.push_roll(face));
    }
    done(slot.finish());
    done(slot.skip_check());
    read_back_all(&slot);
    for (export, call) in exports {
        assert_eq!(call(&slot), Got::Done, "{export} after the read-back");
    }
    assert_eq!(
        got(slot.watch_only(Some(""))),
        Got::Refused(Refusal::Core(CoreError::EmptyPassphrase))
    );
    assert!(done(slot.watch_only(Some("TREZOR"))).passphrase_used());
}

fn is_ok(verdict: &FaceVerdict) -> bool {
    matches!(verdict, FaceVerdict::Ok)
}

// The dispatcher (the re-plan's M5-21): the calls whose reply is the status byte alone, on a
// dice-only run to a Stop and its restart; an op the table does not hold, an input that is not its
// layout and a call in the wrong stage each halt, and the halt latches. The other ops' layouts are
// the ffi_wire tests below.
#[test]
fn ffi_dispatch_status_ops() {
    let slot = Slot::new();
    let status = |op: u32, input: &[u8]| slot.dispatch(op, input)[..].to_vec();
    assert_eq!(status(wire::SELF_TEST, &[]), [wire::OK]);
    assert_eq!(status(wire::START, &[12, 2]), [wire::OK]);
    assert_eq!(status(wire::ADD_EXTRA, &[1, 9, 9]), [wire::OK]);
    assert_eq!(status(wire::ADD_EXTRA, &[2]), [wire::OK]);
    assert_eq!(status(wire::COMMIT, &[]), [wire::OK]);
    assert_eq!(status(wire::START_DICE, &[]), [wire::OK]);
    assert_eq!(status(wire::PUSH_ROLL, &[6]), [wire::OK]);
    assert_eq!(status(wire::UNDO_ROLL, &[]), [wire::OK]);
    for face in rolls("dice-50-words12") {
        assert_eq!(status(wire::PUSH_ROLL, &[face]), [wire::OK]);
    }
    assert_eq!(status(wire::FINISH, &[]), [wire::OK]);
    assert_eq!(status(wire::START_CHECK, &[]), [wire::OK]);
    assert_eq!(status(wire::MATCH_FOUND, &[]), [wire::OK]);
    assert_eq!(status(wire::START, &[24, 2]), [wire::OK]);
    assert_eq!(status(wire::DISCARD, &[]), [wire::OK]);
    assert_eq!(slot.holds().stage, StageKind::Idle);
    assert!(slot.holds().kept);
    assert_eq!(status(wire::WIPE_ALL, &[]), [wire::OK]);
    assert_eq!(slot.holds(), HOME);
    for (op, input) in [
        (999, &[][..]),
        (wire::START, &[13, 2][..]),
        (wire::START, &[12, 3][..]),
        (wire::START, &[12, 2, 0][..]),
        (wire::COMMIT, &[][..]),
    ] {
        let slot = Slot::new();
        assert_eq!(slot.dispatch(op, input)[..], [wire::HALTED], "op {op}");
        assert_eq!(slot.holds(), HALTED, "op {op}");
        assert_eq!(
            slot.dispatch(wire::WIPE_ALL, &[])[..],
            [wire::HALTED],
            "op {op}"
        );
    }
}

/// The registry's origin in every QR's text until M9 (core's seal module).
const ORIGIN: &str = "https://registry.invalid";

/// The go-ahead result of a typed code that reveals (wire.rs): clear, with no registry header.
const CLEAR: [u8; 2] = [0, 0];

/// A dispatched call's `OK` reply, without its status byte; another status fails the test, naming
/// the op and that byte alone.
fn wired(slot: &Slot, op: u32, input: &[u8]) -> Zeroizing<Vec<u8>> {
    let reply = slot.dispatch(op, input);
    assert_eq!(reply.first(), Some(&wire::OK), "op {op}");
    Zeroizing::new(reply[1..].to_vec())
}

/// A text field (wire.rs): its length in one byte, then its bytes.
fn text_field(text: &str) -> Vec<u8> {
    let mut field = vec![u8::try_from(text.len()).expect("a text")];
    field.extend_from_slice(text.as_bytes());
    field
}

/// `day` (YYYYMMDD) as an input's date, then `rest`.
fn dated(day: u32, rest: &[u8]) -> Vec<u8> {
    let mut input = day.to_be_bytes().to_vec();
    input.extend_from_slice(rest);
    input
}

/// `text`'s QR matrix (wire.rs's layout) from qrcodegen-no-heap's own output at pi/app's settings
/// (pi/app/src/ui/qr.rs): versions 1-11, low error correction boosted, the encoder's mask.
fn qr_matrix(text: &str) -> Vec<u8> {
    let len = Version::new(11).buffer_len();
    let (mut temp, mut out) = (vec![0; len], vec![0; len]);
    let qr = QrCode::encode_text(
        text,
        &mut temp,
        &mut out,
        QrCodeEcc::Low,
        Version::MIN,
        Version::new(11),
        None,
        true,
    )
    .expect("fits version 11");
    let side = usize::try_from(qr.size()).expect("21-61");
    let mut bits = vec![0u8; (side * side).div_ceil(8)];
    for y in 0..side {
        for x in 0..side {
            let module = (i32::try_from(x).expect("x"), i32::try_from(y).expect("y"));
            if qr.get_module(module.0, module.1) {
                let i = y * side + x;
                bits[i / 8] |= 0x80 >> (i % 8);
            }
        }
    }
    let mut matrix = vec![u8::try_from(side).expect("21-61")];
    matrix.extend(bits);
    matrix
}

/// A QR matrix's version and error correction level, from its side and its format modules (0, 8)
/// and (1, 8) as pi/app's tests read them: L is 01, M 00, Q 11 and H 10 once the format mask's 1
/// and 0 there are undone.
fn version_and_level(matrix: &[u8]) -> (u8, char) {
    let side = usize::from(matrix[0]);
    let dark = |x: usize, y: usize| {
        let i = y * side + x;
        matrix[1 + i / 8] & (0x80 >> (i % 8)) != 0
    };
    let level = match (!dark(0, 8), dark(1, 8)) {
        (false, true) => 'L',
        (false, false) => 'M',
        (true, true) => 'Q',
        (true, false) => 'H',
    };
    ((matrix[0] - 17) / 4, level)
}

/// braille.json's text rule over its cells (UEB grade 1): a number sign opens each run of digits,
/// digit d is letter "jabcdefghi"[d]'s cell, a letter a-j right after a digit takes the grade 1
/// indicator first, and a letter, a space or a hyphen ends the run.
fn braille_text(text: &str) -> String {
    let cells = braille().get("cells");
    let letter = |c: char| {
        cells
            .get("letters")
            .list()
            .iter()
            .find(|cell| cell.get("letter").text().starts_with(c))
            .expect("a letter's cell")
            .get("cell")
            .text()
            .to_owned()
    };
    let sign = |name: &str| cells.get("signs").named(name).get("cell").text().to_owned();
    let mut out = String::new();
    let mut digits = false;
    for c in text.chars() {
        match c {
            '0'..='9' => {
                if !digits {
                    out.push_str(&sign("number_sign"));
                    digits = true;
                }
                let d = usize::from(u8::try_from(c).expect("ASCII") - b'0');
                out.push_str(&letter(char::from(b"jabcdefghi"[d])));
            }
            ' ' | '-' => {
                digits = false;
                out.push_str(&sign(if c == ' ' { "space" } else { "hyphen" }));
            }
            _ => {
                if digits && ('a'..='j').contains(&c) {
                    out.push_str(&sign("grade1_indicator"));
                }
                digits = false;
                out.push_str(&letter(c));
            }
        }
    }
    out
}

/// The seal card's grid (wire.rs) from T by seal.json's spec: the 32 bits of T[1..5], most
/// significant first, fill columns 0-3 row by row and column 7 - c mirrors c; row r is byte r and
/// column c its bit 7 - c.
fn grid_rows(tag: &[u8]) -> [u8; 8] {
    let bits = u32::from_be_bytes([tag[1], tag[2], tag[3], tag[4]]);
    std::array::from_fn(|row| {
        let left = u8::try_from((bits >> (28 - 4 * row)) & 0xf).expect("4 bits");
        let right = (0..4).fold(0, |right, c| right | (((left >> c) & 1) << (3 - c)));
        (left << 4) | right
    })
}

/// The seal card (wire.rs) of a seal with tag T and `seal_id`: the grid from T, T[0] mod 8, the
/// Seal ID and its braille by braille.json's text rule, lowercase.
fn seal_card(tag: &[u8], seal_id: &str) -> Vec<u8> {
    let mut card = grid_rows(tag).to_vec();
    card.push(tag[0] % 8);
    card.extend_from_slice(seal_id.as_bytes());
    card.extend(text_field(&braille_text(&seal_id.to_ascii_lowercase())));
    card
}

/// seal.json's vector for `mnemonic`.
fn seal_vector(mnemonic: &str) -> &'static Json {
    let vectors = common::seal().get("vectors").list();
    let found: Vec<&Json> = vectors
        .iter()
        .filter(|vector| vector.get("mnemonic").text() == mnemonic)
        .collect();
    assert_eq!(found.len(), 1, "one seal vector");
    found[0]
}

/// seal.json's own card of a vector, field by field: its grid rows ('#' filled), colour index,
/// Seal ID and Seal ID braille.
fn seal_json_card(vector: &Json) -> Vec<u8> {
    let mut card: Vec<u8> = vector
        .get("grid")
        .list()
        .iter()
        .map(|row| {
            row.text()
                .chars()
                .fold(0, |byte, c| (byte << 1) | u8::from(c == '#'))
        })
        .collect();
    card.push(u8::try_from(vector.get("colour_index").number()).expect("0-7"));
    card.extend_from_slice(vector.get("seal_id").text().as_bytes());
    card.extend(text_field(vector.get("seal_id_braille").text()));
    card
}

/// A face's letter in braille.json, as the word page's byte: ASCII, 0 for none.
fn ascii(letter: Option<char>) -> u8 {
    match letter {
        Some(letter) => u8::try_from(letter).expect("ASCII"),
        None => 0,
    }
}

/// Insert `position`'s word page (wire.rs) of `word` in a `count`-word phrase, from braille.json:
/// its device, devices and sequence, its SeedBook number, and faces 1-5 with their dots, the
/// lighter face and the mirror partners.
fn word_page(word: &str, position: u8, count: u8) -> Vec<u8> {
    let positions =
        braille()
            .get("positions")
            .get(if count == 24 { "words_24" } else { "words_12" });
    let at = &positions.list()[usize::from(position - 1)];
    let entry = braille()
        .get("words")
        .list()
        .iter()
        .find(|entry| entry.get("word").text() == word)
        .expect("a BIP39 word");
    let byte = |json: &Json| u8::try_from(json.number()).expect("a byte");
    let mut page = vec![
        position,
        count,
        byte(at.get("device")),
        byte(at.get("devices")),
        byte(at.get("sequence")),
    ];
    let number = u16::try_from(entry.get("number").number()).expect("1-2048");
    page.extend_from_slice(&number.to_be_bytes());
    page.extend(text_field(word));
    let first = |json: &Json| {
        json.text_or_null()
            .map(|text| text.chars().next().expect("a letter"))
    };
    let lighter = entry.get("lighter_face");
    for face in 0..5 {
        let letter = first(&entry.get("faces").list()[face]);
        let dots = match letter {
            Some(letter) => dots_of(letter),
            None => 0,
        };
        let lighter_here =
            !lighter.is_null() && lighter.number() == u64::try_from(face + 1).expect("1-5");
        let mirror = first(&entry.get("mirror_partners").list()[face]);
        page.extend([ascii(letter), dots, u8::from(lighter_here), ascii(mirror)]);
    }
    page
}

/// A registry header (wire.rs) of kcr.json's `expect`, as `header` gives it.
fn header_field(registry: Registry) -> Vec<u8> {
    let mut field = registry.number.to_be_bytes().to_vec();
    field.extend(registry.date.yyyymmdd().to_be_bytes());
    field.extend(
        u32::try_from(registry.count)
            .expect("a count")
            .to_be_bytes(),
    );
    field.push(match registry.freshness {
        Freshness::Current => 0,
        Freshness::Stale => 1,
        Freshness::Future => 2,
    });
    field
}

/// The watch-only reply (wire.rs) of `export`: its summary, its passphrase flag, and the matrices
/// of its account QR text and of its two descriptors on two lines.
fn watch_only_reply(export: &WatchOnlyExport) -> Vec<u8> {
    let mut reply = export.fingerprint().to_vec();
    reply.extend(text_field(export.first_address()));
    reply.push(u8::from(export.passphrase_used()));
    let account = qr_matrix(export.qr_text());
    let descriptors = qr_matrix(&format!(
        "{}\n{}",
        export.receive_descriptor(),
        export.change_descriptor()
    ));
    // pi/app's measured codes for these payloads: version 8 at L, and version 11 at L.
    assert_eq!(version_and_level(&account), (8, 'L'));
    assert_eq!(version_and_level(&descriptors), (11, 'L'));
    reply.extend(account);
    reply.extend(descriptors);
    reply
}

// The wire tests' own helpers first, each against vectors/: braille.json's text cases and
// seal.json's Seal ID braille; seal.json's grids and colours from T, and its vectors' whole cards;
// and the QR helper at the versions and levels pi/app's tests measured for the check, register and
// re-check URLs of seal.json's vector 1 and its go-ahead nonce.
#[test]
fn ffi_wire_helpers_match_their_vectors() {
    for case in braille().get("text").list() {
        assert_eq!(
            braille_text(case.get("text").text()),
            case.get("cells").text()
        );
    }
    for vector in common::seal().get("vectors").list() {
        let id = vector.get("seal_id").text();
        let tag = vector.get("seal_tag_hex").hex();
        assert_eq!(
            braille_text(&id.to_ascii_lowercase()),
            vector.get("seal_id_braille").text()
        );
        assert_eq!(seal_card(&tag, id), seal_json_card(vector), "{id}");
    }
    let vector = &common::seal().get("vectors").list()[0];
    let tag = vector.get("seal_tag_hex").text();
    let nonce = vector.get("go_ahead").get("nonce_hex").text();
    let code = vector.get("seal_code_hashed").text();
    for (url, measured) in [
        (format!("{ORIGIN}/check#t={tag}&n={nonce}"), (6, 'L')),
        (format!("{ORIGIN}/register#c={code}"), (4, 'M')),
        (format!("{ORIGIN}/check#t={tag}"), (5, 'L')),
    ] {
        assert_eq!(version_and_level(&qr_matrix(&url)), measured, "{url}");
    }
}

// A dice-only ceremony over the wire (todo.md, M5 group 9), byte for byte, on gate seeds
// dice-50-words12 and dice-99-words24: the device leg's progress (none in dice-only mode) and no C;
// the dice counts; the seal card from kcr.json's T and Seal ID with braille.json's braille; the
// check QR; refused codes 2 and 1, then the go-ahead result; every word page from braille.json, 24
// words on device 1 of 2 and 2 of 2; the read-back; the summary; the registration QR with
// kcr.json's code; and the watch-only export with and without a BIP39 passphrase, an empty one
// refused (18). Each QR matrix is qrcodegen-no-heap's own for the same text, at the version and
// level pi/app's tests measured for its payload.
#[test]
fn ffi_wire_dice_ceremony() {
    for name in ["dice-50-words12", "dice-99-words24"] {
        let (count, minimum): (u8, u16) = match length(name) {
            SeedLength::Words24 => (24, 99),
            SeedLength::Words12 => (12, 50),
        };
        let slot = Slot::new();
        assert_eq!(slot.dispatch(wire::START, &[count, 2])[..], [wire::OK]);
        assert_eq!(wired(&slot, wire::DEVICE_PROGRESS, &[])[..], [0; 16]);
        assert_eq!(slot.dispatch(wire::COMMIT, &[])[..], [wire::OK]);
        assert!(wired(&slot, wire::COMMITMENT, &[]).is_empty(), "no C");
        assert_eq!(slot.dispatch(wire::START_DICE, &[])[..], [wire::OK]);
        let faces = rolls(name);
        for &face in &faces {
            assert_eq!(slot.dispatch(wire::PUSH_ROLL, &[face])[..], [wire::OK]);
        }
        let rolled = u16::try_from(faces.len()).expect("rolls");
        let mut progress = rolled.to_be_bytes().to_vec();
        progress.extend(minimum.to_be_bytes());
        progress.extend((u32::from(rolled) * 2_585).to_be_bytes());
        assert_eq!(wired(&slot, wire::DICE_PROGRESS, &[])[..], progress[..]);
        assert_eq!(slot.dispatch(wire::FINISH, &[])[..], [wire::OK]);

        let tag = seed(name, "seal_tag_hex");
        let card = seal_card(&common::hex(&tag), &seed(name, "seal_id"));
        assert_eq!(wired(&slot, wire::SEAL, &[])[..], card[..], "{name}");
        assert_eq!(slot.dispatch(wire::START_CHECK, &[])[..], [wire::OK]);
        assert_eq!(wired(&slot, wire::SEAL, &[])[..], card[..], "checking");
        let url = done(slot.check_request());
        assert!(url.starts_with(&format!("{ORIGIN}/check#t={tag}&n=")));
        let check = wired(&slot, wire::CHECK_REQUEST, &[]);
        assert_eq!(check[..], qr_matrix(&url)[..]);
        assert_eq!(version_and_level(&check), (6, 'L'));
        assert_eq!(
            slot.dispatch(wire::REVEAL_CODE, b"ZZZZ-ZZZZ")[..],
            [wire::REFUSED, 2]
        );
        assert_eq!(
            slot.dispatch(wire::REVEAL_CODE, b"0000")[..],
            [wire::REFUSED, 1]
        );
        assert_eq!(
            wired(&slot, wire::REVEAL_CODE, go_ahead(&url).as_bytes())[..],
            CLEAR
        );

        let mnemonic = seed(name, "mnemonic");
        for (position, word) in (1..=count).zip(mnemonic.split(' ')) {
            assert_eq!(
                wired(&slot, wire::WORD_PAGE, &[position])[..],
                word_page(word, position, count)[..],
                "{name} insert {position}"
            );
        }
        for (position, word) in (1..=count).zip(mnemonic.split(' ')) {
            let mut input = vec![position];
            input.extend(word.bytes().take(4));
            assert_eq!(
                wired(&slot, wire::CHECK_READBACK, &input)[..],
                [0, u8::from(position == count)],
                "{name} insert {position}"
            );
        }
        let summary = done(slot.summary());
        let mut expect = summary.fingerprint().to_vec();
        expect.extend(text_field(summary.first_address()));
        assert_eq!(wired(&slot, wire::SUMMARY, &[])[..], expect[..]);
        let registration = wired(&slot, wire::REGISTRATION, &[]);
        let code = seed(name, "seal_code_hashed");
        assert_eq!(
            registration[..],
            qr_matrix(&format!("{ORIGIN}/register#c={code}"))[..]
        );
        assert_eq!(version_and_level(&registration), (4, 'M'));

        let export = done(slot.watch_only(None));
        assert_eq!(
            (export.fingerprint(), export.first_address()),
            (summary.fingerprint(), summary.first_address())
        );
        assert_eq!(
            wired(&slot, wire::WATCH_ONLY, &[0])[..],
            watch_only_reply(&export)[..]
        );
        let other = done(slot.watch_only(Some("TREZOR")));
        assert!(other.passphrase_used() && other.fingerprint() != summary.fingerprint());
        assert_eq!(
            wired(&slot, wire::WATCH_ONLY, b"\x01TREZOR")[..],
            watch_only_reply(&other)[..]
        );
        assert_eq!(
            slot.dispatch(wire::WATCH_ONLY, &[1])[..],
            [wire::REFUSED, 18]
        );
        assert_eq!(slot.dispatch(wire::END, &[])[..], [wire::OK]);
        assert_eq!(slot.holds(), HOME);
    }
}

// Mixed mode on the OS source over the wire (todo.md, M5 group 9): a phone's 256 of 256 credited
// bits; C and D, 32 bytes each, the safe layer's own, with C = SHA-256("KCE/v1/commit" || D)
// (CLAUDE.md's domain constants). A throwaway seed: compared in memory, under fixed messages.
#[test]
fn ffi_wire_mixed_commitment_and_device_leg() {
    let slot = Slot::new();
    assert_eq!(slot.dispatch(wire::START, &[12, 1])[..], [wire::OK]);
    let mut progress = 256u64.to_be_bytes().to_vec();
    progress.extend(256u64.to_be_bytes());
    assert_eq!(wired(&slot, wire::DEVICE_PROGRESS, &[])[..], progress[..]);
    assert_eq!(slot.dispatch(wire::COMMIT, &[])[..], [wire::OK]);
    let c = wired(&slot, wire::COMMITMENT, &[]);
    let shown = done(slot.commitment()).expect("C in Mixed mode");
    assert!(c[..] == shown[..], "C: its 32 bytes");
    done(slot.start_dice());
    for face in rolls("dice-50-words12") {
        done(slot.push_roll(face));
    }
    done(slot.finish());
    done(slot.skip_check());
    read_back_all(&slot);
    let d = wired(&slot, wire::REVEAL_DEVICE_LEG, &[]);
    let revealed = done(slot.reveal_device_leg());
    assert!(d[..] == revealed[..], "D: its 32 bytes");
    let recomputed = Sha256::new()
        .chain_update(b"KCE/v1/commit")
        .chain_update(&d[..])
        .finalize();
    assert!(
        recomputed[..] == c[..],
        "C = SHA-256(\"KCE/v1/commit\" || D)"
    );
}

// "Check a backup" over the wire (todo.md, M5 group 9): backup.json's abandon-12 and zoo-24 files
// (work factor 10), opened with their passphrases' first four letters, give watchonly.json's
// fingerprints, the backup's seal card (abandon-12's is seal.json's vector 1, field for field) and
// its re-check QR, and word pages from braille.json, zoo-24's 24 on two devices. An entry that
// names no word is refused before scrypt (72), swapped entries after it (16); Done ends it.
#[test]
fn ffi_wire_check_a_backup() {
    for (name, wallet, count) in [
        ("abandon-12-binary", "abandon", 12),
        ("zoo-24", "zoo-24", 24),
    ] {
        let age = common::backup().get("age_files").named(name);
        let file = if age.has("file_hex") {
            age.get("file_hex").hex()
        } else {
            age.get("file").text().as_bytes().to_vec()
        };
        let words: Vec<&str> = age.get("passphrase").text().split(' ').collect();
        let input = |entries: &[&str]| {
            let mut input: Vec<u8> = entries
                .iter()
                .flat_map(|word| text_field(&word.chars().take(4).collect::<String>()))
                .collect();
            input.extend_from_slice(&file);
            input
        };
        let slot = Slot::new();
        let mut unknown = words.clone();
        unknown[3] = "zzzz";
        assert_eq!(
            slot.dispatch(wire::OPEN_BACKUP, &input(&unknown))[..],
            [wire::REFUSED, 72]
        );
        let mut swapped = words.clone();
        swapped.swap(0, 1);
        assert_eq!(
            slot.dispatch(wire::OPEN_BACKUP, &input(&swapped))[..],
            [wire::REFUSED, 16]
        );
        assert_eq!(slot.holds(), HOME);

        let plaintext = common::backup()
            .get("plaintexts")
            .named(age.get("plaintext").text());
        let mnemonic = plaintext.get("mnemonic").text();
        let first_four: Vec<String> = words.iter().map(|w| w.chars().take(4).collect()).collect();
        let typed: Vec<&str> = first_four.iter().map(String::as_str).collect();
        let seal = done(Slot::new().open_backup(&file, &typed)).seal;
        let tag = seal.tag().to_hex();
        let card = seal_card(seal.tag().as_bytes(), seal.seal_id());
        if count == 12 {
            let vector = seal_vector(mnemonic);
            assert_eq!(tag, vector.get("seal_tag_hex").text());
            assert_eq!(card, seal_json_card(vector), "seal.json's card");
        }
        let recheck = qr_matrix(&format!("{ORIGIN}/check#t={tag}"));
        assert_eq!(version_and_level(&recheck), (5, 'L'));
        let fingerprint = watchonly().get("wallets").named(wallet).get("fingerprint");
        assert_eq!(plaintext.get("fingerprint").text(), fingerprint.text());
        let mut expect = fingerprint.hex();
        expect.extend(card);
        expect.extend(recheck);
        assert_eq!(
            wired(&slot, wire::OPEN_BACKUP, &input(&words))[..],
            expect[..],
            "{name}"
        );
        for (position, word) in (1..=count).zip(mnemonic.split(' ')) {
            assert_eq!(
                wired(&slot, wire::WORD_PAGE, &[position])[..],
                word_page(word, position, count)[..],
                "{name} insert {position}"
            );
        }
        assert_eq!(slot.dispatch(wire::END, &[])[..], [wire::OK]);
        assert_eq!(slot.holds(), HOME, "Done");
    }
}

// The registry over the wire (todo.md, M5 group 9). In either build, Match found keeps the report,
// whose QR carries dice-50-words12's code from kcr.json. A release build refuses a snapshot and a
// proof for want of a key (19). The test registry gives kcr.json's headers byte for byte: a loaded
// snapshot, Stale at an M5 date, and the collision it finds, with the report's QR again; a proof's
// clear, Current at its own date. A file too short is 32, text that is no UR 50, and a proof for
// another bucket 3.
#[test]
fn ffi_wire_registry() {
    let report = qr_matrix(&format!(
        "{ORIGIN}/register#c={}",
        seed("dice-50-words12", "seal_code_hashed")
    ));
    assert_eq!(version_and_level(&report), (4, 'M'));
    let slot = Slot::new();
    checking(&slot, "dice-50-words12");
    assert_eq!(slot.dispatch(wire::MATCH_FOUND, &[])[..], [wire::OK]);
    assert_eq!(wired(&slot, wire::COLLISION_REPORT, &[])[..], report[..]);
    let clear = proof_ur("clear-empty-bucket");
    let with_dice_50 = snapshot("with-dice-50");
    if !registry_key_is_test() {
        let slot = Slot::new();
        assert_eq!(
            slot.dispatch(wire::LOAD_SNAPSHOT, &dated(M5_DAY, &with_dice_50))[..],
            [wire::REFUSED, 19]
        );
        checking(&slot, "dice-99-words12");
        assert_eq!(
            slot.dispatch(wire::REVEAL_PROOF, &dated(M5_DAY, clear.as_bytes()))[..],
            [wire::REFUSED, 19]
        );
        return;
    }
    let slot = Slot::new();
    assert_eq!(
        slot.dispatch(wire::LOAD_SNAPSHOT, &dated(M5_DAY, &with_dice_50[..10]))[..],
        [wire::REFUSED, 32]
    );
    let stale = header_field(header("snapshots", "with-dice-50", Freshness::Stale));
    assert_eq!(
        wired(&slot, wire::LOAD_SNAPSHOT, &dated(M5_DAY, &with_dice_50))[..],
        stale[..]
    );
    checking(&slot, "dice-50-words12");
    let mut collision = vec![1, 1];
    collision.extend(&stale);
    assert_eq!(
        wired(&slot, wire::REVEAL_SNAPSHOT, &M5_DAY.to_be_bytes())[..],
        collision[..]
    );
    assert_eq!(wired(&slot, wire::COLLISION_REPORT, &[])[..], report[..]);

    let slot = Slot::new();
    checking(&slot, "dice-50-words12");
    assert_eq!(
        slot.dispatch(wire::REVEAL_PROOF, &dated(VECTOR_DAY, b"not a ur"))[..],
        [wire::REFUSED, 50]
    );
    assert_eq!(
        slot.dispatch(wire::REVEAL_PROOF, &dated(VECTOR_DAY, clear.as_bytes()))[..],
        [wire::REFUSED, 3]
    );
    let slot = Slot::new();
    checking(&slot, "dice-99-words12");
    let mut revealed = vec![0, 1];
    revealed.extend(header_field(header(
        "proofs",
        "clear-empty-bucket",
        Freshness::Current,
    )));
    assert_eq!(
        wired(
            &slot,
            wire::REVEAL_PROOF,
            &dated(VECTOR_DAY, clear.as_bytes())
        )[..],
        revealed[..]
    );
}

// The read-back and the backup over the wire (todo.md, M5 group 9; BP:327), on dice-99-words12:
// each mismatch's verdicts byte for byte (a mirror misread, a letter on a blank face, a missed
// letter, a wrong letter with braille.json's missing and extra dots); then the passphrase's pages
// and confirm questions as the safe layer gives them, a wrong and a right confirm, the encrypted
// file under its name, verified, and a changed byte refused. The passphrase is a throwaway's:
// compared under fixed messages.
#[test]
fn ffi_wire_readback_and_backup() {
    let name = "dice-99-words12";
    let mnemonic = seed(name, "mnemonic");
    let words: Vec<&str> = mnemonic.split(' ').collect();
    let at = |word: &str| {
        let index = words
            .iter()
            .position(|w| *w == word)
            .expect("a word of the seed");
        u8::try_from(index + 1).expect("1-12")
    };
    let slot = Slot::new();
    sealed(&slot, name);
    done(slot.skip_check());
    let (a, b) = (dots_of('a'), dots_of('b'));
    let ok = [0, 0, 0];
    for (word, typed, faces) in [
        ("various", "vawi", [ok, ok, [1, 0, 0], ok]),
        ("day", "days", [ok, ok, ok, [2, 0, 0]]),
        ("various", "var", [ok, ok, ok, [3, 0, 0]]),
        ("various", "vbri", [ok, [4, a & !b, b & !a], ok, ok]),
    ] {
        let mut input = vec![at(word)];
        input.extend_from_slice(typed.as_bytes());
        let mut expect = vec![1];
        expect.extend(faces.concat());
        assert_eq!(
            wired(&slot, wire::CHECK_READBACK, &input)[..],
            expect[..],
            "{typed} for {word}"
        );
    }
    read_back_all(&slot);

    assert_eq!(
        slot.dispatch(wire::GENERATE_BACKUP_PASSPHRASE, &[])[..],
        [wire::OK]
    );
    for page in 0..2 {
        let shown = done(slot.backup_passphrase_page(page));
        let field = Zeroizing::new(text_field(&shown));
        assert!(
            wired(&slot, wire::BACKUP_PASSPHRASE_PAGE, &[page])[..] == field[..],
            "the passphrase page, a text"
        );
    }
    let passphrase = passphrase(&slot);
    let challenge = done(slot.backup_challenge());
    let mut expect = Zeroizing::new(Vec::new());
    for question in challenge.questions() {
        expect.push(question.position());
        for choice in question.choices() {
            expect.extend(text_field(choice));
        }
    }
    assert!(
        wired(&slot, wire::BACKUP_CHALLENGE, &[])[..] == expect[..],
        "the confirm questions"
    );
    let right = right_picks(&slot, &passphrase);
    let wrong = [(right[0] + 1) % 4, right[1]];
    assert_eq!(wired(&slot, wire::CONFIRM_BACKUP, &wrong)[..], [0]);
    assert_eq!(wired(&slot, wire::CONFIRM_BACKUP, &right)[..], [1]);
    let file = wired(&slot, wire::ENCRYPT_BACKUP, &[]);
    let name_len = usize::from(file[0]);
    let file_name = std::str::from_utf8(&file[1..=name_len]).expect("ASCII");
    assert!(file_name.starts_with("keepcrypt-backup-") && file_name.ends_with(".age"));
    let saved = &file[1 + name_len..];
    assert_eq!(slot.dispatch(wire::VERIFY_BACKUP, saved)[..], [wire::OK]);
    let mut changed = saved.to_vec();
    let middle = changed.len() / 2;
    changed[middle] ^= 0x01;
    assert!(matches!(
        slot.dispatch(wire::VERIFY_BACKUP, &changed)[..],
        [wire::REFUSED, 16 | 64..=72]
    ));
    assert_eq!(slot.holds().stage, StageKind::Ready, "the words stay");
}

/// Ready with every insert read back: a stage that offers every word and export op.
fn read_back(slot: &Slot) {
    drive(slot, StageKind::Ready);
    read_back_all(slot);
}

/// Ready, every insert read back and the passphrase generated: a stage that offers every word,
/// export and backup op.
fn ready_to_export(slot: &Slot) {
    read_back(slot);
    done(slot.generate_backup_passphrase());
}

/// The passphrase's confirm passed: a stage that offers the encrypted backup.
fn confirmed(slot: &Slot) {
    ready_to_export(slot);
    let right = right_picks(slot, &passphrase(slot));
    assert!(done(slot.confirm_backup(right)), "the confirm passes");
}

/// All of dice-50-words12's rolls in: a stage whose `finish` makes the seed.
fn rolled(slot: &Slot) {
    drive(slot, StageKind::Rolling);
    for face in rolls("dice-50-words12") {
        done(slot.push_roll(face));
    }
}

/// A Mixed ceremony on the OS source, read back: a stage that offers D. A throwaway seed.
fn mixed_read_back(slot: &Slot) {
    done(slot.start(SeedLength::Words12, Mode::Mixed));
    done(slot.commit());
    done(slot.start_dice());
    for face in rolls("dice-50-words12") {
        done(slot.push_roll(face));
    }
    done(slot.finish());
    done(slot.skip_check());
    read_back_all(slot);
}

/// with-dice-50 loaded and a check open on dice-50-words12: a stage that offers the check against
/// the snapshot (the test-registry build alone loads one).
fn snapshot_checking(slot: &Slot) {
    done(slot.load_snapshot(&snapshot("with-dice-50"), M5_DAY));
    checking(slot, "dice-50-words12");
}

// Malformed inputs halt (wire.rs): an input that is not its op's exact layout (a length, a value
// outside its range, a text that is not UTF-8, entries that run past the input, a byte after a
// status-only op's empty input) empties the slot and latches; so does an op the table does not
// hold. Each op's inputs run in a stage that offers it, which its well-formed input proves on a
// fresh slot there (an OK or a refusal, never a halt), so only the input halts. The check against
// the snapshot needs a loaded one, which only the test-registry build can load.
#[test]
fn ffi_wire_malformed_inputs_halt() {
    type Op = (fn(&Slot), u32, Vec<u8>, Vec<Vec<u8>>);
    let byte = || vec![vec![0]];
    // Eight entries of four letters that each name a word, and an empty file: refused, after them.
    let entries: Vec<u8> = (0..8).flat_map(|_| text_field("aban")).collect();
    let mut ops: Vec<Op> = vec![
        (|_| {}, wire::SELF_TEST, vec![], byte()),
        (
            |_| {},
            wire::START,
            vec![12, 2],
            vec![vec![], vec![12], vec![12, 2, 0], vec![13, 2], vec![12, 3]],
        ),
        (
            |s| drive(s, StageKind::Collecting),
            wire::ADD_EXTRA,
            vec![1, 9, 9],
            vec![vec![], vec![0], vec![3, 1]],
        ),
        (
            |s| drive(s, StageKind::Collecting),
            wire::DEVICE_PROGRESS,
            vec![],
            byte(),
        ),
        (
            |s| drive(s, StageKind::Collecting),
            wire::COMMIT,
            vec![],
            byte(),
        ),
        (
            |s| drive(s, StageKind::Committed),
            wire::COMMITMENT,
            vec![],
            byte(),
        ),
        (
            |s| drive(s, StageKind::Committed),
            wire::START_DICE,
            vec![],
            byte(),
        ),
        (
            |s| drive(s, StageKind::Rolling),
            wire::PUSH_ROLL,
            vec![6],
            vec![vec![], vec![6, 6]],
        ),
        (
            |s| drive(s, StageKind::Rolling),
            wire::UNDO_ROLL,
            vec![],
            byte(),
        ),
        (
            |s| drive(s, StageKind::Rolling),
            wire::DICE_PROGRESS,
            vec![],
            byte(),
        ),
        (rolled, wire::FINISH, vec![], byte()),
        (|s| drive(s, StageKind::Sealed), wire::SEAL, vec![], byte()),
        (
            |s| drive(s, StageKind::Sealed),
            wire::SKIP_CHECK,
            vec![],
            byte(),
        ),
        (
            |s| drive(s, StageKind::Sealed),
            wire::START_CHECK,
            vec![],
            byte(),
        ),
        (
            |s| drive(s, StageKind::Checking),
            wire::CHECK_REQUEST,
            vec![],
            byte(),
        ),
        (
            |s| drive(s, StageKind::Checking),
            wire::REVEAL_CODE,
            b"0000-0000".to_vec(),
            vec![vec![0xff]],
        ),
        (
            |s| drive(s, StageKind::Checking),
            wire::REVEAL_PROOF,
            dated(VECTOR_DAY, b"not a ur"),
            vec![vec![1, 52, 37], dated(VECTOR_DAY, &[0xff])],
        ),
        (
            |s| drive(s, StageKind::Checking),
            wire::MATCH_FOUND,
            vec![],
            byte(),
        ),
        (
            |s| drive(s, StageKind::Checking),
            wire::CANNOT_CHECK,
            vec![],
            byte(),
        ),
        (
            |s| drive(s, StageKind::Restart),
            wire::COLLISION_REPORT,
            vec![],
            byte(),
        ),
        (
            |s| drive(s, StageKind::Ready),
            wire::WORD_PAGE,
            vec![1],
            vec![vec![], vec![1, 1]],
        ),
        (
            |s| drive(s, StageKind::Ready),
            wire::CHECK_READBACK,
            vec![1, b'a', b'b', b'c'],
            vec![vec![], vec![1, 0xff, b'a', b'b']],
        ),
        (
            |s| drive(s, StageKind::Ready),
            wire::SUMMARY,
            vec![],
            byte(),
        ),
        (|s| drive(s, StageKind::Ready), wire::END, vec![], byte()),
        (read_back, wire::GENERATE_BACKUP_PASSPHRASE, vec![], byte()),
        (
            read_back,
            wire::WATCH_ONLY,
            vec![0],
            vec![vec![], vec![0, 0], vec![2], vec![1, 0xff]],
        ),
        (read_back, wire::REGISTRATION, vec![], byte()),
        (
            ready_to_export,
            wire::BACKUP_PASSPHRASE_PAGE,
            vec![0],
            vec![vec![], vec![0, 0]],
        ),
        (ready_to_export, wire::BACKUP_CHALLENGE, vec![], byte()),
        (
            ready_to_export,
            wire::CONFIRM_BACKUP,
            vec![0, 0],
            vec![vec![0], vec![0, 0, 0]],
        ),
        (confirmed, wire::ENCRYPT_BACKUP, vec![], byte()),
        (mixed_read_back, wire::REVEAL_DEVICE_LEG, vec![], byte()),
        (|_| {}, wire::DISCARD, vec![], byte()),
        (|_| {}, wire::WIPE_ALL, vec![], byte()),
        (
            |_| {},
            wire::LOAD_SNAPSHOT,
            dated(VECTOR_DAY, &[]),
            vec![vec![1, 52, 37]],
        ),
        (
            |_| {},
            wire::OPEN_BACKUP,
            entries.clone(),
            vec![
                vec![],
                // Seven entries, and no eighth.
                entries[..35].to_vec(),
                // An entry longer than the input.
                vec![200, 97],
                // Eight entries, the first not UTF-8.
                [&[4, 0xff, 98, 97, 110][..], &entries[5..]].concat(),
            ],
        ),
    ];
    if registry_key_is_test() {
        ops.push((
            snapshot_checking,
            wire::REVEAL_SNAPSHOT,
            M5_DAY.to_be_bytes().to_vec(),
            vec![vec![1, 52, 37], dated(M5_DAY, &[0])],
        ));
    }
    let mut covered: Vec<u32> = ops.iter().map(|&(_, op, _, _)| op).collect();
    covered.sort_unstable();
    let mut every: Vec<u32> = (1..=38).filter(|&op| op != wire::VERIFY_BACKUP).collect();
    if !registry_key_is_test() {
        every.retain(|&op| op != wire::REVEAL_SNAPSHOT);
    }
    // Every op but VERIFY_BACKUP, whose input is the file whatever it holds, each once.
    assert_eq!(covered, every);
    for (setup, op, good, bad) in ops {
        let slot = Slot::new();
        setup(&slot);
        let reply = slot.dispatch(op, &good);
        assert!(
            matches!(reply.first(), Some(&(wire::OK | wire::REFUSED))),
            "op {op}: its well-formed input is offered here"
        );
        for input in bad {
            let slot = Slot::new();
            setup(&slot);
            assert_eq!(
                slot.dispatch(op, &input)[..],
                [wire::HALTED],
                "op {op}, input {input:?}"
            );
            assert_eq!(slot.holds(), HALTED, "op {op}, input {input:?}");
            assert_eq!(
                slot.dispatch(wire::WIPE_ALL, &[])[..],
                [wire::HALTED],
                "op {op}: the halt latches"
            );
        }
    }
    for op in [0, 39, u32::MAX] {
        let slot = Slot::new();
        assert_eq!(slot.dispatch(op, &[])[..], [wire::HALTED], "op {op}");
        assert_eq!(slot.holds(), HALTED, "op {op}");
    }
}
