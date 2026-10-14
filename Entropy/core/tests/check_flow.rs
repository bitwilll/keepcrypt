//! The collision check end to end (docs/seal-watchonly-braille.md "Go-ahead before reveal", "Add
//! fresh entropy", "Results"; docs/build-plan.md test matrix "Go-ahead vectors and tampering";
//! tasks/todo.md, M1 group 10 and Verification "Go-ahead tests", M3 group 2). Public vectors only:
//! kcr.json's dice-only seeds, snapshots and proofs, signed by the test registry key this build
//! pins.
//!
//! - A 12-word dice-only session from the 50-roll string reaches `Sealed` with kcr.json's T; its
//!   go-ahead code reveals the expected words, and a typo keeps the session and the nonce.
//! - The collision snapshot and the collision proof both give `Collision`; the report holds that
//!   seed's code, and the restart refuses 50 rolls and accepts the 99-roll string.
//! - `restart` borrows the `Wiped` (M3 Q26 C), so a kept `Wiped` restarts at 99 every time until a
//!   check passes: twice from one collision `Wiped`, for either length, with a failed restart
//!   between them, and twice from the `Wiped` of a "Cannot check" in that restart. A "Cannot
//!   check" in a first session restarts at 50, twice. The shipped `restart`, on the OS source as
//!   the Pi calls it, also restarts one collision `Wiped` twice at 99, and the report stays.
//! - A proof for another bucket gives `Retry`, and the right code still reveals.
//! - Freshness is the shell's warning, not a refusal: the stale proof is `Stale` for kcr.json's
//!   pinned today (a phone warns) and still reveals; the future-dated proof is `Future`.
//! - A snapshot loaded before the ceremony serves the check after a restart too (`GoAhead` borrows).

mod common;

use common::{hex, named, read, text};
use keepcrypt_core::{
    CheckError, Checking, CoreError, Discard, Freshness, GoAhead, KatId, Mode, Platform, Ready,
    RegistryDate, Rejected, Rolling, Sealed, SeedLength, Session, StubEntropy, StubSource,
    VerifiedProof, VerifiedSnapshot, WipeProbe, Wiped, verify_bucket_proof, verify_bucket_proof_qr,
    verify_snapshot,
};
use serde_json::Value;

const NONCE: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

fn kcr() -> Value {
    read("kcr.json")
}

fn seed(name: &str) -> Value {
    named(&kcr()["seeds"], name).clone()
}

fn snapshot(name: &str) -> VerifiedSnapshot {
    verify_snapshot(&hex(&named(&kcr()["snapshots"], name)["kcr_hex"])).expect("valid")
}

fn proof(name: &str) -> VerifiedProof {
    verify_bucket_proof(&hex(&named(&kcr()["proofs"], name)["kcp1_hex"])).expect("valid")
}

fn today() -> RegistryDate {
    let value = u32::try_from(kcr()["today"].as_u64().expect("today")).expect("u32");
    RegistryDate::from_yyyymmdd(value).expect("a date")
}

/// A seed's roll string, as faces.
fn faces(seed: &Value) -> Vec<u8> {
    text(&seed["rolls"]).bytes().map(|b| b - b'0').collect()
}

fn roll_all(mut rolling: Session<Rolling>, faces: &[u8]) -> Session<Rolling> {
    for &face in faces {
        rolling = rolling.push_roll(face).expect("a face");
    }
    rolling
}

/// The 12-word dice-only session of kcr.json's `dice-50-words12`, through `finish`, on a stub that
/// serves the check nonce 0001020304050607.
fn sealed_dice_50(probe: &WipeProbe) -> Session<Sealed> {
    let stub = StubSource::new(StubEntropy::Fixed(NONCE.to_vec()), probe);
    let committed = Session::new_with_stub(
        SeedLength::Words12,
        Mode::DiceOnly,
        Platform::Phone,
        stub,
        None,
    )
    .and_then(Session::commit)
    .expect("committed");
    roll_all(committed.start_dice(), &faces(&seed("dice-50-words12")))
        .finish()
        .expect("sealed")
}

fn words(ready: &Session<Ready>) -> String {
    ready.mnemonic().words().collect::<Vec<_>>().join(" ")
}

/// The words a `reveal` gave, or a panic naming what it gave instead.
fn revealed(result: Result<Session<Ready>, Rejected>) -> Session<Ready> {
    match result {
        Ok(ready) => ready,
        Err(rejected) => panic!("{rejected:?}"),
    }
}

/// The session a `Retry` gave back, after checking its reason.
fn retried(result: Result<Session<Ready>, Rejected>, why: CheckError) -> Session<Checking> {
    match result {
        Err(Rejected::Retry(session, got)) => {
            assert_eq!(got, why);
            session
        }
        Err(other) => panic!("{other:?}"),
        Ok(_) => panic!("revealed"),
    }
}

fn collision(result: Result<Session<Ready>, Rejected>) -> Wiped {
    match result {
        Err(Rejected::Collision(wiped)) => wiped,
        Err(other) => panic!("{other:?}"),
        Ok(_) => panic!("revealed"),
    }
}

#[test]
fn the_code_reveals_the_words_and_a_typo_keeps_the_session() {
    let v = seed("dice-50-words12");
    let probe = WipeProbe::new();
    let sealed = sealed_dice_50(&probe);
    let tag = text(&v["seal_tag_hex"]);
    assert_eq!(sealed.seal().tag().to_hex(), tag);
    assert_eq!(sealed.seal().seal_id(), text(&v["seal_id"]));
    assert_eq!(
        sealed.seal().recheck_url(),
        format!("https://registry.invalid/check#t={tag}")
    );
    let checking = sealed.start_check().expect("checking");
    let url = format!("https://registry.invalid/check#t={tag}&n=0001020304050607");
    assert_eq!(checking.check_request().url(), url);
    assert_eq!(checking.seal().tag().to_hex(), tag);
    let checking = retried(
        checking.reveal(GoAhead::Code("PBJN-YZY6")),
        CheckError::WrongCode,
    );
    let checking = retried(
        checking.reveal(GoAhead::Code("PBJN-YZY")),
        CheckError::MalformedCode,
    );
    let checking = retried(
        checking.reveal(GoAhead::Code(text(&seed("vector-1")["go_ahead"]))),
        CheckError::WrongCode,
    );
    assert_eq!(checking.check_request().url(), url, "the same nonce");
    assert_eq!(probe.wipes(), 0, "a typo wipes nothing");
    let ready = revealed(checking.reveal(GoAhead::Code("pbjn yzy5")));
    assert_eq!(words(&ready), text(&v["mnemonic"]));
    assert_eq!(text(&v["go_ahead"]), "PBJN-YZY5");
}

#[test]
fn collision_evidence_wipes_the_seed_and_the_report_holds_its_code() {
    let v = seed("dice-50-words12");
    let with_dice_50 = snapshot("with-dice-50");
    let collision_proof = proof("collision-dice-50");
    for evidence in [
        GoAhead::Snapshot(&with_dice_50),
        GoAhead::BucketProof(&collision_proof),
    ] {
        let probe = WipeProbe::new();
        let checking = sealed_dice_50(&probe).start_check().expect("checking");
        let wiped = collision(checking.reveal(evidence));
        assert_eq!(probe.wipes(), 1, "{evidence:?}");
        let report = wiped.collision_report().expect("a report");
        assert_eq!(report.grouped_code(), text(&v["seal_code"]));
        assert_eq!(report.seal_id(), text(&v["seal_id"]));
        assert_eq!(
            report.url(),
            format!(
                "https://registry.invalid/register#c={}",
                text(&v["seal_code_hashed"])
            )
        );
    }
}

/// A `Wiped` after a collision found by the snapshot that registers the 50-roll seed.
fn wiped_by_collision() -> Wiped {
    let with_dice_50 = snapshot("with-dice-50");
    let checking = sealed_dice_50(&WipeProbe::new())
        .start_check()
        .expect("checking");
    collision(checking.reveal(GoAhead::Snapshot(&with_dice_50)))
}

#[test]
fn the_restart_refuses_50_rolls_and_accepts_the_99_roll_string() {
    let probe = WipeProbe::new();
    let rolling = wiped_by_collision()
        .restart_with_stub(
            SeedLength::Words12,
            Mode::DiceOnly,
            StubSource::new(StubEntropy::Fail, &probe),
            None,
        )
        .and_then(Session::commit)
        .expect("restarted")
        .start_dice();
    assert_eq!(rolling.minimum_rolls(), 99);
    let rolling = roll_all(rolling, &faces(&seed("dice-50-words12")));
    assert_eq!(rolling.finish().map(|_| ()), Err(CoreError::TooFewRolls));
    assert_eq!(probe.wipes(), 1);

    let v = seed("dice-99-words12");
    let rolling = wiped_by_collision()
        .restart_with_stub(
            SeedLength::Words12,
            Mode::DiceOnly,
            StubSource::new(StubEntropy::Fixed(NONCE.to_vec()), &WipeProbe::new()),
            None,
        )
        .and_then(Session::commit)
        .expect("restarted")
        .start_dice();
    let sealed = roll_all(rolling, &faces(&v)).finish().expect("sealed");
    assert_eq!(sealed.seal().tag().to_hex(), text(&v["seal_tag_hex"]));
    let checking = sealed.start_check().expect("checking");
    let ready = revealed(checking.reveal(GoAhead::Code(text(&v["go_ahead"]))));
    assert_eq!(words(&ready), text(&v["mnemonic"]));
}

/// The 99-roll seeds, by length. Their roll string is the same.
const NINETY_NINE: [(SeedLength, &str); 2] = [
    (SeedLength::Words12, "dice-99-words12"),
    (SeedLength::Words24, "dice-99-words24"),
];

/// `wiped` restarted at `len` in dice-only mode, up to the dice, on a stub that serves the check
/// nonce 0001020304050607. It borrows, so the caller keeps the `Wiped`.
fn restarted(wiped: &Wiped, len: SeedLength, probe: &WipeProbe) -> Session<Rolling> {
    wiped
        .restart_with_stub(
            len,
            Mode::DiceOnly,
            StubSource::new(StubEntropy::Fixed(NONCE.to_vec()), probe),
            None,
        )
        .and_then(Session::commit)
        .expect("restarted")
        .start_dice()
}

/// The seed of `v`'s roll string, then "Cannot check".
fn cannot_check(rolling: Session<Rolling>, v: &Value) -> Wiped {
    roll_all(rolling, &faces(v))
        .finish()
        .and_then(Session::start_check)
        .expect("checking")
        .discard(Discard::CannotCheck)
}

/// The shell keeps the collision `Wiped` and restarts from it again when the idle wipe ends the
/// restarted ceremony (owner item 14): every restart needs 99 rolls, for either length. A restart
/// whose known-answer suite fails wipes only its new session, and the report stays with the
/// `Wiped`. The second restart's check passes; the shell then drops the `Wiped`, which ends the
/// 99-roll minimum.
#[test]
fn a_kept_wiped_restarts_at_99_until_a_check_passes() {
    let destroyed = seed("dice-50-words12");
    for (len, name) in NINETY_NINE {
        let v = seed(name);
        let kept = wiped_by_collision();
        let probe = WipeProbe::new();
        let rolling = restarted(&kept, len, &probe);
        assert_eq!(rolling.minimum_rolls(), 99, "{name}: the first restart");
        drop(rolling);
        assert_eq!(probe.wipes(), 1, "{name}: the idle wipe");

        let probe = WipeProbe::new();
        let failed = kept.restart_with_stub(
            len,
            Mode::DiceOnly,
            StubSource::new(StubEntropy::Fail, &probe),
            Some(KatId::Sha256),
        );
        assert!(
            matches!(failed, Err(CoreError::Kat(KatId::Sha256))),
            "{name}"
        );
        assert_eq!(probe.wipes(), 1, "{name}: the failed restart");
        let report = kept.collision_report().expect("the report stays");
        assert_eq!(
            report.grouped_code(),
            text(&destroyed["seal_code"]),
            "{name}"
        );

        let rolling = restarted(&kept, len, &WipeProbe::new());
        assert_eq!(rolling.minimum_rolls(), 99, "{name}: the second restart");
        let checking = roll_all(rolling, &faces(&v))
            .finish()
            .and_then(Session::start_check)
            .expect("checking");
        let ready = revealed(checking.reveal(GoAhead::Code(text(&v["go_ahead"]))));
        assert_eq!(words(&ready), text(&v["mnemonic"]), "{name}");
    }
}

/// The same through the shipped `restart`, the one the Pi calls, on the OS source rather than the
/// stub twin's: each of two restarts from one kept collision `Wiped` needs 99 rolls, for either
/// length, and the destroyed seed's report stays with it.
#[test]
fn the_shipped_restart_keeps_a_kept_wiped_at_99() {
    let destroyed = seed("dice-50-words12");
    for (len, name) in NINETY_NINE {
        let kept = wiped_by_collision();
        for restart in 1..=2 {
            let rolling = kept
                .restart(len, Mode::DiceOnly)
                .and_then(Session::commit)
                .expect("restarted")
                .start_dice();
            assert_eq!(rolling.minimum_rolls(), 99, "{name}: restart {restart}");
            let report = kept.collision_report().expect("the report stays");
            assert_eq!(
                report.grouped_code(),
                text(&destroyed["seal_code"]),
                "{name}: restart {restart}"
            );
        }
    }
}

/// "Cannot check" in the restart after a collision keeps that session's 99-roll flag: the newer
/// `Wiped`, which replaces the kept one, holds no report and restarts at 99 every time.
#[test]
fn a_cannot_check_in_the_restart_after_a_collision_restarts_at_99() {
    for (len, name) in NINETY_NINE {
        let kept = wiped_by_collision();
        let kept = cannot_check(restarted(&kept, len, &WipeProbe::new()), &seed(name));
        assert!(kept.collision_report().is_none(), "{name}");
        for restart in 1..=2 {
            let rolling = restarted(&kept, len, &WipeProbe::new());
            assert_eq!(rolling.minimum_rolls(), 99, "{name}: restart {restart}");
        }
    }
}

/// "Cannot check" in a first session keeps its own flag, here none: every restart from that
/// `Wiped` uses the normal minimum, 50 rolls for 12 words.
#[test]
fn a_cannot_check_in_a_first_session_restarts_at_50() {
    let kept = sealed_dice_50(&WipeProbe::new())
        .start_check()
        .expect("checking")
        .discard(Discard::CannotCheck);
    assert!(kept.collision_report().is_none());
    for restart in 1..=2 {
        let rolling = restarted(&kept, SeedLength::Words12, &WipeProbe::new());
        assert_eq!(rolling.minimum_rolls(), 50, "restart {restart}");
    }
}

#[test]
fn a_proof_for_another_bucket_retries_and_the_code_still_reveals() {
    let other_bucket = proof("clear-shared-prefix");
    let other_bucket_qr =
        verify_bucket_proof_qr(text(&named(&kcr()["proofs"], "ur-uppercase")["ur"]))
            .expect("valid");
    let checking = sealed_dice_50(&WipeProbe::new())
        .start_check()
        .expect("checking");
    let checking = retried(
        checking.reveal(GoAhead::BucketProof(&other_bucket)),
        CheckError::WrongBucket,
    );
    let checking = retried(
        checking.reveal(GoAhead::BucketProof(&other_bucket_qr)),
        CheckError::WrongBucket,
    );
    let ready = revealed(checking.reveal(GoAhead::Code("PBJN-YZY5")));
    assert_eq!(words(&ready), text(&seed("dice-50-words12")["mnemonic"]));
}

/// Clear evidence of every age reveals: a phone shows `Stale` or `Future` as a warning, the Pi
/// shows the date for the user to confirm; core has no clock and refuses neither.
#[test]
fn freshness_is_the_shells_warning_not_a_refusal() {
    let today = today();
    for (name, freshness, date) in [
        ("current-day-30", Freshness::Current, 20260130),
        ("stale-day-31", Freshness::Stale, 20260129),
        ("future-day-1", Freshness::Future, 20260302),
    ] {
        let proof = proof(name);
        let snapshot = snapshot(name);
        assert_eq!(proof.freshness(today), freshness, "{name}");
        assert_eq!(snapshot.freshness(today), freshness, "{name}");
        assert_eq!(proof.date().yyyymmdd(), date, "{name}");
        for evidence in [GoAhead::BucketProof(&proof), GoAhead::Snapshot(&snapshot)] {
            let checking = sealed_dice_50(&WipeProbe::new())
                .start_check()
                .expect("checking");
            let ready = revealed(checking.reveal(evidence));
            assert_eq!(
                words(&ready),
                text(&seed("dice-50-words12")["mnemonic"]),
                "{name}"
            );
        }
    }
}

/// `GoAhead` borrows the verified snapshot, so one loaded before the ceremony serves the check
/// after a restart too: it stops the 50-roll seed and clears the 99-roll seed.
#[test]
fn a_snapshot_loaded_before_the_ceremony_serves_every_check() {
    let loaded = snapshot("with-dice-50");
    let checking = sealed_dice_50(&WipeProbe::new())
        .start_check()
        .expect("checking");
    let wiped = collision(checking.reveal(GoAhead::Snapshot(&loaded)));
    let v = seed("dice-99-words12");
    let rolling = wiped
        .restart_with_stub(
            SeedLength::Words12,
            Mode::DiceOnly,
            StubSource::new(StubEntropy::Fixed(NONCE.to_vec()), &WipeProbe::new()),
            None,
        )
        .and_then(Session::commit)
        .expect("restarted")
        .start_dice();
    let checking = roll_all(rolling, &faces(&v))
        .finish()
        .and_then(|sealed| sealed.start_check())
        .expect("checking");
    let ready = revealed(checking.reveal(GoAhead::Snapshot(&loaded)));
    assert_eq!(words(&ready), text(&v["mnemonic"]));
    assert_eq!(loaded.number(), 4, "the same snapshot, loaded once");
}
