//! A panic wipes the session (CLAUDE.md rule 3; tasks/todo.md, M1 group 9 "Ready and panics" and
//! group 10). A panic unwinds (the release profile states `panic = "unwind"`, and `cargo test`
//! always unwinds), and the unwind drops the session's `Box<Inner>`, whose `Drop` zeroizes it; the
//! zeroize bumps the stub's wipe probe last, once every field is clear. Nothing catches the panic:
//! `catch_unwind` is banned in core, so the thread dies with it, and the session with the thread.

use keepcrypt_core::{
    Mode, Platform, ReadbackResult, Rolling, SeedLength, Session, StubEntropy, StubSource,
    WipeProbe,
};
use std::thread;

/// Runs `body` on its own thread with a fresh probe and returns whether the thread panicked and how
/// many wipes the probe saw.
fn on_a_thread(body: fn(&WipeProbe)) -> (bool, usize) {
    let probe = WipeProbe::new();
    let held = probe.clone();
    let joined = thread::spawn(move || body(&held)).join();
    (joined.is_err(), probe.wipes())
}

fn rolled_session(probe: &WipeProbe) -> Session<Rolling> {
    let stub = StubSource::new(StubEntropy::Fixed(vec![0; 8]), probe);
    let mut rolling = Session::new_with_stub(
        SeedLength::Words12,
        Mode::DiceOnly,
        Platform::Phone,
        stub,
        None,
    )
    .and_then(Session::commit)
    .expect("committed")
    .start_dice();
    for face in (1..=6).cycle().take(50) {
        rolling = rolling.push_roll(face).expect("a face");
    }
    rolling
}

#[test]
fn a_panic_while_collecting_wipes_the_session() {
    let (panicked, wipes) = on_a_thread(|probe| {
        let stub = StubSource::new(StubEntropy::Fail, probe);
        let session =
            Session::new_with_stub(SeedLength::Words24, Mode::Mixed, Platform::Pi, stub, None)
                .expect("a session");
        assert_eq!(probe.wipes(), 0);
        assert_eq!(session.mode(), Mode::Mixed);
        panic!("a shell bug while the session is held");
    });
    assert!(panicked);
    assert_eq!(wipes, 1);
}

#[test]
fn a_panic_while_rolling_or_checking_wipes_the_seed() {
    let (panicked, wipes) = on_a_thread(|probe| {
        let rolling = rolled_session(probe);
        assert_eq!(rolling.rolls(), 50);
        panic!("a shell bug with the dice entered");
    });
    assert_eq!((panicked, wipes), (true, 1));

    let (panicked, wipes) = on_a_thread(|probe| {
        let checking = rolled_session(probe)
            .finish()
            .and_then(|sealed| sealed.start_check())
            .expect("checking");
        assert!(!checking.check_request().url().is_empty());
        panic!("a shell bug during the check");
    });
    assert_eq!((panicked, wipes), (true, 1));
}

#[test]
fn a_panic_with_the_words_shown_wipes_them() {
    let (panicked, wipes) = on_a_thread(|probe| {
        let mut ready = rolled_session(probe).finish().expect("sealed").skip_check();
        let first: String = ready
            .braille()
            .insert(1)
            .expect("an insert")
            .word()
            .chars()
            .take(4)
            .collect();
        assert!(matches!(
            ready.check_readback(1, &first),
            Ok(ReadbackResult::Match)
        ));
        assert_eq!(probe.wipes(), 0);
        panic!("a shell bug with the words on screen");
    });
    assert!(panicked);
    assert_eq!(wipes, 1);
}

/// The control: a thread that ends normally drops its session too, once, and does not panic.
#[test]
fn a_thread_that_ends_normally_wipes_once_without_a_panic() {
    let (panicked, wipes) = on_a_thread(|probe| {
        let rolling = rolled_session(probe);
        assert_eq!(rolling.minimum_rolls(), 50);
    });
    assert_eq!((panicked, wipes), (false, 1));
}
