//! The real OS path (docs/build-plan.md test matrix "Source-substitution"; tasks/todo.md, M1 group 10
//! and Verification "A real-OS test shows two sessions differ"): default features, no stub. Two
//! phone sessions give different commitments, and two checks of the same dice-only seed draw
//! different nonces. The tests assert inequality only and print nothing.

use keepcrypt_core::{Mode, Platform, SeedLength, Session};

#[test]
fn two_real_sessions_give_different_commitments() {
    let commit = || {
        Session::new(SeedLength::Words12, Mode::Mixed, Platform::Phone)
            .and_then(Session::commit)
            .expect("committed")
            .commitment()
            .expect("C in Mixed mode")
    };
    assert_ne!(commit(), commit());
}

#[test]
fn two_real_checks_draw_different_nonces() {
    let check_url = || {
        let mut rolling = Session::new(SeedLength::Words12, Mode::DiceOnly, Platform::Pi)
            .and_then(Session::commit)
            .expect("committed")
            .start_dice();
        for face in (1..=6).cycle().take(50) {
            rolling = rolling.push_roll(face).expect("a face");
        }
        let checking = rolling
            .finish()
            .and_then(|sealed| sealed.start_check())
            .expect("checking");
        checking.check_request().url().to_owned()
    };
    let (first, second) = (check_url(), check_url());
    let tag = |url: &str| url.split("&n=").next().map(str::to_owned);
    assert_eq!(tag(&first), tag(&second), "the same seed, so the same T");
    assert_ne!(first, second, "a fresh nonce per check");
}
