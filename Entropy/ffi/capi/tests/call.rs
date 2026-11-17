//! keepcrypt-capi's two exports, called by their Rust paths as Swift calls them through
//! include/keepcrypt.h (tasks/todo.md, M6 item B1), in the release configuration (`cargo test -p
//! keepcrypt-capi`) and the registry one (with `-p keepcrypt-ffi --features
//! keepcrypt-core/test-registry`, which needs a selected crate with a keepcrypt-core edge).
//!
//! The phone's slot is the process's one, so each case runs on a fresh slot in a child process of
//! its own, which the test at the end starts. Test data comes from vectors/ only (rule 12): kcr.json's
//! public dice-only gate seed dice-50-words12 and braille.json's SeedBook numbers. Assertion
//! messages are fixed or name public values only.

use std::env;
use std::process::Command;

use keepcrypt_capi::{kc_call, kc_max_out};

/// keepcrypt-ffi's wire.rs, which this crate cannot name (as keepcrypt-jni's tests): the ops a
/// dice-only ceremony and its words page use, the OK status, and the halt status of an internal
/// halt (HALTED, then its code 4).
const SELF_TEST: u32 = 1;
const START: u32 = 2;
const COMMIT: u32 = 4;
const START_DICE: u32 = 5;
const PUSH_ROLL: u32 = 6;
const FINISH: u32 = 8;
const SKIP_CHECK: u32 = 9;
const END: u32 = 14;
const WORD_PAGE: u32 = 26;
const OK: u8 = 0;
const HALTED_INTERNAL: [u8; 2] = [3, 4];

/// The reply bound (tasks/todo.md, M6 item B2).
const MAX_OUT: usize = 16_384;
/// keepcrypt-jni's input cap, a full snapshot with its date.
const MAX_INPUT: usize = 75_497_598;

/// The guard's test op (keepcrypt-guard's PLANTED, M5-38), which exists only in the guard's own
/// unit tests: in this build it is an op the table does not hold.
const GUARD_TEST_OP: u32 = u32::MAX;

/// A field of gate seed `name` in kcr.json, a JSON string.
fn seed(name: &str, field: &str) -> String {
    let kcr = include_str!("../../../vectors/kcr.json");
    let at = kcr
        .find(&format!("\"name\": \"{name}\""))
        .expect("the gate seed");
    let key = format!("\"{field}\": \"");
    let start = at + kcr[at..].find(&key).expect("its field") + key.len();
    let end = start + kcr[start..].find('"').expect("its end");
    kcr[start..end].to_owned()
}

/// The 1-based BIP39 index of `word`, its SeedBook number, from braille.json.
fn seedbook(word: &str) -> u16 {
    let braille = include_str!("../../../vectors/braille.json");
    let line = braille
        .lines()
        .find(|line| line.contains(&format!("\"word\": \"{word}\",")))
        .expect("a BIP39 word");
    let key = "{\"number\": ";
    let start = line.find(key).expect("its number") + key.len();
    let end = start + line[start..].find(',').expect("its end");
    line[start..end].parse().expect("1-2048")
}

/// One call with `input` and an output buffer of `cap` bytes: what `kc_call` gives, and the bytes
/// it wrote (the buffer up to that count, or all of it, untouched, for -1).
fn call_with(op: u32, input: &[u8], cap: usize) -> (i64, Vec<u8>) {
    let mut out = vec![0; cap];
    // SAFETY: input is valid for reads of its length and out for writes of cap bytes, and neither
    // is used by anything else during the call.
    let len = unsafe { kc_call(op, input.as_ptr(), input.len(), out.as_mut_ptr(), cap) };
    if len >= 0 {
        out.truncate(usize::try_from(len).expect("a length"));
    }
    (len, out)
}

/// One call with a `kc_max_out()` buffer: the reply's bytes.
fn call(op: u32, input: &[u8]) -> Vec<u8> {
    let (len, reply) = call_with(op, input, kc_max_out());
    assert!(len > 0, "op {op}: a reply, never -1 here");
    reply
}

/// The slot is live: Self test passes.
fn live() {
    assert_eq!(call(SELF_TEST, &[]), [OK], "the slot is live");
}

/// The slot halted as internal, for good: Self test and a start give that halt status.
fn halted_for_good() {
    assert_eq!(call(SELF_TEST, &[]), HALTED_INTERNAL, "halted");
    assert_eq!(call(START, &[12, 2]), HALTED_INTERNAL, "halted for good");
}

/// Gate seed dice-50-words12 driven to Ready: 12 words, dice only, Skip.
fn ready() {
    assert_eq!(call(START, &[12, 2]), [OK]);
    assert_eq!(call(COMMIT, &[]), [OK]);
    assert_eq!(call(START_DICE, &[]), [OK]);
    let rolls = seed("dice-50-words12", "rolls");
    assert_eq!(rolls.len(), 50, "50 rolls");
    for digit in rolls.bytes() {
        assert!((b'1'..=b'6').contains(&digit), "a face");
        assert_eq!(call(PUSH_ROLL, &[digit - b'0']), [OK]);
    }
    assert_eq!(call(FINISH, &[]), [OK]);
    assert_eq!(call(SKIP_CHECK, &[]), [OK]);
}

/// The reply bound and the input cap, as pinned.
#[test]
fn the_reply_bound_and_the_input_cap() {
    assert_eq!(kc_max_out(), MAX_OUT);
    assert_eq!(MAX_INPUT, 4 + 122 + 18 * (1 << 22));
}

/// Set for the child process alone, to the case it runs on the process's fresh slot.
const CHILD: &str = "KC_CAPI_CASE";
/// The cases' test, by its full name.
const CASES: &str = "case_on_a_fresh_slot";

/// One case on a fresh slot. It runs only in the child processes the test below starts, since the
/// slot is the process's one.
#[test]
fn case_on_a_fresh_slot() {
    let Some(case) = env::var_os(CHILD) else {
        return;
    };
    match case.to_str() {
        // Self test, its reply written to the buffer and counted; a null input with a zero length
        // is no input, and a buffer of exactly the reply's length takes it.
        Some("self-test") => {
            assert_eq!(call_with(SELF_TEST, &[], kc_max_out()), (1, vec![OK]));
            let mut out = [0xaa; 1];
            // SAFETY: a null input with a zero length, which the contract allows (nothing is read),
            // and out valid for writes of its one byte.
            let len = unsafe { kc_call(SELF_TEST, core::ptr::null(), 0, out.as_mut_ptr(), 1) };
            assert_eq!((len, out), (1, [OK]));
            live();
        }
        // The dice-only ceremony to Ready, every words page as kcr.json's mnemonic and
        // braille.json's SeedBook numbers give it (wire.rs's word page: the position, the count,
        // the device and the devices, the sequence, the number, the word as a text, then faces 1-5,
        // four bytes each, the letter first), and Finish.
        Some("ceremony") => {
            ready();
            let mnemonic = seed("dice-50-words12", "mnemonic");
            let words: Vec<&str> = mnemonic.split(' ').collect();
            assert_eq!(words.len(), 12, "12 words");
            for (position, word) in (1..=12u8).zip(&words) {
                let page = call(WORD_PAGE, &[position]);
                let len = usize::from(page[8]);
                assert_eq!(
                    page[..6],
                    [OK, position, 12, 1, 1, position],
                    "insert {position}"
                );
                assert_eq!(
                    page[6..8],
                    seedbook(word).to_be_bytes(),
                    "insert {position}"
                );
                assert_eq!(&page[9..9 + len], word.as_bytes(), "insert {position}");
                let faces = &page[9 + len..];
                assert_eq!(faces.len(), 20, "insert {position}: five faces");
                // A blank face's letter is 0.
                let letters = word.bytes().chain([0; 5]);
                for (face, letter) in faces.chunks(4).zip(letters) {
                    assert_eq!(face[0], letter, "insert {position}");
                }
            }
            assert_eq!(call(END, &[]), [OK]);
            live();
        }
        // A null input with a non-zero length: halts before anything is read.
        Some("null-input") => {
            live();
            let mut out = vec![0; kc_max_out()];
            // SAFETY: a null input, which the call refuses before reading; out is valid for writes
            // of its length.
            let len = unsafe { kc_call(START, core::ptr::null(), 2, out.as_mut_ptr(), out.len()) };
            assert_eq!(len, -1);
            assert!(out.iter().all(|&byte| byte == 0), "nothing written");
            halted_for_good();
        }
        // An input one byte past the cap: halts before a byte is read, so the short buffer behind
        // the pointer is never read past.
        Some("past-the-input-cap") => {
            live();
            let input = [12u8, 2];
            let mut out = vec![0; kc_max_out()];
            // SAFETY: the call refuses a length past MAX_INPUT before reading through input, so no
            // byte past its two is read; out is valid for writes of its length.
            let len = unsafe {
                kc_call(
                    START,
                    input.as_ptr(),
                    MAX_INPUT + 1,
                    out.as_mut_ptr(),
                    out.len(),
                )
            };
            assert_eq!(len, -1);
            halted_for_good();
        }
        // A null output buffer, whatever its stated size: halts before the op runs.
        Some("null-out") => {
            live();
            // SAFETY: an empty input and a null out, which the call refuses before writing.
            let len = unsafe {
                kc_call(
                    SELF_TEST,
                    [0u8; 0].as_ptr(),
                    0,
                    core::ptr::null_mut(),
                    MAX_OUT,
                )
            };
            assert_eq!(len, -1);
            halted_for_good();
        }
        // A reply one byte longer than the buffer: the words page at Ready, wiped unread; nothing
        // is written, and the slot halts, words and all.
        Some("short-out-cap") => {
            ready();
            let page = call(WORD_PAGE, &[1]);
            let (len, out) = call_with(WORD_PAGE, &[1], page.len() - 1);
            assert_eq!(len, -1);
            assert!(out.iter().all(|&byte| byte == 0), "nothing written");
            halted_for_good();
        }
        // A buffer of no bytes: even Self test's one-byte reply does not fit.
        Some("zero-out-cap") => {
            live();
            assert_eq!(call_with(SELF_TEST, &[], 0), (-1, Vec::new()));
            halted_for_good();
        }
        // The guard's test op: in this build an op the table does not hold, which halts the slot
        // as internal through the reply's status, not -1.
        Some("guard-test-op") => {
            live();
            assert_eq!(call(GUARD_TEST_OP, &[]), HALTED_INTERNAL);
            halted_for_good();
        }
        _ => panic!("an unknown case"),
    }
}

/// Runs each case above in a child process of its own, on its own fresh slot: each passes.
#[test]
fn each_case_passes_on_a_fresh_slot() {
    for case in [
        "self-test",
        "ceremony",
        "null-input",
        "past-the-input-cap",
        "null-out",
        "short-out-cap",
        "zero-out-cap",
        "guard-test-op",
    ] {
        let output = Command::new(env::current_exe().expect("the test binary"))
            .args([CASES, "--exact"])
            .env(CHILD, case)
            .output()
            .expect("the child runs");
        let stdout = String::from_utf8(output.stdout).expect("text");
        assert!(output.status.success(), "{case} fails:\n{stdout}");
        assert!(stdout.contains("running 1 test\n"), "{case} ran");
    }
}
