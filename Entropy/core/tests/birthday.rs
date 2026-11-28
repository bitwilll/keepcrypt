//! The birthday-collision test (docs/design.md "Prove the path" 3; docs/build-plan.md test matrix
//! "Birthday collision"; tasks/todo.md, M7 Stage A). A generator whose state is narrower than
//! about 36 bits repeats a device leg within 1,000,000 sessions: about 116 repeated pairs at 32
//! bits, about 7 at 36. The Coldcard bug was a 32-bit reseed.
//!
//! - `one_million_real_device_legs_never_repeat` (A1, nightly): 1,000 child processes, each making
//!   1,000 real phone sessions on the OS source (no stub) and committing them, so the legs span
//!   process restarts; any repeated commitment fails. The test compares commitments C, never D:
//!   C = SHA256("KCE/v1/commit" || D) is public (safe to display before any roll) and equal exactly
//!   when D is, so the test handles no secret. Each child writes its 1,000 C values, raw, to a file
//!   of its own under cargo's CARGO_TARGET_TMPDIR, which the parent reads and removes. Core never
//!   prints (rule 5, core/clippy.toml), tests included, so the counts live in the assertions.
//! - `narrowed::narrowed_states_are_caught` (A2, `test-sources`): stub sessions whose every OS byte
//!   comes from a state of 24 or 28 bits. Their commitments must repeat exactly as often as the
//!   states do (each repeated state gives the same C, each distinct one a different C), and that
//!   is more than zero. At 2^16 sessions those widths expect about 128 and 8 repeated pairs, the
//!   regime of 32 and 36 bits at 1,000,000 (n^2 / 2^(k+1)), at a fifteenth of the cost (lead
//!   decision M7-1). The states are a fixed SHA-256 counter, so the counts never change.
//!
//! Both are `#[ignore]`d, so `cargo test` stays fast; the nightly workflow runs them by name.

use keepcrypt_core::{Mode, Platform, SeedLength, Session};

/// Sessions per child process, and child processes, for A1.
const PER_CHILD: usize = 1_000;
const CHILDREN: usize = 1_000;

/// The child's output file, set by the parent; the child does nothing without it.
const CHILD_OUT: &str = "KC_BIRTHDAY_OUT";

/// Repeated pairs among `values`: a value seen k times adds k(k-1)/2. Sorting, so no hasher.
fn repeated_pairs<T: Ord>(mut values: Vec<T>) -> u64 {
    values.sort_unstable();
    let mut pairs = 0u64;
    let mut run = 1u64;
    for i in 1..values.len() {
        if values[i] == values[i - 1] {
            run += 1;
        } else {
            pairs += run * (run - 1) / 2;
            run = 1;
        }
    }
    pairs + run * (run - 1) / 2
}

/// The workers to run at once: the machine's CPUs (fail closed: no default).
fn workers() -> usize {
    std::thread::available_parallelism()
        .expect("the CPU count")
        .get()
}

/// One child process's sessions: run only by the parent below, which names the output file.
#[test]
#[ignore = "a child of one_million_real_device_legs_never_repeat"]
fn birthday_child() {
    let Some(out) = std::env::var_os(CHILD_OUT) else {
        return;
    };
    let mut bytes = Vec::with_capacity(PER_CHILD * 32);
    for _ in 0..PER_CHILD {
        let c = Session::new(SeedLength::Words12, Mode::Mixed, Platform::Phone)
            .and_then(Session::commit)
            .expect("a committed real session")
            .commitment()
            .expect("C in Mixed mode");
        bytes.extend_from_slice(&c);
    }
    std::fs::write(out, bytes).expect("the child's file");
}

/// Runs child `n` and returns its commitments.
fn run_child(n: usize) -> Vec<[u8; 32]> {
    let out = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("birthday-{n}.bin"));
    let exe = std::env::current_exe().expect("the test binary");
    let status = std::process::Command::new(exe)
        .args([
            "birthday_child",
            "--exact",
            "--ignored",
            "--test-threads=1",
            "--quiet",
        ])
        .env(CHILD_OUT, &out)
        .stdout(std::process::Stdio::null())
        .status()
        .expect("a child process");
    assert!(status.success(), "child {n} failed");
    let bytes = std::fs::read(&out).expect("the child's file");
    std::fs::remove_file(&out).expect("the child's file removed");
    assert_eq!(
        bytes.len(),
        PER_CHILD * 32,
        "child {n} reported every session"
    );
    let (chunks, rest) = bytes.as_chunks::<32>();
    assert!(rest.is_empty(), "whole commitments");
    chunks.to_vec()
}

#[test]
#[ignore = "nightly: 1,000,000 real sessions (tasks/todo.md, M7 A1)"]
fn one_million_real_device_legs_never_repeat() {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let all: Vec<[u8; 32]> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers())
            .map(|_| {
                scope.spawn(|| {
                    let mut mine = Vec::new();
                    loop {
                        let n = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if n >= CHILDREN {
                            break mine;
                        }
                        mine.extend(run_child(n));
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("a worker"))
            .collect()
    });
    assert_eq!(all.len(), PER_CHILD * CHILDREN, "1,000,000 device legs");
    let pairs = repeated_pairs(all);
    assert_eq!(
        pairs, 0,
        "{pairs} repeated device legs in 1,000,000: the source's state is narrow"
    );
}

#[cfg(feature = "test-sources")]
mod narrowed {
    use super::{repeated_pairs, workers};
    use keepcrypt_core::{Mode, Platform, SeedLength, Session, StubEntropy, StubSource, WipeProbe};
    use sha2::{Digest, Sha256};

    /// Sessions per width: 2^16.
    const SESSIONS: usize = 1 << 16;

    /// State i of `bits` bits (24 or 28): the top bits of SHA256("KCE/test/birthday-state" || i),
    /// the rest of four bytes cleared. Byte operations only; no integer narrowing.
    fn state(i: usize, bits: u32) -> [u8; 4] {
        let digest = Sha256::new()
            .chain_update(b"KCE/test/birthday-state")
            .chain_update(i.to_be_bytes())
            .finalize();
        let mut s = [digest[0], digest[1], digest[2], digest[3]];
        match bits {
            24 => s[3] = 0,
            28 => s[3] &= 0xF0,
            other => panic!("no narrowed width {other}"),
        }
        s
    }

    /// C of a phone session whose every OS byte comes from `state`.
    fn commitment(state: [u8; 4]) -> [u8; 32] {
        let mut label = b"KCE/test/narrowed/".to_vec();
        label.extend_from_slice(&state);
        let stub = StubSource::new(StubEntropy::Stream(label), &WipeProbe::new());
        Session::new_with_stub(
            SeedLength::Words12,
            Mode::Mixed,
            Platform::Phone,
            stub,
            None,
        )
        .and_then(Session::commit)
        .expect("a committed stub session")
        .commitment()
        .expect("C in Mixed mode")
    }

    /// (repeated pairs among the states, among their sessions' commitments).
    fn pairs_at(bits: u32) -> (u64, u64) {
        let states: Vec<[u8; 4]> = (0..SESSIONS).map(|i| state(i, bits)).collect();
        let n = workers();
        let commitments: Vec<[u8; 32]> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..n)
                .map(|w| {
                    let states = &states;
                    scope.spawn(move || {
                        states
                            .iter()
                            .skip(w)
                            .step_by(n)
                            .map(|&s| commitment(s))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().expect("a worker"))
                .collect()
        });
        assert_eq!(commitments.len(), SESSIONS);
        (repeated_pairs(states), repeated_pairs(commitments))
    }

    #[test]
    #[ignore = "nightly canary (tasks/todo.md, M7 A2)"]
    fn narrowed_states_are_caught() {
        let (s24, c24) = pairs_at(24);
        let (s28, c28) = pairs_at(28);
        assert_eq!(c24, s24, "24 bits: the commitments repeat as the states do");
        assert_eq!(c28, s28, "28 bits: the commitments repeat as the states do");
        assert!(c28 > 0, "a 28-bit state went unseen");
        assert!(
            c24 > c28,
            "the narrower state repeats more ({c24} against {c28})"
        );
    }
}

#[test]
fn repeated_pairs_counts_each_pair() {
    let (a, b) = ([1u8; 32], [2u8; 32]);
    assert_eq!(repeated_pairs::<[u8; 32]>(vec![]), 0);
    assert_eq!(repeated_pairs(vec![a, b]), 0);
    assert_eq!(repeated_pairs(vec![a, b, a]), 1);
    assert_eq!(repeated_pairs(vec![a, a, a, b, b]), 4);
}
