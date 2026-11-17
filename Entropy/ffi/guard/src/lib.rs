//! keepcrypt-guard: the phone FFI's one panic catch (Q53, Q66; tasks/todo.md, M5 group 10 as the
//! re-plan and lead decisions M5-35 and M5-38 amend it). `guarded` runs the safe layer's dispatch,
//! keepcrypt-ffi's, under std::panic::catch_unwind: a panic has already dropped, and so wiped,
//! whatever the call had moved out of the slot when the catch halts the slot, and its payload is
//! dropped unread. The workspace's only catch, in a crate with no unsafe code.
//!
//! - **The surface is `guarded` alone** (the gate pins its line): keepcrypt-jni depends on this crate
//!   and jni-sys only, so it reaches the safe layer through the catch or not at all.
//! - **Wiping buffers both ways**: the input the boundary hands over is wrapped before any copy, and
//!   the reply is the safe layer's own; each is wiped when it is dropped.
//! - **Silent**: the first call sets a panic hook that prints nothing (rule 5), as the Pi's binary
//!   does (pi/app's device/linux.rs), since a panic's message could name a secret; so no boundary
//!   needs `JNI_OnLoad` for it.
#![forbid(unsafe_code)]

use std::sync::Once;

use keepcrypt_ffi::Zeroizing;
use keepcrypt_ffi::ceremony::HaltReason;
#[cfg(not(test))]
use keepcrypt_ffi::dispatch;

/// The silent panic hook, set once.
static QUIET: Once = Once::new();

/// `op` with `input` on the phone's slot, and the reply's bytes (keepcrypt-ffi's wire.rs): the one
/// call per boundary (M5-21). A panic in the call halts the slot as a panic and gives the halt
/// status, which names the slot's first halt (a panic's, unless the call had halted it before).
pub fn guarded(op: u32, input: Vec<u8>) -> Zeroizing<Vec<u8>> {
    let input = Zeroizing::new(input);
    QUIET.call_once(|| std::panic::set_hook(Box::new(|_| {})));
    match std::panic::catch_unwind(|| dispatch(op, &input)) {
        Ok(reply) => reply,
        Err(_) => keepcrypt_ffi::halt(HaltReason::Panic),
    }
}

/// Under test only (M5-38): the op that panics inside a Ready call.
#[cfg(test)]
const PLANTED: u32 = u32::MAX;

/// Under test only: set when an `Observed` holding a word page is dropped.
#[cfg(test)]
static OBSERVED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Under test only: a reply in the planted call's frame, which records its own drop.
#[cfg(test)]
struct Observed(Zeroizing<Vec<u8>>);

#[cfg(test)]
impl Drop for Observed {
    fn drop(&mut self) {
        let page = self.0.first() == Some(&keepcrypt_ffi::wire::OK) && self.0.len() > 1;
        OBSERVED.store(page, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Under test only (M5-38): keepcrypt-ffi's dispatch, but `PLANTED` makes a Ready call on the
/// real slot (the first word page), hands its reply to an `Observed` in this frame and panics, as
/// a panic in core would unwind through what a Ready call had moved out with the session.
#[cfg(test)]
fn dispatch(op: u32, input: &[u8]) -> Zeroizing<Vec<u8>> {
    if op != PLANTED {
        return keepcrypt_ffi::dispatch(op, input);
    }
    let page = Observed(keepcrypt_ffi::dispatch(
        keepcrypt_ffi::wire::WORD_PAGE,
        &[1],
    ));
    panic!(
        "a planted panic inside a Ready call, over {} bytes",
        page.0.len()
    );
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::process::Command;
    use std::sync::atomic::Ordering;

    use keepcrypt_ffi::ceremony::{FFI, Holds, StageKind};
    use keepcrypt_ffi::wire::{self, HALTED, OK};

    use super::{OBSERVED, PLANTED, guarded};

    /// Set for the child process alone, where a scenario runs with its output captured.
    const CHILD: &str = "KC_GUARD_PANIC_CHILD";
    /// The scenarios' tests, by their full names.
    const READY: &str = "tests::scenario_a_panic_inside_a_ready_call";
    const FIRST: &str = "tests::scenario_a_panic_in_the_first_call";
    /// wire.rs's halt codes (its PINNED_HALTS): the halt status of an internal halt, and of a
    /// caught panic's.
    const INTERNAL: [u8; 2] = [HALTED, 4];
    const PANIC: [u8; 2] = [HALTED, 6];

    /// kcr.json's rolls of gate seed dice-50-words12, as faces (rule 12: vectors/ only).
    fn rolls() -> Vec<u8> {
        let kcr = include_str!("../../../vectors/kcr.json");
        let seed = kcr
            .find("\"name\": \"dice-50-words12\"")
            .expect("the gate seed");
        let field = "\"rolls\": \"";
        let start = seed + kcr[seed..].find(field).expect("its rolls") + field.len();
        let end = start + kcr[start..].find('"').expect("their end");
        let faces: Vec<u8> = kcr[start..end].bytes().map(|digit| digit - b'0').collect();
        assert_eq!(faces.len(), 50, "50 rolls");
        assert!(faces.iter().all(|face| (1..=6).contains(face)), "faces");
        faces
    }

    /// One call through the catch, and its reply's bytes.
    fn call(op: u32, input: &[u8]) -> Vec<u8> {
        guarded(op, input.to_vec())[..].to_vec()
    }

    /// Group 10's second item and group 11's halt by panic, by M5-38's route: the real slot driven
    /// to Ready through keepcrypt-ffi's dispatch on gate seed dice-50-words12 (12 words, dice only,
    /// Skip), then the planted panic. The unwind drops the word page the call held, the catch
    /// halts the slot as a panic, which holds nothing more, and every later call halts with the
    /// panic's code (M5 commit U3a), the shell's bug of an op the table does not hold included. It
    /// runs only in the child process a test below starts, since the slot is the process's one.
    #[test]
    fn scenario_a_panic_inside_a_ready_call() {
        if env::var_os(CHILD).is_none() {
            return;
        }
        assert_eq!(call(wire::START, &[12, 2]), [OK]);
        assert_eq!(call(wire::COMMIT, &[]), [OK]);
        assert_eq!(call(wire::START_DICE, &[]), [OK]);
        for face in rolls() {
            assert_eq!(call(wire::PUSH_ROLL, &[face]), [OK]);
        }
        assert_eq!(call(wire::FINISH, &[]), [OK]);
        assert_eq!(call(wire::SKIP_CHECK, &[]), [OK]);
        assert_eq!(FFI.holds().stage, StageKind::Ready);
        assert!(!OBSERVED.load(Ordering::SeqCst), "nothing observed yet");

        assert_eq!(call(PLANTED, &[]), PANIC);
        assert!(
            OBSERVED.load(Ordering::SeqCst),
            "the unwind dropped the Ready call's word page"
        );
        let halted = Holds {
            stage: StageKind::Halted,
            kept: false,
            report: false,
            snapshot: false,
            backup: false,
        };
        assert_eq!(FFI.holds(), halted);
        // Every op of the table, 1-38, and two it does not hold; then a start with its input.
        for op in 0..=39 {
            assert_eq!(call(op, &[]), PANIC, "op {op}");
        }
        assert_eq!(call(wire::START, &[12, 2]), PANIC);
        assert_eq!(FFI.holds(), halted);
    }

    /// The hook is set before the first catch: on a fresh slot the process's first call through
    /// guarded is the planted one, whose page call gives no page at Idle (it halts the slot, as
    /// internal), and it panics. The catch gives the halt status with the slot Halted, naming that
    /// first halt (M5 commit U3a), and the test below sees nothing on stderr. It runs only in the
    /// child process that test starts.
    #[test]
    fn scenario_a_panic_in_the_first_call() {
        if env::var_os(CHILD).is_none() {
            return;
        }
        assert_eq!(FFI.holds().stage, StageKind::Idle);
        assert_eq!(call(PLANTED, &[]), INTERNAL);
        assert!(!OBSERVED.load(Ordering::SeqCst), "no page at Idle");
        assert_eq!(FFI.holds().stage, StageKind::Halted);
    }

    /// Runs `scenario` in a child process, as pi/sim's no-output tests run their binary: it
    /// passes, nothing reaches stderr (the planted panic's message would, but for the silent hook)
    /// and stdout holds the harness's own lines alone.
    fn passes_silently(scenario: &str) {
        let output = Command::new(env::current_exe().expect("the test binary"))
            .args([scenario, "--exact", "--nocapture"])
            .env(CHILD, "1")
            .output()
            .expect("the child runs");
        let stdout = String::from_utf8(output.stdout).expect("text");
        assert!(output.status.success(), "the scenario fails:\n{stdout}");
        assert!(output.stderr.is_empty(), "nothing on stderr");
        assert!(stdout.contains("running 1 test\n"), "the scenario ran");
        let harness = format!("test {scenario} ... ok");
        let ours: Vec<&str> = stdout
            .lines()
            .filter(|line| {
                !(line.is_empty()
                    || line.starts_with("running ")
                    || line.starts_with("test result: ok.")
                    || *line == harness)
            })
            .collect();
        assert!(ours.is_empty(), "stdout holds only the harness's lines");
    }

    #[test]
    fn a_panic_inside_a_ready_call_halts_drops_what_it_held_and_prints_nothing() {
        passes_silently(READY);
    }

    /// The silent hook is set before the first catch, not after it: a panic in the process's first
    /// call prints nothing either.
    #[test]
    fn a_panic_in_the_first_call_prints_nothing() {
        passes_silently(FIRST);
    }
}
