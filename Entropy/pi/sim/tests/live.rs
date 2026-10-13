//! The live bin (tasks/todo.md, M3 group 12), run as a user runs it: pi/app's `App` over core on
//! `SimHal`, the keys typed on stdin, and nothing printed but screen ids.
//!
//! Which bytes `live.png` gets is tests/hal.rs's live-mode test: the simulator reads no file back.

use std::ffi::OsStr;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use keepcrypt_pi::screen::ScreenId;

/// The folder `name` under cargo's test tmpdir, removed with what it held.
fn cleared(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    match fs::remove_dir_all(&dir) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => panic!("cannot clear {}: {error}", dir.display()),
    }
    dir
}

/// Runs the bin with `args` and `stdin` typed in, to its end.
fn run<A: AsRef<OsStr>>(args: &[A], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_keepcrypt-pi-sim"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the bin starts");
    let mut input = child.stdin.take().expect("its stdin");
    input
        .write_all(stdin.as_bytes())
        .expect("the keys are typed");
    drop(input);
    child.wait_with_output().expect("the bin ends")
}

/// Runs `live --out out` with `stdin` typed in.
fn live(out: &Path, stdin: &str) -> Output {
    run(
        &[OsStr::new("live"), OsStr::new("--out"), out.as_os_str()],
        stdin,
    )
}

/// The names in `dir`.
fn names(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .expect("the live folder")
        .map(|entry| {
            let entry = entry.expect("an entry");
            entry.file_name().into_string().expect("a UTF-8 name")
        })
        .collect()
}

#[test]
fn live_mode_runs_the_app_over_core_and_prints_only_screen_ids() {
    let out = cleared("pi-sim-live");
    // From Home: New seed, 12 words, step 4's quota in 3 s, Continue, the commitment, 50 rolls of
    // 1 (up, then a press, each), Done, Skip and its confirm, the privacy gate, the first insert;
    // then ten minutes with no key on it.
    let mut lines = vec!["", "", "t3", "", ""];
    for _ in 0..50 {
        lines.extend(["w", ""]);
    }
    lines.extend(["3", "s", "", "", "", "t600"]);
    let output = live(&out, &(lines.join("\n") + "\n"));
    assert!(output.status.success(), "the session ends with its input");
    assert!(output.stderr.is_empty(), "nothing on stderr");
    let stdout = String::from_utf8(output.stdout).expect("text");
    let shown: Vec<&str> = stdout.lines().collect();
    // Every line is a screen id: the bin prints nothing else (rule 5).
    for line in &shown {
        assert!(
            ScreenId::ALL.iter().any(|id| id.name() == *line),
            "a line of stdout is no screen id"
        );
    }
    assert_eq!(shown[..5], ["boot", "home", "length", "wait", "hwrng"]);
    // The dice, then a redraw per press: 50 faces picked and 50 confirmed.
    assert_eq!(shown.iter().filter(|&&id| id == "dice").count(), 101);
    assert!(
        shown.ends_with(&[
            "privacy-gate",
            "words-insert",
            "cover",
            "idle-warning",
            "blank",
            "idle-wiped",
        ]),
        "the first insert, covered, warned, then wiped"
    );
    // Every present rewrote the one file.
    assert_eq!(names(&out), ["live.png"]);
}

#[test]
fn live_mode_starts_with_an_empty_stick_in_the_slot() {
    // Home's "Check a backup": usb-insert finds the stick at its first look, with no backup on it,
    // and usb-pick says so; KEY1 returns Home. With no stick, usb-insert would wait through t1.
    let out = cleared("pi-sim-live-stick");
    let output = live(&out, "s\ns\n\nt1\n1\n");
    assert!(output.status.success(), "the session ends with its input");
    assert!(output.stderr.is_empty(), "nothing on stderr");
    assert_eq!(
        String::from_utf8(output.stdout).expect("text"),
        "boot\nhome\nhome\nhome\nusb-insert\nusb-pick\nhome\n"
    );
}

#[test]
fn any_other_command_line_or_input_line_ends_the_bin_with_status_2_and_nothing_printed() {
    let out = cleared("pi-sim-live-refused");
    let dir = out.to_str().expect("a UTF-8 path");
    for args in [
        &[][..],
        &["live"],
        &["live", "--out"],
        &["live", dir],
        &["live", "--out", dir, "more"],
        &["capture", "--out", dir],
    ] {
        let output = run(args, "");
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}: nothing printed");
        assert!(output.stderr.is_empty(), "{args:?}: nothing on stderr");
        assert!(!out.exists(), "{args:?}: nothing written");
    }
    // A line that is no input ends a session after the screens so far.
    let output = live(&out, "s\nx\ns\n");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stdout).expect("text"),
        "boot\nhome\nhome\n"
    );
    assert!(output.stderr.is_empty(), "nothing on stderr");
    assert_eq!(names(&out), ["live.png"]);
}
