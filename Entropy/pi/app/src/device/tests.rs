//! The device module's own tests (tasks/todo.md, M4 group 10): the start mode.

use std::ffi::OsString;

use super::*;

/// Q35: no argument runs the ceremony; `--stopped`, which init passes once the firmware process
/// has ended, and any other argument whatever, is stop mode.
#[test]
fn no_argument_runs_and_any_argument_is_stop_mode() {
    let args = |words: &[&str]| words.iter().map(OsString::from).collect::<Vec<_>>();
    assert_eq!(mode(args(&[])), Mode::Run);
    for words in [
        &["--stopped"][..],
        &["--run"],
        &[""],
        &["--stopped", "--stopped"],
        &["x", "--stopped"],
    ] {
        assert_eq!(mode(args(words)), Mode::Stopped, "{words:?}");
    }
}
