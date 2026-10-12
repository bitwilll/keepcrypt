//! The tests' one print site (tasks/todo.md, M3 Q31 (i)): a pi/sim test that prints includes this
//! module and prints only through `report`, and only screen ids, scenario names, counts and render
//! times, never screen text (rule 5).

use std::fmt;

/// Prints one line.
#[expect(
    clippy::print_stdout,
    reason = "pi/sim's one allowed print site in the tests (tasks/todo.md, M3 Q31 (i))"
)]
pub fn report(line: fmt::Arguments<'_>) {
    println!("{line}");
}
