//! Compile-fail tests (trybuild; CLAUDE.md rules 5 and 6; tasks/todo.md, M1 group 10). Each
//! fixture in `compile_fail/` must fail to build with exactly its pinned `.stderr`.
//!
//! The `.stderr` files are pinned to toolchain 1.98.1 and trybuild 1.0.121. A toolchain or
//! trybuild bump regenerates them in the same change: `TRYBUILD=overwrite cargo test -p
//! keepcrypt-core --test typestate`, then review the diff. trybuild's scratch output goes to
//! `core/wip/`, which git ignores.
//!
//! Group 2 starts the suite with the secret types and the session itself; group 10 adds the
//! typestate fixtures (dice before commit, words before finish, exports in Sealed and Checking,
//! skip after a check started, and the rest).

#[test]
fn compile_fail() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/*.rs");
}
