//! Compile-fail tests (trybuild; CLAUDE.md rules 5 and 6; docs/build-plan.md "Sealed-state
//! compile-fail tests" and test matrix "Typestate misuse"; tasks/todo.md, M1 group 10). Each
//! fixture in `compile_fail/` must fail to build with exactly its pinned `.stderr`.
//!
//! The fixtures, by what they prove:
//! - Order: `dice_before_commit` (no dice before `commit`, and none before `start_dice`),
//!   `words_before_finish` (no words, braille, seal, Skip, check or reveal while rolling),
//!   `sealed_state_holds_no_secret` and `checking_state_holds_no_secret` (no mnemonic, braille, D,
//!   backup, watch-only export, registration, read-back, fingerprint or address in `Sealed` or
//!   `Checking`, and no `reveal` before a check starts), `no_skip_after_check_started`,
//!   `transitions_consume_the_session` (`commit` and `reveal` take the session by value, E0382),
//!   and `wiped_holds_no_secret`.
//! - Generated backup passphrases only: `backup_takes_no_passphrase` (neither typed words nor a
//!   display copy reaches `encrypt_backup` or `verify_backup`).
//! - Secrets cannot be printed or copied: no `Debug`, `Display` or `Clone` on the session, the
//!   mnemonic, D, the new and typed backup passphrases, the confirm challenge, the BIP39
//!   passphrase, `CheckedBackup`, the seal code and its QRs, the watch-only export, the braille
//!   views (`BrailleInserts`, `Insert`, `Face`) and the read-back result (`ReadbackResult`,
//!   `ReadbackMismatch`, `FaceVerdict`, `Dots`).
//! - Only core builds them: `no_struct_literals` (a `Ready` session, verified snapshots and
//!   proofs, a seal, a checked backup, typed passphrase words, a check nonce).
//! - Borrows end with their secret: `revealed_words_cannot_outlive_their_secret` and
//!   `views_cannot_outlive_their_secret` (braille views and insert words cannot outlive the
//!   session, nor a checked backup's reveals the backup; E0505).
//!
//! trybuild builds the fixtures with the features of the run, so every `.stderr` holds both in
//! `cargo test --workspace` (default features) and in `cargo test -p keepcrypt-core --features
//! test-sources`. The files are pinned to toolchain 1.98.1 and trybuild 1.0.121. A toolchain or
//! trybuild bump regenerates them in the same change: `TRYBUILD=overwrite cargo test -p
//! keepcrypt-core --test typestate`, then review the diff. A mismatch is written to `core/wip/`,
//! which git ignores.

#[test]
fn compile_fail() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/*.rs");
}
