# Task: KeepCrypt milestones M0 and M1

Spec: `docs/build-plan.md` (milestones, core API, CI rules) and `docs/seal-watchonly-braille.md`.
Claude Code: refine this plan, then **check in with the owner before writing code**.

## Open questions for the owner (answer before M0 starts)

- [ ] Licence: MIT, Apache-2.0, or dual MIT/Apache-2.0?
- [ ] GitHub organisation and repository name
- [ ] Release signing: minisign or GPG, and who holds the key offline?
- [ ] Registry domain name (needed later, in M9)
- [ ] Confirm the default seed length of 12 words (one KeepCrypt Hinge or Screw); 24 words stay available
- [ ] For 24-word seeds on two devices, how should the second set of inserts be labelled, since both are numbered 01-12?

## M0: Repo bootstrap

### Plan
- [ ] Cargo workspace with crates `core`, `ffi`, `pi/app`, `pi/sim`; `rust-toolchain.toml` pinned to a specific stable release
- [ ] `#![forbid(unsafe_code)]` in `core`; `core` has no logging dependency
- [ ] `deny.toml`: ban the `rand` family (`rand`, `rand_core` users other than `getrandom`, `fastrand`, `oorandom`, `nanorand`) for `core`; licence allow-list
- [ ] `clippy.toml`: `disallowed-methods` for `Result::unwrap_or`, `unwrap_or_default`, `unwrap_or_else` inside `core`
- [ ] `scripts/banned-api-check.sh`: grep gate for `Math.random`, `java.util.Random`, `kotlin.random`, `arc4random_uniform`, `import random`, `mt19937`, `srand(`, `URLSession`, `NWConnection`, `setPrimaryClip`, `UIPasteboard`
- [ ] CI workflow: fmt, clippy `-D warnings`, test, `cargo deny`, `cargo audit`, banned-API gate
- [ ] Cross-compile job: `arm-unknown-linux-gnueabihf`, `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`, `aarch64-apple-ios`, `aarch64-apple-ios-sim`
- [ ] `vectors/`: BIP39 `vectors.json` (trezor/python-mnemonic), Coldcard `rolls.py`/`rolls12.py` expected outputs for fixed roll strings, an age test-kit subset, and `seal.json` holding the docs' seal and go-ahead vectors
- [ ] `SECURITY.md` stub and `LICENSE` (after the owner answers)
- [ ] `CODEOWNERS` requiring two approvals for `core/`, `ffi/`, `pi/os/`

### Verification
- [ ] CI is green on a clean clone
- [ ] Cross-compile job log shows all six targets built
- [ ] Negative test: a throwaway branch adding `rand` to `core` fails `cargo deny`
- [ ] Negative test: a throwaway file containing `Math.random` fails the banned-API gate

## M1: Core crate (`keepcrypt-core`)

### Plan (each module with unit tests before moving on)
- [ ] `secret`: zeroizing wrappers; a test formats every public type and asserts no BIP39 word appears
- [ ] `kat`: known-answer tests for SHA-256, SHA-512, BIP39, age, seal, braille; run in `Session::new`
- [ ] `pool`: SHA-512 pool with `source id u16 || len u64 BE || data` records and the `KCE/v1/pool` tag
- [ ] `health`: Repetition Count, Adaptive Proportion and startup tests (SP 800-90B, alpha = 2^-20)
- [ ] `source`: `getrandom(64)` (blocking, short read = error), credit policy per platform (Pi: 512 credited hwrng bits at 4 bits per byte), the `test-sources` feature with the `KC_TEST_SOURCE_DO_NOT_SHIP` marker
- [ ] `dice`: faces 1 to 6 only, undo, bit counting, ASCII string R
- [ ] `seed`: C, E (mixed), E (dice only), 12/24-word BIP39, fingerprint, first BIP84 address
- [ ] `seal`: code, tag (over the 26-char code without dashes), Seal ID, 8x8 grid and colour index, check nonce and go-ahead code G, `.kcr` snapshot parse with bucket-root recomputation and Ed25519 header verify, bucket-proof verify, lookup
- [ ] `braille`: SeedBook format (see `docs/KeepCrypt-SeedBook_Braille.pdf`): grade 1 cells, insert faces 1-5 with significant blanks, 1-based SeedBook numbers, mirror-pair flags (e/i, d/f, h/j, r/w), number sign for passphrases, and `check_readback` for the metal read-back
- [ ] `descriptor`: BIP84 account xpub, receive and change descriptors with checksums, BC-UR `crypto-account`
- [ ] `backup`: age scrypt encrypt/decrypt (log2 N = 18), 8-word passphrase generator, plaintext format v1 including `braille:` lines
- [ ] `session`: typestate `Collecting → Committed → Rolling → Sealed → (Checking) → Ready`; `skip_check()` only from `Sealed`; `reveal(GoAhead)` is the only way from `Checking` to `Ready`; `discard()` wipes; `Wiped::restart()` sets the 99-roll minimum after a collision
- [ ] `vectors/braille.json` (all 2,048 words with SeedBook numbers, faces and mirror flags; must match ABANDON 0001, ACT 0020, METAL 1121, ZOO 2048) and `vectors/keepcrypt.json` (C, E for fixed D and rolls)

### Verification
- [ ] All vectors pass, including the seal vector in `CLAUDE.md`
- [ ] Source-substitution test: a fixed stub gives a known D; changing one stub byte changes D
- [ ] Error-injection test for every source and health test: the session halts and wipes
- [ ] `trybuild` compile-fail tests: dice before commit, reveal before finish, mnemonic/D/backup/export in the sealed or checking state, skip after a check started
- [ ] Go-ahead tests: the vector in `CLAUDE.md` passes; a code for another T or nonce is rejected; forged, truncated and wrong-bucket proofs are rejected; a proof containing T wipes the session
- [ ] Dice-only output equals Coldcard `rolls.py`/`rolls12.py` for the fixed roll strings
- [ ] Line coverage in `core/` is at least 95% (`cargo llvm-cov`)
- [ ] Clippy, deny, audit and the banned-API gate are clean

## Review
_Added after completion, with pasted proof for every ticked item._
