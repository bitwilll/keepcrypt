# Task: KeepCrypt milestones M0 and M1

Spec: `docs/build-plan.md` (milestones, core API, CI rules) and `docs/seal-watchonly-braille.md`.
Claude Code: refine this plan, then **check in with the owner before writing code**.

## Open questions for the owner

### Needed before any M0 code (answered 2026-10-09)
- [x] **Repo root:** the `Entropy-Keep Crypt` folder. The starter files moved up from `keepcrypt-starter/` so
      `CLAUDE.md` sits at the root; `keepcrypt-starter.zip` stays untracked (listed in `.git/info/exclude`).
- [x] **Local toolchain:** the owner installed `rustup` (Homebrew, keg-only, so `/opt/homebrew/opt/rustup/bin` goes
      first on `PATH`). Installed: toolchain 1.98.1 with the six targets; cargo-deny 0.20.2, cargo-audit 0.22.2 and
      cargo-vet 0.10.2. Rustup's auto-install also added stable 1.99.0 as the default; the repo pin overrides it.
- [x] **Downloads for `vectors/`:** approved.
- [x] **Licence:** dual MIT/Apache-2.0.
- [x] **SeedBook PDF:** goes into the repo.
- [x] **Core crates in M0:** approved.

### Needed before the M0 gate (answered 2026-10-09)
- [x] **GitHub:** `bitwilll/keepcrypt` (public), with this project in `Entropy/`. The local clone is
      `Desktop/Claude Projects/keepcrypt`; the old `Entropy-Keep Crypt` folder is no longer the working copy.
- [x] **Git identity:** the `gh` CLI is signed in as `bitwilll` (admin). Commits use that account with its GitHub
      no-reply address (`211763171+bitwilll@users.noreply.github.com`), set in the clone's local git config.
- [x] **Reviewers and disclosure:** the CODEOWNERS owner is `msaval02@nyit.edu`, the bitwilll account's verified
      email. GitHub rejected `admin@keepcrypt.com` as an unknown owner, and now reports 0 CODEOWNERS errors. The
      SECURITY.md disclosure address is `admin@keepcrypt.com`. Branch protection with two required approvals is not set
      yet; `main` is unprotected today.
- [x] **Approvals:** the owner answered "OK" to the "Changes during M0" list.
- Monorepo adjustments, made when moving in:
  - The workflow lives at the repo root as `.github/workflows/entropy-ci.yml`. It runs every step in `Entropy/`, and
    it triggers only on changes under `Entropy/` or to itself.
  - CODEOWNERS sits at the repo root with `/Entropy/` paths.
  - `scripts/check-path-deps.sh` also refuses a cargo config in any parent directory, because cargo reads those and a
    config at the monorepo root would apply to `Entropy/`. A 37th canary, `cargo-config-parent`, proves it.
  - `LICENSE-MIT`'s holder matches the root `LICENSE` ("bitwilll").
  - The owner's `Entropy/1.txt` placeholder is left as it was.
  - If the Entropy checks are ever made required in branch protection, the path filter means PRs that do not touch
    `Entropy/` never report them. Use a ruleset scoped to these paths, or drop the filter.

### Needed before M1 (found while planning; M0 is not blocked)
- [ ] **The `age` crate breaks three rules.** `age` 0.12.1 hard-depends on `rand` 0.8 (banned in core, rule 1). It
      pulls `log` through `i18n-embed` (rule 5). It draws the file key and nonce from its own `OsRng`, which is a
      second OS-randomness path (rule 1). Options: (a) implement the age v1 scrypt-only format in `core/backup` from
      RustCrypto primitives (`scrypt`, `chacha20poly1305`, `hkdf`, `hmac`, `base64`), with key and nonce from
      `core/src/source`, proven against the CCTV kit and the reference `age` CLI in both directions; (b) keep `age`
      and allow `rand` and `log` only beneath it. Recommended: (a). It gives one RNG path and a far smaller tree,
      but it composes primitives in our own code, which needs your sign-off under rule 11.
- [ ] **The BC-UR encoder breaks rule 1.** `ur` 0.5.2 (and `bc-ur`, which wraps it) requires `rand_xoshiro`, the
      non-cryptographic PRNG the BC-UR spec uses for multi-part fountain codes. It only sees public data, but it is
      a banned crate. Options: (a) single-frame UR only, since a one-key `crypto-account` fits in one QR and needs no
      PRNG; (b) do the UR encoding outside core; (c) allow `rand_xoshiro` beneath the UR crate only.
      Recommended: (a).
- [ ] **No Ed25519 crate is on the approved list**, yet snapshot and go-ahead-QR verification need one.
      Recommended: `ed25519-dalek` 3.x, verify-only, without its optional `rand_core` feature.
- [ ] **`trybuild`**, needed for the rule 6 compile-fail tests, is not on the list either; it needs approval and a
      vet entry.
- [ ] Confirm the default seed length of 12 words (one KeepCrypt Hinge or Screw); 24 words stay available
- [ ] For 24-word seeds on two devices, how should the second set of inserts be labelled, since both are numbered
      01-12? This affects `braille` in M1.

### Later
- [ ] Release signing: minisign or GPG, and who holds the key offline? (M7)
- [ ] Registry domain name (M9; until then M1 uses a placeholder constant in the check-QR URL)

### Notes for later milestones
- The release symbol check expects libc `getrandom` and no `arc4random`. That fits Linux (Pi, Android). On iOS the
  `getrandom` crate calls `CCRandomGenerateBytes`, so M6 or M7 needs its own list of expected symbols.
- UniFFI converts Rust panics into Kotlin and Swift errors that app code could catch and then carry on. M5 must make
  any core panic wipe the session.

## M0: Repo bootstrap

### Decisions built into this plan (override any of them)
- The device workspace holds `core`, `ffi`, `pi/app` and `pi/sim` only. `registry/server` gets its own workspace and
  `Cargo.lock` in M9, so no network crate can ever enter the device lockfile, and the device workspace can ban
  network crates outright.
- Every negative test becomes a permanent CI canary instead of a one-off throwaway branch, so each gate is proven to
  fire on every run. Coldcard's `#ifndef` guard stopped firing silently; principle 7 is "test the path, not the presence".
- Cross-compiling in M0 means building the `keepcrypt-core` rlib for each target. Linking a real Pi binary moves to the
  Buildroot toolchain in M4, and the app libraries (`cdylib`, `staticlib`) move to M5 and M6.
- Supply-chain cool-off: each pinned toolchain and crate version must have been released at least 14 days earlier.

### Plan
**Repository**
- [x] Git: the project lives in `Entropy/` of `bitwilll/keepcrypt`. The first commit on `m0-bootstrap` holds the
      starter files exactly as delivered; M0 merges by PR bitwilll/keepcrypt#1.
- [x] `.gitignore`: `target/`, `.DS_Store`, `*.age` (everywhere, vectors/ included), key and signing files (`*.key`,
      `*.sec`, `*.pem`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `*.p8`, `keystore.properties`, `id_ed25519*`,
      `id_rsa*`, `*.gpg`), `.env`, `.env.*`, `.envrc`, `.netrc`, Python bytecode
- [x] Local setup, once the toolchain question is answered: rustup, the pinned toolchain with its six targets, and
      cargo-deny, cargo-audit and cargo-vet. Only host builds run locally; the six-target proof comes from CI.

**Cargo workspace**
- [x] Root `Cargo.toml`: a virtual workspace with edition 2024, resolver 3, shared `[workspace.package]` (version,
      licence, `rust-version` equal to the pinned toolchain) and `publish = false`. `scripts/testdata/` is excluded.
- [x] `rust-toolchain.toml`: an exact `x.y.z` stable release, `profile = "minimal"`, the components `rustfmt`,
      `clippy` and `llvm-tools-preview` (for `cargo llvm-cov` in M1), and the six targets
- [x] `core` (`keepcrypt-core`, lib): `#![forbid(unsafe_code)]`; clippy `print_stdout`, `print_stderr` and `dbg_macro`
      set to deny; no logging dependency; the approved crates below. No M1 modules yet.
- [x] `ffi` (`keepcrypt-ffi`, lib): depends on `core` only; UniFFI waits until M5
- [x] `pi/app` (`keepcrypt-pi`, lib + bin) and `pi/sim` (`keepcrypt-pi-sim`, bin): `main` stubs only; the hardware
      and SDL crates wait until M3 and M4
- [x] `Cargo.lock` committed *(written and checked; committed with the first commit)*

Core crates for owner approval (exact versions are recorded in Review; `age`, the BC-UR encoder and Ed25519 wait for
the M1 questions above):

| Crate | Features | Note |
| --- | --- | --- |
| `getrandom` 0.4 | default | The only OS RNG; its per-target backends get exercised by the cross-compile |
| `sha2` 0.11 | default | Pool and hashes |
| `bip39` | `std`, `zeroize`; no `rand` | Version 3.0.0 came out 2026-09-17; otherwise 2.x |
| `bitcoin` 0.32 | `default-features = false`, `std`; no `rand-std`, no `secp-recovery` | Pulls in the C code of `secp256k1-sys` |
| `miniscript` 13 | `std` | Descriptors and checksums |
| `zeroize`, `secrecy` 0.10, `thiserror` 2 | default (`zeroize_derive` on) | Secret wrappers and errors |

As built (2026-10-09), with deviations from the table above:
- `zeroize` 1.9.0, not 1.9.1 (3 days old); its derive feature is named `derive`.
- `sha2` 0.11.0 with its `zeroize` feature on, so hash state that held secret input is wiped on drop.
- `miniscript` 13.1.0 without default features: its `std` feature would switch `bitcoin`'s `secp-recovery` back on.
- `bip39` 3.0.0 with `alloc` and `zeroize` (not `std`; see "Changes during M0", item 3); `bitcoin` 0.32.102 with
  `std` only; `getrandom` 0.4.3; `secrecy` 0.10.3; `thiserror` 2.0.21.
- Lockfile cool-off, by elapsed time (14 x 24 h): `libc` 0.2.189, `cc` 1.4.7, `find-msvc-tools` 0.1.13,
  `bitcoin-consensus-encoding` 1.2.0, `bitcoin-internals` 0.6.0. All 46 locked third-party crates pass; the table is
  in Review.
- Licences the graph needs beyond MIT, Apache-2.0 and CC0-1.0: MITNFA (`hex_lit`) and Unicode-3.0 (`unicode-ident`).

**Gates**
- [x] `deny.toml`, covering the device workspace including dev-dependencies (as built: also all features and no
      target filter; see "Changes during M0", item 6):
  - bans with no exceptions: the rand family (`rand`, `rand_core`, `rand_chacha`, `rand_xoshiro`, `rand_xorshift`,
    `rand_pcg`, `rand_hc`, `rand_isaac`, `fastrand`, `oorandom`, `nanorand`, `tinyrand`, `turborand`); network crates
    (`tokio`, `mio`, `hyper`, `h2`, `reqwest`, `ureq`, `curl`, `isahc`, `axum`, `async-std`); logging crates (`log`,
    `tracing`, `slog`, `env_logger`)
  - sources: crates.io only, with git and other registries denied, since Coldcard's bug came from a submodule
  - licences: exactly the licences in the current graph. As built: MIT, Apache-2.0, CC0-1.0, MITNFA (`hex_lit`),
    Unicode-3.0 (`unicode-ident`); an unused allowance fails
  - advisories: deny vulnerabilities, unsound crates and yanked versions; warn on unmaintained crates; warn on
    multiple versions of one crate
- [x] `core/clippy.toml`, with the same file in `ffi/` so a core failure cannot be swallowed at the FFI boundary
      (as built: also `pi/app/`, 20 entries, and no in-code exceptions; "Changes during M0", items 1 and 2):
      `disallowed-methods` covers `Result::{unwrap_or, unwrap_or_default, unwrap_or_else, map_or, map_or_else, ok}`,
      `Option::{unwrap_or, unwrap_or_default, unwrap_or_else, map_or, map_or_else}` and `std::panic::catch_unwind`.
      `.ok()` and the `Option` forms are included because `.ok().unwrap_or(x)` would slip past a ban on `Result` alone.
      ~~Any exception needs `#[expect(clippy::disallowed_methods, reason = "...")]`~~ As built, no in-code exception
      is possible (`forbid`); an exception is a reviewed change to `Cargo.toml`.
- [x] `scripts/banned-api-check.sh` (POSIX `sh` and `grep`, no dependencies) scans the repo except `docs/`, `tasks/`,
      `CLAUDE.md` and `scripts/testdata/`, and prints `file:line` for every hit. As built it is wider than the list
      below: categories RNG, Network, Clipboard (copy/share UI), Rule1, FailOpen and Include. The script header is the
      authoritative pattern list; see "Changes during M0", items 2 and 5.
  - RNG: `Math.random`, `java.util.Random`, `ThreadLocalRandom`, `kotlin.random`, `arc4random`,
    `SystemRandomNumberGenerator`, `.random(` and `.shuffled(` (Kotlin and Swift use the default RNG through these),
    `import random`, `from random`, `numpy.random`, `mt19937`, `rand(`, `srand(`, `drand48`
  - Network (skips `registry/`): `URLSession`, `NWConnection`, `CFNetwork`, `java.net.`, `HttpURLConnection`,
    `okhttp`, `std::net`, `TcpStream`, `UdpSocket`
  - Clipboard: `setPrimaryClip`, `ClipboardManager`, `UIPasteboard`
  - Rule 1 path check: fail on any `getrandom` in `core/` outside `core/src/source/`, and fail if `core/src/lib.rs`
    is missing `#![forbid(unsafe_code)]`
  - `--selftest`: every fixture in `scripts/testdata/banned-api/` must trip the gate, and a clean fixture must pass
- [x] Canaries: crates outside the workspace that must fail every CI run, for the right reason. As built, 37 checks
      (see "Changes during M0", item 13); the two below became `deny-banned` and `clippy-fallback`:
  - `scripts/testdata/deny-rand/` depends on `rand`; `cargo deny check bans` with the root `deny.toml` must fail and
    name `rand`
  - `scripts/testdata/clippy-fallback/` calls `.unwrap_or(...)` on a `Result`; clippy with `core/clippy.toml` must
    fail with `disallowed_methods`
- [x] `cargo vet init` → `supply-chain/`. Audits are imported from Mozilla, Google, Bytecode Alliance, ISRG and Zcash
      (owner to confirm this trusted set). Every remaining crate starts as an exemption listed in Review for approval.
- [x] `.github/CODEOWNERS` (at the repo root, `/Entropy/` paths, owner `msaval02@nyit.edu`): `core/`, `ffi/`, `pi/os/`, plus the gate files themselves (`deny.toml`, `*/clippy.toml`,
      `scripts/`, `supply-chain/`, `rust-toolchain.toml`, `.github/`), so a gate cannot be weakened unseen.
      Owners follow the reviewers answer.
- [x] `SECURITY.md` stub (disclosure address `admin@keepcrypt.com`) and `LICENSE-MIT` + `LICENSE-APACHE` (dual licence)

**Vectors**
- [x] `vectors/bip39/vectors.json` from trezor/python-mnemonic, pinned to a commit
- [x] `vectors/coldcard/rolls.json`: the published `123456` example (24 and 12 words), plus outputs of Coldcard's own
      `rolls.py` and `rolls12.py` for fixed roll strings of 50, 99 and 100 rolls. R excludes the trailing newline,
      which Coldcard's scripts strip.
- [x] `vectors/age/`: all 26 `scrypt*` cases of the CCTV age test kit, both accept and reject cases
- [x] `vectors/seal.json`: the CLAUDE.md seal code, tag, Seal ID, lookup prefix, 8x8 grid, colour index and go-ahead
      vectors, produced by `tools/verify/verify.py`
- [x] `vectors/SOURCES.md`: URL, upstream commit or date, licence and SHA-256 for every file fetched from outside
- [x] `tools/verify/verify.py --selftest` (standard library only). In M0 it only regenerates `seal.json` and checks
      the hashes in `SOURCES.md`; M2 grows it into the full verifier. This makes the CLAUDE.md command list true from
      M0 on and follows the lesson that computed values come from committed scripts that CI re-runs. As built it has
      4 checks: seal known answers for all three vectors, seal.json byte equality, SOURCES.md hashes and coverage, and
      a re-run of Coldcard's committed scripts against rolls.json ("Changes during M0", item 4).

**CI** (repo-root `.github/workflows/entropy-ci.yml`; written, YAML validated, first run is on the M0 PR)
- [ ] Hardening: runs on PRs and pushes to `main`; `permissions: contents: read`; checkout uses
      `persist-credentials: false`; only first-party actions (`actions/checkout`, `actions/cache`), each pinned by
      commit SHA; tools come from `cargo install --locked --version ...`; the toolchain comes from `rust-toolchain.toml`
- [ ] `lint`: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `test`: `cargo test --workspace --locked`
- [ ] `supply-chain`: `cargo deny --locked check`, `cargo audit`, `cargo vet --locked` and `scripts/check-path-deps.sh`
- [ ] `gates`: the banned-API check and its `--selftest`, `verify.py --selftest` and `scripts/canaries.sh`
- [ ] `verifier (python 3.9)` on macos-26: `/usr/bin/python3` must be 3.9 and pass `verify.py --selftest`
- [ ] `cross`, a matrix running per-target clippy (core plus `pi/app` or `ffi`) and
      `cargo build --release --locked -p keepcrypt-core --target <t>`, with no `target/` cache:
  - ubuntu, `arm-unknown-linux-gnueabihf`: Ubuntu's `gcc-arm-linux-gnueabihf` with
    `-march=armv6zk -mfpu=vfp -mfloat-abi=hard -marm` for the C parts; Buildroot's toolchain replaces it in M4
  - ubuntu, the three Android targets: the runner's preinstalled NDK clang
  - macOS, `aarch64-apple-ios` and `aarch64-apple-ios-sim`: the runner's Xcode

**Out of M0** (and where each item lands): the `test-sources` feature and the release scan for markers and RNG symbols
(M1, alongside the feature); `cargo llvm-cov` (M1); UniFFI and app libraries (M5, M6); hardware and SDL crates (M3);
the Buildroot toolchain (M4).

### Verification
- [x] Locally: fmt, clippy, test, `cargo deny check`, `cargo audit`, `cargo vet`, the banned-API check and
      `verify.py --selftest` all pass; output pasted
- [x] CI is green on a clean clone of the GitHub repo; run link pasted
- [x] Cross-compile job log shows all six targets built; excerpt pasted
- [x] Every canary and banned-API fixture fails for the intended reason on every run, and CI goes red if one passes
      *(proven locally under sh and dash; CI run pending)*
- [x] One-time end-to-end proof on the real crates: one draft PR adding `rand` to `core`, and one adding `Math.random`
      to a source file, are both red in CI, then closed unmerged; links pasted
- [x] `verify.py --selftest` reproduces every value in `seal.json` and every hash in `SOURCES.md`
- [x] `git ls-files` shows no secrets, keys, or `.age` files outside `vectors/`. On `m0-bootstrap`: 304 files, no
      `target/`, `.DS_Store`, `.age`, `.key` or `.pem` paths; the only key-shaped string is the published CCTV test
      identity in `vectors/age/scrypt/scrypt_and_x25519`

### Changes during M0 that need owner approval (2026-10-09)
Each item came out of building M0 or the three adversarial review rounds. Approve or reject each at the gate.
1. **No in-code exceptions to the rule 3 and rule 5 lints.** The plan said an exception needs
   `#[expect(clippy::disallowed_methods, reason = "...")]`. As built, `core`, `ffi` and `pi/app` set
   `disallowed_methods`, `let_underscore_must_use`, `print_stdout`, `print_stderr`, `dbg_macro` (clippy) and
   `unused_must_use` (rustc) to `forbid`. `#[allow]`, `#[expect]`, crate-level attributes and
   `#![allow(clippy::all)]` all fail with E0453, `src/main.rs` included. An exception is now a reviewed change to
   `Cargo.toml`, and `scripts/canaries.sh` pins the lint tables exactly. `allow_attributes` and
   `allow_attributes_without_reason` stay `deny`, so other lints still take a reasoned `#[expect]`.
   Forward risk for M5: a dependency macro that emits `#[allow(clippy::all)]` or `#[allow(unused_must_use)]`
   (UniFFI scaffolding, for example) would fail the same way.
2. **The fail-closed ban is wider.**
   - It now also covers `Result::or`/`or_else`/`err`, `Option::or`/`or_else`, `core::mem::forget` and
     `std::io::stdout`/`stderr`, for 20 entries. `.err()` is banned in every position, so M1 code uses
     `match` or `if let Err` instead.
   - It covers `pi/app`, which holds `hal::HwRng`, so the Pi firmware cannot print diagnostics without a reviewed
     change.
   - The same `[lints.clippy]` block in all three crates denies `let _ =` on must-use values, `#[allow]` attributes,
     reasonless `#[expect]`, printing and `dbg!`.
   - The grep gate (FailOpen) bans `_ = expr`, `let _x = expr`, `drop(call())`/`forget(call())`, clippy used as a
     `cfg` predicate (`#[cfg(not(clippy))]` hides code from every lint), and writes to `/dev/stdout`, `/dev/stderr`
     or `/dev/tty` in those crates. An RAII guard is written `let guard = ...; drop(guard);`.
3. **`bip39` uses `alloc`, not `std`.** `std` switched on serde and `impl Serialize for Mnemonic`. serde,
   serde_core and serde_derive stay in `Cargo.lock` only, because of Cargo's weak-feature locking: they are never
   compiled, but they still need cargo-vet exemptions.
4. **`verify.py --selftest` runs third-party code in CI.** Coldcard's `rolls.py` and `rolls12.py` say
   "Public domain" in their headers, so they are now committed unmodified. Check 4 runs them with `python3 -I`, only
   after their SHA-256 matches `SOURCES.md`, and compares every case in `rolls.json`.
5. **The banned-API gate is wider than the approved list.**
   - More RNG, network and copy/share-UI patterns.
   - A `FailOpen` category (item 2).
   - An `Include` category: `#[path]` and `include!` can pull in code the scan skips.
   - Files are scanned as text unless their extension is on a binary skip list.
   - Symlinked directories are refused.
   - Rule 1 now covers every `*.rs` file except `core/src/source.rs`, `core/src/source/` and the Pi games
     (`pi/app/src/games.rs`, `pi/app/src/games/`).
   - Left out on purpose: `import Network` (NWPathMonitor), `java.nio.channels` (FileChannel),
     `.textSelection(.disabled)` (required by the docs).
6. **deny.toml.**
   - No `[graph] targets` filter, since target-only dependencies were invisible.
   - `all-features = true`, since feature-gated dependencies were invisible.
   - `unmaintained = "none"`, because cargo-deny 0.20 has no warn level; `cargo audit` prints the warning. The
     stricter option is `"workspace"`.
7. **cargo vet.** Imports from Mozilla, Google, Bytecode Alliance, ISRG and Zcash; ISRG and Zcash cover nothing yet.
   The remaining exemptions are listed in Review for approval.
8. **Cool-off is counted in elapsed time** (14 x 24 h before the lockfile is written). To meet it, `cc` went to
   1.4.7, `find-msvc-tools` to 0.1.13, `bitcoin-consensus-encoding` to 1.2.0 and `bitcoin-internals` to 0.6.0.
9. **New supply-chain gate `scripts/check-path-deps.sh`.** Every crate outside the declared workspace members must
   come from crates.io. It blocks `[patch]`/`[replace]` path overrides and auto-member vendored crates, and it
   refuses any `.cargo/config`, which could replace the crates.io source.
10. **CI.**
    - Clippy also runs per cross target (`core` plus `pi/app` on the Pi, `core` plus `ffi` on the phones).
    - The cross job no longer caches `target/`, so the C code is always rebuilt with the image's current compiler.
    - A macOS job runs `verify.py` under `/usr/bin/python3` and asserts it is 3.9, the stated floor.
    - Action pins: checkout v7.0.1, cache v6.1.0. Runners: ubuntu-24.04 and macos-26.
    - `IPHONEOS_DEPLOYMENT_TARGET=17.0`; `cargo deny --locked check`.
11. **Repo files.**
    - CODEOWNERS covers more than the gate files: `CLAUDE.md`, `docs/`, `tasks/lessons.md`, `SECURITY.md`,
      `pi/app/`, every `Cargo.toml`, `.cargo/`, the legacy `rust-toolchain` file and `vectors/`.
    - `LICENSE-MIT` holder: "bitwilll", matching the repo's root `LICENSE`.
    - SECURITY.md disclosure address: `admin@keepcrypt.com`.
    - `.gitignore` no longer re-includes `*.age` under `vectors/`.
    - `armor_scrypt` counts as the 26th scrypt case, since only 25 names start with `scrypt`.
13. **Canaries: 37 checks in `scripts/canaries.sh`, each required to fail for its stated reason.**
    - `deny-banned`: one standalone crate whose graph proves each deny.toml property (rand, tokio, log, a dev-only
      fastrand, a Windows-only oorandom, a feature-gated nanorand).
    - `clippy-fallback`: calls all 20 banned methods; every configured path must fire, and a mistyped path fails.
    - `real-keepcrypt-{core,ffi,pi}`: mutated copies of the real crates with an `unwrap_or` fallback must fail
      `disallowed_methods` at `-F`.
    - 21 per-crate lint canaries: let-underscore, must-use, print-stderr, print-stdout, dbg-macro,
      allow-attributes and expect-without-reason in each of the three crates.
    - `real-deny-bans`: rand added to the real `core` must be banned.
    - `path-override`, `path-member`, `path-member-listed`, `cargo-config`, `cargo-config-parent`:
      `check-path-deps.sh` refuses `[patch]` path overrides, auto-member and declared vendored crates, and cargo
      config files in or above the workspace.
    - `deny-git-source`: a git dependency on a throwaway local repo fails `unknown-git`.
    - Static checks: the three `clippy.toml` files are identical; the `[lints.clippy]` and `[lints.rust]` tables are
      pinned exactly; deny.toml `[graph]`, the 27-name `[bans] deny` list and `[sources]` are pinned exactly. A real
      change to any of these must update `canaries.sh` in the same reviewed change.
14. **Residual risks, deliberately not gated (accept, or ask for more).** A grep gate cannot be complete; these were
    found by the reviewers, reproduced, and left to review, the M1 error-injection tests or a later milestone:
    - Discard shapes no lint or grep sees: `if let Err(_) = f() {}`, `if f().is_err() {}`, tuple and array
      destructuring (`let (_, x) = (f(), 1);`), `f().iter();`, and a result named first and dropped later
      (`let r = f(); drop(r);`).
    - Obfuscated sources the grep cannot follow: UTF-16 files; device paths built in pieces (`"/dev/" + "urandom"`);
      `__import__("random")`; a computed C `#include`; a remote URL held in a constant before `URL(string: base)`.
    - `RandomState` used as a PRNG in `pi/app`; code under `#[cfg(not(debug_assertions))]`, which dev-profile
      clippy never lints.
    - A `#![forbid(unsafe_code)]` line inside a block comment satisfies the grep, but `[lints.rust]` still forbids
      unsafe code.
    - Python `os.urandom` and `secrets` are allowed in tools: `docs/design.md` endorses them.
    - The lint and test jobs still cache `target/` (only the cross job must rebuild C code every run).
    - Known fail-closed noise: a format argument named `path` that rustfmt wraps onto its own line, a `: _ =` type
      placeholder, a field named `include`. Rename these.
15. **Privacy slip during the build.** A builder agent sent one test request to crates.io with the owner's email
    address in its User-Agent header. Every later request used a generic User-Agent. It cannot be undone; agents are
    now told explicitly never to put personal data in requests.

### Checked while planning (2026-10-09)
- A stdlib script reproduced every seal vector in CLAUDE.md: S prefix, code `JXP3R-DXYAC-JZ1NA-X3RGQ-DJCJJN`, T,
  Seal ID `5E0G7J6X`, colour index 3, the 8x8 grid, and go-ahead `CF94-BCAJ`.
- The 2,048 words of the SeedBook PDF hash to the official BIP39 SHA-256 (`2f5eed53...`). Its printed numbers run
  0001-2048 with each appearing once, and ABANDON 0001, ACT 0020, ACTION 0021, METAL 1121, WIRE 2018 and ZOO 2048 all
  match. The docs' counts (279 words one mirror flip from another word's first four letters; 49 short words that are
  prefixes of longer ones) reproduce.
- Dependency trees came from crates.io: `age` 0.12.1 → `rand` 0.8 and `i18n-embed` → `log`; `ur` 0.5.2 →
  `rand_xoshiro` 0.8; `bitcoin` 0.32.102 → `secp256k1` 0.29 without `rand`; in `bip39` 3.0.0, `rand` is optional;
  in `ed25519-dalek` 3.0.0, `rand_core` is optional.

## M1: Core crate (`keepcrypt-core`)

### Inputs from M0 (fold into the M1 plan when it is refined)
- `core/src/source` may be `source.rs` or `source/`. No other `.rs` file may name `getrandom`, comments included.
- R is exactly the ASCII digits 1-6. Coldcard's scripts accept any characters and keep internal whitespace; KeepCrypt
  must reject anything else rather than copy that leniency.
- age reader policy: decide the accepted scrypt work-factor range. CCTV's accept cases use 10, KeepCrypt writes 18,
  and `scrypt_work_factor_23` must be a header failure. Decide whether armored input is read (`armor_scrypt` expects
  success). Add our own trailing-garbage negative test: upstream's `trailing_garbage` file is byte-identical to
  `leading_garbage`.
- Commit a counting script next to `vectors/braille.json`, and have CI re-check the docs' 279 mirror-flip words, the
  49 short-word prefixes and the word-list SHA-256 (lessons.md rule).
- `if let Err(_) = getrandom::fill(..) {}` is caught by no lint: the error-injection tests must prove that every
  source failure halts and wipes.
- Phone games (M5, M6): getrandom is banned outside `core/src/source` and the Pi games, and `SecureRandom` and
  `SecRandomCopyBytes` are banned in app code. The phone games need an owner-approved source, for example a core API
  that returns game bytes from a separate getrandom call and never touches the pool.

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

### M0, local proof (2026-10-09; final tree without this file: 300 files, sorted-manifest SHA-256
`20ca6f0346e60ba265bdaf84566db3ec06575048c615dab9ad53df5a3a03135e`)
All commands were run from the repo root with toolchain 1.98.1, under `/bin/sh` and `dash` where they are scripts.

```text
cargo fmt --all --check                                   rc=0
cargo clippy --workspace --all-targets --locked -- -D warnings
                                                          rc=0  Finished `dev` profile
cargo test --workspace --locked                           rc=0  8x "test result: ok. 0 passed" (M0 has no tests)
cargo deny --locked check                                 rc=0  advisories ok, bans ok, licenses ok, sources ok
cargo audit                                               rc=0  Scanning Cargo.lock (50 crate dependencies), no findings
cargo vet --locked                                        rc=0  Vetting Succeeded (3 fully audited, 43 exempted)
scripts/check-path-deps.sh            (sh, dash)          rc=0  clean, 46 packages outside the workspace, all from
                                                                crates.io; workspace members exactly core, ffi,
                                                                pi/app, pi/sim; no cargo config files
scripts/banned-api-check.sh           (sh, dash)          rc=0  clean, 61 files scanned (1 binary by extension)
scripts/banned-api-check.sh --selftest (sh, dash)         rc=0  selftest: 209 passed, 0 failed
python3 tools/verify/verify.py --selftest   (3.12, 3.9.6) rc=0  selftest passed: 4 checks
scripts/canaries.sh                   (sh, dash)          rc=0  36 PASS, 0 FAIL, about 6 s warm (37 after the move
                                                                into the monorepo; re-run there before committing)
```

Cross builds proven locally: iOS only, using the installed Xcode 27.0 with
`DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer IPHONEOS_DEPLOYMENT_TARGET=17.0`.

```text
clippy core+ffi --target aarch64-apple-ios       rc=0, 0 warnings
build --release core --target aarch64-apple-ios     rc=0, libkeepcrypt_core.rlib 3808 bytes, secp256k1 minos 17.0
clippy core+ffi --target aarch64-apple-ios-sim   rc=0, 0 warnings
build --release core --target aarch64-apple-ios-sim rc=0, rlib 3816 bytes, secp256k1 platform 7 minos 17.0
```

The Pi (`arm-unknown-linux-gnueabihf`) and Android legs need the ARM gcc and the NDK, which are not on this Mac;
CI is their first real run.

Lead check that no `#[expect]` can excuse a rule 3/5 lint (scratch copy, after the final `forbid` change):

```text
ffi/src/lib.rs   #![expect(clippy::print_stderr, reason = "..")] + eprintln!
                 error[E0453]: expect(clippy::print_stderr) incompatible with previous forbid      rc=101
pi/app/src/main.rs  the same attribute + eprintln!
                 error[E0453]: expect(clippy::print_stderr) incompatible with previous forbid      rc=101
pi/app/src/main.rs  #[expect(clippy::let_underscore_must_use, reason = "x")] let _ = r;
                 error[E0453]: expect(clippy::let_underscore_must_use) incompatible with previous forbid  rc=101
```

Other checks:
- **Spec vectors:**
  - All three seal vectors were reproduced by two separate implementations: `verify.py`, and the reviewer's
    stdlib script.
  - The CLAUDE.md vector: code `JXP3R-DXYAC-JZ1NA-X3RGQ-DJCJJN`, Seal ID `5E0G7J6X`, colour 3, the 8x8 grid, and
    G `CF94-BCAJ` for n = 0001020304050607.
  - Coldcard's published `123456` example reproduces exactly.
  - All 24 English BIP39 seeds in `vectors.json` were recomputed.
  - The 26 age files are byte-identical to CCTV @ 50a8ecf2.
- **Cool-off by elapsed time:** all 46 locked third-party crates are at least 14 x 24 h old at the time
  `Cargo.lock` was written. The youngest are thiserror 2.0.21 (15d10h), cc 1.4.7 and find-msvc-tools 0.1.13
  (20d17h) and bip39 3.0.0 (21d17h). The toolchain 1.98.1 dates from 2026-09-03.
- **Repo hygiene:**
  - A throwaway git copy shows all 301 files visible to git; only `.DS_Store` and `keepcrypt-starter.zip` (via
    `.git/info/exclude`) are ignored.
  - Exactly four executables, all mode 755: the three scripts and `verify.py`.
  - `docs/` is byte-identical to the zip. CLAUDE.md differs only in its Commands block.
- **cargo-vet exemptions to approve (43, all `safe-to-deploy`):** arrayvec 0.7.8, base58ck 0.1.101, bech32 0.11.1,
  bip39 3.0.0, bitcoin 0.32.102, bitcoin-consensus-encoding 1.2.0, bitcoin-internals 0.6.0, bitcoin-io 0.1.101,
  bitcoin-units 0.1.101, bitcoin_hashes 0.14.101, block-buffer 0.12.1, cc 1.4.7, cfg-if 1.0.5, const-oid 0.10.2,
  cpufeatures 0.3.1, crypto-common 0.2.2, digest 0.11.3, find-msvc-tools 0.1.13, getrandom 0.4.3,
  hex-conservative 0.2.3, hex-conservative 1.3.0, hex_lit 0.1.1, hybrid-array 0.4.15, libc 0.2.189,
  miniscript 13.1.0, proc-macro2 1.0.107, r-efi 6.0.0, secp256k1 0.29.1, secp256k1-sys 0.10.1, secrecy 0.10.3,
  serde 1.0.229, serde_core 1.0.229, serde_derive 1.0.229 (the three serde crates are never compiled),
  sha2 0.11.0, syn 2.0.119, syn 3.0.6, thiserror 2.0.21, thiserror-impl 2.0.21, tinyvec 1.13.3, typenum 1.20.1,
  unicode-ident 1.0.26, zeroize 1.9.0, zeroize_derive 1.5.0.
  Passing on imported audits only: quote 1.0.47, shlex 2.0.1, unicode-normalization 0.1.25.
- **Review process:** the builders' work went through three adversarial review rounds plus a narrow final
  verification. Every finding was reproduced on a scratch copy before it was fixed. The raw reports stay in the
  session scratchpad; this file records the outcome.

### M0 on GitHub (2026-10-09)
PR bitwilll/keepcrypt#1. Entropy CI was green on both pushes, 11/11 jobs each:
- https://github.com/bitwilll/keepcrypt/actions/runs/37943086359 (6796cf5)
- https://github.com/bitwilll/keepcrypt/actions/runs/37944150801 (f49d84e)

```text
cross (arm-unknown-linux-gnueabihf)  target/arm-unknown-linux-gnueabihf/release/libkeepcrypt_core.rlib: 3998 bytes
cross (aarch64-linux-android)        target/aarch64-linux-android/release/libkeepcrypt_core.rlib: 4610 bytes
cross (armv7-linux-androideabi)      target/armv7-linux-androideabi/release/libkeepcrypt_core.rlib: 3994 bytes
cross (x86_64-linux-android)         target/x86_64-linux-android/release/libkeepcrypt_core.rlib: 4578 bytes
cross (aarch64-apple-ios)            target/aarch64-apple-ios/release/libkeepcrypt_core.rlib: 3784 bytes  (Xcode 26.6)
cross (aarch64-apple-ios-sim)        target/aarch64-apple-ios-sim/release/libkeepcrypt_core.rlib: 3784 bytes
gates         banned-api-check: clean, 59 files; selftest: 209 passed, 0 failed (first run on GNU grep);
              verify.py: selftest passed: 4 checks; canaries.sh: 37 PASS
supply-chain  advisories ok, bans ok, licenses ok, sources ok; Vetting Succeeded (3 fully audited, 43 exempted);
              check-path-deps: clean, no cargo config files in or above the workspace
verifier      /usr/bin/python3 = Python 3.9.6; selftest passed: 4 checks
```

Negative tests, both closed unmerged:
- bitwilll/keepcrypt#2 adds `rand` to `core`. In run https://github.com/bitwilll/keepcrypt/actions/runs/37944355102,
  supply-chain failed with `error[banned]: crate 'rand = 0.8.5' is explicitly banned`, plus RUSTSEC-2026-0097.
  Gates was red too, because the `real-deny-bans` canary cannot add rand to a core that already has it: it fails
  closed.
- bitwilll/keepcrypt#3 adds `Math.random()` in app code. In run
  https://github.com/bitwilll/keepcrypt/actions/runs/37944361988, gates failed with
  `RNG: mobile/android/app/src/main/kotlin/app/Dice.kt:4` from `banned-api-check.sh`.

The repo also has a Vercel deploy integration (team bitwillls-projects), whose "Vercel" check fails on these PRs. It is
not part of Entropy CI.

### M0 gate status: MET, awaiting owner approval
The gate in docs/build-plan.md asks for CI green and a core that cross-compiles for the Pi Zero, Android and iOS
targets. Both are shown above. Per CLAUDE.md, M1 does not start until the owner approves and PR #1 is merged.
