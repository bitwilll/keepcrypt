# KeepCrypt: rules for Claude Code

KeepCrypt-Entropy is an open-source Bitcoin seed generator built so the July 2026 Coldcard
weak-entropy theft cannot happen here. One Rust core (`core/`) does all randomness, seed and
backup work. Thin shells sit on top of it: Raspberry Pi firmware (`pi/`), an Android app, an
iPhone app (`mobile/`), plus a small public seal registry (`registry/`) and an offline Python
verifier (`tools/verify/`).

The specification lives in `docs/`. Read all of it before starting any milestone:

| File | Covers |
| --- | --- |
| `docs/design.md` | Why: incidents, threat model, entropy principles, mixing, health tests |
| `docs/build-plan.md` | What to build: architecture, repo layout, core API, CI rules, milestones M0 to M9 |
| `docs/pi-firmware.md` | Pi hardware, OS image, firmware, ceremony screens |
| `docs/mobile-apps.md` | Android and iPhone apps, capture protection, offline rules |
| `docs/seal-watchonly-braille.md` | Collision seal and registry, watch-only export, braille backup |
| `docs/KeepCrypt-SeedBook_Braille.pdf` | The owner's braille reference: insert format and the full word list |

If the docs and this file disagree, stop and ask the owner. Do not guess.

## Workflow (mandatory on every task)

1. **Start of session:** read `tasks/lessons.md`, then the current milestone in `tasks/todo.md`.
2. **Plan first:** write or refine the plan in `tasks/todo.md` as `- [ ]` items, including a
   Verification list. **Check in with the owner before writing implementation code.**
3. **Track as you go:** tick items `- [x]` only after proving they work. Paste the proof under
   the milestone's Review section: test output, a simulator screenshot, a reproduced hash.
4. **Gates:** at the end of every milestone, stop, report against the gate in
   `docs/build-plan.md`, and wait for approval. Never start the next milestone on your own.
5. **Corrections:** after any correction from the owner, add an entry to `tasks/lessons.md`
   (Mistake, Root cause, Rule) before continuing.
6. **Bugs and failing CI:** fix them yourself, find the root cause, and never paper over them.
7. **Elegance:** choose the simplest correct design. If a fix feels hacky, stop and redesign it.
   Touch only what the task needs.
8. **If something goes sideways:** stop, re-plan in `tasks/todo.md`, and check in.

## Non-negotiable security rules

These rules exist because each one was broken in a real theft. Never relax one to make a test
pass. If one seems to block you, ask the owner.

1. **One source of OS randomness:** only `core/src/source` calls `getrandom`. Banned
   everywhere in shipped code: the `rand` crate family in `core/`, `Math.random`,
   `java.util.Random`, `kotlin.random.Random`, `arc4random_uniform` in app code,
   Python `random`, `mt19937`, `rand()`/`srand()`, and any hand-written PRNG.
   Games use their own separate `getrandom` calls and never touch the pool.
2. **Never narrow the pipe:** nothing between the pool and the seed is narrower than 256 bits.
   No truncation to `u32`/`u64`, no integer casts of secret material, no "reseed with 4 bytes".
3. **Fail closed:** no fallback source, no default value, no `unwrap_or*` and no
   catch-and-continue around entropy, health tests or known-answer tests. Any failure halts
   the session and wipes it.
4. **Hash, never XOR:** sources are absorbed as `source id (u16) || length (u64 BE) || data`
   into SHA-512, with fixed domain tags (below).
5. **Secrets stay secret:** use `zeroize`/`secrecy` wrappers with no `Debug`, `Display`, `Clone`
   or `Serialize`. Never log, print, persist, copy to the clipboard or render secrets outside
   protected screens. `core/` has no logging dependency.
6. **Typestate order:** `Collecting → Committed → Rolling → Sealed → (Checking) → Ready`. The
   sealed and checking states expose no mnemonic, device leg D, backup or export. Skip exists only
   in the sealed state; once a check starts, only a verified go-ahead reaches `Ready` and every
   other exit wipes the seed. Prove it with `trybuild` compile-fail tests.
7. **Seal:** computed only from the BIP39 seed with an empty passphrase, never from public keys.
8. **Files:** the only file ever written is the age v1 backup (scrypt only, log2 N = 18,
   generated 8-word passphrase). The only files ever read are `.age` backups and signed
   `.kcr` registry snapshots.
9. **Apps:** Android has no `INTERNET` permission and sets `FLAG_SECURE` on every window,
   including dialogs and popups. iOS has no networking code and uses capture-state redaction,
   discard-on-screenshot and an app-switcher cover. No analytics, crash or ad SDKs.
10. **Test stubs never ship:** fake sources live behind the `test-sources` cargo feature and embed
    the marker string `KC_TEST_SOURCE_DO_NOT_SHIP`. The test registry key lives behind the
    separate `test-registry` feature, which `test-sources` turns on (never the reverse), and
    embeds the marker `KC_TEST_REGISTRY_DO_NOT_SHIP`. CI fails any release artifact that contains
    either marker, the test registry key or an unexpected RNG symbol.
11. **No home-made crypto:** use only the crates named in `docs/build-plan.md`. Adding any
    dependency needs owner approval and a `cargo vet` entry.
12. **No real seeds in tests:** use the vectors in `vectors/` only. Never commit secrets or keys.

## Domain constants (must match the docs and the verifier exactly)

```text
Pool tag            KCE/v1/pool
Commitment          C = SHA256("KCE/v1/commit" || D)
Seed (mixed mode)   E = SHA256("KCE/v1/seed" || D || len(R) as u64 BE || R)
Seed (dice only)    E = SHA256(R)                 # R = ASCII dice string, same as Coldcard
Seed length         default 12 words = first 128 bits of E (fills one KeepCrypt Hinge or Screw);
                    24 words = all 256 bits (needs two devices)
Seal code           Crockford base32 of top 130 bits of HMAC-SHA256(S, "KCE/v1/seal")
                    S = BIP39 PBKDF2 seed, empty passphrase
Seal tag            T = SHA256("KCE/v1/seal-tag" || ASCII(seal code: 26 chars, no grouping dashes))
Check nonce         n = 8 fresh bytes per check, carried in the check QR with T
Go-ahead code       G = Crockford base32 of first 40 bits of SHA256("KCE/v1/go" || T || n), 8 chars
Bucket proof        Merkle tree over 2^20 buckets (20-bit prefix of T); leaf = SHA256(0x00 ||
                    "KCE/v1/bucket" || prefix as 3 bytes || entries); node = SHA256(0x01 || l || r);
                    the snapshot's Ed25519 signature covers a header that holds the root
Dice quota          99 rolls (24 words), 50 rolls (12 words), 99 after a collision; 2.585 bits per roll
Pi device quota     getrandom(64) + 512 credited bits of health-tested raw /dev/hwrng
                    (hwrng credited at 4 bits per byte, H = 4 for health-test cutoffs, until lab data)
Braille (SeedBook)  UEB grade 1, one cell per letter, no contractions; insert faces 1-5 = first
                    five letters (blank faces are significant), face 6 = sequence number 01-12;
                    SeedBook number = 1-based BIP39 index 0001-2048; mirror pairs e/i d/f h/j r/w;
                    metal read-back of the first four letters of every word is mandatory
```

Braille cross-check vectors (from the KeepCrypt SeedBook_01): ABANDON 0001, ACT 0020 (a c t +
two blank faces), ACTION 0021, METAL 1121, WIRE 2018, ZOO 2048.

Seal test vector (`abandon` x11 + `about`): code `JXP3R-DXYAC-JZ1NA-X3RGQ-DJCJJN`,
T = `2b8103c8dd64611df5c8c28b8fbf864a1005372f5da06a5777f92708ce79cb5c`, Seal ID `5E0G7J6X`.
Go-ahead vector: that T with n = `0001020304050607` gives G = `CF94-BCAJ`.

## Commands

Create these in M0 and keep this list current as the repo grows.

```bash
# Run from Entropy/, the project root inside the keepcrypt monorepo (CI: .github/workflows/entropy-ci.yml).
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings   # the stubs and test key too
cargo test --workspace --locked      # the release configuration: no test feature
cargo test -p keepcrypt-core --locked --features test-sources   # stub, fault-injection and test-registry tests
# Test features are switched on only like this, with -p, never in a manifest (canaries.sh enforces it).
cargo llvm-cov --locked -p keepcrypt-core --features test-sources --no-cfg-coverage --fail-under-lines 95 --summary-only
                                     # cargo-llvm-cov 0.9.1; the M1 gate is 95% of core's lines
TRYBUILD=overwrite cargo test -p keepcrypt-core --test typestate   # only after a toolchain or trybuild bump:
                                     # regenerates the pinned .stderr files; review the diff
cargo deny --locked check && cargo audit && cargo vet --locked   # plain `cargo vet` re-fetches imports
scripts/check-path-deps.sh           # every non-workspace crate comes from crates.io (no path or git overrides)
python3 tools/verify/verify.py --selftest   # 11 checks; also with /usr/bin/python3 (3.9, the floor)
# Generated vectors are regenerated, never hand-edited, then checked by --selftest:
python3 tools/verify/verify.py --write-seal-vectors        # vectors/seal.json
python3 tools/verify/verify.py --write-kat-vectors         # vectors/kat.json
python3 tools/verify/verify.py --write-keepcrypt-vectors   # vectors/keepcrypt.json
python3 tools/verify/verify.py --write-braille-vectors     # vectors/braille.json
python3 tools/verify/verify.py --write-watchonly-vectors   # vectors/watchonly.json
python3 tools/verify/verify.py --write-kcr-vectors         # vectors/kcr.json
python3 tools/verify/verify.py --write-backup-vectors      # vectors/backup.json
scripts/age-interop.py --core        # the age CLI against verify.py and core, both directions, work factor 18
                                     # (needs age; CI: Ubuntu's 1.1.1). --generate rewrites age_cli_written.json
scripts/banned-api-check.sh          # grep gate for banned RNG, network and clipboard APIs
scripts/banned-api-check.sh --selftest   # also builds the artifact fixtures (needs the pinned toolchain)
# Release-artifact scan (CI's cross job, per target T; on Linux and Android T builds with
# CARGO_TARGET_<T>_RUSTFLAGS='--cfg getrandom_backend="linux_getrandom"'):
cargo build --release --locked -p keepcrypt-core --lib --example release_probe --target T
scripts/banned-api-check.sh --artifact T target/T/release/libkeepcrypt_core.rlib target/T/release/examples/release_probe
scripts/canaries.sh                  # proves every gate still fires, the scan's positive controls included
```

## Definition of done (every task)

- [ ] Tests written first or alongside, and passing locally and in CI
- [ ] New behaviour covered by vectors where the docs define them
- [ ] Clippy, fmt, deny and the banned-API gate are clean
- [ ] Proof pasted into `tasks/todo.md` Review
- [ ] Would a security-minded staff engineer approve this diff?

## Git

- One branch per milestone (`m1-core`, `m2-verifier`, ...); small, focused commits.
- Never push to `main` directly; open a PR whose description lists the gate evidence.
- Never commit generated secrets, `.age` files from real ceremonies, or signing keys.
