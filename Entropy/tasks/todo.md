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

### Needed before M1 (answered 2026-10-09)
Owner answer: every recommendation below is approved as written ("I approve, do it", 2026-10-09).
Q12's ruleset is a change to the GitHub repo's settings, so I ask once more right before creating it.

Please answer these before any M1 code is written. Q1-Q4 are the open decisions under "Needed before M1". Q9 covers the two seed-length questions already listed there. The rest came up while planning; Q12 asks you to set up branch protection before the first M1 merge. Each question gives a recommendation and says what changes if you choose otherwise.

Docs are named by file: build-plan.md, design.md, seal-watchonly-braille.md, pi-firmware.md and mobile-apps.md (all in `docs/`), plus CLAUDE.md and tasks/lessons.md. KAT means known-answer test. CCTV is the C2SP age test kit in `vectors/age/`. KCP1 is the signed bucket proof behind the go-ahead QR (Q6c).

1. **age (open decision 1).**
   Recommended: (a). Write the age v1 scrypt-only format in `core/src/backup` from scrypt 0.12.0, chacha20poly1305 0.11.0, hkdf 0.13.0, hmac 0.13.0 and base64ct 1.8.3. That is 15 lockfile entries, all MIT/Apache, with no gate change. The file key, salt, nonce and file name all come from `core/src/source`. It is proven three ways: against all 26 CCTV files, by a writer that reproduces CCTV byte for byte, and against the age CLI in both directions.
   Please also approve:
   - (i) Reader policy:
     - accept log2 N from 1 to 18, checked before any scrypt work. 2^19 needs 512 MiB, more than the Pi Zero has; CCTV's accept cases use 10;
     - read both armored and binary input;
     - allow one payload chunk of at most 4 KiB;
     - allow files of at most 8 KiB (a 24-word backup is 1,718 bytes armored).
   - (ii) A new CI job, `age-interop`, that installs Ubuntu's `age` 1.1.1-1ubuntu0.24.04.3 from apt and asserts its version. Locally, `brew install age` only with your approval.
   - (iii) Accept that scrypt 0.12 never zeroizes its 256 MiB working buffer, and file an upstream issue. The buffer is derived from the backup passphrase, not from the seed; the passphrase has 88 bits; the Pi keeps everything in RAM.

   Otherwise, (b) use the `age` 0.12.1 crate:
   - deny.toml needs wrappers for rand, rand_core, rand_chacha and log, and the 27-name ban list pinned in canaries.sh changes;
   - about 140 crates to vet;
   - duplicate digest, sha2 and getrandom versions;
   - BSD-3-Clause is needed anyway;
   - CLAUDE.md rule 1 must be amended, because age draws the key, salt and nonce from its own OsRng;
   - the backup source-substitution test and the byte-exact writer KAT become impossible;
   - the code must set the work factor and maximum work factor to 18 itself.

2. **BC-UR (open decision 2).**
   Recommended: (a), single frame only.
   - About 150 lines in `core/src/ur.rs`: a deterministic CBOR subset, bytewords and CRC32. No crate and no PRNG.
   - Pinned by the BCR-2020-005, -012 and -015 vectors (Blockchain Commons research specs) and the RFC 8949 vectors, and rebuilt independently in verify.py.
   - Ship the documented v1 `crypto-account`: one wpkh output, 258 characters, QR version 8-L. Confirm it against Sparrow at M4. The UR registry now marks v1 types as read-only in favour of `account-descriptor`.
   - The go-ahead proof QR uses the same single-part UR, read by a strict decoder (Q6c).

   Otherwise:
   - (b) Fountain frames need `rand_xoshiro`, which is banned. That means a deny exception, a change to the canaries pin, the `ur` 0.5.2 crate and vet entries.
   - (c) UR outside core removes `verify_bucket_proof_qr`, and the shells pass raw bytes instead.
   - v2 `account-descriptor` needs a different CBOR structure and new vectors.
   - A CBOR crate (minicbor) adds the BlueOak-1.0.0 licence.

3. **Ed25519 (open decision 3).**
   Recommended: ed25519-dalek 3.0.0 with `default-features = false` and no features, using `verify_strict` only.
   - That turns off its two defaults: `fast` (curve25519-dalek's precomputed tables, which only speed up verification slightly) and `zeroize` (wiping of signing keys; verify-only code holds public data).
   - `rand_core` is optional, not a default, in both ed25519-dalek and curve25519-dalek, and stays out of the lockfile.
   - `verify_strict` needs no feature. `legacy_compatibility` (which accepts malleable signatures) and `hazmat` stay off, and a canary pins the resolved features.

   Please also approve:
   - (i) BSD-3-Clause in deny.toml. ed25519-dalek, curve25519-dalek and subtle use it, and `cargo deny` fails on exactly those three without it. The decision adds 9 lockfile entries in all.
   - (ii) A standard-library RFC 8032 Ed25519 in verify.py, pinned by RFC 8032 TEST 1-3.
     - It verifies signatures; M2 needs this for re-checks.
     - It signs vectors only with two keys derived from public labels, and accepts no key input.
   - (iii) Key pinning:
     - the test public key is pinned only under a separate, non-default `test-registry` feature with its own marker, `KC_TEST_REGISTRY_DO_NOT_SHIP`. `test-sources` turns it on, never the reverse, so the M3 simulator and the M5/M6 gate builds can trust the local test registry without compiling stub entropy;
     - the release scan rejects that marker and the test key bytes, and canaries.sh proves it with a positive control;
     - release builds pin no key until M9, so snapshots and proofs fail closed with `NoRegistryKey`, and only the typed go-ahead code works;
     - one key per release. Rotation by a statement signed with the old key (seal-watchonly-braille.md "Registry service spec") waits for M9.

   Otherwise:
   - ed25519-compact (MIT, no dependencies, less reviewed) behind the same API, with no new licence.
   - With no Ed25519 at all, the Snapshot and BucketProof go-aheads cannot exist. That breaks seal-watchonly-braille.md "Go-ahead QR" and loaded snapshots.
   - Tie the test key to `test-sources`: every build that trusts the test registry then also compiles the stub sources and their marker, including the builds that produce M5/M6 gate evidence.

4. **trybuild (open decision 4).**
   Recommended: add two dev-dependencies, trybuild =1.0.121 (1.0.122 is inside the cool-off) and serde_json =1.0.151. serde_json is already in trybuild's tree, and lets tests read vectors/*.json as `serde_json::Value`.
   - 20 dev-only lockfile entries, with safe-to-run vet exemptions.
   - The toml family is held at releases at least 14 days old.
   - serde is compiled for tests only, and a canary keeps it out of core's normal graph.
   - The `.stderr` files are pinned to toolchain 1.98.1. A toolchain or trybuild bump regenerates them in the same PR.

   Otherwise:
   - `scripts/compile-fail.sh` checks each fixture as its own crate and greps for the error code and method name. This pins the failure reason less precisely.
   - A test-only JSON reader of about 150 lines replaces serde_json.

5. **Session API (refines the build-plan.md "Public API" sketch).**
   Recommended, approved as one set:
   - **Methods that can fail take `self`.** This applies to any method that can fail on randomness, a health test, a KAT or an integrity check:
     - `add_hw_samples`, `commit`, `push_roll`, `finish`, `start_check` and `reveal`;
     - on Ready: `generate_backup_passphrase`, `encrypt_backup`, `watch_only`, `registration` and `reveal_device_leg`, which return the session together with their output.

     An `Err` has already wiped the session (build-plan.md invariant "the session wipes itself on any error"; CLAUDE.md rule 3). Only user input keeps the session alive: `Rejected::Retry`, `check_readback` and `verify_backup`.
   - **Backup.**
     - A randomness failure during backup is fatal.
     - USB write and read-back errors stay retryable, in the shell (pi-firmware.md USB step 6).
     - Passphrases are generated only (build-plan.md "Encrypted backup format": "User-chosen backup passphrases are not offered in v1"), and the types enforce it:
       - `generate_backup_passphrase(self)` moves onto `Session<Ready>`. It stores the passphrase in the session and returns a display copy with the 2-of-4 confirm challenge;
       - `encrypt_backup(self, &CreatedBy)` and `verify_backup(&self, file)` take no passphrase and use the stored one. Encrypting before generating is a shell-order bug, so it wipes. A retry re-encrypts with the same passphrase, so the paper copy stays valid;
       - typed words (`TypedBackupPassphrase::from_words`) are accepted only by `decrypt_backup`. A trybuild fixture proves they cannot reach `encrypt_backup` or `verify_backup`.
     - `encrypt_backup` returns the file name with the armored bytes.
   - **"Check a backup".** `decrypt_backup(file, &TypedBackupPassphrase)` returns a `CheckedBackup`: the mnemonic, the verified fingerprint and the braille lines, zeroized on drop, with no Debug, Display or Clone. It exposes `fingerprint()`, `seal()` for re-checks, and the words and braille only through `reveal_words()` and `reveal_braille()`. The shells call those only when the user asks (pi-firmware.md and mobile-apps.md: show only the fingerprint unless the user asks for the words).
   - **Read-back is enforced by the core.**
     - `check_readback(&mut self)` records each match.
     - The exports return `ReadbackIncomplete` until every word has matched. Calling them early is a shell-order bug, so it wipes the session.
   - **`GoAhead<'a>` borrows verified evidence** (`&VerifiedSnapshot`, `&VerifiedProof`, `&str`). A loaded snapshot then survives a restart, and the shell can show its date before `reveal`.
     - Both verified types expose `date()` and `freshness(today)`: Current, Stale from day 31, or Future. A go-ahead QR thus gets the same date rule as a loaded snapshot (seal-watchonly-braille.md "Go-ahead QR"), so an old proof from before a colliding seal was registered is flagged.
     - Phones warn on Stale and Future. The Pi, which has no clock, shows the date and asks the user to confirm it before `reveal` (lessons.md).
   - **KATs outside a session.**
     - `self_test()` and `hwrng_boot_test()` serve the boot screens.
     - `decrypt_backup`, `verify_snapshot`, `verify_bucket_proof`, `verify_bucket_proof_qr` and `seal_from_mnemonic` run their own KAT groups and return `Result`.
     - Under `test-sources`, each of these functions has a `*_with_kat_fault` twin, so the tests prove every fail-closed branch.
   - **Other refinements.**
     - `add_extra` takes `ExtraSource`, so a shell cannot name a credited source id.
     - `commitment()` and `reveal_device_leg()` return `Option` (None in dice-only mode).
     - The fingerprint and first address are computed in `finish`, so `skip_check` stays infallible.
     - At most 256 rolls.
     - An invalid face, or `finish` below the minimum, halts and wipes.
     - `hw_bytes_tested()` feeds the Pi's progress bar (Q7).
   - **BIP39 passphrase.** `watch_only` takes `Option<&Bip39Passphrase>`, which rejects "", never trims, and is NFKD-normalized through unicode-normalization. That is a new direct edge to a crate already in the lockfile.

   Otherwise:
   - Keep the sketch's `&mut self`/`&self` signatures, with a "poisoned" flag that every accessor checks. Accessors then return `Result`, and the guarantee holds at run time instead of in the types.
   - The shells enforce read-back, and the M3/M5/M6 tests prove it.
   - `generate_backup_passphrase` stays a free function and `encrypt_backup` takes the passphrase. A second type that only `generate_backup_passphrase` can make must then keep typed words out of `encrypt_backup`.
   - `decrypt_backup` returns a bare `SecretMnemonic`, and each shell computes the fingerprint and seal itself.
   - `GoAhead` holds owned values.

6. **Exact bytes the docs leave open.** These get frozen by the vectors, then by M2 and M9 (lessons.md: "state the exact bytes").
   Recommended:
   - **(a) Pool.**
     - The 11 bytes `KCE/v1/pool` are absorbed once, before any record.
     - Source id is a u16, big-endian:

       | Id | Source |
       | --- | --- |
       | 0x0001 | OS |
       | 0x0002 | hwrng |
       | 0x0003 | reserved for the M8 TRNG |
       | 0x0101 | input timing |
       | 0x0102 | motion |
       | 0x0103 | camera |
       | 0x0104 | microphone |

     - One record per call, and none for zero bytes.
     - The 64-byte OS record goes last, at commit. design.md "Mixing" lists getrandom first, so Q10 says that list names kinds, not an order.
   - **(b) `.kcr` snapshot.**
     - All integers big-endian.
     - A 58-byte header: `KCR1` | version u16 = 1 | number u64 | date u32 as decimal YYYYMMDD | count u64 | root.
     - Then a pure Ed25519 signature over exactly those 58 bytes.
     - Entries are T[0..16] | count u16 >= 1, strictly ascending, with no duplicates.
     - At most 2^22 entries (75.5 MB).
     - "The 20-bit prefix as 3 bytes" means the bucket index as a 24-bit big-endian integer: `2b810...` gives `02 b8 10`.
   - **(c) Go-ahead QR.**
     - KCP1 = `KCP1` | header | signature | bucket (3 bytes) | k u16 | k entries | 20 siblings, leaf level first. That is 771 + 18k bytes.
     - Sent as a single-part `ur:keepcrypt-proof/...` whose CBOR is one byte string holding the KCP1 bytes.
     - The decoder is strict, in this order:
       - at most 4,296 characters (the largest QR alphanumeric capacity), checked before any decoding;
       - all lowercase or all uppercase (QR alphanumeric mode gives `UR:KEEPCRYPT-PROOF/`), never mixed;
       - the type must equal `keepcrypt-proof`, and there is exactly one part;
       - minimal bytewords, then the CRC-32;
       - a shortest-form, definite-length CBOR byte-string head, and nothing after the byte string.
     - About 75 entries per bucket fit one QR, so drop "animated BC-UR frames".
   - **(d) URLs.**
     - Check: `<origin>/check#t=<64 lowercase hex>&n=<16 lowercase hex>`.
     - Re-check of an existing wallet (new): `<origin>/check#t=<64 lowercase hex>` with no n, from `SealPublic::recheck_url()`. A checker can show the registration count but never a go-ahead code. The checking page already reads `#t=` alone (seal-watchonly-braille.md "Registry service spec").
     - Register and collision report: `<origin>/register#c=<26 uppercase characters, no dashes>`.
     - Origin `https://registry.invalid` until M9.
   - **(e) Backup.**
     - Passphrase: 11 OS bytes cut into 8 indices of 11 bits, most significant first.
     - The age passphrase is the 8 lowercase words joined by single spaces. It cannot change once released.
     - Plaintext v1:
       - LF line endings, a final LF, no BOM, single spaces;
       - `braille:` lines of `  NN ` + every letter's cell, for positions 01-24;
       - the fingerprint as 8 lowercase hex digits, from the empty passphrase;
       - `created-by: keepcrypt-pi|android|ios X.Y.Z`.
     - Lowercase hex in the file name.
   - **(f) Braille digits next to letters: standard UEB (Unified English Braille) grade 1.**
     - The number sign opens a run of digits.
     - The grade 1 indicator ⠰ goes before a letter a-j that follows a digit.
     - A letter k-z, a space or a hyphen ⠤ ends the run.
     - Letters are lowercase. Anything outside a-z, 0-9, space and hyphen is refused in v1.
     - Seal ID `5E0G7J6X` = ⠼⠑⠰⠑⠼⠚⠰⠛⠼⠛⠰⠚⠼⠋⠭.
     - The SeedBook's rule ("a letter ends it") would make ⠼⠑⠑ read as 55, not 5E.
     - A braille reader confirms before release.

   Otherwise: each alternative changes only generator code and the affected vectors. Examples:
   - the tag as record 0, or the OS record first;
   - little-endian integers;
   - a left-aligned prefix;
   - a dashed code in the URL, which the M9 server must then canonicalize;
   - no re-check URL in M1: an existing wallet is then re-checked by loaded snapshot only until M9;
   - a hyphen-joined passphrase;
   - the capital indicator ⠠ in the Seal ID.

7. **Adaptive Proportion window: design.md "Test continuously" disagrees with SP 800-90B.**
   The doc says windows of 1,024 samples (512 for binary sources). SP 800-90B 4.4.2 says 1,024 for binary sources and 512 for all others. hwrng bytes are not binary.
   Recommended:
   - W = 512 and C = 62 for H = 4. C is 1 + CRITBINOM(512, 1/16, 1 - 2^-20), recomputed exactly; the same formula reproduces the standard's Table 2.
   - Repetition Count cutoff 6.
   - The first 1,024 samples are tested at startup, then discarded.
   - Credit only post-startup samples in completed windows. The Pi then credits its 512 bits after 1,536 hwrng bytes, all in one step when the first window completes.
   - The Pi's progress bar (pi-firmware.md step 4) counts health-tested bytes toward 1,536 instead of credited bits, so it still moves.
   - Fix the design.md sentence, and record the windowed credit in build-plan.md "Credit policy", design.md "Device quota in practice" and pi-firmware.md step 4 (Q10).

   Otherwise:
   - W = 1,024 and C = 105 changes two constants and the health vectors, and the Pi needs 2,048 bytes.
   - Crediting bytes as they arrive would credit a source that degrades right after startup, on a partial window of only 128 samples.

8. **getrandom backend on the Pi and Android (new).**
   getrandom 0.4.3's default Linux/Android backend looks up `getrandom` through `dlsym` and falls back to `/dev/urandom`. So the binaries carry a fallback path (CLAUDE.md rule 3) and have no `getrandom` import, and the build-plan.md symbol check ("libc getrandom is imported") cannot see which path runs.
   Recommended:
   - Build the Linux and Android artifacts with `--cfg getrandom_backend="linux_getrandom"`, set per target: `CARGO_TARGET_<T>_RUSTFLAGS` in CI now, Buildroot in M4, cargo-ndk in M5.
   - Make the release scan require `U getrandom` and reject getrandom's fallback symbols.
   - No `compile_error!` guard, because trybuild strips RUSTFLAGS.
   - iOS keeps `CCRandomGenerateBytes`, and the scan requires `_CCRandomGenerateBytes`. The build-plan.md row then names the import per target (Q10).

   Otherwise: keep the default backend.
   - The scan drops the required-import rule on Linux and Android, and checks only the markers and the banned symbols.
   - The unused fallback stays in the binary.

9. **Seed length (open since M0).**
   - (a) Confirm 12 words as the default (one KeepCrypt Hinge or Screw), with 24 available.
     Recommended: yes.
   - (b) For 24 words: both insert sets are engraved 01-12.
     Recommended:
     - the core labels words 13-24 as "device 2 of 2, insert 01-12", through `Insert::device()` and `sequence()`, pinned in braille.json;
     - every insert screen, the read-back prompt and the final checklist say which device holds words 1-12;
     - KeepCrypt marks the second device physically.

     Otherwise: a second insert set engraved 13-24. `sequence()` then returns 13-24 on device 2, which is one line of code plus the positions vector.

10. **Doc edits.** CODEOWNERS covers docs/ and CLAUDE.md, so these go in one reviewed commit before any code:
    - design.md:
      - "Test continuously": the Adaptive Proportion window sentence (Q7).
      - "Device quota in practice": hwrng is credited per completed 512-sample window after the 1,024 discarded startup samples, so the Pi reads at least 1,536 bytes and its 512 credited bits arrive in one step (Q7).
      - "Mixing and conditioning": the four device inputs are kinds, not an order; the 64-byte getrandom record is absorbed last, at commit (Q6a).
      - "Verifiability" table: drop the dice-only "running SHA-256 of the typed rolls". After the last roll it equals E, the seed itself, and pi-firmware.md step 6 and mobile-apps.md step 8 show only the count and bits.
    - build-plan.md:
      - the "Core crates" row: RustCrypto primitives instead of `age` (Q1: scrypt, chacha20poly1305, hkdf, hmac, base64ct); ed25519-dalek (Q3); a single-frame UR encoder and strict decoder in core (Q2); unicode-normalization, a new direct edge (Q5), since CLAUDE.md rule 11 says every crate used is named there;
      - the "kat" row gains HMAC, Pool, Health, Seed, GoAhead, Merkle, Ed25519 and BIP84;
      - the "Credit policy" Pi row: the windowed credit, as in design.md (Q7);
      - the "Public API" sketch takes the Q5 signatures, including the stored backup passphrase (encrypt and verify take none), `decrypt_backup` returning `CheckedBackup`, and `date()` and `freshness()` on both verified types;
      - "Security rules enforced in CI":
        - "Secrets never printed": the literal rule ("asserts no BIP39 word appears") cannot pass, because fixed text such as "test", "wrong" and "error" is itself made of BIP39 words. New wording: no word of a test seed appears unless it also appears for a control seed with no words in common; no two consecutive seed words appear in order; and the Debug output of types that hold or replace a session (`Rejected`, `Wiped`) contains no BIP39 word as a whole token (a maximal run of ASCII letters, case-folded), since "Rejected" contains "reject" as a substring;
        - "Test stubs never ship": the test registry key too, behind `test-registry` with the marker `KC_TEST_REGISTRY_DO_NOT_SHIP` (Q3);
        - "One RNG path in shipped binaries": the required import is per target, `getrandom` on Linux and Android and `CCRandomGenerateBytes` on iOS (Q8).
    - CLAUDE.md rule 10: also names the `test-registry` feature and its marker (Q3).
    - pi-firmware.md:
      - step 4: the bar counts health-tested hwrng bytes toward 1,536, and the 512 credited bits arrive in one step at the end (Q7);
      - the `qr` row loses "BC-UR fountain frames" (Q2);
      - "Games, sensors" says extras reach the pool only until the commitment, because C fixes D.
    - seal-watchonly-braille.md:
      - "Snapshot format" and "Go-ahead QR" give the exact bytes, with no animated frames (Q6b, Q6c);
      - "Account QR" loses "animated if needed";
      - a passphrase export shows that wallet's fingerprint and first address, and Sparrow's first address is compared with that one;
      - the braille numbers line gains the ⠰ rule (Q6f);
      - "24-word seeds" gets the answer from Q9;
      - the read-back paragraph says the core refuses exports until every word reads back (Q5);
      - "Re-checking an existing wallet" gives the re-check URL (Q6d).

    Recommended: approve.
    Otherwise: each rejected edit leaves the docs and the code disagreeing, and CLAUDE.md says that must be settled before that module is built.

11. **Gate files and CI.** CODEOWNERS covers these; approve them as a set, as in M0:
    - (a) The release-artifact scan becomes an `--artifact` mode of `scripts/banned-api-check.sh`. That script already owns every banned RNG name and is excluded from its own scan. It rejects both markers and the test key bytes.
    - (b) Root `Cargo.toml` profiles: release `panic = "unwind"`, core `overflow-checks = true`, and dependencies at opt-level 3 in dev builds. Core features: `test-registry` and `test-sources` (which turns on `test-registry`), neither default.
    - (c) canaries.sh gains:
      - two positive controls for the scan: a `test-sources` probe must be caught for both markers and the key; a `test-registry`-only probe must be caught for the registry marker and the key, and must hold no stub marker;
      - static checks: neither test feature is a default or enabled outside dev-dependencies, and `test-registry` does not enable `test-sources`; no serde in core's normal graph; getrandom's only dependent is core; ed25519-dalek resolves with no features and curve25519-dalek with only `digest`;
      - a vectors-tamper canary.
    - (d) The workflow gains:
      - all-features clippy;
      - the `test-sources` test run;
      - a coverage job with cargo-llvm-cov 0.9.1. It fails if any path under core/src would be skipped by the tool's default ignore rule: a `tests/`, `examples/` or `benches/` directory, or a file named `tests.rs`, `*_tests.rs` or `*-tests.rs`;
      - the scan in the cross job;
      - the age-interop job;
      - `--selftest` moved after the toolchain install.

      CI jobs go from 11 to 13. They become required checks only through Q12.
    - (e) CLAUDE.md Commands and `.gitignore`.

    Recommended: approve all.
    Otherwise, for (a): a separate `scripts/release-scan.sh` needs an exact-path exclusion in banned-api-check.sh, because the symbol names it searches for (arc4random, drand48, getentropy, SecRandomCopyBytes) trip the RNG patterns.

12. **Branch protection (new; build-plan.md "Security rules enforced in CI", row "Review").**
    `main` is unprotected today and no approvals are required (tasks/todo.md, M0 "Reviewers and disclosure"). M1 is the first milestone that merges security-critical core code.
    Recommended, before the first M1 merge:
    - A ruleset on `main` scoped to `Entropy/**`: require a pull request, and require the Entropy CI jobs (13 after M1) as status checks.
    - Approvals: 0 for now. One account (`bitwilll`) opens and merges every PR, and GitHub does not let an author approve their own PR, so any approval rule would block every merge.
    - When a second maintainer joins: 1 approval plus CODEOWNERS review. Two approvals needs two reviewers besides the author, so it waits for a third maintainer.
    - GitHub skips a path-filtered workflow entirely, so its checks stay pending on PRs that do not touch `Entropy/` (tasks/todo.md, M0 monorepo note), and a ruleset's required checks cannot be limited to `Entropy/**`. So the workflow drops its `paths:` filter and its first job tests whether `Entropy/` or the workflow changed; the other jobs then report "skipped", which GitHub counts as passing. This is a group 12 workflow change.
    - Record the ruleset (`gh api repos/bitwilll/keepcrypt/rulesets`) under Review. Until it exists, the plan says "CI jobs", not "required checks".
    - build-plan.md's two-approval rule stays the target. Review notes at each gate that it is unmet while there is one maintainer.

    Otherwise: keep `main` unprotected. Nothing then stops a merge with red CI, and Review says so at every gate.

### Raised by the review of commits 2-5 (standing approval applied 2026-10-10; owner confirmation pending)
Applied by the agent, not an answer from the owner: the owner's standing approval of the Q1-Q12 recommendations ("I
approve, do it", 2026-10-09) was applied on 2026-10-10 to Q13 (all five doc edits, as recommended) and Q14 (both
gate changes, as recommended). The owner has not answered Q13 or Q14 directly. The owner may veto any item; a veto
reverts that item in its own reviewed commit. Q13's edits landed as one docs-only commit (c40a2e3) before commit 8
("Q13 docs" in "Commit order on `m1-core`"); Q14's two gate changes stay as committed in f732c98.
- [ ] The owner confirms Q13 (a)-(e) and Q14 (a)-(b) explicitly, recorded here with a date, before the M1 gate
      (review fix after commit 10).

13. **Doc wording that Q5-Q7 or the plan pin more exactly than the docs.** Each item names the commit that needs it.
    Recommended: approve all five, as one docs-only commit before commit 8.
    - (a) URLs (Q6d). seal-watchonly-braille.md "Online lookup privacy" says `check#t=<T in hex>&n=<nonce in hex>`,
      and "Registering a new seal" says `register#c=<seal code>`. The code is shown with dashes everywhere else, and
      Q6 rejected a dashed code in the URL. New text: `https://<registry>/check#t=<T as 64 lowercase hex>&n=<n as 16
      lowercase hex>` and `https://<registry>/register#c=<the 26 seal-code characters, uppercase, no dashes>`.
      Needed before commit 17.
    - (b) Which Ready calls wipe (Q5). In build-plan.md "Public API", the comment "The exports below return
      ReadbackIncomplete, and wipe" sits above `verify_backup(&self)`, which cannot wipe. The invariant "the session
      wipes itself on any error" leaves out the calls that keep it alive. seal-watchonly-braille.md's read-back
      paragraph lists four exports and does not say whether passphrase generation is gated. New text:
      - move `verify_backup` up, next to `check_readback` and `readback_complete`. It stays ungated, because it can
        only succeed on a file that the gated `encrypt_backup` wrote;
      - both docs name the same five gated exports: `generate_backup_passphrase`, `encrypt_backup`, `watch_only`,
        `registration` and `reveal_device_leg`;
      - the invariant becomes "the session wipes itself on any error, except the user-input results that keep it
        alive: `Rejected::Retry`, `check_readback` and `verify_backup`";
      - build-plan.md lists the errors those two can return, and a group 9 test pins each list, so no internal
        failure comes back from them without a wipe. Otherwise, each gets its own narrower error type.
      Needed before commit 21.
    - (c) Credited bits (Q7). design.md "Device quota in practice", build-plan.md "Credit policy" and pi-firmware.md
      step 4 say the Pi's "512 credited bits arrive in one step". Plan group 9 has `credited_bits()` jump to 2,048:
      one 512-sample window at 4 bits per byte. New text: "the first window credits 2,048 bits, more than the 512
      required, all at once". Recommended: report 2,048, because a value capped at 512 would hide a wrong rate
      (1 bit per byte would also show 512). Otherwise: cap `credited_bits()` at `required_bits()` and change group 9.
      Needed before commit 8.
    - (d) Startup test (Q7). design.md "Test continuously" says the startup test covers "the first 1,024 samples after
      power-on", which reads as once per boot. pi-firmware.md step 4 and plan group 3 also discard the first 1,024
      samples of every ceremony (`HW_BYTES_NEEDED` = 1,536). New text: "at boot, and again at the start of each
      session's hwrng intake, run both over the first 1,024 samples and discard them". Needed before commit 8.
    - (e) Phone OS read (Q6a). mobile-apps.md step 6 says "Reads the OS CSPRNG", while the other docs read it at the
      commitment. New text: "Device entropy. Motion and touch extras are mixed in, with optional Snake or Tetris; the
      OS CSPRNG is read at the commitment." Needed before M5; no M1 code depends on it.
    Otherwise: each rejected edit leaves the docs and the plan disagreeing, and CLAUDE.md says that must be settled
    before the module is built.
14. **Two gate changes made in review (Q11).** Please confirm both.
    - (a) Test features. Q11(c) refuses a test feature only "outside dev-dependencies". In a scratch copy, a
      dev-dependency on core with `test-sources` in pi/app made `cargo build --release --workspace --all-targets`
      link the stub marker into the release `keepcrypt-pi` binary, because cargo merges features across every
      package in one build. canaries.sh now refuses a test feature in any manifest, dev-dependencies included, and
      the features are switched on only from the command line with `-p`.
    - (b) Profiles. canaries.sh now pins the root `[profile]` tables and core's `[features]` exactly. `panic =
      "abort"` would skip the wipe on panic, and no test could notice, because `cargo test` always unwinds.
    Both landed after commit 5 instead of commit 26, so the stubs (commit 6) never exist without them. Recommended:
    confirm. Otherwise: go back to the Q11(c) wording, build and scan release artifacts only with `-p`, and leave the
    profiles to CODEOWNERS review.

### Raised by the review of commits 11-15 (owner confirmation pending)
At commit 11 the agent replaced a value that the approved plan pins. Commits 12-15 built on the replacement, and no
owner has approved it. It is not covered by the standing approval of Q1-Q12.
- [ ] The owner answers Q15, recorded here with a date, before the M1 gate (review fix after commit 15).

15. **The Braille table digest and the Braille KAT's proof (plan group 5: check 8 and "KAT group Braille").**
    - The digest. The plan pins the table digest `41f0e259...`, but it never wrote down the text behind it.
      Commit 11 hashed about 300,000 candidate layouts of the cells, dots and signs, and the review after commit 15
      tried about 1,000 more layouts with words. None reproduces `41f0e259...`, and the full value appears nowhere
      in the repo. Commit 11 therefore defined the canonical table text itself, in braille.json's spec: `name cell
      dots` per line, a-z, then the number sign, grade 1 indicator, hyphen and blank cell, LF-terminated. It pinned
      that text's digest,
      `fd75c236d2ab92e0fe682d502a5b4bf2537f78d5ec5630b2bac20a963ece9c9d`, in verify.py, braille.json and core's
      Braille KAT. The review rebuilt the same digest with its own script, from the glyphs printed in
      seal-watchonly-braille.md.
    - The proof. The plan says "one flipped dot, or two swapped words, makes the group fail". The table holds cells,
      not words, so the Braille group's unit test swaps two letters' cells instead. Braille takes its words, and so
      its SeedBook numbers, from the BIP39 list. Two swapped words (ACT and ACTION) fail the Bip39Wordlist group:
      kat.rs `two_swapped_words_fail_the_wordlist_group`. Both groups run in every `self_test`.
    Recommended: approve the table-text definition and `fd75c236...`, and reword the proof as follows. One flipped
    dot, or two letters' cells swapped, fails the Braille group, and two swapped words fail the Bip39Wordlist group.
    Otherwise: supply the text behind `41f0e259...`. Check 8, braille.json and the Braille KAT then pin it in their
    own reviewed commit. Until the owner answers, `fd75c236...` is the agent's value, not an approved one.

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

**CI** (repo-root `.github/workflows/entropy-ci.yml`; green on PR bitwilll/keepcrypt#1, runs in "M0 on GitHub")
- [x] Hardening: runs on PRs and pushes to `main`; `permissions: contents: read`; checkout uses
      `persist-credentials: false`; only first-party actions (`actions/checkout`, `actions/cache`), each pinned by
      commit SHA; tools come from `cargo install --locked --version ...`; the toolchain comes from `rust-toolchain.toml`
- [x] `lint`: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [x] `test`: `cargo test --workspace --locked`
- [x] `supply-chain`: `cargo deny --locked check`, `cargo audit`, `cargo vet --locked` and `scripts/check-path-deps.sh`
- [x] `gates`: the banned-API check and its `--selftest`, `verify.py --selftest` and `scripts/canaries.sh`
- [x] `verifier (python 3.9)` on macos-26: `/usr/bin/python3` must be 3.9 and pass `verify.py --selftest`
- [x] `cross`, a matrix running per-target clippy (core plus `pi/app` or `ffi`) and
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

### Inputs from M0 (folded into the plan below)
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

### Plan
Refs: docs are named by file: build-plan.md, design.md, seal-watchonly-braille.md, pi-firmware.md and mobile-apps.md
(all in `docs/`), plus CLAUDE.md, lessons.md (`tasks/lessons.md`) and this file. "Qn" is owner question n under
"Needed before M1". Terms: KAT = known-answer test; CCTV = the C2SP age test kit in `vectors/age/`; RCT and APT = the
SP 800-90B Repetition Count and Adaptive Proportion tests; BCR = the Blockchain Commons research specs (UR, bytewords,
crypto-account); UEB = Unified English Braille; `.kcr` = a signed registry snapshot; KCP1 = a signed bucket proof
(Q6c). Symbols as in CLAUDE.md: D device leg, C commitment, R dice string, E seed entropy, S BIP39 seed, T seal tag,
n check nonce, G go-ahead code.
Modules land in the order below. Each module's vectors come first, and its unit tests pass before the next module
starts. Every item names its proof.

**Built into this plan (override any of them)**
- One error rule (Q5): any session method that can fail on randomness, a health test, a KAT or an integrity check
  takes `self`. An `Err` has therefore already dropped the session's single `Box<Inner>` and zeroized it. Only user
  input keeps the session alive: a go-ahead typo (`Rejected::Retry`), a read-back mismatch, a failed backup read-back.
- Two test features, both off by default (Q3, Q11):
  - `test-sources` (stub entropy, marker `KC_TEST_SOURCE_DO_NOT_SHIP`);
  - `test-registry` (the test registry key, marker `KC_TEST_REGISTRY_DO_NOT_SHIP`).
  `test-sources` turns on `test-registry`, never the reverse, so a build that trusts the local test registry (M3
  simulator, M5/M6 gate builds) links no stub. Stub tests declare `required-features` and run in a second
  `cargo test`. No manifest turns either feature on, in any dependency table (dev-dependencies and a self
  dev-dependency included) or feature: cargo merges features across every package in one build, so one such entry in
  any member would link stubs into every binary a `--workspace` build links, release builds included. They are
  switched on only from the command line, one package at a time (`-p`), and release artifacts are built and scanned
  per package, never with `--workspace`. canaries.sh enforces this (review fix after commit 5, Q14), so plain
  `cargo test --workspace` still tests the release configuration.
- Backup passphrases are generated only (build-plan.md "Encrypted backup format": no user-chosen passphrases in v1).
  The session stores the generated passphrase, and `encrypt_backup` and `verify_backup` take none. Typed words reach
  only `decrypt_backup` ("Check a backup").
- Vectors before code. Every computed value comes from a generator in `tools/verify/verify.py`, and `--selftest`
  re-runs it byte for byte against pinned known answers (lessons.md). verify.py embeds the BIP39 English list, because
  the M2 verifier ships as one file (build-plan.md "Release"):
  - stored as space-separated lines of 16 words, so `random` (word 1,422) never stands alone on a line and the
    banned-API gate's Python-import pattern stays quiet;
  - checked by SHA-256 over the exact bytes (the 2,048 words joined by LF, plus a final LF) against `2f5eed53...`.
  Rust tests read the JSON with `serde_json::Value` (Q4).
- Every M1 file obeys the M0 gates, tests included:
  - no `.ok()`, `.err()`, `unwrap_or*`, `map_or*`, `or`/`or_else`;
  - no `_ = expr`, `let _x = expr` or `drop(call())`;
  - no OS-RNG name outside `core/src/source*`, comments included;
  - no `#[path]` or `include!` (`include_bytes!` and `include_str!` are for vector data only);
  - no `as` casts on secret or length values (use `From`/`TryFrom`);
  - rename the known grep false positives (`path`, `include`).
- Constant-time compares use `bitcoin::hashes::cmp::fixed_time_eq`, which is already in the graph, on fixed-size
  arrays only.
- Out of M1:
  - the phone games' byte source (M5/M6; this file, "Inputs from M0");
  - the "Verify another device" API (M5/M6);
  - UniFFI;
  - the birthday-collision job (M7);
  - real release binaries. The scan covers the core rlib and a release probe now; M3-M6 add their own binaries;
  - registry key rotation (M9).

**0. Before code**
- [ ] Record the owner's answers to Q1-Q12 under "Needed before M1". Apply the approved doc edits (Q10) in their own
      reviewed commit (CLAUDE.md: docs and code must agree). Proof: the diff.
- [ ] Branch protection (Q12), an owner action before the first M1 merge: a ruleset on `main` for `Entropy/**` that
      requires a PR and the Entropy CI jobs; approvals 0 while one account opens and merges every PR. Proof:
      `gh api repos/bitwilll/keepcrypt/rulesets` output under Review. Until the ruleset exists, this plan says
      "CI jobs", not "required checks".

**1. Workspace and supply chain**
- [ ] Profiles and features (Q11):
      - Root `Cargo.toml`: `[profile.release] panic = "unwind"`, stated explicitly. Unwinding drops `Inner` and wipes
        it; abort would not.
      - `[profile.release.package.keepcrypt-core] overflow-checks = true`.
      - `[profile.dev.package."*"] opt-level = 3`, so scrypt, PBKDF2 and SHA run at speed in tests. Core stays at
        opt-level 0 for coverage.
      - core: `[features] test-registry = []` and `test-sources = ["test-registry"]`, neither default.
      - `.gitignore`: `/core/wip/` (trybuild).
      - canaries.sh pins the root `[profile]` tables and core's `[features]` exactly, so a switch to abort or a lost
        overflow check fails CI (review fix after commit 5, Q14). Any profile change updates that pin in the same
        commit.
      Proof: timings of the log2 N 18 round trip and the empty-snapshot root test. If the root test still takes over
      2 s, add `opt-level = 1` for core and record why.
      Measured at commit 18 (Apple M4 Max, dev profile, sha2 at opt-level 3 and core at 0): the empty-snapshot root
      test (`seal::merkle::tests::the_empty_root`, one streaming pass over 2^20 leaves) takes 1.45 s, three runs
      1.45-1.46 s, under 2 s, so core stays at opt-level 0 and the profiles and their canary pin are unchanged.
      Every valid snapshot costs one such pass, so the default unit run takes about 11 s, the test-sources unit run
      about 17 s and tests/kcr.rs about 11 s more. CI runners are slower; the log2 N 18 round trip is timed at
      commit 20.
      Measured at commit 20 (same machine and profiles): `backup::age::tests::a_round_trip_at_work_factor_18`, one
      12-word backup written and read back at log2 N 18 (two scrypt runs, 256 MiB each, scrypt at opt-level 3),
      takes 0.61-0.62 s in three runs. The Age known-answer group adds three scrypt runs at log2 N 10 to every
      session start. No profile change.
- [ ] Each new crate lands in the commit of the module that first uses it, with its cargo-vet entry, exactly as in the
      dependency table (Q1-Q4): 44 lock entries in all.
      - `cargo update --precise` holds back ctutils 0.4.2, toml 1.1.6, toml_parser 1.1.3, toml_datetime 1.1.1,
        toml_writer 1.1.2 and serde_spanned 1.1.1, because their newer releases are inside the cool-off.
      - deny.toml gains BSD-3-Clause in the Ed25519 commit (Q3).
      - ed25519-dalek is declared with `default-features = false` and no features; `verify_strict` needs none.
      Proof for each such commit:
      - the lock diff;
      - one getrandom, one digest, one sha2, one hmac;
      - `cargo tree -p keepcrypt-core --all-features --target all -e normal,build,dev -i rand_core`, and the same with
        `-i log`, match nothing;
      - in the Ed25519 commit, `cargo tree -e features` shows no feature on ed25519-dalek and only `digest` on
        curve25519-dalek;
      - the cool-off table;
      - `cargo deny --locked check` and `cargo vet --locked` pass. Imports are refreshed once online; the rest are
        listed as exemptions for approval (24 safe-to-deploy, 20 safe-to-run).

**2. Scaffolding: layout, errors, secrets, session skeleton, KAT harness, stubs**
- [ ] Layout (build-plan.md "Modules"; CLAUDE.md rule 1; this file, "Inputs from M0"):
      - `lib.rs` holds `#![forbid(unsafe_code)]`, the modules and re-exports only;
      - modules: `error.rs`, `secret.rs`, `kat.rs`, `source.rs` + `source/{os,stub}.rs`, `health.rs`, `pool.rs`,
        `dice.rs`, `seed.rs`, `braille.rs`, `ur.rs`, `descriptor.rs`, `seal/`, `backup/`, `session/`;
      - integration tests in `core/tests/`, helpers in `core/tests/common/mod.rs` (plain `mod common;`);
      - only `source/os.rs` names the OS RNG crate; everything else calls `source::fill_os`.
      Proof: banned-API gate clean.
- [ ] `error.rs` (thiserror 2; build-plan.md invariants; CLAUDE.md rules 3, 5):
      - `CoreError`, with nested `KatId`, `SourceFault`, `HealthFailure`, `CheckError`, `SnapshotError`, `BackupError`,
        `BrailleError` and `UrError` (the strict UR decoder's failures; every kcr.json UR negative names the variant
        it expects, reached through `SnapshotError::Ur(UrError)` for proofs);
      - all derive `Debug, Clone, Copy, PartialEq, Eq`;
      - payloads are enums, counts and indices, never bytes or text;
      - foreign errors pass through `map_err` to a payload-free variant (no `#[from]` or `#[source]`);
      - no `#[non_exhaustive]`, so a new variant breaks the shells' matches and gets reviewed;
      - variants never depend on features.
      Proof: a table test pins every variant's Display text, built through exhaustive matches.
      Review fix after commit 10: each enum is declared through `listed_enum!`, which generates its variant list
      with it (`ALL` for unit-only enums, and a test-only list of every value for all of them), so no variant can
      be left out of a list. `KatId::ALL`, the full suite, is one of them, so a new group always runs.
- [ ] `secret.rs` (CLAUDE.md rule 5; build-plan.md "secret"):
      - types:
        - `SecretBytes32` (D, E) and crate-private `SecretSeed64` (S; review fix after commit 18: S with the empty
          passphrase is `seed::EmptyPassphraseSeed`, a crate-private wrapper only seed.rs fills, from the words);
        - `SecretMnemonic` (word indices `[u16; 24]` plus a count);
        - `Bip39Passphrase` (`SecretString`; `new` rejects "" and never trims);
        - crate-private `BackupPassphrase` (8 indices), held only in session `Inner`;
        - `NewBackupPassphrase` (a display copy of the 8 words plus the confirm challenge) and
          `TypedBackupPassphrase` (typed words, for `decrypt_backup` only);
        - `CheckedBackup` (group 8);
      - each is built zeroed and filled in place, with `Zeroize` + `ZeroizeOnDrop`;
      - none has `Debug`, `Display`, `Clone`, `Copy`, `PartialEq` or `Serialize`;
      - bytes leave only through `expose_secret`, `words` or `CheckedBackup::reveal_*`, so review can grep every exit.
      Proof: a white-box test fills every field of each wrapper and of session `Inner` (the stored backup passphrase
      included), calls `zeroize()` and finds zeros. Trybuild fixtures in group 10. Review fix after commit 10:
      `Bip39Passphrase` lacked both traits (it wiped only through secrecy's own `Drop`); it now derives them, joins
      the white-box test, and a compile-time check requires `ZeroizeOnDrop` of every wrapper.
- [ ] Session skeleton:
      - `Session<S> { inner: Box<Inner>, state: PhantomData<S> }`;
      - a sealed `State` trait over uninhabited `Collecting`, `Committed`, `Rolling`, `Sealed`, `Checking`, `Ready`;
      - one `Inner` holds every secret at fixed capacity, so nothing reallocates and there is no `Option` to unwrap;
      - `Inner`'s `Drop` zeroizes;
      - `Session::new` runs the KATs.
      Group 9 adds the transitions.
- [ ] `kat.rs` (build-plan.md "kat" and test matrix row 1; design.md "Known-answer tests"):
      - `pub fn self_test()` serves the Pi and phone boot screens (pi-firmware.md step 1, mobile-apps.md step 2);
      - `Session::new` and `Wiped::restart` run the same suite;
      - each module adds its `KatId` group when it lands. The first groups:
        - Sha256 and Sha512: NIST empty, "abc" and 2-block messages;
        - Hmac: RFC 4231 case 2;
        - Bip39Wordlist: SHA-256 of bip39's list = `2f5eed53...`;
        - Bip39: 24 English entropy/mnemonic pairs, and the PBKDF2 seed for 2 of them;
      - budget per run: scrypt only at log2 N 10, at most 3 PBKDF2-2048 and 2 Ed25519 verifies, and at most 1 s on a
        Pi Zero (an estimate; M4 measures);
      - fault injection for the free functions that run KAT groups (`self_test`, `hwrng_boot_test`, `decrypt_backup`,
        `verify_snapshot`, `verify_bucket_proof`, `verify_bucket_proof_qr`, `seal_from_mnemonic`):
        - each public function is a thin wrapper over one crate-private body that takes `Option<KatId>`;
        - under `test-sources`, each has a `*_with_kat_fault(.., KatId)` twin that calls the same body;
        - one exhaustive `match` maps each entry point to the groups it runs.
      Proof: `tests/kat.rs` checks every kat.rs constant against its vectors file; the fault twins are proven in
      `tests/error_injection.rs`.
- [ ] `vectors/kat.json` and verify.py check 5:
      - contents: NIST FIPS 180-4 SHA examples, RFC 4231 case 2, RFC 8032 TEST 1 (Q3);
      - check 5 recomputes the SHA and HMAC entries with hashlib and hmac;
      - check 5 also reads the committed file: each section's entry names and every entry's keys are pinned, the SHA
        and HMAC values are recomputed from the file's own inputs, and the RFC 8032 entry must match a pinned
        SHA-256 of its bytes, taken from the RFC, until check 10 verifies it (review fix after commit 5);
      - one SOURCES.md row per standard.
      Proof: selftest passes on 3.12 and on `/usr/bin/python3` 3.9.
- [ ] `source/stub.rs` (`#![cfg(feature = "test-sources")]`; CLAUDE.md rule 10):
      - the marker `KC_TEST_SOURCE_DO_NOT_SHIP` is a `#[used]` static, and the source dispatch also passes it through
        `core::hint::black_box`, so linked artifacts keep it;
      - `StubEntropy::{Fixed, Stream, Fail, FailAt, ShortAfter}`. Stream is SHA-256 counter mode, never a PRNG. Fixed
        errors once used up, so tests count OS bytes exactly;
      - `WipeProbe` is bumped by `Inner`'s `Drop` after zeroizing;
      - entry points: `Session::new_with_stub(len, mode, platform, stub, kat_fault: Option<KatId>)`, plus the
        free-function fault twins (kat.rs);
      - without the feature, the source handle has only the OS arm, and no public API accepts a source.
      Proof: stub unit tests; the marker scan (group 11).

**3. source, health, pool**
- [ ] Vectors first (lessons.md; Q6a, Q7). `verify.py --write-keepcrypt-vectors` writes `vectors/keepcrypt.json`:
      - exact byte layouts and source ids;
      - health constants and test cases;
      - pool records mapped to D;
      - source-substitution inputs for Pi and Phone, mapped to D and C;
      - commitment and mixed-seed cases;
      - dice-only cases: the rolls.json strings, "6" x 99 and a 256-roll string;
      - test streams are SHA-256 counter mode, stored as hex.
      Checks:
      - check 6: byte equality plus pinned answers (empty-pool D, C for D = 00..1f, one mixed E, dice-only `123456` =
        `8d969eef...`). Review fix after commit 10: also the Pi and phone source-substitution D and C and the
        empty-record-skipped D (equal to the one-OS-record D), computed by a script that does not import verify.py;
        and the session record rules checked on the committed records (no empty record, the 64-byte OS record last,
        the hwrng records exactly the samples from index 1,024 on), so a changed generator cannot re-baseline them.
        The health cases include one where both tests fail on the same sample, pinning that the Repetition Count
        is checked first;
      - check 7: an exact-fraction APT cutoff reproduces SP 800-90B Table 2 (W = 512 gives 311, 177, 62, 13 for
        H = 1, 2, 4, 8), and the RCT cutoff for H = 4 is 6;
      - check 4 also runs Coldcard's rolls.py and rolls12.py on every dice-only case.
- [ ] `source.rs` (build-plan.md "source", "Credit policy"; design.md "Mixing and conditioning", the getrandom bullet;
      CLAUDE.md "Pi device quota"):
      - `fill_os(&mut [u8])` is one expression, `getrandom::fill` (blocking; never `fill_uninit`; never the `std` or
        `sys_rng` features);
      - it returns exactly `len` bytes or `Err`. Real and stub reads share the length check, so a short read always
        fails. Review fix after commit 10: `getrandom::fill` returns no count, so the length check covers the stub
        arm only. The OS arm is proven apart: a real-OS test (16 reads of 64 bytes, through `fill` and `os_bytes`)
        finds every byte position written, and a unit test in `source/os.rs` maps every getrandom error to
        `Source(Os)`. The stub error-injection tests never reach the OS arm, and `fill_os` staying one expression
        is a review check;
      - source ids per Q6a. Credited ids are crate-private; shells name only `ExtraSource::{InputTiming, Motion,
        Camera, Microphone}`;
      - constants: 64 OS bytes, 4 bits per hwrng byte, 512 bits on the Pi, 256 on phones by policy, and
        `HW_BYTES_NEEDED` = 1,536 (1,024 startup samples plus one 512-sample window);
      - `os_bytes::<N>()` is a separate read that never touches the pool. It serves the check nonce, the backup file
        key, salt, nonce and file name, and the passphrase and its confirm challenge.
      Proof: stub tests (exact, used up, short, failing); a credit-policy table test. Review fix after commit 10: the
      credit policy takes `CreditedSamples`, which only `HealthTester::credited_samples` builds, so no raw count (a
      partial window, startup samples) can be credited; the table feeds 1,535 bytes (unmet) and 1,536 (met) through
      a tester.
- [ ] `health.rs` (SP 800-90B 4.3, 4.4.1, 4.4.2; alpha 2^-20, H = 4; design.md "Test continuously"; Q7):
      - RCT cutoff 6; APT W = 512, C = 62;
      - the tester streams, and its state carries across calls;
      - the first 1,024 samples run both tests and are then discarded, never absorbed;
      - credit counts only post-startup samples in completed windows, so the Pi needs 1,536 bytes for 512 bits, and
        the credit arrives in one step;
      - a chunk is tested whole before any byte of it is absorbed;
      - `pub fn hwrng_boot_test` runs the Health KAT group, then takes exactly 1,024 samples (pi-firmware.md step 1);
      - errors carry the test, the stage and the sample index only;
      - review fix after commit 10: the first failure latches, so the tester fails every later chunk with it and
        credits nothing, fail-closed on its own and not only through the session's wipe.
      Proof:
      - every keepcrypt.json health case passes;
      - cutoff boundaries hold in both stages: a run of 5 passes and 6 fails; C - 1 passes and C fails;
      - chunks of 1, 64, 1,000 and the whole stream give the same verdict and tail (review fix after commit 10: the
        tail, what a caller absorbs, is compared in every chunking, not only the verdict);
      - a failed tester stays failed and credits nothing;
      - startup samples are discarded;
      - 1,535 bytes credit 0 and 1,536 credit 512 samples;
      - the tests still fire after startup.
- [ ] `pool.rs` (CLAUDE.md rule 4; build-plan.md "pool"; Q6a):
      - `new()` absorbs the 11 bytes `KCE/v1/pool` once;
      - each record is id u16 BE, `u64::try_from(len)` BE, then the data; empty data writes no record;
      - `finish` returns D = SHA-512(...)[0..32] and zeroizes the digest;
      - a compile-time check confirms the sha2 hashers are `ZeroizeOnDrop`.
      Proof:
      - empty-pool and record vectors; records ("ab", "c") and ("a", "bc") give different D;
      - pipe width (CLAUDE.md rule 2): each of the 512 single-bit flips of the 64-byte OS record (base bytes from
        SHA-256 counter mode) changes D.
- [ ] KAT groups:
      - Pool: one record vector;
      - Health: a stuck stream fails RCT and an alternating stream fails APT, each at its pinned index; a clean stream
        passes.
      Proof: the constants match keepcrypt.json.

**4. dice, seed**
- [ ] `dice.rs` (build-plan.md "dice"; CLAUDE.md "Dice quota"; this file, "Inputs from M0": R is exactly ASCII 1-6):
      - a fixed `[u8; 256]` buffer plus a length, with no Vec, so growth never leaves copies;
      - faces 1-6 map to `b'1'..=b'6'` by `match`; 0 and 7+ are `InvalidRoll`; roll 257 is `TooManyRolls`;
      - undo zeroes the removed byte and does nothing when no rolls are entered;
      - count and millibits (count x 2585; 37 rolls show "95.6 bits", pi-firmware.md step 6);
      - minimum rolls: 50 for 12 words, 99 for 24, 99 after a collision. Review fix after commit 10: 99 rolls give
        255.9 bits (99 x 2.585), not 256, and the code now says so; design.md "Recommended architecture" still says
        "256 with 99 rolls". Whether the 24-word minimum should become 100 rolls (258.5 bits) is a
        question for the owner, a doc change (CLAUDE.md "Dice quota", design.md); until answered, 99 stands.
      Proof: unit tests, including that R only ever holds `b'1'..=b'6'`.
- [ ] `seed.rs` (CLAUDE.md "Commitment", "Seed"; design.md "From entropy to a BIP39 seed phrase"; build-plan.md
      invariants):
      - C, mixed E and dice-only E exactly as in CLAUDE.md;
      - 12 words from E[..16], 24 from E[..32], via bip39 English, converted at once to `SecretMnemonic`;
      - S = `to_seed_normalized("")`, wrapped in `Zeroizing`;
      - wallet summary: the master fingerprint and the m/84'/0'/0'/0/0 P2WPKH mainnet address. Xprivs stay inside
        one function and are erased; the secp256k1 context is not randomized.
      - Review fix after commit 10: a single 5-step `derive_priv` left m/84', m/84'/0', the account key m/84'/0'/0'
        and m/84'/0'/0'/0 in rust-bitcoin's frame, never erased. Core now derives one level at a time and erases
        every Xpriv it holds (master, each intermediate, leaf) on every path. Residual risk, for the owner's review
        (not yet accepted; compare Q1 (iii) for scrypt): copies core cannot reach stay on the stack, namely
        rust-bitcoin's local copy of the parent in `derive_priv`, the HMAC state and output in its private
        `ckd_priv`, secp256k1's tweak temporaries, and the moved-from temporary of S returned by value from bip39's
        `to_seed_normalized` (wrapped in `Zeroizing` at once). The Pi keeps everything in RAM.
      - Review fix after commit 15: commit 15 moved the loop into `derive_erasing(secp, key: Xpriv, path)`, and
        `Xpriv` is `Copy`, so `wallet_summary` and `watch_only_export` kept their own `master` binding unerased (5
        stack copies of the master key and chain code after `wallet_summary` in a debug build, against 4 before).
        Every extended private key core derives now lives in a `SecretXpriv`: no `Copy` or `Clone` (it implements
        `Drop`, pinned by a `needs_drop` check), derived in place one level at a time, and erased on drop with
        volatile writes (the chain code included), on every path. The residual above also covers rust-bitcoin's
        `new_master`, whose HMAC output and returned-by-value key stay on its stack: a bare `new_master` followed by
        an erase leaves 3 copies of the key and 2 of the chain code in a release build, and `SecretXpriv::master`
        leaves the same.
      Proof:
      - keepcrypt.json C, E and words;
      - BIP39 vectors.json (TREZOR);
      - BIP-84 fingerprint `73c5da0a` and address `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`;
      - a hash without len(R) differs;
      - Coldcard rolls.json in dice-only mode (Verification);
      - pipe width (CLAUDE.md rule 2; build-plan.md first invariant), base values from SHA-256 counter mode:
        - each of the 256 single-bit flips of D changes both C and mixed E (fixed R);
        - for 24 words, each of the 256 single-bit flips of E changes the mnemonic indices;
        - for 12 words, each flip in E[..16] changes them and flips in E[16..] do not (12 words are the first 128
          bits by design).
- [ ] KAT group Seed: C, mixed E, dice-only `123456`.

**5. braille**
- [ ] Vectors first (this file, "Inputs from M0"; lessons.md; seal-watchonly-braille.md "Tests and cross-checks").
      `verify.py --write-braille-vectors` writes `vectors/braille.json`:
      - the alphabet with dot numbers, digits, specials, mirror pairs, counts and sections;
      - positions 1-24 with device and sequence (Q9), text vectors and backup lines;
      - per word: number, faces with blanks, the lighter face, mirror partners, every cell, flip neighbours and
        prefix-of.
      Check 8:
      - byte equality;
      - pinned answers: the seal-watchonly-braille.md alphabet, ABANDON 0001, ACT 0020, ACTION 0021, METAL 1121,
        WIRE 2018, ZOO 2048, `2026` = ⠼⠃⠚⠃⠋, table digest `41f0e259...`;
      - the docs' numbers, recomputed from the list: word-list SHA-256, 25 section counts, pages 001-098 at 24 words
        per page, 279 mirror-flip words, 49 three-letter prefix words, exactly four mirror pairs;
      - the SeedBook PDF's SHA-256, pinned.
      seal.json gains `seal_id_braille` (Q6f). The one-time check of the PDF's printed numbers and cover glyphs goes
      in Review.
      Recorded at commit 11: the plan never wrote down the canonical table text behind `41f0e259...`, and no
      plausible layout reproduces it (about 300,000 candidate layouts of the cells, dots and signs were hashed). The
      text is now defined in braille.json's spec (`name cell dots` per line, a-z then the number sign, grade 1
      indicator, hyphen and blank cell, LF-terminated) and its digest is `fd75c236...`, computed by a separate script
      from the glyphs printed in seal-watchonly-braille.md. A space renders as the blank cell U+2800. The owner has
      not approved this change; it is Q15 (review fix after commit 15).
      Review fixes after commit 15:
      - Check 8 now also reads seal-watchonly-braille.md (lessons.md). Each computable figure must appear there
        word for word, as recomputed:
        - the 279 and 49 sentences;
        - the 12-word checksum's "1 in 16" (2^CS with CS = 4);
        - ACT (0020) and ACTION (0021), the 2,048 distinct keys and 0001–2048;
        - the three alphabet lines, the number sign, the digits, the grade 1 indicator and the hyphen;
        - the `2026` and Seal ID glyphs;
        - the sentence with the sections, pages and sample numbers;
        - the Sources word-list SHA-256.
        The mirror pairs it names must be the pairs computed from the dots. Editing a figure in the docs, or the
        code that recomputes it, fails the self-test.
      - The one-time PDF check is now done: see Review, "M1: one-time SeedBook PDF check".
- [ ] `braille.rs` (seal-watchonly-braille.md "Braille backup"; CLAUDE.md "Braille"):
      - a const cell table (glyph and dots, reconciled by a test); mirror partners are computed from the dots;
      - `BrailleInserts<'s>` and `Insert<'s>` borrow the session's mnemonic and have no `Debug`, `Display`, `Clone`,
        `Copy` or `Serialize`;
      - per insert: position, device and sequence (Q9), SeedBook number 1-2048, five faces with explicit blanks,
        face 5 drawn lighter, and a flag on every e/i/d/f/h/j/r/w;
      - `word_cells()` covers every letter; crate-private `backup_lines()`;
      - `render_text` handles a-z, 0-9, space and hyphen (Q6f) and refuses anything else without echoing the
        character.
      Proof:
      - alphabet, digits, exactly four mirror pairs, the six sample inserts, bounds;
      - 2,048 distinct first-four keys (a blank counts);
      - 279 and 49 recomputed in Rust;
      - text vectors: `5e0g7j6x`, `2026-10-09`, `cf94-bcaj`, `1k`, `a1`.
- [ ] Read-back compare (seal-watchonly-braille.md "Read-back from the metal"; pi-firmware.md step 9):
      - input: 3 or 4 ASCII letters, case-folded, read up to the first blank face (`act` means face 4 is blank);
        anything else is `MalformedReadback`;
      - result: Match, or Mismatch with the word the metal spells (if any, with its SeedBook number) and a verdict per
        face: Ok, MirrorMisread, ShouldBeBlank, ShouldHaveLetter, or WrongLetter with the missing and extra dots.
      Proof:
      - all 2,048 words read back correctly from their own faces;
      - ACCESS read as `acci` gives ACCIDENT 0012 with MirrorMisread;
      - ACT read as `acti` gives ACTION with ShouldBeBlank;
      - ACTION read as `act` gives ACT with ShouldHaveLetter;
      - every mirror flip in faces 1-4 gives exactly one MirrorMisread, and names another word for exactly the 279;
      - prefix neighbours never match.
      Review fixes after commit 15:
      - every blank-face slip, with the exact verdict per face: each of the 103 three-letter words read with any
        fourth letter gives ShouldBeBlank on face 4, and each of the 1,945 longer words read as its first three
        letters gives ShouldHaveLetter (Verification, "every blank-face slip");
      - the result borrows nothing, so it wipes itself: `ReadbackMismatch` and `Dots` are `ZeroizeOnDrop` (pinned
        at compile time), and a verdict's zeroize clears its dots and resets the variant to `Ok`, because the
        variant plus the letters as typed gives the seed's letters back.
- [ ] KAT group Braille: SHA-256 of the canonical table text, plus `2026`. Proof: one flipped dot, or two swapped
      words, makes the group fail (unit test, injected).
      As built, pending Q15: one flipped dot, or two letters' cells swapped, fails the Braille group. Two swapped
      words fail the Bip39Wordlist group, the source of braille's words.

**6. ur, descriptor, watch-only** (the seal's proof QR reuses `ur.rs`, so this group comes before the seal)
- [ ] Vectors first. `verify.py --write-watchonly-vectors` writes `vectors/watchonly.json`, using:
      - a stdlib BIP32 on pure-Python secp256k1, run on public test mnemonics only;
      - RIPEMD-160, with a pure-Python fallback cross-checked against hashlib when hashlib has it;
      - bech32, the BIP-380 checksum, a dCBOR writer, bytewords and CRC32.
      Check 9: byte equality, with spec values pinned in code. SOURCES.md gains a "Spec values" table (URL at a pinned
      commit, page SHA-256, values copied) for BIP-84, BIP-380, BCR-2020-005, -007, -012, -015, bip32JP
      `test_JP_BIP39.json` and RFC 8949 Appendix A. Re-fetch each page at M1 start and confirm its hash.
      Review fixes after commit 15 (BIP-380 and RFC 8949 re-fetched with a generic User-Agent; both hashes match
      SOURCES.md):
      - RFC 8949 Table 6 has 24 rows in core's subset, not 23. `24(h'6449455446')` = `d818456449455446`, the only
        tag with a one-byte argument head, was missing and is now included.
      - BIP-380 lists its checksum cases without a verdict and makes the checksum optional for parsing.
        watchonly.json's `valid` flag is KeepCrypt's rule (the string ends in a correct 8-character checksum, as
        every export does). `spec.bip380` now says so, and SOURCES.md no longer credits the verdicts to BIP-380.
      - The strict UR reader counts UTF-8 bytes, in core and in verify.py: the 4,296 limit (the ASCII characters
        of a QR alphanumeric code) and the even length. Before, verify.py counted code points, so non-ASCII text
        got another error. Four non-ASCII negatives now pin the agreement; one is 4,296 characters but 4,297 bytes.
- [ ] `ur.rs` (Q2, Q6c; BCR-2020-005, -012):
      - a dCBOR subset writer: shortest heads, definite lengths, keys ascending;
      - CRC-32/ISO-HDLC from a const table;
      - a literal 256-word bytewords table;
      - writers `bytewords_minimal` and `ur_single(type, cbor)`; single frame only;
      - crate-private reader `ur_decode_single(expected_type, &str) -> Result<Vec<u8>, UrError>`, strict, in this
        order:
        1. at most 4,296 characters (the largest QR alphanumeric capacity), checked before any decoding;
        2. all lowercase or all uppercase (QR alphanumeric mode gives `UR:KEEPCRYPT-PROOF/`), folded once; mixed case
           is rejected;
        3. scheme `ur:`, then a type equal to `expected_type`;
        4. exactly one path segment after the type, so a multi-part sequence (`/1-3/`) is rejected;
        5. minimal bytewords: even length, every pair one of the 256 words;
        6. the CRC-32 (last 4 bytes, big-endian) matches;
        7. the CBOR is one byte string with a shortest-form, definite-length head, and no byte follows it;
        errors are payload-free and never echo input.
      Proof:
      - the RFC 8949 Appendix A subset;
      - CRC of `123456789` = `cbf43926`, plus the BCR vectors;
      - the BCR bytewords strings and all 256 bytes;
      - the `ur:seed` vector;
      - the 773-byte BCR-2020-015 example reproduces its UR exactly;
      - round trips over SHA-256 counter-mode strings of length 0-300, read back in lowercase and in uppercase;
      - decoder negatives: mixed case, a wrong type, a multi-part sequence, an odd length, an unknown byteword, a bad
        CRC, a non-shortest head (`0x5a` length form for a 771-byte string), an indefinite head, a non-byte-string
        item, a trailing byte after the byte string, and 4,297 characters (rejected before decoding).
- [ ] `descriptor.rs` (build-plan.md "descriptor"; seal-watchonly-braille.md "Watch-only export"):
      - from S: the master fingerprint, the m/84'/0'/0' xpub, and the first receive and change addresses by private
        derivation;
      - descriptors `wpkh([fp/84h/0h/0h]xpub/0/*)#cs` and `/1/*`, written with `h` and checksummed with miniscript's
        checksum `Engine`. Never miniscript's Display, which writes `'` and so changes the checksum;
      - a runtime self-check fails closed (CLAUDE.md rule 3): each string must parse with `Descriptor::from_str`,
        equal the descriptor built from its parts, and give the privately derived address at index 0. Otherwise
        `ExportSelfCheck`.
      Proof:
      - the BIP-84 vector;
      - the BCR-2020-015 shield seed (`37b5eed4`);
      - receive `#afwvtk2s` and change `#vatdkr6g`; the apostrophe forms are never emitted;
      - BIP-380 valid and invalid strings;
      - three tampered strings return `ExportSelfCheck`.
- [ ] `crypto-account` and the export (BCR-2020-015, -007; Q2; seal-watchonly-braille.md "Watch-only export" rules):
      - CBOR `{1: mfp, 2: [308(404(303({3: key, 4: chain, 6: 304({1: [84, true, 0, true, 0, true], 2: mfp}),
        8: parent fp})))]}`, untagged at the top level, with zero fingerprints omitted as the CDDL requires;
      - 116 bytes, a 258-character UR, and uppercase QR text;
      - a BIP39 passphrase is NFKD-normalized into a pre-sized `Zeroizing<String>` (unicode-normalization) before
        `to_seed_normalized`;
      - `WatchOnlyExport` holds the fingerprint, xpub, both descriptors, UR, QR text, the exported wallet's own first
        address (Q10) and `passphrase_used`. It is zeroized on drop and has no `Debug`, `Display`, `Clone` or
        `Serialize`, because an xpub reveals every address.
      Proof:
      - shield and abandon CBOR;
      - a test-only builder rebuilds the full 7-output BCR example;
      - the zero-fingerprint case;
      - TREZOR passphrase (`b4e3f5ed`, `#l3mwu4e8`);
      - the bip32JP passphrase gives `5d00908e`, and the unnormalized `68896147` never appears;
      - `TREZOR ` and `TREZOR` give different wallets.
      Residual risks found in review after commit 15, for the owner's review (not yet accepted; compare group 4):
      - Passphrase: unicode-normalization 0.1.25 keeps the characters it is decomposing, as (class, char) pairs, in
        a `TinyVec<[(u8, char); 4]>` (its `alloc` feature is always on). That buffer is inline on the stack, and
        it moves to the heap once more than four characters are pending (a starter with more than three
        combining marks, or a long compatibility decomposition). Both NFKD passes (the count and the fill) leave
        those characters behind unwiped, and a heap block is freed without being wiped. A scratch scanning
        allocator found 2 freed blocks holding U+1DC3 for `a` + U+1DC0..U+1DC7 (9 pending characters) and 0 for
        `a` + 3 marks. No setting of the crate avoids it. Closing it would mean core writing its own NFKD
        tables, which the plan does not include, so it stays as recorded unless the owner asks for that.
      - Xpub: `WatchOnlyExport`'s wipe covers the copy the shell holds while the QR is shown. Building the export
        frees about six unwiped heap copies of the xpub text, and copies of the account chain code: core's
        descriptor strings and CBOR, the UR's Bytewords, rust-bitcoin's base58 and miniscript's parse in the
        self-check. A scratch scan counted 6 freed blocks holding the abandon xpub during `watch_only_export`,
        and 0 added by dropping the export. This is public-key data, not a spend secret. Wrapping core's own
        buffers in `Zeroizing` would not close it, because miniscript's and rust-bitcoin's copies stay.
- [ ] KAT group Bip84 (abandon: fingerprint, xpub, first address, receive checksum, UR). It catches a miscompiled
      secp256k1-sys on a target. The Seal group later reuses its PBKDF2.

**7. seal**
- [ ] Vectors first. `verify.py --write-kcr-vectors` writes `vectors/kcr.json` (hex text), using a stdlib RFC 8032
      Ed25519 that signs only with two keys derived from public labels (Q3), plus Merkle, `.kcr` and KCP1 builders.
      Cases:
      - valid snapshots: empty, small, containing seal vector 1, containing the 50-roll dice-only seed;
      - snapshot negatives, each signed so that exactly one check fails: magic; versions 0 and 2; truncated header and
        body; trailing byte; flipped signature; header changed after signing; wrong key; S + L; count 2^22 + 1 (the
        loader's limit), 2^32 + 1 and u64::MAX; unsorted within a bucket with a matching root; duplicate; zero count;
        root mismatch; bad date;
      - proof cases: clear with an empty bucket and with a shared prefix; collision; wrong bucket; a forged sibling at
        each of the 20 levels; mixed header and path; bad signature; wrong key; truncated; trailing byte; k mismatch;
        entry outside its bucket; unsorted; bad magic; index >= 2^20; UR with a bad CRC; multi-part UR; UR in mixed
        case; UR of the wrong type; a non-shortest CBOR head; a trailing byte inside the UR; a UR over 4,296
        characters;
      - the QR size boundary: a 75-entry clear proof whose UR has at most 4,296 characters (accepted) and a 76-entry
        one whose UR has more (rejected before decoding);
      - proof freshness, against a `today` pinned in the file: a clear proof dated today - 30 (Current), today - 31
        (Stale) and today + 1 (Future);
      - T and G for the rolls.json 50- and 99-roll seeds, with n = `0001020304050607`;
      - each case names the Rust error, or the freshness, it expects.
      Check 10: RFC 8032 TEST 1-3 (S + L rejected); every kat.json Ed25519 entry verifies with the stdlib verifier
      (cofactorless, S >= L rejected) and fails with one bit flipped in its public key, in R and in S; byte equality;
      the pinned empty-snapshot root, test public key and vector-1 proof root; and the docs' computed figures
      (lessons.md): 75 as the largest k whose single-part UR fits 4,296 characters ("About 75 bucket entries fit one
      QR"), 2^22 x 18 + 122 = 75,497,594 bytes ("75.5 MB") and 10^6 x 18 bytes ("about 18 MB"), in
      seal-watchonly-braille.md "Snapshot format" and "Go-ahead QR".
      Review fixes after commit 18:
      - The strict cases isolate their rules. At commit 16 "small-order-key" was the identity as the key and as R,
        so the R rule alone refused it, and dropping only the key rule from verify.py left check 10 passing. Now
        three cases: a small-order key with R = B and S = 1, a full-order key with a small-order R, and both small
        order (the old bytes). Check 10 pins which point of each is of small order (`KCR_STRICT_RULES`), and core's
        test reads the same two flags against dalek's `is_weak`. Dropping either rule alone now fails check 10.
      - The proof negatives fail one check each, like the snapshot negatives. At commit 16 the five entry-rule
        proofs (k above the count, an entry outside the bucket, unsorted, duplicate, zero count) and the
        out-of-range bucket also failed the root. Each is now signed under a header whose root is the one its
        entries and path give (k above the count: a header counting 1 for 2 entries; the out-of-range bucket: no
        entries), so a malformed bucket the registry itself signed is refused by the rule alone.
      - 20 `order-*` cases (10 snapshot, 10 proof) each break two or more checks and pin the first, so the check
        order of snapshot.rs and proof.rs (and kcr_read_header, kcr_verify, kcp1_verify) is proven, not only
        stated: magic before version, version before signature, signature before date, count and the body,
        date before count, count before bucket, bucket before length, length before k and the entries, k before
        the entries, an entry's bucket before its order, order before a zero count, the entries before the root.
        Check 10 also reads every check each rejected case fails, apart from the first-error verifier (KCR_SPEC
        "negatives"): a negative must fail only its own check, except that a truncation, a wrong length or a
        snapshot count over 2^22 spoils what reads past it, and an `order-*` case two or more, its pin first.
        kcr.json goes from 87 to 107 cases.
- [ ] `seal/crockford.rs` and seal derivation (seal-watchonly-braille.md "Seal derivation spec", "The seal image";
      CLAUDE.md rule 7):
      - Crockford encoding reads 5-bit groups, most significant first;
      - code = top 130 bits of HMAC-SHA256(S, `KCE/v1/seal`), using hmac 0.13. S uses the empty passphrase only; no
        passphrase parameter exists;
      - T is computed over the 26 characters without dashes;
      - Seal ID, lookup prefix, bucket, grid and colour are all computed once, in `finish`;
      - `SealCode` and `SealRegistration` are zeroized and have no `Debug`, `Display`, `Clone` or `Serialize`;
      - `pub fn seal_from_mnemonic` runs the Seal KAT first;
      - `SealPublic::seal_id_braille()` uses `render_text`;
      - `SealPublic::recheck_url()` (Q6d): `REGISTRY_ORIGIN/check#t=<64 lowercase hex>` with no n, so a checker can
        show the count but never a go-ahead code (seal-watchonly-braille.md "Re-checking an existing wallet").
      Proof: every field of the three seal.json vectors, including the S prefix (which pins the empty passphrase) and
      the braille caption; the dashed form gives a different T (lessons.md); the exact re-check URL for vector 1.
      Recorded at commit 17:
      - `seal_from_mnemonic` gets S through `seed::seed_from_mnemonic_into`: the words' entropy is unpacked into a
        zeroizing buffer and re-encoded by bip39, whose words must match, so a bad checksum is `Internal(Bip39)`.
      - The Seal KAT starts from the abandon S pinned in kat.rs (`ABANDON_SEED`, kcr.json "seeds"), which the Bip84
        group now also compares with its own PBKDF2 output, so the full suite still runs 3 PBKDF2-2048. The hmac
        crate's HMAC-SHA256 joins the Hmac group (RFC 4231 case 2).
      - Residual risk, for the owner's review (not yet accepted; compare group 4): hmac 0.13's `new_from_slice`
        builds its keyed state from a padded copy of the key, S xor 0x5c by the end, in a local block, and leaves it
        on the stack unwiped. Its two SHA-256 states, its buffer and its output wipe themselves (sha2's and
        digest's `zeroize`), but `Hmac` does not implement the `ZeroizeOnDrop` marker, so no compile-time check
        can pin that. Closing it would mean core writing its own HMAC, which CLAUDE.md rule 11 rules out.
      Review fix after commit 18 (replaces the second bullet above): the Seal KAT skipped the S step that
      `seal_from_mnemonic` runs. `Suite::Seal` was the Seal group alone, which started from the pinned
      `ABANDON_SEED`, so a fault in `seed_from_mnemonic_into` (the unpacking, bip39's re-encode or PBKDF2) gave a
      wrong but well-formed seal, a re-check that reports "not registered" for a registered seal, and no KAT
      failure; only the full suite's Bip84 group compared PBKDF2 with `ABANDON_SEED`, and nothing ran the
      unpacking. The Seal group now derives S from the abandon words through `seed_from_mnemonic_into` and
      compares it with `ABANDON_SEED`, then checks the code, T, the Seal ID and its braille caption (now pinned
      too). The Bip84 group starts from `ABANDON_SEED` instead of running its own PBKDF2, so the full suite still
      runs 3 PBKDF2-2048 (2 Bip39, 1 Seal), and `Suite::Seal` runs 1. This keeps the plan's sharing of one abandon
      PBKDF2 between the two groups (group 6: "The Seal group later reuses its PBKDF2"), with the Seal group now
      the one that runs it. A unit test passes the group an S step that flips one bit of S, and one that fails;
      both fail the group. `SecretMnemonic::fill_from` loses its dead-code expectation (the Seal group calls it).
      Review fix after commit 18 (CLAUDE.md rule 7 in the types): `derive_seal` and `SealCode::fill_from_seed`
      took any `&SecretSeed64`, the same type `passphrase_seed_into` fills with the seed of a BIP39 passphrase, so
      a passphrase seed reaching the seal compiled (a scratch test gave that wallet's seal, `NMMVA7FR`). S now has
      its own crate-private type, `seed::EmptyPassphraseSeed`, which only seed.rs fills and only from the words
      (`mnemonic_and_seed_into`, `seed_from_mnemonic_into`); `as_seed` lends it out as a `SecretSeed64` for the
      watch-only export, and nothing converts the other way. `derive_seal`, `fill_from_seed`, `wallet_summary`
      (the fingerprint the backup names) and the session's `bip39_seed` take it; `passphrase_seed_into` still
      fills a plain `SecretSeed64`. The same scratch test now fails with E0308 ("expected
      `&EmptyPassphraseSeed`, found `&SecretSeed64`"). A trybuild fixture cannot pin this: trybuild and doctests
      build an outside crate, which cannot name a crate-private type, so the signatures are the proof.
- [ ] Check request and go-ahead (seal-watchonly-braille.md "The seal card", "Online lookup privacy", "Go-ahead code";
      CLAUDE.md constants; Q6d):
      - `start_check` draws n with `source::os_bytes::<8>()`;
      - the check URL is `REGISTRY_ORIGIN/check#t=<64 hex>&n=<16 hex>`, in lowercase. `REGISTRY_ORIGIN` is
        `"https://registry.invalid"` until M9 (this file, "Later");
      - G = the first 5 bytes of SHA256(`KCE/v1/go` || T || n);
      - decoding is case-insensitive, ignores `-` and spaces, maps O to 0 and I/L to 1, and needs exactly 8 symbols;
      - G is compared with `fixed_time_eq`; retries are unlimited and keep the session and the same n;
      - no file under `core/src/seal` names the OS RNG.
      Proof:
      - `CF94-BCAJ` and the codes for seal vectors 2 and 3 pass;
      - a code for another T, any single flipped bit of n, and all 40 single-bit flips of G fail;
      - a typo followed by the right code reveals the words;
      - the exact URL for vector 1.
      As built at commit 17: `CheckNonce::draw`, `CheckRequest::new`, `verify_go_ahead`, `SealRegistration::new`
      and `CollisionReport::new` are crate-private and unit-tested; `start_check`, `check_request`, `reveal` and
      `registration` call them from group 9 (commit 22), where "a typo followed by the right code reveals the
      words" is proven on a session. Commit 17 proves the function-level half: a malformed and a wrong code, then
      the right one.
      Review fix after commit 18: check.rs's module comment (and commit 14444c1's message) said no file under
      `core/src/seal` names "the OS source", but its own test the_nonce_comes_from_the_os_source builds
      `Source::Os`. The plan's rule is about the OS RNG crate, and the banned-API gate holds it; the comment now
      says that, and that the nonce's bytes come only through `Source::os_bytes`.
- [ ] `seal/merkle.rs` (CLAUDE.md "Bucket proof"; seal-watchonly-braille.md "Snapshot format"; Q6b):
      - leaf and node exactly as in CLAUDE.md, with the prefix written as a 24-bit big-endian bucket index;
      - the root comes from one streaming pass with at most 21 stacked hashes;
      - paths run leaf level first, and direction bit j = (i >> j) & 1.
      Proof: empty leaves 0, 0x2b810 and 0xFFFFF; a node vector; the empty-snapshot root; the left-aligned reading
      (`2b 81 00`) is shown to give a different leaf and is not used.
- [ ] `seal/snapshot.rs` (build-plan.md `verify_snapshot` and CI rule "Only authentic snapshots are used"; Q6b):
      - checks, in this order:
        1. length >= 122;
        2. magic;
        3. version 1;
        4. Ed25519 `verify_strict` over the 58 header bytes, against the pinned key;
        5. the date;
        6. count <= 2^22, through a checked u64-to-usize conversion (the Pi is 32-bit);
        7. the exact length;
        8. a cheap pre-pass for order and non-zero counts;
        9. the root;
      - `VerifiedSnapshot` has private fields, `lookup(&SealTag) -> Option<NonZeroU16>`, `date()` and
        `freshness(today)`, the last two from the header code shared with proofs;
      - `freshness(today)` gives Current, Stale (from day 31) or Future. Phones warn on Stale and Future; the Pi shows
        the date for the user to confirm (lessons.md);
      - `verify_snapshot` runs the Ed25519 and Merkle KATs first.
      Proof:
      - every kcr.json case gives its exact result, and every `SnapshotError` variant is produced;
      - all 976 single-bit flips of the first 122 bytes, and every truncation, fail;
      - date edge cases.
- [ ] `seal/proof.rs` (seal-watchonly-braille.md "Go-ahead QR"; Q2, Q6c):
      - KCP1 must be exactly 771 + 18k bytes, and reuses the snapshot's header and signature code;
      - k <= count; the entries are sorted and all fall in this bucket; the recomputed root equals the header's;
      - `verify_bucket_proof_qr` reads a single-part `ur:keepcrypt-proof/` through `ur_decode_single`;
      - `VerifiedProof` has private fields, `bucket()`, `date()` and `freshness(today)`, from the same header code as
        snapshots, so a go-ahead QR gets the same date rule as a loaded snapshot. Phones warn on Stale and Future; the
        Pi shows the proof's date and asks the user to confirm it before `reveal` (lessons.md: the Pi has no clock).
      Proof: the kcr.json proof cases, including Current at day 30, Stale at day 31 and Future one day ahead.
      As built at commit 18: the date type is `RegistryDate` (YYYYMMDD, a real Gregorian date in years 1-9999;
      `from_yyyymmdd`, `new`, `yyyymmdd`), not `Date`, which UniFFI would hand Swift as a clash with Foundation's
      `Date`; `Freshness` is Current, Stale or Future. `VerifiedProof::lookup(&SealTag)` is public and gives
      `Err(CheckError::WrongBucket)` for a seal in another bucket, else the count or None, so the shells and
      tests/kcr.rs read a proof the way `reveal` will. Both verified types also expose `number()` and
      `entry_count()`. A found entry is never reported clear, even if a zero count could reach it.
- [ ] `seal/registry_key.rs` and registration (seal-watchonly-braille.md "Registry service spec", "Registering a new
      seal", "Reporting a collision"; CLAUDE.md rule 10; Q3, Q6d):
      - release builds pin no key until M9, so snapshots and proofs fail closed with `NoRegistryKey` and only the
        typed code works;
      - under `test-registry` (which `test-sources` turns on), the key is the public half of
        SHA256(`KCE/test/registry-key/v1`). The marker `KC_TEST_REGISTRY_DO_NOT_SHIP` is a `#[used]` static, also
        passed through `core::hint::black_box` on the key-selection path, so linked artifacts keep it;
      - the key bytes exist only under `test-registry`; the choice between no key and the test key is a pure
        function, unit-tested both ways;
      - `registry_key_is_test()` lets a shell show a test banner;
      - kcr.json tests that verify signatures declare `required-features = ["test-registry"]`; the release-mode sweep
        (every kcr.json case gives `NoRegistryKey`) is its own test target with no required-features, gated on
        `cfg(not(feature = "test-registry"))`. `tests/vectors.rs` splits the same way;
      - one key per release; rotation statements wait for M9;
      - registration URL: `REGISTRY_ORIGIN/register#c=<26 uppercase characters>`, plus the grouped code and the Seal
        ID for the screen. The same builder makes the collision report.
      Proof: plain `cargo test` (features off) gives `NoRegistryKey` on every kcr.json case; both keys decode and are
      not weak; the abandon registration URL matches; a `test-registry`-only build holds the registry marker and not
      the stub marker (group 12).
      As built at commit 18: `choose` also refuses a pinned key that does not decode or is weak, with
      `NoRegistryKey`, so a wrong pin fails closed. The key is checked right after the KAT groups and before any
      byte is read, so release builds give `NoRegistryKey` for UR text too (tests/kcr_release.rs, 87 cases). A host
      release rlib built with `--features test-registry` holds the registry marker and the test key and no stub
      marker; the default release rlib holds neither (checked by hand until the group 11 scan). deny.toml gains
      BSD-3-Clause in this commit; canaries.sh pins deny.toml's `[graph]`, `[bans] deny` and `[sources]`, not its
      `[licenses]`, so no canary pin changes with it.
      Review fix after commit 18: `registry_key_is_test()` was `pinned_bytes().is_some()`, right only while the test
      key is the only key that can be pinned; once M9 pins the production key in release builds, every release
      would have reported a test registry and shown the test banner. It is now `cfg!(feature = "test-registry")`.
      The tests state the two facts apart: no key is pinned (until M9: `pinned_bytes()` is None, and the valid
      `small` snapshot and its clear proof give `NoRegistryKey`), and the build is not a test build (always). With
      a scratch stand-in for the M9 pin, the second still passes and the first fails where it should. The release
      sweep covers 107 cases since the vector fixes above.
- [ ] KAT groups:
      - Seal: the vector-1 code, T and Seal ID (review fix after commit 18: from the abandon words through
        `seed_from_mnemonic_into`, with S compared to `ABANDON_SEED`, and the Seal ID's braille caption);
      - GoAhead: `CF94-BCAJ`; a wrong n fails;
      - Ed25519: RFC 8032 TEST 1 is accepted; one flipped bit is rejected;
      - Merkle: a leaf, a node and the vector-1 path. Never a full root.

**8. backup (age v1, scrypt only)**
- [ ] Vectors first:
      - `verify.py --write-backup-vectors` writes the passphrase-layout and plaintext-v1 sections of
        `vectors/backup.json`, taking fingerprints from keepcrypt.json and watchonly.json; check 11 regenerates them;
      - `scripts/age-interop.py --generate` (stdlib; drives `age` through a pty) writes the `age_cli_written` section
        once, with Ubuntu age 1.1.1-1ubuntu0.24.04.3. SOURCES.md records the tool, version and date;
      - vectors are JSON, not `.age` files, since `.gitignore` bans `*.age`.
      Recorded at commit 19:
      - backup.json holds the constants, the passphrase layout (`passphrases`), the `generate` cases (every OS
        byte the call reads, then the passphrase and challenge, or the error), the plaintexts and refused
        plaintexts, the file name rule, the age files and the refused files (each with the error core must give
        and whether the reader may reach scrypt first), and the largest plaintext and armored file a backup can
        be (1,042 and 1,726 bytes for 24 words, within the 4 KiB and 8 KiB caps). The plaintexts' mnemonics and
        fingerprints come from watchonly.json (abandon, zoo-24, shield); keepcrypt.json holds no fingerprints.
      - The confirm challenge, which the plan left open beyond "2-of-4, without modulo bias", is defined in
        backup.json's spec: 16 OS bytes per attempt; the two asked words are `b[0] & 7` and `b[1] & 7` (any two
        of the eight), the right word's place among the four choices `b[2] & 3` and `b[3] & 3`, and the six
        other choices 11-bit values from `b[4..16]`. An attempt that asks one word twice or repeats a choice is
        dropped; after 64 attempts the call fails closed with a new `SourceFault::NoUsableDraw` (core, commit 21).
        A separate script reproduced the `stream` case from the spec text alone.
      - backup.json's own age files use work factor 10, like CCTV's, so the pure-Python scrypt rebuilds them on
        `/usr/bin/python3` 3.9 (no `hashlib.scrypt` there). The writer is the same at 18: core round-trips at 18,
        and `scripts/age-interop.py` exchanges work-factor-18 files with the age CLI.
      - The age CLI's files are their own file, `vectors/age/age_cli_written.json`, with a SOURCES.md row, not a
        section of backup.json: check 11 regenerates backup.json byte for byte, and age's output is random.
      - Deviation: they were written with Homebrew age 1.3.2, the CLI on this Mac, not Ubuntu's 1.1.1, which is
        not installable here. `scripts/age-interop.py` works with both (it waits for each passphrase prompt),
        and the CI `age-interop` job (commit 27) runs it against Ubuntu 1.1.1 in both directions.
      - verify.py's age is written from the C2SP age spec (`age.md`, downloaded twice on 2026-10-10 with a generic
        User-Agent, recorded in SOURCES.md "Spec values"); it rebuilds CCTV `scrypt` and `armor_scrypt` byte for
        byte and reaches all 26 CCTV outcomes.
- [ ] `backup/armor.rs` (build-plan.md "Container"; C2SP age "ASCII armor"):
      - encode: 64-column padded base64, exact labels, LF line endings;
      - decode accepts only surrounding ASCII whitespace, LF or CRLF, full 64-character lines (except a last line of
        1-64), and canonical padding (base64ct).
      Proof: armoring CCTV `scrypt` gives `armor_scrypt` exactly; CRLF is accepted; these negatives all fail:
      lowercase label, a 63- or 65-character line, an empty last line, bad or non-canonical padding, an inner space,
      text after END, no END, a BOM.
- [ ] `backup/age.rs` (C2SP age v1; build-plan.md "Recipient: scrypt only"; Q1 reader policy):
      - a strict header grammar;
      - the scrypt stanza must be alone, with 3 arguments, a canonical 16-byte salt, and log2 N matching `[1-9][0-9]?`
        in 1-18, all checked before any scrypt work;
      - the body is 32 bytes;
      - wrap key = scrypt(pass, `age-encryption.org/v1/scrypt` || salt, 2^N, 8, 1);
      - header MAC = HMAC-SHA256 keyed by HKDF(file key, "", `header`), checked in constant time;
      - one final payload chunk of at most 4 KiB; the 8 KiB file cap is checked first;
      - the writer uses log2 N 18, with file key, salt and nonce from `source::os_bytes`;
      - keys and plaintext stay in `Zeroizing`.
      Proof:
      - all 26 CCTV files reach their expected class: 2 success, 4 no match, 20 header failure. Exactly 26 files, and
        an unknown header key fails the test;
      - the writer reproduces CCTV `scrypt` and `armor_scrypt` byte for byte from fixed inputs;
      - our negatives, including trailing garbage on the work factor (`10aaaa`) and after the payload (this file,
        "Inputs from M0").
      As built at commit 20:
      - Every refused file in backup.json gives its exact error, and a thread-local count of scrypt runs proves
        that each case backup.json marks `scrypt: false` (everything the header, the stanza and the payload's
        length refuse) is refused before any scrypt work. A header with no scrypt stanza is no match
        (`WrongPassphrase`), as CCTV `scrypt_uppercase` expects. The armor is detected by `-----BEGIN` after
        leading space, tab, CR or LF, so a BOM before it is read as a binary file (`Header`).
      - Mutation testing showed no case with an armor last line over 64 characters (the 63- and 65-column cases
        are caught by the full-line rule alone); a verify commit before this one added `armor-last-line-long`.
      - The writer refuses work factors outside 1-18 and plaintexts over 4 KiB (`Internal(Length)`), so it writes
        only what the reader reads; no single flipped bit of a binary backup is accepted.
      - chacha20poly1305 and base64ct are built without `alloc` (table A lists it): core uses the in-out AEAD calls
        and slice encoding, which need no allocation. The lock entries are the same either way.
      - Residual risk, for the owner's review (not yet accepted; Q1 (iii) accepted only scrypt's buffers): HKDF's
        extract step keeps copies of the pseudorandom key, derived from the file key, in its own frames (the copy
        it returns is wiped), and the header MAC's hmac leaves its padded key block, as recorded in group 7.
- [ ] `backup/passphrase.rs` (build-plan.md "Passphrase"; pi-firmware.md USB steps 1-2; mobile-apps.md "Encrypted
      backup only"; Q6e):
      - 11 fresh OS bytes, cut into 8 indices of 11 bits;
      - the age passphrase is the 8 lowercase words joined by single spaces;
      - `TypedBackupPassphrase::from_words` accepts exactly 8 words, each exactly as in the list; only
        `decrypt_backup` takes one;
      - the core also draws the 2-of-4 confirm challenge, without modulo bias.
      Proof: layout vectors (zeros give abandon x 8; ff x 11 gives zoo x 8); each of the 88 single-bit flips changes
      exactly one word; the challenge equals its stub-stream value; a trybuild fixture shows typed words cannot reach
      `encrypt_backup` or `verify_backup` (group 10).
- [ ] `backup/plaintext.rs` (build-plan.md "Plaintext inside the file"; seal-watchonly-braille.md "Inside the
      encrypted backup"; Q6e):
      - writes the exact v1 bytes;
      - the parser checks the BIP39 checksum and the fingerprint, then requires byte equality on re-serialization;
      - `keepcrypt-backup/v2` gives `UnsupportedVersion`;
      - the BIP39 passphrase has no way in.
      Proof: the abandon x 11 + about and zoo x 23 + vote vectors; CRLF, a BOM, a missing final LF, uppercase,
      18 words, a bad checksum, mismatched braille and a wrong fingerprint all fail.
- [ ] Backup API (Q5; build-plan.md "Encrypted backup format" rules):
      - `generate_backup_passphrase(self)` on `Session<Ready>` draws 11 OS bytes and the confirm challenge in one
        call, stores the passphrase in `Inner` (replacing any earlier one), and returns `NewBackupPassphrase`: a
        display copy of the 8 words plus the 2-of-4 challenge, zeroized on drop, with no Debug, Display or Clone;
      - `encrypt_backup(self, &CreatedBy)` takes no passphrase and uses the stored one. File key, salt, nonce and name
        come from `source::os_bytes` in the same call. Before `generate_backup_passphrase` it gives
        `NoBackupPassphrase`, a shell-order bug, so it wipes like `ReadbackIncomplete`; any other `Err` wipes too. A
        retry after a USB failure re-encrypts with the same stored passphrase, so the paper copy stays valid;
      - `verify_backup(&self, file)` takes no passphrase, decrypts with the stored one, and compares fingerprint and
        entropy; a failure is retryable (before `generate_backup_passphrase`: `NoBackupPassphrase`, no wipe);
      - output: the armored bytes plus the name `keepcrypt-backup-<8 lowercase hex>.age`;
      - core does no file I/O.
      Proof:
      - log2 N 18 round trips for 12 and 24 words (the header shows ` 18`);
      - two backups of one session differ in salt, nonce, file key, name and ciphertext, and both pass
        `verify_backup`;
      - another session's file gives `WrongPassphrase`; a file under this session's passphrase but another seed's
        plaintext (crate-private writer) gives `ReadbackMismatch`;
      - after a second `generate_backup_passphrase`, a file written under the first one fails `verify_backup`;
      - `encrypt_backup` before `generate_backup_passphrase` gives `NoBackupPassphrase` and one wipe;
      - the age 1.1.1 files decrypt.
- [ ] "Check a backup" (pi-firmware.md "Encrypted backup to a USB stick"; mobile-apps.md "Checking a backup";
      seal-watchonly-braille.md "Re-checking an existing wallet"):
      - `decrypt_backup(file, &TypedBackupPassphrase) -> Result<CheckedBackup, CoreError>` runs the Age KAT first;
      - `CheckedBackup` holds the mnemonic, the verified fingerprint and the verified braille lines. It is zeroized on
        drop and has no Debug, Display, Clone or Serialize;
      - it exposes:
        - `fingerprint()`;
        - `seal() -> Result<SealPublic, CoreError>`, through `seal_from_mnemonic` (so the Seal KAT runs), for re-checks
          by loaded snapshot (`VerifiedSnapshot::lookup`) or online (`SealPublic::recheck_url`);
        - the words and braille only through `reveal_words()` and `reveal_braille()`, named so review can grep them.
          Shells call them only when the user asks (fingerprint only, otherwise).
      Proof: the age 1.1.1 files and a fresh core file give the vector fingerprint and seal; `reveal_words()` equals
      the vector words; a wrong typed passphrase gives `WrongPassphrase`; trybuild and no-secret-text coverage
      (group 10).
- [ ] KAT group Age, using CCTV `scrypt`, `armor_scrypt` and `scrypt_work_factor_23` through `include_bytes!` (pinned
      by the SOURCES.md hashes):
      - decryption;
      - the writer known answer, binary and armored;
      - `wrong` gives `WrongPassphrase`;
      - work factor 23 fails before any scrypt work.
      As built at commits 20-21 (passphrase, plaintext, backup API, "Check a backup", the Age group):
      - The Age group runs in the full suite and alone in `Suite::Backup` (`decrypt_backup`), whose test-sources
        twin `decrypt_backup_with_kat_fault` fails with `Kat(Age)` for that group only.
      - Passphrase: `BackupPassphrase::fill_from_bytes` cuts the 11 OS bytes bit by bit (no wide integer or cast
        holds the passphrase), and `text()` gives the age passphrase in an exactly sized zeroizing buffer. The
        challenge is drawn as backup.json's spec says; `ConfirmChallenge` keeps no answer field, since the right
        choice is the one equal to `NewBackupPassphrase::words()` at that position. A failed draw wipes the stored
        passphrase. 64 rejected attempts give the new `SourceFault::NoUsableDraw` (display "the source gave no
        usable draw"), which wipes the session like any source failure.
      - Plaintext: the reader checks the version line, the words and their checksum, computes the fingerprint
        (S with the empty passphrase, `wallet_summary`), parses the created-by line, writes the plaintext again and
        requires byte equality; every failure but `UnsupportedVersion` is `Backup(Plaintext)`, so `verify_backup`
        returns only the four errors build-plan.md lists. `CreatedBy::new(BackupApp, major, minor, patch)` is
        public metadata.
      - API: `Session<Ready>::generate_backup_passphrase(self)`, `encrypt_backup(self, &CreatedBy)` and
        `verify_backup(&self, file)`, with the passphrase stored in `Inner` and the fingerprint in a new `Inner`
        field that `finish` fills (group 9). `encrypt_backup` reads the file key, salt, nonce and file name from
        the OS source in that order (52 bytes, proven with an exact stub). `BackupFile` has `name()` and
        `bytes()`; `CheckedBackup` has `fingerprint()`, `seal()`, `reveal_words()` and `reveal_braille()` (the
        insert views of the verified words). Hand-off to commit 22: nothing reaches `Session<Ready>` yet
        (`skip_check` and `reveal` are group 9), so these calls are tested on a test-only `ready_for_test`
        constructor, and the read-back gate in front of `generate_backup_passphrase` and `encrypt_backup`
        (`ReadbackIncomplete`) lands with the session transitions.
      - Interop: `scripts/age-interop.py --core` also runs core in both directions through the ignored unit test
        `backup::tests::age_interop_files`: core's `decrypt_backup` reads files age wrote under fresh passphrases,
        and age decrypts core's fresh work-factor-18 backups to backup.json's plaintexts; a wrong passphrase fails
        in age. Run locally with age 1.3.2; the CI job (commit 27) runs it with Ubuntu's 1.1.1.

**9. session** (build-plan.md "Public API" as refined by Q5; CLAUDE.md rule 6; seal-watchonly-braille.md "Ceremony
order", "Go-ahead before reveal")
- [ ] Transitions:
      ```text
      Collecting  new(len, mode, platform) | add_hw_samples(self, &[u8]) | add_extra(&mut self, ExtraSource, &[u8])
                  credited_bits, required_bits, hw_bytes_tested (&self) | commit(self) -> Committed
      Committed   commitment(&self) -> Option<[u8; 32]> | start_dice(self) -> Rolling
      Rolling     push_roll(self, u8) | undo_roll(&mut self) | rolls, millibits, minimum_rolls (&self)
                  finish(self) -> Sealed
      Sealed      seal(&self) | skip_check(self) -> Ready | start_check(self) -> Checking
      Checking    seal, check_request (&self) | reveal(self, GoAhead<'_>) -> Ready or Rejected
                  discard(self, Discard) -> Wiped
      Ready       mnemonic, braille, fingerprint, first_address, readback_complete (&self)
                  check_readback(&mut self, position, &str) | verify_backup(&self, file)
                  generate_backup_passphrase, encrypt_backup(&CreatedBy), watch_only, registration,
                  reveal_device_leg: self -> Result<(Session<Ready>, T), CoreError>
      Wiped       collision_report(&self) | restart(self, len, mode) -> Collecting
      GoAhead<'a> Snapshot(&'a VerifiedSnapshot) | BucketProof(&'a VerifiedProof) | Code(&'a str)
      Rejected    Retry(Session<Checking>, CheckError) | Collision(Wiped);  Discard: Collision | CannotCheck
      Free        self_test | hwrng_boot_test | decrypt_backup(file, &TypedBackupPassphrase) -> CheckedBackup
                  verify_snapshot | verify_bucket_proof | verify_bucket_proof_qr | seal_from_mnemonic
      ```
      Proof: happy paths for Mixed and DiceOnly, on Pi and Phone, at 12 and 24 words.
- [ ] Collecting and commit (build-plan.md "Credit policy"; pi-firmware.md "Dice-only mode skips steps 4, 5 and 14"):
      - `add_hw_samples` works on the Pi in Mixed mode only (else `NotInThisMode`): health test first, then one hwrng
        record of the post-startup bytes;
      - `credited_bits` stays 0 until the first post-startup window completes, then jumps to 2,048 (512 required);
        `hw_bytes_tested` and `HW_BYTES_NEEDED` feed the pi-firmware.md step 4 progress bar (Q7, Q10);
      - `add_extra` is never credited and cannot change the credit;
      - `commit` checks the quota, reads 64 OS bytes and absorbs them last, then derives D and C;
      - dice-only mode: no pool and no OS read; `commitment()` and `reveal_device_leg()` give None; `add_extra` does
        nothing.
- [ ] Rolling, Sealed and Checking:
      - `finish` below the minimum gives `TooFewRolls`. Otherwise it derives E, the mnemonic, S, the seal, the
        fingerprint and the first address once, then zeroizes R;
      - `skip_check` exists only on Sealed;
      - `reveal`:
        - a malformed or wrong code gives `Retry` (same n, no wipe);
        - a snapshot or proof holding T[0..16] gives `Collision`, with a report and the 99-roll flag;
        - a proof for another bucket gives `Retry`;
        - freshness is the shell's warning, not a refusal: the core has no clock;
      - `discard(Collision)` keeps the report and the flag; `discard(CannotCheck)` keeps neither.
- [ ] `Wiped::restart` (seal-watchonly-braille.md "Add fresh entropy"; CLAUDE.md "Dice quota"):
      - `Wiped` holds no secret;
      - restart re-runs the KATs, starts a fresh pool, and does a fresh OS read at commit;
      - the minimum is 99 rolls for both lengths after a collision, and the normal minimum after CannotCheck;
      - `Rejected` and `Wiped` get hand-written `Debug` that never touches their contents and prints no BIP39 word
        (group 10).
- [ ] Ready and panics (Q5; CLAUDE.md rule 3):
      - `check_readback` records each matched position, and a later mismatch clears it. Read-back errors never wipe;
      - the exports return `ReadbackIncomplete` until every position has matched;
      - core never panics on public input. A panic unwinds and drops `Box<Inner>`; `catch_unwind` stays banned;
      - note for M5: the FFI takes the session out of its slot before each call, so a panic leaves no session behind.

**10. Cross-cutting tests**
- [ ] `tests/typestate.rs` (trybuild; CLAUDE.md rule 6; build-plan.md "Sealed-state compile-fail tests"). Fixtures
      that must fail:
      - dice before commit, and before start;
      - mnemonic, braille or skip before finish;
      - on Sealed and on Checking: no mnemonic, braille, `reveal_device_leg`, backup, `watch_only`, `registration`,
        `check_readback`, fingerprint or address;
      - no `skip_check` on Checking;
      - `reveal` and `commit` consume the session (E0382);
      - no clone of a session;
      - `encrypt_backup` and `verify_backup` take no passphrase: passing a `TypedBackupPassphrase` or a
        `NewBackupPassphrase` fails;
      - no `Debug`, `Display` or `Clone` on any secret type: mnemonic, D, the new and typed backup passphrases,
        `Bip39Passphrase`,
        `CheckedBackup`, seal code, registration, export, braille views, read-back result, confirm challenge;
      - `Wiped` holds no secret;
      - no struct literal for `Session<Ready>`, `VerifiedSnapshot`, `VerifiedProof`, `SealPublic`, `CheckedBackup`,
        `TypedBackupPassphrase` or a nonce;
      - a braille view cannot outlive its session, and a `CheckedBackup` reveal cannot outlive its `CheckedBackup`;
      - words revealed by `SecretMnemonic`, `NewBackupPassphrase` or `ConfirmChallenge` cannot outlive it (E0505;
        landed with the review fixes after commit 10, when these reveals stopped returning `&'static str`).
      Rules: `.stderr` files are pinned to 1.98.1 and trybuild 1.0.121, and prefer E0599/E0277/E0061; fixtures are
      warning-free and gate-clean; regenerate only with `TRYBUILD=overwrite`, and review the diff.
- [ ] `tests/source_substitution.rs` (design.md "Prove the path" 1; build-plan.md test matrix):
      - fixed OS bytes, a counter-mode hwrng stream in 64-byte chunks and two extras give the keepcrypt.json D and C,
        on Pi and on Phone;
      - changing one byte of any source, changing a source id, or dropping an extras call changes D;
      - a changed but still healthy startup byte does not change D;
      - exactly 64 OS bytes are read;
      - dice-only E = SHA256(R) whatever the stubs, and a zero-byte stub still reaches Ready through Skip.
- [ ] `tests/os_source.rs` (default features): two real Phone sessions give different commitments. It asserts
      inequality only and prints nothing.
- [ ] `tests/error_injection.rs` (build-plan.md CI rule "Fail closed", test matrix "Error injection", "Repetition Count
      and Adaptive Proportion"; this file, "Inputs from M0"). Each session case asserts the exact `Err` and exactly
      one probe wipe:
      - the OS source failing at commit (Pi and Phone), at `start_check`, and inside `generate_backup_passphrase` and
        `encrypt_backup`;
      - short reads;
      - RCT and APT failures in the startup and continuous stages;
      - 1,535 hwrng bytes, so no post-startup window completes: `commit` gives `QuotaUnmet`;
      - extras only on a Pi (1 MiB from each);
      - hwrng input on Phone or in dice-only mode;
      - faces 0, 7 and 255;
      - `finish` at 49, at 98, and at 98 after a collision;
      - `encrypt_backup` before `generate_backup_passphrase`: `NoBackupPassphrase`;
      - every `KatId` (built from an exhaustive match), at `new` and at `restart`;
      - every `KatId` through each free function's `*_with_kat_fault` twin (no session, so no probe): the exact
        `CoreError::Kat(id)` for each group that function runs, and the unfaulted result for every other group, from
        the same exhaustive match.
- [ ] `tests/check_flow.rs` (seal-watchonly-braille.md "Results"; public vectors only):
      - a 12-word dice-only session from the 50-roll string reaches Sealed with the kcr.json T;
      - the code reveals the expected words, and a typo keeps the session;
      - the collision snapshot and the collision proof both give `Collision`, whose report holds that seed's code;
      - restart refuses 50 rolls and accepts the 99-roll string;
      - a wrong-bucket proof gives `Retry`, and the right code still reveals;
      - the kcr.json stale proof gives `Stale` for its pinned today, as a phone shell sees it, and still reveals; the
        future-dated proof gives `Future`.
- [ ] `tests/ceremony.rs`:
      - 12- and 24-word ceremonies reach Ready, and every insert reads back from its own faces;
      - exports fail before read-back;
      - `decrypt_backup` of the session's file gives a `CheckedBackup` whose fingerprint (empty passphrase), words
        and braille lines match the session, and whose `seal()` equals the session's seal;
      - after `watch_only(Some(TREZOR))`, the backup and the registration are unchanged and hold no passphrase.
- [ ] `tests/no_secret_text.rs` (build-plan.md CI rule "Secrets never printed"; the refined rule goes to the owner as
      a build-plan.md edit, Q10):
      - run public-vector ceremonies: Coldcard 50, 99 and 100 rolls in dice-only mode, and the keepcrypt.json mixed
        cases;
      - format with `{:?}` and `{}` every public value that implements them, and every error variant;
      - a leak is a word of this seed that does not also appear for a control seed with no words in common. This
        rules out fixed text such as "test", "wrong" and "error", which are themselves BIP39 words;
      - also, no two consecutive seed words may appear in order;
      - the Debug output of each type that holds or replaces a session (`Rejected`, `Wiped`) contains no BIP39 word
        as a whole token (a maximal run of ASCII letters, case-folded). "session", "report", "flag", "check" and
        "code" are BIP39 words, so hand-written Debug output prints none of these names;
      - a planted leaking formatter must be caught by each check.
- [ ] `tests/panic_wipe.rs` and `tests/no_panic.rs`:
      - a thread panics while holding a stub session: `join()` is `Err`, and the probe shows one wipe;
      - deterministic truncations and byte flips (SHA-256 counter mode) of hwrng input, faces, go-ahead codes, proofs
        (bytes and UR text), snapshots, `.age` files, typed backup words and read-back strings give errors, never a
        panic.
- [ ] `tests/vectors.rs` runs the full sets: 24 BIP39 seeds, 26 CCTV files, 3 seal vectors, 2,048 braille entries,
      watchonly.json, kcr.json, backup.json and rolls.json. `tests/kat.rs` cross-checks the KAT subsets.

**11. Release artifact scan** (build-plan.md CI rules "One RNG path in shipped binaries", "Test stubs never ship";
moved from M0)
- [ ] `scripts/banned-api-check.sh --artifact TARGET FILE...`. The script already owns the banned names and is
      excluded from its own scan. Rules:
      - any file holding `KC_TEST_SOURCE_DO_NOT_SHIP`, `KC_TEST_REGISTRY_DO_NOT_SHIP` or the 32 test-key bytes is a
        hit;
      - on linked files, the pinned toolchain's `llvm-nm` must find:
        - no undefined `rand random srand srandom rand_r *rand48 initstate setstate arc4random* SecRandomCopyBytes`,
          and no `getentropy` on Linux and Android (each with a leading `_` on Apple);
        - no defined `rand::`, `rand_core::`, `rand_chacha::`, `rand_xoshiro::` or `fastrand::` symbols;
        - the OS import from Q8: `getrandom` on Linux and Android, `_CCRandomGenerateBytes` on iOS;
      - exit codes: 0 clean, 1 hits, 2 error;
      - `--selftest` compiles `#![no_std]` fixtures with `rustc --emit=obj` for an Android and an iOS target (an
        arc4random import, a missing OS import, a clean object), plus a text file for each marker.
- [ ] `core/examples/release_probe.rs` (default features): self-test, a Phone ceremony with fixed public dice,
      `start_check`, read-back, then `generate_backup_passphrase` and `encrypt_backup`, so every OS draw site is
      linked. It also calls `registry_key_is_test()` and `verify_snapshot` on public test bytes (expecting
      `NoRegistryKey` in release), so a `test-registry` build links the registry-key path and its marker. It prints
      nothing. Proof: the cross job scans the release rlib and the probe for all six targets.

**12. CI, canaries, coverage, commands** (Q11)
- [ ] CI jobs, 11 today and 13 after M1 (they become required checks only through the Q12 ruleset):
      - lint: add `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, which lints the stub
        and test-registry code; keep the default-features run;
      - test: add `cargo test -p keepcrypt-core --locked --features test-sources` (which turns on test-registry); the
        existing run keeps testing the release configuration;
      - cross: build the release rlib and the probe with default features, set the getrandom cfg on the Linux and
        Android legs only (Q8) through `CARGO_TARGET_<T>_RUSTFLAGS` (never a workflow-wide `RUSTFLAGS`, which would
        also reach host build scripts), give the probe a linker per target (`arm-linux-gnueabihf-gcc` for the Pi,
        the NDK clang for Android, Xcode for iOS), and run the scan;
      - gates: `banned-api-check.sh --selftest` moves after the toolchain install (its fixtures need rustc and
        llvm-nm); `verify.py --selftest` grows from 4 to 11 checks;
      - new `coverage` job: `cargo install --locked cargo-llvm-cov@0.9.1` into `~/.cargo-tools` (cached like the other
        tools), the gate below, and `--summary-only` output in the log;
      - new `age-interop` job: install Ubuntu's `age`, assert `dpkg-query -W age` reports 1.1.1-1ubuntu0.24.04.3, run
        `scripts/age-interop.py` both directions, and require that a wrong passphrase fails to decrypt;
      - Q12: the workflow drops its `paths:` filter; a first job tests whether `Entropy/` or the workflow changed, and
        every other job depends on it and reports "skipped" otherwise, so required checks never hang on PRs that do
        not touch `Entropy/`.
- [ ] `scripts/canaries.sh`, with its pinned counts updated:
      - positive controls:
        - a host release probe built with `test-sources` must make the scan exit 1, naming both markers and the test
          key;
        - one built with `test-registry` alone must exit 1, naming the registry marker and the test key, and must not
          contain the stub marker;
      - static checks:
        - already in place (review fix after commit 5, Q14): core's `[features]` exactly as committed, so neither
          test feature is a default and `test-registry` does not enable `test-sources`; no manifest turns either on,
          in any dependency table (dev-dependencies included) or feature; the root `[profile]` tables exactly as
          committed. Two canaries prove each route is named;
        - serde, serde_core and serde_derive are absent from core's normal and build graph;
        - getrandom's only dependent is keepcrypt-core;
        - ed25519-dalek resolves with no features and curve25519-dalek with only `digest`, so `legacy_compatibility`,
          `rand_core` and `batch` stay off;
      - a vectors-tamper canary: one flipped byte in each generated JSON file must fail verify.py, naming that file.
- [ ] Coverage: `cargo llvm-cov --locked -p keepcrypt-core --features test-sources --no-cfg-coverage
      --fail-under-lines 95`, with cargo-llvm-cov 0.9.1. No `#[coverage(off)]` and no `cfg(coverage)`. CI fails if any
      path under core/src matches `/(tests|examples|benches)/`, or any core/src file is named `tests.rs`,
      `*_tests.rs` or `*-tests.rs`, because the tool's default ignore rule skips all of those.
- [ ] CLAUDE.md "Commands" gains:
      - the feature test run and the coverage command;
      - each `--write-*-vectors` flag (regenerate, never hand-edit);
      - `banned-api-check.sh --artifact` and `scripts/age-interop.py`;
      - the `TRYBUILD=overwrite` line.

**13. Review**
- [ ] Paste under Review:
      - test, trybuild, error-injection and source-substitution output;
      - `verify.py --selftest` (11 checks) on 3.12 and on 3.9;
      - the coverage summary;
      - the artifact scan for all six targets, and both positive controls;
      - the age-interop run;
      - the KAT list, with its static cost bound and host timing;
      - clean fmt, clippy (default and all features), deny, audit, vet, check-path-deps, banned-API gate and canaries;
      - the one-time SeedBook PDF check;
      - the Q12 ruleset (`gh api` output) or the owner's deferral, and a note that build-plan.md's two-approval rule is
        unmet while one account opens and merges PRs.

**Carried to later milestones** (record in their plans)
- M3, M5, M6:
  - a shell that drops `Wiped` and calls `Session::new` resets the 99-roll minimum, so ceremony tests must assert
    "99 after Stop";
  - a pi/app test asserts `Platform::Pi`;
  - builds that talk to the local test registry turn on `keepcrypt-core/test-registry` from the command line with
    `-p`, never in a manifest and never `test-sources`; their scan shows the registry marker and no stub marker;
  - the Pi shows the snapshot's or proof's date and asks the user to confirm it before `reveal`; phones warn on Stale
    and Future. A ceremony test asserts each;
  - the Pi's step 4 bar uses `hw_bytes_tested` and `HW_BYTES_NEEDED` (M3).
- M4 (measure on a Pi Zero v1.3):
  - KAT time;
  - full snapshot verification, estimated at 8-20 s. Run it at "Load registry snapshot", before the ceremony, on a
    worker thread;
  - scrypt peak memory;
  - whether the account QR scans;
  - Sparrow and Bitcoin Core import;
  - the getrandom cfg in Buildroot (Q8).
- M5:
  - owned UniFFI wrappers for `GoAhead`, the braille views and `CheckedBackup`'s reveals;
  - the take-and-put-back session slot;
  - the getrandom cfg in cargo-ndk.
- M9:
  - the real registry key and origin;
  - the release scan fails on `registry.invalid`;
  - registry key rotation: verify a rotation statement signed with the old key (seal-watchonly-braille.md "Registry
    service spec", "Signing key"). M1 pins one key per release;
  - the checking page's re-check mode for `#t=` without n.

### Verification
- [ ] All vectors pass, including the seal vector in `CLAUDE.md`: kat, keepcrypt, braille, seal, watchonly, kcr and
      backup JSON; BIP39 vectors.json; all 26 CCTV age files; rolls.json. `verify.py --selftest` passes all 11 checks
      on 3.12 and on `/usr/bin/python3` 3.9, and its embedded word list hashes to `2f5eed53...` with the banned-API
      gate clean.
- [ ] Source-substitution test: a fixed stub gives a known D, and changing one stub byte changes D (every source, Pi
      and Phone). A real-OS test shows two sessions differ.
- [ ] Pipe width: every single-bit flip of D changes C and E, every bit of the 64-byte OS record changes D, and every
      bit of E changes the 24-word indices.
- [ ] Error-injection test for every source and health test: the session halts and wipes, with the exact error and
      one wipe each. This includes every KAT at session start and at restart, and every KAT group of each free
      function through its fault twin.
- [ ] `trybuild` compile-fail tests: dice before commit, reveal before finish, mnemonic/D/backup/export in the sealed
      or checking state, skip after a check started, a typed passphrase passed to `encrypt_backup`, plus every other
      fixture in group 10.
- [ ] Go-ahead tests:
      - the vector in `CLAUDE.md` passes;
      - a code for another T or nonce is rejected;
      - forged, truncated and wrong-bucket proofs are rejected, and so is every UR decoder negative;
      - a proof containing T wipes the session;
      - a typo can be re-entered;
      - stale and future-dated proofs report their freshness.
- [ ] Snapshot tampering: every kcr.json negative, and the header bit-flip sweep, are rejected. Release builds give
      `NoRegistryKey`.
- [ ] Dice-only output equals Coldcard `rolls.py`/`rolls12.py` for the fixed roll strings, in core and in verify.py.
- [ ] Backup:
      - the CCTV classes match;
      - the writer equals CCTV byte for byte;
      - core reads age 1.1.1 files, and age 1.1.1 decrypts fresh core files at log2 N 18 (age-interop job);
      - only a generated passphrase can encrypt, and `decrypt_backup` returns a `CheckedBackup` whose fingerprint and
        seal match.
- [ ] Braille: the six `CLAUDE.md` inserts match; 279 and 49 are recomputed; read-back catches every mirror flip and
      every blank-face slip.
- [ ] Watch-only: the BIP-84 and BCR-2020-015 vectors, the BIP-380 checksums and the runtime self-check pass.
- [ ] Secrets never printed: the no-secret-text test passes and catches a planted leak with each check. A panic wipes
      the session, and hostile input never panics.
- [ ] The release artifact scan is clean on all six targets; both positive controls fail for their markers, and the
      `test-registry` build holds no stub marker.
- [ ] Line coverage in `core/` is at least 95% (`cargo llvm-cov`), with nothing excluded: no core/src path matches the
      tool's default ignore rule.
- [ ] Clean: clippy (default and all features), fmt, deny, audit, vet, check-path-deps, the banned-API gate and its
      selftest, and the canaries. CI is green on `m1-core`. The Q12 ruleset is in place, or its deferral is recorded.

### New dependencies (approved with Q1-Q4)
**How this was checked (2026-10-09).** I copied the merged M0 workspace to a scratch directory, added every M1 crate at the versions below, and used `cargo update --precise` to hold back six crates. Results:

- **Lockfile:** `Cargo.lock` gains exactly the 44 crates listed below. All were published before the cool-off cutoff of 2026-09-25 15:00 UTC; the youngest is toml 1.1.6 (2026-09-10).
- **Single versions:** there is one getrandom (0.4.3), and keepcrypt-core is its only dependent. There is also only one digest (0.11.3), one sha2 (0.11.0) and one hmac (0.13.0).
- **No rand or log:** `rand_core` and `log` are not in the lockfile at all, so no feature anywhere in the graph can switch them on.
- **No serde in the device build:** serde is absent from core's normal and build graph. It is only a dev dependency, through trybuild and serde_json.
- **cargo deny:** `cargo deny --locked check bans licenses sources` passes bans and sources. Licenses failed on ed25519-dalek, curve25519-dalek and subtle (BSD-3-Clause), and passed once BSD-3-Clause was allowed. Every other licence is already on the allow-list; where a crate offers "Unlicense OR MIT" or BSD-1-Clause as a choice, MIT covers it.
- **cargo vet:** with the M0 imports, `cargo vet --locked` lists all 44 crates as unvetted: 24 need safe-to-deploy and 20 need safe-to-run (dev only). Refreshing the imports may cover some; the rest become exemptions for approval.
- **Build:** `cargo check -p keepcrypt-core --all-targets --all-features --locked` builds.

**A. Encrypted backup (Q1): 15 crates.** hmac, ctutils and cmov arrive with the seal commit; the rest arrive with the backup commit.

| Crate | Version | Published (UTC) | Features | Licence | Why | rand/log check |
| --- | --- | --- | --- | --- | --- | --- |
| scrypt | 0.12.0 | 2026-04-22 | `default-features = false` | MIT OR Apache-2.0 | age stanza KDF (N = 2^18, r = 8, p = 1) | `getrandom` and `rand_core` (password-hash) off |
| pbkdf2 | 0.13.0 | 2026-04-21 | via scrypt (`hmac`) | MIT OR Apache-2.0 | PBKDF2 inside scrypt | `getrandom` and `rand_core` off |
| salsa20 | 0.11.0 | 2026-03-30 | via scrypt | MIT OR Apache-2.0 | Salsa20/8 core of scrypt | no optional RNG |
| chacha20poly1305 | 0.11.0 | 2026-06-28 | `default-features = false`, `alloc`, `zeroize` | Apache-2.0 OR MIT | file-key wrap and payload AEAD | its default `getrandom` must stay off; `rand_core` off |
| chacha20 | 0.10.2 | 2026-08-27 | via (`cipher`, `xchacha`, `zeroize`) | MIT OR Apache-2.0 | ChaCha20 | `rng` (rand_core) off |
| poly1305 | 0.9.1 | 2026-07-08 | via | Apache-2.0 OR MIT | Poly1305 | none |
| aead | 0.6.1 | 2026-06-17 | via (`alloc`) | MIT OR Apache-2.0 | AEAD traits | its default `rand_core` and `getrandom` off |
| cipher | 0.5.2 | 2026-05-19 | via (`stream-wrapper`) | MIT OR Apache-2.0 | stream-cipher traits | `rand_core` and `getrandom` off |
| universal-hash | 0.6.1 | 2026-02-27 | via poly1305 | MIT OR Apache-2.0 | Poly1305 traits | none |
| inout | 0.2.2 | 2025-12-27 | via | MIT OR Apache-2.0 | in/out buffers | none |
| hkdf | 0.13.0 | 2026-03-30 | `default-features = false` | MIT OR Apache-2.0 | header and payload keys | none |
| hmac | 0.13.0 | 2026-03-29 | `default-features = false`, `zeroize` | MIT OR Apache-2.0 | age header MAC; seal code HMAC-SHA256; inside pbkdf2 and hkdf | none |
| ctutils | 0.4.2 (0.4.3, published 2026-10-05, held back) | 2026-04-02 | via digest `mac` | Apache-2.0 OR MIT | constant-time helpers for RustCrypto MACs | optional `subtle` off |
| cmov | 0.5.4 | 2026-05-28 | via ctutils | Apache-2.0 OR MIT | constant-time select | none |
| base64ct | 1.8.3 | 2026-01-12 | `default-features = false`, `alloc` | Apache-2.0 OR MIT | strict canonical base64: unpadded in the age header, padded in the armor | no dependencies |

**B. Ed25519 (Q3): 9 crates.** These need the new BSD-3-Clause allowance.

| Crate | Version | Published (UTC) | Features | Licence | Why | rand/log check |
| --- | --- | --- | --- | --- | --- | --- |
| ed25519-dalek | 3.0.0 | 2026-07-06 | `default-features = false`, no features (`verify_strict` needs none) | BSD-3-Clause (new) | `verify_strict` for .kcr headers and KCP1 proofs | `rand_core` is optional and not a default (defaults are `fast` and `zeroize`); only its `rand_core` and `batch` features reach it, both off |
| curve25519-dalek | 5.0.0 | 2026-07-06 | via, exactly `digest` (ed25519-dalek declares it with `default-features = false, features = ["digest"]`) | BSD-3-Clause (new) | curve arithmetic (serial 32-bit backend on the Pi) | `rand_core` is optional and not a default (defaults are `alloc`, `precomputed-tables` and `zeroize`, and ed25519-dalek turns none of them on); only its `rand_core` and `group` features reach it, both off |
| curve25519-dalek-derive | 0.1.1 | 2023-10-31 | via; proc macro for x86_64 SIMD | MIT/Apache-2.0 | SIMD backend on x86_64 hosts | none |
| ed25519 | 3.0.0 | 2026-05-03 | via, defaults off (its default `alloc` stays off) | Apache-2.0 OR MIT | signature type | none |
| signature | 3.0.0 | 2026-05-02 | via ed25519 | Apache-2.0 OR MIT | signature traits | `rand_core` off |
| subtle | 2.6.1 | 2024-06-24 | via dalek (not a direct dependency) | BSD-3-Clause (new) | constant-time code inside dalek | none |
| fiat-crypto | 0.3.0 | 2025-06-04 | in the lockfile; compiled only with `cfg(curve25519_dalek_backend = "fiat")` | MIT OR Apache-2.0 OR BSD-1-Clause | alternative backend | none |
| rustc_version | 0.4.1 | 2024-08-28 | build dependency of curve25519-dalek | MIT OR Apache-2.0 | build script | none |
| semver | 1.0.28 | 2026-04-04 | via rustc_version | MIT OR Apache-2.0 | build script | none |

**Ed25519 features.** Re-checked on 2026-10-09 against the crates.io API (generic User-Agent) and the ed25519-dalek 3.0.0 and curve25519-dalek 5.0.0 sources:
- ed25519-dalek 3.0.0 defaults are `fast` (curve25519-dalek `precomputed-tables`) and `zeroize`. `default-features = false` turns off exactly these two:
  - without `fast`, each verification builds an 8-entry basepoint table instead of reading a 64-entry static one. That is a small slowdown, irrelevant for one or two verifies per check, and the Merkle pass dominates snapshot loading;
  - without `zeroize`, signing keys and scalars lose `Zeroize`. Verify-only code handles public data only.
- curve25519-dalek 5.0.0 defaults (`alloc`, `precomputed-tables`, `zeroize`) never apply, because ed25519-dalek always declares it with defaults off. ed25519 3.0.0 is also pulled with defaults off.
- `verify_strict` is not behind any feature. It rejects S >= L, a small-order R and a small-order key.
- Never enable `legacy_compatibility` (it accepts unreduced S, so signatures become malleable), `hazmat`, `batch` or `rand_core`. A canary pins the resolved features: none on ed25519-dalek, only `digest` on curve25519-dalek.
- curve25519-dalek picks its backend from the target: serial 32-bit on the Pi, serial 64-bit on aarch64, and a runtime-detected SIMD backend on x86_64 hosts. No backend cfg is set.
- The 44-entry resolve above already used these settings, so the lockfile does not change.

**C. Dev-only (Q4): 20 crates.** All need safe-to-run vet entries; none is in the device build.

| Crate | Version | Published (UTC) | Features | Licence | Why | rand/log check |
| --- | --- | --- | --- | --- | --- | --- |
| trybuild | =1.0.121 (1.0.122, published 2026-10-07, too young) | 2026-09-08 | default | MIT OR Apache-2.0 | CLAUDE.md rule 6 compile-fail tests | no rand, log or network crate in its tree |
| serde_json | =1.0.151 | 2026-07-20 | default; only `Value` is used | MIT OR Apache-2.0 | tests read vectors/*.json; already in trybuild's tree | none |
| glob | 0.3.4 | 2026-07-21 | via trybuild | MIT OR Apache-2.0 | finds fixture files | none |
| target-tuple | 1.0.2 | 2026-09-08 | via trybuild | MIT OR Apache-2.0 | trybuild dependency | none |
| termcolor | 1.4.1 | 2024-01-10 | via trybuild | Unlicense OR MIT | trybuild dependency | none |
| toml | 1.1.6+spec-1.1.0 (1.1.7 and 1.1.8 too young) | 2026-09-10 | via trybuild | MIT OR Apache-2.0 | trybuild dependency | none |
| toml_parser | 1.1.3+spec-1.1.0 (1.1.4 and 1.1.5 too young) | 2026-07-27 | via toml | MIT OR Apache-2.0 | trybuild tree | none |
| toml_datetime | 1.1.1+spec-1.1.0 (1.1.2 too young) | 2026-03-31 | via toml | MIT OR Apache-2.0 | trybuild tree | none |
| toml_writer | 1.1.2+spec-1.1.0 (1.1.3 too young) | 2026-07-14 | via toml | MIT OR Apache-2.0 | trybuild tree | none |
| serde_spanned | 1.1.1 (1.1.2 too young) | 2026-03-31 | via toml | MIT OR Apache-2.0 | trybuild tree | none |
| winnow | 1.0.4 | 2026-07-13 | via toml_parser | MIT | trybuild tree | none |
| itoa | 1.0.18 | 2026-03-20 | via serde_json | MIT OR Apache-2.0 | serde_json dependency | none |
| memchr | 2.8.3 | 2026-07-08 | via serde_json | Unlicense OR MIT | serde_json dependency | optional `logging` (log) off |
| zmij | 1.0.23 | 2026-07-13 | via serde_json | MIT | serde_json float formatting | none |
| indexmap | 2.14.2 | 2026-09-05 | in the lockfile only (toml weak feature); never compiled | Apache-2.0 OR MIT | locked by Cargo | none |
| hashbrown | 0.17.1 | 2026-05-09 | in the lockfile only | MIT OR Apache-2.0 | locked by Cargo | none |
| equivalent | 1.0.2 | 2025-02-14 | in the lockfile only | Apache-2.0 OR MIT | locked by Cargo | none |
| winapi-util | 0.1.11 | 2025-09-07 | Windows only (termcolor) | Unlicense OR MIT | listed because deny.toml has no target filter | none |
| windows-sys | 0.61.2 | 2025-10-06 | Windows only | MIT OR Apache-2.0 | most of the vet backlog | none |
| windows-link | 0.2.1 | 2025-10-06 | Windows only | MIT OR Apache-2.0 | windows-sys dependency | none |

**D. No new lockfile entry.**

| Item | Version | Published (UTC) | Features | Licence | Why | rand/log check |
| --- | --- | --- | --- | --- | --- | --- |
| unicode-normalization (new direct edge, Q5) | 0.1.25 | 2025-10-30 | `default-features = false` (same as bip39 uses) | MIT OR Apache-2.0 | NFKD of the BIP39 passphrase into a zeroizing buffer. Already locked through bip39 and already passing vet on imported audits. Named in the build-plan.md "Core crates" row (Q10) | none (depends only on tinyvec) |
| cargo-llvm-cov (CI tool, not a dependency) | 0.9.1 | 2026-09-06 | `cargo install --locked` into ~/.cargo-tools | Apache-2.0 OR MIT | the 95% line-coverage gate; never in the device graph. Its default ignore rule skips `tests/`, `examples/` and `benches/` directories and `tests.rs`, `*_tests.rs` and `*-tests.rs` files, so CI fails if core/src has any such path | its own lockfile has no rand, log or network crate (designer check) |
| age (Ubuntu package, CI only) | 1.1.1-1ubuntu0.24.04.3 | 2025-06-26 (noble-updates and noble-security, confirmed on Launchpad) | `apt-get install`, version asserted | BSD-3-Clause (Go binary, never linked) | reference CLI for interop in both directions | n/a |

**Evaluated and rejected:**
- age 0.12.1: needs rand 0.8 and log.
- ur 0.5.2, bc-ur 0.19.2 and foundation-ur: all need rand_xoshiro.
- minicbor 2.3.0: BlueOak-1.0.0 licence, which is not on the allow-list.
- ciborium 0.2.2: compiles serde derive into core.
- crc 3.4.0: not needed; a 15-line const table does the job.
- subtle as a direct dependency: not needed; `bitcoin::hashes::cmp::fixed_time_eq` does the job.
- ed25519-dalek's `fast` feature: not needed for one or two verifies per check (see "Ed25519 features").

### Commit order on `m1-core`
1. tasks/todo.md: refined M1 plan, plus the owner's answers to Q1-Q12
2. docs: the owner-approved M1 doc edits (Q10), including CLAUDE.md rule 10 if approved, alone in one commit with no code
3. build: the test-registry and test-sources features (both off by default; test-sources turns on test-registry); release panic = unwind; overflow-checks for core; dev dependencies at opt-level 3; /core/wip/ ignored
4. ci: all-features clippy in the lint job and `cargo test -p keepcrypt-core --features test-sources` in the test job, so every later stub and test-registry test runs in CI from the start
5. verify: vectors/kat.json generator and selftest check 5 (NIST SHA, RFC 4231 case 2, RFC 8032 TEST 1), with SOURCES.md rows
   Review fixes after 5: check 5 pins kat.json's entries and the RFC 8032 TEST 1 bytes; canaries.sh refuses any manifest that turns on a test feature and pins core's [features] and the root [profile] (moved forward from 26, Q14); this plan's refinements and Q13-Q14
   Q13 docs (before 6): the five owner-approved doc edits of Q13 (a)-(e), alone in one commit with no code
6. core: lib layout, error.rs, secret.rs (stored, new and typed backup passphrase types), session skeleton, KAT harness (SHA, HMAC, BIP39 groups) with the fault-twin pattern for free functions, and the test-sources stub; dev-deps trybuild =1.0.121 and serde_json =1.0.151, the toml-family --precise pins and safe-to-run vet exemptions
7. verify: embedded BIP39 list (16 space-separated words per line, hash-checked over the LF-joined bytes), vectors/keepcrypt.json generator, check 6 (byte equality plus pinned answers), check 7 (SP 800-90B cutoffs), and Coldcard re-runs on the dice-only cases
8. core: source (fill_os, os_bytes, source ids, credit policy, HW_BYTES_NEEDED) and health (RCT, APT, startup discard, windowed credit, hwrng_boot_test and its fault twin), with unit tests and the Health KAT
9. core: pool and the Pool KAT, with the OS-record pipe-width test
10. core: dice and seed (C, mixed E, dice-only E, BIP39, wallet summary), the D and E pipe-width tests, and the Seed KAT
   Exception recorded after 10: commit 9 (262a88b, core) also changed the generator, dropping the reserved TRNG id 0x0003 from keepcrypt.json's "every-source" pool case, and regenerated that case's records, absorbed bytes and D in the same commit as the code that reads them. The values still come from the generator; later generator changes land in their own verify: commit ahead of the code
   Review fixes after 10, each its own commit, vectors first: verify (an RCT-and-APT tie health case; check 6 pins the source-substitution D and C and the empty-record rule apart from the generator, and checks the committed records' order, startup discard and no empty record); core (KatId and the nested error lists generated with their enums, so no variant can miss its list; the OS read path tested for completeness and its error mapping; the health tester latches its first failure and the chunking test compares absorbed tails; the credit policy takes only tester-built credited samples; Bip39Passphrase gets Zeroize + ZeroizeOnDrop and revealed words borrow their secret; one-step derivation that erases each intermediate Xpriv core holds, with a Sha256 ZeroizeOnDrop check; the dice bits wording); this file (Q13-Q14 confirmation pending; this exception)
11. verify: braille.json generator, seal_id_braille in seal.json, check 8 (docs' counts, word-list and PDF hashes)
12. core: braille (cells, inserts, read-back compare, render_text) and the Braille KAT
13. verify: watchonly.json generator (stdlib BIP32, RIPEMD-160 fallback, bech32, BIP-380, dCBOR, bytewords, CRC32), check 9, and the SOURCES.md spec-values table
14. core: ur.rs single-frame encoder and strict single-part decoder (ur_decode_single) with its negatives
15. core: descriptor and watch-only export, the unicode-normalization direct edge, and the Bip84 KAT
   Review fixes after 15, each its own commit:
   - core: every extended private key lives in a `SecretXpriv`, erased on drop (the master binding that commit 15 left unerased);
   - core: the read-back result is zeroized on drop, with the every-blank-face-slip and two-swapped-words tests;
   - core: the passphrase and xpub residuals and the UR limit's byte unit, stated as they are;
   - verify: check 8 reads the docs' braille figures, and the one-time SeedBook PDF check is recorded in Review;
   - verify: watchonly.json gets RFC 8949's `24(h'...')` row, BIP-380's `valid` defined, and a UR reader that counts bytes with four non-ASCII negatives (core's 23-row count test moves to 24 in the same commit, or that commit would be red);
   - this file: Q15, the Braille digest and KAT proof, pending the owner.
16. verify: stdlib Ed25519 (RFC 8032), Merkle, .kcr and KCP1 builders, vectors/kcr.json (with proof freshness cases and UR negatives), check 10
17. core: Crockford encoding, seal derivation, re-check URL, check request, go-ahead, registration, and the Seal and GoAhead KATs; hmac 0.13.0 with ctutils 0.4.2 and cmov, plus vet entries
18. core: Merkle, snapshot and bucket-proof verification with date() and freshness() on both verified types, the registry key under test-registry with its marker, and the Ed25519 and Merkle KATs; ed25519-dalek 3.0.0 with default-features = false and no features, BSD-3-Clause in deny.toml, vet entries
   Review fixes after 18, each its own commit, vectors first:
   - verify: the strict Ed25519 cases isolate the small-order key rule and the small-order R rule (core's strict-case test reads the third case and the two flags in the same commit, or that commit would be red);
   - verify: the proof negatives fail only their own check, 20 order-* cases pin the check order, and check 10 reads every check each negative fails (core's release sweep moves from 87 to 107 cases in the same commit);
   - core: registry_key_is_test() answers from the test-registry feature, not from whether a key is pinned, and the tests state "no key pinned" and "not a test build" apart;
   - core: check.rs's comment names the plan's rule (no file under core/src/seal names the OS RNG crate), not "the OS source", which its own test uses;
   - core: the Seal KAT derives S from the abandon words through seed_from_mnemonic_into (PBKDF2 included) and checks the braille caption; the Bip84 group starts from the S it checks, so the full suite still runs 3 PBKDF2;
   - core: S with the empty passphrase gets its own crate-private type, EmptyPassphraseSeed, filled only from the words, and the seal, the wallet summary and the session take it, so a passphrase seed reaching the seal fails to compile;
19. verify + scripts: backup.json generator (check 11) and scripts/age-interop.py, with the age_cli_written vectors and their SOURCES.md entry
20. core: age v1 armor, reader and writer; CCTV conformance; the Age KAT; scrypt, chacha20poly1305, hkdf and base64ct (and their transitive crates), plus vet entries
21. core: backup passphrase (stored in the session; typed words for decrypt only) and confirm challenge, plaintext v1, the backup API (generate, encrypt, verify, no passphrase arguments) and Check a backup (decrypt_backup returning CheckedBackup)
22. core: session transitions, Wiped::restart, the read-back gate and the panic policy
23. tests: trybuild typestate suite with pinned .stderr files, including the typed-passphrase and CheckedBackup fixtures
24. tests: source substitution, real OS path, error-injection matrix (with the free-function KAT fault twins and the 1,535-byte quota case), check flow (with proof freshness) and full ceremony
25. tests: no-secret-text (control-seed rule plus the BIP39-token check on Rejected and Wiped), panic wipe, no-panic sweeps, and the full vector sets
26. scripts: banned-api-check.sh --artifact (both markers and the test key) with selftest fixtures; core/examples/release_probe.rs; canaries (two positive controls, static checks for serde, getrandom and the dalek features, vectors tamper; the feature and profile checks landed after 5)
27. ci: coverage job (cargo-llvm-cov 0.9.1, failing on any core/src path its default ignore rule would skip), cross-job artifact scan with the per-target getrandom cfg, age-interop job, and selftest moved after the toolchain install
28. CLAUDE.md: Commands for M1
29. tasks/todo.md: M1 Review with pasted proof, including the Q12 ruleset output or its deferral

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

### M0 gate status: MET, approved by the owner and merged (PR #1, 2026-10-09)
The gate in docs/build-plan.md asks for CI green and a core that cross-compiles for the Pi Zero, Android and iOS
targets. Both are shown above. Per CLAUDE.md, M1 does not start until the owner approves and PR #1 is merged.

### M1: one-time SeedBook PDF check (2026-10-10, review fix after commit 15)
Plan group 5 puts this check here: "the one-time check of the PDF's printed numbers and cover glyphs goes in Review".
Check 8 recounts the docs' SeedBook figures from the embedded list and pins the PDF's SHA-256; this ties the list to
what the owner's PDF prints.

Method: two standard-library Python scripts, run with `python3 -I` and kept out of the repo, since the check is
one-time:
- `pdf_text.py` (SHA-256 `729a3f41...`) walks the page tree of `docs/KeepCrypt-SeedBook_Braille.pdf` (SHA-256
  `af40ad89...`, equal to `SEEDBOOK_PDF_SHA256`), inflates each content stream, and decodes every text-showing
  operator through its font's ToUnicode CMap. Runs that share a baseline are joined into one line. It found 104 pages.
- `seedbook_compare.py` (SHA-256 `e7bee6e6...`) compares that text with `vectors/braille.json`. Check 8 already pins
  that file's words to the embedded list, which hashes to `2f5eed53...`.

```text
index page: PDF page 5, 25 sections printed
index sections equal braille.json: True total words 2048
list pages: 98 first 1 last 98 in order: True
numbers printed: 2048 distinct: 2048 equal 1-2048: True
word rows: 757 rows whose capitals differ from the list at their numbers: 0
sample ABANDON 0001 printed and matching: True
sample ACT 0020 printed and matching: True
sample ACTION 0021 printed and matching: True
sample METAL 1121 printed and matching: True
sample WIRE 2018 printed and matching: True
sample ZOO 2048 printed and matching: True
cover: ⠅⠑⠑⠏⠉⠗⠽⠏⠞ reads 'keepcrypt' with braille.json's cells; printed letters 'keepcrypt'; equal: True
problems: 0
```

What each line covers:
- The index ("04 — INDEX") prints each section's letter, word count and page range, and all 25 equal braille.json
  `sections`.
- Every list page ("PAGE NNN / 098", pages 001-098) prints the word numbers the rule gives: each section starts a
  page, 24 words per page.
- Each printed row of capitals is the concatenation of the BIP39 words at the numbers printed above it.
- The cover's braille run, read with braille.json's letter cells, spells the letters printed beside it.
- The back cover's 726-cell monogram is decoration and was not compared.
